use core::future::Future;
use core::pin::Pin;
use std::convert::Infallible;
use std::sync::Arc;

use super::EncryptionKeys;
use fdo_data_formats::{
    constants::ErrorCode,
    messages::{self, Message},
};

use serde::Deserialize;
use thiserror::Error;
use warp::{Filter, Rejection};
pub use warp_sessions::Session;

pub type SessionStoreT = Arc<Box<dyn SessionStore>>;

pub struct SessionWithStore {
    pub session: Session,
    session_store: SessionStoreT,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Unspecified error: {0}")]
    Unspecified(String),
}

pub trait SessionStore: Send + Sync {
    fn load_session<'life0, 'async_trait>(
        &'life0 self,
        token: String,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Session>, SessionError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
    fn store_session<'life0, 'async_trait>(
        &'life0 self,
        session: Session,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, SessionError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
    fn destroy_session<'life0, 'async_trait>(
        &'life0 self,
        session: Session,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
    fn clean_expired_sessions<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
}

#[derive(Debug, Deserialize)]
pub enum SessionStoreDriver {
    #[cfg(feature = "in_memory_session_store")]
    InMemory,
}

impl SessionStoreDriver {
    pub fn initialize(
        &self,
        cfg: Option<config::Value>,
    ) -> Result<Box<dyn SessionStore>, SessionError> {
        match self {
            #[cfg(feature = "in_memory_session_store")]
            SessionStoreDriver::InMemory => memory_store::initialize(cfg),
        }
    }
}

mod memory_store {
    use async_std::sync::{Arc, RwLock};

    use std::collections::HashMap;

    use async_trait::async_trait;

    use super::Session;
    use super::SessionError;
    use super::SessionStore;

    #[derive(Debug)]
    struct MemoryStore {
        store: Arc<RwLock<HashMap<String, Session>>>,
    }

    pub(super) fn initialize(
        _cfg: Option<config::Value>,
    ) -> Result<Box<dyn SessionStore>, SessionError> {
        Ok(Box::new(MemoryStore {
            store: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    #[async_trait]
    impl SessionStore for MemoryStore {
        async fn load_session(&self, token: String) -> Result<Option<Session>, SessionError> {
            let id = Session::id_from_cookie_value(&token)
                .map_err(|_| SessionError::Unspecified("Invalid cookie token".to_string()))?;
            log::trace!("Session id {} loading", id);
            Ok(self
                .store
                .read()
                .await
                .get(&id)
                .cloned()
                .and_then(Session::validate))
        }

        async fn store_session(&self, session: Session) -> Result<Option<String>, SessionError> {
            log::trace!("Storing session with id {}", session.id());
            self.store
                .write()
                .await
                .insert(session.id().to_string(), session.clone());

            session.reset_data_changed();
            Ok(session.into_cookie_value())
        }

        async fn destroy_session(&self, session: Session) -> Result<(), SessionError> {
            log::trace!("Deleting session with id {}", session.id());
            self.store.write().await.remove(session.id());
            Ok(())
        }

        async fn clean_expired_sessions(&self) -> Result<(), SessionError> {
            // TODO
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct Error(messages::ErrorMessage);

impl Error {
    pub fn new(error_code: ErrorCode, previous_message_id: u8, error_string: &str) -> Self {
        let new_uuid = uuid::Uuid::new_v4();

        Error(messages::ErrorMessage::new(
            error_code,
            previous_message_id,
            error_string.to_string(),
            new_uuid.to_u128_le() & 0xFFFFFFFFFFFFFFFF,
        ))
    }
}

impl warp::reject::Reject for Error {}

async fn handle_rejection<IM>(err: Rejection) -> Result<warp::reply::Response, Infallible>
where
    IM: Message,
{
    let local_err: Error;

    let err = if let Some(err) = err.find::<Error>() {
        err
    } else if let Some(ParseError) = err.find() {
        local_err = Error::new(
            ErrorCode::MessageBodyError,
            IM::message_type(),
            "Invalid request body",
        );
        &local_err
    } else if err.is_not_found() {
        local_err = Error::new(
            ErrorCode::MessageBodyError,
            IM::message_type(),
            "Invalid request type",
        );
        &local_err
    } else {
        local_err = Error::new(
            ErrorCode::InternalServerError,
            IM::message_type(),
            "Error processing response",
        );
        &local_err
    };

    Ok(to_response::<messages::ErrorMessage>(
        err.0.to_response(),
        None,
    ))
}

#[derive(Debug)]
struct ParseError;
impl warp::reject::Reject for ParseError {}

const ENCRYPTION_KEYS_SES_KEY: &str = "_encryption_keys_";

async fn parse_request<IM>(
    inbound: warp::hyper::body::Bytes,
    ses_with_store: SessionWithStore,
) -> Result<(IM, SessionWithStore), warp::Rejection>
where
    IM: messages::Message,
{
    let keys: EncryptionKeys = ses_with_store
        .session
        .get(ENCRYPTION_KEYS_SES_KEY)
        .unwrap_or(EncryptionKeys::None);
    let inbound = match keys.decrypt(&inbound) {
        Ok(v) => v,
        Err(_) => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                IM::message_type(),
                "Error decrypting",
            )
            .into())
        }
    };

    Ok((
        serde_cbor::from_slice(&inbound).map_err(|e| {
            println!("Error parsing request: {:?}", e);
            warp::reject::custom(ParseError)
        })?,
        ses_with_store,
    ))
}

pub fn set_encryption_keys<IM>(
    ses: &mut Session,
    new_keys: EncryptionKeys,
) -> Result<(), warp::Rejection>
where
    IM: Message,
{
    ses.insert(ENCRYPTION_KEYS_SES_KEY, new_keys).map_err(|e| {
        println!("Error setting session encryption keys: {:?}", e);
        Error::new(
            ErrorCode::InternalServerError,
            IM::message_type(),
            "Internal error",
        )
        .into()
    })
}

async fn store_session<IM, OM>(
    response: OM,
    ses_with_store: SessionWithStore,
) -> Result<(OM, Option<String>, EncryptionKeys), warp::Rejection>
where
    IM: Message,
{
    let keys = ses_with_store
        .session
        .get(ENCRYPTION_KEYS_SES_KEY)
        .unwrap_or(EncryptionKeys::None);

    Ok((
        response,
        ses_with_store
            .session_store
            .store_session(ses_with_store.session)
            .await
            .map_err(|_| {
                Error::new(
                    ErrorCode::InternalServerError,
                    IM::message_type(),
                    "Error storing session",
                )
            })?,
        keys,
    ))
}

fn to_response<MT>(val: Vec<u8>, token: Option<String>) -> warp::reply::Response
where
    MT: Message,
{
    let mut builder = warp::http::response::Response::builder()
        .status(MT::status_code())
        .header("Message-Type", MT::message_type().to_string());

    if let Some(token) = token {
        if !token.is_empty() {
            builder = builder.header("Authorization", token);
        }
    }

    builder.body(val.into()).unwrap()
}

async fn encrypt_and_generate_response<IM, OM>(
    val: Vec<u8>,
    token: Option<String>,
    enc_keys: EncryptionKeys,
) -> Result<warp::reply::Response, warp::Rejection>
where
    IM: Message,
    OM: Message,
{
    let val = match enc_keys.encrypt(&val) {
        Ok(v) => v,
        Err(_) => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                IM::message_type(),
                "Error encrypting",
            )
            .into())
        }
    };

    Ok(to_response::<OM>(val, token))
}

pub fn fdo_request_filter<UDT, IM, OM, F, FR>(
    user_data: UDT,
    session_store: SessionStoreT,
    handler: F,
) -> warp::filters::BoxedFilter<(warp::reply::Response,)>
where
    UDT: Clone + Send + Sync + 'static,
    F: Fn(UDT, SessionWithStore, IM) -> FR + Clone + Send + Sync + 'static,
    FR: futures::Future<Output = Result<(OM, SessionWithStore), warp::Rejection>> + Send,
    IM: messages::Message + 'static,
    OM: messages::Message + 'static,
{
    warp::post()
        // Construct expected HTTP path
        .and(warp::path("fdo"))
        .and(warp::path("100"))
        .and(warp::path("msg"))
        .and(warp::path(IM::message_type().to_string()))
        // Parse the request
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::bytes())
        .and(warp::header::exact("Content-Type", "application/cbor"))
        // Process "session" (i.e. Authorization header) retrieval
        .and(warp::header::optional("Authorization"))
        .map(move |req, hdr| (req, hdr, session_store.clone()))
        .and_then(
            |(req, hdr, ses_store): (warp::hyper::body::Bytes, Option<String>, SessionStoreT)| async move {
                let ses = match hdr {
                    Some(val) => match ses_store.load_session(val).await {
                        Ok(Some(ses)) => ses,
                        Ok(None) => Session::new(),
                        Err(_) => {
                            return Err(Rejection::from(Error::new(
                                ErrorCode::InternalServerError,
                                IM::message_type(),
                                "Error retrieving session",
                            )))
                        }
                    },
                    None => Session::new(),
                };
                Ok((
                    req,
                    SessionWithStore {
                        session: ses,
                        session_store: ses_store,
                    },
                ))
            },
        )
        .untuple_one()
        .and_then(parse_request)
        // Insert the user data
        .map(move |(req, ses)| (user_data.clone(), req, ses))
        // Move the request message to the end
        .map(move |(user_data, req, ses)| (user_data, ses, req))
        // Call the handler
        .untuple_one()
        .and_then(handler)
        .untuple_one()
        // Process "session" storage
        .and_then(store_session::<IM, _>)
        .map(
            |(res, ses_token, enc_keys): (OM, Option<String>, EncryptionKeys)| {
                (res.to_response(), ses_token, enc_keys)
            },
        )
        .untuple_one()
        .and_then(encrypt_and_generate_response::<IM, OM>)
        .recover(handle_rejection::<IM>)
        .unify()
        .boxed()
}
