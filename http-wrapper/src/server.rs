use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use super::EncryptionKeys;
use fdo_data_formats::{
    constants::{ErrorCode, MessageType},
    messages::{self, ClientMessage, EncryptionRequirement, Message, ServerMessage},
};
use fdo_store::Store;

use thiserror::Error;
use warp::{Filter, Rejection};
pub use warp_sessions::Session;

pub struct SessionWithStore {
    pub session: Session,
    session_store: SessionStoreT,
}

type SessionStoreT = Arc<SessionStore>;

pub struct SessionStore {
    store: Box<dyn Store<fdo_store::ReadWriteOpen, String, Session>>,
}

impl SessionStore {
    pub fn new(store: Box<dyn Store<fdo_store::ReadWriteOpen, String, Session>>) -> Arc<Self> {
        Arc::new(SessionStore { store })
    }
}

impl SessionStore {
    async fn load_session(&self, token: String) -> Result<Option<Session>, SessionError> {
        let id = Session::id_from_cookie_value(&token)
            .map_err(|_| SessionError::Unspecified("Invalid cookie token".to_string()))?;
        Ok(self.store.load_data(&id).await?.and_then(Session::validate))
    }

    async fn store_session(&self, session: Session) -> Result<Option<String>, SessionError> {
        self.store
            .store_data(
                session.id().to_string(),
                Some(Duration::from_secs(600)),
                session.clone(),
            )
            .await?;
        session.reset_data_changed();
        Ok(session.into_cookie_value())
    }

    pub async fn destroy_session(&self, session: Session) -> Result<(), SessionError> {
        let id = session.id().to_string();
        self.store.destroy_data(&id).await?;
        Ok(())
    }

    pub async fn perform_maintenance(&self) -> Result<(), SessionError> {
        Ok(self.store.perform_maintenance().await?)
    }
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Unspecified error: {0}")]
    Unspecified(String),
    #[error("Store error")]
    Store(#[from] fdo_store::StoreError),
}

#[derive(Debug)]
pub struct Error(messages::ErrorMessage);

impl Error {
    pub fn new(
        error_code: ErrorCode,
        previous_message_type: MessageType,
        error_string: &str,
    ) -> Self {
        let new_uuid = uuid::Uuid::new_v4();

        Error(messages::ErrorMessage::new(
            error_code,
            previous_message_type,
            error_string.to_string(),
            new_uuid.to_u128_le() & 0xFFFFFFFFFFFFFFFF,
        ))
    }

    pub fn from_error<M, ET>(err: ET) -> Self
    where
        M: Message,
        ET: std::error::Error,
    {
        log::error!(
            "Error occured while processing message type {:?}: {:?}",
            M::message_type(),
            err
        );
        Error::new(
            ErrorCode::InternalServerError,
            M::message_type(),
            "Internal server error",
        )
    }
}

impl warp::reject::Reject for Error {}

pub async fn handle_rejection(err: Rejection) -> Result<warp::reply::Response, Infallible> {
    let local_err: Error;

    log::warn!("Error processing request: {:?}", err);

    let err = if let Some(err) = err.find::<Error>() {
        err
    } else if let Some(ParseError) = err.find() {
        local_err = Error::new(
            ErrorCode::MessageBodyError,
            MessageType::Invalid,
            "Invalid request body",
        );
        &local_err
    } else if err.is_not_found() {
        local_err = Error::new(
            ErrorCode::MessageBodyError,
            MessageType::Invalid,
            "Invalid request type",
        );
        &local_err
    } else {
        local_err = Error::new(
            ErrorCode::InternalServerError,
            MessageType::Invalid,
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
const LAST_MSG_SES_KEY: &str = "_last_message_type_";

async fn parse_request<IM>(
    inbound: warp::hyper::body::Bytes,
    ses_with_store: SessionWithStore,
) -> Result<(IM, SessionWithStore), warp::Rejection>
where
    IM: messages::Message,
{
    let last_msg_type: Option<MessageType> = ses_with_store.session.get(LAST_MSG_SES_KEY);
    if !IM::is_valid_previous_message(last_msg_type) {
        todo!();
    }

    let keys: EncryptionKeys = ses_with_store
        .session
        .get(ENCRYPTION_KEYS_SES_KEY)
        .unwrap_or_else(EncryptionKeys::unencrypted);

    if let Some(req_enc_requirement) = IM::encryption_requirement() {
        if req_enc_requirement == EncryptionRequirement::MustBeEncrypted && keys.is_none() {
            return Err(Error::new(
                ErrorCode::InternalServerError,
                IM::message_type(),
                "IM encryption requirement not met",
            )
            .into());
        }
        if req_enc_requirement == EncryptionRequirement::MustNotBeEncrypted && keys.is_some() {
            return Err(Error::new(
                ErrorCode::InternalServerError,
                IM::message_type(),
                "IM encryption requirement not met",
            )
            .into());
        }
    }

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
    let req = IM::deserialize_data(&inbound).map_err(|e| {
        log::info!("Error parsing request: {:?}", e);
        warp::reject::custom(ParseError)
    })?;

    Ok((req, ses_with_store))
}

pub fn set_encryption_keys<IM>(
    ses: &mut Session,
    new_keys: EncryptionKeys,
) -> Result<(), warp::Rejection>
where
    IM: Message,
{
    ses.insert(ENCRYPTION_KEYS_SES_KEY, new_keys).map_err(|e| {
        log::error!("Error setting encryption keys on session: {:?}", e);
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
    mut ses_with_store: SessionWithStore,
) -> Result<(OM, Option<String>, EncryptionKeys), warp::Rejection>
where
    IM: Message,
    OM: Message,
{
    ses_with_store
        .session
        .insert(LAST_MSG_SES_KEY, OM::message_type())
        .map_err(|e| {
            log::error!("Error storing last message: {:?}", e);
            Error::new(
                ErrorCode::InternalServerError,
                IM::message_type(),
                "Error storing last message",
            )
        })?;
    let keys = ses_with_store
        .session
        .get(ENCRYPTION_KEYS_SES_KEY)
        .unwrap_or_else(EncryptionKeys::unencrypted);

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
    MT: Message + ServerMessage,
{
    let mut builder = warp::http::response::Response::builder()
        .status(MT::status_code())
        .header("Message-Type", (MT::message_type() as u8).to_string());

    let token = token.map(|t| format!("Bearer {}", t));

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
    IM: Message + ClientMessage,
    OM: Message + ServerMessage,
{
    if let Some(enc_requirement) = OM::encryption_requirement() {
        if enc_requirement == EncryptionRequirement::MustBeEncrypted && enc_keys.is_none() {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                IM::message_type(),
                "Sequence error: must be encrypted",
            )
            .into());
        }
        if enc_requirement == EncryptionRequirement::MustNotBeEncrypted && enc_keys.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                IM::message_type(),
                "Sequence error: must not be encrypted",
            )
            .into());
        }
    }
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

pub fn ping_handler() -> warp::filters::BoxedFilter<(warp::reply::Response,)> {
    warp::post()
        .and(warp::path("ping"))
        .map(|| warp::reply::Response::new("pong".into()))
        .boxed()
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
    IM: messages::Message + ClientMessage + 'static,
    OM: messages::Message + ServerMessage + 'static,
{
    if !OM::is_valid_previous_message(Some(IM::message_type())) {
        // This is a programming error, let's just check this on start
        panic!(
            "Programming error: IM {:?} is not valid for OM {:?}",
            IM::message_type(),
            OM::message_type()
        );
    }

    warp::post()
        // Construct expected HTTP path
        .and(warp::path("fdo"))
        .and(warp::path("100"))
        .and(warp::path("msg"))
        .and(warp::path((IM::message_type() as u8).to_string()))
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
                    Some(val) =>  {
                        let val = if val.contains(' ') {
                            val.split(' ').nth(1).unwrap().to_string()
                        } else {
                            val
                        };
                        match ses_store.load_session(val.to_string()).await {
                            Ok(Some(ses)) => ses,
                            Ok(None) => Session::new(),
                            Err(_) => {
                                return Err(Rejection::from(Error::new(
                                    ErrorCode::InternalServerError,
                                    IM::message_type(),
                                    "Error retrieving session",
                                )))
                            }
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
        .boxed()
}
