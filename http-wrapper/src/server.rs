use std::convert::Infallible;

use serde::{Deserialize, Serialize};

use fdo_data_formats::{
    constants::ErrorCode,
    messages::{self, Message},
};

use warp::{Filter, Rejection};
use warp_sessions::{Session, SessionStore, SessionWithStore};

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

async fn parse_request<IM, SST>(
    inbound: warp::hyper::body::Bytes,
    ses_with_store: SessionWithStore<SST>,
) -> Result<(IM, SessionWithStore<SST>), warp::Rejection>
where
    IM: messages::Message,
    SST: SessionStore,
{
    let keys = ses_with_store
        .session
        .get("encryption_keys")
        .unwrap_or(EncryptionKeys::None);
    // TODO: Possibly decrypt

    Ok((
        IM::from_wire(&inbound).map_err(|e| {
            println!("Error parsing request: {:?}", e);
            warp::reject::custom(ParseError)
        })?,
        ses_with_store,
    ))
}

#[derive(Debug, Serialize, Deserialize)]
enum EncryptionKeys {
    None,
    AEAD(Vec<u8>),
    Separate(Vec<u8>, Vec<u8>),
}

async fn store_session<IM, OM, SST>(
    response: OM,
    ses_with_store: SessionWithStore<SST>,
) -> Result<(OM, Option<String>, EncryptionKeys), warp::Rejection>
where
    IM: Message,
    SST: SessionStore,
{
    let keys = ses_with_store
        .session
        .get("encryption_keys")
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

async fn encrypt_and_generate_response<OM>(
    val: Vec<u8>,
    token: Option<String>,
    enc_keys: EncryptionKeys,
) -> Result<warp::reply::Response, warp::Rejection>
where
    OM: Message,
{
    // TODO: Possibly encrypt

    Ok(to_response::<OM>(val, token))
}

pub fn fdo_request_filter<UDT, IM, OM, F, FR, SST>(
    user_data: UDT,
    session_store: SST,
    handler: F,
) -> warp::filters::BoxedFilter<(warp::reply::Response,)>
where
    UDT: Clone + Send + Sync + 'static,
    F: Fn(UDT, SessionWithStore<SST>, IM) -> FR + Clone + Send + Sync + 'static,
    SST: SessionStore,
    FR: futures::Future<Output = Result<(OM, SessionWithStore<SST>), warp::Rejection>> + Send,
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
            |(req, hdr, ses_store): (warp::hyper::body::Bytes, Option<String>, SST)| async move {
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
                        cookie_options: Default::default(),
                    },
                ))
            },
        )
        .map(|(req, ses_with_store)| {
            // TODO: Decrypt
            (req, ses_with_store)
        })
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
        .and_then(store_session::<IM, _, _>)
        .map(
            |(res, ses_token, enc_keys): (OM, Option<String>, EncryptionKeys)| {
                (res.to_response(), ses_token, enc_keys)
            },
        )
        .untuple_one()
        .and_then(encrypt_and_generate_response::<OM>)
        .recover(handle_rejection::<IM>)
        .unify()
        .boxed()
}
