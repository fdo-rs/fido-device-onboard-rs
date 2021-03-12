use std::convert::Infallible;

use fdo_data_formats::{
    constants::ErrorCode,
    messages::{self, Message},
};

use warp::{Filter, Rejection};
use warp_sessions::{
    Session,
    SessionStore,
    SessionWithStore,
};

#[derive(Debug)]
pub struct Error (
    messages::ErrorMessage
);

impl Error {
    pub fn new(error_code: ErrorCode, previous_message_id: u8, error_string: &str) -> Self {
        let new_uuid = uuid::Uuid::new_v4();

        Error(
            messages::ErrorMessage::new(
                error_code,
                previous_message_id,
                error_string.to_string(),
                new_uuid.to_u128_le() & 0xFFFFFFFFFFFFFFFF,
            )
        )
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
        println!("Error: {:?}", err);
        local_err = Error::new(
            ErrorCode::InternalServerError,
            IM::message_type(),
            "Error processing response",
        );
        &local_err
    };

    Ok(
        err.0.to_response("")
    )
}

#[derive(Debug)]
struct ParseError;
impl warp::reject::Reject for ParseError {}

async fn parse_request<IM>(inbound: warp::hyper::body::Bytes) -> Result<IM, warp::Rejection>
where
    IM: messages::Message,
{
    IM::from_wire(&inbound)
    .map_err(|e| { println!("Error parsing request: {:?}", e);  warp::reject::custom(ParseError) })
}

async fn store_session<IM, OM, SST>(response: OM, ses_with_store: SessionWithStore<SST>) -> Result<(OM, Option<String>), warp::Rejection>
where
    IM: Message,
    SST: SessionStore,
{
    Ok((
        response,
        ses_with_store.session_store.store_session(ses_with_store.session).await.map_err(|_| Error::new(ErrorCode::InternalServerError, IM::message_type(), "Error storing session"))?
    ))
}

pub fn fdo_request_filter<IM, OM, F, FR, SST>(session_store: SST, handler: F) -> warp::filters::BoxedFilter<(warp::reply::Response,)>
where
    F: Fn(IM, SessionWithStore<SST>) -> FR + Clone + Send + Sync + 'static,
    SST: SessionStore,
    FR: futures::Future<Output = Result<(OM, SessionWithStore<SST>), warp::Rejection>> + Send,
    IM: messages::Message + 'static,
    OM: messages::Message + 'static,
{
    warp::post()
        .and(warp::path("fdo")).and(warp::path("100")).and(warp::path("msg")).and(warp::path(IM::message_type().to_string()))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::bytes())
        .and(warp::header::exact("Content-Type", "application/cbor"))
        .and_then(parse_request)

        // Process "session" (i.e. Authorization header) retrieval
        .and(warp::header::optional("Authorization"))
        .map(move |req, hdr| (req, hdr, session_store.clone()))
        .and_then(
            |(req, hdr, ses_store): (IM, Option<String>, SST)| async move {
                println!("Requesting session with {:?}", hdr);
                let ses = match hdr {
                    Some(val) => {
                        match ses_store.load_session(val).await {
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
                Ok((req, SessionWithStore {
                    session: ses,
                    session_store: ses_store,
                    cookie_options: Default::default(),
                }))
            }
        )
        .untuple_one()

        // Call the handler
        .and_then(handler)

        // Process "session" storage
        .untuple_one()
        .and_then(store_session::<IM, _, _>)

        // Process response
        .map(|(res, ses_token): (OM, Option<String>)| res.to_response(&ses_token.unwrap_or_else(|| "".to_string())))
        .recover(handle_rejection::<IM>)
        .unify()
        .boxed()
}
