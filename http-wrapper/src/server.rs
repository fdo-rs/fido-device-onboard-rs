use std::convert::Infallible;

use fdo_data_formats::{
    constants::ErrorCode,
    messages::{self, Message},
};

use warp::{Filter, Rejection};

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

async fn handle_rejection(err: Rejection) -> Result<warp::reply::Response, Infallible> {
    let local_err: Error;

    let err = if let Some(err) = err.find::<Error>() {
        err
    } else if let Some(ParseError) = err.find() {
        local_err = Error::new(
            ErrorCode::MessageBodyError,
            0,
            "Invalid request body",
        );
        &local_err
    } else if err.is_not_found() {
        local_err = Error::new(
            ErrorCode::MessageBodyError,
            0,
            "Invalid request type",
        );
        &local_err
    } else {
        println!("Error: {:?}", err);
        local_err = Error::new(
            ErrorCode::InternalServerError,
            0,
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

pub fn fdo_request_filter<IM, OM, F, FR>(handler: F) -> warp::filters::BoxedFilter<(warp::reply::Response,)>
where
    F: Fn(IM) -> FR + Clone + Send + Sync + 'static,
    FR: futures::Future<Output = Result<OM, warp::Rejection>> + Send,
    IM: messages::Message + 'static,
    OM: messages::Message,
{
    warp::post()
        .and(warp::path("fdo")).and(warp::path("100")).and(warp::path("msg")).and(warp::path(IM::message_type().to_string()))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::bytes())
        .and(warp::header::exact("Content-Type", "application/cbor"))
        .and_then(parse_request)
        .and_then(handler)
        // TODO: Token
        .map(|res: OM| res.to_response(""))
        .recover(handle_rejection)
        .unify()
        .boxed()
}
