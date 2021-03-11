use warp::Filter;

mod handlers {
    use fdo_data_formats::messages;
    use fdo_data_formats::constants::ErrorCode;

    use fdo_http_wrapper::server::Error;

    pub async fn appstart(msg: messages::DIAppStart) -> Result<messages::DISetCredentials, warp::Rejection>
    {
        println!("DI Appstart: {:?}", msg);
        return Err(Error::new(ErrorCode::InvalidJWT, 0, "Testing all the errors").into());
    }
}

#[tokio::main]
async fn main() {
    let hello = warp::get()
        .map(|| "Hello from the MFG Station");

    let routes = warp::any()
        .and(hello)
        .or(fdo_http_wrapper::server::fdo_request_filter(handlers::appstart));

    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
