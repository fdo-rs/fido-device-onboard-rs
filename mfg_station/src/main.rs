use warp::Filter;

mod handlers {
    use fdo_data_formats::messages;
    use fdo_data_formats::constants::ErrorCode;

    use fdo_http_wrapper::server::Error;

    use warp_sessions::{
        SessionStore,
        SessionWithStore,
    };

    pub async fn appstart<ST: SessionStore>(msg: messages::DIAppStart, mut ses_with_store: SessionWithStore<ST>) -> Result<(messages::DISetCredentials, SessionWithStore<ST>), warp::Rejection>
    {
        let mut session = ses_with_store.session;

        println!("DI Appstart: {:?}", msg);
        println!("Session: {:?}", session);

        let newval = match session.get::<u8>("ctr") {
            Some(4) => return Err(Error::new(ErrorCode::InvalidJWT, 0, "Called 4 times").into()),
            Some(n) => n+1,
            None => 1,
        };
        session.insert("ctr", newval).unwrap();

        println!("Counter is now set with val {}", newval);

        ses_with_store.session = session;

        println!("Returning");
        return Ok((
            messages::DISetCredentials::new(vec![newval]),
            ses_with_store,
        ))
    }
}

#[tokio::main]
async fn main() {
    let hello = warp::get()
        .map(|| "Hello from the MFG Station");

    let ses_store = warp_sessions::MemoryStore::new();

    let routes = warp::any()
        .and(hello)
        .or(fdo_http_wrapper::server::fdo_request_filter(ses_store.clone(), handlers::appstart));

    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}
