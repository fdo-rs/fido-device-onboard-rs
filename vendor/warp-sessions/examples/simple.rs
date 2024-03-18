use warp::{Filter, Rejection};
use warp_sessions::{MemoryStore, SessionWithStore};

#[tokio::main]
async fn main() {
    let session_store = MemoryStore::new();

    let route = warp::get()
        .and(warp::path!("test"))
        .and(warp_sessions::request::with_session(session_store, None))
        .and_then(
            move |session_with_store: SessionWithStore<MemoryStore>| async move {
                Ok::<_, Rejection>((
                    warp::reply::html("<html></html>".to_string()),
                    session_with_store,
                ))
            },
        )
        .untuple_one()
        .and_then(warp_sessions::reply::with_session);

    // Start the server
    let port = 8080;
    println!("starting server listening on ::{}", port);
    warp::serve(route).run(([0, 0, 0, 0], port)).await;
}
