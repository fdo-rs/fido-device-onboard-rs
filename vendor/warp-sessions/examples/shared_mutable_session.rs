use std::sync::{Arc, RwLock};
use warp::{Filter, Rejection};
use warp_sessions::{MemoryStore, SessionWithStore};

/// By extracting session_with_store.session and wrapping it in an Arc<RwLock>,
/// the session object becomes a shared, mutable reference that can be passed
/// around to any other consuming code. When the route is ready to reply,
/// the session is moved out of the Arc<RwLock> and placed back into the
/// SessionWithStore struct to be processed by the reply::with_session function.
#[tokio::main]
async fn main() {
    let session_store = MemoryStore::new();

    let route = warp::get()
        .and(warp::path!("test"))
        .and(warp_sessions::request::with_session(session_store, None))
        .and_then(
            move |mut session_with_store: SessionWithStore<MemoryStore>| async move {
                let shared_session = Arc::new(RwLock::new(session_with_store.session));
                shared_session
                    .write()
                    .unwrap()
                    .insert("key", "value")
                    .unwrap();
                session_with_store.session = Arc::try_unwrap(shared_session)
                    .unwrap()
                    .into_inner()
                    .unwrap();

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
