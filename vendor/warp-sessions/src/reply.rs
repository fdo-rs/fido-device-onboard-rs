use super::{SessionStore, SessionWithStore, WithSession};
use warp::{Rejection, Reply};

/// Accepts a type that implements warp::Reply and a SessionWithStore
/// and binds the session to the reply. It does this by first saving
/// any changes to the session, and then adding a session ID cookie
/// to reply containing the ID of this particular session.
/// When the request::with_session filter runs, it will pick this cookie
/// up and restore the session from the store.
pub async fn with_session<T: Reply, S: SessionStore>(
    reply: T,
    session_with_store: SessionWithStore<S>,
) -> Result<WithSession<T>, Rejection> {
    WithSession::new(reply, session_with_store).await
}

#[cfg(test)]
mod tests {
    use super::WithSession;
    use crate::{cookie::CookieOptions, SessionWithStore};
    use async_session::{MemoryStore, Session};

    #[tokio::test]
    async fn test_reply_is_created() {
        let html_reply = warp::reply::html("".to_string());
        let session = Session::new();
        let session_store = MemoryStore::new();
        let cookie_options = CookieOptions::default();
        let session_with_store = SessionWithStore {
            session,
            session_store,
            cookie_options,
        };

        assert_eq!(session_with_store.session.data_changed(), false);
        WithSession::new(html_reply, session_with_store)
            .await
            .unwrap();
    }
}
