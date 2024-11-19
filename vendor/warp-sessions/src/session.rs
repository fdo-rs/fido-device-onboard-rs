use crate::cookie::CookieOptions;
use crate::error::SessionError;
use async_session::{Session, SessionStore};
use async_trait::async_trait;
use std::{ops::Deref, sync::Arc};
use warp::{Rejection, Reply};

#[derive(Debug, Clone)]
pub struct ArcSessionStore<T: SessionStore>(pub Arc<T>);

#[async_trait]
impl<T> SessionStore for ArcSessionStore<T>
where
    T: SessionStore,
{
    async fn load_session(&self, cookie_value: String) -> async_session::Result<Option<Session>> {
        self.0.deref().load_session(cookie_value).await
    }
    async fn store_session(&self, session: Session) -> async_session::Result<Option<String>> {
        self.0.deref().store_session(session).await
    }
    async fn destroy_session(&self, session: Session) -> async_session::Result {
        self.0.deref().destroy_session(session).await
    }
    async fn clear_store(&self) -> async_session::Result {
        self.0.deref().clear_store().await
    }
}

/// SessionWithStore binds a session object with its backing store and some cookie options.
/// This is passed around by routes wanting to do things with a session.
#[derive(Clone)]
pub struct SessionWithStore<S: SessionStore> {
    pub session: Session,
    pub session_store: S,
    pub cookie_options: CookieOptions,
}

/// WithSession is a warp::Reply that attaches a session ID in the form of
/// a Set-Cookie header to an existing warp::Reply
pub struct WithSession<T: Reply> {
    reply: T,
    cookie_options: CookieOptions,
}

impl<T> WithSession<T>
where
    T: Reply,
{
    /// This function binds a session to a warp::Reply. It takes the given
    /// session and binds it to the given warp::Reply by attaching a Set-Cookie
    /// header to it. This cookie contains the session ID. If the session was
    /// destroyed, it handles destroying the session in the store and removing
    /// the cookie.
    pub async fn new<S: SessionStore>(
        reply: T,
        session_with_store: SessionWithStore<S>,
    ) -> Result<WithSession<T>, Rejection> {
        let mut cookie_options = session_with_store.cookie_options;

        if session_with_store.session.is_destroyed() {
            cookie_options.cookie_value = Some("".to_string());
            cookie_options.max_age = Some(0);

            session_with_store
                .session_store
                .destroy_session(session_with_store.session)
                .await
                .map_err(|source| SessionError::DestroyError { source })?;
        } else {
            if session_with_store.session.data_changed() {
                match session_with_store
                    .session_store
                    .store_session(session_with_store.session)
                    .await
                    .map_err(|source| SessionError::StoreError { source })?
                {
                    Some(sid) => cookie_options.cookie_value = Some(sid),
                    None => (),
                }
            }
        }

        Ok(WithSession {
            reply,
            cookie_options,
        })
    }
}

impl<T> Reply for WithSession<T>
where
    T: Reply,
{
    fn into_response(self) -> warp::reply::Response {
        let mut res = self.reply.into_response();
        if let Some(_) = self.cookie_options.cookie_value {
            res.headers_mut().append(
                "Set-Cookie",
                http::header::HeaderValue::from_str(&self.cookie_options.to_string()).unwrap(),
            );
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionWithStore, WithSession};
    use crate::cookie::CookieOptions;
    use async_session::{MemoryStore, Session};

    #[tokio::test]
    async fn test_session_reply_with_no_data_changed() {
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

    #[tokio::test]
    async fn test_session_reply_with_data_changed() {
        let html_reply = warp::reply::html("".to_string());
        let mut session = Session::new();
        session.insert("key", "value").unwrap();
        let session_store = MemoryStore::new();
        let cookie_options = CookieOptions::default();
        let session_with_store = SessionWithStore {
            session,
            session_store,
            cookie_options,
        };

        assert_eq!(session_with_store.session.data_changed(), true);
        WithSession::new(html_reply, session_with_store)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_session_reply_with_session_destroyed() {
        let html_reply = warp::reply::html("".to_string());
        let mut session = Session::new();
        session.destroy();
        let session_store = MemoryStore::new();
        let cookie_options = CookieOptions::default();
        let session_with_store = SessionWithStore {
            session,
            session_store,
            cookie_options,
        };

        assert_eq!(session_with_store.session.is_destroyed(), true);
        WithSession::new(html_reply, session_with_store)
            .await
            .unwrap();
    }
}
