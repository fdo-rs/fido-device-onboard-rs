//! # warp-sessions
//!
//! The `warp-sessions` crate provides a set of filters and an
//! interface to add session support to your warp handlers.
//!
//! It operates as such:
//! 1. A warp filter is created which has access to some `SessionStore`.
//!    This filter will, upon receiving a request, extract the session ID
//!    cookie, fetch the matching session, and return it to be used by the
//!    route handler. It'll also handle creating a new session in the absence
//!     of one.
//! 2. The route handler operates as normal, fetching and setting information
//!    in the session struct it received.
//! 3. When the route is ready to reply, it creates its reply struct and places
//!    it in a tuple with the session struct it received. It then calls the session
//!    reply handler inside a `.and_then(...)` call, using `.untuple_one()` to unpair
//!    the output first.
//!
//! # Example
//!
//! ```
//! use warp::{Filter, Rejection};
//! use warp_sessions::{MemoryStore, SessionWithStore, CookieOptions, SameSiteCookieOption};
//!
//! #[tokio::main]
//! async fn main() {
//!     let session_store = MemoryStore::new();
//!
//!     let route = warp::get()
//!         .and(warp::path!("test"))
//!         .and(warp_sessions::request::with_session(
//!             session_store,
//!             Some(CookieOptions {
//!                 cookie_name: "sid",
//!                 cookie_value: None,
//!                 max_age: Some(60),
//!                 domain: None,
//!                 path: None,
//!                 secure: false,
//!                 http_only: true,
//!                 same_site: Some(SameSiteCookieOption::Strict),
//!             }),
//!         ))
//!         .and_then(
//!             move |session_with_store: SessionWithStore<MemoryStore>| async move {
//!                 Ok::<_, Rejection>((
//! 		        warp::reply::html("<html></html>".to_string()),
//!                     session_with_store,
//!                 ))
//!             },
//!         )
//!         .untuple_one()
//!         .and_then(warp_sessions::reply::with_session);
//!
//!     // Start the server
//!     let port = 8080;
//!     println!("starting server listening on ::{}", port);
//!     // warp::serve(route).run(([0, 0, 0, 0], port)).await;
//! }
//! ```
//!
//! The `Some(CookieOptions)` provided as the second argument to `warp_sessions::request::with_session`
//! can optionally be `None`. This will result in a value of CookieOptions::default(). This option
//! encodes the full set of possible cookie parameters that could be applied to the session ID cookie.
//! Check the [CookieOptions](crate::cookie::CookieOptions) for information on fields.
//!
//! Addresses issue [#609](https://github.com/seanmonstar/warp/issues/609) by appending to
//! the header map rather than inserting, allowing for multiple session cookies to be set.
//!
//! This session middleware is meant to be very light and has no shared state other than
//! the session store. It could be reused multiple times in the same route, and with
//! different session stores.
//!
//! The backing session logic is provided by the [async-session](https://docs.rs/async-session/2.0.1/async_session/)
//! crate. Simply implement the `SessionStore` trait and pass it on to the provided
//! `with_session(...)` filter to use it.

mod cookie;
mod error;
mod session;

pub mod reply;
pub mod request;

pub use async_session::{MemoryStore, Session, SessionStore};
pub use cookie::{CookieOptions, SameSiteCookieOption};
pub use error::SessionError;
pub use session::{ArcSessionStore, SessionWithStore, WithSession};
