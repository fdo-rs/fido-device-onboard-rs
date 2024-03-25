use super::{CookieOptions, Session, SessionError, SessionStore, SessionWithStore};
use warp::{Filter, Rejection};

/// This function builds a filter from a SessionStore and a set of
/// cookie options for the session. The filter pulls the cookie with
/// name 'sid' from the request and uses the passed in session store
/// to retrieve the session. It returns the session for use by the
/// downstream session handler.
pub fn with_session<T: SessionStore>(
    session_store: T,
    cookie_options: Option<CookieOptions>,
) -> impl Filter<Extract = (SessionWithStore<T>,), Error = Rejection> + Clone {
    let cookie_options = match cookie_options {
        Some(co) => co,
        None => {
            let mut co = CookieOptions::default();
            co.cookie_name = "sid";
            co
        }
    };
    warp::any()
        .and(warp::any().map(move || session_store.clone()))
        .and(warp::cookie::optional(cookie_options.cookie_name))
        .and(warp::any().map(move || cookie_options.clone()))
        .and_then(
	    |session_store: T,
	    sid_cookie: Option<String>,
	    cookie_options: CookieOptions| async move {
                match sid_cookie {
		    Some(sid) => match session_store.load_session(sid).await {
                        Ok(Some(session)) => {
			    Ok::<_, Rejection>(SessionWithStore {
                                session,
                                session_store,
				cookie_options,
			    })
                        }
                        Ok(None) => {
			    Ok::<_, Rejection>(SessionWithStore {
                                session: Session::new(),
                                session_store,
				cookie_options,
			    })
                        }
                        Err(source) => Err(Rejection::from(SessionError::LoadError { source })),
		    },
		    None => {
                        Ok::<_, Rejection>(SessionWithStore {
			    session: Session::new(),
			    session_store,
			    cookie_options,
                        })
		    }
                }
	    },
        )
}
