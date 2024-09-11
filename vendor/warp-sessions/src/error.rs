use std::error::Error;
use std::fmt::Display;
use warp::reject::Reject;

/// Error type that converts to a warp::Rejection
#[derive(Debug)]
pub enum SessionError {
    /// Represents an error which occurred while loading a session from
    /// the backing session store.
    LoadError { source: async_session::Error },

    /// Represents an error that occurred while saving a session to
    /// the backing session store.
    StoreError { source: async_session::Error },

    /// Represents an error that occurred while destroying a session
    /// record from the backing session store.
    DestroyError { source: async_session::Error },
}

impl Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            SessionError::LoadError { ref source } => Some(source.as_ref()),
            SessionError::StoreError { ref source } => Some(source.as_ref()),
            SessionError::DestroyError { ref source } => Some(source.as_ref()),
        }
    }
}

impl Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            SessionError::LoadError { .. } => {
                write!(f, "Failed to load session")
            }
            SessionError::StoreError { .. } => {
                write!(f, "Failed to store session")
            }
            SessionError::DestroyError { .. } => {
                write!(f, "Failed to destroy session")
            }
        }
    }
}

impl Reject for SessionError {}
