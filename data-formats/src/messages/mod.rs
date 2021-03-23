use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::constants::ErrorCode;

mod error;
pub use error::ErrorMessage;

pub mod di;
pub mod to0;
pub mod to1;
pub mod to2;

pub trait ClientMessage: Message {}
pub trait ServerMessage: Message {}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Serialization error")]
    Serde(#[from] serde_cbor::Error),
    #[error("Invalid body")]
    InvalidBody,
}

pub trait Message: Send + Serialize + DeserializeOwned + Sized {
    fn message_type() -> u8;

    fn to_wire(&self) -> Result<Vec<u8>, ParseError> {
        Ok(serde_cbor::to_vec(&self)?)
    }

    fn status_code() -> http::StatusCode {
        http::StatusCode::OK
    }

    fn to_response(&self) -> Vec<u8> {
        match serde_cbor::to_vec(&self) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error serializing response: {:?}", e);
                let errmsg = ErrorMessage::new(
                    ErrorCode::InternalServerError,
                    Self::message_type(),
                    "Error serializing response".to_string(),
                    0,
                );
                serde_cbor::to_vec(&errmsg).expect("Error serializing error message")
            }
        }
    }
}
