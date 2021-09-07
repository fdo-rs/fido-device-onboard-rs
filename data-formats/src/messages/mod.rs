use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::constants::{ErrorCode, MessageType};

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

#[derive(Debug, PartialEq, Eq)]
pub enum EncryptionRequirement {
    MustBeEncrypted,
    MustNotBeEncrypted,
}

pub trait Message: Send + Serialize + DeserializeOwned + Sized {
    fn message_type() -> MessageType;

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool;

    fn encryption_requirement() -> Option<EncryptionRequirement>;

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
