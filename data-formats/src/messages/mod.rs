use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::constants::ErrorCode;

mod di;
pub use di::{DIAppStart, DISetCredentials};

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Serialization error")]
    Serde(#[from] serde_cbor::Error),
    #[error("Invalid body")]
    InvalidBody,
}

pub trait Message: Send + Serialize + Sized {
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

    fn from_wire(body: &[u8]) -> Result<Self, ParseError>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorMessage(ErrorCode, u8, String, Option<serde_cbor::Value>, u128);

impl ErrorMessage {
    pub fn new(
        error_code: ErrorCode,
        previous_message_id: u8,
        error_string: String,
        error_uuid: u128,
    ) -> Self {
        ErrorMessage(
            error_code,
            previous_message_id,
            error_string,
            None,
            error_uuid,
        )
    }

    pub fn error_code(&self) -> ErrorCode {
        self.0
    }

    pub fn previous_message_id(&self) -> u8 {
        self.1
    }

    pub fn error_string(&self) -> &str {
        &self.2
    }

    pub fn error_timestamp(&self) -> Option<&serde_cbor::Value> {
        self.3.as_ref()
    }

    pub fn error_uuid(&self) -> u128 {
        self.4
    }
}

impl Message for ErrorMessage {
    fn message_type() -> u8 {
        255
    }

    fn status_code() -> http::StatusCode {
        http::StatusCode::INTERNAL_SERVER_ERROR
    }

    fn from_wire(body: &[u8]) -> Result<Self, ParseError> {
        Ok(serde_cbor::from_slice(body)?)
    }
}
