use thiserror::Error;
use serde::{Serialize, Serializer, Deserialize};
use serde::ser::SerializeSeq;
use serde_cbor::Value;

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

pub trait Message: Send + InternalMessage {
    fn message_type() -> u32;

    fn to_wire(&self) -> Result<Vec<u8>, ParseError> {
        Ok(serde_cbor::to_vec(&self)?)
    }

    fn to_response(&self, token: &str) -> http::response::Response<hyper::body::Body> {
        match self.try_to_response(&Self::message_type().to_string(), token) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error serializing response: {:?}", e);
                // TODO: Serialize a new ErrorMessage
                todo!();
            }
        }
    }

    fn from_wire(body: &[u8]) -> Result<Self, ParseError>;

    /*fn from_wire(body: &[u8]) -> Result<Self, ParseError> {
        let raw = serde_cbor::from_slice(body)?;
        match raw {
            Value::Array(vals) if vals.len() == Self::raw_component_len() => Self::from_raw(vals),
            _ => Err(ParseError::InvalidBody),
        }
    }*/
}

pub trait InternalMessage: Send + Serialize + Sized {
    fn status_code() -> http::StatusCode {
        http::StatusCode::OK
    }

    fn try_to_response(&self, message_type: &str, token: &str) -> Result<http::response::Response<hyper::body::Body>, serde_cbor::Error> {
        let body = serde_cbor::to_vec(&self)?;
        let body = hyper::body::Body::from(body);

        let mut builder = http::response::Response::builder()
            .status(Self::status_code())
            .header("Message-Type", message_type);

        if !token.is_empty() {
            builder = builder.header("Authorization", token);
        }

        Ok(builder.body(body).unwrap())
    }

}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorMessage(
    ErrorCode,
    u8,
    String,
    Option<serde_cbor::Value>,
    u128,
);

impl ErrorMessage {
    pub fn new(error_code: ErrorCode, previous_message_id: u8, error_string: String, error_uuid: u128) -> Self {
        ErrorMessage (
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
    fn message_type() -> u32 {
        255
    }

    fn from_wire(body: &[u8]) -> Result<Self, ParseError> {
        Ok(serde_cbor::from_slice(body)?)
    }
}

impl InternalMessage for ErrorMessage {
    fn status_code() -> http::StatusCode {
        http::StatusCode::INTERNAL_SERVER_ERROR
    }
}
