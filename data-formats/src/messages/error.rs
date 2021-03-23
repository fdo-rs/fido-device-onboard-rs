use serde::{Deserialize, Serialize};

use super::{ClientMessage, Message, ServerMessage};

use crate::constants::ErrorCode;

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
}

impl ClientMessage for ErrorMessage {}
impl ServerMessage for ErrorMessage {}
