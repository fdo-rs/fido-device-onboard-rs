use serde::{Deserialize, Serialize};

use super::{ClientMessage, EncryptionRequirement, Message, ServerMessage};

use crate::constants::{ErrorCode, MessageType};

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorMessage {
    error_code: ErrorCode,
    previous_message_type: MessageType,
    error_string: String,
    error_timestamp: Option<serde_cbor::Value>,
    error_uuid: u128,
}

impl ErrorMessage {
    pub fn new(
        error_code: ErrorCode,
        previous_message_type: MessageType,
        error_string: String,
        error_uuid: u128,
    ) -> Self {
        ErrorMessage {
            error_code,
            previous_message_type,
            error_string,
            error_timestamp: None,
            error_uuid,
        }
    }

    pub fn error_code(&self) -> ErrorCode {
        self.error_code
    }

    pub fn previous_message_type(&self) -> MessageType {
        self.previous_message_type
    }

    pub fn error_string(&self) -> &str {
        &self.error_string
    }

    pub fn error_timestamp(&self) -> Option<&serde_cbor::Value> {
        self.error_timestamp.as_ref()
    }

    pub fn error_uuid(&self) -> u128 {
        self.error_uuid
    }
}

impl Message for ErrorMessage {
    fn message_type() -> MessageType {
        MessageType::Error
    }

    fn is_valid_previous_message(_message_type: Option<MessageType>) -> bool {
        true
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        None
    }

    fn status_code() -> http::StatusCode {
        http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl ClientMessage for ErrorMessage {}
impl ServerMessage for ErrorMessage {}
