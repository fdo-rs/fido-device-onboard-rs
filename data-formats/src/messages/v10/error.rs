use serde_tuple::{Deserialize_tuple, Serialize_tuple};

use crate::{
    constants::{ErrorCode, MessageType},
    messages::{ClientMessage, EncryptionRequirement, Message, ServerMessage},
};

#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
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

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version1_0
    }
}

impl ClientMessage for ErrorMessage {}
impl ServerMessage for ErrorMessage {}

#[cfg(test)]
mod test {
    use std::u128;

    use super::ErrorCode;
    use super::ErrorMessage;
    use super::MessageType;
    use crate::Serializable;

    #[test]
    fn test_error_message_serialization() {
        let error_code = ErrorCode::InvalidOwnershipVoucher;
        let previous_message_type = MessageType::TO0OwnerSign;
        let error_string = "Ownership voucher manufacturer not trusted".to_string();
        let error_uuid = 16378777930150272023 as u128;
        let error = ErrorMessage::new(error_code, previous_message_type, error_string, error_uuid);

        let serialized_error = error.serialize_data();
        assert!(serialized_error.is_ok());
        let serialized_data = serialized_error.unwrap();
        let serialized_string = hex::encode(serialized_data);
        // Check the error message is serialized as a CBOR array
        assert!(serialized_string.starts_with("85"));
    }
    #[test]
    fn test_error_message_deserialization() {
        let error_message_encoded = "850216782a4f776e65727368697020766f7563686572206d616e756661637475726572206e6f742074727573746564f61be34d1bbfbd9d5c17";

        let error_code = ErrorCode::InvalidOwnershipVoucher;
        let previous_message_type = MessageType::TO0OwnerSign;
        let error_string = "Ownership voucher manufacturer not trusted".to_string();
        let error_uuid = 16378777930150272023 as u128;

        let error_decoded = hex::decode(error_message_encoded);
        assert!(error_decoded.is_ok());
        let mut error_bytes = error_decoded.unwrap();
        let error_test = &error_bytes.as_mut_slice();
        let error_deserialized = ErrorMessage::deserialize_data(error_test);
        assert!(error_deserialized.is_ok());
        let error_message = error_deserialized.unwrap();
        assert_eq!(error_message.error_code(), error_code);
        assert_eq!(error_message.previous_message_type(), previous_message_type);
        assert_eq!(error_message.error_string(), error_string);
        assert_eq!(error_message.error_uuid(), error_uuid);
    }
}
