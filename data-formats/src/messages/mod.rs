use thiserror::Error;

use crate::{
    constants::{ErrorCode, MessageType},
    ProtocolVersion, Serializable,
};

pub mod v11;

pub trait ClientMessage: Message {}
pub trait ServerMessage: Message {}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Overall error: {0}")]
    Error(#[from] crate::Error),
    #[error("Invalid body")]
    InvalidBody,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncryptionRequirement {
    MustBeEncrypted,
    MustNotBeEncrypted,
}

pub trait Message: Send + Serializable + Sized {
    fn protocol_version() -> ProtocolVersion;

    fn message_type() -> MessageType;

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool;

    fn encryption_requirement() -> Option<EncryptionRequirement>;

    fn status_code() -> http::StatusCode {
        http::StatusCode::OK
    }

    fn to_response(&self) -> Vec<u8> {
        match self.serialize_data() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error serializing response: {:?}", e);

                let errmsg = match Self::protocol_version() {
                    ProtocolVersion::Version1_0 => v11::ErrorMessage::new(
                        ErrorCode::InternalServerError,
                        Self::message_type(),
                        "Error serializing response".to_string(),
                        0,
                    ),
                    ProtocolVersion::Version1_1 => v11::ErrorMessage::new(
                        ErrorCode::InternalServerError,
                        Self::message_type(),
                        "Error serializing response".to_string(),
                        0,
                    ),
                };
                serde_cbor::to_vec(&errmsg).expect("Error serializing error message")
            }
        }
    }
}

#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! simple_message_serializable {
    ($name:ident, $inner_type:ident) => {
        impl crate::Serializable for $name {
            fn serialize_to_writer<W>(&self, writer: W) -> core::result::Result<(), crate::Error>
            where
                W: std::io::Write,
            {
                self.0.serialize_to_writer(writer)
            }

            fn deserialize_from_reader<R>(reader: R) -> core::result::Result<Self, crate::Error>
            where
                R: std::io::Read,
            {
                Ok(Self($inner_type::deserialize_from_reader(reader)?))
            }
        }
    };
}
