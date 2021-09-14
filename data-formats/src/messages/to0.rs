use serde::{Deserialize, Serialize};
use serde_tuple::Serialize_tuple;

use super::{ClientMessage, EncryptionRequirement, Message, ServerMessage};

use crate::{
    constants::MessageType,
    types::{COSESign, Nonce, TO0Data},
};

#[derive(Debug, Deserialize)]
pub struct Hello {}

impl Hello {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Hello {}
    }
}

impl Message for Hello {
    fn message_type() -> MessageType {
        MessageType::TO0Hello
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, None)
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl Serialize for Hello {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let seq = serializer.serialize_seq(Some(0))?;
        seq.end()
    }
}

impl ClientMessage for Hello {}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloAck {
    nonce3: Nonce,
}

impl HelloAck {
    pub fn new(nonce3: Nonce) -> Self {
        HelloAck { nonce3 }
    }

    pub fn nonce3(&self) -> &Nonce {
        &self.nonce3
    }
}

impl Message for HelloAck {
    fn message_type() -> MessageType {
        MessageType::TO0HelloAck
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO0Hello))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ServerMessage for HelloAck {}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct OwnerSign {
    to0d: TO0Data,
    to1d: COSESign,
}

impl OwnerSign {
    pub fn new(to0d: TO0Data, to1d: COSESign) -> Self {
        OwnerSign { to0d, to1d }
    }

    pub fn to0d(&self) -> &TO0Data {
        &self.to0d
    }

    pub fn to1d(&self) -> &COSESign {
        &self.to1d
    }
}

impl Message for OwnerSign {
    fn message_type() -> MessageType {
        MessageType::TO0OwnerSign
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO0HelloAck))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ClientMessage for OwnerSign {}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct AcceptOwner {
    wait_seconds: u32,
}

impl AcceptOwner {
    pub fn new(wait_seconds: u32) -> Self {
        AcceptOwner { wait_seconds }
    }

    pub fn wait_seconds(&self) -> u32 {
        self.wait_seconds
    }
}

impl Message for AcceptOwner {
    fn message_type() -> MessageType {
        MessageType::TO0AcceptOwner
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO0OwnerSign))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ServerMessage for AcceptOwner {}
