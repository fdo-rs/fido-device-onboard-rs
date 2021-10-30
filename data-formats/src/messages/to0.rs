use serde::{Deserialize, Serialize};
use serde_tuple::Serialize_tuple;

use super::{ClientMessage, EncryptionRequirement, Message, ServerMessage};

use crate::{
    cborparser::ParsedArray,
    constants::{HashType, MessageType},
    types::{COSESign, Hash, Nonce, TO0Data},
    Error, Serializable,
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

#[derive(Debug)]
pub struct OwnerSign {
    contents: ParsedArray<crate::cborparser::ParsedArraySize2>,

    cached_to0d: TO0Data,
    cached_to1d: COSESign,
}

impl Serializable for OwnerSign {
    fn deserialize_data(data: &[u8]) -> Result<Self, Error> {
        let contents: ParsedArray<crate::cborparser::ParsedArraySize2> =
            ParsedArray::deserialize_data(data)?;
        let to0d = contents.get(0)?;
        let to1d = contents.get(1)?;

        Ok(OwnerSign {
            contents,

            cached_to0d: to0d,
            cached_to1d: to1d,
        })
    }

    fn serialize_data(&self) -> Result<Vec<u8>, Error> {
        self.contents.serialize_data()
    }
}

impl OwnerSign {
    pub fn new(to0d: TO0Data, to1d: COSESign) -> Result<Self, Error> {
        let mut contents = unsafe { ParsedArray::new() };
        contents.set(0, &to0d)?;
        contents.set(1, &to1d)?;

        Ok(OwnerSign {
            contents,

            cached_to0d: to0d,
            cached_to1d: to1d,
        })
    }

    pub fn to0d(&self) -> &TO0Data {
        &self.cached_to0d
    }

    pub fn to1d(&self) -> &COSESign {
        &self.cached_to1d
    }

    pub fn to0d_hash(&self, hash_type: HashType) -> Result<Hash, Error> {
        self.contents.get_hash(0, hash_type)
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
