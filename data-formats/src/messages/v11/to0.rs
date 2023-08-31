use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_tuple::Serialize_tuple;

use crate::{
    cborparser::{ParsedArray, ParsedArrayBuilder},
    constants::{HashType, MessageType},
    messages::{ClientMessage, EncryptionRequirement, Message, ServerMessage},
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
        message_type.is_none()
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version1_1
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

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version1_1
    }
}

impl ServerMessage for HelloAck {}

#[derive(Debug)]
pub struct OwnerSign {
    contents: ParsedArray<crate::cborparser::ParsedArraySize2>,

    cached_to0d: ByteBuf,
    cached_to1d: COSESign,
}

impl Serializable for OwnerSign {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self, Error>
    where
        R: std::io::Read,
    {
        let contents: ParsedArray<crate::cborparser::ParsedArraySize2> =
            ParsedArray::deserialize_from_reader(reader)?;
        let to0d = contents.get(0)?;
        let to1d = contents.get(1)?;

        Ok(OwnerSign {
            contents,

            cached_to0d: to0d,
            cached_to1d: to1d,
        })
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        self.contents.serialize_to_writer(writer)
    }
}

impl OwnerSign {
    pub fn new(to0d: ByteBuf, to1d: COSESign) -> Result<Self, Error> {
        let mut contents = ParsedArrayBuilder::new();
        contents.set(0, &to0d)?;
        contents.set(1, &to1d)?;
        let contents = contents.build();

        Ok(OwnerSign {
            contents,

            cached_to0d: to0d,
            cached_to1d: to1d,
        })
    }

    pub fn to0d(&self) -> Result<TO0Data, Error> {
        TO0Data::deserialize_data(&self.cached_to0d)
    }

    pub fn to1d(&self) -> &COSESign {
        &self.cached_to1d
    }

    pub fn to0d_hash(&self, hash_type: HashType) -> Result<Hash, Error> {
        Hash::from_data(hash_type, &self.cached_to0d)
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

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version1_1
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

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version1_1
    }
}

impl ServerMessage for AcceptOwner {}
