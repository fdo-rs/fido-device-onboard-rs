use serde::{Deserialize, Serialize, Serializer};
use serde_tuple::Serialize_tuple;

use super::{ClientMessage, EncryptionRequirement, Message, ServerMessage};
use crate::{
    constants::MessageType,
    types::{CborSimpleType, HMac},
};

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct AppStart {
    mfg_info: CborSimpleType,
}

impl AppStart {
    pub fn new(mfg_info: CborSimpleType) -> Self {
        AppStart { mfg_info }
    }

    pub fn mfg_info(&self) -> &CborSimpleType {
        &self.mfg_info
    }
}

impl Message for AppStart {
    fn message_type() -> MessageType {
        MessageType::DIAppStart
    }

    fn is_valid_previous_message(message_type: Option<crate::constants::MessageType>) -> bool {
        matches!(message_type, None | Some(MessageType::DIUNDone))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        None
    }
}

impl ClientMessage for AppStart {}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct SetCredentials {
    ov_header: Vec<u8>,
}

impl SetCredentials {
    pub fn new(ov_header: Vec<u8>) -> Self {
        SetCredentials { ov_header }
    }

    pub fn ov_header(&self) -> &[u8] {
        &self.ov_header
    }
}

impl Message for SetCredentials {
    fn message_type() -> MessageType {
        MessageType::DISetCredentials
    }

    fn is_valid_previous_message(message_type: Option<crate::constants::MessageType>) -> bool {
        matches!(message_type, Some(MessageType::DIAppStart))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        None
    }
}

impl ServerMessage for SetCredentials {}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct SetHMAC {
    hmac: HMac,
}

impl SetHMAC {
    pub fn new(hmac: HMac) -> Self {
        SetHMAC { hmac }
    }

    pub fn hmac(&self) -> &HMac {
        &self.hmac
    }
}

impl Message for SetHMAC {
    fn message_type() -> MessageType {
        MessageType::DISetHMAC
    }

    fn is_valid_previous_message(message_type: Option<crate::constants::MessageType>) -> bool {
        matches!(message_type, Some(MessageType::DISetCredentials))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        None
    }
}

impl ClientMessage for SetHMAC {}

#[derive(Debug, Deserialize)]
pub struct Done {}

#[allow(clippy::new_without_default)]
impl Done {
    pub fn new() -> Self {
        Done {}
    }
}

impl Message for Done {
    fn message_type() -> MessageType {
        MessageType::DIDone
    }

    fn is_valid_previous_message(message_type: Option<crate::constants::MessageType>) -> bool {
        matches!(message_type, Some(MessageType::DISetHMAC))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        None
    }
}

impl ServerMessage for Done {}

// We can't use Serialize_tuple here because that doesn't work for empty things
impl Serialize for Done {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let seq = serializer.serialize_seq(Some(0))?;
        seq.end()
    }
}
