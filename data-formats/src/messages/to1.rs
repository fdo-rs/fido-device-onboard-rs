use serde::{Deserialize, Serialize};
use serde_tuple::Serialize_tuple;

use super::{ClientMessage, EncryptionRequirement, Message, ServerMessage};

use crate::{
    constants::MessageType,
    types::{COSESign, Guid, Nonce, SigInfo},
};

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloRV {
    guid: Guid,
    a_signature_info: SigInfo,
}

impl HelloRV {
    pub fn new(guid: Guid, a_signature_info: SigInfo) -> Self {
        HelloRV {
            guid,
            a_signature_info,
        }
    }

    pub fn guid(&self) -> &Guid {
        &self.guid
    }

    pub fn a_signature_info(&self) -> &SigInfo {
        &self.a_signature_info
    }
}

impl Message for HelloRV {
    fn message_type() -> MessageType {
        MessageType::TO1HelloRV
    }

    fn is_valid_previous_message(message_type: Option<crate::constants::MessageType>) -> bool {
        matches!(message_type, None)
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ClientMessage for HelloRV {}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloRVAck {
    nonce4: Nonce,
    b_signature_info: SigInfo,
}

impl HelloRVAck {
    pub fn new(nonce4: Nonce, b_signature_info: SigInfo) -> Self {
        HelloRVAck {
            nonce4,
            b_signature_info,
        }
    }

    pub fn nonce4(&self) -> &Nonce {
        &self.nonce4
    }

    pub fn b_signature_info(&self) -> &SigInfo {
        &self.b_signature_info
    }
}

impl Message for HelloRVAck {
    fn message_type() -> MessageType {
        MessageType::TO1HelloRVAck
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO1HelloRV))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ServerMessage for HelloRVAck {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProveToRV(COSESign);

impl ProveToRV {
    pub fn new(token: COSESign) -> Self {
        ProveToRV(token)
    }

    pub fn token(&self) -> &COSESign {
        &self.0
    }
}

impl Message for ProveToRV {
    fn message_type() -> MessageType {
        MessageType::TO1ProveToRV
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO1HelloRVAck))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ClientMessage for ProveToRV {}

#[derive(Debug, Serialize, Deserialize)]
pub struct RVRedirect(COSESign);

impl RVRedirect {
    pub fn new(to1d: COSESign) -> Self {
        RVRedirect(to1d)
    }

    pub fn to1d(&self) -> &COSESign {
        &self.0
    }

    pub fn into_to1d(self) -> COSESign {
        self.0
    }
}

impl Message for RVRedirect {
    fn message_type() -> MessageType {
        MessageType::TO1RVRedirect
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO1ProveToRV))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ServerMessage for RVRedirect {}
