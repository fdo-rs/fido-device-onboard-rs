use serde::Deserialize;
use serde_tuple::Serialize_tuple;

use crate::{
    constants::{KeyStorageType, MessageType, MfgStringType, PublicKeyType},
    messages::{ClientMessage, EncryptionRequirement, Message, ServerMessage},
    simple_message_serializable,
    types::{COSESign, CipherSuite, KexSuite, Nonce},
};

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct Connect {
    nonce_diun_1: Nonce,
    kex_suite: KexSuite,
    cipher_suite: CipherSuite,
    key_exchange: Vec<u8>,
}

impl Connect {
    pub fn new(
        nonce_diun_1: Nonce,
        kex_suite: KexSuite,
        cipher_suite: CipherSuite,
        key_exchange: Vec<u8>,
    ) -> Self {
        Connect {
            nonce_diun_1,
            kex_suite,
            cipher_suite,
            key_exchange,
        }
    }

    pub fn nonce_diun_1(&self) -> &Nonce {
        &self.nonce_diun_1
    }

    pub fn kex_suite(&self) -> &KexSuite {
        &self.kex_suite
    }

    pub fn cipher_suite(&self) -> &CipherSuite {
        &self.cipher_suite
    }

    pub fn key_exchange(&self) -> &[u8] {
        &self.key_exchange
    }
}

impl Message for Connect {
    fn message_type() -> MessageType {
        MessageType::DIUNConnect
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

impl ClientMessage for Connect {}

#[derive(Debug)]
pub struct Accept(COSESign);

simple_message_serializable!(Accept, COSESign);

impl Accept {
    pub fn new(token: COSESign) -> Self {
        Accept(token)
    }

    pub fn into_token(self) -> COSESign {
        self.0
    }
}

impl Message for Accept {
    fn message_type() -> MessageType {
        MessageType::DIUNAccept
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::DIUNConnect))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version1_1
    }
}

impl ServerMessage for Accept {}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct AcceptPayload {
    key_exchange: Vec<u8>,
}

impl AcceptPayload {
    pub fn new(key_exchange: Vec<u8>) -> Self {
        AcceptPayload { key_exchange }
    }

    pub fn key_exchange(&self) -> &[u8] {
        &self.key_exchange
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct RequestKeyParameters {
    tenant_id: Option<String>,
}

#[allow(clippy::new_without_default)]
impl RequestKeyParameters {
    pub fn new(tenant_id: Option<String>) -> Self {
        RequestKeyParameters { tenant_id }
    }

    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }
}

impl Message for RequestKeyParameters {
    fn message_type() -> MessageType {
        MessageType::DIUNRequestKeyParameters
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::DIUNAccept))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version1_1
    }
}

impl ClientMessage for RequestKeyParameters {}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct ProvideKeyParameters {
    key_type: PublicKeyType,
    key_storage_types_allowed: Option<Vec<KeyStorageType>>,
}

impl ProvideKeyParameters {
    pub fn new(
        key_type: PublicKeyType,
        key_storage_types_allowed: Option<Vec<KeyStorageType>>,
    ) -> Self {
        ProvideKeyParameters {
            key_type,
            key_storage_types_allowed,
        }
    }

    pub fn key_type(&self) -> &PublicKeyType {
        &self.key_type
    }

    pub fn key_storage_types_allowed(&self) -> Option<&[KeyStorageType]> {
        self.key_storage_types_allowed.as_deref()
    }
}

impl Message for ProvideKeyParameters {
    fn message_type() -> MessageType {
        MessageType::DIUNProvideKeyParameters
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::DIUNRequestKeyParameters))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version1_1
    }
}

impl ServerMessage for ProvideKeyParameters {}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct ProvideKey {
    public_key: Vec<u8>, // Key in DER-encoded SubjectPublicKeyInfo format
    public_key_storage: KeyStorageType,
}

impl ProvideKey {
    pub fn new(public_key: Vec<u8>, public_key_storage: KeyStorageType) -> Self {
        ProvideKey {
            public_key,
            public_key_storage,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn public_key_storage(&self) -> KeyStorageType {
        self.public_key_storage
    }
}

impl Message for ProvideKey {
    fn message_type() -> MessageType {
        MessageType::DIUNProvideKey
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::DIUNProvideKeyParameters))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version1_1
    }
}

impl ClientMessage for ProvideKey {}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct Done {
    mfg_string_type: MfgStringType,
}

impl Done {
    pub fn new(mfg_string_type: MfgStringType) -> Self {
        Done { mfg_string_type }
    }

    pub fn mfg_string_type(&self) -> MfgStringType {
        self.mfg_string_type
    }
}

impl Message for Done {
    fn message_type() -> MessageType {
        MessageType::DIUNDone
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::DIUNProvideKey))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version1_1
    }
}

impl ServerMessage for Done {}
