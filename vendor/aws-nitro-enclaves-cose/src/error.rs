//! COSE Operation errors and causes

use std::error::Error;
use std::fmt;

use serde_cbor::Error as CborError;

#[derive(Debug)]
/// Aggregation of all error types returned by this library
pub enum CoseError {
    /// Signature could not be performed due to OpenSSL error.
    SignatureError(openssl::error::ErrorStack),
    /// This feature is not yet fully implemented according
    /// to the spec.
    UnimplementedError,
    /// This specific configuration is not supported, although
    /// the spec allows it.
    UnsupportedError(String),
    /// Could not verify signature.
    UnverifiedSignature,
    /// Deserialized structure does not respect the COSE specification.
    SpecificationError(String),
    /// Error while serializing or deserializing structures.
    SerializationError(CborError),
    /// Tag is missing or incorrect.
    TagError(Option<u64>),
    /// Encryption could not be performed due to OpenSSL error.
    EncryptionError(openssl::error::ErrorStack),
    /// TPM error occured
    #[cfg(feature = "key_tpm")]
    TpmError(tss_esapi::Error),
}

impl fmt::Display for CoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoseError::SignatureError(e) => write!(f, "Signature error: {}", e),
            CoseError::UnimplementedError => write!(f, "Not implemented"),
            CoseError::UnsupportedError(e) => write!(f, "Not supported: {}", e),
            CoseError::UnverifiedSignature => write!(f, "Unverified signature"),
            CoseError::SpecificationError(e) => write!(f, "Specification error: {}", e),
            CoseError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            CoseError::TagError(Some(tag)) => write!(f, "Tag {} was not expected", tag),
            CoseError::TagError(None) => write!(f, "Expected tag is missing"),
            CoseError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            #[cfg(feature = "key_tpm")]
            CoseError::TpmError(e) => write!(f, "TPM error: {}", e),
        }
    }
}

impl Error for CoseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CoseError::SignatureError(e) => Some(e),
            CoseError::SerializationError(e) => Some(e),
            _ => None,
        }
    }
}
