use thiserror::Error;

use crate::ProtocolVersion;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("Chain is empty")]
    Empty,
    #[error("Invalid signed certificate at position {0}")]
    InvalidSignedCert(usize),
    #[error("No trusted root encountered")]
    NoTrustedRoot,
    #[error("Non-issuer certificate at position {0}")]
    NonIssuer(usize),
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Cryptographic error stack: {0}")]
    CryptoStack(#[from] openssl::error::ErrorStack),
    #[error("Key derivation error: {0:?}")]
    Kdf(#[from] openssl_kdf::KdfError),
    #[error("Serialization error: {0}")]
    SerdeCborError(#[from] serde_cbor::Error),
    #[error("Deserialization error (ciborium): {0}")]
    CiboriumDeError(#[from] ciborium::de::Error<std::io::Error>),
    #[error("Serialization error (ciborium): {0}")]
    CiboriumSerError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("COSE error: {0}")]
    Cose(#[from] aws_nitro_enclaves_cose::error::CoseError),
    #[error("Invalid hash value")]
    IncorrectHash,
    #[error("Incorrect nonce value")]
    IncorrectNonce,
    #[error("Unsupported algorithm used")]
    UnsupportedAlgorithm,
    #[error("Non-owner key attempted to sign")]
    NonOwnerKey,
    #[error("Feature not implemented yet: {0}")]
    NotImplemented(&'static str),
    #[error("Inconsistent values were used for '{0}'")]
    InconsistentValue(&'static str),
    #[error("An invalid state machine transition was attempted")]
    InvalidTransition,
    #[error("Data structure with invalid protocol version {0} was encountered")]
    InvalidProtocolVersion(ProtocolVersion),
    #[error("Invalid cryptographic suite name requested: {0}")]
    InvalidSuiteName(String),
    #[error("Invalid entry number requested")]
    InvalidEntryNum,
    #[error("Error in key exchange: {0}")]
    KeyExchangeError(&'static str),
    #[error("Invalid certificate chain encountered: {0}")]
    InvalidChain(ChainError),
    #[error("Array parse error: {0}")]
    ArrayParseError(#[from] crate::cborparser::ArrayParseError),
    #[error("PEM parse error")]
    PemError(#[from] pem::PemError),
    #[error("Invalid PEM tag: {0}")]
    InvalidPemTag(String),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    #[error("Error parsing hex value: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Error parsing ip address: {0}")]
    AddrError(#[from] std::net::AddrParseError),
    #[error("Unsupported version structure encountered. Version: {0:?}")]
    UnsupportedVersion(Option<crate::constants::ProtocolVersion>),
}
