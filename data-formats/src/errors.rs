use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("Chain is empty")]
    Empty,
    #[error("Invalid signed certificate at position {0}")]
    InvalidSignedCert(usize),
    #[error("No trusted root encountered")]
    NoTrustedRoot,
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Cryptographic error stack: {0}")]
    CryptoStack(#[from] openssl::error::ErrorStack),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_cbor::Error),
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
    #[error("Inconsistent values were used for '{0}'")]
    InconsistentValue(&'static str),
    #[error("An invalid state machine transition was attempted")]
    InvalidTransition,
    #[error("Invalid cryptographic suite name requested: {0}")]
    InvalidSuiteName(String),
    #[error("Invalid entry number requested")]
    InvalidEntryNum,
    #[error("Error in key exchange: {0}")]
    KeyExchangeError(&'static str),
    #[error("Invalid certificate chain encountered: {0}")]
    InvalidChain(ChainError),
}
