use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Cryptographic error stack: {0}")]
    CryptoStack(#[from] openssl::error::ErrorStack),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_cbor::Error),
    #[error("COSE error: {0}")]
    Cose(#[from] aws_nitro_enclaves_cose::error::COSEError),
}
