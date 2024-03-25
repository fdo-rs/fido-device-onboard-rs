use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KdfError {
    #[error("OpenSSL error: {0:?}")]
    OpenSSL(#[from] openssl::error::ErrorStack),
    #[error("Unsupported option for current backend: {0}")]
    UnsupportedOption(String),
    #[error("Unimplemented option for current backend: {0}")]
    Unimplemented(&'static str),
    #[error("Required option not specified: {0}")]
    MissingArgument(&'static str),
    #[error("Invalid option provided: {0}")]
    InvalidOption(&'static str),
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum KdfKbMode {
    Counter,
    Feedback,
}

#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum KdfMacType {
    Hmac(openssl::hash::MessageDigest),
    Cmac(openssl::symm::Cipher),
}

impl KdfMacType {
    #[allow(unused)]
    fn has_md(&self) -> bool {
        matches!(self, KdfMacType::Hmac(_))
    }

    #[allow(unused)]
    fn get_md(&self) -> Option<&openssl::hash::MessageDigest> {
        match self {
            KdfMacType::Hmac(md) => Some(md),
            KdfMacType::Cmac(_) => None,
        }
    }

    #[allow(unused)]
    fn has_cipher(&self) -> bool {
        matches!(self, KdfMacType::Cmac(_))
    }

    #[allow(unused)]
    fn get_cipher(&self) -> Option<&openssl::symm::Cipher> {
        match self {
            KdfMacType::Cmac(cipher) => Some(cipher),
            KdfMacType::Hmac(_) => None,
        }
    }
}

impl std::fmt::Debug for KdfMacType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KdfMacType::Hmac(md) => write!(f, "Hmac({:?})", md.type_().long_name()),
            KdfMacType::Cmac(cipher) => write!(f, "Cmac({:?})", cipher.nid().long_name()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum KdfType {
    KeyBased,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KdfArgument<'a> {
    Key(&'a [u8]),
    // Called "Label" in SP800-108
    Salt(&'a [u8]),
    // Called "Context" in SP800-108
    KbInfo(&'a [u8]),

    KbSeed(&'a [u8]),

    R(u8),
    UseSeparator(bool),
    UseL(bool),
    LBits(u8),

    Mac(KdfMacType),
    KbMode(KdfKbMode),
}

pub fn perform_kdf<'a>(
    type_: KdfType,
    args: &[&'a KdfArgument],
    length: usize,
) -> Result<Vec<u8>, KdfError> {
    let mut last_result = None;
    for implementation in AVAILABLE_IMPLEMENTATIONS {
        last_result = Some((implementation.func)(type_, args, length));
        match last_result {
            Some(Err(KdfError::Unimplemented(_))) => continue,
            Some(Err(KdfError::UnsupportedOption(_))) => continue,
            Some(_) => break,
            None => unreachable!(),
        }
    }

    if let Some(result) = last_result {
        result
    } else {
        Err(KdfError::Unimplemented("No implementation available"))
    }
}

pub fn supports_args<'a>(args: &[&'a KdfArgument]) -> bool {
    for implementation in AVAILABLE_IMPLEMENTATIONS {
        if (implementation.supports_args)(args) {
            return true;
        }
    }

    false
}

struct Implementation {
    supports_args: &'static dyn Fn(&[&KdfArgument]) -> bool,
    func: &'static dyn Fn(KdfType, &[&KdfArgument], usize) -> Result<Vec<u8>, KdfError>,
}

#[cfg(implementation = "custom")]
mod custom;
#[cfg(implementation = "ossl11")]
mod ossl11;
#[cfg(implementation = "ossl3")]
mod ossl3;

const AVAILABLE_IMPLEMENTATIONS: &[&Implementation] = &[
    #[cfg(implementation = "ossl11")]
    &ossl11::IMPLEMENTATION,
    #[cfg(implementation = "ossl3")]
    &ossl3::IMPLEMENTATION,
    #[cfg(implementation = "custom")]
    &custom::IMPLEMENTATION,
];

#[cfg(test)]
mod test;
