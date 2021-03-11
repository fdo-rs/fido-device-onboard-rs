use std::convert::TryFrom;

use openssl::{
    pkey::{PKey, Public},
    x509::X509,
};
use serde::{Deserialize, Serialize};

use crate::{
    constants::{PublicKeyEncoding, PublicKeyType},
    errors::{Error, Result},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey(PublicKeyType, PublicKeyEncoding, Vec<u8>);

impl PublicKey {
    pub fn new(keytype: PublicKeyType, body: PublicKeyBody) -> Result<Self> {
        match body {
            PublicKeyBody::Crypto(v) => Ok(PublicKey(keytype, PublicKeyEncoding::Crypto, v)),
            PublicKeyBody::X509(v) => Ok(PublicKey(keytype, PublicKeyEncoding::X509, v.to_der()?)),
            _ => todo!(),
        }
    }

    pub fn keytype(&self) -> PublicKeyType {
        self.0
    }

    pub fn into_body(&self) -> Result<(PublicKeyType, PublicKeyBody)> {
        match self.1 {
            PublicKeyEncoding::Crypto => Ok((self.0, PublicKeyBody::Crypto(self.2.clone()))),
            PublicKeyEncoding::X509 => Ok((self.0, PublicKeyBody::X509(X509::from_der(&self.2)?))),
            _ => todo!(),
        }
    }

    pub fn as_pkey(&self) -> Result<PKey<Public>> {
        PublicKeyBody::try_from(self)?.as_pkey()
    }
}

#[derive(Debug, Clone)]
pub enum PublicKeyBody {
    Crypto(Vec<u8>),
    X509(X509),
    // TODO
    //COSEX509(Vec<u8>),
    // TODO
    // COSEKEY(COSEKey),
}

impl TryFrom<&PublicKey> for PublicKeyBody {
    type Error = Error;

    fn try_from(pk: &PublicKey) -> Result<Self> {
        Ok(pk.into_body()?.1)
    }
}

impl PublicKeyBody {
    pub fn as_pkey(&self) -> Result<PKey<Public>> {
        match self {
            PublicKeyBody::X509(cert) => cert.public_key().map_err(Error::from),
            _ => todo!(),
        }
    }
}
