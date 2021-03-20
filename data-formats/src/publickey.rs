use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;

use openssl::{
    pkey::{PKey, PKeyRef, Public},
    x509::{X509Ref, X509},
};
use serde::{Deserialize, Serialize};
use serde_tuple::Serialize_tuple;

use crate::{
    constants::{PublicKeyEncoding, PublicKeyType},
    errors::{Error, Result},
};

#[derive(Debug, Clone, Serialize_tuple, Deserialize)]
pub struct PublicKey {
    key_type: PublicKeyType,
    encoding: PublicKeyEncoding,
    data: Vec<u8>,
}

impl PublicKey {
    pub fn new(keytype: PublicKeyType, body: PublicKeyBody) -> Result<Self> {
        match body {
            PublicKeyBody::Crypto(v) => Ok(PublicKey {
                key_type: keytype,
                encoding: PublicKeyEncoding::Crypto,
                data: v,
            }),
            PublicKeyBody::X509(v) => Ok(PublicKey {
                key_type: keytype,
                encoding: PublicKeyEncoding::X509,
                data: v.to_der()?,
            }),
            _ => todo!(),
        }
    }

    pub fn keytype(&self) -> PublicKeyType {
        self.key_type
    }

    pub fn get_body(&self) -> Result<(PublicKeyType, PublicKeyBody)> {
        match self.encoding {
            PublicKeyEncoding::Crypto => {
                Ok((self.key_type, PublicKeyBody::Crypto(self.data.clone())))
            }
            PublicKeyEncoding::X509 => Ok((
                self.key_type,
                PublicKeyBody::X509(X509::from_der(&self.data)?),
            )),
            _ => todo!(),
        }
    }

    pub fn as_pkey(&self) -> Result<PKey<Public>> {
        PublicKeyBody::try_from(self)?.as_pkey()
    }

    pub fn matches_pkey<T: openssl::pkey::HasPublic>(&self, other: &PKeyRef<T>) -> Result<bool> {
        let self_pkey = self.as_pkey()?;

        Ok(self_pkey.public_eq(other))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Public key ({:?}): ", self.key_type)?;
        let body = match self.get_body() {
            Err(_) => return Err(std::fmt::Error),
            Ok(v) => v.1,
        };
        body.fmt(f)
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

impl Display for PublicKeyBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKeyBody::Crypto(v) => write!(f, "crypto: {}", hex::encode(v)),
            PublicKeyBody::X509(v) => write!(f, "X509 Subject: {:?}", v.subject_name()),
        }
    }
}

impl TryFrom<&PublicKey> for PublicKeyBody {
    type Error = Error;

    fn try_from(pk: &PublicKey) -> Result<Self> {
        Ok(pk.get_body()?.1)
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

#[derive(Debug)]
pub struct X5Chain {
    chain: Vec<X509>,
}

impl X5Chain {
    pub fn new(chain: Vec<X509>) -> Self {
        X5Chain { chain }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let chain = self
            .chain
            .iter()
            .map(|cert| cert.to_der().map_err(Error::from))
            .collect::<Result<Vec<Vec<u8>>>>()?;
        Ok(serde_cbor::to_vec(&chain)?)
    }

    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let chain: Vec<Vec<u8>> = serde_cbor::from_slice(&data)?;
        let chain = chain
            .iter()
            .map(|cert| X509::from_der(&cert).map_err(Error::from))
            .collect::<Result<Vec<X509>>>()?;
        Ok(X5Chain { chain })
    }
}
