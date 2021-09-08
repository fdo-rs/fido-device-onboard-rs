use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;

use openssl::{
    nid::Nid,
    pkey::{PKey, PKeyRef, Public},
    x509::{X509VerifyResult, X509},
};
use serde::Deserialize;
use serde_tuple::Serialize_tuple;

use crate::{
    constants::{PublicKeyEncoding, PublicKeyType},
    enhanced_types::X5Bag,
    errors::{ChainError, Error, Result},
    types::Hash,
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
#[non_exhaustive]
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

impl TryFrom<PublicKeyBody> for PublicKey {
    type Error = Error;

    fn try_from(pkb: PublicKeyBody) -> Result<Self> {
        match &pkb {
            PublicKeyBody::X509(cert) => {
                let algo = match cert.public_key()?.ec_key()?.group().curve_name() {
                    Some(Nid::X9_62_PRIME256V1) => PublicKeyType::SECP256R1,
                    Some(Nid::SECP384R1) => PublicKeyType::SECP384R1,
                    other => {
                        log::error!("Unsupported EC group encountered: {:?}", other);
                        return Err(Error::UnsupportedAlgorithm);
                    }
                };

                PublicKey::new(algo, pkb)
            }
            _ => Err(Error::UnsupportedAlgorithm),
        }
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

    pub fn verify_from_x5bag(&self, bag: &X5Bag) -> Result<&X509> {
        self.verify(|bag, cert| bag.contains(cert), bag)
    }

    pub fn verify_from_digest(&self, digest: &Hash) -> Result<&X509> {
        let correct_type = digest.get_type().try_into()?;
        self.verify(
            |correct_digest, cert| {
                let cert_digest = cert.digest(correct_type).unwrap();
                log::trace!("Checking digest: {}", hex::encode(cert_digest));
                correct_digest.eq(&cert_digest)
            },
            digest,
        )
    }

    pub fn insecure_verify_without_root_verification(&self) -> Result<&X509> {
        self.verify(|_, _| true, &true)
    }

    pub fn verify<UD, F>(&self, is_trusted_root: F, user_data: &UD) -> Result<&X509>
    where
        F: Fn(&UD, &X509) -> bool,
    {
        log::trace!("Validating X5Chain {:?}", self);

        match self.chain.len() {
            0 => Err(Error::InvalidChain(ChainError::Empty)),
            1 => {
                if is_trusted_root(user_data, &self.chain[0]) {
                    Ok(&self.chain[0])
                } else {
                    Err(Error::InvalidChain(ChainError::NoTrustedRoot))
                }
            }
            _ => {
                let mut has_trusted_root = false;
                for certpos in 0..self.chain.len() - 1 {
                    let cert = &self.chain[certpos];
                    let issuer = &self.chain[certpos + 1];
                    if issuer.issued(&cert) == X509VerifyResult::OK {
                        return Err(Error::InvalidChain(ChainError::NonIssuer(certpos)));
                    }
                    if !cert.verify(&issuer.public_key().unwrap())? {
                        return Err(Error::InvalidChain(ChainError::InvalidSignedCert(certpos)));
                    }
                    if !has_trusted_root && is_trusted_root(user_data, issuer) {
                        has_trusted_root = true;
                    }
                }
                if !has_trusted_root {
                    return Err(Error::InvalidChain(ChainError::NoTrustedRoot));
                }

                Ok(&self.chain[self.chain.len() - 1])
            }
        }
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
        let chain: Vec<Vec<u8>> = serde_cbor::from_slice(data)?;
        let chain = chain
            .iter()
            .map(|cert| X509::from_der(cert).map_err(Error::from))
            .collect::<Result<Vec<X509>>>()?;
        Ok(X5Chain { chain })
    }

    pub fn chain(&self) -> &[X509] {
        &self.chain
    }

    pub fn into_chain(self) -> Vec<X509> {
        self.chain
    }
}
