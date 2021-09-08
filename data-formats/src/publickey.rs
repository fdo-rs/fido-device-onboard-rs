use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;

use openssl::{
    nid::Nid,
    pkey::{self, PKey, PKeyRef, Public},
    x509::{X509Ref, X509VerifyResult, X509},
};
use serde::Deserialize;
use serde_tuple::Serialize_tuple;

use crate::{
    constants::{PublicKeyEncoding, PublicKeyType},
    enhanced_types::X5Bag,
    errors::{ChainError, Error, Result},
    types::Hash,
};

#[derive(Debug, Clone, Serialize_tuple)]
pub struct PublicKey {
    key_type: PublicKeyType,
    encoding: PublicKeyEncoding,
    data: Vec<u8>,

    #[serde(skip)]
    pkey: PKey<Public>,
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<PublicKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> serde::de::Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tuple of (PublicKeyType, PublicKeyEncoding, Vec<u8>)")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let key_type: PublicKeyType = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let encoding: PublicKeyEncoding = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let data: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;

                PublicKey::new(key_type, encoding, data).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_tuple(3, PublicKeyVisitor)
    }
}

impl PublicKey {
    pub fn new(
        key_type: PublicKeyType,
        encoding: PublicKeyEncoding,
        data: Vec<u8>,
    ) -> Result<Self> {
        let pkey = PublicKey::parse_pkey(key_type, encoding, &data)?;

        Ok(PublicKey {
            key_type,
            encoding,
            data,

            pkey,
        })
    }

    pub fn keytype(&self) -> PublicKeyType {
        self.key_type
    }

    fn parse_pkey(
        key_type: PublicKeyType,
        encoding: PublicKeyEncoding,
        data: &[u8],
    ) -> Result<PKey<Public>> {
        match encoding {
            PublicKeyEncoding::X509 => match key_type {
                PublicKeyType::SECP256R1 | PublicKeyType::SECP384R1 => {
                    Ok(PKey::public_key_from_der(data)?)
                }
            },
            _ => todo!(),
        }
    }

    pub fn pkey(&self) -> &PKeyRef<Public> {
        &self.pkey
    }

    pub fn matches_pkey<T: openssl::pkey::HasPublic>(&self, other: &PKeyRef<T>) -> Result<bool> {
        Ok(self.pkey.public_eq(other))
    }
}

impl<P> TryFrom<&PKeyRef<P>> for PublicKey
where
    P: openssl::pkey::HasPublic,
{
    type Error = Error;

    fn try_from(pkey: &PKeyRef<P>) -> Result<Self> {
        let key = pkey.public_key_to_der()?;
        let key_type = match pkey.id() {
            pkey::Id::EC => match pkey.ec_key()?.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => PublicKeyType::SECP256R1,
                Some(Nid::SECP384R1) => PublicKeyType::SECP384R1,
                _ => return Err(Error::UnsupportedAlgorithm),
            },
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        PublicKey::new(key_type, PublicKeyEncoding::X509, key)
    }
}

impl<P> TryFrom<&PKey<P>> for PublicKey
where
    P: openssl::pkey::HasPublic,
{
    type Error = Error;

    fn try_from(pkey: &PKey<P>) -> Result<Self> {
        PublicKey::try_from(pkey.as_ref())
    }
}

impl TryFrom<&X509> for PublicKey {
    type Error = Error;

    fn try_from(x509: &X509) -> Result<Self> {
        PublicKey::try_from(x509.as_ref())
    }
}

impl TryFrom<&X509Ref> for PublicKey {
    type Error = Error;

    fn try_from(x509: &X509Ref) -> Result<Self> {
        PublicKey::try_from(x509.public_key()?.as_ref())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Public key ({:?}): {:?}", self.key_type, self.data)
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
        self.verify(
            |bag, cert| {
                log::trace!("Checking for cert {:?} in X5Bag {:?}", cert, bag);
                bag.contains(cert)
            },
            bag,
        )
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
        self.verify(
            |_, cert| {
                log::trace!("Trusting any certificate as root, so trusting {:?}", cert);
                true
            },
            &true,
        )
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
            n => {
                for certpos in 0..n - 1 {
                    let cert = &self.chain[certpos];
                    let issuer = &self.chain[certpos + 1];
                    log::trace!("Validating that {:?} is signed by {:?}", cert, issuer);
                    if issuer.issued(cert) != X509VerifyResult::OK {
                        return Err(Error::InvalidChain(ChainError::NonIssuer(certpos)));
                    }
                    if !cert.verify(&issuer.public_key().unwrap())? {
                        return Err(Error::InvalidChain(ChainError::InvalidSignedCert(certpos)));
                    }
                    log::trace!("Checking if {:?} is a trusted root", issuer);
                    if is_trusted_root(user_data, issuer) {
                        // We have chained up to a trusted root, so we're all good
                        log::trace!("Was a trusted root, returning leaf certificate");
                        return Ok(&self.chain[0]);
                    }
                }
                Err(Error::InvalidChain(ChainError::NoTrustedRoot))
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
