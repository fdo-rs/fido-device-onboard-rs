use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;

use openssl::{
    nid::Nid,
    pkey::{self, PKey, PKeyRef, Public},
    x509::{X509VerifyResult, X509},
};
use serde::{
    de::Error as _,
    ser::{Error as _, SerializeSeq},
    Deserialize, Serialize,
};
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
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,

    #[serde(skip)]
    pkey: PKey<Public>,

    #[serde(skip)]
    certs: Option<X5Chain>,
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
                let data: serde_bytes::ByteBuf = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let data = data.into_vec();

                PublicKey::new(key_type, encoding, data).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_tuple(3, PublicKeyVisitor)
    }
}

impl PublicKey {
    fn new(key_type: PublicKeyType, encoding: PublicKeyEncoding, data: Vec<u8>) -> Result<Self> {
        log::trace!(
            "Parsing public key, type: {:?}, encoding: {:?}, data: {:?}",
            key_type,
            encoding,
            data
        );
        let (certs, pkey) = PublicKey::parse_data(key_type, encoding, &data)?;

        Ok(PublicKey {
            key_type,
            encoding,
            data,

            pkey,
            certs,
        })
    }

    pub fn chain(&self) -> Option<&X5Chain> {
        self.certs.as_ref()
    }

    pub fn keytype(&self) -> PublicKeyType {
        self.key_type
    }

    fn parse_data(
        _key_type: PublicKeyType,
        encoding: PublicKeyEncoding,
        data: &[u8],
    ) -> Result<(Option<X5Chain>, PKey<Public>)> {
        match encoding {
            PublicKeyEncoding::X509 => {
                let key = openssl::pkey::PKey::public_key_from_der(data)?;
                Ok((None, key))
            }
            PublicKeyEncoding::X5CHAIN => {
                if data.is_empty() {
                    return Err(Error::InconsistentValue("Empty public key"));
                }

                let chain = X5Chain::from_slice(data)?;

                if chain.chain.is_empty() {
                    return Err(Error::InconsistentValue("Empty x5chain provided"));
                }
                let leaf_cert = chain.leaf_certificate().unwrap();
                let pkey = leaf_cert.public_key()?;

                Ok((Some(chain), pkey))
            }
            PublicKeyEncoding::Crypto | PublicKeyEncoding::Cosekey => {
                Err(Error::UnsupportedAlgorithm)
            }
        }
    }

    fn key_type_from_pkey(pkey: &PKeyRef<Public>) -> Result<PublicKeyType> {
        match pkey.id() {
            pkey::Id::EC => match pkey.ec_key()?.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => Ok(PublicKeyType::SECP256R1),
                Some(Nid::SECP384R1) => Ok(PublicKeyType::SECP384R1),
                _ => Err(Error::UnsupportedAlgorithm),
            },
            pkey::Id::RSA => match pkey.bits() {
                2048 => Ok(PublicKeyType::Rsa2048RESTR),
                3072 => Ok(PublicKeyType::RsaPkcs),
                _ => Err(Error::UnsupportedAlgorithm),
            },
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }

    pub fn pkey(&self) -> &PKeyRef<Public> {
        &self.pkey
    }

    pub fn matches_pkey<T: openssl::pkey::HasPublic>(&self, other: &PKeyRef<T>) -> Result<bool> {
        Ok(self.pkey.public_eq(other))
    }
}

impl TryFrom<X5Chain> for PublicKey {
    type Error = Error;

    fn try_from(chain: X5Chain) -> Result<Self> {
        let leaf_cert = chain
            .leaf_certificate()
            .ok_or(Error::InconsistentValue("x5chain without leaf certificate"))?;
        let pkey = leaf_cert.public_key()?;
        let key_type = PublicKey::key_type_from_pkey(&pkey)?;
        let encoded = chain.to_vec()?;

        Ok(PublicKey {
            key_type,
            encoding: PublicKeyEncoding::X5CHAIN,
            data: encoded,

            pkey,
            certs: Some(chain),
        })
    }
}

impl TryFrom<X509> for PublicKey {
    type Error = Error;

    fn try_from(x509: X509) -> Result<Self> {
        let pkey = x509.public_key()?;
        let key_type = PublicKey::key_type_from_pkey(&pkey)?;
        let encoded = pkey.public_key_to_der()?;

        Ok(PublicKey {
            key_type,
            encoding: PublicKeyEncoding::X509,
            data: encoded,

            pkey,
            certs: None,
        })
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Public key ({:?}): {:?} (chain: {:?})",
            self.key_type, self.data, self.certs
        )
    }
}

// X5Chain order: [leaf, intermediate1, ..., intermediateN, root]
#[derive(Debug, Clone)]
pub struct X5Chain {
    chain: Vec<X509>,
}

impl<'de> Deserialize<'de> for X5Chain {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct X5ChainVisitor;

        impl<'de> serde::de::Visitor<'de> for X5ChainVisitor {
            type Value = X5Chain;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a vector of X509")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut chain = Vec::new();

                while let Some(x509) = seq.next_element::<serde_bytes::ByteBuf>()? {
                    log::trace!("Deserializing certificate: {:?}", x509);
                    let x509 = X509::from_der(&x509).map_err(A::Error::custom)?;
                    chain.push(x509);
                }
                Ok(X5Chain { chain })
            }
        }

        deserializer.deserialize_seq(X5ChainVisitor)
    }
}

impl Serialize for X5Chain {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.chain.len()))?;
        for cert in &self.chain {
            let cert = cert.to_der().map_err(S::Error::custom)?;
            let cert = serde_bytes::ByteBuf::from(cert);
            log::trace!("Serializing certificate: {:?}", cert);
            seq.serialize_element(&cert)?;
        }
        seq.end()
    }
}

impl X5Chain {
    pub fn new(chain: Vec<X509>) -> Result<Self> {
        if chain.is_empty() {
            Err(Error::InconsistentValue("Empty x5chain"))
        } else {
            Ok(X5Chain { chain })
        }
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

    pub fn leaf_certificate(&self) -> Option<&X509> {
        self.chain.first()
    }

    pub fn from_slice(data: &[u8]) -> Result<Self> {
        serde_cbor::from_slice(data).map_err(Error::from)
    }

    fn to_vec(&self) -> Result<Vec<u8>> {
        serde_cbor::to_vec(self).map_err(Error::from)
    }

    pub fn chain(&self) -> &[X509] {
        &self.chain
    }
}
