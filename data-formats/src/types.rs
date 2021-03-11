use std::{convert::TryInto, ops::Deref};
use serde_tuple::{Serialize_tuple};

use crate::{
    constants::{DeviceSigType, HashType, RendezvousVariable, TransportProtocol},
    errors::{Error},
    publickey::PublicKey,
    PROTOCOL_VERSION,
};

use aws_nitro_enclaves_cose::sign::HeaderMap;
use openssl::hash::{hash, MessageDigest};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use serde::ser::{SerializeSeq};
use serde::de::{self, Visitor, SeqAccess};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Hash(
    HashType, // hashtype
    Vec<u8>,  // hash
);

impl Hash {
    pub fn new(alg: Option<HashType>, data: &[u8]) -> Result<Self, Error> {
        let alg = alg.unwrap_or(HashType::Sha384);

        Ok(Hash(alg, hash(alg.try_into()?, data)?.to_vec()))
    }

    pub fn get_type(&self) -> HashType {
        self.0
    }

    pub fn compare_data(&self, other: &[u8]) -> Result<(), Error> {
        let other_digest = hash(self.0.try_into()?, other)?;

        // Compare
        if openssl::memcmp::eq(&self.1, &other_digest) {
            Ok(())
        } else {
            Err(Error::IncorrectHash)
        }
    }
}

pub type HMac = Hash;

#[derive(Debug, Serialize, Deserialize)]
pub struct SigInfo(
    DeviceSigType, // sgType
    Vec<u8>,       // Info
);

impl SigInfo {
    pub fn new(dst: DeviceSigType, info: Vec<u8>) -> Self {
        SigInfo(dst, info)
    }

    pub fn get_sig_type(&self) -> DeviceSigType {
        self.0
    }

    pub fn get_info(&self) -> &[u8] {
        &self.1
    }
}

fn new_nonce_or_guid_val() -> Result<[u8; 16], Error> {
    let mut val = [0u8; 16];

    openssl::rand::rand_bytes(&mut val);

    Ok(val)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Nonce([u8; 16]);

impl Nonce {
    fn new() -> Result<Nonce, Error> {
        Ok(Nonce(new_nonce_or_guid_val()?))
    }

    fn value(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Nonce {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Guid([u8; 16]);

impl Guid {
    fn new() -> Result<Guid, Error> {
        Ok(Guid(new_nonce_or_guid_val()?))
    }

    fn value(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Guid {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub use std::net::{IpAddr as IPAddress, Ipv4Addr as IP4, Ipv6Addr as IP6};

pub type DNSAddress = String;
pub type Port = u16;

pub type RendezvousInfo = Vec<RendezvousDirective>;
pub type RendezvousDirective = Vec<RendezvousInstruction>;
pub type RendezvousInstruction = (RendezvousVariable, CborSimpleType);

// TODO: This sends serde_cbor outwards. Possibly re-do this
pub type CborSimpleType = serde_cbor::Value;

pub type TO2Address = Vec<TO2AddressEntry>;

#[derive(Debug, Serialize, Deserialize)]
pub struct TO2AddressEntry(
    Option<IPAddress>,  // RVIP
    Option<DNSAddress>, // RVDNS
    Port,               // RVPort
    TransportProtocol,  // RVProtocol
);

type MAROEPrefix = Vec<u8>;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExchange(
    Vec<u8>, // xAKeyExchange
    Vec<u8>, // xBKeyExchange
);

type IVData = Vec<u8>;

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceCredential(
    bool,           // Active
    u16,            // ProtVer
    Vec<u8>,        // HmacSecret
    String,         // DeviceInfo
    Guid,           // Guid
    RendezvousInfo, // RVInfo
    Hash,           // PubKeyHash
);

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageProtocolInfo {
    token: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct Message {
    msglen: u16,
    msgtype: crate::constants::MessageType,
    protver: u16,
    protocol_info: MessageProtocolInfo,
    body: Vec<u8>,
}

impl Serialize for Message {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(5))?;

        seq.serialize_element(&self.msglen)?;
        seq.serialize_element(&self.msgtype)?;
        seq.serialize_element(&self.protver)?;
        seq.serialize_element(&self.protocol_info)?;
        seq.serialize_element(&self.body)?;

        seq.end()
    }
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D>(deserializer: D) -> Result<Message, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MessageVisitor;

        impl<'de> Visitor<'de> for MessageVisitor {
            type Value = Message;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("A sequence")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Message, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let msglen = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let msgtype = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let protver = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let protocol_info = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let body = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?;
                Ok(Message{
                    msglen,
                    msgtype,
                    protver,
                    protocol_info,
                    body,
                })
            }
        }

        deserializer.deserialize_seq(MessageVisitor)
    }
}
