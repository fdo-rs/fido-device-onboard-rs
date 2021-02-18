use std::ops::Deref;

use crate::{
    constants::{DeviceSigType, HashType, RendezvousVariable, TransportProtocol},
    errors::Result,
    publickey::PublicKey,
    PROTOCOL_VERSION,
};

use aws_nitro_enclaves_cose::sign::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Hash(
    HashType, // hashtype
    Vec<u8>,  // hash
);

pub type HMac = Hash;

impl Hash {
    pub fn new(ht: HashType, hash: Vec<u8>) -> Self {
        Hash(ht, hash)
    }

    pub fn get_hashtype(&self) -> HashType {
        self.0
    }

    pub fn get_hash(&self) -> &[u8] {
        &self.1
    }
}

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

fn new_nonce_or_guid_val() -> Result<[u8; 16]> {
    let mut val = [0u8; 16];

    openssl::rand::rand_bytes(&mut val);

    Ok(val)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Nonce([u8; 16]);

impl Nonce {
    fn new() -> Result<Nonce> {
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Guid([u8; 16]);

impl Guid {
    fn new() -> Result<Guid> {
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
