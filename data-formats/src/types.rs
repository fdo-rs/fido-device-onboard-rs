use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    net::IpAddr,
    ops::Deref,
    str::FromStr,
    string::ToString,
};

use aws_nitro_enclaves_cose::crypto::{Openssl, SigningPrivateKey, SigningPublicKey};
use aws_nitro_enclaves_cose::CoseSign1 as COSESignInner;
use serde_bytes::ByteBuf;
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_tuple::Serialize_tuple;

use crate::{
    cborparser::{ParsedArray, ParsedArrayBuilder},
    constants::{
        DeviceSigType, HashType, HeaderKeys, RendezvousVariable, ServiceInfoModule,
        StandardServiceInfoModule, TransportProtocol,
    },
    errors::Error,
    ownershipvoucher::OwnershipVoucher,
    publickey::PublicKey,
    Serializable,
};

use openssl::{
    bn::{BigNum, BigNumContext},
    dh::Dh,
    ec::{EcGroup, EcKey, EcPoint},
    hash::{hash, MessageDigest},
    nid::Nid,
    pkey::Params,
    rand::rand_bytes,
    symm::Cipher,
};
use openssl_kdf::{perform_kdf, KdfArgument, KdfKbMode, KdfMacType, KdfType};
use serde::{Deserialize, Serialize};

#[derive(Serialize_tuple, Deserialize, Clone)]
pub struct Hash {
    hash_type: HashType,

    #[serde(with = "serde_bytes")]
    value: Vec<u8>,
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hash")
            .field("hash_type", &self.hash_type)
            .field("value", &hex::encode(&self.value))
            .finish()
    }
}

impl FromStr for Hash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let splitloc = match s.find(':') {
            Some(loc) => loc,
            None => {
                return Err(Error::InconsistentValue(
                    "Hash string is missing ':' separator",
                ))
            }
        };
        let (alg, val) = s.split_at(splitloc);
        let val = &val[1..];
        let alg = HashType::from_str(alg)?;
        let val = hex::decode(val)?;
        Hash::from_digest(alg, val)
    }
}

impl Hash {
    pub fn from_data(alg: HashType, data: &[u8]) -> Result<Self, Error> {
        Ok(Hash {
            hash_type: alg,
            value: hash(alg.try_into()?, data)?.to_vec(),
        })
    }

    pub fn from_digest(hash_type: HashType, value: Vec<u8>) -> Result<Self, Error> {
        if value.len() != hash_type.digest_size() {
            return Err(Error::InconsistentValue("Digest string is invalid length"));
        }
        Ok(Hash { hash_type, value })
    }

    pub fn get_type(&self) -> HashType {
        self.hash_type
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn value_bytes(&self) -> &serde_bytes::Bytes {
        serde_bytes::Bytes::new(&self.value)
    }

    pub fn compare_data(&self, other: &[u8]) -> Result<(), Error> {
        let other_digest = hash(self.hash_type.try_into()?, other)?;

        // Compare
        if openssl::memcmp::eq(&self.value, &other_digest) {
            Ok(())
        } else {
            Err(Error::IncorrectHash)
        }
    }

    pub fn compare(&self, other: &Hash) -> Result<(), Error> {
        if self == other {
            Ok(())
        } else {
            Err(Error::IncorrectHash)
        }
    }
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        openssl::memcmp::eq(&self.value, &other.value)
    }
}

impl PartialEq<openssl::hash::DigestBytes> for Hash {
    fn eq(&self, other: &openssl::hash::DigestBytes) -> bool {
        openssl::memcmp::eq(&self.value, other.as_ref())
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:?})", hex::encode(&self.value), self.hash_type)
    }
}

#[cfg(test)]
mod test_hash {
    use std::str::FromStr;

    use crate::Error;

    use super::Hash;

    #[test]
    fn test_hash_fromstr_no_splitloc() {
        let data = "8a2235cbccf8f70f55d5f610053685eefc153983eb9867f556976115fb9a1692"; //DevSkim: ignore DS173237
        let result = Hash::from_str(data).unwrap_err();
        assert!(matches!(
            result,
            Error::InconsistentValue("Hash string is missing ':' separator"),
        ));
    }

    #[test]
    fn test_hash_fromstr_invalid_type_name() {
        let data = "foo:8a2235cbccf8f70f55d5f610053685eefc153983eb9867f556976115fb9a1692"; //DevSkim: ignore DS173237
        let result = Hash::from_str(data).unwrap_err();
        assert!(matches!(
            result,
            Error::InconsistentValue("Invalid digest name"),
        ));
    }

    #[test]
    fn test_hash_fromstr_invalid_value_length() {
        let data = "sha384:8a2235cbccf8f70f55d5f610053685eefc153983eb9867f556976115fb9a1692";
        let result = Hash::from_str(data).unwrap_err();
        assert!(matches!(
            result,
            Error::InconsistentValue("Digest string is invalid length"),
        ));
    }

    #[test]
    fn test_hash_fromstr_valid() {
        let data = "sha256:8a2235cbccf8f70f55d5f610053685eefc153983eb9867f556976115fb9a1692";
        Hash::from_str(data).unwrap();
    }
}

pub type HMac = Hash;

#[derive(Clone, Debug, Serialize_tuple, Deserialize)]
pub struct SigInfo {
    sig_type: DeviceSigType, // sgType
    #[serde(with = "serde_bytes")]
    info: Vec<u8>, // Info
}

impl SigInfo {
    pub fn new(dst: DeviceSigType, info: Vec<u8>) -> Self {
        SigInfo {
            sig_type: dst,
            info,
        }
    }

    pub fn sig_type(&self) -> DeviceSigType {
        self.sig_type
    }

    pub fn info(&self) -> &[u8] {
        &self.info
    }
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct Bstr16(#[serde(with = "serde_bytes")] Vec<u8>);

impl Bstr16 {
    fn check(&self) -> Result<(), Error> {
        if self.0.len() != 16 {
            return Err(Error::InconsistentValue("Bstr16 is not 16 bytes"));
        }
        Ok(())
    }
}

impl TryFrom<Bstr16> for Nonce {
    type Error = Error;

    fn try_from(value: Bstr16) -> Result<Self, Self::Error> {
        value.check()?;
        Ok(Nonce(value.0))
    }
}

impl TryFrom<Bstr16> for Guid {
    type Error = Error;

    fn try_from(value: Bstr16) -> Result<Self, Self::Error> {
        value.check()?;
        Ok(Guid(value.0))
    }
}

fn new_nonce_or_guid_val() -> Result<[u8; 16], Error> {
    let mut val = [0u8; 16];

    openssl::rand::rand_bytes(&mut val)?;

    Ok(val)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "Bstr16")]
pub struct Nonce(#[serde(with = "serde_bytes")] Vec<u8>);

impl Nonce {
    pub fn new() -> Result<Nonce, Error> {
        Ok(Nonce(new_nonce_or_guid_val()?.to_vec()))
    }

    pub fn from_value(val: &[u8]) -> Result<Self, Error> {
        Ok(Nonce(val.into()))
    }

    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for Nonce {
    fn eq(&self, other: &Self) -> bool {
        openssl::memcmp::eq(&self.0, &other.0)
    }
}

impl Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        hex::encode(&self.0).fmt(f)
    }
}

impl FromStr for Nonce {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let decoded = hex::decode(s).unwrap();
        let boxed_slice = decoded.into_boxed_slice();
        let boxed_array: Box<[u8; 16]> = boxed_slice.try_into().unwrap();
        Ok(Nonce(boxed_array.to_vec()))
    }
}

impl Deref for Nonce {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const EAT_RAND: u8 = 0x01;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Default)]
#[serde(try_from = "Bstr16")]
pub struct Guid(#[serde(with = "serde_bytes")] Vec<u8>);

impl Guid {
    pub fn new() -> Result<Guid, Error> {
        Ok(Guid(new_nonce_or_guid_val()?.to_vec()))
    }

    fn as_uuid(&self) -> uuid::Uuid {
        let data: [u8; 16] = self.0.clone().try_into().unwrap();
        uuid::Uuid::from_bytes(data)
    }

    fn as_ueid(&self) -> Vec<u8> {
        let mut new: Vec<u8> = self.0.clone();

        new.insert(0, EAT_RAND);

        new
    }

    fn from_ueid(data: &[u8]) -> Result<Self, Error> {
        if data[0] != EAT_RAND {
            Err(Error::InconsistentValue("Invalid UEID"))
        } else {
            Ok(Guid(data[1..].into()))
        }
    }
}

impl FromStr for Guid {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Guid, uuid::Error> {
        Ok(Guid(uuid::Uuid::from_str(s)?.as_bytes().to_vec()))
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_uuid().fmt(f)
    }
}

impl Deref for Guid {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct IPAddress(std::net::IpAddr);

impl From<std::net::IpAddr> for IPAddress {
    fn from(addr: std::net::IpAddr) -> IPAddress {
        IPAddress(addr)
    }
}

impl std::fmt::Display for IPAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for IPAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let octets = match &self.0 {
            std::net::IpAddr::V4(addr) => addr.octets().to_vec(),
            std::net::IpAddr::V6(addr) => addr.octets().to_vec(),
        };

        serializer.serialize_bytes(&octets)
    }
}

impl<'de> Deserialize<'de> for IPAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct IPAddressVisitor;

        impl serde::de::Visitor<'_> for IPAddressVisitor {
            type Value = IPAddress;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an ip address byte string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let addr = match v.len() {
                    4 => {
                        let v: [u8; 4] = v.try_into().unwrap();
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(v))
                    }
                    16 => {
                        let v: [u8; 16] = v.try_into().unwrap();
                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(v))
                    }
                    _ => return Err(E::invalid_length(v.len(), &self)),
                };

                Ok(IPAddress(addr))
            }
        }

        deserializer.deserialize_seq(IPAddressVisitor)
    }
}

pub type DNSAddress = String;
pub type Port = u16;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(transparent)]
pub struct RendezvousInfo(Vec<RendezvousDirective>);

impl RendezvousInfo {
    pub fn new(
        directives: Vec<Vec<(RendezvousVariable, CborSimpleType)>>,
    ) -> Result<RendezvousInfo, Error> {
        let mut out = Vec::new();

        for directive in directives {
            let mut out_directive = Vec::new();

            for (variable, value) in directive {
                let value = value.serialize_data()?;
                let value = ByteBuf::from(value);

                out_directive.push((variable, value));
            }

            out.push(out_directive);
        }

        Ok(RendezvousInfo(out))
    }

    pub fn values(&self) -> &[RendezvousDirective] {
        &self.0
    }
}

pub type RendezvousDirective = Vec<RendezvousInstruction>;
pub type RendezvousInstruction = (RendezvousVariable, ByteBuf);

// TODO: This sends serde_cbor outwards. Possibly re-do this
pub type CborSimpleType = serde_cbor::Value;

pub trait CborSimpleTypeExt {
    fn as_bool(&self) -> Option<bool>;
    fn as_bytes(&self) -> Option<&[u8]>;
    fn as_u32(&self) -> Option<u32>;
    fn as_i64(&self) -> Option<i64>;
    fn as_u64(&self) -> Option<u64>;
    fn as_f64(&self) -> Option<f64>;
    fn as_str(&self) -> Option<&str>;
    fn as_str_array(&self) -> Option<Vec<String>>;
}

impl CborSimpleTypeExt for CborSimpleType {
    fn as_bool(&self) -> Option<bool> {
        match self {
            serde_cbor::Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            serde_cbor::Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    fn as_u32(&self) -> Option<u32> {
        match self {
            serde_cbor::Value::Integer(u) => Some(*u as u32),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            serde_cbor::Value::Integer(u) => Some(*u as u64),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            serde_cbor::Value::Integer(i) => Some(*i as i64),
            _ => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            serde_cbor::Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            serde_cbor::Value::Text(s) => Some(s),
            _ => None,
        }
    }

    fn as_str_array(&self) -> Option<Vec<String>> {
        match self {
            serde_cbor::Value::Array(a) => {
                let mut out = Vec::new();

                for item in a {
                    match item {
                        serde_cbor::Value::Text(s) => out.push(s.to_string()),
                        _ => return None,
                    }
                }

                Some(out)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Serialize_tuple, Deserialize, Clone)]
pub struct TO2AddressEntry {
    ip: Option<IPAddress>,       // RVIP
    dns: Option<DNSAddress>,     // RVDNS
    port: Port,                  // RVPort
    protocol: TransportProtocol, // RVProtocol
}

impl TO2AddressEntry {
    pub fn new(
        ip: Option<IPAddress>,
        dns: Option<DNSAddress>,
        port: Port,
        protocol: TransportProtocol,
    ) -> Self {
        TO2AddressEntry {
            ip,
            dns,
            port,
            protocol,
        }
    }

    pub fn ip(&self) -> Option<&IPAddress> {
        self.ip.as_ref()
    }

    pub fn dns(&self) -> Option<&DNSAddress> {
        self.dns.as_ref()
    }

    pub fn port(&self) -> Port {
        self.port
    }

    pub fn protocol(&self) -> TransportProtocol {
        self.protocol
    }
}

#[derive(Debug, Clone)]
pub struct TO0Data {
    contents: ParsedArray<crate::cborparser::ParsedArraySize3>,

    cached_ownership_voucher: OwnershipVoucher,
    cached_wait_seconds: u32,
    cached_nonce: Nonce,
}

impl Serializable for TO0Data {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self, Error>
    where
        R: std::io::Read,
    {
        let contents = ParsedArray::deserialize_from_reader(reader)?;

        let ownership_voucher = contents.get(0)?;
        let wait_seconds = contents.get(1)?;
        let nonce = contents.get(2)?;

        Ok(TO0Data {
            contents,

            cached_ownership_voucher: ownership_voucher,
            cached_wait_seconds: wait_seconds,
            cached_nonce: nonce,
        })
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        self.contents.serialize_to_writer(writer)
    }
}

impl TO0Data {
    pub fn new(
        ownership_voucher: OwnershipVoucher,
        wait_seconds: u32,
        nonce: Nonce,
    ) -> Result<Self, Error> {
        let mut contents = ParsedArrayBuilder::new();
        contents.set(0, &ownership_voucher)?;
        contents.set(1, &wait_seconds)?;
        contents.set(2, &nonce)?;

        let contents = contents.build();

        Ok(TO0Data {
            contents,

            cached_ownership_voucher: ownership_voucher,
            cached_wait_seconds: wait_seconds,
            cached_nonce: nonce,
        })
    }

    pub fn ownership_voucher(&self) -> &OwnershipVoucher {
        &self.cached_ownership_voucher
    }

    pub fn wait_seconds(&self) -> u32 {
        self.cached_wait_seconds
    }

    pub fn nonce(&self) -> &Nonce {
        &self.cached_nonce
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct TO1DataPayload {
    to2_addresses: Vec<TO2AddressEntry>,
    to1d_to_to0d_hash: Hash,
}

impl TO1DataPayload {
    pub fn new(to2_addresses: Vec<TO2AddressEntry>, to1d_to_to0d_hash: Hash) -> Self {
        TO1DataPayload {
            to2_addresses,
            to1d_to_to0d_hash,
        }
    }

    pub fn to2_addresses(&self) -> &[TO2AddressEntry] {
        &self.to2_addresses
    }

    pub fn to1d_to_to0d_hash(&self) -> &Hash {
        &self.to1d_to_to0d_hash
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct TO2SetupDevicePayload {
    rendezvous_info: RendezvousInfo,
    guid: Guid,
    nonce7: Nonce,
    owner2_key: PublicKey,
}

impl TO2SetupDevicePayload {
    pub fn new(
        rendezvous_info: RendezvousInfo,
        guid: Guid,
        nonce7: Nonce,
        owner2_key: PublicKey,
    ) -> Self {
        TO2SetupDevicePayload {
            rendezvous_info,
            guid,
            nonce7,
            owner2_key,
        }
    }

    pub fn rendezvous_info(&self) -> &RendezvousInfo {
        &self.rendezvous_info
    }

    pub fn guid(&self) -> &Guid {
        &self.guid
    }

    pub fn nonce7(&self) -> &Nonce {
        &self.nonce7
    }

    pub fn owner2_key(&self) -> &PublicKey {
        &self.owner2_key
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct TO2ProveDevicePayload {
    #[serde(with = "serde_bytes")]
    b_key_exchange: Vec<u8>,
}

impl TO2ProveDevicePayload {
    pub fn new(b_key_exchange: Vec<u8>) -> Self {
        TO2ProveDevicePayload { b_key_exchange }
    }

    pub fn b_key_exchange(&self) -> &[u8] {
        &self.b_key_exchange
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceInfo(Vec<(String, ByteBuf)>);

impl ServiceInfo {
    pub fn new() -> Self {
        ServiceInfo(vec![])
    }

    pub fn add<M, T>(&mut self, module: M, key: &str, value: &T) -> Result<(), Error>
    where
        M: Into<ServiceInfoModule>,
        T: serde::Serialize,
    {
        let module: ServiceInfoModule = module.into();

        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&value, &mut buffer)?;
        let value = ByteBuf::from(buffer);
        self.0.push((format!("{module}:{key}"), value));
        Ok(())
    }

    pub fn add_modules(&mut self, modules: &[ServiceInfoModule]) -> Result<(), Error> {
        self.add(
            StandardServiceInfoModule::DevMod,
            "nummodules",
            &modules.len(),
        )?;

        // We have a special case of this, because this is a list with different types.
        let mut list = vec![
            serde_cbor::Value::Integer(0),
            serde_cbor::Value::Integer(modules.len() as i128),
        ];

        for module in modules {
            list.push(serde_cbor::Value::Text(module.to_string()));
        }

        self.add(StandardServiceInfoModule::DevMod, "modules", &list)
    }

    pub fn iter(&self) -> ServiceInfoIter {
        ServiceInfoIter { info: self, pos: 0 }
    }

    pub fn values(&self) -> Result<Vec<(String, String, CborSimpleType)>, Error> {
        self.0
            .iter()
            .map(|(k, v)| match k.find(':') {
                None => Err(Error::InconsistentValue(
                    "ServiceInfo key missing module separation",
                )),
                Some(pos) => {
                    let (module, key) = k.split_at(pos);
                    let value = serde_cbor::from_slice(v)?;
                    Ok((module.to_string(), key.to_string(), value))
                }
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct ServiceInfoIter<'a> {
    info: &'a ServiceInfo,
    pos: usize,
}

impl Iterator for ServiceInfoIter<'_> {
    type Item = (ServiceInfoModule, String, CborSimpleType);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.info.0.len() {
            return None;
        }
        let (module_key, val) = &self.info.0[self.pos];
        self.pos += 1;

        // When it's stable, use str.split_once
        let split_pos = match module_key.find(':') {
            None => {
                log::error!("ServiceInfo module_key missing colon: {}", module_key);
                return None;
            }
            Some(v) => v,
        };

        let (module, key) = module_key.split_at(split_pos);
        let value = match serde_cbor::from_slice(val) {
            Ok(val) => val,
            Err(e) => {
                log::error!("ServiceInfo value is invalid: {:?}", e);
                return None;
            }
        };
        let module = ServiceInfoModule::from_str(module).unwrap();
        Some((module, key[1..].to_string(), value))
    }
}

#[derive(Debug)]
pub struct TO2ProveOVHdrPayload {
    contents: ParsedArray<crate::cborparser::ParsedArraySize8>,

    cached_ov_header: ByteBuf,
    cached_num_ov_entries: u16,
    cached_hmac: HMac,
    cached_nonce5: Nonce,
    cached_b_signature_info: SigInfo,
    cached_a_key_exchange: ByteBuf,
    cached_hello_device_hash: Hash,
    cached_max_owner_message_size: u16,
}

impl Serializable for TO2ProveOVHdrPayload {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self, Error>
    where
        R: std::io::Read,
    {
        let contents = ParsedArray::deserialize_from_reader(reader)?;

        let cached_ov_header = contents.get(0)?;
        let cached_num_ov_entries = contents.get(1)?;
        let cached_hmac = contents.get(2)?;
        let cached_nonce5 = contents.get(3)?;
        let cached_b_signature_info = contents.get(4)?;
        let cached_a_key_exchange = contents.get(5)?;
        let cached_hello_device_hash = contents.get(6)?;
        let cached_max_owner_message_size = contents.get(7)?;

        Ok(TO2ProveOVHdrPayload {
            contents,

            cached_ov_header,
            cached_num_ov_entries,
            cached_hmac,
            cached_nonce5,
            cached_b_signature_info,
            cached_a_key_exchange,
            cached_hello_device_hash,
            cached_max_owner_message_size,
        })
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        self.contents.serialize_to_writer(writer)
    }
}

impl TO2ProveOVHdrPayload {
    pub fn new(
        ov_header: ByteBuf,
        num_ov_entries: u16,
        hmac: HMac,
        nonce5: Nonce,
        b_signature_info: SigInfo,
        a_key_exchange: Vec<u8>,
        hello_device_hash: Hash,
    ) -> Result<Self, Error> {
        let a_key_exchange = ByteBuf::from(a_key_exchange);

        let mut contents = ParsedArrayBuilder::new();
        contents.set(0, &ov_header)?;
        contents.set(1, &num_ov_entries)?;
        contents.set(2, &hmac)?;
        contents.set(3, &nonce5)?;
        contents.set(4, &b_signature_info)?;
        contents.set(5, &a_key_exchange)?;
        contents.set(6, &hello_device_hash)?;
        contents.set(7, &crate::messages::v11::to2::MAX_MESSAGE_SIZE)?;
        let contents = contents.build();

        Ok(TO2ProveOVHdrPayload {
            contents,

            cached_ov_header: ov_header,
            cached_num_ov_entries: num_ov_entries,
            cached_hmac: hmac,
            cached_nonce5: nonce5,
            cached_b_signature_info: b_signature_info,
            cached_a_key_exchange: a_key_exchange,
            cached_hello_device_hash: hello_device_hash,
            cached_max_owner_message_size: crate::messages::v11::to2::MAX_MESSAGE_SIZE,
        })
    }

    pub fn ov_header(&self) -> &[u8] {
        &self.cached_ov_header
    }

    pub fn into_ov_header(self) -> ByteBuf {
        self.cached_ov_header
    }

    pub fn num_ov_entries(&self) -> u16 {
        self.cached_num_ov_entries
    }

    pub fn hmac(&self) -> &HMac {
        &self.cached_hmac
    }

    pub fn nonce5(&self) -> &Nonce {
        &self.cached_nonce5
    }

    pub fn b_signature_info(&self) -> &SigInfo {
        &self.cached_b_signature_info
    }

    pub fn a_key_exchange(&self) -> &[u8] {
        &self.cached_a_key_exchange
    }

    pub fn hello_device_hash(&self) -> &Hash {
        &self.cached_hello_device_hash
    }

    pub fn max_owner_message_size(&self) -> u16 {
        self.cached_max_owner_message_size
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MAROEPrefix(Vec<u8>);

impl MAROEPrefix {
    pub fn new(data: Vec<u8>) -> Self {
        MAROEPrefix(data)
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
pub enum DerivedKeys {
    Combined { sevk: Vec<u8> },
    Split { sek: Vec<u8>, svk: Vec<u8> },
}

impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[[ DERIVEDKEYS: REDACTED ]]")
    }
}

#[derive(Debug)]
pub enum KeyDeriveSide {
    OwnerService,
    Device,
}

#[derive(Serialize, Deserialize)]
pub enum KeyExchange {
    Ecdh(KexSuite, Vec<u8>, Vec<u8>),
    Dhkex(KexSuite, Vec<u8>),
}

const KEY_DERIVE_LABEL: &[u8] = b"FIDO-KDF";
const KEY_DERIVE_CONTEXT_PREFIX: &[u8] = b"AutomaticOnboardTunnel";

impl KeyExchange {
    pub fn new(suite: KexSuite) -> Result<Self, Error> {
        match suite {
            KexSuite::DhkexId14 | KexSuite::DhkexId15 => {
                let dh_params = suite.get_dh_params()?;
                let key = dh_params.generate_key()?;
                Ok(KeyExchange::Dhkex(suite, key.private_key().to_vec()))
            }
            KexSuite::Ecdh256 | KexSuite::Ecdh384 => {
                let ec_group = suite.get_ecdh_group()?;
                let key = EcKey::generate(&ec_group)?;
                let key = key.private_key_to_der()?;

                let mut our_random = vec![0; suite.get_ecdh_random_size()];
                rand_bytes(&mut our_random)?;

                Ok(KeyExchange::Ecdh(suite, key, our_random))
            }
        }
    }

    pub fn get_public(&self) -> Result<Vec<u8>, Error> {
        match self {
            KeyExchange::Dhkex(suite, key) => {
                let key = BigNum::from_slice(key)?;
                let dh_params = suite.get_dh_params()?;
                let key = dh_params.set_private_key(key)?;
                Ok(key.public_key().to_vec())
            }
            KeyExchange::Ecdh(suite, key, our_random) => {
                let ec_group = suite.get_ecdh_group()?;
                let key = EcKey::private_key_from_der(key)?;

                let mut public_x = BigNum::new()?;
                let mut public_y = BigNum::new()?;
                let mut bnctx = BigNumContext::new()?;

                key.public_key().affine_coordinates_gfp(
                    &ec_group,
                    &mut public_x,
                    &mut public_y,
                    &mut bnctx,
                )?;

                let public_x = public_x.to_vec();
                let public_y = public_y.to_vec();

                Ok(self.encode_ecdh_bstr(&public_x, &public_y, our_random))
            }
        }
    }

    fn encode_ecdh_bstr(&self, ax: &[u8], ay: &[u8], random: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + ax.len() + 2 + ax.len() + 2 + random.len());

        out.extend_from_slice(&(ax.len() as u16).to_be_bytes());
        out.extend_from_slice(ax);

        out.extend_from_slice(&(ay.len() as u16).to_be_bytes());
        out.extend_from_slice(ay);

        out.extend_from_slice(&(random.len() as u16).to_be_bytes());
        out.extend_from_slice(random);

        out
    }

    #[allow(clippy::type_complexity)]
    fn decode_ecdh_bstr(&self, bstr: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
        let (ax_len, bstr) = bstr.split_at(std::mem::size_of::<u16>());
        let ax_len = u16::from_be_bytes(ax_len.try_into().unwrap());

        let (ax, bstr) = bstr.split_at(ax_len as usize);

        let (ay_len, bstr) = bstr.split_at(std::mem::size_of::<u16>());
        let ay_len = u16::from_be_bytes(ay_len.try_into().unwrap());

        let (ay, bstr) = bstr.split_at(ay_len as usize);

        let (random_len, bstr) = bstr.split_at(std::mem::size_of::<u16>());
        let random_len = u16::from_be_bytes(random_len.try_into().unwrap());

        let (random, bstr) = bstr.split_at(random_len as usize);

        if !bstr.is_empty() {
            Err(Error::KeyExchangeError("Invalid ecdh bstr received"))
        } else {
            Ok((ax.to_vec(), ay.to_vec(), random.to_vec()))
        }
    }

    fn derive_key_dh(&self, other: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if let KeyExchange::Dhkex(suite, key) = self {
            let other = BigNum::from_slice(other)?;

            let key = BigNum::from_slice(key)?;
            let dh_params = suite.get_dh_params()?;
            let key = dh_params.set_private_key(key)?;

            Ok((key.compute_key(&other)?, vec![]))
        } else {
            // Only DH suites call into here
            unreachable!()
        }
    }

    fn derive_key_ecdh(
        &self,
        our_side: KeyDeriveSide,
        other: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if let KeyExchange::Ecdh(suite, key, our_random) = self {
            let ec_group = suite.get_ecdh_group()?;

            let (other_x, other_y, other_random) = self.decode_ecdh_bstr(other)?;
            if other_random.len() != suite.get_ecdh_random_size() {
                return Err(Error::KeyExchangeError("Other random is invalid size"));
            }
            let other_x = BigNum::from_slice(&other_x)?;
            let other_y = BigNum::from_slice(&other_y)?;
            let other_pub =
                EcKey::from_public_key_affine_coordinates(&ec_group, &other_x, &other_y)?;
            other_pub.check_key()?;

            let our_key = EcKey::private_key_from_der(key)?;

            let mut bnctx = BigNumContext::new()?;

            let mut derived = EcPoint::new(&ec_group)?;
            derived.mul(
                &ec_group,
                other_pub.public_key(),
                our_key.private_key(),
                &bnctx,
            )?;
            if derived.is_infinity(&ec_group) || !derived.is_on_curve(&ec_group, &mut bnctx)? {
                return Err(Error::KeyExchangeError("Invalid key derived"));
            }

            let mut derived_x = BigNum::new()?;
            let mut derived_y = BigNum::new()?;
            derived.affine_coordinates_gfp(
                &ec_group,
                &mut derived_x,
                &mut derived_y,
                &mut bnctx,
            )?;
            let derived_x = derived_x.to_vec();

            let mut shared_secret =
                Vec::with_capacity(derived_x.len() + our_random.len() + other_random.len());
            shared_secret.extend_from_slice(&derived_x);
            match our_side {
                KeyDeriveSide::Device => {
                    shared_secret.extend_from_slice(our_random);
                    shared_secret.extend_from_slice(&other_random);
                }
                KeyDeriveSide::OwnerService => {
                    shared_secret.extend_from_slice(&other_random);
                    shared_secret.extend_from_slice(our_random);
                }
            }

            Ok((shared_secret, vec![]))
        } else {
            // Only ECDH suites call into here
            unreachable!()
        }
    }

    pub fn derive_key(
        &self,
        our_side: KeyDeriveSide,
        cipher: CipherSuite,
        other: &[u8],
        mut use_noninteroperable_kdf: bool,
    ) -> Result<DerivedKeys, Error> {
        let (shared_secret, context_rand) = match self {
            KeyExchange::Dhkex(..) => self.derive_key_dh(other)?,
            KeyExchange::Ecdh(..) => self.derive_key_ecdh(our_side, other)?,
        };

        let mut salt = Vec::with_capacity(KEY_DERIVE_CONTEXT_PREFIX.len() + context_rand.len() + 2);
        salt.extend_from_slice(KEY_DERIVE_CONTEXT_PREFIX);
        salt.extend_from_slice(&context_rand);
        salt.extend_from_slice(&((cipher.required_keylen() * 8) as u16).to_be_bytes());

        if !crate::interoperable_kdf_available() {
            log::warn!("Forcing use of non-interoperable key derivation");
            use_noninteroperable_kdf = true;
        }

        let interoperable_kdf_args = [
            &KdfArgument::KbMode(KdfKbMode::Counter),
            &KdfArgument::Mac(KdfMacType::Hmac(cipher.kdf_digest())),
            &KdfArgument::Salt(KEY_DERIVE_LABEL),
            &KdfArgument::KbInfo(&salt),
            &KdfArgument::Key(&shared_secret),
            &KdfArgument::UseL(false),
            &KdfArgument::R(8),
        ];
        let noninteroperable_kdf_args = [
            &KdfArgument::KbMode(KdfKbMode::Counter),
            &KdfArgument::Mac(KdfMacType::Hmac(cipher.kdf_digest())),
            &KdfArgument::Salt(KEY_DERIVE_LABEL),
            &KdfArgument::KbInfo(&salt),
            &KdfArgument::Key(&shared_secret),
        ];
        let key_out = perform_kdf(
            KdfType::KeyBased,
            if use_noninteroperable_kdf {
                log::info!("Using non-interoperable KDF");
                &noninteroperable_kdf_args
            } else {
                log::trace!("Using fully interoperable KDF");
                &interoperable_kdf_args
            },
            cipher.required_keylen(),
        )?;

        if cipher.uses_combined_key() {
            Ok(DerivedKeys::Combined { sevk: key_out })
        } else {
            let (svk, sek) = key_out.split_at(cipher.split_key_split_pos());
            Ok(DerivedKeys::Split {
                svk: svk.to_vec(),
                sek: sek.to_vec(),
            })
        }
    }
}

impl std::fmt::Debug for KeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[[ KEYEXCHANGE: REDACTED ]]")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageProtocolInfo {
    token: Option<Vec<u8>>,
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct SizedMessage {
    msglen: u16,
    msgtype: crate::constants::MessageType,
    protver: u16,
    protocol_info: MessageProtocolInfo,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum KexSuite {
    // Elliptic Curve Diffie-Hellman Key Exchange Protocol
    Ecdh256,
    Ecdh384,
    // Diffie-Hellmann Key Exchange Protocol
    DhkexId14,
    DhkexId15,
}

impl FromStr for KexSuite {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "ECDH256" => Ok(KexSuite::Ecdh256),
            "ECDH384" => Ok(KexSuite::Ecdh384),
            "DHKEXid14" => Ok(KexSuite::DhkexId14),
            "DHKEXid15" => Ok(KexSuite::DhkexId15),
            other => Err(Error::InvalidSuiteName(other.to_string())),
        }
    }
}

impl Display for KexSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KexSuite::Ecdh256 => write!(f, "ECDH256"),
            KexSuite::Ecdh384 => write!(f, "ECDH384"),
            KexSuite::DhkexId14 => write!(f, "DHKEXid14"),
            KexSuite::DhkexId15 => write!(f, "DHKEXid15"),
        }
    }
}

impl Serialize for KexSuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for KexSuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KexSuiteVisitor;

        impl serde::de::Visitor<'_> for KexSuiteVisitor {
            type Value = KexSuite;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a kexsuite string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                KexSuite::from_str(v).map_err(|_| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(v),
                        &"a valid kex suite",
                    )
                })
            }
        }

        deserializer.deserialize_str(KexSuiteVisitor)
    }
}

impl KexSuite {
    fn get_ecdh_random_size(&self) -> usize {
        match self {
            KexSuite::Ecdh256 => 16,
            KexSuite::Ecdh384 => 48,
            // Only ECDH suites call into here
            _ => unreachable!(),
        }
    }

    fn get_ecdh_group(&self) -> Result<EcGroup, Error> {
        let curve_name = match self {
            KexSuite::Ecdh256 => Nid::X9_62_PRIME256V1,
            KexSuite::Ecdh384 => Nid::SECP384R1,
            // Only ECDH suites call into here
            _ => unreachable!(),
        };
        Ok(EcGroup::from_curve_name(curve_name)?)
    }

    fn get_dh_params(&self) -> Result<Dh<Params>, Error> {
        match self {
            KexSuite::DhkexId14 => {
                // From RFC3526, section 3
                let prime = BigNum::from_hex_str(
                    "
                FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
                29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
                EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
                E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
                EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
                C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
                83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
                670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
                E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
                DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
                15728E5A 8AACAA68 FFFFFFFF FFFFFFFF",
                )?;
                let generator = BigNum::from_u32(2)?;
                Ok(Dh::from_pqg(prime, None, generator)?)
            }
            KexSuite::DhkexId15 => {
                // From RFC3526, section 4
                let prime = BigNum::from_hex_str(
                    "
                FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
                29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
                EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
                E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
                EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
                C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
                83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
                670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
                E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
                DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
                15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
                ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
                ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
                F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
                BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
                43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF",
                )?;
                let generator = BigNum::from_u32(2)?;
                Ok(Dh::from_pqg(prime, None, generator)?)
            }
            // Only DH suites call into here
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum CipherSuite {
    // Combined ciphers
    A128Gcm = 1,
    A256Gcm = 3,
}

impl CipherSuite {
    fn uses_combined_key(&self) -> bool {
        match self {
            CipherSuite::A128Gcm | CipherSuite::A256Gcm => true,
        }
    }

    fn split_key_split_pos(&self) -> usize {
        match self {
            CipherSuite::A128Gcm | CipherSuite::A256Gcm => {
                // Gcm ciphers should never call into the split_key
                unreachable!()
            }
        }
    }

    fn required_keylen(&self) -> usize {
        match self {
            CipherSuite::A128Gcm => 16,
            CipherSuite::A256Gcm => 32,
        }
    }

    fn kdf_digest(&self) -> MessageDigest {
        match self {
            CipherSuite::A128Gcm | CipherSuite::A256Gcm => MessageDigest::sha256(),
        }
    }

    pub fn openssl_cipher(&self) -> Cipher {
        match self {
            CipherSuite::A128Gcm => Cipher::aes_128_gcm(),
            CipherSuite::A256Gcm => Cipher::aes_256_gcm(),
        }
    }
}

impl FromStr for CipherSuite {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "A128GCM" => Ok(CipherSuite::A128Gcm),
            "A256GCM" => Ok(CipherSuite::A256Gcm),
            other => Err(Error::InvalidSuiteName(other.to_string())),
        }
    }
}

impl Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherSuite::A128Gcm => write!(f, "A128GCM"),
            CipherSuite::A256Gcm => write!(f, "A256GCM"),
        }
    }
}

pub trait PayloadState {}
pub trait PayloadStateUnverified: PayloadState {}
pub trait PayloadStateVerified: PayloadState {}
pub trait PayloadStateCreating: PayloadState {}

#[derive(Debug)]
pub struct PayloadVerified;
impl PayloadState for PayloadVerified {}
impl PayloadStateVerified for PayloadVerified {}

#[derive(Debug)]
pub struct PayloadUnverified;
impl PayloadState for PayloadUnverified {}
impl PayloadStateUnverified for PayloadUnverified {}

#[derive(Debug)]
pub struct PayloadCreating;
impl PayloadState for PayloadCreating {}
impl PayloadStateCreating for PayloadCreating {}

pub struct UnverifiedValue<T>(T);

impl<T> std::fmt::Debug for UnverifiedValue<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[ UNVERIFIED VALUE: [[ ")?;
        self.0.fmt(f)?;
        f.write_str(" ]] ]")
    }
}

impl<T> UnverifiedValue<T> {
    pub fn get_unverified_value(&self) -> &T {
        &self.0
    }

    unsafe fn into_unverified(self) -> T {
        self.0
    }
}

#[derive(Debug)]
pub struct EATokenPayload<S>
where
    S: PayloadState,
{
    _phantom_state: std::marker::PhantomData<S>,

    payload: Option<CborSimpleType>,
    nonce: Nonce,
    device_guid: Vec<u8>,
    other_claims: COSEHeaderMap,
}

impl<S> EATokenPayload<S>
where
    S: PayloadState,
{
    fn payload_internal<T>(&self) -> Result<Option<T>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        match &self.payload {
            None => Ok(None),
            Some(val) => Ok(Some(serde_cbor::value::from_value(val.clone())?)),
        }
    }

    fn nonce_internal(&self) -> &Nonce {
        &self.nonce
    }

    fn device_guid_internal(&self) -> Guid {
        // This was previously validated during from_map construction
        Guid::from_ueid(&self.device_guid).unwrap()
    }

    fn other_claim_internal<T>(&self, key: HeaderKeys) -> Result<Option<T>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        self.other_claims.get(&key)
    }

    fn to_map(&self) -> COSEHeaderMap {
        let mut res = self.other_claims.clone();

        if let Some(payload) = &self.payload {
            res.insert(HeaderKeys::EatFDO, payload)
                .expect("Error adding to res");
        }
        res.insert(HeaderKeys::EatNonce, &self.nonce)
            .expect("Error adding to res");
        res.insert(
            HeaderKeys::EatUeid,
            &serde_bytes::ByteBuf::from(self.device_guid.clone()),
        )
        .expect("Error adding to res");

        res
    }
}

impl<S> EATokenPayload<S>
where
    S: PayloadStateUnverified,
{
    pub fn payload_unverified<T>(&self) -> Result<UnverifiedValue<Option<T>>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        Ok(UnverifiedValue(self.payload_internal()?))
    }

    pub fn nonce_unverified(&self) -> UnverifiedValue<&Nonce> {
        UnverifiedValue(self.nonce_internal())
    }

    pub fn device_guid_unverified(&self) -> UnverifiedValue<Guid> {
        UnverifiedValue(self.device_guid_internal())
    }

    pub fn other_claim_unverified<T>(
        &self,
        key: HeaderKeys,
    ) -> Result<Option<UnverifiedValue<T>>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        match self.other_claim_internal(key) {
            Ok(Some(val)) => Ok(Some(UnverifiedValue(val))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<S> EATokenPayload<S>
where
    S: PayloadStateVerified,
{
    pub fn payload<T>(&self) -> Result<Option<T>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        self.payload_internal()
    }

    pub fn nonce(&self) -> &Nonce {
        self.nonce_internal()
    }

    pub fn device_guid(&self) -> Guid {
        self.device_guid_internal()
    }

    pub fn other_claim<T>(&self, key: HeaderKeys) -> Result<Option<T>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        self.other_claim_internal(key)
    }
}

fn eat_from_map<S>(mut claims: COSEHeaderMap) -> Result<EATokenPayload<S>, Error>
where
    S: PayloadState,
{
    let payload: Option<CborSimpleType> = claims.0.remove(&(HeaderKeys::EatFDO as i64));
    let nonce = match claims.0.remove(&(HeaderKeys::EatNonce as i64)) {
        None => return Err(Error::InconsistentValue("Missing nonce")),
        Some(val) => serde_cbor::value::from_value(val)?,
    };
    let ueid: serde_bytes::ByteBuf = match claims.0.remove(&(HeaderKeys::EatUeid as i64)) {
        None => return Err(Error::InconsistentValue("Missing UEID")),
        Some(val) => {
            let val: serde_bytes::ByteBuf = serde_cbor::value::from_value(val)?;
            // Just verifying that it's valid
            if Guid::from_ueid(&val).is_err() {
                return Err(Error::InconsistentValue("Invalid UEID"));
            }
            val
        }
    };

    let ueid = ueid.into_vec();

    Ok(EATokenPayload {
        _phantom_state: std::marker::PhantomData,

        payload,
        nonce,
        device_guid: ueid,

        other_claims: claims,
    })
}

pub fn new_eat<T>(
    payload: Option<&T>,
    nonce: Nonce,
    device_guid: Guid,
) -> Result<EATokenPayload<PayloadCreating>, Error>
where
    T: Serialize,
{
    let payload = match payload {
        None => None,
        Some(payload) => Some(serde_cbor::value::to_value(payload)?),
    };
    Ok(EATokenPayload {
        _phantom_state: std::marker::PhantomData,

        payload,
        nonce,
        device_guid: device_guid.as_ueid(),
        other_claims: COSEHeaderMap::new(),
    })
}

type COSEHeaderMapType = std::collections::HashMap<i64, serde_cbor::Value>;

#[derive(Debug, Clone)]
pub struct COSEHeaderMap(COSEHeaderMapType);

impl From<COSEHeaderMap> for aws_nitro_enclaves_cose::header_map::HeaderMap {
    fn from(mut chm: COSEHeaderMap) -> aws_nitro_enclaves_cose::header_map::HeaderMap {
        let mut new = aws_nitro_enclaves_cose::header_map::HeaderMap::new();
        for (key, value) in chm.0.drain() {
            new.insert(serde_cbor::Value::Integer(key as i128), value);
        }
        new
    }
}

impl COSEHeaderMap {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        COSEHeaderMap(std::collections::HashMap::new())
    }

    pub fn insert<T>(&mut self, key: HeaderKeys, value: &T) -> Result<(), Error>
    where
        T: Serialize,
    {
        self.0
            .insert(key as i64, serde_cbor::value::to_value(value)?);
        Ok(())
    }

    fn get<T>(&self, key: &HeaderKeys) -> Result<Option<T>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        match self.0.get(&(*key as i64)) {
            None => Ok(None),
            Some(val) => Ok(Some(serde_cbor::value::from_value(val.clone())?)),
        }
    }
}

const COSESIGN_TAG: u64 = 18;

#[derive(Debug, Clone)]
pub struct COSESign {
    contents: ParsedArray<crate::cborparser::ParsedArraySize4>,

    cached_inner: COSESignInner,
}

impl Serializable for COSESign {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self, Error>
    where
        R: std::io::Read,
    {
        let array = ParsedArray::deserialize_from_reader(reader)?;

        if array.tag() != Some(COSESIGN_TAG) {
            if array.tag().is_none() {
                return Err(Error::InconsistentValue("Missing tag on COSESign"));
            } else {
                return Err(Error::InconsistentValue("Invalid tag on COSESign"));
            }
        }

        // TODO
        let data = array.serialize_data()?;
        let inner = COSESignInner::from_bytes(&data)?;

        Ok(COSESign {
            contents: array,

            cached_inner: inner,
        })
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        // There is no way this data structure should be able to be constructed without either
        // deserializing (which checks the tag) or us constructing it, where we set the tag.
        // Just make sure it's there before serializing.
        if !matches!(self.contents.tag(), Some(COSESIGN_TAG)) {
            return Err(Error::InconsistentValue(
                "Invalid tag on COSESign on serialize_data",
            ));
        }

        self.contents.serialize_to_writer(writer)
    }
}

impl COSESign {
    fn new_from_inner(inner: COSESignInner) -> Result<Self, Error> {
        let mut contents = ParsedArray::deserialize_data(&inner.serialize_data()?)?;
        contents.set_tag(Some(COSESIGN_TAG));

        Ok(COSESign {
            contents,

            cached_inner: inner,
        })
    }

    pub fn new<T>(
        payload: &T,
        unprotected: Option<COSEHeaderMap>,
        sign_key: &dyn SigningPrivateKey,
    ) -> Result<Self, Error>
    where
        T: Serializable,
    {
        let unprotected = match unprotected {
            Some(v) => v,
            None => COSEHeaderMap::new(),
        };
        let payload = payload.serialize_data()?;

        let inner = COSESignInner::new::<Openssl>(&payload, &unprotected.into(), sign_key)?;

        Self::new_from_inner(inner)
    }

    pub fn new_with_protected<T>(
        payload: &T,
        protected: COSEHeaderMap,
        unprotected: Option<COSEHeaderMap>,
        sign_key: &dyn SigningPrivateKey,
    ) -> Result<Self, Error>
    where
        T: Serializable,
    {
        let unprotected = match unprotected {
            Some(v) => v,
            None => COSEHeaderMap::new(),
        };
        let payload = payload.serialize_data()?;

        let (sig_alg, _) = sign_key.get_parameters()?;
        let mut protected: aws_nitro_enclaves_cose::header_map::HeaderMap = protected.into();
        protected.insert(1.into(), (sig_alg as i8).into());

        let inner = COSESignInner::new_with_protected::<Openssl>(
            &payload,
            &protected,
            &unprotected.into(),
            sign_key,
        )?;

        Self::new_from_inner(inner)
    }

    pub fn verify(&self, sign_key: &dyn SigningPublicKey) -> Result<(), Error> {
        if self.cached_inner.verify_signature::<Openssl>(sign_key)? {
            Ok(())
        } else {
            Err(Error::InconsistentValue("Signature verification failed"))
        }
    }

    pub fn from_eat<ES>(
        eat: EATokenPayload<ES>,
        unprotected: Option<COSEHeaderMap>,
        sign_key: &dyn SigningPrivateKey,
    ) -> Result<Self, Error>
    where
        ES: PayloadState,
    {
        let claims = eat.to_map();
        Self::new(&claims.0, unprotected, sign_key)
    }

    pub fn get_payload_unverified<T>(&self) -> Result<UnverifiedValue<T>, Error>
    where
        T: Serializable,
    {
        let payload = self.cached_inner.get_payload::<Openssl>(None)?;
        Ok(UnverifiedValue(T::deserialize_data(&payload)?))
    }

    pub fn get_payload<T>(&self, key: &dyn SigningPublicKey) -> Result<T, Error>
    where
        T: Serializable,
    {
        let payload = self.cached_inner.get_payload::<Openssl>(Some(key))?;
        T::deserialize_data(&payload)
    }

    pub fn get_eat_unverified(&self) -> Result<EATokenPayload<PayloadUnverified>, Error> {
        let claims: COSEHeaderMapType = unsafe { self.get_payload_unverified()?.into_unverified() };
        let claims = COSEHeaderMap(claims);

        eat_from_map(claims)
    }

    pub fn get_eat(
        &self,
        key: &dyn SigningPublicKey,
    ) -> Result<EATokenPayload<PayloadVerified>, Error> {
        let claims: COSEHeaderMapType = self.get_payload(key)?;
        let claims = COSEHeaderMap(claims);

        eat_from_map(claims)
    }

    pub fn get_protected_value_unverified<T>(
        &self,
        header_key: HeaderKeys,
    ) -> Result<Option<UnverifiedValue<T>>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let (protected, _) = self
            .cached_inner
            .get_protected_and_payload::<Openssl>(None)?;
        match protected.get(&header_key.cbor_value()) {
            None => Ok(None),
            Some(val) => Ok(Some(UnverifiedValue(serde_cbor::value::from_value(
                val.clone(),
            )?))),
        }
    }

    pub fn get_protected_value<T>(
        &self,
        header_key: HeaderKeys,
        key: &dyn SigningPublicKey,
    ) -> Result<Option<T>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let (protected, _) = self
            .cached_inner
            .get_protected_and_payload::<Openssl>(Some(key))?;
        match protected.get(&header_key.cbor_value()) {
            None => Ok(None),
            Some(val) => Ok(Some(serde_cbor::value::from_value(val.clone())?)),
        }
    }

    pub fn get_unprotected_value<T>(&self, key: HeaderKeys) -> Result<Option<T>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        match self.cached_inner.get_unprotected().get(&key.cbor_value()) {
            None => Ok(None),
            Some(val) => Ok(Some(serde_cbor::value::from_value(val.clone())?)),
        }
    }
}

#[derive(Debug)]
pub enum RemoteTransport {
    Tcp,
    Tls,
    Http,
    CoAP,
    Https,
    CoAPS,
}

impl Serialize for RemoteTransport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(match self {
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Http => "http",
            Self::CoAP => "coap",
            Self::Https => "https",
            Self::CoAPS => "coaps",
        })
    }
}

impl<'de> Deserialize<'de> for RemoteTransport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RemoteTransportVisitor;

        impl serde::de::Visitor<'_> for RemoteTransportVisitor {
            type Value = RemoteTransport;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(match &v.to_lowercase()[..] {
                    "tcp" => RemoteTransport::Tcp,
                    "tls" => RemoteTransport::Tls,
                    "http" => RemoteTransport::Http,
                    "coap" => RemoteTransport::CoAP,
                    "https" => RemoteTransport::Https,
                    "coaps" => RemoteTransport::CoAPS,
                    _ => {
                        return Err(serde::de::Error::invalid_value(
                            serde::de::Unexpected::Str(v),
                            &"a supported transport type",
                        ))
                    }
                })
            }
        }

        deserializer.deserialize_str(RemoteTransportVisitor)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RemoteAddress {
    IP { ip_address: String },
    Dns { dns_name: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct RemoteConnection {
    transport: RemoteTransport,
    addresses: Vec<RemoteAddress>,
    port: u16,
}

impl RemoteConnection {
    pub fn new(transport: RemoteTransport, addresses: Vec<RemoteAddress>, port: u16) -> Self {
        Self {
            transport,
            addresses,
            port,
        }
    }
}

impl TryFrom<RemoteConnection> for Vec<TO2AddressEntry> {
    type Error = Error;

    fn try_from(rc: RemoteConnection) -> Result<Vec<TO2AddressEntry>, Error> {
        let transport = match rc.transport {
            RemoteTransport::Tcp => TransportProtocol::Tcp,
            RemoteTransport::Tls => TransportProtocol::Tls,
            RemoteTransport::Http => TransportProtocol::Http,
            RemoteTransport::CoAP => TransportProtocol::CoAP,
            RemoteTransport::Https => TransportProtocol::Https,
            RemoteTransport::CoAPS => TransportProtocol::CoAPS,
        };

        let mut results = Vec::new();

        for addr in &rc.addresses {
            match addr {
                RemoteAddress::IP { ip_address } => {
                    let addr = IpAddr::from_str(ip_address)?;
                    results.push(TO2AddressEntry::new(
                        Some(addr.into()),
                        None,
                        rc.port,
                        transport,
                    ));
                }
                RemoteAddress::Dns { dns_name } => {
                    results.push(TO2AddressEntry::new(
                        None,
                        Some(dns_name.clone()),
                        rc.port,
                        transport,
                    ));
                }
            }
        }

        Ok(results)
    }
}
