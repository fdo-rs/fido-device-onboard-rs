use std::{convert::TryInto, ops::Deref, str::FromStr, string::ToString};

use aws_nitro_enclaves_cose::COSESign1 as COSESignInner;
use openssl::pkey::{PKeyRef, Private, Public};
use serde_tuple::Serialize_tuple;

use crate::{
    constants::{DeviceSigType, HashType, HeaderKeys, RendezvousVariable, TransportProtocol},
    errors::Error,
    ownershipvoucher::{OwnershipVoucher, OwnershipVoucherHeader},
    publickey::PublicKey,
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
use openssl_kdf::{Kdf, KdfKbMode, KdfMacType, KdfType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize_tuple, Deserialize, Clone)]
pub struct Hash {
    hash_type: HashType,
    value: Vec<u8>,
}

impl Hash {
    pub fn new(alg: Option<HashType>, data: &[u8]) -> Result<Self, Error> {
        let alg = alg.unwrap_or(HashType::Sha384);

        Ok(Hash {
            hash_type: alg,
            value: hash(alg.try_into()?, data)?.to_vec(),
        })
    }

    pub fn new_from_data(hash_type: HashType, value: Vec<u8>) -> Self {
        Hash { hash_type, value }
    }

    pub fn get_type(&self) -> HashType {
        self.hash_type
    }

    pub fn value(&self) -> &[u8] {
        &self.value
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
}

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        openssl::memcmp::eq(&self.value, &other.value)
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:?})", hex::encode(&self.value), self.hash_type)
    }
}

pub type HMac = Hash;

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct SigInfo {
    sig_type: DeviceSigType, // sgType
    info: Vec<u8>,           // Info
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

fn new_nonce_or_guid_val() -> Result<[u8; 16], Error> {
    let mut val = [0u8; 16];

    openssl::rand::rand_bytes(&mut val)?;

    Ok(val)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Nonce([u8; 16]);

impl Nonce {
    pub fn new() -> Result<Nonce, Error> {
        Ok(Nonce(new_nonce_or_guid_val()?))
    }

    pub fn from_value(val: &[u8]) -> Result<Self, Error> {
        Ok(Nonce(val.try_into().map_err(|_| Error::IncorrectNonce)?))
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

impl ToString for Nonce {
    fn to_string(&self) -> String {
        hex::encode(&self.0)
    }
}

impl FromStr for Nonce {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let decoded = hex::decode(s).unwrap();
        let boxed_slice = decoded.into_boxed_slice();
        let boxed_array: Box<[u8; 16]> = boxed_slice.try_into().unwrap();
        Ok(Nonce(*boxed_array))
    }
}

impl Deref for Nonce {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const EAT_RAND: u8 = 0x01;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
pub struct Guid([u8; 16]);

impl Guid {
    pub fn new() -> Result<Guid, Error> {
        Ok(Guid(new_nonce_or_guid_val()?))
    }

    fn as_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_bytes(self.0)
    }

    fn as_ueid(&self) -> Vec<u8> {
        let mut new: Vec<u8> = self.0.try_into().unwrap();

        new.insert(0, EAT_RAND);

        new
    }

    fn from_ueid(data: &[u8]) -> Result<Self, Error> {
        if data[0] != EAT_RAND {
            Err(Error::InconsistentValue("Invalid UEID"))
        } else {
            Ok(Guid(data[1..].try_into().unwrap()))
        }
    }
}

impl FromStr for Guid {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Guid, uuid::Error> {
        Ok(Guid(uuid::Uuid::from_str(s)?.as_bytes().to_owned()))
    }
}

impl ToString for Guid {
    fn to_string(&self) -> String {
        self.as_uuid().to_string()
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RendezvousInfo(Vec<RendezvousDirective>);

impl RendezvousInfo {
    pub fn new(directives: Vec<RendezvousDirective>) -> RendezvousInfo {
        RendezvousInfo(directives)
    }

    pub fn values(&self) -> &[RendezvousDirective] {
        &self.0
    }
}

pub type RendezvousDirective = Vec<RendezvousInstruction>;
pub type RendezvousInstruction = (RendezvousVariable, CborSimpleType);

// TODO: This sends serde_cbor outwards. Possibly re-do this
pub type CborSimpleType = serde_cbor::Value;

#[derive(Debug, Serialize_tuple, Deserialize)]
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

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct TO0Data {
    ownership_voucher: OwnershipVoucher,
    wait_seconds: u32,
    nonce: Nonce,
}

impl TO0Data {
    pub fn new(ownership_voucher: OwnershipVoucher, wait_seconds: u32, nonce: Nonce) -> Self {
        TO0Data {
            ownership_voucher,
            wait_seconds,
            nonce,
        }
    }

    pub fn ownership_voucher(&self) -> &OwnershipVoucher {
        &self.ownership_voucher
    }

    pub fn wait_seconds(&self) -> u32 {
        self.wait_seconds
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
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
pub struct ServiceInfo(Vec<(String, CborSimpleType)>);

impl ServiceInfo {
    pub fn new() -> Self {
        ServiceInfo(Vec::new())
    }

    pub fn add<T>(&mut self, module: &str, key: &str, value: &T) -> Result<(), Error>
    where
        T: serde::Serialize,
    {
        let value = serde_cbor::value::to_value(&value)?;
        self.0.push((format!("{}:{}", module, key), value));
        Ok(())
    }

    pub fn add_modules(&mut self, modules: &[String]) -> Result<(), Error> {
        self.add("devmod", "nummodules", &modules.len())?;

        // We have a special case of this, becasue this is a list with different types.
        let mut list = Vec::new();

        list.push(serde_cbor::Value::Integer(0));
        list.push(serde_cbor::Value::Integer(modules.len() as i128));
        for module in modules {
            list.push(serde_cbor::Value::Text(module.to_string()));
        }

        self.add("devmod", "modules", &list)
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
                    Ok((module.to_string(), key.to_string(), v.clone()))
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
    type Item = (String, String, CborSimpleType);

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
        Some((module.to_string(), key[1..].to_string(), val.clone()))
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct TO2ProveOVHdrPayload {
    ov_header: OwnershipVoucherHeader,
    num_ov_entries: u16,
    hmac: HMac,
    nonce5: Nonce,
    b_signature_info: SigInfo,
    a_key_exchange: Vec<u8>,
}

impl TO2ProveOVHdrPayload {
    pub fn new(
        ov_header: OwnershipVoucherHeader,
        num_ov_entries: u16,
        hmac: HMac,
        nonce5: Nonce,
        b_signature_info: SigInfo,
        a_key_exchange: Vec<u8>,
    ) -> Self {
        TO2ProveOVHdrPayload {
            ov_header,
            num_ov_entries,
            hmac,
            nonce5,
            b_signature_info,
            a_key_exchange,
        }
    }

    pub fn ov_header(&self) -> &OwnershipVoucherHeader {
        &self.ov_header
    }

    pub fn num_ov_entries(&self) -> u16 {
        self.num_ov_entries
    }

    pub fn hmac(&self) -> &HMac {
        &self.hmac
    }

    pub fn nonce5(&self) -> &Nonce {
        &self.nonce5
    }

    pub fn b_signature_info(&self) -> &SigInfo {
        &self.b_signature_info
    }

    pub fn a_key_exchange(&self) -> &[u8] {
        &self.a_key_exchange
    }
}

#[derive(Debug, Serialize, Deserialize)]
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
                let key = BigNum::from_slice(&key)?;
                let dh_params = suite.get_dh_params()?;
                let key = dh_params.set_private_key(key)?;
                Ok(key.public_key().to_vec())
            }
            KeyExchange::Ecdh(suite, key, our_random) => {
                let ec_group = suite.get_ecdh_group()?;
                let key = EcKey::private_key_from_pem(&key)?;

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

                Ok(self.encode_ecdh_bstr(&public_x, &public_y, &our_random))
            }
        }
    }

    fn encode_ecdh_bstr(&self, ax: &[u8], ay: &[u8], random: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + ax.len() + 2 + ax.len() + 2 + random.len());

        out.extend_from_slice(&(ax.len() as u16).to_be_bytes());
        out.extend_from_slice(&ax);

        out.extend_from_slice(&(ay.len() as u16).to_be_bytes());
        out.extend_from_slice(&ay);

        out.extend_from_slice(&(random.len() as u16).to_be_bytes());
        out.extend_from_slice(&random);

        out
    }

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
            let other = BigNum::from_slice(&other)?;

            let key = BigNum::from_slice(&key)?;
            let dh_params = suite.get_dh_params()?;
            let key = dh_params.set_private_key(key)?;

            Ok((key.compute_key(&other)?, vec![]))
        } else {
            panic!("Invalid derive_key_dh call");
        }
    }

    fn derive_key_ecdh(
        &self,
        our_side: KeyDeriveSide,
        other: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if let KeyExchange::Ecdh(suite, key, our_random) = self {
            let ec_group = suite.get_ecdh_group()?;

            let (other_x, other_y, other_random) = self.decode_ecdh_bstr(&other)?;
            if other_random.len() != suite.get_ecdh_random_size() {
                return Err(Error::KeyExchangeError("Other random is invalid size"));
            }
            let other_x = BigNum::from_slice(&other_x)?;
            let other_y = BigNum::from_slice(&other_y)?;
            let other_pub =
                EcKey::from_public_key_affine_coordinates(&ec_group, &other_x, &other_y)?;
            other_pub.check_key()?;

            let our_key = EcKey::private_key_from_pem(&key)?;

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
                    shared_secret.extend_from_slice(&our_random);
                    shared_secret.extend_from_slice(&other_random);
                }
                KeyDeriveSide::OwnerService => {
                    shared_secret.extend_from_slice(&other_random);
                    shared_secret.extend_from_slice(&our_random);
                }
            }

            Ok((shared_secret, vec![]))
        } else {
            panic!("Invalid derive_key_ecdh call");
        }
    }

    pub fn derive_key(
        &self,
        our_side: KeyDeriveSide,
        cipher: CipherSuite,
        other: &[u8],
    ) -> Result<DerivedKeys, Error> {
        let (shared_secret, context_rand) = match self {
            KeyExchange::Dhkex(..) => self.derive_key_dh(other)?,
            KeyExchange::Ecdh(..) => self.derive_key_ecdh(our_side, other)?,
        };

        let kdf = Kdf::new(KdfType::KeyBased)?;
        kdf.set_kb_mode(KdfKbMode::Counter)?;
        kdf.set_kb_mac_type(KdfMacType::Hmac)?;
        kdf.set_digest(cipher.kdf_digest())?;
        // Label
        kdf.set_salt(&KEY_DERIVE_LABEL)?;
        // Context
        let mut context = Vec::with_capacity(KEY_DERIVE_CONTEXT_PREFIX.len() + context_rand.len());
        context.extend_from_slice(&KEY_DERIVE_CONTEXT_PREFIX);
        context.extend_from_slice(&context_rand);
        kdf.set_kb_info(&context)?;
        // Key
        kdf.set_key(&shared_secret)?;
        let key_out = kdf.derive(cipher.required_keylen())?;

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

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct DeviceCredential {
    pub active: bool,           // Active
    pub protver: u16,           // ProtVer
    pub hmac_secret: Vec<u8>,   // HmacSecret
    pub device_info: String,    // DeviceInfo
    pub guid: Guid,             // Guid
    pub rvinfo: RendezvousInfo, // RVInfo
    pub pubkey_hash: Hash,      // PubKeyHash

    // Custom from here
    pub private_key: Vec<u8>,
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

impl ToString for KexSuite {
    fn to_string(&self) -> String {
        match self {
            KexSuite::Ecdh256 => "ECDH256".to_string(),
            KexSuite::Ecdh384 => "ECDH384".to_string(),
            KexSuite::DhkexId14 => "DHKEXid14".to_string(),
            KexSuite::DhkexId15 => "DHKEXid15".to_string(),
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

        impl<'de> serde::de::Visitor<'de> for KexSuiteVisitor {
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
            KexSuite::Ecdh256 => 128,
            KexSuite::Ecdh384 => 384,
            _ => panic!("Invalid get_ecdh_random_size call"),
        }
    }

    fn get_ecdh_group(&self) -> Result<EcGroup, Error> {
        let curve_name = match self {
            KexSuite::Ecdh256 => Nid::X9_62_PRIME256V1,
            KexSuite::Ecdh384 => Nid::SECP384R1,
            _ => panic!("Invalid get_ecdh_group call"),
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
            _ => panic!("Invalid get_dh_params call"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CipherSuite {
    // Combined ciphers
    A128Gcm,
    A256Gcm,
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
                panic!("Invalid call to split_key_split_pos")
            }
        }
    }

    fn required_keylen(&self) -> usize {
        match self {
            CipherSuite::A128Gcm => 128,
            CipherSuite::A256Gcm => 256,
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

impl ToString for CipherSuite {
    fn to_string(&self) -> String {
        match self {
            CipherSuite::A128Gcm => "A128GCM".to_string(),
            CipherSuite::A256Gcm => "A256GCM".to_string(),
        }
    }
}

impl Serialize for CipherSuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CipherSuite {
    fn deserialize<D>(deserializer: D) -> Result<CipherSuite, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CipherSuiteVisitor;

        impl<'de> serde::de::Visitor<'de> for CipherSuiteVisitor {
            type Value = CipherSuite;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a ciphersuite string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                CipherSuite::from_str(v).map_err(|_| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(v),
                        &"a valid cipher suite",
                    )
                })
            }
        }

        deserializer.deserialize_str(CipherSuiteVisitor)
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

    payload: Option<Vec<u8>>,
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
            Some(val) => Ok(Some(serde_cbor::from_slice(&val)?)),
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
        res.insert(HeaderKeys::EatUeid, &self.device_guid)
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
    let payload = match claims.0.remove(&(HeaderKeys::EatFDO as i64)) {
        None => None,
        Some(val) => Some(serde_cbor::value::from_value(val)?),
    };
    let nonce = match claims.0.remove(&(HeaderKeys::EatNonce as i64)) {
        None => return Err(Error::InconsistentValue("Missing nonce")),
        Some(val) => serde_cbor::value::from_value(val)?,
    };
    let ueid = match claims.0.remove(&(HeaderKeys::EatUeid as i64)) {
        None => return Err(Error::InconsistentValue("Missing UEID")),
        Some(val) => {
            let val: Vec<u8> = serde_cbor::value::from_value(val)?;
            // Just verifying that it's valid
            if Guid::from_ueid(&val).is_err() {
                return Err(Error::InconsistentValue("Invalid UEID"));
            }
            val
        }
    };

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
        Some(payload) => Some(serde_cbor::to_vec(&payload)?),
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

impl From<COSEHeaderMap> for aws_nitro_enclaves_cose::sign::HeaderMap {
    fn from(mut chm: COSEHeaderMap) -> aws_nitro_enclaves_cose::sign::HeaderMap {
        let mut new = aws_nitro_enclaves_cose::sign::HeaderMap::new();
        for (key, value) in chm.0.drain() {
            new.insert(serde_cbor::Value::Integer(key as i128), value);
        }
        new
    }
}

impl COSEHeaderMap {
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct COSESign(COSESignInner);

impl COSESign {
    pub fn new<T>(
        payload: T,
        unprotected: Option<COSEHeaderMap>,
        sign_key: &PKeyRef<Private>,
    ) -> Result<Self, Error>
    where
        T: Serialize,
    {
        let unprotected = match unprotected {
            Some(v) => v,
            None => COSEHeaderMap::new(),
        };
        let payload = serde_cbor::to_vec(&payload)?;
        Ok(COSESign(COSESignInner::new(
            &payload,
            &unprotected.into(),
            sign_key,
        )?))
    }

    pub fn from_eat<ES>(
        eat: EATokenPayload<ES>,
        unprotected: Option<COSEHeaderMap>,
        sign_key: &PKeyRef<Private>,
    ) -> Result<Self, Error>
    where
        ES: PayloadState,
    {
        let claims = eat.to_map();
        Self::new(claims.0, unprotected, sign_key)
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.0.as_bytes(true)?)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        Ok(COSESign(COSESignInner::from_bytes(data)?))
    }

    pub fn get_payload_unverified<T>(&self) -> Result<UnverifiedValue<T>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let payload = self.0.get_payload(None)?;
        Ok(UnverifiedValue(serde_cbor::from_slice(&payload)?))
    }

    pub fn get_payload<T>(&self, key: &PKeyRef<Public>) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let payload = self.0.get_payload(Some(key))?;
        Ok(serde_cbor::from_slice(&payload)?)
    }

    pub fn get_eat_unverified(&self) -> Result<EATokenPayload<PayloadUnverified>, Error> {
        let claims: COSEHeaderMapType = unsafe { self.get_payload_unverified()?.into_unverified() };
        let claims = COSEHeaderMap(claims);

        eat_from_map(claims)
    }

    pub fn get_eat(&self, key: &PKeyRef<Public>) -> Result<EATokenPayload<PayloadVerified>, Error> {
        let claims: COSEHeaderMapType = self.get_payload(key)?;
        let claims = COSEHeaderMap(claims);

        eat_from_map(claims)
    }

    pub fn get_unprotected_value<T>(&self, key: HeaderKeys) -> Result<Option<T>, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        match self.0.get_unprotected().get(&key.cbor_value()) {
            None => Ok(None),
            Some(val) => Ok(Some(serde_cbor::value::from_value(val.clone())?)),
        }
    }
}
