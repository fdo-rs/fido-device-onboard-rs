use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

use crate::{errors::Result, types::CborSimpleType, Error};

use openssl::{
    hash::{hash, DigestBytes, MessageDigest},
    nid::Nid,
};
use serde_cbor::Value;
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum HashType {
    Sha256 = 8,
    Sha384 = 14,
    HmacSha256 = 5,
    HmacSha384 = 6,
}

impl TryFrom<HashType> for MessageDigest {
    type Error = Error;

    fn try_from(ht: HashType) -> Result<MessageDigest> {
        match ht {
            HashType::Sha256 => Ok(MessageDigest::sha256()),
            HashType::Sha384 => Ok(MessageDigest::sha384()),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

impl TryFrom<MessageDigest> for HashType {
    type Error = Error;

    fn try_from(md: MessageDigest) -> Result<HashType> {
        match md.type_() {
            // TODO
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, Eq, PartialEq)]
#[repr(i8)]
#[non_exhaustive]
pub enum DeviceSigType {
    StSECP256R1 = (aws_nitro_enclaves_cose::sign::SignatureAlgorithm::ES256 as i8),
    StSECP384R1 = (aws_nitro_enclaves_cose::sign::SignatureAlgorithm::ES384 as i8),
    // StRSA2048 = RS256,
    // StRSA3072 = RS384,
    StEPID10 = 90,
    StEPID11 = 91,
    StEPID20 = 92,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(i8)]
#[non_exhaustive]
pub enum PublicKeyType {
    // Rsa2048RESTR = RS256,
    // Rsa = RS384,
    SECP256R1 = (aws_nitro_enclaves_cose::sign::SignatureAlgorithm::ES256 as i8),
    SECP384R1 = (aws_nitro_enclaves_cose::sign::SignatureAlgorithm::ES384 as i8),
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum PublicKeyEncoding {
    Crypto = 0,
    X509 = 1,
    COSEX509 = 2,
    COSEKEY = 3,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
//#[derive(PartialEq, Eq)]
#[repr(i64)]
#[non_exhaustive]
pub enum HeaderKeys {
    CUPHNonce = -17760701,       // IANA Pending
    CUPHOwnerPubKey = -17760702, // IANA Pending
}

impl HeaderKeys {
    pub const EUPHNonce: HeaderKeys = HeaderKeys::CUPHNonce;
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(i64)]
#[non_exhaustive]
pub enum CryptoTypes {
    CoseAES128CBC = -17760703, // IANA Pending
    CoseAES128CTR = -17760704, // IANA Pending
    CoseAES256CBC = -17760705, // IANA Pending
    CoseAES256CTR = -17760706, // IANA Pending
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum TransportProtocol {
    TCP = 1,
    TLS = 2,
    HTTP = 3,
    CoAP = 4,
    HTTPS = 5,
    CoAPS = 6,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum RendezvousVariable {
    DeviceOnly = 0,
    OwnerOnly = 1,
    IPAddress = 2,
    DevicePort = 3,
    OwnerPort = 4,
    Dns = 5,
    ServerCertHash = 6,
    CaCertHash = 7,
    UserInput = 8,
    WifiSsid = 9,
    WifiPw = 10,
    Medium = 11,
    Protocol = 12,
    Delaysec = 13,
    Bypass = 14,
    //Extended = 15,
}

impl RendezvousVariable {
    fn name(&self) -> &'static str {
        match self {
            RendezvousVariable::DeviceOnly => "device-only",
            RendezvousVariable::OwnerOnly => "owner-only",
            RendezvousVariable::IPAddress => "ip-address",
            RendezvousVariable::DevicePort => "device-port",
            RendezvousVariable::OwnerPort => "owner-port",
            RendezvousVariable::Dns => "dns",
            RendezvousVariable::ServerCertHash => "server-cert-hash",
            RendezvousVariable::CaCertHash => "ca-cert-hash",
            RendezvousVariable::UserInput => "user-input",
            RendezvousVariable::WifiSsid => "wifi-ssid",
            RendezvousVariable::WifiPw => "wifi-pw",
            RendezvousVariable::Medium => "medium",
            RendezvousVariable::Protocol => "protocol",
            RendezvousVariable::Delaysec => "delay-sec",
            RendezvousVariable::Bypass => "bypass",
        }
    }

    pub fn value_from_human_to_machine(&self, val: serde_cbor::Value) -> Result<serde_cbor::Value> {
        Ok(match self {
            // These are just markers: their existance means they're true
            RendezvousVariable::DeviceOnly
            | RendezvousVariable::OwnerOnly
            | RendezvousVariable::UserInput
            | RendezvousVariable::Bypass => serde_cbor::Value::Null,

            // These are integers
            RendezvousVariable::DevicePort
            | RendezvousVariable::OwnerPort
            | RendezvousVariable::Delaysec => match val {
                serde_cbor::Value::Integer(i) => serde_cbor::Value::Integer(i),
                _ => return Err(Error::InconsistentValue(self.name())),
            },

            // These are strings
            RendezvousVariable::Dns | RendezvousVariable::WifiSsid | RendezvousVariable::WifiPw => {
                match val {
                    serde_cbor::Value::Text(t) => serde_cbor::Value::Text(t),
                    _ => return Err(Error::InconsistentValue(self.name())),
                }
            }

            // Slightly more complicated values
            RendezvousVariable::Protocol => match val {
                serde_cbor::Value::Text(v) => {
                    serde_cbor::value::to_value(RendezvousProtocolValue::from_str(&v)?)?
                }
                _ => return Err(Error::InconsistentValue("protocol (type)")),
            },

            // TODO
            RendezvousVariable::IPAddress => todo!(),
            RendezvousVariable::ServerCertHash => todo!(),
            RendezvousVariable::CaCertHash => todo!(),
            RendezvousVariable::Medium => todo!(),
        })
    }
}

impl FromStr for RendezvousVariable {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match &s.to_lowercase()[..] {
            "deviceonly" | "device_only" => RendezvousVariable::DeviceOnly,
            "owneronly" | "owner_only" => RendezvousVariable::OwnerOnly,
            "ipaddress" | "ip_address" | "ip" => RendezvousVariable::IPAddress,
            "deviceport" | "device_port" => RendezvousVariable::DevicePort,
            "ownerport" | "owner_port" => RendezvousVariable::OwnerPort,
            "dns" => RendezvousVariable::Dns,
            "servercerthash" | "server_cert_hash" => RendezvousVariable::ServerCertHash,
            "cacerthash" | "ca_cert_hash" => RendezvousVariable::CaCertHash,
            "userinput" | "user_input" => RendezvousVariable::UserInput,
            "wifissid" | "wifi_ssid" => RendezvousVariable::WifiSsid,
            "wifipw" | "wifi_pw" => RendezvousVariable::WifiPw,
            "medium" => RendezvousVariable::Medium,
            "protocol" => RendezvousVariable::Protocol,
            "delaysec" | "delay_sec" | "delay" => RendezvousVariable::Delaysec,
            "bypass" => RendezvousVariable::Bypass,
            //"extended" => RendezvousVariable::Extended,
            _ => return Err(Error::InconsistentValue("variable-name")),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum RendezvousProtocolValue {
    Rest = 0,
    HTTP = 1,
    HTTPS = 2,
    TCP = 3,
    TLS = 4,
    CoAPTCP = 5,
    CoAPUDP = 6,
}

impl FromStr for RendezvousProtocolValue {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match &s.to_lowercase()[..] {
            "rest" => RendezvousProtocolValue::Rest,
            "http" => RendezvousProtocolValue::HTTP,
            "https" => RendezvousProtocolValue::HTTPS,
            "tcp" => RendezvousProtocolValue::TCP,
            "tls" => RendezvousProtocolValue::TLS,
            "coaptcp" => RendezvousProtocolValue::CoAPTCP,
            "coapudp" => RendezvousProtocolValue::CoAPUDP,
            _ => return Err(Error::InconsistentValue("protocol")),
        })
    }
}

impl RendezvousProtocolValue {
    pub(crate) fn default_port(&self) -> u32 {
        match self {
            RendezvousProtocolValue::HTTP => 80,
            RendezvousProtocolValue::HTTPS => 443,
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum MessageType {
    // Device Initialization
    DIAppStart = 10,
    DISetCredentials = 11,
    DISetHMAC = 12,
    DIDone = 13,
    // Transfer Ownership protocol 0 (TO0)
    TO0Hello = 20,
    TO0HelloAck = 21,
    TO0OwnerSign = 22,
    TO0AcceptOwner = 23,
    // Transfer Ownership protocol 1 (TO1)
    TO1HelloRV = 30,
    TO1HelloRVAck = 31,
    TO1ProveToRV = 32,
    TO1RVRedirect = 33,
    // Transfer Ownership protocol 2 (TO2)
    TO2HelloDevice = 60,
    TO2ProveOVHdr = 61,
    TO2GetOVNextEntry = 62,
    TO2OVNextEntry = 63,
    TO2ProveDevice = 64,
    TO2SetupDevice = 65,
    TO2DeviceServiceInfoReady = 66,
    TO2OwnerServiceInfoReady = 67,
    TO2DeviceServiceInfo = 68,
    TO2OwnerServiceInfo = 69,
    TO2Done = 70,
    TO2Done2 = 71,
    // Error
    Error = 255,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u16)]
#[non_exhaustive]
pub enum ErrorCode {
    InvalidJWT = 1,
    InvalidOwnershipVoucher = 2,
    InvalidOwnerSignBody = 3,
    InvalidIPAddress = 4,
    InvalidGUID = 5,
    ResourceNotFound = 6,
    MessageBodyError = 100,
    InvalidMessageError = 101,
    CredReuseError = 102,
    InternalServerError = 500,
}
