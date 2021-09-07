use std::convert::TryFrom;
use std::str::FromStr;

use crate::{errors::Result, Error};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use openssl::hash::MessageDigest;
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(i8)]
#[non_exhaustive]
pub enum HashType {
    Sha256 = -16,
    Sha384 = -43,
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

impl HashType {
    pub fn get_md(&self) -> MessageDigest {
        match self {
            HashType::Sha256 => MessageDigest::sha256(),
            HashType::Sha384 => MessageDigest::sha384(),
            HashType::HmacSha256 => MessageDigest::sha256(),
            HashType::HmacSha384 => MessageDigest::sha384(),
        }
    }

    pub fn guess_from_length(len: usize) -> Option<Self> {
        match len {
            32 => Some(HashType::Sha256),
            48 => Some(HashType::Sha384),
            _ => None,
        }
    }
}

impl TryFrom<MessageDigest> for HashType {
    type Error = Error;

    fn try_from(md: MessageDigest) -> Result<HashType> {
        #[allow(clippy::match_single_binding)]
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
    Cosekey = 3,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
//#[derive(PartialEq, Eq)]
#[repr(i64)]
#[non_exhaustive]
pub enum HeaderKeys {
    EatNonce = 9,
    EatUeid = 10,

    CUPHNonce = -17760701,       // IANA Pending
    CUPHOwnerPubKey = -17760702, // IANA Pending

    EatFDO = -17760707,
}

impl HeaderKeys {
    pub(crate) fn cbor_value(&self) -> serde_cbor::Value {
        serde_cbor::Value::Integer(*self as i128)
    }
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
    Tcp = 1,
    Tls = 2,
    Http = 3,
    CoAP = 4,
    Https = 5,
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
    Http = 1,
    Https = 2,
    Tcp = 3,
    Tls = 4,
    CoAPTCP = 5,
    CoAPUDP = 6,
}

impl FromStr for RendezvousProtocolValue {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match &s.to_lowercase()[..] {
            "rest" => RendezvousProtocolValue::Rest,
            "http" => RendezvousProtocolValue::Http,
            "https" => RendezvousProtocolValue::Https,
            "tcp" => RendezvousProtocolValue::Tcp,
            "tls" => RendezvousProtocolValue::Tls,
            "coaptcp" => RendezvousProtocolValue::CoAPTCP,
            "coapudp" => RendezvousProtocolValue::CoAPUDP,
            _ => return Err(Error::InconsistentValue("protocol")),
        })
    }
}

impl RendezvousProtocolValue {
    pub(crate) fn default_port(&self) -> u32 {
        match self {
            RendezvousProtocolValue::Http => 80,
            RendezvousProtocolValue::Https => 443,
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, FromPrimitive, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum MessageType {
    Invalid = 0,

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

    // Custom: DIUN
    DIUNConnect = 210,
    DIUNAccept = 211,
    DIUNRequestKeyParameters = 212,
    DIUNProvideKeyParameters = 213,
    DIUNProvideKey = 214,
    DIUNDone = 215,

    // Error
    Error = 255,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> std::result::Result<Self, ()> {
        match MessageType::from_u8(value) {
            Some(v) => Ok(v),
            None => Err(()),
        }
    }
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

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(i8)]
#[non_exhaustive]
pub enum MfgStringType {
    SerialNumber = 0,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(i8)]
#[non_exhaustive]
pub enum KeyStorageType {
    FileSystem = 0,
    Tpm = 1,
}
