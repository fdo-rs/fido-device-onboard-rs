use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum HashType {
    Sha256 = 8,
    Sha384 = 14,
    HmacSha256 = 5,
    HmacSha384 = 6,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
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
    ClientCertHash = 7,
    UserInput = 8,
    WifiSsid = 9,
    WifiPw = 10,
    Medium = 11,
    Protocol = 12,
    Delaysec = 13,
}
