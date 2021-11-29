mod errors;
pub use errors::Error;

const PROTOCOL_MAJOR_VERSION: u16 = 1;
const PROTOCOL_MINOR_VERSION: u16 = 0;
pub const PROTOCOL_VERSION: u16 = (PROTOCOL_MAJOR_VERSION * 100) + PROTOCOL_MINOR_VERSION;

pub mod constants;

pub mod devicecredential;
pub use crate::devicecredential::DeviceCredential;

pub mod types;

pub mod enhanced_types;

pub mod ownershipvoucher;

pub mod publickey;

pub mod messages;

pub mod cborparser;

mod serializable;
pub use serializable::DeserializableMany;
pub use serializable::Serializable;
