mod errors;
pub use errors::Error;

pub mod constants;
pub use constants::ProtocolVersion;

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

#[cfg(feature = "use_noninteroperable_kdf")]
pub const INTEROPERABLE_KDF: bool = false;
#[cfg(not(feature = "use_noninteroperable_kdf"))]
pub const INTEROPERABLE_KDF: bool = true;
