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

pub mod serializable;
pub use serializable::DeserializableMany;
pub use serializable::Serializable;

pub fn interoperable_kdf_available() -> bool {
    #[cfg(feature = "use_noninteroperable_kdf")]
    {
        false
    }
    #[cfg(not(feature = "use_noninteroperable_kdf"))]
    {
        if std::env::var("FORCE_NONINTEROPERABLE_KDF").is_ok() {
            log::warn!("Forcing the use of non-interoperable KDF via environment variable");
            false
        } else {
            true
        }
    }
}
