use crate::{
    errors::Error,
    types::{Guid, HMac, Hash, RendezvousInfo},
};

pub trait DeviceCredential: std::fmt::Debug {
    fn is_active(&self) -> bool;
    fn protocol_version(&self) -> u16;
    fn verify_hmac(&self, data: &[u8], hmac: &HMac) -> Result<(), Error>;
    fn device_info(&self) -> &str;
    fn device_guid(&self) -> &Guid;
    fn rendezvous_info(&self) -> &RendezvousInfo;
    fn manufacturer_pubkey_hash(&self) -> &Hash;

    fn get_signer(
        &self,
    ) -> Result<Box<dyn aws_nitro_enclaves_cose::crypto::SigningPrivateKey>, Error>;
}

mod file;
pub use crate::devicecredential::file::FileDeviceCredential;
