use crate::{
    errors::Error,
    types::HMac,
    types::{Guid, Hash, RendezvousInfo},
    DeviceCredential,
};

use openssl::{pkey::PKey, sign::Signer};
use serde::Deserialize;
use serde_tuple::Serialize_tuple;

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct FileDeviceCredential {
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

impl DeviceCredential for FileDeviceCredential {
    fn is_active(&self) -> bool {
        self.active
    }

    fn protocol_version(&self) -> u16 {
        self.protver
    }

    fn verify_hmac(&self, data: &[u8], hmac: &HMac) -> Result<(), Error> {
        let hmac_type = hmac.get_type();

        let hmac_key = PKey::hmac(&self.hmac_secret)?;
        let mut hmac_signer = Signer::new(hmac_type.get_md(), &hmac_key)?;
        hmac_signer.update(data)?;
        let ov_hmac = hmac_signer.sign_to_vec()?;
        let ov_hmac = HMac::new_from_data(hmac_type, ov_hmac);

        if &ov_hmac != hmac {
            Err(Error::IncorrectHash)
        } else {
            Ok(())
        }
    }

    fn device_info(&self) -> &str {
        &self.device_info
    }

    fn device_guid(&self) -> &Guid {
        &self.guid
    }

    fn rendezvous_info(&self) -> &RendezvousInfo {
        &self.rvinfo
    }

    fn manufacturer_pubkey_hash(&self) -> &Hash {
        &self.pubkey_hash
    }

    fn get_signer(
        &self,
    ) -> Result<Box<dyn aws_nitro_enclaves_cose::crypto::SigningPrivateKey>, Error> {
        Ok(Box::new(PKey::private_key_from_der(&self.private_key)?))
    }
}
