use fdo_store::StoreConfig;
use serde::{Deserialize, Serialize};

use super::{AbsolutePathBuf, Bind};

#[derive(Debug, Serialize, Deserialize)]
pub struct RendezvousServerSettings {
    // Storage info
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub storage_driver: StoreConfig,

    // Session store info
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub session_store_driver: StoreConfig,

    // Trusted keys
    pub trusted_manufacturer_keys_path: Option<AbsolutePathBuf>,

    // Other info
    pub max_wait_seconds: Option<u32>,

    // Bind information
    pub bind: Bind,
}
