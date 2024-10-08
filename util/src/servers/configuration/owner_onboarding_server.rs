use fdo_data_formats::types::RemoteConnection;
use fdo_store::StoreConfig;
use serde::{Deserialize, Serialize};

use super::{AbsolutePathBuf, Bind};

#[derive(Debug, Serialize, Deserialize)]
pub struct OwnerOnboardingServerSettings {
    // Ownership Voucher storage info
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub ownership_voucher_store_driver: StoreConfig,

    // Session store info
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub session_store_driver: StoreConfig,

    // Trusted keys
    pub trusted_device_keys_path: Option<AbsolutePathBuf>,

    // Our private owner key
    pub owner_private_key_path: AbsolutePathBuf,
    pub owner_public_key_path: AbsolutePathBuf,

    // Bind information
    pub bind: Bind,

    // Service Info API Server
    pub service_info_api_url: String,
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub service_info_api_authentication: fdo_http_wrapper::client::JsonAuthentication,

    pub owner_addresses: Vec<RemoteConnection>,

    pub report_to_rendezvous_endpoint_enabled: bool,

    pub ov_registration_period: Option<u32>,
    pub ov_re_registration_window: Option<u32>,
}

// 10 minutes
pub const DEFAULT_REGISTRATION_PERIOD: u32 = 600;
// ~1 minute
pub const DEFAULT_RE_REGISTRATION_WINDOW: u32 = 61;
