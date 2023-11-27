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
    pub trusted_device_keys_path: AbsolutePathBuf,

    // Our private owner key
    pub owner_private_key_path: AbsolutePathBuf,
    pub owner_public_key_path: AbsolutePathBuf,
    pub owner_server_https_cert: AbsolutePathBuf,
    pub owner_server_https_key: AbsolutePathBuf,

    // Bind information
    pub bind_http: Bind,
    pub bind_https: Bind,

    // Service Info API Server
    pub service_info_api_url: String,
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub service_info_api_authentication: fdo_http_wrapper::client::JsonAuthentication,

    pub owner_addresses: Vec<RemoteConnection>,

    pub report_to_rendezvous_endpoint_enabled: bool,
}
