use std::collections::HashMap;

use fdo_data_formats::constants::ServiceInfoModule;
use fdo_store::StoreConfig;
use serde::{Deserialize, Serialize};

use super::Bind;

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceInfoApiServerSettings {
    pub service_info: ServiceInfoSettings,
    pub bind: Bind,

    pub service_info_auth_token: Option<String>,
    pub admin_auth_token: Option<String>,

    #[serde(with = "serde_yaml::with::singleton_map")]
    pub device_specific_store_driver: StoreConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceInfoSettings {
    pub initial_user: Option<ServiceInfoInitialUser>,

    pub files: Option<Vec<ServiceInfoFile>>,

    pub commands: Option<Vec<ServiceInfoCommand>>,

    pub diskencryption_clevis: Option<Vec<ServiceInfoDiskEncryptionClevis>>,

    pub additional_serviceinfo: Option<HashMap<ServiceInfoModule, Vec<(String, String)>>>,

    pub after_onboarding_reboot: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceInfoDiskEncryptionClevisBinding {
    pub pin: String,
    pub config: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceInfoDiskEncryptionClevis {
    pub disk_label: String,
    pub binding: ServiceInfoDiskEncryptionClevisBinding,
    pub reencrypt: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceInfoFile {
    pub path: String,
    pub permissions: Option<String>,
    #[serde(skip)]
    pub parsed_permissions: Option<u32>,
    #[serde(skip)]
    pub contents_len: usize,
    #[serde(skip)]
    pub contents_hex: String,
    #[serde(skip)]
    pub hash_hex: String,
    pub source_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceInfoCommand {
    pub command: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub may_fail: bool,
    #[serde(default)]
    pub return_stdout: bool,
    #[serde(default)]
    pub return_stderr: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceInfoInitialUser {
    pub username: String,
    pub sshkeys: Vec<String>,
}
