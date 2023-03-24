use std::collections::BTreeMap;

use fdo_data_formats::constants::{KeyStorageType, MfgStringType, PublicKeyType};
use fdo_store::StoreConfig;
use serde::{Deserialize, Serialize};

use super::{AbsolutePathBuf, Bind};

#[derive(Debug, Serialize, Deserialize)]
pub struct ManufacturingServerSettings {
    // Session store info
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub session_store_driver: StoreConfig,

    // Ownership Voucher store info
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub ownership_voucher_store_driver: StoreConfig,

    // Public key store info
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub public_key_store_driver: Option<StoreConfig>,

    // Bind information
    pub bind: Bind,

    pub protocols: ProtocolSetting,

    pub rendezvous_info: Vec<BTreeMap<String, serde_yaml::Value>>,

    pub manufacturing: ManufacturingSettings,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManufacturingSettings {
    pub manufacturer_cert_path: AbsolutePathBuf,
    pub device_cert_ca_private_key: AbsolutePathBuf,
    pub device_cert_ca_chain: AbsolutePathBuf,

    pub owner_cert_path: Option<AbsolutePathBuf>,
    pub manufacturer_private_key: Option<AbsolutePathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolSetting {
    pub plain_di: Option<bool>,
    pub diun: Option<DiunSettings>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiunSettings {
    pub mfg_string_type: MfgStringTypeString,

    pub key_type: PublicKeyTypeString,
    pub allowed_key_storage_types: Vec<KeyStorageTypeString>,

    pub key_path: AbsolutePathBuf,
    pub cert_path: AbsolutePathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum MfgStringTypeString {
    SerialNumber,
    MACAddress,
}

impl From<MfgStringTypeString> for MfgStringType {
    fn from(mfg_string_type: MfgStringTypeString) -> Self {
        match mfg_string_type {
            MfgStringTypeString::SerialNumber => MfgStringType::SerialNumber,
            MfgStringTypeString::MACAddress => MfgStringType::MACAddress,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum PublicKeyTypeString {
    SECP256R1,
    SECP384R1,
}

impl From<PublicKeyTypeString> for PublicKeyType {
    fn from(key_type: PublicKeyTypeString) -> Self {
        match key_type {
            PublicKeyTypeString::SECP256R1 => PublicKeyType::SECP256R1,
            PublicKeyTypeString::SECP384R1 => PublicKeyType::SECP384R1,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum KeyStorageTypeString {
    FileSystem,
    Tpm,
}

impl From<KeyStorageTypeString> for KeyStorageType {
    fn from(key_type: KeyStorageTypeString) -> Self {
        match key_type {
            KeyStorageTypeString::FileSystem => KeyStorageType::FileSystem,
            KeyStorageTypeString::Tpm => KeyStorageType::Tpm,
        }
    }
}
