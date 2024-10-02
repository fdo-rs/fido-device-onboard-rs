use anyhow::{bail, Context, Result};
use config::Config;
use fdo_data_formats::constants::ServiceInfoModule;
use fdo_store::StoreConfig;
use glob::glob;
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_yaml::Value;
use std::env;
use std::path::Path;
use std::result::Result::Ok;

pub mod configuration;
use crate::servers::configuration::serviceinfo_api_server::{
    ServiceInfoApiServerSettings, ServiceInfoSettings,
};

// TODO(runcom): find a better home for this as it's shared between
// owner-onboarding-server and manufacturing-server...
#[non_exhaustive]
pub enum OwnershipVoucherStoreMetadataKey {
    To2Performed,
    To0AcceptOwnerWaitSeconds,
}

impl fdo_store::MetadataLocalKey for OwnershipVoucherStoreMetadataKey {
    fn to_key(&self) -> &'static str {
        match self {
            OwnershipVoucherStoreMetadataKey::To2Performed => "fdo.to2_performed",
            OwnershipVoucherStoreMetadataKey::To0AcceptOwnerWaitSeconds => {
                "fdo.to0_accept_owner_wait_seconds"
            }
        }
    }
}

pub fn settings_for(component: &str) -> Result<config::Config> {
    // the last added source (if available) will be the one being used
    Config::builder()
        .add_source(
            glob(
                &conf_dir_from_env(&format_conf_dir_env(component))
                    .unwrap_or_else(|| format!("/etc/fdo/{component}.conf.d/*.yml")),
            )?
            .map(|path| config::File::from(path.unwrap()))
            .collect::<Vec<_>>(),
        )
        .add_source(
            config::File::from(Path::new(
                &conf_dir_from_env(&format_conf_env(component))
                    .unwrap_or_else(|| format!("/etc/fdo/{component}.yml")),
            ))
            .required(false),
        )
        .add_source(
            config::File::from(Path::new(&format!("/usr/share/fdo/{component}.yml")))
                .required(false),
        )
        .build()
        .context(format!("Loading configuration for {component}"))
}

pub fn settings_per_device(guid: &str) -> Result<ServiceInfoSettings> {
    // here we first check if the requested device has per-device file stored
    // in device_specific_store_driver, if not return error

    let settings: ServiceInfoApiServerSettings = settings_for("serviceinfo-api-server")?
        .try_deserialize()
        .context("Error parsing configuration")?;

    let path_per_device_store = match settings.device_specific_store_driver {
        StoreConfig::Directory { mut path } => {
            let file_name = format!("{}.yml", guid);
            path.push(file_name);
            path.to_string_lossy().into_owned()
        }
        StoreConfig::Sqlite { .. } => {
            bail!("Per-device settings with sqlite database not implemented");
        }
        StoreConfig::Postgres { .. } => {
            bail!("Per-device settings with Postgres database not implemented");
        }
    };
    let config = Config::builder()
        .add_source(config::File::from(Path::new(&path_per_device_store)))
        .build()
        .context(format!(
            "Error loading device specific config file for {path_per_device_store}"
        ))?;
    log::debug!("Loaded device specific config from {path_per_device_store}");
    let per_device_settings = config.try_deserialize::<ServiceInfoSettings>()?;
    log::debug!(
        "device specific serviceinfosettings: initial_user: {:#?} username: {:#?} sshkeys {:#?} files {:#?} commands {:#?}",
        per_device_settings.initial_user,
        per_device_settings
            .initial_user
            .as_ref()
            .map(|user| &user.username),
        per_device_settings
            .initial_user
            .as_ref()
            .map(|user| &user.sshkeys),
        per_device_settings.files,
        per_device_settings.commands
    );
    Ok(per_device_settings)
}

pub fn format_conf_env(component: &str) -> String {
    format!("{}_CONF", component_env_prefix(component))
}

pub fn format_conf_dir_env(component: &str) -> String {
    format!("{}_CONF_DIR", component_env_prefix(component))
}

fn component_env_prefix(component: &str) -> String {
    component.to_string().replace('-', "_").to_uppercase()
}

fn conf_dir_from_env(key: &str) -> Option<String> {
    match env::var_os(key) {
        None => None,
        Some(v) => match v.into_string() {
            Ok(s) => Some(s),
            Err(_) => None,
        },
    }
}

pub fn yaml_to_cbor(val: &Value) -> Result<CborValue> {
    Ok(match val {
        Value::Null => CborValue::Null,
        Value::Bool(b) => CborValue::Bool(*b),
        Value::Number(nr) => {
            if let Some(nr) = nr.as_u64() {
                CborValue::Integer(nr as i128)
            } else if let Some(nr) = nr.as_i64() {
                CborValue::Integer(nr as i128)
            } else if let Some(nr) = nr.as_f64() {
                CborValue::Float(nr)
            } else {
                bail!("Invalid number encountered");
            }
        }
        Value::String(str) => CborValue::Text(str.clone()),
        Value::Sequence(seq) => CborValue::Array(
            seq.iter()
                .map(yaml_to_cbor)
                .collect::<Result<Vec<CborValue>>>()?,
        ),
        Value::Mapping(map) => CborValue::Map(
            map.iter()
                .map(|(key, val)| (yaml_to_cbor(key).unwrap(), yaml_to_cbor(val).unwrap()))
                .collect(),
        ),
        Value::Tagged(_) => bail!("YAML tags are unsupported"),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceInfoApiReplyInitialUser {
    pub username: String,
    pub password: Option<String>,
    pub ssh_keys: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceInfoApiReplyReboot {
    pub reboot: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceInfoApiReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_user: Option<ServiceInfoApiReplyInitialUser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_commands: Option<Vec<(ServiceInfoModule, String, serde_json::Value)>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reboot: Option<ServiceInfoApiReplyReboot>,
}
