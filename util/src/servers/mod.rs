use fdo_data_formats::constants::ServiceInfoModule;
use glob::glob;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;

use anyhow::{bail, Context, Result};

use serde_cbor::Value as CborValue;
use serde_yaml::Value;

pub mod configuration;

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
    Ok(config::Config::default()
        .merge(
            config::File::from(Path::new(&format!("/usr/share/fdo/{}.yml", component)))
                .required(false),
        )
        .context("Loading configuration file from /usr/share/fdo")?
        .merge(
            config::File::from(Path::new(
                &conf_dir_from_env(&format_conf_env(component))
                    .unwrap_or_else(|| format!("/etc/fdo/{}.yml", component)),
            ))
            .required(false),
        )
        .context("Loading configuration file from /etc/fdo")?
        .merge(
            glob(
                &conf_dir_from_env(&format_conf_dir_env(component))
                    .unwrap_or_else(|| format!("/etc/fdo/{}.conf.d/*.yml", component)),
            )?
            .map(|path| config::File::from(path.unwrap()))
            .collect::<Vec<_>>(),
        )
        .context("Loading configuration files from conf.d")?
        .clone())
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
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceInfoApiReplyInitialUser {
    pub username: String,
    pub ssh_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceInfoApiReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_user: Option<ServiceInfoApiReplyInitialUser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_commands: Option<Vec<(ServiceInfoModule, String, serde_json::Value)>>,
}
