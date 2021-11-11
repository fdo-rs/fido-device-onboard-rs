use glob::glob;
use std::env;
use std::path::Path;

use anyhow::{Context, Result};

// TODO(runcom): find a better home for this as it's shared between
// owner-onboarding-server and manufacturing-server...
#[non_exhaustive]
pub enum OwnershipVoucherStoreMetadataKey {
    To2Performed,
}

impl fdo_store::MetadataLocalKey for OwnershipVoucherStoreMetadataKey {
    fn to_key(&self) -> &'static str {
        match self {
            OwnershipVoucherStoreMetadataKey::To2Performed => "user.fdo.to2_performed",
        }
    }
}

pub fn settings_for(component: &str) -> Result<config::Config> {
    Ok(config::Config::default()
        .merge(
            config::File::from(Path::new(&format!("/usr/fdo/{}.yml", component))).required(false),
        )
        .context("Loading configuration file from /usr/fdo")?
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
    component.to_string().replace("-", "_").to_uppercase()
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
