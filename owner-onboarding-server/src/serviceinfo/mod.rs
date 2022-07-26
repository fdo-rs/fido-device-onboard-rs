use std::collections::HashSet;

use anyhow::{Context, Error, Result};
use serde::Deserialize;

use fdo_data_formats::{
    constants::HashType,
    messages,
    types::{Hash, ServiceInfo},
};
use fdo_http_wrapper::server::Session;

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceInfoSettings {
    rhsm_organization_id: Option<String>,
    rhsm_activation_key: Option<String>,
    rhsm_run_insights: Option<bool>,

    sshkey_user: Option<String>,
    sshkey_key: Option<String>,

    files: Option<Vec<ServiceInfoFile>>,

    commands: Option<Vec<ServiceInfoCommand>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceInfoFile {
    path: String,
    permissions: Option<String>,
    #[serde(skip)]
    parsed_permissions: Option<u32>,
    source_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceInfoCommand {
    command: String,
    args: Vec<String>,
    #[serde(default)]
    may_fail: bool,
    #[serde(default)]
    return_stdout: bool,
    #[serde(default)]
    return_stderr: bool,
}

#[derive(Debug)]
pub struct ServiceInfoConfiguration {
    settings: ServiceInfoSettings,
}

impl ServiceInfoConfiguration {
    pub(crate) fn from_settings(mut settings: ServiceInfoSettings) -> Result<Self> {
        // Perform checks on the configuration

        // Check permissions for files are valid
        settings.files = if let Some(files) = settings.files {
            let mut new_files = Vec::new();

            for mut file in files {
                let path = &file.path;

                file.parsed_permissions = if let Some(permissions) = &file.permissions {
                    Some(u32::from_str_radix(permissions, 8).with_context(|| {
                        format!(
                            "Invalid permission string for file {}: {} (invalid octal)",
                            path, permissions
                        )
                    })?)
                } else {
                    None
                };

                new_files.push(file);
            }

            Some(new_files)
        } else {
            None
        };

        Ok(ServiceInfoConfiguration { settings })
    }
}

pub(crate) async fn perform_service_info(
    user_data: super::OwnerServiceUDT,
    _session: &mut Session,
    msg: messages::v11::to2::DeviceServiceInfo,
    loop_num: u32,
) -> Result<messages::v11::to2::OwnerServiceInfo, Error> {
    let in_si = msg.service_info();
    let mut out_si = ServiceInfo::new();
    let is_done = loop_num != 0;

    log::trace!("Received ServiceInfo loop {}: {:?}", loop_num, in_si);

    for (module, var, value) in in_si.iter() {
        log::trace!("Received module {}, var {}, value {:?}", module, var, value);
        if module == "devmod" && var == "modules" {
            let mut rawmodlist: Vec<serde_cbor::Value> = serde_cbor::value::from_value(value)?;
            log::trace!("Received module list: {:?}", rawmodlist);

            // Skip the first two items.... They are integers :()
            let mut modlist: HashSet<String> = HashSet::new();
            for rawmod in rawmodlist.drain(..).skip(2) {
                modlist.insert(serde_cbor::value::from_value(rawmod)?);
            }
            log::trace!("Module list: {:?}", modlist);

            if modlist.contains("sshkey")
                && user_data
                    .service_info_configuration
                    .settings
                    .sshkey_user
                    .is_some()
            {
                log::trace!("Found SSH key module, sending SSH key information");

                out_si.add("sshkey", "active", &true)?;
                out_si.add(
                    "sshkey",
                    "username",
                    &user_data
                        .service_info_configuration
                        .settings
                        .sshkey_user
                        .as_ref()
                        .unwrap(),
                )?;
                out_si.add(
                    "sshkey",
                    "key",
                    &user_data
                        .service_info_configuration
                        .settings
                        .sshkey_key
                        .as_ref()
                        .unwrap(),
                )?;
            }

            if modlist.contains("rhsm")
                && user_data
                    .service_info_configuration
                    .settings
                    .rhsm_organization_id
                    .is_some()
            {
                log::trace!("Found RHSM module, sending RHSM information");

                out_si.add("rhsm", "active", &true)?;
                out_si.add(
                    "rhsm",
                    "organization_id",
                    &user_data
                        .service_info_configuration
                        .settings
                        .rhsm_organization_id
                        .as_ref()
                        .unwrap(),
                )?;
                out_si.add(
                    "rhsm",
                    "activation_key",
                    &user_data
                        .service_info_configuration
                        .settings
                        .rhsm_activation_key
                        .as_ref()
                        .unwrap(),
                )?;
                out_si.add(
                    "rhsm",
                    "perform_insights",
                    &user_data
                        .service_info_configuration
                        .settings
                        .rhsm_run_insights
                        .as_ref()
                        .unwrap(),
                )?;
            }

            if modlist.contains("binaryfile") {
                if let Some(files) = &user_data.service_info_configuration.settings.files {
                    log::trace!("Found binaryfile module, sending files");

                    out_si.add("binaryfile", "active", &true)?;
                    for file in files {
                        let contents = std::fs::read(&file.source_path)?;
                        let hash = Hash::from_data(HashType::Sha384, &contents)?;

                        out_si.add("binaryfile", "name", &file.path)?;
                        out_si.add("binaryfile", "length", &contents.len())?;
                        if let Some(parsed_permissions) = file.parsed_permissions {
                            out_si.add("binaryfile", "mode", &parsed_permissions)?;
                        }
                        out_si.add("binaryfile", "data001", &serde_bytes::Bytes::new(&contents))?;
                        out_si.add("binaryfile", "sha-384", &hash.value_bytes())?;
                    }
                }
            }

            if modlist.contains("command") {
                if let Some(commands) = &user_data.service_info_configuration.settings.commands {
                    log::trace!("Found command module, sending commands");

                    out_si.add("command", "active", &true)?;
                    for command in commands {
                        out_si.add("command", "command", &command.command)?;
                        out_si.add("command", "args", &command.args)?;
                        out_si.add("command", "may_fail", &command.may_fail)?;
                        out_si.add("command", "return_stdout", &command.return_stdout)?;
                        out_si.add("command", "return_stderr", &command.return_stderr)?;
                        out_si.add("command", "execute", &true)?;
                    }
                }
            }
        }
    }

    log::trace!("Sending ServiceInfo loop {}: {:?}", loop_num, out_si);
    Ok(messages::v11::to2::OwnerServiceInfo::new(
        false, is_done, out_si,
    ))
}
