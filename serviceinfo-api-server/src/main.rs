use std::{collections::HashSet, str::FromStr};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::signal::unix::{signal, SignalKind};
use warp::Filter;

use fdo_data_formats::{
    constants::{FedoraIotServiceInfoModule, HashType, ServiceInfoModule},
    types::{Guid, Hash},
};
use fdo_store::Store;
use fdo_util::servers::{
    configuration::serviceinfo_api_server::{ServiceInfoApiServerSettings, ServiceInfoSettings},
    settings_for, ServiceInfoApiReply, ServiceInfoApiReplyInitialUser, ServiceInfoApiReplyReboot,
};

#[derive(Debug)]
struct ServiceInfoConfiguration {
    settings: ServiceInfoSettings,
}

impl ServiceInfoConfiguration {
    fn from_settings(mut settings: ServiceInfoSettings) -> Result<Self> {
        // Perform checks on the configuration

        // Check permissions for files are valid
        settings.files = if let Some(files) = settings.files {
            let mut new_files = Vec::new();

            for mut file in files {
                let path = &file.path;

                file.parsed_permissions = if let Some(permissions) = &file.permissions {
                    Some(u32::from_str_radix(permissions, 8).with_context(|| {
                        format!(
                            "Invalid permission string for file {path}: {permissions} (invalid octal)"
                        )
                    })?)
                } else {
                    None
                };

                let contents = std::fs::read(&file.source_path)
                    .with_context(|| format!("Failed to read file {}", file.source_path))?;
                file.hash_hex = hex::encode(
                    Hash::from_data(HashType::Sha384, &contents)
                        .with_context(|| format!("Failed to hash file {}", file.source_path))?
                        .value_bytes(),
                );
                file.contents_len = contents.len();
                file.contents_hex = hex::encode(&contents);

                new_files.push(file);
            }

            Some(new_files)
        } else {
            None
        };

        Ok(ServiceInfoConfiguration { settings })
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
enum ServiceInfoMetadataKey {}

impl fdo_store::MetadataLocalKey for ServiceInfoMetadataKey {
    fn to_key(&self) -> &'static str {
        match *self {}
    }
}

type ServiceInfoStoreData = Vec<(ServiceInfoModule, String, serde_json::Value)>;

struct ServiceInfoApiServerUD {
    // Stores
    device_specific_store: Box<
        dyn Store<fdo_store::ReadWriteOpen, Guid, ServiceInfoStoreData, ServiceInfoMetadataKey>,
    >,

    // Auth Info
    service_info_auth_token: Option<String>,
    admin_auth_token: Option<String>,

    // Basic Service Info configuration
    service_info_configuration: ServiceInfoConfiguration,
}

type ServiceInfoApiServerUDT = std::sync::Arc<ServiceInfoApiServerUD>;

#[derive(Debug, Default)]
struct ServiceInfoApiReplyBuilder {
    enabled_modules: std::collections::HashSet<ServiceInfoModule>,
    reply: ServiceInfoApiReply,
}

impl ServiceInfoApiReplyBuilder {
    fn add_extra<T, MT>(&mut self, module: MT, command: &str, argument: &T)
    where
        T: serde::Serialize,
        MT: Into<ServiceInfoModule>,
    {
        let module: ServiceInfoModule = module.into();

        if self.reply.extra_commands.is_none() {
            self.reply.extra_commands = Some(Vec::new());
        }
        if !self.enabled_modules.contains(&module) {
            self.enabled_modules.insert(module.clone());
            self.reply.extra_commands.as_mut().unwrap().push((
                module.clone(),
                "active".to_string(),
                serde_json::Value::Bool(true),
            ));
        }

        self.reply.extra_commands.as_mut().unwrap().push((
            module,
            command.to_string(),
            serde_json::to_value(argument).expect("Error converting to json value"),
        ));
    }
}

async fn admin_auth_handler(
    user_data: ServiceInfoApiServerUDT,
    auth_header: String,
) -> Result<ServiceInfoApiServerUDT, warp::Rejection> {
    match &user_data.admin_auth_token {
        None => {
            log::warn!("Admin API server disabled");
            return Err(warp::reject::reject());
        }
        Some(token) => {
            if token != &auth_header {
                log::warn!("Request with invalid auth token");
                return Err(warp::reject::reject());
            }
        }
    }

    Ok(user_data)
}

#[derive(Debug, Deserialize)]
struct AdminV0Request {
    #[serde(deserialize_with = "deserialize_from_str")]
    device_guid: fdo_data_formats::types::Guid,
    service_info: Vec<(ServiceInfoModule, String, serde_json::Value)>,
}

#[derive(Debug, Serialize)]
struct AdminV0Reply {
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,

    success: bool,
}

async fn admin_v0_handler(
    user_data: ServiceInfoApiServerUDT,
    request_info: AdminV0Request,
) -> Result<warp::reply::Json, warp::Rejection> {
    match user_data
        .device_specific_store
        .store_data(request_info.device_guid, request_info.service_info)
        .await
    {
        Ok(_) => Ok(warp::reply::json(&AdminV0Reply {
            error: None,
            success: true,
        })),
        Err(e) => Ok(warp::reply::json(&AdminV0Reply {
            error: Some(e.to_string()),
            success: false,
        })),
    }
}

async fn serviceinfo_auth_handler(
    user_data: ServiceInfoApiServerUDT,
    auth_header: String,
) -> Result<ServiceInfoApiServerUDT, warp::Rejection> {
    match &user_data.service_info_auth_token {
        None => {
            log::trace!("service_info_auth_token is disabled");
            return Ok(user_data);
        }
        Some(token) => {
            if token != &auth_header {
                log::warn!("Request with invalid auth token");
                return Err(warp::reject::reject());
            }
        }
    }

    Ok(user_data)
}

async fn serviceinfo_handler(
    user_data: ServiceInfoApiServerUDT,
    query_info: QueryInfo,
) -> Result<warp::reply::Json, warp::Rejection> {
    if query_info.api_version != 1 {
        log::warn!(
            "Unsupported API version {} requested",
            query_info.api_version
        );
        return Err(warp::reject::reject());
    }
    log::info!(
        "ServiceInfo (api version {}) request for device {:?}, modules {:?}",
        query_info.api_version,
        query_info.device_guid,
        query_info.modules
    );

    let mut reply: ServiceInfoApiReplyBuilder = Default::default();

    if query_info
        .modules
        .contains(&FedoraIotServiceInfoModule::SSHKey.into())
    {
        if let Some(initial_user) = &user_data.service_info_configuration.settings.initial_user {
            reply.reply.initial_user = Some(ServiceInfoApiReplyInitialUser {
                username: initial_user.username.clone(),
                ssh_keys: initial_user.sshkeys.clone(),
            });
        }
    }

    if query_info
        .modules
        .contains(&FedoraIotServiceInfoModule::BinaryFile.into())
    {
        if let Some(files) = &user_data.service_info_configuration.settings.files {
            for file in files {
                reply.add_extra(FedoraIotServiceInfoModule::BinaryFile, "name", &file.path);
                reply.add_extra(
                    FedoraIotServiceInfoModule::BinaryFile,
                    "length",
                    &file.contents_len,
                );
                if let Some(parsed_permissions) = &file.parsed_permissions {
                    reply.add_extra(
                        FedoraIotServiceInfoModule::BinaryFile,
                        "mode",
                        &parsed_permissions,
                    );
                }
                reply.add_extra(
                    FedoraIotServiceInfoModule::BinaryFile,
                    "data001|hex",
                    &file.contents_hex,
                );
                reply.add_extra(
                    FedoraIotServiceInfoModule::BinaryFile,
                    "sha-384|hex",
                    &file.hash_hex,
                );
            }
        }
    }

    if query_info
        .modules
        .contains(&FedoraIotServiceInfoModule::Command.into())
    {
        if let Some(commands) = &user_data.service_info_configuration.settings.commands {
            for command in commands {
                reply.add_extra(
                    FedoraIotServiceInfoModule::Command,
                    "command",
                    &command.command,
                );
                reply.add_extra(FedoraIotServiceInfoModule::Command, "args", &command.args);
                reply.add_extra(
                    FedoraIotServiceInfoModule::Command,
                    "may_fail",
                    &command.may_fail,
                );
                reply.add_extra(
                    FedoraIotServiceInfoModule::Command,
                    "return_stdout",
                    &command.return_stdout,
                );
                reply.add_extra(
                    FedoraIotServiceInfoModule::Command,
                    "return_stderr",
                    &command.return_stderr,
                );
                reply.add_extra(FedoraIotServiceInfoModule::Command, "execute", &true);
            }
        }
    }

    if query_info
        .modules
        .contains(&FedoraIotServiceInfoModule::DiskEncryptionClevis.into())
    {
        if let Some(disk_encryptions) = &user_data
            .service_info_configuration
            .settings
            .diskencryption_clevis
        {
            for encryption in disk_encryptions {
                reply.add_extra(
                    FedoraIotServiceInfoModule::DiskEncryptionClevis,
                    "disk-label",
                    &encryption.disk_label,
                );
                reply.add_extra(
                    FedoraIotServiceInfoModule::DiskEncryptionClevis,
                    "pin",
                    &encryption.binding.pin,
                );
                reply.add_extra(
                    FedoraIotServiceInfoModule::DiskEncryptionClevis,
                    "config",
                    &encryption.binding.config,
                );
                reply.add_extra(
                    FedoraIotServiceInfoModule::DiskEncryptionClevis,
                    "reencrypt",
                    &encryption.reencrypt,
                );
                reply.add_extra(
                    FedoraIotServiceInfoModule::DiskEncryptionClevis,
                    "execute",
                    &serde_json::Value::Null,
                );
            }
        }
    }

    if query_info
        .modules
        .contains(&FedoraIotServiceInfoModule::Reboot.into())
    {
        if let Some(reboot) = &user_data
            .service_info_configuration
            .settings
            .after_onboarding_reboot
        {
            reply.reply.reboot = Some(ServiceInfoApiReplyReboot {
                reboot: reboot.to_owned(),
            })
        }
    }

    if let Some(additional_serviceinfo) = &user_data
        .service_info_configuration
        .settings
        .additional_serviceinfo
    {
        for (module, serviceinfo_lines) in additional_serviceinfo {
            if query_info.modules.contains(module) {
                for (key, value) in serviceinfo_lines {
                    reply.add_extra(module.clone(), key, value);
                }
            }
        }
    }

    let device_specific_info = match user_data
        .device_specific_store
        .load_data(&query_info.device_guid)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            log::warn!("Error loading device specific store: {:?}", e);
            return Err(warp::reject::reject());
        }
    };
    if let Some(device_specific_info) = device_specific_info {
        log::trace!("Loaded device-specific information");
        for (module, key, value) in device_specific_info {
            reply.add_extra(module, &key, &value);
        }
    }

    Ok(warp::reply::json(&reply.reply))
}

fn deserialize_from_str<'de, D>(deserializer: D) -> Result<fdo_data_formats::types::Guid, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    FromStr::from_str(&s).map_err(serde::de::Error::custom)
}

fn deserialize_from_comma_separated_strings<'de, D>(
    deserializer: D,
) -> Result<HashSet<ServiceInfoModule>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(s.split(',')
        .map(|s| ServiceInfoModule::from_str(s).unwrap())
        .collect())
}

#[derive(Debug, Deserialize)]
struct QueryInfo {
    #[serde(rename = "serviceinfo_api_version")]
    api_version: u32,
    #[serde(deserialize_with = "deserialize_from_str")]
    device_guid: fdo_data_formats::types::Guid,
    #[serde(deserialize_with = "deserialize_from_comma_separated_strings")]
    modules: HashSet<ServiceInfoModule>,
}

#[tokio::main]
async fn main() -> Result<()> {
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

    let settings: ServiceInfoApiServerSettings = settings_for("serviceinfo-api-server")?
        .try_deserialize()
        .context("Error parsing configuration")?;

    // Bind information
    let bind_addr = settings.bind.clone();

    // ServiceInfo settings
    let service_info_configuration = ServiceInfoConfiguration::from_settings(settings.service_info)
        .context("Error preparing ServiceInfo configuration")?;

    let device_specific_store = settings
        .device_specific_store_driver
        .initialize()
        .context("Error initializing device-specific store")?;

    let user_data = std::sync::Arc::new(ServiceInfoApiServerUD {
        service_info_configuration,

        device_specific_store,

        service_info_auth_token: settings
            .service_info_auth_token
            .map(|s| format!("Bearer {s}")),
        admin_auth_token: settings.admin_auth_token.map(|s| format!("Bearer {s}")),
    });
    let ud_si = user_data.clone();
    let ud_admin = user_data.clone();

    let serviceinfo = warp::path("device_info")
        .map(move || ud_si.clone())
        .and(warp::header::header("Authorization"))
        .and_then(serviceinfo_auth_handler)
        .and(warp::query::query::<QueryInfo>())
        .and_then(serviceinfo_handler);

    let admin_v0 = warp::post()
        .and(warp::path("admin"))
        .and(warp::path("v0"))
        .map(move || ud_admin.clone())
        .and(warp::header::header("Authorization"))
        .and_then(admin_auth_handler)
        .and(warp::body::json())
        .and_then(admin_v0_handler);

    let handler_ping = fdo_http_wrapper::server::ping_handler();

    let routes = warp::get()
        .and(serviceinfo)
        .or(admin_v0)
        .or(handler_ping)
        .with(warp::log("serviceinfo-api-server"));

    log::info!("Listening on {}", bind_addr);
    let server = warp::serve(routes);
    let server = server
        .bind_with_graceful_shutdown(bind_addr, async {
            signal(SignalKind::terminate()).unwrap().recv().await;
            log::info!("Terminating");
        })
        .1;
    tokio::join!(server);

    Ok(())
}
