use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    str::FromStr,
};

use anyhow::{Context, Result};
use fdo_data_formats::{constants::HashType, types::Hash};
use serde::Deserialize;
use tokio::signal::unix::{signal, SignalKind};
use warp::Filter;

use fdo_util::servers::{settings_for, ServiceInfoApiReply, ServiceInfoApiReplyInitialUser};

#[derive(Debug, Deserialize, Clone)]
struct ServiceInfoFile {
    path: String,
    permissions: Option<String>,
    #[serde(skip)]
    parsed_permissions: Option<u32>,
    #[serde(skip)]
    contents_len: usize,
    #[serde(skip)]
    contents_hex: String,
    #[serde(skip)]
    hash_hex: String,
    source_path: String,
}

#[derive(Debug, Deserialize, Clone)]
struct ServiceInfoCommand {
    command: String,
    args: Vec<String>,
    #[serde(default)]
    may_fail: bool,
    #[serde(default)]
    return_stdout: bool,
    #[serde(default)]
    return_stderr: bool,
}

#[derive(Debug, Deserialize, Clone)]
struct ServiceInfoInitialUser {
    username: String,
    sshkeys: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct ServiceInfoSettings {
    initial_user: Option<ServiceInfoInitialUser>,

    files: Option<Vec<ServiceInfoFile>>,

    commands: Option<Vec<ServiceInfoCommand>>,

    additional_serviceinfo: Option<HashMap<String, Vec<(String, String)>>>,
}

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
                            "Invalid permission string for file {}: {} (invalid octal)",
                            path, permissions
                        )
                    })?)
                } else {
                    None
                };

                let contents = std::fs::read(&file.source_path)
                    .with_context(|| format!("Failed to read file {}", file.source_path))?;
                file.hash_hex = hex::encode(
                    &Hash::from_data(HashType::Sha384, &contents)
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

const AUTHENTICATION_TOKEN: &str = "Bearer TestAuthToken";

#[derive(Debug, Deserialize)]
struct Settings {
    service_info: ServiceInfoSettings,
    bind: String,
}

struct ServiceInfoApiDevServerUD {
    service_info_configuration: ServiceInfoConfiguration,
}

type ServiceInfoApiDevServerUDT = std::sync::Arc<ServiceInfoApiDevServerUD>;

#[derive(Debug, Default)]
struct ServiceInfoApiReplyBuilder {
    enabled_modules: std::collections::HashSet<String>,
    reply: ServiceInfoApiReply,
}

impl ServiceInfoApiReplyBuilder {
    fn add_extra<T>(&mut self, module: &str, command: &str, argument: &T)
    where
        T: serde::Serialize,
    {
        if self.reply.extra_commands.is_none() {
            self.reply.extra_commands = Some(Vec::new());
        }
        if !self.enabled_modules.contains(module) {
            self.enabled_modules.insert(module.to_string());
            self.reply.extra_commands.as_mut().unwrap().push((
                module.to_string(),
                "active".to_string(),
                serde_json::Value::Bool(true),
            ));
        }

        self.reply.extra_commands.as_mut().unwrap().push((
            module.to_string(),
            command.to_string(),
            serde_json::to_value(argument).expect("Error converting to json value"),
        ));
    }
}

async fn serviceinfo_handler(
    user_data: ServiceInfoApiDevServerUDT,
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

    if query_info.modules.contains("sshkey") {
        if let Some(initial_user) = &user_data.service_info_configuration.settings.initial_user {
            reply.reply.initial_user = Some(ServiceInfoApiReplyInitialUser {
                username: initial_user.username.clone(),
                ssh_keys: initial_user.sshkeys.clone(),
            });
        }
    }

    if query_info.modules.contains("binaryfile") {
        if let Some(files) = &user_data.service_info_configuration.settings.files {
            for file in files {
                reply.add_extra("binaryfile", "name", &file.path);
                reply.add_extra("binaryfile", "length", &file.contents_len);
                if let Some(parsed_permissions) = &file.parsed_permissions {
                    reply.add_extra("binaryfile", "mode", &parsed_permissions);
                }
                reply.add_extra("binaryfile", "data001|hex", &file.contents_hex);
                reply.add_extra("binaryfile", "sha-384|hex", &file.hash_hex);
            }
        }
    }

    if query_info.modules.contains("command") {
        if let Some(commands) = &user_data.service_info_configuration.settings.commands {
            for command in commands {
                reply.add_extra("command", "command", &command.command);
                reply.add_extra("command", "args", &command.args);
                reply.add_extra("command", "may_fail", &command.may_fail);
                reply.add_extra("command", "return_stdout", &command.return_stdout);
                reply.add_extra("command", "return_stderr", &command.return_stderr);
                reply.add_extra("command", "execute", &true);
            }
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
                    reply.add_extra(module, key, value);
                }
            }
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
) -> Result<HashSet<String>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(s.split(',').map(|s| s.to_string()).collect())
}

#[derive(Debug, Deserialize)]
struct QueryInfo {
    #[serde(rename = "serviceinfo_api_version")]
    api_version: u32,
    #[serde(deserialize_with = "deserialize_from_str")]
    device_guid: fdo_data_formats::types::Guid,
    #[serde(deserialize_with = "deserialize_from_comma_separated_strings")]
    modules: HashSet<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

    let settings: Settings = settings_for("serviceinfo-api-dev-server")?
        .try_into()
        .context("Error parsing configuration")?;

    // Bind information
    let bind_addr = SocketAddr::from_str(&settings.bind)
        .with_context(|| format!("Error parsing bind string '{}'", &settings.bind))?;

    // ServiceInfo settings
    let service_info_configuration = ServiceInfoConfiguration::from_settings(settings.service_info)
        .context("Error preparing ServiceInfo configuration")?;

    let user_data = std::sync::Arc::new(ServiceInfoApiDevServerUD {
        service_info_configuration,
    });

    let serviceinfo = warp::path("device_info")
        .and(warp::header::exact("Authorization", AUTHENTICATION_TOKEN))
        .and(warp::query::query::<QueryInfo>())
        .map(move |queryinfo| (user_data.clone(), queryinfo))
        .untuple_one()
        .and_then(serviceinfo_handler);

    let handler_ping = fdo_http_wrapper::server::ping_handler();

    let routes = warp::get()
        .and(serviceinfo)
        .or(handler_ping)
        .with(warp::log("serviceinfo-api-dev-server"));

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
