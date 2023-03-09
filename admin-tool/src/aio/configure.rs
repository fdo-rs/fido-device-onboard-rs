use anyhow::{bail, Context, Error, Result};
use clap::Args;
use fdo_data_formats::types::RemoteConnection;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::{collections::BTreeMap, net::IpAddr, path::Path};

use fdo_store::StoreConfig;
use fdo_util::servers::configuration::{
    serviceinfo_api_server::ServiceInfoSettings, AbsolutePathBuf, Bind,
};

const SERVICEINFO_TOKEN_SECRET_STRENGTH_BYTES: usize = 32;

#[derive(Debug, Args, Clone, Serialize, Deserialize)]
pub(super) struct Configuration {
    #[clap(long, default_value_t = String::from("FDO AIO"))]
    pub cert_organization: String,
    #[clap(long, default_value_t = String::from("US"))]
    pub cert_country: String,

    #[clap(long, default_value_t = String::from("0.0.0.0"))]
    pub listen_ip_address: String,

    #[clap(long, default_value_t = 8080)]
    pub listen_port_manufacturing_server: u16,
    #[clap(long, default_value_t = 8081)]
    pub listen_port_owner_onboarding_server: u16,
    #[clap(long, default_value_t = 8082)]
    pub listen_port_rendezvous_server: u16,
    #[clap(long, default_value_t = 8083)]
    pub listen_port_serviceinfo_api_server: u16,

    #[clap(long)]
    pub separate_manufacturing_and_owner_voucher_store: bool,

    #[clap(long)]
    pub manufacturing_enable_plain_di: bool,

    #[clap(long)]
    pub manufacturing_disable_key_storage_filesystem: bool,

    #[clap(long)]
    pub manufacturing_disable_key_storage_tpm: bool,

    #[clap(long)]
    pub manufacturing_use_secp256r1: bool,

    /// The hostname or IP address that clients should use to connect to the AIO components
    /// (if not specified, will be all IP addresses of the system).
    /// Note that this is not equal to the listen address, as the AIO components will always
    /// listen on all interfaces.
    #[clap(long)]
    pub contact_hostname: Option<String>,

    // Data used during the process that's not actually configuration, but instead used
    // and generate the intermediate data
    #[clap(skip)]
    pub contact_addresses: Vec<ContactAddress>,
    #[clap(skip)]
    pub serviceinfo_api_auth_token: String,
    #[clap(skip)]
    pub serviceinfo_api_admin_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum ContactAddress {
    IpAddr(IpAddr),
    Hostname(String),
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            cert_organization: String::from("FDO AIO"),
            cert_country: String::from("US"),

            listen_ip_address: String::from("0.0.0.0"),
            listen_port_manufacturing_server: 8080,
            listen_port_owner_onboarding_server: 8081,
            listen_port_rendezvous_server: 8082,
            listen_port_serviceinfo_api_server: 8083,

            separate_manufacturing_and_owner_voucher_store: false,
            manufacturing_enable_plain_di: false,
            manufacturing_disable_key_storage_filesystem: false,
            manufacturing_disable_key_storage_tpm: false,
            manufacturing_use_secp256r1: false,

            contact_hostname: None,

            contact_addresses: vec![],
            serviceinfo_api_auth_token: String::from(""),
            serviceinfo_api_admin_token: String::from(""),
        }
    }
}

impl Configuration {
    fn generate_rendezvous_info(&self) -> Result<Vec<BTreeMap<String, serde_yaml::Value>>, Error> {
        let mut rendezvous_entries = vec![];

        for contact_address in &self.contact_addresses {
            let mut entry = BTreeMap::new();

            match contact_address {
                ContactAddress::IpAddr(ip_addr) => {
                    entry.insert(
                        "ip_address".to_string(),
                        serde_yaml::Value::String(ip_addr.to_string()),
                    );
                }
                ContactAddress::Hostname(hostname) => {
                    entry.insert(
                        "dns".to_string(),
                        serde_yaml::Value::String(hostname.to_string()),
                    );
                }
            }

            entry.insert(
                "protocol".to_string(),
                serde_yaml::Value::String("http".to_string()),
            );
            entry.insert(
                "deviceport".to_string(),
                serde_yaml::Value::Number(self.listen_port_rendezvous_server.into()),
            );
            entry.insert(
                "ownerport".to_string(),
                serde_yaml::Value::Number(self.listen_port_rendezvous_server.into()),
            );

            rendezvous_entries.push(entry);
        }

        Ok(rendezvous_entries)
    }

    fn generate_owner_addresses(&self) -> Result<Vec<RemoteConnection>, Error> {
        let mut owner_addresses = vec![];

        for contact_address in &self.contact_addresses {
            owner_addresses.push(match contact_address {
                ContactAddress::IpAddr(ip_addr) => fdo_data_formats::types::RemoteAddress::IP {
                    ip_address: ip_addr.to_string(),
                },
                ContactAddress::Hostname(hostname) => fdo_data_formats::types::RemoteAddress::Dns {
                    dns_name: hostname.to_string(),
                },
            })
        }

        Ok(vec![fdo_data_formats::types::RemoteConnection::new(
            fdo_data_formats::types::RemoteTransport::Http,
            owner_addresses,
            self.listen_port_owner_onboarding_server,
        )])
    }

    fn generate_serviceinfo_settings(&self) -> Result<ServiceInfoSettings, Error> {
        Ok(ServiceInfoSettings {
            initial_user: None,
            files: None,
            commands: None,
            diskencryption_clevis: None,
            additional_serviceinfo: None,
            after_onboarding_reboot: Some(false),
        })
    }
}

fn write_config<T>(aio_dir: &Path, name: &str, contents: &T) -> Result<(), Error>
where
    T: serde::ser::Serialize,
{
    let cfg_file = std::fs::File::create(aio_dir.join("configs").join(name))
        .context("Error creating configuration file")?;
    serde_yaml::to_writer(&cfg_file, &contents).context("Error writing configuration file")?;
    cfg_file
        .sync_all()
        .context("Error syncing configuration file")
}

fn generate_configs(aio_dir: &Path, config_args: &Configuration) -> Result<(), Error> {
    let get_bind = |port: u16| -> Result<Bind, anyhow::Error> {
        Ok(Bind::new(
            format!("0.0.0.0:{port}")
                .parse()
                .context("Error parsing bind")?,
        ))
    };

    log::trace!("Generating Rendezvous Server configuration");
    let rendezvous_config =
        fdo_util::servers::configuration::rendezvous_server::RendezvousServerSettings {
            storage_driver: StoreConfig::Directory {
                path: aio_dir.join("stores").join("rendezvous_registered"),
            },

            session_store_driver: StoreConfig::Directory {
                path: aio_dir.join("stores").join("rendezvous_sessions"),
            },

            trusted_manufacturer_keys_path: Some(
                AbsolutePathBuf::new(aio_dir.join("keys").join("manufacturer_cert.pem"))
                    .expect("Failed to build absolute path"),
            ),

            max_wait_seconds: None,

            bind: get_bind(config_args.listen_port_rendezvous_server)?,
        };
    write_config(aio_dir, "rendezvous_server.yml", &rendezvous_config)
        .context("Error writing rendezvous server configuration file")?;

    log::trace!("Generating ServiceInfo API Server configuration");
    let serviceinfo_api_config =
        fdo_util::servers::configuration::serviceinfo_api_server::ServiceInfoApiServerSettings {
            service_info: config_args
                .generate_serviceinfo_settings()
                .context("Error generating serviceinfo settings")?,

            bind: get_bind(config_args.listen_port_serviceinfo_api_server)?,

            service_info_auth_token: Some(config_args.serviceinfo_api_auth_token.clone()),
            admin_auth_token: Some(config_args.serviceinfo_api_admin_token.clone()),

            device_specific_store_driver: StoreConfig::Directory {
                path: aio_dir.join("stores").join("serviceinfo_api_devices"),
            },
        };
    write_config(
        aio_dir,
        "serviceinfo_api_server.yml",
        &serviceinfo_api_config,
    )
    .context("Error writing ServiceInfo API server configuration file")?;

    log::trace!("Generating Manufacturing Server configuration");
    let mut allowed_key_storage_types = vec![];
    if !config_args.manufacturing_disable_key_storage_tpm {
        allowed_key_storage_types
            .push(fdo_util::servers::configuration::manufacturing_server::KeyStorageTypeString::Tpm)
    }
    if !config_args.manufacturing_disable_key_storage_filesystem {
        allowed_key_storage_types.push(fdo_util::servers::configuration::manufacturing_server::KeyStorageTypeString::FileSystem)
    }
    let manufacturing_server_config =
        fdo_util::servers::configuration::manufacturing_server::ManufacturingServerSettings {
            session_store_driver: StoreConfig::Directory {
                path: aio_dir.join("stores").join("manufacturing_sessions"),
            },

            bind: get_bind(config_args.listen_port_manufacturing_server)?,

            ownership_voucher_store_driver: StoreConfig::Directory {
                path: aio_dir.join("stores").join(if config_args.separate_manufacturing_and_owner_voucher_store {
                    "manufacturing_vouchers"
                } else {
                    "owner_vouchers"
                })
            },
            public_key_store_driver: Some(StoreConfig::Directory {
                path: aio_dir.join("stores").join("manufacturer_keys"),
            }),
            protocols: fdo_util::servers::configuration::manufacturing_server::ProtocolSetting {
                plain_di: Some(config_args.manufacturing_enable_plain_di),
                diun: Some(fdo_util::servers::configuration::manufacturing_server::DiunSettings {
                    mfg_string_type: fdo_util::servers::configuration::manufacturing_server::MfgStringTypeString::SerialNumber,
                    key_type: if config_args.manufacturing_use_secp256r1 {
                        fdo_util::servers::configuration::manufacturing_server::PublicKeyTypeString::SECP256R1
                    } else {
                        fdo_util::servers::configuration::manufacturing_server::PublicKeyTypeString::SECP384R1
                    },
                    allowed_key_storage_types,
                    key_path: AbsolutePathBuf::new(
                        aio_dir.join("keys").join("diun_key.der"),
                    ).unwrap(),
                    cert_path: AbsolutePathBuf::new(
                        aio_dir.join("keys").join("diun_cert.pem"),
                    ).unwrap(),
                }
                )
            },
            rendezvous_info: config_args
                .generate_rendezvous_info()
                .context("Error generating rendezvous info")?,
            manufacturing: fdo_util::servers::configuration::manufacturing_server::ManufacturingSettings {
                manufacturer_cert_path: AbsolutePathBuf::new(aio_dir.join("keys").join("manufacturer_cert.pem")).unwrap(),
                manufacturer_private_key: Some(AbsolutePathBuf::new(aio_dir.join("keys").join("manufacturer_key.der")).unwrap()),
                device_cert_ca_private_key: AbsolutePathBuf::new(aio_dir.join("keys").join("device_ca_key.der")).unwrap(),
                device_cert_ca_chain: AbsolutePathBuf::new(aio_dir.join("keys").join("device_ca_cert.pem")).unwrap(),
                owner_cert_path: Some(AbsolutePathBuf::new(aio_dir.join("keys").join("owner_cert.pem")).unwrap()),
            }
        };
    write_config(
        aio_dir,
        "manufacturing_server.yml",
        &manufacturing_server_config,
    )
    .context("Error writing manufacturing server configuration file")?;

    log::trace!("Generating Owner Onboarding Server configuration");
    let owner_onboarding_server_config =
        fdo_util::servers::configuration::owner_onboarding_server::OwnerOnboardingServerSettings {
            session_store_driver: StoreConfig::Directory {
                path: aio_dir.join("stores").join("owner_onboarding_sessions"),
            },

            bind: get_bind(config_args.listen_port_owner_onboarding_server)?,

            ownership_voucher_store_driver: StoreConfig::Directory {
                path: aio_dir.join("stores").join("owner_vouchers"),
            },
            trusted_device_keys_path: AbsolutePathBuf::new(
                aio_dir.join("keys").join("device_ca_cert.pem"),
            )
            .unwrap(),
            owner_private_key_path: AbsolutePathBuf::new(
                aio_dir.join("keys").join("owner_key.der"),
            )
            .unwrap(),

            owner_public_key_path: AbsolutePathBuf::new(
                aio_dir.join("keys").join("owner_cert.pem"),
            )
            .unwrap(),
            service_info_api_url: format!(
                "http://localhost:{}/device_info", //DevSkim: ignore DS137138
                config_args.listen_port_serviceinfo_api_server
            ),
            service_info_api_authentication:
                fdo_http_wrapper::client::JsonAuthentication::BearerToken {
                    token: config_args.serviceinfo_api_auth_token.clone(),
                },
            owner_addresses: config_args
                .generate_owner_addresses()
                .context("Error generating owner addresses")?,
            report_to_rendezvous_endpoint_enabled: true,
        };
    write_config(
        aio_dir,
        "owner_onboarding_server.yml",
        &owner_onboarding_server_config,
    )
    .context("Error writing owner onboarding server configuration file")?;

    Ok(())
}

fn generate_secret_token() -> Result<String, Error> {
    let mut bytes = [0u8; SERVICEINFO_TOKEN_SECRET_STRENGTH_BYTES];
    openssl::rand::rand_bytes(&mut bytes).context("Error generating random bytes")?;
    Ok(openssl::base64::encode_block(&bytes))
}

fn is_valid_address(addr: &IpAddr) -> bool {
    if addr.is_unspecified() {
        log::trace!("Skipping unspecified address {:?}", addr);
        return false;
    }
    if addr.is_loopback() {
        log::trace!("Skipping loopback address {:?}", addr);
        return false;
    }
    if addr.is_multicast() {
        log::trace!("Skipping multicast address {:?}", addr);
        return false;
    }
    true
}

pub(super) fn generate_configs_and_keys(
    aio_dir: &Path,
    config_args: Option<Configuration>,
) -> Result<(), Error> {
    log::debug!(
        "Generating configuration in {:?}, with config args {:?}",
        aio_dir,
        config_args
    );
    let config_args = config_args.unwrap_or_default();

    if !aio_dir.exists() {
        std::fs::create_dir(aio_dir).context("Error creating AIO directory")?;
    }
    if aio_dir.join("aio_configuration").exists() {
        bail!("{:?} already configured", aio_dir);
    }
    if aio_dir.read_dir()?.next().is_some() {
        // Improvement: erase everything with a possible --force flag?
        bail!("{:?} is not empty", aio_dir);
    }
    let aio_dir = aio_dir
        .canonicalize()
        .context("Could not canonicalize AIO dir")?;

    log::debug!("Creating empty directories");
    for dir in &["work", "keys", "configs", "stores", "logs"] {
        std::fs::create_dir_all(aio_dir.join(dir))
            .with_context(|| format!("Error creating {dir} directory"))?;
    }
    for store_dir in &[
        "mfg_sessions",
        "rendezvous_sessions",
        "owner_sessions",
        "manufacturing_sessions",
        "rendezvous_registered",
        "owner_vouchers",
        "serviceinfo_api_per_device",
        "manufacturer_keys",
    ] {
        std::fs::create_dir(aio_dir.join("stores").join(store_dir))
            .with_context(|| format!("Error creating {store_dir} store directory"))?;
    }
    if config_args.separate_manufacturing_and_owner_voucher_store {
        std::fs::create_dir(aio_dir.join("stores").join("manufacturing_vouchers"))
            .context("Error creating manufacturing_vouchers store directory")?;
    }

    log::debug!("Creating keys");
    for key_subject in [
        crate::Subject::Diun,
        crate::Subject::Manufacturer,
        crate::Subject::DeviceCA,
        crate::Subject::Owner,
    ] {
        crate::generate_key_and_cert(&crate::GenerateKeyAndCertArguments {
            subject: key_subject,
            organization: config_args.cert_organization.clone(),
            country: config_args.cert_country.clone(),
            destination_dir: aio_dir.join("keys").to_string_lossy().to_string(),
        })
        .with_context(|| format!("Error creating {key_subject:?} key"))?;
    }

    let mut config_args = config_args;
    log::debug!("Generating ServiceInfo API secrets");
    config_args.serviceinfo_api_auth_token =
        generate_secret_token().context("Error generating auth token")?;
    config_args.serviceinfo_api_admin_token =
        generate_secret_token().context("Error generating admin token")?;

    log::debug!("Determining contact addresses");
    match config_args.contact_hostname {
        Some(ref hostname) => {
            config_args.contact_addresses = vec![ContactAddress::Hostname(hostname.clone())]
        }
        None => {
            log::trace!("Determining all IP addresses");
            let mut contact_addresses = vec![];

            let ifaddrs =
                nix::ifaddrs::getifaddrs().context("Error getting network interface list")?;
            for ifaddr in ifaddrs {
                if let Some(sockaddrsto) = ifaddr.address {
                    if let Some(sockaddr) = sockaddrsto.as_sockaddr_in() {
                        let address = IpAddr::from(Ipv4Addr::from(sockaddr.ip()));
                        if is_valid_address(&address) {
                            contact_addresses.push(ContactAddress::IpAddr(address));
                        }
                    } else if let Some(sockaddr) = sockaddrsto.as_sockaddr_in6() {
                        let address = IpAddr::from(sockaddr.ip());
                        if is_valid_address(&address) {
                            contact_addresses.push(ContactAddress::IpAddr(address));
                        }
                    }
                }
            }
            log::trace!("Found contact addresses: {:?}", contact_addresses);
            config_args.contact_addresses = contact_addresses;
        }
    }

    log::debug!("Creating configuration files");
    generate_configs(&aio_dir, &config_args).context("Error generating configuration files")?;

    log::debug!("Recording AIO configuration");
    let cfg_file = std::fs::File::create(aio_dir.join("aio_configuration"))
        .context("Error creating aio_configuration file")?;
    serde_yaml::to_writer(cfg_file, &config_args).context("Error writing aio_configuration file")
}

#[cfg(test)]
mod test {
    use fdo_util::servers::configuration::manufacturing_server::ManufacturingServerSettings;
    use fdo_util::servers::configuration::owner_onboarding_server::OwnerOnboardingServerSettings;
    use fdo_util::servers::configuration::rendezvous_server::RendezvousServerSettings;
    use fdo_util::servers::configuration::serviceinfo_api_server::ServiceInfoApiServerSettings;

    use crate::aio::configure;
    use rand::distributions::{Alphanumeric, DistString};
    use std::fs;
    use std::path::PathBuf;

    use super::Configuration;

    #[test]
    /// Serializes all the configuration files (common server .yaml config
    /// files and the internal aio_configuration file) and then tries to read
    /// them.
    // cargo test --bin fdo-admin-tool
    fn serialize_and_deserialize() {
        let config_args = Configuration::default();
        let dir = format!(
            "{}{}",
            "./aio-tests-",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 16)
        );
        let aio_dir = PathBuf::from(&dir);
        // this serializes the contents of Rust types into yamls
        configure::generate_configs_and_keys(&aio_dir, Some(config_args)).unwrap();

        // deserialization tests: from .yml into Rust types, simply panic if something goes wrong
        let manu_server = PathBuf::from(format!("{}{}", &dir, "/configs/manufacturing_server.yml"));
        let manu_config = fs::read_to_string(manu_server).unwrap();
        let _: ManufacturingServerSettings = serde_yaml::from_str(&manu_config).unwrap();

        let oo_server = PathBuf::from(format!(
            "{}{}",
            &dir, "/configs/owner_onboarding_server.yml"
        ));
        let oo_config = fs::read_to_string(oo_server).unwrap();
        let _: OwnerOnboardingServerSettings = serde_yaml::from_str(&oo_config).unwrap();

        let rendezvous_server =
            PathBuf::from(format!("{}{}", &dir, "/configs/rendezvous_server.yml"));
        let rendezvous_config = fs::read_to_string(rendezvous_server).unwrap();
        let _: RendezvousServerSettings = serde_yaml::from_str(&rendezvous_config).unwrap();

        let serviceinfo_server =
            PathBuf::from(format!("{}{}", &dir, "/configs/serviceinfo_api_server.yml"));
        let serviceinfo_config = fs::read_to_string(serviceinfo_server).unwrap();
        let _: ServiceInfoApiServerSettings = serde_yaml::from_str(&serviceinfo_config).unwrap();

        let aio = PathBuf::from(format!("{}{}", &dir, "/aio_configuration"));
        let aio_config = fs::read_to_string(aio).unwrap();
        let _: Configuration = serde_yaml::from_str(&aio_config).unwrap();

        // clean up the dir
        std::fs::remove_dir_all(&aio_dir).unwrap();
    }
}
