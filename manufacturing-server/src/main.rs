use std::convert::{TryFrom, TryInto};
use std::fs;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Context, Error, Result};
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use serde::Deserialize;
use tokio::signal::unix::{signal, SignalKind};
use warp::Filter;

use fdo_data_formats::{
    constants::{KeyStorageType, MfgStringType, PublicKeyType},
    ownershipvoucher::OwnershipVoucher,
    publickey::{PublicKey, X5Chain},
    types::{Guid, RendezvousInfo},
};
use fdo_store::{Store, StoreDriver};

const PERFORMED_DIUN_SES_KEY: &str = "mfg_global_diun_performed";
const DEVICE_KEY_FROM_DIUN_SES_KEY: &str = "mfg_global_device_key_from_diun";

mod handlers;

struct DiunConfiguration {
    mfg_string_type: MfgStringType,

    key_type: PublicKeyType,
    allowed_key_storage_types: Vec<KeyStorageType>,

    key: PKey<Private>,
    public_keys: PublicKey,
}

struct ManufacturingServiceUD {
    // Stores
    session_store: Arc<fdo_http_wrapper::server::SessionStore>,
    ownership_voucher_store: Box<dyn Store<fdo_store::WriteOnlyOpen, Guid, OwnershipVoucher>>,
    public_key_store: Option<Box<dyn Store<fdo_store::ReadOnlyOpen, String, Vec<u8>>>>,

    // Certificates
    manufacturer_cert: X509,
    manufacturer_key: Option<PKey<Private>>,
    device_cert_key: PKey<Private>,
    device_cert_chain: X5Chain,
    owner_cert: Option<PublicKey>,

    // Rendezvous Info
    rendezvous_info: RendezvousInfo,

    // Protocols
    enable_di: bool,

    // DIUN settings
    diun_configuration: Option<DiunConfiguration>,
}

type ManufacturingServiceUDT = Arc<ManufacturingServiceUD>;

#[derive(Debug, Deserialize, Clone, Copy)]
enum KeyStorageTypeString {
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

#[derive(Debug, Deserialize, Clone, Copy)]
enum PublicKeyTypeString {
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

#[derive(Debug, Deserialize, Clone, Copy)]
enum MfgStringTypeString {
    SerialNumber,
}

impl From<MfgStringTypeString> for MfgStringType {
    fn from(mfg_string_type: MfgStringTypeString) -> Self {
        match mfg_string_type {
            MfgStringTypeString::SerialNumber => MfgStringType::SerialNumber,
        }
    }
}

#[derive(Debug, Deserialize)]
struct DiunSettings {
    mfg_string_type: MfgStringTypeString,

    key_type: PublicKeyTypeString,
    allowed_key_storage_types: Vec<KeyStorageTypeString>,

    key_path: String,
    cert_path: String,
}

impl TryFrom<DiunSettings> for DiunConfiguration {
    type Error = Error;

    fn try_from(value: DiunSettings) -> Result<DiunConfiguration, Error> {
        let key = fs::read(value.key_path).context("Error reading DIUN key")?;
        let key = PKey::private_key_from_der(&key).context("Error parsing DIUN key")?;
        let public_keys = X5Chain::new(
            X509::stack_from_pem(
                &fs::read(value.cert_path).context("Error reading DIUN certificate")?,
            )
            .context("Error parsing DIUN certificate")?,
        )
        .context("Error generating X5Chain")?
        .try_into()
        .context("Error generating PublicKey")?;

        Ok(DiunConfiguration {
            mfg_string_type: value.mfg_string_type.into(),
            key_type: value.key_type.into(),
            allowed_key_storage_types: value
                .allowed_key_storage_types
                .iter()
                .map(|x| KeyStorageType::from(*x))
                .collect(),

            key,
            public_keys,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ManufacturingSettings {
    manufacturer_cert_path: String,
    device_cert_ca_private_key: String,
    device_cert_ca_chain: String,

    owner_cert_path: Option<String>,
    manufacturer_private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProtocolSetting {
    plain_di: Option<bool>,
    diun: Option<DiunSettings>,
}

#[derive(Debug, Deserialize)]
struct Settings {
    // Session store info
    session_store_driver: StoreDriver,
    session_store_config: Option<config::Value>,

    // Ownership Voucher store info
    ownership_voucher_store_driver: StoreDriver,
    ownership_voucher_store_config: Option<config::Value>,

    // Public key store info
    public_key_store_driver: Option<StoreDriver>,
    public_key_store_config: Option<config::Value>,

    // Bind information
    bind: String,

    protocols: ProtocolSetting,

    rendezvous_info: RendezvousInfo,

    manufacturing: ManufacturingSettings,
}

const MAINTENANCE_INTERVAL: u64 = 60;

async fn perform_maintenance(
    udt: ManufacturingServiceUDT,
) -> std::result::Result<(), &'static str> {
    log::info!(
        "Scheduling maintenance every {} seconds",
        MAINTENANCE_INTERVAL
    );

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(MAINTENANCE_INTERVAL)).await;

        let ov_maint = udt.ownership_voucher_store.perform_maintenance();
        let ses_maint = udt.session_store.perform_maintenance();

        #[allow(unused_must_use)]
        let (ov_res, ses_res) = tokio::join!(ov_maint, ses_maint);
        if let Err(e) = ov_res {
            log::warn!("Error during ownership voucher store maintenance: {:?}", e);
        }
        if let Err(e) = ses_res {
            log::warn!("Error during session store maintenance: {:?}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    fdo_http_wrapper::init_logging();

    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("manufacturing-server"))
        .context("Loading configuration files")?
        .merge(config::Environment::with_prefix("manufacturing-server"))
        .context("Loading configuration from environment variables")?;
    let settings: Settings = settings.try_into().context("Error parsing configuration")?;

    // Bind information
    let bind_addr = SocketAddr::from_str(&settings.bind)
        .with_context(|| format!("Error parsing bind string '{}'", &settings.bind))?;

    // Initialize stores
    let session_store = settings
        .session_store_driver
        .initialize(settings.session_store_config)
        .context("Error initializing session store")?;
    let session_store = fdo_http_wrapper::server::SessionStore::new(session_store);
    let ownership_voucher_store = settings
        .ownership_voucher_store_driver
        .initialize(settings.ownership_voucher_store_config)
        .context("Error initializing ownership voucher store")?;
    let public_key_store = match settings.public_key_store_driver {
        None => None,
        Some(driver) => Some(
            driver
                .initialize(settings.public_key_store_config)
                .context("Error initializing public key store")?,
        ),
    };

    // Read keys and certificates
    let device_cert_key = PKey::private_key_from_der(
        &fs::read(settings.manufacturing.device_cert_ca_private_key)
            .context("Error reading device CA private key")?,
    )
    .context("Error parsing device CA private key")?;
    let device_cert_chain = X5Chain::new(
        X509::stack_from_pem(
            &fs::read(settings.manufacturing.device_cert_ca_chain)
                .context("Error reading device CA chain")?,
        )
        .context("Error parsing device CA chain")?,
    )
    .context("Error creating device cert chain")?;
    let manufacturer_cert = X509::from_pem(
        &fs::read(settings.manufacturing.manufacturer_cert_path)
            .context("Error reading manufacturer certificate")?,
    )
    .context("Error parsing manufacturer certificate")?;

    let manufacturer_key = match settings.manufacturing.manufacturer_private_key {
        None => None,
        Some(path) => Some(
            PKey::private_key_from_der(
                &fs::read(path).context("Error reading manufacturer private key")?,
            )
            .context("Error parsing manufacturer private key")?,
        ),
    };
    let owner_cert = match settings.manufacturing.owner_cert_path {
        None => None,
        Some(path) => Some(
            X509::from_pem(&fs::read(path).context("Error reading owner certificate")?)
                .context("Error parsing owner certificate")?
                .try_into()
                .context("Error converting owner certificate to PublicKey")?,
        ),
    };

    if manufacturer_key.is_none() != owner_cert.is_none() {
        bail!("Manufacturer private key and owner certificate must both be specified or not specified");
    }

    let diun_configuration = match settings.protocols.diun {
        None => None,
        Some(v) => Some(v.try_into().context("Error parsing DIUN configuration")?),
    };

    let rendezvous_info = settings.rendezvous_info; // .into();

    // Initialize user data
    let user_data = Arc::new(ManufacturingServiceUD {
        // Stores
        session_store: session_store.clone(),
        ownership_voucher_store,
        public_key_store,

        device_cert_key,
        device_cert_chain,
        manufacturer_cert,
        manufacturer_key,
        owner_cert,

        rendezvous_info,

        enable_di: settings.protocols.plain_di.unwrap_or(false),
        diun_configuration,
    });

    // Initialize handlers
    let hello = warp::get().map(|| "Hello from the manufacturing server");
    let handler_ping = fdo_http_wrapper::server::ping_handler();

    // DI
    let handler_di_app_start = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::di::app_start,
    );
    let handler_di_set_hmac = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::di::set_hmac,
    );

    // DIUN
    let handler_diun_connect = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::diun::connect,
    );
    let handler_diun_request_key_parameters = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::diun::request_key_parameters,
    );
    let handler_diun_provide_key = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::diun::provide_key,
    );

    let routes = warp::post()
        .and(
            hello
                .or(handler_ping)
                // DI
                .or(handler_di_app_start)
                .or(handler_di_set_hmac)
                // DIUN
                .or(handler_diun_connect)
                .or(handler_diun_request_key_parameters)
                .or(handler_diun_provide_key),
        )
        .recover(fdo_http_wrapper::server::handle_rejection)
        .with(warp::log("manufacturing-server"));

    log::info!("Listening on {}", bind_addr);
    let server = warp::serve(routes);

    let maintenance_runner =
        tokio::spawn(async move { perform_maintenance(user_data.clone()).await });

    let server = server
        .bind_with_graceful_shutdown(bind_addr, async {
            signal(SignalKind::terminate()).unwrap().recv().await;
            log::info!("Terminating");
        })
        .1;
    let server = tokio::spawn(server);
    let _ = tokio::select!(
    _ = server => {
        log::info!("Server terminated");
    },
    _ = maintenance_runner => {
        log::info!("Maintenance runner terminated");
    });

    Ok(())
}
