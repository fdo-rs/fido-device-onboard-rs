use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::fs;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Context, Error, Result};
use fdo_util::servers::configuration::AbsolutePathBuf;
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use serde_yaml::Value;
use tokio::signal::unix::{signal, SignalKind};
use warp::Filter;

use fdo_data_formats::{
    constants::{KeyStorageType, MfgStringType, PublicKeyType, RendezvousVariable},
    ownershipvoucher::OwnershipVoucher,
    publickey::{PublicKey, X5Chain},
    types::{Guid, RendezvousInfo},
    ProtocolVersion,
};
use fdo_store::Store;
use fdo_util::servers::{
    configuration::manufacturing_server::{DiunSettings, ManufacturingServerSettings},
    settings_for, yaml_to_cbor, OwnershipVoucherStoreMetadataKey,
};

use std::convert::Infallible;
//use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslAcceptorBuilder};
//use tokio::net::TcpListener;
//use std::net::SocketAddr;
use hyper::server::conn::AddrIncoming;
use tls_listener::TlsListener;

pub mod tls_config;
use tls_config::tls_acceptor;

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

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
enum PublicKeyStoreMetadataKey {}

impl fdo_store::MetadataLocalKey for PublicKeyStoreMetadataKey {
    fn to_key(&self) -> &'static str {
        match *self {}
    }
}

pub struct ManufacturingServiceUD {
    // Stores
    session_store: Arc<fdo_http_wrapper::server::SessionStore>,
    ownership_voucher_store: Box<
        dyn Store<
            fdo_store::WriteOnlyOpen,
            Guid,
            OwnershipVoucher,
            OwnershipVoucherStoreMetadataKey,
        >,
    >,
    public_key_store:
        Option<Box<dyn Store<fdo_store::ReadOnlyOpen, String, Vec<u8>, PublicKeyStoreMetadataKey>>>,

    // Certificates
    manufacturer_cert: X509,
    manufacturer_key: Option<PKey<Private>>,
    device_cert_key: PKey<Private>,
    device_cert_chain: X5Chain,
    owner_cert: Option<PublicKey>,
    manufacturing_server_https_cert: AbsolutePathBuf,
    manufacturing_server_https_key: AbsolutePathBuf,
    rendezvous_info: RendezvousInfo,

    // Protocols
    enable_di: bool,

    // DIUN settings
    diun_configuration: Option<DiunConfiguration>,
}

type ManufacturingServiceUDT = Arc<ManufacturingServiceUD>;

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

fn load_rendezvous_info(rvs: &[BTreeMap<String, Value>]) -> Result<RendezvousInfo> {
    let mut info = Vec::new();
    for val in rvs {
        let mut entry = Vec::new();

        for (key, val) in val.iter() {
            let key = RendezvousVariable::from_str(key)
                .with_context(|| format!("Error parsing rendezvous key '{key}'"))?;

            let val = yaml_to_cbor(val)?;
            let val = key
                .value_from_human_to_machine(val)
                .with_context(|| format!("Error parsing value for key '{key:?}'"))?;

            entry.push((key, val));
        }

        info.push(entry);
    }

    RendezvousInfo::new(info).context("Error serializing rendezvous info")
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
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

    let settings: ManufacturingServerSettings = settings_for("manufacturing-server")?
        .try_deserialize()
        .context("Error parsing configuration")?;

    // Bind information
    // seperate bind address for running http and https
    let bind_https_addr = settings.bind_https.clone();
    let bind_http_addr = settings.bind_http.clone();

    // Initialize stores
    let session_store = settings
        .session_store_driver
        .initialize()
        .context("Error initializing session store")?;
    let session_store = fdo_http_wrapper::server::SessionStore::new(session_store);
    let ownership_voucher_store = settings
        .ownership_voucher_store_driver
        .initialize()
        .context("Error initializing ownership voucher store")?;
    let public_key_store = match settings.public_key_store_driver {
        None => None,
        Some(driver) => Some(
            driver
                .initialize()
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
    let manufacturing_server_https_cert = settings.manufacturing.manufacturing_server_https_cert;
    let manufacturing_server_https_key = settings.manufacturing.manufacturing_server_https_key;

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

    let rendezvous_info = load_rendezvous_info(&settings.rendezvous_info)
        .context("Error processing rendezvous info")?;

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
        manufacturing_server_https_cert,
        manufacturing_server_https_key,

        rendezvous_info,

        enable_di: settings.protocols.plain_di.unwrap_or(false),
        diun_configuration,
    });

    // Initialize handlers
    let hello = warp::get().map(|| "Hello from the manufacturing server");
    let handler_ping = fdo_http_wrapper::server::ping_handler();

    // DI
    let handler_di_app_start = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::di::app_start,
    );
    let handler_di_set_hmac = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::di::set_hmac,
    );

    // DIUN
    let handler_diun_connect = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::diun::connect,
    );
    let handler_diun_request_key_parameters = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::diun::request_key_parameters,
    );
    let handler_diun_provide_key = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_1,
        user_data.clone(),
        session_store.clone(),
        handlers::diun::provide_key,
    );

    // routes, no change in protocol handlers required since https request once handled at TLS layer should
    // work the same way as http protocol handler

    let routes = warp::post()
        .and(
            hello
                .clone()
                .or(handler_ping.clone())
                // DI
                .or(handler_di_app_start.clone())
                .or(handler_di_set_hmac.clone())
                // DIUN
                .or(handler_diun_connect.clone())
                .or(handler_diun_request_key_parameters.clone())
                .or(handler_diun_provide_key.clone()),
        )
        .recover(fdo_http_wrapper::server::handle_rejection.clone())
        .with(warp::log("manufacturing-server to handle https and https"));

    // Convert routes into a warp service, so that we can use hyper to serve this services with TLS config.
    let service = warp::service(routes.clone());

    let make_svc = hyper::service::make_service_fn(move |_| {
        let svc = service.clone();
        async move { Ok::<_, Infallible>(svc) }
    });

    let incoming = TlsListener::new(
        tls_acceptor(user_data.clone()),
        AddrIncoming::bind(&bind_https_addr.into())?,
    );
    let https_server = hyper::Server::builder(incoming).serve(make_svc);
    let https_server = https_server.with_graceful_shutdown(async {
        signal(SignalKind::terminate()).unwrap().recv().await;
        log::info!("Terminating HTTPS server");
    });
    let https_server_handle = tokio::spawn(https_server);

    let http_server = warp::serve(routes.clone());
    let http_server = http_server
        .bind_with_graceful_shutdown(bind_http_addr, async {
            signal(SignalKind::terminate()).unwrap().recv().await;
            log::info!("Terminating HTTP server");
        })
        .1;
    let http_server_handle = tokio::spawn(http_server);

    // maintainance runner
    let maintenance_runner_handle =
        tokio::spawn(async move { perform_maintenance(user_data.clone()).await });

    log::info!("starting both servers with http & https support");
    // Join all the three handlers and wait
    let (http_result, https_result, maintenance_result) = tokio::join!(
        http_server_handle,
        https_server_handle,
        maintenance_runner_handle
    );

    // Check the results and handle accordingly since we have joined
    match http_result {
        Ok(_) => log::info!("HTTP server terminated successfully"),
        Err(err) => log::error!("HTTP server terminated with an error: {:?}", err),
    }

    match https_result {
        Ok(_) => log::info!("HTTPS server terminated successfully"),
        Err(err) => log::error!("HTTPS server terminated with an error: {:?}", err),
    }

    match maintenance_result {
        Ok(_) => log::info!("Maintenance runner terminated successfully"),
        Err(err) => log::error!("Maintenance runner terminated with an error: {:?}", err),
    }

    Ok(())
}
