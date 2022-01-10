use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use openssl::x509::X509;
use serde::Deserialize;
use tokio::signal::unix::{signal, SignalKind};
use warp::Filter;

use fdo_data_formats::{
    cborparser::ParsedArray,
    enhanced_types::X5Bag,
    publickey::PublicKey,
    types::{COSESign, Guid},
    ProtocolVersion, Serializable,
};
use fdo_store::{Store, StoreDriver};
use fdo_util::servers::{settings_for, AbsolutePathBuf};

mod handlers_to0;
mod handlers_to1;

#[derive(Clone, Debug)]
struct StoredItem {
    public_key: PublicKey,
    to1d: COSESign,
}

impl Serializable for StoredItem {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self, fdo_data_formats::Error>
    where
        R: std::io::Read,
    {
        let contents: ParsedArray<fdo_data_formats::cborparser::ParsedArraySize2> =
            ParsedArray::deserialize_from_reader(reader)?;

        let public_key = contents.get(0)?;
        let to1d = contents.get(1)?;

        Ok(StoredItem { public_key, to1d })
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<(), fdo_data_formats::Error>
    where
        W: std::io::Write,
    {
        let mut contents: ParsedArray<fdo_data_formats::cborparser::ParsedArraySize2> =
            unsafe { ParsedArray::new() };
        contents.set(0, &self.public_key)?;
        contents.set(1, &self.to1d)?;

        contents.serialize_to_writer(writer)
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
enum RendezvousStoreMetadataKey {}

impl fdo_store::MetadataLocalKey for RendezvousStoreMetadataKey {
    fn to_key(&self) -> &'static str {
        match *self {}
    }
}

struct RendezvousUD {
    max_wait_seconds: u32,
    trusted_manufacturer_keys: Option<X5Bag>,
    store: Box<dyn Store<fdo_store::ReadWriteOpen, Guid, StoredItem, RendezvousStoreMetadataKey>>,

    session_store: Arc<fdo_http_wrapper::server::SessionStore>,
}

type RendezvousUDT = Arc<RendezvousUD>;

#[derive(Debug, Deserialize)]
struct Settings {
    // Storage info
    storage_driver: StoreDriver,
    storage_config: Option<config::Value>,

    // Session store info
    session_store_driver: StoreDriver,
    session_store_config: Option<config::Value>,

    // Trusted keys
    trusted_manufacturer_keys_path: Option<AbsolutePathBuf>,

    // Other info
    max_wait_seconds: Option<u32>,

    // Bind information
    bind: String,
}

const MAINTENANCE_INTERVAL: u64 = 60;

async fn perform_maintenance(udt: RendezvousUDT) {
    log::info!(
        "Scheduling maintenance every {} seconds",
        MAINTENANCE_INTERVAL
    );

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(MAINTENANCE_INTERVAL)).await;

        let store_maint = udt.store.perform_maintenance();
        let ses_maint = udt.session_store.perform_maintenance();

        let (store_res, ses_res) = tokio::join!(store_maint, ses_maint);
        if let Err(e) = store_res {
            log::warn!("Error during store maintenance: {:?}", e);
        }
        if let Err(e) = ses_res {
            log::warn!("Error during session store maintenance: {:?}", e);
        }
    }
}

const DEFAULT_MAX_WAIT_SECONDS: u32 = 2592000;

#[tokio::main]
async fn main() -> Result<()> {
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

    let settings: Settings = settings_for("rendezvous-server")?
        .try_into()
        .context("Error parsing configuration")?;

    let max_wait_seconds = settings
        .max_wait_seconds
        .unwrap_or(DEFAULT_MAX_WAIT_SECONDS);

    // Bind information
    let bind_addr = SocketAddr::from_str(&settings.bind)
        .with_context(|| format!("Error parsing bind string '{}'", &settings.bind))?;

    // Initialize stores
    let store = settings
        .storage_driver
        .initialize(settings.storage_config)
        .context("Error initializing store")?;
    let session_store = settings
        .session_store_driver
        .initialize(settings.session_store_config)
        .context("Error initializing session store")?;
    let session_store = fdo_http_wrapper::server::SessionStore::new(session_store);

    // Load X509 certs
    let trusted_manufacturer_keys = settings
        .trusted_manufacturer_keys_path
        .map(|path| -> Result<X5Bag, anyhow::Error> {
            let trusted_manufacturer_keys = {
                let contents = std::fs::read(&path).with_context(|| {
                    format!("Error reading trusted manufacturer keys at {}", &path)
                })?;
                X509::stack_from_pem(&contents)
                    .context("Error parsing trusted manufacturer keys")?
            };
            X5Bag::with_certs(trusted_manufacturer_keys)
                .context("Error building trusted manufacturer keys X5Bag")
        })
        .transpose()
        .context("Error loading trusted manufacturer keys")?;

    // Initialize handler stores
    let user_data = Arc::new(RendezvousUD {
        max_wait_seconds,
        store,
        trusted_manufacturer_keys,

        session_store: session_store.clone(),
    });

    // Install handlers
    let hello = warp::get().map(|| "Hello from the rendezvous server");
    let handler_ping = fdo_http_wrapper::server::ping_handler();

    // TO0
    let handler_to0_hello = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_0,
        user_data.clone(),
        session_store.clone(),
        handlers_to0::hello,
    );
    let handler_to0_ownersign = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_0,
        user_data.clone(),
        session_store.clone(),
        handlers_to0::ownersign,
    );

    // TO1
    let handler_to1_hello_rv = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_0,
        user_data.clone(),
        session_store.clone(),
        handlers_to1::hello_rv,
    );
    let handler_to1_prove_to_rv = fdo_http_wrapper::server::fdo_request_filter(
        ProtocolVersion::Version1_0,
        user_data.clone(),
        session_store.clone(),
        handlers_to1::prove_to_rv,
    );

    let routes = warp::post()
        .and(
            hello
                .or(handler_ping)
                // TO0
                .or(handler_to0_hello)
                .or(handler_to0_ownersign)
                // TO1
                .or(handler_to1_hello_rv)
                .or(handler_to1_prove_to_rv),
        )
        .recover(fdo_http_wrapper::server::handle_rejection)
        .with(warp::log("rendezvous-server"));

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

    #[allow(clippy::panic)]
    let _ = tokio::select!(
    _ = server => {
        log::info!("Server terminated");
    },
    _ = maintenance_runner => {
        log::info!("Maintenance runner terminated");
    });

    Ok(())
}
