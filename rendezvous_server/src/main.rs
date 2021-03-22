use std::sync::Arc;

use anyhow::{Context, Result};
use aws_nitro_enclaves_cose::COSESign1;
use openssl::x509::X509;
use serde::Deserialize;
use warp::Filter;

use fdo_data_formats::{enhanced_types::X5Bag, publickey::PublicKey, types::Guid};
use fdo_store::{Store, StoreDriver};

mod handlers_to0;
mod handlers_to1;

struct RendezvousUD {
    max_wait_seconds: u32,
    trusted_manufacturer_keys: X5Bag,
    trusted_device_keys: X5Bag,
    store: Box<dyn Store<Guid, (PublicKey, COSESign1)>>,
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
    trusted_manufacturer_keys_path: String,
    trusted_device_keys_path: String,

    // Other info
    max_wait_seconds: Option<u32>,
}

const DEFAULT_MAX_WAIT_SECONDS: u32 = 2592000;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("rendezvous_service"))
        .context("Loading configuration files")?
        .merge(config::Environment::with_prefix("rendezvous"))
        .context("Loading configuration from environment variables")?;
    let settings: Settings = settings.try_into().context("Error parsing configuration")?;
    let max_wait_seconds = settings
        .max_wait_seconds
        .unwrap_or(DEFAULT_MAX_WAIT_SECONDS);

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
    let trusted_manufacturer_keys = {
        let trusted_keys_path = settings.trusted_manufacturer_keys_path;
        let contents = std::fs::read(&trusted_keys_path).with_context(|| {
            format!(
                "Error reading trusted manufacturer keys at {}",
                &trusted_keys_path
            )
        })?;
        X509::stack_from_pem(&contents).context("Error parsing trusted manufacturer keys")?
    };
    let trusted_manufacturer_keys = X5Bag::new(trusted_manufacturer_keys);
    let trusted_device_keys = {
        let trusted_keys_path = settings.trusted_device_keys_path;
        let contents = std::fs::read(&trusted_keys_path).with_context(|| {
            format!(
                "Error reading trusted device keys at {}",
                &trusted_keys_path
            )
        })?;
        X509::stack_from_pem(&contents).context("Error parsing trusted device keys")?
    };
    let trusted_device_keys = X5Bag::new(trusted_device_keys);

    // Initialize handler stores
    let user_data = Arc::new(RendezvousUD {
        max_wait_seconds,
        store,
        trusted_manufacturer_keys,
        trusted_device_keys,
    });

    // Install handlers
    let hello = warp::get().map(|| "Hello from the rendezvous server");

    // TO0
    let handler_to0_hello = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers_to0::hello,
    );
    let handler_to0_ownersign = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers_to0::ownersign,
    );

    // TO1
    let handler_to1_hello_rv = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers_to1::hello_rv,
    );
    let handler_to1_prove_to_rv = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers_to1::prove_to_rv,
    );

    let routes = warp::post()
        .and(
            hello
                // TO0
                .or(handler_to0_hello)
                .or(handler_to0_ownersign)
                // TO1
                .or(handler_to1_hello_rv)
                .or(handler_to1_prove_to_rv),
        )
        .recover(fdo_http_wrapper::server::handle_rejection)
        .with(warp::log("rendezvous_server"));

    println!("Listening on :8081");
    warp::serve(routes).run(([0, 0, 0, 0], 8081)).await;
    Ok(())
}
