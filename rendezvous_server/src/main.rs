use anyhow::{bail, Context, Result};
use openssl::x509::X509;
use serde::Deserialize;
use warp::Filter;

use std::sync::Arc;

use fdo_data_formats::types::Guid;
use fdo_store::{Store, StoreDriver};

mod handlers {
    use fdo_data_formats::constants::ErrorCode;
    use fdo_data_formats::messages;

    use fdo_http_wrapper::server::Error;
    use fdo_http_wrapper::server::{SessionStore, SessionWithStore};

}

struct RendezvousUD {
    trusted_keys: Vec<X509>,
    store: Box<dyn Store<Guid, Vec<u8>>>,
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
    trusted_keys_path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("rendezvous_config"))
        .context("Loading configuration files")?
        .merge(config::Environment::with_prefix("rendezvous"))
        .context("Loading configuration from environment variables")?;
    let settings: Settings = settings.try_into().context("Error parsing configuration")?;

    // Initialize stores
    let store = settings
        .storage_driver
        .initialize(settings.storage_config)?;
    let session_store = settings
        .session_store_driver
        .initialize(settings.session_store_config)?;
    let session_store = fdo_http_wrapper::server::SessionStore::new(session_store);

    // Load X509 certs
    let trusted_keys = {
        let trusted_keys_path = settings.trusted_keys_path;
        let contents = std::fs::read(&trusted_keys_path)
            .with_context(|| format!("Error reading trusted keys at {}", &trusted_keys_path))?;
        X509::stack_from_pem(&contents).context("Error parsing trusted keys")?
    };

    // Initialize handler stores
    let user_data = Arc::new(RendezvousUD {
        store,
        trusted_keys,
    });

    // Install handlers
    let hello = warp::get().map(|| "Hello from the rendezvous server");

    println!("Hello, world!");

    Ok(())
}
