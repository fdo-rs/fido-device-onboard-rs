use anyhow::{bail, Context, Result};
use openssl::x509::X509;
use serde::Deserialize;
use warp::Filter;

use std::sync::{Arc, RwLock};

use fdo_data_formats::types::Guid;
use fdo_http_wrapper::server::SessionStoreDriver;

mod handlers {
    use fdo_data_formats::{constants::ErrorCode, messages};

    use fdo_http_wrapper::server::{Error, SessionStore, SessionWithStore};

    pub(super) async fn hello(
        _user_data: super::RendezvousUDT,
        mut ses_with_store: SessionWithStore,
        msg: messages::to0::Hello,
    ) -> Result<(messages::to0::HelloAck, SessionWithStore), warp::Rejection> {
        todo!();
    }
}

#[derive(Debug)]
struct RendezvousStorageError;

trait RendezvousStorage: std::fmt::Debug {
    fn store(&self, guid: Guid, data: Vec<u8>) -> Result<(), RendezvousStorageError>;
    fn lookup(&self, guid: Guid) -> Result<Option<Vec<u8>>, RendezvousStorageError>;
}

mod in_memory_storage {
    use std::sync::RwLock;

    use anyhow::Result;

    use super::RendezvousStorage;
    use super::RendezvousStorageError;

    use fdo_data_formats::types::Guid;

    #[derive(Debug)]
    struct InMemoryRendezvousStorage {
        data: RwLock<std::collections::HashMap<Guid, Vec<u8>>>,
    }

    pub(super) fn initialize(_cfg: Option<config::Value>) -> Result<Box<dyn RendezvousStorage>> {
        Ok(Box::new(InMemoryRendezvousStorage {
            data: RwLock::new(std::collections::HashMap::new()),
        }))
    }

    impl RendezvousStorage for InMemoryRendezvousStorage {
        fn store(&self, guid: Guid, value: Vec<u8>) -> Result<(), RendezvousStorageError> {
            let mut data = self.data.write().unwrap();
            data.insert(guid, value);

            Ok(())
        }

        fn lookup(&self, guid: Guid) -> Result<Option<Vec<u8>>, RendezvousStorageError> {
            let data = self.data.read().unwrap();
            Ok(data.get(&guid).cloned())
        }
    }
}

#[derive(Debug)]
struct RendezvousUD {
    trusted_keys: Vec<X509>,
    storage: Box<dyn RendezvousStorage>,
}

type RendezvousUDT = Arc<RendezvousUD>;

#[derive(Debug, Deserialize)]
enum StorageDriver {
    #[cfg(feature = "storage_driver_in_memory")]
    InMemory,
}

impl StorageDriver {
    fn initialize(&self, cfg: Option<config::Value>) -> Result<Box<dyn RendezvousStorage>> {
        match self {
            #[cfg(feature = "storage_driver_in_memory")]
            StorageDriver::InMemory => in_memory_storage::initialize(cfg),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Settings {
    // Storage info
    storage_driver: StorageDriver,
    storage_config: Option<config::Value>,

    // Session store info
    session_store_driver: SessionStoreDriver,
    session_store_config: Option<config::Value>,

    // Trusted keys
    trusted_keys_path: String,
}

fn main() -> Result<()> {
    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("rendezvous_config"))
        .context("Loading configuration files")?
        .merge(config::Environment::with_prefix("rendezvous"))
        .context("Loading configuration from environment variables")?;
    let settings: Settings = settings.try_into().context("Error parsing configuration")?;

    // Initialize storage
    let storage = settings
        .storage_driver
        .initialize(settings.storage_config)?;
    let session_store = settings
        .session_store_driver
        .initialize(settings.session_store_config)?;

    // Load X509 certs
    let trusted_keys = {
        let trusted_keys_path = settings.trusted_keys_path;
        let contents = std::fs::read(&trusted_keys_path)
            .with_context(|| format!("Error reading trusted keys at {}", &trusted_keys_path))?;
        X509::stack_from_pem(&contents).context("Error parsing trusted keys")?
    };

    // Initialize handler stores
    let user_data = Arc::new(RendezvousUD {
        storage,
        trusted_keys,
    });

    // Install handlers
    let hello = warp::get().map(|| "Hello from the rendezvous server");

    println!("User data: {:?}", user_data);

    println!("Hello, world!");

    Ok(())
}
