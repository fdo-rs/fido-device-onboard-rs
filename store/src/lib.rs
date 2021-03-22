use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Unspecified error occured: {0}")]
    Unspecified(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
}

pub trait Store<K, V>: Send + Sync {
    fn load_data<'life0, 'life1, 'async_trait>(
        &'life0 self,
        key: &'life1 K,
    ) -> Pin<Box<dyn Future<Output = Result<Option<V>, StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;

    fn store_data<'life0, 'async_trait>(
        &'life0 self,
        key: K,
        ttl: Option<Duration>,
        value: V,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;

    fn destroy_data<'life0, 'life1, 'async_trait>(
        &'life0 self,
        key: &'life1 K,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait;

    fn perform_maintenance<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
}

#[cfg(feature = "directory")]
mod directory;
mod in_memory;

#[derive(Debug, Deserialize)]
pub enum StoreDriver {
    InMemory,
    #[cfg(feature = "directory")]
    Directory,
}

impl StoreDriver {
    pub fn initialize<K, V>(
        &self,
        cfg: Option<config::Value>,
    ) -> Result<Box<dyn Store<K, V>>, StoreError>
    where
        // K and V are supersets of the possible requirements for the different implementations
        K: Eq + std::hash::Hash + Send + Sync + std::string::ToString + std::str::FromStr + 'static,
        V: Send + Sync + Clone + Serialize + DeserializeOwned + 'static,
    {
        match self {
            StoreDriver::InMemory => in_memory::initialize(cfg),
            #[cfg(feature = "directory")]
            StoreDriver::Directory => directory::initialize(cfg),
        }
    }
}
