use core::pin::Pin;
use core::future::Future;
use core::time::Duration;

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Unspecified error occured")]
    Unspecified,
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
    ) -> Pin<Box<dyn Future<Output=Result<(), StoreError>> + 'async_trait + Send>>
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

mod in_memory {
    use std::collections::HashMap;
    use core::time::Duration;
    use std::time::SystemTime;

    use async_trait::async_trait;
    use async_std::sync::{Arc, RwLock};

    use super::Store;
    use super::StoreError;

    type ValueT<V> = (Option<SystemTime>, V);

    #[derive(Debug)]
    struct MemoryStore<K, V>
    where
    {
        store: Arc<RwLock<HashMap<K, ValueT<V>>>>,
    }

    pub(super) fn initialize<K, V>(
        _cfg: Option<config::Value>,
    ) -> Result<Box<dyn Store<K, V>>, StoreError>
    where
        K: Eq + std::hash::Hash + Send + Sync + 'static,
        V: Send + Sync + Clone + 'static,
    {
        Ok(Box::new(MemoryStore {
            store: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    #[async_trait]
    impl<K, V> Store<K, V> for MemoryStore<K, V>
    where
        K: Eq + std::hash::Hash + Send + Sync,
        V: Send + Sync + Clone,
    {
        async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {

            Ok(
                self
                .store
                .read()
                .await
                .get(key)
                .filter(|(ttl, _)| ttl.is_none() || ttl.unwrap() < SystemTime::now())
                .map(|(_, v)| v)
                .cloned()
            )
        }

        async fn store_data(&self, key: K, ttl: Option<Duration>, value: V) -> Result<(), StoreError> {
            let ttl = ttl.map(|d| SystemTime::now() + d);

            self.store.write().await.insert(key, (ttl, value));
            Ok(())
        }

        async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
            self.store.write().await.remove(key);
            Ok(())
        }

        async fn perform_maintenance(&self) -> Result<(), StoreError> {
            // TODO
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize)]
pub enum StoreDriver {
    //#[cfg(feature = "in_memory")]
    InMemory,
}

impl StoreDriver {
    pub fn initialize<K, V>(&self, cfg: Option<config::Value>) -> Result<Box<dyn Store<K, V>>, StoreError>
    where
        K: Eq + std::hash::Hash + Send + Sync + 'static,
        V: Send + Sync + Clone + Serialize + DeserializeOwned + 'static,
    {
        match self {
            //#[cfg(feature = "in_memory")]
            StoreDriver::InMemory => in_memory::initialize(cfg),
        }
    }
}
