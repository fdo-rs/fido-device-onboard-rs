use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use log::trace;
use tokio::sync::RwLock;

use super::Store;
use super::StoreError;

type ValueT<V> = (Option<SystemTime>, V);

#[derive(Debug)]
struct MemoryStore<K, V> {
    store: Arc<RwLock<HashMap<K, ValueT<V>>>>,
}

pub(super) fn initialize<K, V>(
    _cfg: Option<config::Value>,
) -> Result<Box<dyn Store<K, V>>, StoreError>
where
    K: std::string::ToString + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + Clone + 'static,
{
    Ok(Box::new(MemoryStore {
        store: Arc::new(RwLock::new(HashMap::new())),
    }))
}

#[async_trait]
impl<K, V> Store<K, V> for MemoryStore<K, V>
where
    K: std::string::ToString + Eq + std::hash::Hash + Send + Sync,
    V: Send + Sync + Clone,
{
    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        trace!("Looking for entry {}", key.to_string());
        let store = self.store.read().await;
        let data = store.get(key);

        if data.is_none() {
            trace!("Entry not found");
            return Ok(None);
        }
        let (ttl, data) = data.unwrap();
        if ttl.is_some() && ttl.unwrap() < SystemTime::now() {
            trace!("Entry had expired");
            return Ok(None);
        }
        trace!("Returning data");
        return Ok(Some(data.clone()));
    }

    async fn store_data(&self, key: K, ttl: Option<Duration>, value: V) -> Result<(), StoreError> {
        trace!("Storing entry, key {}, TTL {:?}", key.to_string(), ttl);

        let ttl = ttl.map(|d| SystemTime::now() + d);

        self.store.write().await.insert(key, (ttl, value));
        Ok(())
    }

    async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
        trace!("Destroying entry");

        self.store.write().await.remove(key);
        Ok(())
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        // TODO
        Ok(())
    }
}
