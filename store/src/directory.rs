use core::time::Duration;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::Store;
use super::StoreError;

type ValueT<V> = (Option<SystemTime>, V);

pub(super) fn initialize<K, V>(
    cfg: Option<config::Value>,
) -> Result<Box<dyn Store<K, V>>, StoreError>
where
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    let directory: String = match cfg {
        None => {
            return Err(StoreError::Configuration(
                "No storage directory provided".to_string(),
            ))
        }
        Some(v) => v.try_into(),
    }
    .map_err(|_| StoreError::Configuration("Storage directory invalid type".to_string()))?;

    let dirpath = Path::new(&directory).canonicalize().map_err(|e| {
        StoreError::Configuration(format!(
            "Storage directory '{}' could not be canonicalized: {}",
            directory, e
        ))
    })?;

    Ok(Box::new(DirectoryStore {
        phantom_k: PhantomData,
        phantom_v: PhantomData,

        directory: dirpath,
    }))
}

#[derive(Debug)]
struct DirectoryStore<K, V> {
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,

    directory: PathBuf,
}

#[async_trait]
impl<K, V> Store<K, V> for DirectoryStore<K, V>
where
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        todo!();
    }

    async fn store_data(&self, key: K, ttl: Option<Duration>, value: V) -> Result<(), StoreError> {
        todo!();
    }

    async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
        todo!();
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        Ok(())
    }
}
