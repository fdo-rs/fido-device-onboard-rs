use core::future::Future;
use core::pin::Pin;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use fdo_data_formats::{ownershipvoucher::OwnershipVoucher, Serializable};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Unspecified error occurred: {0}")]
    Unspecified(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Method not available")]
    MethodNotAvailable,
    #[error("Internal database error: {0}")]
    Database(String),
}

mod private {
    pub trait Sealed {}

    // Implement for those same types, but no others.
    impl Sealed for super::ReadWriteOpen {}
    impl Sealed for super::ReadOnlyOpen {}
    impl Sealed for super::WriteOnlyOpen {}
}

pub trait Readable: private::Sealed {}
pub trait Writable: private::Sealed {}
pub trait StoreOpenMode: private::Sealed {}

pub struct ReadWriteOpen();
impl StoreOpenMode for ReadWriteOpen {}
impl Readable for ReadWriteOpen {}
impl Writable for ReadWriteOpen {}

pub struct ReadOnlyOpen();
impl StoreOpenMode for ReadOnlyOpen {}
impl Readable for ReadOnlyOpen {}

pub struct WriteOnlyOpen();
impl StoreOpenMode for WriteOnlyOpen {}
impl Writable for WriteOnlyOpen {}

pub trait MetadataValue: Send + Sync {
    fn to_stored(&self) -> Result<Vec<u8>, StoreError>;
    fn to_text(&self) -> String;
}

impl MetadataValue for bool {
    fn to_stored(&self) -> Result<Vec<u8>, StoreError> {
        Ok(self.to_string().as_bytes().to_vec())
    }
    fn to_text(&self) -> String {
        self.to_string()
    }
}

impl MetadataValue for time::Duration {
    fn to_stored(&self) -> Result<Vec<u8>, StoreError> {
        let ttl = time::OffsetDateTime::now_utc() + *self;
        Ok(i64::to_le_bytes(ttl.unix_timestamp()).into())
    }
    fn to_text(&self) -> String {
        let ttl = time::OffsetDateTime::now_utc() + *self;
        ttl.unix_timestamp().to_string()
    }
}

pub trait MetadataLocalKey: Send + Sync {
    fn to_key(&self) -> &'static str;
}

#[non_exhaustive]
pub enum MetadataKey<T: MetadataLocalKey> {
    Ttl,
    Local(T),
}

impl<T: MetadataLocalKey> MetadataKey<T> {
    fn to_key(&self) -> &str {
        match self {
            MetadataKey::Ttl => "store_ttl",
            MetadataKey::Local(k) => k.to_key(),
        }
    }
}

type FilterQueryResult<V> = Option<ValueIter<V>>;

pub trait FilterType<V, MKT>: Send + Sync
where
    V: Clone,
    MKT: MetadataLocalKey,
{
    fn neq(&mut self, key: &MetadataKey<MKT>, expected: &dyn MetadataValue);
    fn lt(&mut self, key: &MetadataKey<MKT>, max: i64);
    fn query<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = Result<FilterQueryResult<V>, StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
}

pub struct ValueIter<V: Clone> {
    values: Vec<V>,
    index: usize,
    errored: bool,
}

impl<V> Iterator for ValueIter<V>
where
    V: Clone,
{
    type Item = V;

    fn next(&mut self) -> Option<Self::Item> {
        if self.errored {
            log::warn!("Previous entry validation failed");
            return None;
        }
        if self.index >= self.values.len() {
            return None;
        }

        let entry = self.values.get(self.index);
        match entry {
            Some(e) => {
                self.index += 1;
                Some(e.clone())
            }
            None => {
                log::warn!("Error getting next entry");
                self.errored = true;
                None
            }
        }
    }
}

type QueryResult<V, MKT> = Result<Box<dyn FilterType<V, MKT>>, StoreError>;

pub trait Store<OT: StoreOpenMode, K, V, MKT: MetadataLocalKey>: Send + Sync {
    fn load_data<'life0, 'life1, 'async_trait>(
        &'life0 self,
        key: &'life1 K,
    ) -> Pin<Box<dyn Future<Output = Result<Option<V>, StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
        OT: Readable;

    fn store_metadata<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        key: &'life1 K,
        metadata_key: &'life2 MetadataKey<MKT>,
        metadata_value: &'life3 dyn MetadataValue,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait,
        OT: Writable;

    fn destroy_metadata<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        key: &'life1 K,
        metadata_key: &'life2 MetadataKey<MKT>,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
        OT: Writable;

    fn query_data<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = QueryResult<V, MKT>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
        OT: Writable;

    fn query_ovs_db<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Vec<OwnershipVoucher>, StoreError>> + 'async_trait + Send>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait;

    fn query_ovs_db_to2_performed_to0_less_than<'life0, 'async_trait>(
        &'life0 self,
        to2: bool,
        to0_max: i64,
    ) -> Pin<
        Box<dyn Future<Output = Result<Vec<OwnershipVoucher>, StoreError>> + 'async_trait + Send>,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait;

    fn store_data<'life0, 'async_trait>(
        &'life0 self,
        key: K,
        value: V,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
        OT: Writable;

    fn destroy_data<'life0, 'life1, 'async_trait>(
        &'life0 self,
        key: &'life1 K,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
        OT: Writable;

    fn perform_maintenance<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
        OT: Writable;
}

#[cfg(feature = "directory")]
mod directory;

#[derive(Debug, Serialize, Deserialize)]
pub enum ServerType {
    Manufacturer,
    Owner,
    Rendezvous,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum StoreConfig {
    #[cfg(feature = "directory")]
    Directory { path: std::path::PathBuf },
    #[cfg(feature = "db")]
    Sqlite { server: ServerType, url: String },
    #[cfg(feature = "db")]
    Postgres { server: ServerType, url: String },
}

#[cfg(feature = "db")]
mod pg;
#[cfg(feature = "db")]
mod sqlite;

impl StoreConfig {
    pub fn initialize<OT, K, V, MKT>(&self) -> Result<Box<dyn Store<OT, K, V, MKT>>, StoreError>
    where
        OT: StoreOpenMode + 'static,
        // K and V are supersets of the possible requirements for the different implementations
        K: Eq + std::hash::Hash + Send + Sync + std::string::ToString + std::str::FromStr + 'static,
        V: Send + Sync + Clone + Serializable + 'static,
        MKT: crate::MetadataLocalKey + 'static,
    {
        match self {
            #[cfg(feature = "directory")]
            StoreConfig::Directory { path } => directory::initialize(path),
            #[cfg(feature = "db")]
            StoreConfig::Sqlite { server, url } => sqlite::initialize(server, url.clone()),
            #[cfg(feature = "db")]
            StoreConfig::Postgres { server, url } => pg::initialize(server, url.clone()),
        }
    }
}
