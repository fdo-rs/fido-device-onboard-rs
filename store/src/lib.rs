use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use fdo_data_formats::Serializable;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Unspecified error occured: {0}")]
    Unspecified(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
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

pub trait Store<OT: StoreOpenMode, K, V>: Send + Sync {
    fn load_data<'life0, 'life1, 'async_trait>(
        &'life0 self,
        key: &'life1 K,
    ) -> Pin<Box<dyn Future<Output = Result<Option<V>, StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
        OT: Readable;

    fn store_data<'life0, 'async_trait>(
        &'life0 self,
        key: K,
        ttl: Option<Duration>,
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

#[derive(Debug, Deserialize)]
pub enum StoreDriver {
    #[cfg(feature = "directory")]
    Directory,
}

impl StoreDriver {
    pub fn initialize<OT, K, V>(
        &self,
        cfg: Option<config::Value>,
    ) -> Result<Box<dyn Store<OT, K, V>>, StoreError>
    where
        OT: StoreOpenMode + 'static,
        // K and V are supersets of the possible requirements for the different implementations
        K: Eq + std::hash::Hash + Send + Sync + std::string::ToString + std::str::FromStr + 'static,
        V: Send + Sync + Clone + Serializable + 'static,
    {
        match self {
            #[cfg(feature = "directory")]
            StoreDriver::Directory => directory::initialize(cfg),
        }
    }
}
