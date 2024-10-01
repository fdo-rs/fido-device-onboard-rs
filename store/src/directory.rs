use std::collections::HashSet;
use std::convert::TryInto;
use std::fs::{self, File};
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use xattr::FileExt;

use fdo_data_formats::Serializable;

use crate::{FilterType, MetadataLocalKey, MetadataValue, ValueIter};

use super::Store;
use super::StoreError;

pub(super) fn initialize<OT, K, V, MKT>(
    path: &Path,
) -> Result<Box<dyn Store<OT, K, V, MKT>>, StoreError>
where
    OT: crate::StoreOpenMode,
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: crate::MetadataLocalKey + 'static,
{
    if !path.is_absolute() {
        return Err(StoreError::Configuration(
            "Storage directory is not absolute".to_string(),
        ));
    }
    fs::create_dir_all(path).map_err(|e| {
        StoreError::Configuration(format!(
            "Storage directory '{path:?}' could not be created: {e}"
        ))
    })?;

    let canonicalized_directory = path.canonicalize().map_err(|e| {
        StoreError::Configuration(format!(
            "Storage directory '{path:?}' could not be canonicalized: {e}"
        ))
    })?;

    Ok(Box::new(DirectoryStore {
        phantom_k: PhantomData,
        phantom_v: PhantomData,

        directory: canonicalized_directory,
    }))
}

#[derive(Debug)]
struct DirectoryStore<K, V> {
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,

    directory: PathBuf,
}

impl<K, V> DirectoryStore<K, V>
where
    K: std::string::ToString,
{
    fn get_path(&self, key: &K) -> PathBuf {
        self.directory.join(key.to_string().replace('/', "_slash_"))
    }
}

// TODO(runcom): fix this to use time::Duration and time
fn ttl_from_disk(ttl: &[u8]) -> Result<SystemTime, StoreError> {
    if ttl.len() != 8 {
        return Err(StoreError::Unspecified(format!(
            "TTL length is not u64: {ttl:?}"
        )));
    }
    let ttl = u64::from_le_bytes(ttl.try_into().unwrap());
    let ttl = Duration::from_secs(ttl);
    Ok(SystemTime::UNIX_EPOCH + ttl)
}

pub struct DirectoryStoreFilterType {
    directory: PathBuf,
    neqs: Vec<(String, Vec<u8>)>,
    lts: Vec<(String, i64)>,
}

fn format_xattr(key: &str) -> String {
    format!("user.{key}")
}

#[async_trait]
impl<V, MKT> FilterType<V, MKT> for DirectoryStoreFilterType
where
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: MetadataLocalKey,
{
    fn neq(&mut self, key: &crate::MetadataKey<MKT>, expected: &dyn MetadataValue) {
        self.neqs
            .push((key.to_key().to_owned(), expected.to_stored().unwrap()));
    }
    fn lt(&mut self, key: &crate::MetadataKey<MKT>, max: i64) {
        self.lts.push((key.to_key().to_owned(), max));
    }
    async fn query(&self) -> Result<crate::FilterQueryResult<V>, StoreError> {
        let dir_entries = match fs::read_dir(&self.directory) {
            Err(e) => {
                log::trace!(
                    "Error during maintenance: unable to list directory {}: {:?}",
                    &self.directory.display(),
                    e
                );
                return Ok(None);
            }
            Ok(v) => v,
        };
        let mut results: HashSet<PathBuf> = HashSet::new();
        for entry in dir_entries {
            let entry = match entry {
                Ok(v) => v,
                Err(e) => {
                    log::trace!("Error during maintenance: unable to process entry: {:?}", e);
                    continue;
                }
            };
            let path = entry.path();
            match entry.file_type() {
                Err(e) => {
                    log::trace!(
                        "Error during maintenance: Unable to determine file type of {}: {:?}",
                        path.display(),
                        e
                    );
                    continue;
                }
                Ok(v) if v.is_file() => {}
                Ok(_) => continue,
            }
            let mut neqs: HashSet<PathBuf> = HashSet::new();
            for neq in &self.neqs {
                let (key, expected) = neq;
                match xattr::get(path.clone(), format_xattr(key)) {
                    Ok(Some(v)) => {
                        let matching = expected.iter().zip(&v).filter(|&(a, b)| a == b).count();
                        if expected.len() != matching {
                            neqs.insert(path.clone());
                        }
                    }
                    Ok(None) => {
                        neqs.insert(path.clone());
                    }
                    Err(e) => {
                        log::trace!("Error checking {}: {}", key, e.to_string());
                        continue;
                    }
                }
            }
            for n in neqs {
                for lt in &self.lts {
                    let (key, max) = lt;
                    match xattr::get(n.clone(), format_xattr(key)) {
                        Ok(Some(v)) => {
                            let value = i64::from_le_bytes(v.try_into().unwrap());
                            if value < *max {
                                results.insert(n.clone());
                            }
                        }
                        Ok(None) => {
                            results.insert(n.clone());
                        }
                        Err(e) => {
                            log::trace!("Error checking {}: {}", key, e.to_string());
                            continue;
                        }
                    }
                }
            }
        }
        let mut values = Vec::new();
        for r in results {
            let file = match File::open(&r) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    log::trace!("Error opening file {}", e.to_string());
                    continue;
                }
                Ok(f) => f,
            };
            match V::deserialize_from_reader(&file) {
                Ok(v) => values.push(v),
                Err(e) => log::trace!("Error deserializing data {:?}: {}", r, e),
            }
        }
        Ok(Some(ValueIter {
            index: 0,
            values,
            errored: false,
        }))
    }
}

#[async_trait]
impl<OT, K, V, MKT> Store<OT, K, V, MKT> for DirectoryStore<K, V>
where
    OT: crate::StoreOpenMode,
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: crate::MetadataLocalKey + 'static,
{
    async fn load_all_data(&self) -> Result<Vec<V>, StoreError> {
        let entries = fs::read_dir(&self.directory)
            .map_err(|e| StoreError::Unspecified(format!("Error reading store directory: {e:?}")))?
            .map(|res| res.map(|e| e.path()))
            .collect::<Result<Vec<_>, io::Error>>()
            .map_err(|e| {
                StoreError::Unspecified(format!("Error collecting store directory entries: {e:?}"))
            })?;
        let mut items = Vec::<V>::new();
        for entry in entries {
            let file = match File::open(&entry) {
                Err(e) => return Err(StoreError::Unspecified(format!("Error opening file: {e}"))),
                Ok(f) => f,
            };
            items.push(V::deserialize_from_reader(&file).map_err(|e| {
                StoreError::Unspecified(format!("Error deserializing value: {e:?}"))
            })?);
        }
        Ok(items)
    }

    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        let path = self.get_path(key);
        log::trace!("Attempting to load data from {}", path.display());

        let file = match File::open(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Unspecified(format!("Error opening file: {e}"))),
            Ok(f) => f,
        };
        match file.get_xattr(format_xattr(crate::MetadataKey::<MKT>::Ttl.to_key())) {
            Ok(Some(ttl)) => {
                let ttl = ttl_from_disk(&ttl)?;
                if SystemTime::now() > ttl {
                    log::trace!("Item has expired, attempting removal");
                    if let Err(e) = fs::remove_file(&path) {
                        log::info!("Error deleting expired file {}: {}", path.display(), e);
                    }
                    return Ok(None);
                }
            }
            Ok(None) => {}
            Err(e) => return Err(StoreError::Unspecified(format!("Error checking TTL: {e}"))),
        }

        Ok(Some(V::deserialize_from_reader(&file).map_err(|e| {
            StoreError::Unspecified(format!("Error deserializing value: {e:?}"))
        })?))
    }

    async fn store_metadata(
        &self,
        key: &K,
        metadata_key: &crate::MetadataKey<MKT>,
        metadata_value: &dyn MetadataValue,
    ) -> Result<(), StoreError> {
        let path = self.get_path(key);
        log::trace!("Attempting to load data from {}", path.display());

        let file = match File::open(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(StoreError::Unspecified(format!("Error opening file: {e}"))),
            Ok(f) => f,
        };

        Ok(file
            .set_xattr(
                format_xattr(metadata_key.to_key()),
                &metadata_value.to_stored()?,
            )
            .map_err(|e| {
                StoreError::Unspecified(format!(
                    "Error creating xattr on {}: {:?}",
                    path.display(),
                    e
                ))
            })?)
    }

    async fn destroy_metadata(
        &self,
        key: &K,
        metadata_key: &crate::MetadataKey<MKT>,
    ) -> Result<(), StoreError> {
        let path = self.get_path(key);
        log::trace!("Attempting to load data from {}", path.display());

        let file = match File::open(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(StoreError::Unspecified(format!("Error opening file: {e}"))),
            Ok(f) => f,
        };

        Ok(file
            .remove_xattr(format_xattr(metadata_key.to_key()))
            .map_err(|e| {
                StoreError::Unspecified(format!(
                    "Error removing xattr on {}: {:?}",
                    path.display(),
                    e
                ))
            })?)
    }

    async fn query_data(&self) -> crate::QueryResult<V, MKT> {
        Ok(Box::new(DirectoryStoreFilterType {
            directory: self.directory.clone(),
            neqs: Vec::new(),
            lts: Vec::new(),
        }))
    }

    async fn query_ovs_db(&self) -> Result<Vec<V>, StoreError> {
        Err(StoreError::MethodNotAvailable)
    }

    async fn query_ovs_db_to2_performed_to0_less_than(
        &self,
        _to2: bool,
        _to0_max: i64,
    ) -> Result<Vec<V>, StoreError> {
        Err(StoreError::MethodNotAvailable)
    }

    async fn store_data(&self, key: K, value: V) -> Result<(), StoreError> {
        let finalpath = self.get_path(&key);
        let mut path = finalpath.clone();
        path.set_file_name(format!(
            ".{}.tmp",
            finalpath.file_name().unwrap().to_str().unwrap()
        ));
        log::trace!(
            "Attempting to store data to {} (temporary at {})",
            finalpath.display(),
            path.display()
        );

        let file = File::create(&path).map_err(|e| {
            StoreError::Unspecified(format!("Error creating file {}: {:?}", path.display(), e))
        })?;
        value.serialize_to_writer(&file).map_err(|e| {
            StoreError::Unspecified(format!("Error writing file {}: {:?}", path.display(), e))
        })?;

        fs::rename(&path, &finalpath).map_err(|e| {
            StoreError::Unspecified(format!(
                "Error moving temporary file {} to {}: {:?}",
                path.display(),
                finalpath.display(),
                e
            ))
        })
    }

    async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
        let path = self.get_path(key);
        log::trace!("Attempting to delete data at {}", path.display());

        fs::remove_file(&path).map_err(|e| {
            StoreError::Unspecified(format!("Error removing '{}': {:?}", path.display(), e))
        })
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        let dir_entries = match fs::read_dir(&self.directory) {
            Err(e) => {
                log::trace!(
                    "Error during maintenance: unable to list directory {}: {:?}",
                    &self.directory.display(),
                    e
                );
                return Ok(());
            }
            Ok(v) => v,
        };
        for entry in dir_entries {
            let entry = match entry {
                Ok(v) => v,
                Err(e) => {
                    log::trace!("Error during maintenance: unable to process entry: {:?}", e);
                    continue;
                }
            };
            let path = entry.path();
            match entry.file_type() {
                Err(e) => {
                    log::trace!(
                        "Error during maintenance: Unable to determine file type of {}: {:?}",
                        path.display(),
                        e
                    );
                    continue;
                }
                Ok(v) if v.is_file() => {}
                Ok(_) => continue,
            }
            let ttl = match xattr::get(&path, format_xattr(crate::MetadataKey::<MKT>::Ttl.to_key()))
            {
                Err(e) => {
                    log::trace!("Error looking up TTL xattr for {}: {:?}", path.display(), e);
                    continue;
                }
                Ok(None) => continue,
                Ok(Some(val)) => ttl_from_disk(&val)?,
            };
            if SystemTime::now() < ttl {
                continue;
            }
            log::trace!("File at {} has expired, attempting removal", path.display());
            if let Err(e) = fs::remove_file(&path) {
                log::info!("Error deleting expired file {}: {}", path.display(), e);
            }
        }

        Ok(())
    }
}
