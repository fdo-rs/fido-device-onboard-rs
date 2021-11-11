use std::convert::TryInto;
use std::fs::{self, File};
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
    cfg: Option<config::Value>,
) -> Result<Box<dyn Store<OT, K, V, MKT>>, StoreError>
where
    OT: crate::StoreOpenMode,
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: crate::MetadataLocalKey + 'static,
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

    let dirpath = Path::new(&directory);
    fs::create_dir_all(dirpath).map_err(|e| {
        StoreError::Configuration(format!(
            "Storage directory '{}' could not be created: {}",
            directory, e
        ))
    })?;

    let canonicalized_directory = dirpath.canonicalize().map_err(|e| {
        StoreError::Configuration(format!(
            "Storage directory '{}' could not be canonicalized: {}",
            directory, e
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
        self.directory.join(key.to_string().replace("/", "_slash_"))
    }
}

fn ttl_from_disk(ttl: &[u8]) -> Result<SystemTime, StoreError> {
    if ttl.len() != 8 {
        return Err(StoreError::Unspecified(format!(
            "TTL length is not u64: {:?}",
            ttl
        )));
    }
    let ttl = u64::from_le_bytes(ttl.try_into().unwrap());
    let ttl = Duration::from_secs(ttl as u64);
    Ok(SystemTime::UNIX_EPOCH + ttl)
}

fn ttl_to_disk(ttl: SystemTime) -> Result<Vec<u8>, StoreError> {
    let ttl = ttl.duration_since(SystemTime::UNIX_EPOCH).map_err(|e| {
        StoreError::Unspecified(format!("Error determining time from epoch to TTL: {:?}", e))
    })?;
    let ttl = ttl.as_secs();
    Ok(u64::to_le_bytes(ttl).into())
}

pub struct DirectoryStoreFilterType {
    directory: PathBuf,
    eqs: Vec<(String, Vec<u8>)>,
}

#[async_trait]
impl<V, MKT> FilterType<V, MKT> for DirectoryStoreFilterType
where
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: MetadataLocalKey,
{
    fn eq(&mut self, key: &crate::MetadataKey<MKT>, expected: &dyn MetadataValue) {
        self.eqs
            .push((key.to_key().to_owned(), expected.to_stored().unwrap()));
    }
    fn or(&mut self) {
        todo!()
    }
    fn lt(&mut self, _: &crate::MetadataKey<MKT>, _: i64) {
        todo!()
    }
    async fn query(&self) -> Result<Option<ValueIter<V>>, StoreError> {
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
        let mut results = Vec::new();
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
            let file = match File::open(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    log::trace!("Error opening file {}", e.to_string());
                    continue;
                }
                Ok(f) => f,
            };
            // TODO(runcom): implement "or" and "lt"
            for eq in &self.eqs {
                let (key, expected) = eq;
                match file.get_xattr(key) {
                    Ok(Some(v)) => {
                        let matching = expected.iter().zip(&v).filter(|&(a, b)| a == b).count();
                        if expected.len() == matching {
                            results.push(V::deserialize_from_reader(&file).map_err(|e| {
                                StoreError::Unspecified(format!(
                                    "Error deserializing value: {:?}",
                                    e
                                ))
                            })?)
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        log::trace!("Error checking {}: {}", key, e.to_string());
                        continue;
                    }
                }
            }
        }
        Ok(Some(ValueIter {
            index: 0,
            values: results,
        }))
    }
}

const XATTR_NAME_TTL: &str = "user.store_ttl";

#[async_trait]
impl<OT, K, V, MKT> Store<OT, K, V, MKT> for DirectoryStore<K, V>
where
    OT: crate::StoreOpenMode,
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: crate::MetadataLocalKey + 'static,
{
    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        let path = self.get_path(key);
        log::trace!("Attempting to load data from {}", path.display());

        let file = match File::open(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(StoreError::Unspecified(format!(
                    "Error opening file: {}",
                    e.to_string()
                )))
            }
            Ok(f) => f,
        };
        match file.get_xattr(XATTR_NAME_TTL) {
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
            Err(e) => {
                return Err(StoreError::Unspecified(format!(
                    "Error checking TTL: {}",
                    e
                )))
            }
        }

        Ok(Some(V::deserialize_from_reader(&file).map_err(|e| {
            StoreError::Unspecified(format!("Error deserializing value: {:?}", e))
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
            Err(e) => {
                return Err(StoreError::Unspecified(format!(
                    "Error opening file: {}",
                    e.to_string()
                )))
            }
            Ok(f) => f,
        };

        Ok(file
            .set_xattr(metadata_key.to_key(), &metadata_value.to_stored()?)
            .map_err(|e| {
                StoreError::Unspecified(format!(
                    "Error creating xattr on {}: {:?}",
                    path.display(),
                    e
                ))
            })?)
    }

    async fn query_data(&self) -> Result<Box<dyn crate::FilterType<V, MKT>>, StoreError> {
        Ok(Box::new(DirectoryStoreFilterType {
            directory: self.directory.clone(),
            eqs: Vec::new(),
        }))
    }

    async fn store_data(&self, key: K, ttl: Option<Duration>, value: V) -> Result<(), StoreError> {
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

        let ttl = match ttl {
            None => None,
            Some(ttl) => Some(ttl_to_disk(SystemTime::now() + ttl)?),
        };

        let file = File::create(&path).map_err(|e| {
            StoreError::Unspecified(format!("Error creating file {}: {:?}", path.display(), e))
        })?;
        if let Some(ttl) = ttl {
            file.set_xattr(XATTR_NAME_TTL, &ttl).map_err(|e| {
                StoreError::Unspecified(format!(
                    "Error creating xattr on {}: {:?}",
                    path.display(),
                    e
                ))
            })?;
        }
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
            let ttl = match xattr::get(&path, XATTR_NAME_TTL) {
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
