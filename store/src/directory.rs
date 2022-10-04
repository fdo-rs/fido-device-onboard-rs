use regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs::{self, File};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::{self, FromStr};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use xattr::FileExt;

use fdo_data_formats::Serializable;

use crate::{format_xattr, FdoMetadata, FilterType, MetadataLocalKey, MetadataValue, ValueIter};
use crate::{set_metadata_extension_to_path, FDO_METADATA_EX};

use super::DirectoryStorageMode;
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
            "Storage directory '{:?}' could not be created: {}",
            path, e
        ))
    })?;

    let canonicalized_directory = path.canonicalize().map_err(|e| {
        StoreError::Configuration(format!(
            "Storage directory '{:?}' could not be canonicalized: {}",
            path, e
        ))
    })?;

    let xattr_support = check_xattr_support(&canonicalized_directory)?;

    Ok(Box::new(DirectoryStore {
        phantom_k: PhantomData,
        phantom_v: PhantomData,

        directory: canonicalized_directory,
        xattr_enabled: xattr_support,
    }))
}

pub(super) fn initialize_explicit_mode<OT, K, V, MKT>(
    path: &Path,
    mode: DirectoryStorageMode,
) -> Result<Box<dyn Store<OT, K, V, MKT>>, StoreError>
where
    OT: crate::StoreOpenMode + 'static,
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
            "Storage directory '{:?}' could not be created: {}",
            path, e
        ))
    })?;

    let canonicalized_directory = path.canonicalize().map_err(|e| {
        StoreError::Configuration(format!(
            "Storage directory '{:?}' could not be canonicalized: {}",
            path, e
        ))
    })?;
    let xattr_enabled = match mode {
        DirectoryStorageMode::MetadataFile => false,
        DirectoryStorageMode::Xattr => true,
    };
    Ok(Box::new(DirectoryStore {
        phantom_k: PhantomData,
        phantom_v: PhantomData,

        directory: canonicalized_directory,
        xattr_enabled,
    }))
}

#[derive(Debug)]
struct DirectoryStore<K, V> {
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,

    directory: PathBuf,
    xattr_enabled: bool,
}

impl<K, V> DirectoryStore<K, V>
where
    K: std::string::ToString,
{
    fn get_path(&self, key: &K) -> PathBuf {
        self.directory.join(key.to_string().replace('/', "_slash_"))
    }
}

/// Filesystems supported by the linux kernel that also support extended attributes
enum FileSystemXattrSupport {
    Btrfs,
    Ext2,
    Ext3,
    Ext4,
    F2fs,
    Lustre,
    Jfs,
    Ocfs2,
    Orangefs,
    Reiser4,
    Reiserfs,
    Squashfs,
    Ubifs,
    Xfs,
    Yaffs2,
    Zfs,
}

impl FromStr for FileSystemXattrSupport {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "btrfs" => Ok(FileSystemXattrSupport::Btrfs),
            "ext2" => Ok(FileSystemXattrSupport::Ext2),
            "ext3" => Ok(FileSystemXattrSupport::Ext3),
            "ext4" => Ok(FileSystemXattrSupport::Ext4),
            "f2fs" => Ok(FileSystemXattrSupport::F2fs), // check
            "lustre" => Ok(FileSystemXattrSupport::Lustre), // check
            "jfs" => Ok(FileSystemXattrSupport::Jfs),
            "ocfs2" => Ok(FileSystemXattrSupport::Ocfs2), // check
            "orangefs" => Ok(FileSystemXattrSupport::Orangefs), // check
            "reiser4" => Ok(FileSystemXattrSupport::Reiser4),
            "reiser" => Ok(FileSystemXattrSupport::Reiserfs),
            "squashfs" => Ok(FileSystemXattrSupport::Squashfs),
            "ubifs" => Ok(FileSystemXattrSupport::Ubifs),
            "xfs" => Ok(FileSystemXattrSupport::Xfs),
            "yaffs2" => Ok(FileSystemXattrSupport::Yaffs2), // check
            "zfs" => Ok(FileSystemXattrSupport::Zfs),
            _ => Err(StoreError::Configuration(format!("Unsupported filesystem"))),
        }
    }
}

/// Checks whether the filesystem in the given path supports xattrs
fn check_xattr_support(path: &Path) -> Result<bool, StoreError> {
    let output = Command::new("df")
        .arg("-T")
        .arg(path)
        .output()
        .expect("command failed");
    if !output.status.success() {
        return Err(StoreError::Unspecified(format!(
            "Couldn't initialize store"
        )));
    }
    let result = String::from_utf8(output.stdout);
    let mut result = match result {
        Ok(result) => result,
        Err(e) => {
            return Err(StoreError::Unspecified(format!(
                "Converting df output: {:?}",
                e
            )))
        }
    };
    let pos = result.find("\n").expect("Parsing df output");
    result.drain(..pos + 1);
    let re =
        regex::Regex::new(r"[\d[:alpha:]/]+[[:space:]]+([\d[:alpha:]]+).+").expect("Invalid regex");
    let captures = re.captures(&result).unwrap();
    let filesystem = match captures.get(1) {
        None => return Err(StoreError::Unspecified(format!("Parsing df regex output"))),
        Some(fs) => fs,
    };
    match FileSystemXattrSupport::from_str(&filesystem.as_str()) {
        Ok(_) => {
            log::trace!(
                "'{}' filesystem type, xattr supported",
                &filesystem.as_str()
            );
            return Ok(true);
        }
        Err(_) => {
            log::trace!(
                "'{}' filesystem type, xattr not supported",
                &filesystem.as_str()
            );
            return Ok(false);
        }
    };
}

// TODO(runcom): fix this to use time::Duration and time
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

pub struct DirectoryStoreFilterType {
    directory: PathBuf,
    neqs: Vec<(String, Vec<u8>)>,
    lts: Vec<(String, i64)>,
    xattr_enabled: bool,
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
            // skip metadata files if xattr is not supported, we are iterating
            // the files that have content but filtering based on metadata
            if !self.xattr_enabled {
                match path.as_path().extension() {
                    None => (),
                    Some(ex) => {
                        if ex == FDO_METADATA_EX {
                            continue;
                        }
                    }
                }
            }
            let mut neqs: HashSet<PathBuf> = HashSet::new();
            for neq in &self.neqs {
                let (key, expected) = neq;

                if self.xattr_enabled {
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
                } else {
                    let path_meta = set_metadata_extension_to_path(&path)?;
                    let file = match File::open(&path_meta) {
                        Ok(f) => f,
                        Err(e) => {
                            return Err(StoreError::Unspecified(format!(
                                "Couldn't open file (r): {}",
                                e
                            )))
                        }
                    };
                    let metadata: FdoMetadata = match serde_cbor::from_reader(&file) {
                        Ok(data) => data,
                        Err(e) => {
                            return Err(StoreError::Unspecified(format!(
                                "Error deserialising data: {}",
                                e
                            )))
                        }
                    };
                    // insert the path to the file with contents, not the path
                    // to the associated metadata file
                    match metadata.map.get(&format_xattr(key)) {
                        Some(v) => {
                            let matching = expected.iter().zip(v).filter(|&(a, b)| a == b).count();
                            if expected.len() != matching {
                                neqs.insert(path.clone());
                            }
                        }
                        None => {
                            neqs.insert(path.clone());
                        }
                    }
                }
            }
            for n in neqs {
                for lt in &self.lts {
                    let (key, max) = lt;
                    if self.xattr_enabled {
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
                    } else {
                        // neqs holds paths fo files with data, not metadata,
                        // we need to filter based on metadata
                        let path_meta = set_metadata_extension_to_path(&n)?;
                        let file = match File::open(&path_meta) {
                            Ok(f) => f,
                            Err(e) => {
                                return Err(StoreError::Unspecified(format!(
                                    "Couldn't open file (r): {}",
                                    e
                                )))
                            }
                        };
                        let metadata: FdoMetadata = match serde_cbor::from_reader(file) {
                            Ok(data) => data,
                            Err(e) => {
                                return Err(StoreError::Unspecified(format!(
                                    "Error deserialising data: {}",
                                    e
                                )))
                            }
                        };
                        // if it has what we want insert 'n', the file with data
                        match metadata.map.get(&format_xattr(key)) {
                            Some(v) => {
                                let v: &Vec<u8> = v;
                                let value = i64::from_le_bytes(v.clone().try_into().unwrap());
                                if value < *max {
                                    results.insert(n.clone());
                                }
                            }
                            None => {
                                results.insert(n.clone());
                            }
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
    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        let path = self.get_path(key);
        log::trace!("Attempting to load data from {}", path.display());

        let file = match File::open(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(e) => {
                return Err(StoreError::Unspecified(format!(
                    "Error opening file: {}",
                    e,
                )))
            }
            Ok(f) => f,
        };
        if self.xattr_enabled {
            match file.get_xattr(format_xattr(crate::MetadataKey::<MKT>::Ttl.to_key())) {
                Ok(Some(ttl)) => {
                    let ttl = ttl_from_disk(&ttl)?;
                    if SystemTime::now() > ttl {
                        log::trace!("Item has expired, attempting removal");
                        if let Err(e) = fs::remove_file(&path) {
                            log::warn!("Error deleting expired file {}: {}", path.display(), e);
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
            };
        } else {
            // We have two files, the file with the data (passed as a parameter)
            // and the associated metadata file, which it's in the same path,
            // and has the same name, but a different extension.
            let path_meta = set_metadata_extension_to_path(&path)?;
            let file_meta = match File::open(&path_meta) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error opening file: {}",
                        e,
                    )))
                }
                Ok(f) => f,
            };
            let metadata: FdoMetadata = match serde_cbor::from_reader(&file_meta) {
                Ok(data) => data,
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error reading metadata from '{}': {}",
                        path_meta.display(),
                        e
                    )))
                }
            };
            let val = metadata.map.get(crate::MetadataKey::<MKT>::Ttl.to_key());
            match val {
                Some(ttl) => {
                    let ttl = ttl_from_disk(&ttl)?;
                    if SystemTime::now() > ttl {
                        log::trace!("Item has expired, attempting removal");
                        if let Err(e) = fs::remove_file(&path) {
                            log::warn!("Error deleting expired file {}: {}", path.display(), e);
                        }
                        // also remove associated metadata file
                        if let Err(e) = fs::remove_file(&path_meta) {
                            log::warn!(
                                "Error deleting associated metadata of expired file {}: {}",
                                path_meta.display(),
                                e
                            );
                        }
                        return Ok(None);
                    }
                }
                None => {}
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
        if self.xattr_enabled {
            let file = match File::open(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error opening file: {}",
                        e,
                    )));
                }
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
        } else {
            let path = set_metadata_extension_to_path(&path)?;
            let (file, previous) = match File::open(&path) {
                Ok(f) => (f, true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => match File::create(&path) {
                    Err(e) => {
                        return Err(StoreError::Unspecified(format!(
                            "Couldn't create file: {}",
                            e
                        )));
                    }
                    Ok(f) => (f, false),
                },
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error opening file (r): {}",
                        e,
                    )));
                }
            };
            let mut metadata: FdoMetadata;
            if previous {
                metadata = match serde_cbor::from_reader(&file) {
                    Ok(data) => data,
                    Err(e) => {
                        return Err(StoreError::Unspecified(format!(
                            "Error deserialising data: {}",
                            e
                        )))
                    }
                };
                metadata.map.insert(
                    metadata_key.to_key().to_string(),
                    metadata_value.to_stored()?,
                );
            } else {
                let mut hm = HashMap::new();
                hm.insert(
                    metadata_key.to_key().to_string(),
                    metadata_value.to_stored()?,
                );
                metadata = FdoMetadata { map: hm };
            }
            drop(file);
            let file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error opening file (w): {}",
                        e
                    )))
                }
            };
            match serde_cbor::to_writer(&file, &metadata) {
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error serializing data: {}",
                        e
                    )))
                }
                Ok(_) => Ok(()),
            }
        }
    }

    async fn destroy_metadata(
        &self,
        key: &K,
        metadata_key: &crate::MetadataKey<MKT>,
    ) -> Result<(), StoreError> {
        let path = self.get_path(key);
        log::trace!("Attempting to load data from {}", path.display());

        if self.xattr_enabled {
            let file = match File::open(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error opening file: {}",
                        e,
                    )))
                }
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
        } else {
            let path = set_metadata_extension_to_path(&path)?;
            let file = match File::open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error opening file: {}",
                        e
                    )))
                }
            };
            let mut metadata: FdoMetadata = match serde_cbor::from_reader(&file) {
                Ok(data) => data,
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error deserialising data from '{}': {}",
                        path.display(),
                        e
                    )))
                }
            };
            drop(file);
            metadata
                .map
                .remove_entry(&metadata_key.to_key().to_string());
            let file = match File::create(&path) {
                Ok(f) => f,
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error opening file (w): {}",
                        e
                    )))
                }
            };
            match serde_cbor::to_writer(&file, &metadata) {
                Ok(_) => Ok(()),
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error serializing data to '{}': {}",
                        path.display(),
                        e
                    )))
                }
            }
        }
    }

    async fn query_data(&self) -> crate::QueryResult<V, MKT> {
        println!("On query_data (dir.rs)");
        Ok(Box::new(DirectoryStoreFilterType {
            directory: self.directory.clone(),
            neqs: Vec::new(),
            lts: Vec::new(),
            xattr_enabled: self.xattr_enabled,
        }))
    }

    async fn store_data(&self, key: K, value: V) -> Result<(), StoreError> {
        println!("On store_data (dir.rs)");
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
        println!("On destroy_data (dir.rs)");
        let path = self.get_path(key);
        log::trace!("Attempting to delete data at {}", path.display());

        match fs::remove_file(&path) {
            Ok(_) => (),
            Err(e) => {
                return Err(StoreError::Unspecified(format!(
                    "Error removing '{}': {:?}",
                    path.display(),
                    e
                )))
            }
        };
        // also destroy associated metadata
        if !self.xattr_enabled {
            let path = set_metadata_extension_to_path(&path)?;
            match fs::remove_file(&path) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => {
                    return Err(StoreError::Unspecified(format!(
                        "Error removing associated metadata file '{}': {:?}",
                        path.display(),
                        e,
                    )))
                }
            }
        } else {
            Ok(())
        }
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        println!("On perform_maintenance (dir.rs)");
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
            // skip non-metadata files if xattr is not supported
            if !self.xattr_enabled {
                match path.as_path().extension() {
                    None => continue,
                    Some(ex) => {
                        if ex != FDO_METADATA_EX {
                            continue;
                        }
                    }
                }
                let path_meta = set_metadata_extension_to_path(&path)?;
                let file_meta = match File::open(&path_meta) {
                    Ok(f) => f,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        log::trace!(
                            "Error opening metadata file {}: {:?}",
                            path_meta.display(),
                            e
                        );
                        continue;
                    }
                };
                let metadata: FdoMetadata = match serde_cbor::from_reader(&file_meta) {
                    Ok(data) => data,
                    Err(e) => {
                        return Err(StoreError::Unspecified(format!(
                            "Error reading metadata from '{}': {:?}",
                            path_meta.display(),
                            e
                        )))
                    }
                };
                let val = metadata.map.get(crate::MetadataKey::<MKT>::Ttl.to_key());
                match val {
                    Some(ttl) => {
                        if SystemTime::now() < ttl_from_disk(&ttl)? {
                            continue;
                        }
                    }
                    None => {
                        continue;
                    }
                };
                log::trace!("File at {} has expired, attempting removal", path.display());
                if let Err(e) = fs::remove_file(&path) {
                    log::warn!("Error deleting expired file {}: {}", path.display(), e);
                }
                if let Err(e) = fs::remove_file(&path_meta) {
                    log::warn!(
                        "Error deleting expired metadata file {}: {}",
                        path_meta.display(),
                        e
                    );
                }
            } else {
                let ttl = match xattr::get(
                    &path,
                    format_xattr(crate::MetadataKey::<MKT>::Ttl.to_key()),
                ) {
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
        }

        Ok(())
    }
}
