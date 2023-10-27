use anyhow::bail;
use async_trait::async_trait;
use fdo_data_formats::ownershipvoucher::OwnershipVoucher;
use fdo_db::*;
use std::marker::PhantomData;

use crate::Store;
use crate::StoreError;
use crate::{FilterType, MetadataLocalKey, MetadataValue, ValueIter};
use fdo_data_formats::Serializable;

struct SqliteManufacturerStore<K, V> {
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,
}

impl<K, V> SqliteManufacturerStore<K, V> where K: std::string::ToString {}

pub(super) fn initialize<OT, K, V, MKT>() -> Result<Box<dyn Store<OT, K, V, MKT>>, StoreError>
where
    OT: crate::StoreOpenMode,
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: crate::MetadataLocalKey + 'static,
{
    Ok(Box::new(SqliteManufacturerStore {
        phantom_k: PhantomData,
        phantom_v: PhantomData,
    }))
}

pub struct SqliteManufacturerStoreFilterType {
    neqs: Vec<bool>,
    lts: Vec<bool>,
}

#[async_trait]
impl<V, MKT> FilterType<V, MKT> for SqliteManufacturerStoreFilterType
where
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: MetadataLocalKey,
{
    fn neq(&mut self, _key: &crate::MetadataKey<MKT>, _expected: &dyn MetadataValue) {
        self.neqs = Vec::new();
    }
    fn lt(&mut self, _key: &crate::MetadataKey<MKT>, _max: i64) {
        self.lts = Vec::new();
    }
    async fn query(&self) -> Result<crate::FilterQueryResult<V>, StoreError> {
        let values = Vec::new();
        Ok(Some(ValueIter {
            index: 0,
            values,
            errored: false,
        }))
    }
}

#[async_trait]
impl<OT, K, V, MKT> Store<OT, K, V, MKT> for SqliteManufacturerStore<K, V>
where
    OT: crate::StoreOpenMode,
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: crate::MetadataLocalKey + 'static,
{
    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        let pool = fdo_db::sqlite::SqliteManufacturerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        let ov_db = fdo_db::sqlite::SqliteManufacturerDB::get_ov(&key.to_string(), conn)
            .expect("Error selecting OV");
        Ok(Some(V::deserialize_data(&ov_db.contents).map_err(|e| {
            StoreError::Unspecified(format!("Error deserializing value: {e:?}"))
        })?))
    }

    async fn store_metadata(
        &self,
        key: &K,
        _metadata_key: &crate::MetadataKey<MKT>,
        metadata_value: &dyn MetadataValue,
    ) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteManufacturerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        let val = metadata_value
            .to_text()
            .parse::<i64>()
            .expect("Unable to convert");
        fdo_db::sqlite::SqliteManufacturerDB::update_ov_ttl(&key.to_string(), Some(val), conn)
            .map_err(|e| {
                StoreError::Unspecified(format!(
                    "Unable to update OV with guid {} with {val}: {e:?}",
                    key.to_string()
                ))
            })
    }

    async fn destroy_metadata(
        &self,
        key: &K,
        _metadata_key: &crate::MetadataKey<MKT>,
    ) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteManufacturerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteManufacturerDB::update_ov_ttl(&key.to_string(), None, conn).map_err(
            |e| {
                StoreError::Unspecified(format!(
                    "Unable to set 'None' metadata on OV {}: {e:?}",
                    key.to_string()
                ))
            },
        )
    }

    async fn query_data(&self) -> crate::QueryResult<V, MKT> {
        // NOTE: this function is only used in the owner onboarding server
        // when we need to filter the OVs that haven't done the To2 and still
        // have ttl. It is not used in the manufacturing server.
        // This is why we are returning dummy things to comply with the trait.
        Ok(Box::new(SqliteManufacturerStoreFilterType {
            neqs: Vec::new(),
            lts: Vec::new(),
        }))
    }

    async fn store_data(&self, _key: K, value: V) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteManufacturerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        let raw = V::serialize_data(&value).expect("Error serializing data");
        let ov = OwnershipVoucher::from_pem_or_raw(&raw).expect("Error converting OV");
        fdo_db::sqlite::SqliteManufacturerDB::insert_ov(&ov, None, conn).map_err(|e| {
            StoreError::Unspecified(format!(
                "Error inserting OV with guid {}: {e:?}",
                ov.header().guid().to_string()
            ))
        })
    }

    async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteManufacturerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteManufacturerDB::delete_ov(&key.to_string(), conn).map_err(|e| {
            StoreError::Unspecified(format!(
                "Error deleting OV with guid {}: {e:?}",
                key.to_string()
            ))
        })
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteManufacturerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        fdo_db::sqlite::SqliteManufacturerDB::delete_ov_ttl_le(now, conn).map_err(|e| {
            StoreError::Unspecified(format!("Error deleting OVs with ttl <= {now}: {e:?}"))
        })
    }
}

struct SqliteOwnerStore<K, V> {
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,
}

impl<K, V> SqliteOwnerStore<K, V> where K: std::string::ToString {}

pub struct SqliteOwnerStoreFilterType {
    neqs: Vec<bool>,
    lts: Vec<bool>,
}

#[async_trait]
impl<V, MKT> FilterType<V, MKT> for SqliteOwnerStoreFilterType
where
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: MetadataLocalKey,
{
    fn neq(&mut self, _key: &crate::MetadataKey<MKT>, _expected: &dyn MetadataValue) {
        self.neqs = Vec::new();
    }
    fn lt(&mut self, _key: &crate::MetadataKey<MKT>, _max: i64) {
        self.lts = Vec::new();
    }
    async fn query(&self) -> Result<crate::FilterQueryResult<V>, StoreError> {
        let values = Vec::new();
        Ok(Some(ValueIter {
            index: 0,
            values,
            errored: false,
        }))
    }
}

#[async_trait]
impl<OT, K, V, MKT> Store<OT, K, V, MKT> for SqliteOwnerStore<K, V>
where
    OT: crate::StoreOpenMode,
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: crate::MetadataLocalKey + 'static,
{
    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        let pool = fdo_db::sqlite::SqliteOwnerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        let ov_db = fdo_db::sqlite::SqliteOwnerDB::get_ov(&key.to_string(), conn)
            .expect("Error selecting OV");
        Ok(Some(V::deserialize_data(&ov_db.contents).map_err(|e| {
            StoreError::Unspecified(format!("Error deserializing value: {e:?}"))
        })?))
    }

    async fn store_metadata(
        &self,
        key: &K,
        metadata_key: &crate::MetadataKey<MKT>,
        metadata_value: &dyn MetadataValue,
    ) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteOwnerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        match metadata_key.to_key() {
            "fdo.to2_performed" => {
                let val = metadata_value
                    .to_text()
                    .parse::<bool>()
                    .expect("Unable to convert string to bool");
                fdo_db::sqlite::SqliteOwnerDB::update_ov_to2(&key.to_string(), Some(val), conn)
                    .map_err(|e| {
                        StoreError::Unspecified(format!(
                            "Unable to update OV (guid {}) to2 with value {val}: {e:?}",
                            &key.to_string()
                        ))
                    })
            }
            "fdo.to0_accept_owner_wait_seconds" => {
                let val = metadata_value
                    .to_text()
                    .parse::<i64>()
                    .expect("Unable to convert string to i64");
                fdo_db::sqlite::SqliteOwnerDB::update_ov_to0_wait_seconds(
                    &key.to_string(),
                    Some(val),
                    conn,
                )
                .map_err(|e| {
                    StoreError::Unspecified(format!(
                        "Unable to update OV (guid {}) to0 with value {val}: {e:?}",
                        &key.to_string()
                    ))
                })
            }
            _ => Err(StoreError::Unspecified(format!(
                "Unable to hanlde metadata key {}",
                metadata_key.to_key()
            ))),
        }
    }

    async fn destroy_metadata(
        &self,
        key: &K,
        _metadata_key: &crate::MetadataKey<MKT>,
    ) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteOwnerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteOwnerDB::update_ov_to0_wait_seconds(&key.to_string(), None, conn)
            .map_err(|e| {
                StoreError::Unspecified(format!(
                    "Unable to set 'None' to0 metadata on OV {}: {e:?}",
                    key.to_string()
                ))
            })?;
        fdo_db::sqlite::SqliteOwnerDB::update_ov_to2(&key.to_string(), None, conn).map_err(|e| {
            StoreError::Unspecified(format!(
                "Unable to set 'None' to2 metadata on OV {}: {e:?}",
                key.to_string()
            ))
        })
    }

    async fn query_data(&self) -> crate::QueryResult<V, MKT> {
        todo!();
    }

    async fn store_data(&self, _key: K, value: V) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteOwnerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        let raw = V::serialize_data(&value).expect("Error serializing data");
        let ov = OwnershipVoucher::from_pem_or_raw(&raw).expect("Error converting OV");
        fdo_db::sqlite::SqliteOwnerDB::insert_ov(&ov, None, None, conn).map_err(|e| {
            StoreError::Unspecified(format!(
                "Error inserting OV with guid {}: {e:?}",
                ov.header().guid().to_string()
            ))
        })
    }

    async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteOwnerDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteOwnerDB::delete_ov(&key.to_string(), conn).map_err(|e| {
            StoreError::Unspecified(format!(
                "Error deleting OV with guid {}: {e:?}",
                &key.to_string()
            ))
        })
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        // This is not used in the owner onboarding server since the OVs there
        // do not have a ttl.
        Ok(())
    }
}

struct SqliteRendezvousStore<K, V> {
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,
}

impl<K, V> SqliteRendezvousStore<K, V> where K: std::string::ToString {}

pub struct SqliteRendezvousStoreFilterType {
    neqs: Vec<bool>,
    lts: Vec<bool>,
}

#[async_trait]
impl<V, MKT> FilterType<V, MKT> for SqliteRendezvousStoreFilterType
where
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: MetadataLocalKey,
{
    fn neq(&mut self, _key: &crate::MetadataKey<MKT>, _expected: &dyn MetadataValue) {
        self.neqs = Vec::new();
    }
    fn lt(&mut self, _key: &crate::MetadataKey<MKT>, _max: i64) {
        self.lts = Vec::new();
    }
    async fn query(&self) -> Result<crate::FilterQueryResult<V>, StoreError> {
        let values = Vec::new();
        Ok(Some(ValueIter {
            index: 0,
            values,
            errored: false,
        }))
    }
}

#[async_trait]
impl<OT, K, V, MKT> Store<OT, K, V, MKT> for SqliteRendezvousStore<K, V>
where
    OT: crate::StoreOpenMode,
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: crate::MetadataLocalKey + 'static,
{
    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        let pool = fdo_db::sqlite::SqliteRendezvousDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        let ov_db = fdo_db::sqlite::SqliteRendezvousDB::get_ov(&key.to_string(), conn)
            .expect("Error selecting OV");
        Ok(Some(V::deserialize_data(&ov_db.contents).map_err(|e| {
            StoreError::Unspecified(format!("Error deserializing value: {e:?}"))
        })?))
    }

    async fn store_metadata(
        &self,
        key: &K,
        _metadata_key: &crate::MetadataKey<MKT>,
        metadata_value: &dyn MetadataValue,
    ) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteRendezvousDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        let val = metadata_value
            .to_text()
            .parse::<i64>()
            .expect("Unable to convert");
        fdo_db::sqlite::SqliteRendezvousDB::update_ov_ttl(&key.to_string(), Some(val), conn)
            .map_err(|e| {
                StoreError::Unspecified(format!(
                    "Unable to update OV with guid {} with {val}: {e:?}",
                    key.to_string()
                ))
            })
    }

    async fn destroy_metadata(
        &self,
        key: &K,
        _metadata_key: &crate::MetadataKey<MKT>,
    ) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteRendezvousDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteRendezvousDB::update_ov_ttl(&key.to_string(), None, conn).map_err(
            |e| {
                StoreError::Unspecified(format!(
                    "Unable to set 'None' ttl on OV {}: {e:?}",
                    key.to_string()
                ))
            },
        )
    }

    async fn query_data(&self) -> crate::QueryResult<V, MKT> {
        // NOTE: this function is only used in the owner onboarding server
        // when we need to filter the OVs that haven't done the To2 and still
        // have ttl. It is not used in the rendezvous server.
        // This is why we are returning dummy things to comply with the trait.
        Ok(Box::new(SqliteRendezvousStoreFilterType {
            neqs: Vec::new(),
            lts: Vec::new(),
        }))
    }

    async fn store_data(&self, _key: K, value: V) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteRendezvousDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        let raw = V::serialize_data(&value).expect("Error serializing data");
        let ov = OwnershipVoucher::from_pem_or_raw(&raw).expect("Error converting OV");
        fdo_db::sqlite::SqliteRendezvousDB::insert_ov(&ov, None, conn).map_err(|e| {
            StoreError::Unspecified(format!(
                "Error inserting OV with guid {}: {e:?}",
                ov.header().guid().to_string()
            ))
        })
    }

    async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteRendezvousDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteRendezvousDB::delete_ov(&key.to_string(), conn).map_err(|e| {
            StoreError::Unspecified(format!(
                "Error deleting OV with guid {}: {e:?}",
                key.to_string()
            ))
        })
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        let pool = fdo_db::sqlite::SqliteRendezvousDB::get_conn_pool();
        let conn = &mut pool.get().expect("Couldn't establish a connection");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        fdo_db::sqlite::SqliteRendezvousDB::delete_ov_ttl_le(now, conn).map_err(|e| {
            StoreError::Unspecified(format!("Error deleting OVs with ttl <= {now}: {e:?}"))
        })
    }
}
