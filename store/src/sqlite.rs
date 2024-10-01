use async_trait::async_trait;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use diesel::SqliteConnection;
use fdo_data_formats::ownershipvoucher::OwnershipVoucher;
use fdo_data_formats::StoredItem;
use fdo_db::*;
use std::marker::PhantomData;

use crate::ServerType;
use crate::Store;
use crate::StoreError;
use crate::{FilterType, MetadataLocalKey, MetadataValue, ValueIter};
use fdo_data_formats::Serializable;

pub(super) fn initialize<OT, K, V, MKT>(
    server_type: &ServerType,
    url: String,
) -> Result<Box<dyn Store<OT, K, V, MKT>>, StoreError>
where
    OT: crate::StoreOpenMode,
    K: std::str::FromStr + std::string::ToString + Send + Sync + 'static,
    V: Serializable + Send + Sync + Clone + 'static,
    MKT: crate::MetadataLocalKey + 'static,
{
    match server_type {
        ServerType::Manufacturer => Ok(Box::new(SqliteManufacturerStore {
            phantom_k: PhantomData,
            phantom_v: PhantomData,
            connection_pool: fdo_db::sqlite::SqliteManufacturerDB::get_conn_pool(url),
        })),
        ServerType::Owner => Ok(Box::new(SqliteOwnerStore {
            phantom_k: PhantomData,
            phantom_v: PhantomData,
            connection_pool: fdo_db::sqlite::SqliteOwnerDB::get_conn_pool(url),
        })),
        ServerType::Rendezvous => Ok(Box::new(SqliteRendezvousStore {
            phantom_k: PhantomData,
            phantom_v: PhantomData,
            connection_pool: fdo_db::sqlite::SqliteRendezvousDB::get_conn_pool(url),
        })),
    }
}

struct SqliteManufacturerStore<K, V> {
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,

    connection_pool: Pool<ConnectionManager<SqliteConnection>>,
}

impl<K, V> SqliteManufacturerStore<K, V> where K: std::string::ToString {}

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
    async fn load_all_data(&self) -> Result<Vec<V>, StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        let entries =
            fdo_db::sqlite::SqliteManufacturerDB::get_all_ovs(conn).expect("Error selecting OVs");
        let mut items = Vec::<V>::new();
        for entry in entries {
            items.push(
                V::deserialize_from_reader(&mut &entry.contents[..]).map_err(|e| {
                    StoreError::Unspecified(format!("Error deserializing value: {e:?}"))
                })?,
            );
        }
        Ok(items)
    }

    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
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
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        let val = metadata_value
            .to_text()
            .parse::<i64>()
            .expect("Unable to convert");
        fdo_db::sqlite::SqliteManufacturerDB::update_ov_ttl(&key.to_string(), Some(val), conn)
            .map_err(|e| {
                StoreError::Database(format!(
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
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteManufacturerDB::update_ov_ttl(&key.to_string(), None, conn).map_err(
            |e| {
                StoreError::Database(format!(
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
        Err(StoreError::MethodNotAvailable)
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

    async fn store_data(&self, _key: K, value: V) -> Result<(), StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        let raw = V::serialize_data(&value).expect("Error serializing data");
        let ov = OwnershipVoucher::from_pem_or_raw(&raw).expect("Error converting OV");
        fdo_db::sqlite::SqliteManufacturerDB::insert_ov(&ov, None, conn).map_err(|e| {
            StoreError::Database(format!(
                "Error inserting OV with guid {}: {e:?}",
                ov.header().guid()
            ))
        })
    }

    async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteManufacturerDB::delete_ov(&key.to_string(), conn).map_err(|e| {
            StoreError::Database(format!(
                "Error deleting OV with guid {}: {e:?}",
                key.to_string()
            ))
        })
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        fdo_db::sqlite::SqliteManufacturerDB::delete_ov_ttl_le(now, conn).map_err(|e| {
            StoreError::Database(format!("Error deleting OVs with ttl <= {now}: {e:?}"))
        })
    }
}

struct SqliteOwnerStore<K, V> {
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,

    connection_pool: Pool<ConnectionManager<SqliteConnection>>,
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
    async fn load_all_data(&self) -> Result<Vec<V>, StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        let entries =
            fdo_db::sqlite::SqliteOwnerDB::get_all_ovs(conn).expect("Error selecting OVs");
        let mut items = Vec::<V>::new();
        for entry in entries {
            items.push(
                V::deserialize_from_reader(&mut &entry.contents[..]).map_err(|e| {
                    StoreError::Unspecified(format!("Error deserializing value: {e:?}"))
                })?,
            );
        }
        Ok(items)
    }

    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
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
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        match metadata_key.to_key() {
            "fdo.to2_performed" => {
                let val = metadata_value
                    .to_text()
                    .parse::<bool>()
                    .expect("Unable to convert string to bool");
                fdo_db::sqlite::SqliteOwnerDB::update_ov_to2(&key.to_string(), Some(val), conn)
                    .map_err(|e| {
                        StoreError::Database(format!(
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
                    StoreError::Database(format!(
                        "Unable to update OV (guid {}) to0 with value {val}: {e:?}",
                        &key.to_string()
                    ))
                })
            }
            _ => Err(StoreError::Unspecified(format!(
                "Unable to handle metadata key {}",
                metadata_key.to_key()
            ))),
        }
    }

    async fn destroy_metadata(
        &self,
        key: &K,
        _metadata_key: &crate::MetadataKey<MKT>,
    ) -> Result<(), StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteOwnerDB::update_ov_to0_wait_seconds(&key.to_string(), None, conn)
            .map_err(|e| {
                StoreError::Database(format!(
                    "Unable to set 'None' to0 metadata on OV {}: {e:?}",
                    key.to_string()
                ))
            })?;
        fdo_db::sqlite::SqliteOwnerDB::update_ov_to2(&key.to_string(), None, conn).map_err(|e| {
            StoreError::Database(format!(
                "Unable to set 'None' to2 metadata on OV {}: {e:?}",
                key.to_string()
            ))
        })
    }

    async fn query_data(&self) -> crate::QueryResult<V, MKT> {
        Err(StoreError::MethodNotAvailable)
    }

    async fn query_ovs_db(&self) -> Result<Vec<V>, StoreError> {
        let mut ret = vec![];
        let conn = &mut self
            .connection_pool
            .get()
            .map_err(|e| StoreError::Database(format!("Error connecting to DB {e:?}")))?;
        let db_ovs = fdo_db::sqlite::SqliteOwnerDB::select_ov_to2_performed_and_ov_to0_less_than(
            false,
            time::OffsetDateTime::now_utc().unix_timestamp(),
            conn,
        )
        .map_err(|e| {
            StoreError::Database(format!(
                "Error selecting OVs filtering by to2 and to0: {e:?}"
            ))
        })?;
        for db_ov in db_ovs {
            ret.push(V::deserialize_data(&db_ov.contents).map_err(|e| {
                StoreError::Unspecified(format!("Error deserializing value: {e:?}"))
            })?);
        }
        Ok(ret)
    }

    async fn query_ovs_db_to2_performed_to0_less_than(
        &self,
        to2: bool,
        to0_max: i64,
    ) -> Result<Vec<V>, StoreError> {
        let mut ret = vec![];
        let conn = &mut self
            .connection_pool
            .get()
            .map_err(|e| StoreError::Database(format!("Error connecting to DB {e:?}")))?;
        let db_ovs = fdo_db::sqlite::SqliteOwnerDB::select_ov_to2_performed_and_ov_to0_less_than(
            false, to0_max, conn,
        )
        .map_err(|e| {
            StoreError::Database(format!(
                "Error selecting OVs filering by to2 {to2} and to0 {to0_max}: {e:?}"
            ))
        })?;
        for db_ov in db_ovs {
            ret.push(V::deserialize_data(&db_ov.contents).map_err(|e| {
                StoreError::Unspecified(format!("Error deserializing value: {e:?}"))
            })?);
        }
        Ok(ret)
    }

    async fn store_data(&self, _key: K, value: V) -> Result<(), StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        let raw = V::serialize_data(&value).expect("Error serializing data");
        let ov = OwnershipVoucher::from_pem_or_raw(&raw).expect("Error converting OV");
        fdo_db::sqlite::SqliteOwnerDB::insert_ov(&ov, None, None, conn).map_err(|e| {
            StoreError::Database(format!(
                "Error inserting OV with guid {}: {e:?}",
                ov.header().guid()
            ))
        })
    }

    async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteOwnerDB::delete_ov(&key.to_string(), conn).map_err(|e| {
            StoreError::Database(format!(
                "Error deleting OV with guid {}: {e:?}",
                &key.to_string()
            ))
        })
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        // This is not used in the owner onboarding server since the OVs there
        // do not have a ttl, but we still need to return Ok since the method
        // will be called.
        Ok(())
    }
}

struct SqliteRendezvousStore<K, V> {
    phantom_k: PhantomData<K>,
    phantom_v: PhantomData<V>,

    connection_pool: Pool<ConnectionManager<SqliteConnection>>,
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
    async fn load_all_data(&self) -> Result<Vec<V>, StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        let entries =
            fdo_db::sqlite::SqliteRendezvousDB::get_all_ovs(conn).expect("Error selecting OVs");
        let mut items = Vec::<V>::new();
        for entry in entries {
            items.push(
                V::deserialize_from_reader(&mut &entry.contents[..]).map_err(|e| {
                    StoreError::Unspecified(format!("Error deserializing value: {e:?}"))
                })?,
            );
        }
        Ok(items)
    }

    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
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
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        let val = metadata_value
            .to_text()
            .parse::<i64>()
            .expect("Unable to convert");
        fdo_db::sqlite::SqliteRendezvousDB::update_ov_ttl(&key.to_string(), Some(val), conn)
            .map_err(|e| {
                StoreError::Database(format!(
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
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteRendezvousDB::update_ov_ttl(&key.to_string(), None, conn).map_err(
            |e| {
                StoreError::Database(format!(
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
        Err(StoreError::MethodNotAvailable)
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
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        let raw = V::serialize_data(&value).expect("Error serializing data");
        let stored = StoredItem::deserialize_data(&raw).expect("Error converting StoredItem");
        fdo_db::sqlite::SqliteRendezvousDB::insert_ov(&stored, &key.to_string(), None, conn)
            .map_err(|e| {
                StoreError::Database(format!(
                    "Error inserting StoredItem with guid {}: {e:?}",
                    &key.to_string()
                ))
            })
    }

    async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        fdo_db::sqlite::SqliteRendezvousDB::delete_ov(&key.to_string(), conn).map_err(|e| {
            StoreError::Database(format!(
                "Error deleting OV with guid {}: {e:?}",
                key.to_string()
            ))
        })
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        let conn = &mut self
            .connection_pool
            .get()
            .expect("Couldn't establish a connection");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        fdo_db::sqlite::SqliteRendezvousDB::delete_ov_ttl_le(now, conn).map_err(|e| {
            StoreError::Database(format!("Error deleting OVs with ttl <= {now}: {e:?}"))
        })
    }
}
