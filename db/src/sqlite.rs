use super::{DBStoreManufacturer, DBStoreOwner, DBStoreRendezvous};

use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use diesel::SqliteConnection;

use crate::models::ManufacturerOV;
use crate::models::NewManufacturerOV;
use crate::schema::manufacturer_vouchers;
use crate::schema::owner_vouchers;
use crate::schema::rendezvous_vouchers;

use std::env;

use anyhow::Result;
use dotenvy::dotenv;

use super::models::{NewOwnerOV, NewRendezvousOV, OwnerOV, RendezvousOV};

use fdo_data_formats::ownershipvoucher::OwnershipVoucher as OV;
use fdo_data_formats::Serializable;
use fdo_data_formats::StoredItem;

pub struct SqliteManufacturerDB {}

impl DBStoreManufacturer<SqliteConnection> for SqliteManufacturerDB {
    fn get_connection() -> SqliteConnection {
        dotenv().ok();
        let database_url = env::var("SQLITE_MANUFACTURER_DATABASE_URL")
            .expect("SQLITE_MANUFACTURER_DATABASE_URL must be set");
        SqliteConnection::establish(&database_url).expect("Error connecting to database")
    }

    fn get_conn_pool() -> Pool<ConnectionManager<SqliteConnection>> {
        dotenv().ok();
        let database_url = env::var("SQLITE_MANUFACTURER_DATABASE_URL")
            .expect("SQLITE_MANUFACTURER_DATABASE_URL must be set");
        let manager = ConnectionManager::<SqliteConnection>::new(database_url);
        Pool::builder()
            .test_on_check_out(true)
            .build(manager)
            .expect("Couldn't build db connection pool")
    }

    fn insert_ov(ov: &OV, ttl: Option<i64>, conn: &mut SqliteConnection) -> Result<()> {
        let new_ov_manufacturer = NewManufacturerOV {
            guid: ov.header().guid().to_string(),
            contents: ov.serialize_data()?,
            ttl,
        };
        diesel::insert_into(super::schema::manufacturer_vouchers::table)
            .values(new_ov_manufacturer)
            .execute(conn)?;
        Ok(())
    }

    fn get_ov(guid: &str, conn: &mut SqliteConnection) -> Result<ManufacturerOV> {
        let result = super::schema::manufacturer_vouchers::dsl::manufacturer_vouchers
            .filter(super::schema::manufacturer_vouchers::guid.eq(guid))
            .first(conn)?;
        Ok(result)
    }

    fn get_all_ovs(conn: &mut SqliteConnection) -> Result<Vec<ManufacturerOV>> {
        let result = super::schema::manufacturer_vouchers::dsl::manufacturer_vouchers
            .select(ManufacturerOV::as_select())
            .load(conn)?;
        Ok(result)
    }

    fn delete_ov(guid: &str, conn: &mut SqliteConnection) -> Result<()> {
        diesel::delete(manufacturer_vouchers::dsl::manufacturer_vouchers)
            .filter(super::schema::manufacturer_vouchers::guid.eq(guid))
            .execute(conn)?;
        Ok(())
    }

    fn delete_ov_ttl_le(ttl: i64, conn: &mut SqliteConnection) -> Result<()> {
        diesel::delete(manufacturer_vouchers::dsl::manufacturer_vouchers)
            .filter(super::schema::manufacturer_vouchers::ttl.le(ttl))
            .execute(conn)?;
        Ok(())
    }

    fn update_ov_ttl(guid: &str, ttl: Option<i64>, conn: &mut SqliteConnection) -> Result<()> {
        diesel::update(manufacturer_vouchers::dsl::manufacturer_vouchers)
            .filter(super::schema::manufacturer_vouchers::guid.eq(guid))
            .set(super::schema::manufacturer_vouchers::ttl.eq(ttl))
            .execute(conn)?;
        Ok(())
    }
}

pub struct SqliteOwnerDB {}

impl DBStoreOwner<SqliteConnection> for SqliteOwnerDB {
    fn get_connection() -> SqliteConnection {
        dotenv().ok();
        let database_url =
            env::var("SQLITE_OWNER_DATABASE_URL").expect("SQLITE_OWNER_DATABASE_URL must be set");
        SqliteConnection::establish(&database_url).expect("Error connecting to database")
    }

    fn get_conn_pool() -> Pool<ConnectionManager<SqliteConnection>> {
        dotenv().ok();
        let database_url =
            env::var("SQLITE_OWNER_DATABASE_URL").expect("SQLITE_OWNER_DATABASE_URL must be set");
        let manager = ConnectionManager::<SqliteConnection>::new(database_url);
        Pool::builder()
            .test_on_check_out(true)
            .build(manager)
            .expect("Couldn't build db connection pool")
    }

    fn insert_ov(
        ov: &OV,
        to2: Option<bool>,
        to0: Option<i64>,
        conn: &mut SqliteConnection,
    ) -> Result<()> {
        let new_ov_owner = NewOwnerOV {
            guid: ov.header().guid().to_string(),
            contents: ov.serialize_data()?,
            to2_performed: to2,
            to0_accept_owner_wait_seconds: to0,
        };
        diesel::insert_into(super::schema::owner_vouchers::table)
            .values(new_ov_owner)
            .execute(conn)?;
        Ok(())
    }

    fn get_ov(guid: &str, conn: &mut SqliteConnection) -> Result<OwnerOV> {
        let result = super::schema::owner_vouchers::dsl::owner_vouchers
            .filter(super::schema::owner_vouchers::guid.eq(guid))
            .first(conn)?;
        Ok(result)
    }

    fn delete_ov(guid: &str, conn: &mut SqliteConnection) -> Result<()> {
        diesel::delete(owner_vouchers::dsl::owner_vouchers)
            .filter(super::schema::owner_vouchers::guid.eq(guid))
            .execute(conn)?;
        Ok(())
    }

    #[allow(non_snake_case)]
    fn select_ov_to2_performed(
        to2_performed: bool,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<OwnerOV>> {
        let result = super::schema::owner_vouchers::dsl::owner_vouchers
            .filter(super::schema::owner_vouchers::to2_performed.eq(to2_performed))
            .select(OwnerOV::as_select())
            .load(conn)?;
        Ok(result)
    }

    #[allow(non_snake_case)]
    fn select_ov_to0_less_than(to0_max: i64, conn: &mut SqliteConnection) -> Result<Vec<OwnerOV>> {
        let result = super::schema::owner_vouchers::dsl::owner_vouchers
            .filter(super::schema::owner_vouchers::to0_accept_owner_wait_seconds.lt(to0_max))
            .select(OwnerOV::as_select())
            .load(conn)?;
        Ok(result)
    }

    fn select_ov_to2_performed_and_ov_to0_less_than(
        to2_performed: bool,
        to0_max: i64,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<OwnerOV>> {
        let result = super::schema::owner_vouchers::dsl::owner_vouchers
            .filter(super::schema::owner_vouchers::to0_accept_owner_wait_seconds.lt(to0_max))
            .filter(super::schema::owner_vouchers::to2_performed.eq(to2_performed))
            .select(OwnerOV::as_select())
            .load(conn)?;
        Ok(result)
    }

    fn update_ov_to0_wait_seconds(
        guid: &str,
        wait_seconds: Option<i64>,
        conn: &mut SqliteConnection,
    ) -> Result<()> {
        diesel::update(owner_vouchers::dsl::owner_vouchers)
            .filter(super::schema::owner_vouchers::guid.eq(guid))
            .set(super::schema::owner_vouchers::to0_accept_owner_wait_seconds.eq(wait_seconds))
            .execute(conn)?;
        Ok(())
    }

    fn update_ov_to2(
        guid: &str,
        to2_performed: Option<bool>,
        conn: &mut SqliteConnection,
    ) -> Result<()> {
        diesel::update(owner_vouchers::dsl::owner_vouchers)
            .filter(super::schema::owner_vouchers::guid.eq(guid))
            .set(super::schema::owner_vouchers::to2_performed.eq(to2_performed))
            .execute(conn)?;
        Ok(())
    }
}

pub struct SqliteRendezvousDB {}

impl DBStoreRendezvous<SqliteConnection> for SqliteRendezvousDB {
    fn get_connection() -> SqliteConnection {
        dotenv().ok();
        let database_url = env::var("SQLITE_RENDEZVOUS_DATABASE_URL")
            .expect("SQLITE_RENDEZVOUS_DATABASE_URL must be set");
        SqliteConnection::establish(&database_url).expect("Error connecting to database")
    }

    fn get_conn_pool() -> Pool<ConnectionManager<SqliteConnection>> {
        dotenv().ok();
        let database_url = env::var("SQLITE_RENDEZVOUS_DATABASE_URL")
            .expect("SQLITE_RENDEZVOUS_DATABASE_URL must be set");
        let manager = ConnectionManager::<SqliteConnection>::new(database_url);
        Pool::builder()
            .test_on_check_out(true)
            .build(manager)
            .expect("Couldn't build db connection pool")
    }

    fn insert_ov(
        ov: &StoredItem,
        guid: &str,
        ttl: Option<i64>,
        conn: &mut SqliteConnection,
    ) -> Result<()> {
        let new_ov_rendezvous = NewRendezvousOV {
            guid: guid.to_string(),
            contents: ov.serialize_data()?,
            ttl,
        };
        diesel::insert_into(super::schema::rendezvous_vouchers::table)
            .values(&new_ov_rendezvous)
            .execute(conn)?;
        Ok(())
    }

    fn get_ov(guid: &str, conn: &mut SqliteConnection) -> Result<RendezvousOV> {
        let result = super::schema::rendezvous_vouchers::dsl::rendezvous_vouchers
            .filter(super::schema::rendezvous_vouchers::guid.eq(guid))
            .first(conn)?;
        Ok(result)
    }

    fn delete_ov(guid: &str, conn: &mut SqliteConnection) -> Result<()> {
        diesel::delete(rendezvous_vouchers::dsl::rendezvous_vouchers)
            .filter(super::schema::rendezvous_vouchers::guid.eq(guid))
            .execute(conn)?;
        Ok(())
    }

    fn delete_ov_ttl_le(ttl: i64, conn: &mut SqliteConnection) -> Result<()> {
        diesel::delete(rendezvous_vouchers::dsl::rendezvous_vouchers)
            .filter(super::schema::rendezvous_vouchers::ttl.le(ttl))
            .execute(conn)?;
        Ok(())
    }

    fn update_ov_ttl(guid: &str, ttl: Option<i64>, conn: &mut SqliteConnection) -> Result<()> {
        diesel::update(rendezvous_vouchers::dsl::rendezvous_vouchers)
            .filter(super::schema::rendezvous_vouchers::guid.eq(guid))
            .set(super::schema::rendezvous_vouchers::ttl.eq(ttl))
            .execute(conn)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{SqliteManufacturerDB, SqliteOwnerDB, SqliteRendezvousDB};
    use crate::{schema::*, DBStoreManufacturer, DBStoreOwner, DBStoreRendezvous};
    use anyhow::Result;
    use diesel::connection::SimpleConnection;
    use diesel::prelude::*;
    use fdo_data_formats::ownershipvoucher::OwnershipVoucher as OV;
    use fdo_data_formats::publickey::PublicKey;
    use fdo_data_formats::types::{COSESign, Guid, Nonce, RendezvousInfo, TO2SetupDevicePayload};
    use fdo_data_formats::StoredItem;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use std::collections::HashMap;
    use std::env;

    #[test]
    fn test_manufacturer_database() -> Result<()> {
        println!("Current directory: {:?}", env::current_dir());

        // read test ovs from the integration tests dir
        let mut ov_map = HashMap::new();
        let pool = SqliteManufacturerDB::get_conn_pool();

        // last_guid used later to delete an ov with that key
        let mut last_guid = String::new();
        for path in std::fs::read_dir("../integration-tests/vouchers/v101").expect("Dir not found")
        {
            let ov_path = path.expect("error getting path").path();
            let content = std::fs::read(ov_path).expect("OV couldn't be read");
            let ov = OV::from_pem_or_raw(&content).expect("Error serializing OV");
            last_guid = ov.header().guid().to_string();
            ov_map.insert(ov.header().guid().to_string(), ov);
        }

        // get a connection from the pool
        let conn = &mut pool.get().unwrap();
        // sqlite does not enable this by default, not needed at this point,
        // but I've left it here so that we don't forget
        conn.batch_execute("PRAGMA foreign_keys = ON")?;

        for (_, ov) in ov_map.clone().into_iter() {
            SqliteManufacturerDB::insert_ov(&ov, Some(5000_i64), conn)?;
        }

        // we should have 3 ovs
        let count: i64 = manufacturer_vouchers::dsl::manufacturer_vouchers
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(count, 3);

        // select ov by guid
        let ov_db = SqliteManufacturerDB::get_ov(&last_guid, conn)?;
        assert_eq!(ov_db.guid, last_guid);

        // update ttl of an OV
        SqliteManufacturerDB::update_ov_ttl(&last_guid, Some(12345), conn)?;
        let ov_db = SqliteManufacturerDB::get_ov(&last_guid, conn)?;
        assert_eq!(ov_db.ttl, Some(12345));

        // delete an ov by guid, we should have 2 at the end
        SqliteManufacturerDB::delete_ov(&last_guid, conn)?;
        let count: i64 = manufacturer_vouchers::dsl::manufacturer_vouchers
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(count, 2);

        // delete manufacturer ovs with ttl <= 4000, we shouldn't delete any of them
        SqliteManufacturerDB::delete_ov_ttl_le(4000_i64, conn)?;
        let count: i64 = manufacturer_vouchers::dsl::manufacturer_vouchers
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(count, 2);

        // delete manufacturer ovs with ttl <= 5000, we should delete the remaining 2 ovs
        SqliteManufacturerDB::delete_ov_ttl_le(5000_i64, conn)?;
        let count: i64 = manufacturer_vouchers::dsl::manufacturer_vouchers
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn test_owner_database() -> Result<()> {
        println!("Current directory: {:?}", env::current_dir());

        // read test ovs from the integration tests dir
        let mut ov_map = HashMap::new();
        let pool = SqliteOwnerDB::get_conn_pool();

        // last_guid used later to delete an ov with that key
        let mut last_guid = String::new();
        for path in std::fs::read_dir("../integration-tests/vouchers/v101").expect("Dir not found")
        {
            let ov_path = path.expect("error getting path").path();
            let content = std::fs::read(ov_path).expect("OV couldn't be read");
            let ov = OV::from_pem_or_raw(&content).expect("Error serializing OV");
            last_guid = ov.header().guid().to_string();
            ov_map.insert(ov.header().guid().to_string(), ov);
        }

        // get a connection from the pool
        let conn = &mut pool.get().unwrap();
        // sqlite does not enable this by default, not needed at this point,
        // but I've left it here so that we don't forget
        conn.batch_execute("PRAGMA foreign_keys = ON")?;

        let mut to2_done = true;
        for (_, ov) in ov_map.clone().into_iter() {
            if to2_done {
                SqliteOwnerDB::insert_ov(&ov, Some(to2_done), Some(2000_i64), conn)?;
            } else {
                SqliteOwnerDB::insert_ov(&ov, Some(to2_done), Some(3000_i64), conn)?;
            }
            to2_done = !to2_done;
        }

        // we should have 3 ovs
        let count: i64 = owner_vouchers::dsl::owner_vouchers
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(count, 3);

        // select ov by guid
        let ov_db = SqliteOwnerDB::get_ov(&last_guid, conn)?;
        assert_eq!(ov_db.guid, last_guid);

        // select the owner ovs with to2 performed = true, we should have 2
        let result = SqliteOwnerDB::select_ov_to2_performed(true, conn)?;
        assert_eq!(result.len(), 2);

        // select the owner ovs with to0 less than 2500, we should have 2
        let result = SqliteOwnerDB::select_ov_to0_less_than(2500_i64, conn)?;
        assert_eq!(result.len(), 2);

        // update the wait_seconds field and to2
        SqliteOwnerDB::update_ov_to0_wait_seconds(&last_guid.to_string(), Some(1234), conn)?;
        SqliteOwnerDB::update_ov_to2(&last_guid.to_string(), None, conn)?;

        let ov_db = SqliteOwnerDB::get_ov(&last_guid, conn)?;
        assert_eq!(ov_db.to0_accept_owner_wait_seconds, Some(1234));
        assert_eq!(ov_db.to2_performed, None);

        // delete an ov from the owner, we should have 2 left
        SqliteOwnerDB::delete_ov(&last_guid.to_string(), conn)?;
        let count: i64 = owner_vouchers::dsl::owner_vouchers
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(count, 2);

        Ok(())
    }

    #[test]
    fn test_rendezvous_database() -> Result<()> {
        println!("Current directory: {:?}", env::current_dir());

        // read test ovs from the integration tests dir
        let mut ov_map = HashMap::new();
        let pool = SqliteRendezvousDB::get_conn_pool();

        // last_guid used later to delete an ov with that key
        let mut last_guid = String::new();
        // private key
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = EcKey::generate(&group)?;
        let private_key = PKey::from_ec_key(key.clone())?;
        for path in std::fs::read_dir("../integration-tests/vouchers/v101").expect("Dir not found")
        {
            let ov_path = path.expect("error getting path").path();
            let content = std::fs::read(ov_path).expect("OV couldn't be read");
            let ov = OV::from_pem_or_raw(&content).expect("Error serializing OV");
            last_guid = ov.header().guid().to_string();
            let pubkey: PublicKey = ov
                .device_certificate_chain()
                .unwrap()
                .insecure_verify_without_root_verification()
                .unwrap()
                .clone()
                .try_into()
                .unwrap();
            let new_payload = TO2SetupDevicePayload::new(
                RendezvousInfo::new(Vec::new()).unwrap(),
                Guid::new().unwrap(),
                Nonce::new().unwrap(),
                pubkey.clone(),
            );
            let cose = COSESign::new(&new_payload, None, &private_key).unwrap();
            let tmp = StoredItem {
                public_key: pubkey,
                to1d: cose,
            };
            ov_map.insert(ov.header().guid().to_string(), tmp);
        }

        // get a connection from the pool
        let conn = &mut pool.get().unwrap();
        // sqlite does not enable this by default, not needed at this point,
        // but I've left it here so that we don't forget
        conn.batch_execute("PRAGMA foreign_keys = ON")?;

        for (guid, ov) in ov_map.clone().into_iter() {
            SqliteRendezvousDB::insert_ov(&ov, &guid, Some(5000_i64), conn)?;
        }

        // we should have 3 ovs
        let count: i64 = rendezvous_vouchers::dsl::rendezvous_vouchers
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(count, 3);

        // get an ov by guid
        let ov_db = SqliteRendezvousDB::get_ov(&last_guid, conn)?;
        assert_eq!(ov_db.guid, last_guid);

        // update ttl of an ov
        SqliteRendezvousDB::update_ov_ttl(&last_guid, None, conn)?;
        let ov_db = SqliteRendezvousDB::get_ov(&last_guid, conn)?;
        assert_eq!(ov_db.ttl, None);

        // delete an ov by guid, we should have 2 at the end
        SqliteRendezvousDB::delete_ov(&last_guid, conn)?;
        let count: i64 = rendezvous_vouchers::dsl::rendezvous_vouchers
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(count, 2);

        // delete rendezvous ovs with ttl <= 4000, we shouldn't delete any of them
        SqliteRendezvousDB::delete_ov_ttl_le(4000_i64, conn)?;
        let count: i64 = rendezvous_vouchers::dsl::rendezvous_vouchers
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(count, 2);

        // delete rendezvous ovs with ttl <= 5000, we should delete the remaining 2 ovs
        SqliteRendezvousDB::delete_ov_ttl_le(5000_i64, conn)?;
        let count: i64 = rendezvous_vouchers::dsl::rendezvous_vouchers
            .count()
            .get_result(conn)
            .unwrap();
        assert_eq!(count, 0);
        Ok(())
    }
}
