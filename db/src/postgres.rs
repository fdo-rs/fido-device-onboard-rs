use super::{DBStoreManufacturer, DBStoreOwner, DBStoreRendezvous};
use crate::models::NewManufacturerOV;
use crate::schema::manufacturer_vouchers;
use crate::schema::owner_vouchers;
use crate::schema::rendezvous_vouchers;
use fdo_data_formats::StoredItem;

use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use diesel::PgConnection;

use std::env;

use anyhow::Result;
use dotenvy::dotenv;

use super::models::{ManufacturerOV, NewOwnerOV, NewRendezvousOV, OwnerOV, RendezvousOV};

use fdo_data_formats::ownershipvoucher::OwnershipVoucher as OV;
use fdo_data_formats::Serializable;

pub struct PostgresManufacturerDB {}

impl DBStoreManufacturer<PgConnection> for PostgresManufacturerDB {
    fn get_connection() -> PgConnection {
        dotenv().ok();
        let database_url = env::var("POSTGRES_MANUFACTURER_DATABASE_URL")
            .expect("POSTGRES_MANUFACTURER_DATABASE_URL must be set");
        PgConnection::establish(&database_url).expect("Error connecting to database")
    }

    fn get_conn_pool() -> Pool<ConnectionManager<PgConnection>> {
        dotenv().ok();
        let database_url = env::var("POSTGRES_MANUFACTURER_DATABASE_URL")
            .expect("POSTGRES_MANUFACTURER_DATABASE_URL must be set");
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        Pool::builder()
            .test_on_check_out(true)
            .build(manager)
            .expect("Couldn't build db connection pool")
    }

    fn insert_ov(ov: &OV, ttl: Option<i64>, conn: &mut PgConnection) -> Result<()> {
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

    fn get_ov(guid: &str, conn: &mut PgConnection) -> Result<ManufacturerOV> {
        let result = super::schema::manufacturer_vouchers::dsl::manufacturer_vouchers
            .filter(super::schema::manufacturer_vouchers::guid.eq(guid))
            .first(conn)?;
        Ok(result)
    }

    fn get_all_ovs(conn: &mut PgConnection) -> Result<Vec<ManufacturerOV>> {
        let result = super::schema::manufacturer_vouchers::dsl::manufacturer_vouchers
            .select(ManufacturerOV::as_select())
            .load(conn)?;
        Ok(result)
    }

    fn delete_ov(guid: &str, conn: &mut PgConnection) -> Result<()> {
        diesel::delete(manufacturer_vouchers::dsl::manufacturer_vouchers)
            .filter(super::schema::manufacturer_vouchers::guid.eq(guid))
            .execute(conn)?;
        Ok(())
    }

    fn delete_ov_ttl_le(ttl: i64, conn: &mut PgConnection) -> Result<()> {
        diesel::delete(manufacturer_vouchers::dsl::manufacturer_vouchers)
            .filter(super::schema::manufacturer_vouchers::ttl.le(ttl))
            .execute(conn)?;
        Ok(())
    }

    fn update_ov_ttl(guid: &str, ttl: Option<i64>, conn: &mut PgConnection) -> Result<()> {
        diesel::update(manufacturer_vouchers::dsl::manufacturer_vouchers)
            .filter(super::schema::manufacturer_vouchers::guid.eq(guid))
            .set(super::schema::manufacturer_vouchers::ttl.eq(ttl))
            .execute(conn)?;
        Ok(())
    }
}

pub struct PostgresOwnerDB {}

impl DBStoreOwner<PgConnection> for PostgresOwnerDB {
    fn get_connection() -> PgConnection {
        dotenv().ok();
        let database_url = env::var("POSTGRES_OWNER_DATABASE_URL")
            .expect("POSTGRES_OWNER_DATABASE_URL must be set");
        PgConnection::establish(&database_url).expect("Error connecting to database")
    }

    fn get_conn_pool() -> Pool<ConnectionManager<PgConnection>> {
        dotenv().ok();
        let database_url = env::var("POSTGRES_OWNER_DATABASE_URL")
            .expect("POSTGRES_OWNER_DATABASE_URL must be set");
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        Pool::builder()
            .test_on_check_out(true)
            .build(manager)
            .expect("Couldn't build db connection pool")
    }

    fn insert_ov(
        ov: &OV,
        to2: Option<bool>,
        to0: Option<i64>,
        conn: &mut PgConnection,
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

    fn get_ov(guid: &str, conn: &mut PgConnection) -> Result<OwnerOV> {
        let result = super::schema::owner_vouchers::dsl::owner_vouchers
            .filter(super::schema::owner_vouchers::guid.eq(guid))
            .first(conn)?;
        Ok(result)
    }

    fn delete_ov(guid: &str, conn: &mut PgConnection) -> Result<()> {
        diesel::delete(owner_vouchers::dsl::owner_vouchers)
            .filter(super::schema::owner_vouchers::guid.eq(guid))
            .execute(conn)?;
        Ok(())
    }

    #[allow(non_snake_case)]
    fn select_ov_to2_performed(
        to2_performed: bool,
        conn: &mut PgConnection,
    ) -> Result<Vec<OwnerOV>> {
        let result = super::schema::owner_vouchers::dsl::owner_vouchers
            .filter(super::schema::owner_vouchers::to2_performed.eq(to2_performed))
            .select(OwnerOV::as_select())
            .load(conn)?;
        Ok(result)
    }

    #[allow(non_snake_case)]
    fn select_ov_to0_less_than(to0_max: i64, conn: &mut PgConnection) -> Result<Vec<OwnerOV>> {
        let result = super::schema::owner_vouchers::dsl::owner_vouchers
            .filter(super::schema::owner_vouchers::to0_accept_owner_wait_seconds.lt(to0_max))
            .select(OwnerOV::as_select())
            .load(conn)?;
        Ok(result)
    }

    fn select_ov_to2_performed_and_ov_to0_less_than(
        to2_performed: bool,
        to0_max: i64,
        conn: &mut PgConnection,
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
        conn: &mut PgConnection,
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
        conn: &mut PgConnection,
    ) -> Result<()> {
        diesel::update(owner_vouchers::dsl::owner_vouchers)
            .filter(super::schema::owner_vouchers::guid.eq(guid))
            .set(super::schema::owner_vouchers::to2_performed.eq(to2_performed))
            .execute(conn)?;
        Ok(())
    }
}

pub struct PostgresRendezvousDB {}

impl DBStoreRendezvous<PgConnection> for PostgresRendezvousDB {
    fn get_connection() -> PgConnection {
        dotenv().ok();
        let database_url = env::var("POSTGRES_RENDEZVOUS_DATABASE_URL")
            .expect("POSTGRES_RENDEZVOUS_DATABASE_URL must be set");
        PgConnection::establish(&database_url).expect("Error connecting to database")
    }

    fn get_conn_pool() -> Pool<ConnectionManager<PgConnection>> {
        dotenv().ok();
        let database_url = env::var("POSTGRES_RENDEZVOUS_DATABASE_URL")
            .expect("POSTGRES_RENDEZVOUS_DATABASE_URL must be set");
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        Pool::builder()
            .test_on_check_out(true)
            .build(manager)
            .expect("Couldn't build db connection pool")
    }

    fn insert_ov(
        ov: &StoredItem,
        guid: &str,
        ttl: Option<i64>,
        conn: &mut PgConnection,
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

    fn get_ov(guid: &str, conn: &mut PgConnection) -> Result<RendezvousOV> {
        let result = super::schema::rendezvous_vouchers::dsl::rendezvous_vouchers
            .filter(super::schema::rendezvous_vouchers::guid.eq(guid))
            .first(conn)?;
        Ok(result)
    }

    fn delete_ov(guid: &str, conn: &mut PgConnection) -> Result<()> {
        diesel::delete(rendezvous_vouchers::dsl::rendezvous_vouchers)
            .filter(super::schema::rendezvous_vouchers::guid.eq(guid))
            .execute(conn)?;
        Ok(())
    }

    fn delete_ov_ttl_le(ttl: i64, conn: &mut PgConnection) -> Result<()> {
        diesel::delete(rendezvous_vouchers::dsl::rendezvous_vouchers)
            .filter(super::schema::rendezvous_vouchers::ttl.le(ttl))
            .execute(conn)?;
        Ok(())
    }

    fn update_ov_ttl(guid: &str, ttl: Option<i64>, conn: &mut PgConnection) -> Result<()> {
        diesel::update(rendezvous_vouchers::dsl::rendezvous_vouchers)
            .filter(super::schema::rendezvous_vouchers::guid.eq(guid))
            .set(super::schema::rendezvous_vouchers::ttl.eq(ttl))
            .execute(conn)?;
        Ok(())
    }
}
