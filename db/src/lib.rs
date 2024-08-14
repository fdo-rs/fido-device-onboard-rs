pub mod models;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod schema;
#[cfg(feature = "sqlite")]
pub mod sqlite;

use anyhow::Result;
use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;

use fdo_data_formats::ownershipvoucher::OwnershipVoucher as OV;
use fdo_data_formats::StoredItem;
use models::ManufacturerOV;
use models::OwnerOV;
use models::RendezvousOV;

pub trait DBStoreManufacturer<T>
where
    T: diesel::r2d2::R2D2Connection + 'static,
{
    /// Gets a connection pool
    fn get_conn_pool(url: String) -> Pool<ConnectionManager<T>>;

    /// Inserts an OV
    fn insert_ov(ov: &OV, ttl: Option<i64>, conn: &mut T) -> Result<()>;

    /// Gets an OV
    fn get_ov(guid: &str, conn: &mut T) -> Result<ManufacturerOV>;

    /// Returns all the OVs in the DB
    fn get_all_ovs(conn: &mut T) -> Result<Vec<ManufacturerOV>>;

    /// Deletes an OV
    fn delete_ov(guid: &str, conn: &mut T) -> Result<()>;

    /// Deletes all OVs whose ttl is less or equal to the given ttl
    fn delete_ov_ttl_le(ttl: i64, conn: &mut T) -> Result<()>;

    /// Updates the ttl of an existing OV.
    /// Option<i64> is set as the ttl type so that we can set NULL in the
    /// database if 'None' is passed as the ttl.
    fn update_ov_ttl(guid: &str, ttl: Option<i64>, conn: &mut T) -> Result<()>;
}

pub trait DBStoreOwner<T>
where
    T: diesel::r2d2::R2D2Connection + 'static,
{
    /// Gets a connection pool
    fn get_conn_pool(url: String) -> Pool<ConnectionManager<T>>;

    /// Inserts an OV
    fn insert_ov(ov: &OV, to2: Option<bool>, to0: Option<i64>, conn: &mut T) -> Result<()>;

    /// Gets an OV
    fn get_ov(guid: &str, conn: &mut T) -> Result<OwnerOV>;

    /// Deletes an OV
    fn delete_ov(guid: &str, conn: &mut T) -> Result<()>;

    /// Selects all the OVs with the given to2_performed status
    fn select_ov_to2_performed(to2_performed: bool, conn: &mut T) -> Result<Vec<OwnerOV>>;

    /// Selects all the OVs whose to0 is less than the given maximum
    fn select_ov_to0_less_than(to0_max: i64, conn: &mut T) -> Result<Vec<OwnerOV>>;

    /// Selects all the OVs with the given to2_performed status and those whose
    /// to0 is less that then given maximum
    fn select_ov_to2_performed_and_ov_to0_less_than(
        to2_performed: bool,
        to0_max: i64,
        conn: &mut T,
    ) -> Result<Vec<OwnerOV>>;

    /// Updates the to0_accept_owner_wait_seconds field of an existing OV.
    /// Option<i64> is set as the ttl type so that we can set NULL in the
    /// database if 'None' is passed as the value.
    fn update_ov_to0_wait_seconds(
        guid: &str,
        wait_seconds: Option<i64>,
        conn: &mut T,
    ) -> Result<()>;

    /// Updates the to0 performed status of an existing OV.
    /// Option<bool> is set as the ttl type so that we can set NULL in the
    /// database if 'None' is passed as the to0_performed
    fn update_ov_to2(guid: &str, to0_performed: Option<bool>, conn: &mut T) -> Result<()>;
}

pub trait DBStoreRendezvous<T>
where
    T: diesel::r2d2::R2D2Connection + 'static,
{
    /// Gets a connection pool
    fn get_conn_pool(url: String) -> Pool<ConnectionManager<T>>;

    /// Inserts an OV
    fn insert_ov(ov: &StoredItem, guid: &str, ttl: Option<i64>, conn: &mut T) -> Result<()>;

    /// Gets an OV
    fn get_ov(guid: &str, conn: &mut T) -> Result<RendezvousOV>;

    /// Deletes an OV
    fn delete_ov(guid: &str, conn: &mut T) -> Result<()>;

    /// Deletes all OVs whose ttl is less or equal to the given ttl
    fn delete_ov_ttl_le(ttl: i64, conn: &mut T) -> Result<()>;

    /// Updates the ttl of an existing OV.
    /// Option<i64> is set as the ttl type so that we can set NULL in the
    /// database if 'None' is passed as the ttl.
    fn update_ov_ttl(guid: &str, ttl: Option<i64>, conn: &mut T) -> Result<()>;
}
