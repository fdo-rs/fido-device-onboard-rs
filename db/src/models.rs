use diesel::prelude::*;
use std::fmt;

#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::rendezvous_vouchers)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(guid))]
pub struct RendezvousOV {
    pub guid: String,
    pub contents: Vec<u8>,
    pub ttl: Option<i64>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::rendezvous_vouchers)]
pub struct NewRendezvousOV {
    pub guid: String,
    pub contents: Vec<u8>,
    pub ttl: Option<i64>,
}

#[derive(Queryable, Selectable, Identifiable, AsChangeset)]
#[diesel(table_name = crate::schema::owner_vouchers)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(guid))]
pub struct OwnerOV {
    pub guid: String,
    pub contents: Vec<u8>,
    pub to2_performed: Option<bool>,
    pub to0_accept_owner_wait_seconds: Option<i64>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::owner_vouchers)]
pub struct NewOwnerOV {
    pub guid: String,
    pub contents: Vec<u8>,
    pub to2_performed: Option<bool>,
    pub to0_accept_owner_wait_seconds: Option<i64>,
}

#[derive(Queryable, Selectable, Identifiable, AsChangeset)]
#[diesel(table_name = crate::schema::manufacturer_vouchers)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(guid))]
pub struct ManufacturerOV {
    pub guid: String,
    pub contents: Vec<u8>,
    pub ttl: Option<i64>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::manufacturer_vouchers)]
pub struct NewManufacturerOV {
    pub guid: String,
    pub contents: Vec<u8>,
    pub ttl: Option<i64>,
}

impl fmt::Display for RendezvousOV {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GUID: {}, ttl: {:?}, contents: {:?}",
            self.guid, self.ttl, self.contents
        )
    }
}

impl fmt::Display for OwnerOV {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GUID: {}, to2_performed: {:?}, to0_accept_owner_wait_seconds {:?}, contents: {:?}",
            self.guid, self.to2_performed, self.to0_accept_owner_wait_seconds, self.contents
        )
    }
}

impl fmt::Display for ManufacturerOV {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GUID: {}, ttl: {:?}, contents: {:?}",
            self.guid, self.ttl, self.contents
        )
    }
}
