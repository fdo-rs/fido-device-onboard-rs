use serde::Deserialize;
use serde_tuple::Serialize_tuple;

use super::Message;
use crate::types::CborSimpleType;

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct AppStart {
    mfg_info: CborSimpleType,
}

impl AppStart {
    pub fn new(mfg_info: CborSimpleType) -> Self {
        AppStart { mfg_info }
    }

    pub fn get_mfg_info(&self) -> &CborSimpleType {
        &self.mfg_info
    }
}

impl Message for AppStart {
    fn message_type() -> u8 {
        10
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct SetCredentials {
    //ov_header: OwnershipVoucherHeader,
    ov_header: u8,
}

impl SetCredentials {
    //pub fn new(ov_header: OwnershipVoucherHeader) -> Self {
    pub fn new(ov_header: u8) -> Self {
        SetCredentials { ov_header }
    }

    //pub fn get_ov_header(&self) -> &OwnershipVoucherHeader {
    pub fn get_ov_header(&self) -> u8 {
        self.ov_header
    }
}

impl Message for SetCredentials {
    fn message_type() -> u8 {
        11
    }
}
