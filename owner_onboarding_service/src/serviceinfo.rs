use anyhow::{Error, Result};

use fdo_data_formats::messages;
use fdo_http_wrapper::server::Session;

#[derive(Debug, serde::Deserialize, Clone)]
pub struct ServiceInfoSettings {}

#[derive(Debug)]
pub struct ServiceInfoConfiguration {}

impl ServiceInfoConfiguration {
    pub(crate) fn from_settings(settings: ServiceInfoSettings) -> Result<Self> {
        todo!();
    }
}

pub(crate) async fn perform_service_info(
    user_data: super::OwnerServiceUDT,
    session: &mut Session,
    msg: messages::to2::DeviceServiceInfo,
    loop_num: u32,
) -> Result<messages::to2::OwnerServiceInfo, Error> {
    todo!();
}
