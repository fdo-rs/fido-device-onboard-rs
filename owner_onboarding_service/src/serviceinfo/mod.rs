use std::collections::HashMap;
use std::string::ToString;

use anyhow::{bail, Context, Error, Result};
use serde::Deserialize;

use fdo_data_formats::{messages, types::ServiceInfo};
use fdo_http_wrapper::server::Session;

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceInfoSettings {}

#[derive(Debug)]
pub struct ServiceInfoConfiguration {}

impl ServiceInfoConfiguration {
    pub(crate) fn from_settings(settings: ServiceInfoSettings) -> Result<Self> {
        Ok(ServiceInfoConfiguration {})
    }
}

pub(crate) async fn perform_service_info(
    user_data: super::OwnerServiceUDT,
    session: &mut Session,
    msg: messages::to2::DeviceServiceInfo,
    loop_num: u32,
) -> Result<messages::to2::OwnerServiceInfo, Error> {
    let in_si = msg.service_info();
    let mut out_si = ServiceInfo::new();
    let mut is_done = true;

    log::trace!("Received ServiceInfo loop {}: {:?}", loop_num, in_si);

    log::trace!("Sending ServiceInfo loop {}: {:?}", loop_num, out_si);
    Ok(messages::to2::OwnerServiceInfo::new(false, is_done, out_si))
}
