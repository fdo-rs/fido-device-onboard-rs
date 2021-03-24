use anyhow::Error;

use fdo_data_formats::messages;
use fdo_http_wrapper::server::Session;

pub(crate) async fn perform_service_info(
    user_data: super::OwnerServiceUDT,
    session: &mut Session,
    msg: messages::to2::DeviceServiceInfo,
    loop_num: u32,
) -> Result<messages::to2::OwnerServiceInfo, Error> {
    todo!();
}
