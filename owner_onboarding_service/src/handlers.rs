use core::time::Duration;
use std::convert::TryFrom;

use fdo_data_formats::messages;
use fdo_data_formats::{
    constants::ErrorCode,
    messages::Message,
    publickey::{PublicKey, PublicKeyBody},
    types::{Nonce, TO1DataPayload},
};

use fdo_http_wrapper::server::Error;
use fdo_http_wrapper::server::SessionWithStore;

pub(super) async fn hello_device(
    _user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    _msg: messages::to2::HelloDevice,
) -> Result<(messages::to2::ProveOVHdr, SessionWithStore), warp::Rejection> {
    todo!();
}

pub(super) async fn get_ov_next_entry(
    _user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    _msg: messages::to2::GetOVNextEntry,
) -> Result<(messages::to2::OVNextEntry, SessionWithStore), warp::Rejection> {
    todo!();
}

pub(super) async fn prove_device(
    _user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    _msg: messages::to2::ProveDevice,
) -> Result<(messages::to2::SetupDevice, SessionWithStore), warp::Rejection> {
    todo!();
}

pub(super) async fn device_service_info_ready(
    _user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    _msg: messages::to2::DeviceServiceInfoReady,
) -> Result<(messages::to2::OwnerServiceInfoReady, SessionWithStore), warp::Rejection> {
    todo!();
}

pub(super) async fn device_service_info(
    _user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    _msg: messages::to2::DeviceServiceInfo,
) -> Result<(messages::to2::OwnerServiceInfo, SessionWithStore), warp::Rejection> {
    todo!();
}

pub(super) async fn done(
    _user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    _msg: messages::to2::Done,
) -> Result<(messages::to2::Done2, SessionWithStore), warp::Rejection> {
    todo!();
}
