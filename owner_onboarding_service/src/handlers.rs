use core::time::Duration;
use std::convert::TryFrom;
use std::str::FromStr;

use aws_nitro_enclaves_cose::sign::{COSESign1, HeaderMap};
use serde_cbor::Value;

use fdo_data_formats::messages;
use fdo_data_formats::{
    constants::{DeviceSigType, ErrorCode, HeaderKeys},
    messages::Message,
    publickey::{PublicKey, PublicKeyBody},
    types::{
        Guid, KeyExchange, Nonce, SigInfo, TO1DataPayload, TO2ProveDevicePayload,
        TO2ProveOVHdrPayload,
    },
};

use fdo_http_wrapper::server::Error;
use fdo_http_wrapper::server::SessionWithStore;

pub(super) async fn hello_device(
    user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    msg: messages::to2::HelloDevice,
) -> Result<(messages::to2::ProveOVHdr, SessionWithStore), warp::Rejection> {
    let mut session = ses_with_store.session;

    // Check if we manage this device
    let ownership_voucher = match user_data
        .ownership_voucher_store
        .load_data(msg.guid())
        .await
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?
    {
        None => {
            return Err(Error::new(
                ErrorCode::ResourceNotFound,
                messages::to2::HelloDevice::message_type(),
                "Device not found",
            )
            .into())
        }
        Some(dev) => dev,
    };
    session
        .insert("device_guid", msg.guid().to_string())
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;

    // Check whether we support the specific siginfo
    match msg.a_signature_info().sig_type() {
        DeviceSigType::StSECP256R1 | DeviceSigType::StSECP384R1 => {}
        _ => {
            return Err(Error::new(
                ErrorCode::MessageBodyError,
                messages::to2::HelloDevice::message_type(),
                "Invcalid signature info",
            )
            .into())
        }
    }
    if !msg.a_signature_info().info().is_empty() {
        return Err(Error::new(
            ErrorCode::MessageBodyError,
            messages::to2::HelloDevice::message_type(),
            "Invcalid signature info",
        )
        .into());
    }

    // Build kex a
    let a_key_exchange = KeyExchange::new(msg.kex_suite());
    let nonce6 = Nonce::new().map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;

    // Store data
    session
        .insert("kexsuite", msg.kex_suite())
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;
    session
        .insert("ciphersuite", msg.cipher_suite())
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;
    session
        .insert("a_key_exchange", a_key_exchange.clone())
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;

    // Now produce the result
    let ov_hdr = ownership_voucher
        .get_header()
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;

    let res_payload = TO2ProveOVHdrPayload::new(
        ov_hdr,
        ownership_voucher.num_entries(),
        ownership_voucher.header_hmac().clone(),
        msg.nonce5().clone(),
        SigInfo::new(msg.a_signature_info().sig_type(), vec![]),
        a_key_exchange,
    );
    let res_payload = serde_cbor::to_vec(&res_payload)
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;
    let mut res_header = HeaderMap::new();
    res_header.insert(
        HeaderKeys::CUPHNonce.cbor_value(),
        serde_cbor::value::to_value(nonce6)
            .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?,
    );

    let res = COSESign1::new(&res_payload, &res_header, &user_data.owner_key)
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;
    let res = messages::to2::ProveOVHdr::new(res);

    ses_with_store.session = session;

    Ok((res, ses_with_store))
}

pub(super) async fn get_ov_next_entry(
    user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    msg: messages::to2::GetOVNextEntry,
) -> Result<(messages::to2::OVNextEntry, SessionWithStore), warp::Rejection> {
    let device_guid: String = match ses_with_store.session.get("device_guid") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::GetOVNextEntry::message_type(),
                "Request sequence failure",
            )
            .into())
        }
    };
    let device_guid = Guid::from_str(&device_guid).unwrap();

    let ownership_voucher = match user_data
        .ownership_voucher_store
        .load_data(&device_guid)
        .await
        .map_err(Error::from_error::<messages::to2::GetOVNextEntry, _>)?
    {
        None => {
            return Err(Error::new(
                ErrorCode::ResourceNotFound,
                messages::to2::GetOVNextEntry::message_type(),
                "Device not found",
            )
            .into())
        }
        Some(dev) => dev,
    };

    let entry = match ownership_voucher.entry(msg.entry_num() as u16) {
        Ok(Some(v)) => v,
        other => {
            log::info!("Error when retrieving OV entry: {:?}", other);
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::GetOVNextEntry::message_type(),
                "Error in getting entries",
            )
            .into());
        }
    };

    Ok((
        messages::to2::OVNextEntry::new(msg.entry_num() as u16, entry),
        ses_with_store,
    ))
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
