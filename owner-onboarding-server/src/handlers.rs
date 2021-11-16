use std::str::FromStr;

use fdo_data_formats::messages;
use fdo_data_formats::{
    constants::{DeviceSigType, ErrorCode, HeaderKeys},
    messages::Message,
    types::{
        COSEHeaderMap, COSESign, CipherSuite, Guid, KeyDeriveSide, KeyExchange, Nonce,
        RendezvousInfo, SigInfo, TO2ProveDevicePayload, TO2ProveOVHdrPayload,
        TO2SetupDevicePayload,
    },
};

use fdo_http_wrapper::server::Error;
use fdo_http_wrapper::server::SessionWithStore;
use fdo_http_wrapper::EncryptionKeys;
use fdo_store::MetadataKey;
use fdo_util::servers::OwnershipVoucherStoreMetadataKey;

use crate::serviceinfo::perform_service_info;

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
    let a_key_exchange = KeyExchange::new(msg.kex_suite())
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;
    let nonce6 = Nonce::new().map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;
    let a_key_exchange_public = a_key_exchange
        .get_public()
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;

    // Now produce the result
    let ov_hdr = ownership_voucher.header();

    let res_payload = TO2ProveOVHdrPayload::new(
        ov_hdr.clone(),
        ownership_voucher.num_entries(),
        ownership_voucher.header_hmac().clone(),
        msg.nonce5().clone(),
        SigInfo::new(msg.a_signature_info().sig_type(), vec![]),
        a_key_exchange_public,
    )
    .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;

    // Store data
    session
        .insert("nonce6", nonce6.clone())
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;
    session
        .insert("ciphersuite", msg.cipher_suite())
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;
    session
        .insert("a_key_exchange", a_key_exchange)
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;

    // Continue result production
    let mut res_header = COSEHeaderMap::new();
    res_header
        .insert(HeaderKeys::CUPHNonce, &nonce6)
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;
    res_header
        .insert(HeaderKeys::CUPHOwnerPubKey, &user_data.owner_pubkey)
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;

    let res = COSESign::new(&res_payload, Some(res_header), &user_data.owner_key)
        .map_err(Error::from_error::<messages::to2::HelloDevice, _>)?;
    let res = messages::to2::ProveOVHdr::new(res);

    ses_with_store.session = session;

    Ok((res, ses_with_store))
}

pub(super) async fn get_ov_next_entry(
    user_data: super::OwnerServiceUDT,
    ses_with_store: SessionWithStore,
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

    let entry = ownership_voucher.entry(msg.entry_num() as usize).unwrap();

    Ok((
        messages::to2::OVNextEntry::new(msg.entry_num() as u16, entry),
        ses_with_store,
    ))
}

pub(super) async fn prove_device(
    user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    msg: messages::to2::ProveDevice,
) -> Result<(messages::to2::SetupDevice, SessionWithStore), warp::Rejection> {
    let mut session = ses_with_store.session;

    let device_guid: String = match session.get("device_guid") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::ProveDevice::message_type(),
                "Request sequence failure",
            )
            .into())
        }
    };
    let device_guid = Guid::from_str(&device_guid).unwrap();

    let nonce6: Nonce = match session.get("nonce6") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::ProveDevice::message_type(),
                "Request sequence failure",
            )
            .into())
        }
    };

    let a_key_exchange: KeyExchange = match session.get("a_key_exchange") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::ProveDevice::message_type(),
                "Request sequence failure",
            )
            .into())
        }
    };
    session.remove("a_key_exchange");

    let ciphersuite: CipherSuite = match session.get("ciphersuite") {
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
    session.remove("ciphersuite");

    let ownership_voucher = match user_data
        .ownership_voucher_store
        .load_data(&device_guid)
        .await
        .map_err(Error::from_error::<messages::to2::ProveDevice, _>)?
    {
        None => {
            return Err(Error::new(
                ErrorCode::ResourceNotFound,
                messages::to2::ProveDevice::message_type(),
                "Device not found",
            )
            .into())
        }
        Some(dev) => dev,
    };
    let device_certificate = match ownership_voucher.device_certificate_chain() {
        Some(chain) => match chain.leaf_certificate() {
            Some(cert) => cert,
            None => {
                return Err(Error::new(
                    ErrorCode::InvalidMessageError,
                    messages::to2::ProveDevice::message_type(),
                    "Device certificate not supported",
                )
                .into())
            }
        },
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::ProveDevice::message_type(),
                "Device certificate chain not supported",
            )
            .into())
        }
    };
    let dev_pubkey = &device_certificate
        .public_key()
        .map_err(Error::from_error::<messages::to2::ProveDevice, _>)?;

    // Get device EAT
    let token = msg.into_token();
    let nonce7: Nonce = match token
        .get_unprotected_value(HeaderKeys::EUPHNonce)
        .map_err(Error::from_error::<messages::to2::ProveDevice, _>)?
    {
        Some(n) => n,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::ProveDevice::message_type(),
                "Missing nonce7",
            )
            .into())
        }
    };

    let eat = token
        .get_eat(dev_pubkey.as_ref())
        .map_err(Error::from_error::<messages::to2::ProveDevice, _>)?;

    let eat_payload: TO2ProveDevicePayload = match eat
        .payload()
        .map_err(Error::from_error::<messages::to2::ProveDevice, _>)?
    {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::ProveDevice::message_type(),
                "Missing payload",
            )
            .into())
        }
    };

    // Verify the nonce
    if eat.nonce() != &nonce6 {
        return Err(Error::new(
            ErrorCode::InvalidMessageError,
            messages::to2::ProveDevice::message_type(),
            "Nonce invalid",
        )
        .into());
    }
    session
        .insert("nonce7", nonce7.clone())
        .map_err(Error::from_error::<messages::to2::ProveDevice, _>)?;

    // Derive and set the keys
    let new_keys = a_key_exchange
        .derive_key(
            KeyDeriveSide::OwnerService,
            ciphersuite,
            eat_payload.b_key_exchange(),
        )
        .map_err(Error::from_error::<messages::to2::ProveDevice, _>)?;
    let new_keys = EncryptionKeys::from_derived(ciphersuite, new_keys);
    log::trace!("Got new keys, setting: {:?}", new_keys);
    fdo_http_wrapper::server::set_encryption_keys::<messages::to2::ProveDevice>(
        &mut session,
        new_keys,
    )?;

    // Generate new ephemeral SetupDevicePayload
    let new_payload = TO2SetupDevicePayload::new(
        RendezvousInfo::new(Vec::new()),
        Guid::new().unwrap(),
        nonce7,
        user_data.owner2_pub.clone(),
    );
    let new_token = COSESign::new(&new_payload, None, &user_data.owner2_key)
        .map_err(Error::from_error::<messages::to2::ProveDevice, _>)?;
    let resp = messages::to2::SetupDevice::new(new_token);

    session
        .insert("proven_device", true)
        .map_err(Error::from_error::<messages::to2::ProveDevice, _>)?;

    ses_with_store.session = session;

    Ok((resp, ses_with_store))
}

pub(super) async fn device_service_info_ready(
    _user_data: super::OwnerServiceUDT,
    ses_with_store: SessionWithStore,
    _msg: messages::to2::DeviceServiceInfoReady,
) -> Result<(messages::to2::OwnerServiceInfoReady, SessionWithStore), warp::Rejection> {
    match ses_with_store.session.get::<bool>("proven_device") {
        Some(_) => {}
        None => {
            log::error!("Device attempted to skip the proving");
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::GetOVNextEntry::message_type(),
                "Request sequence failure",
            )
            .into());
        }
    };

    Ok((
        messages::to2::OwnerServiceInfoReady::new(None),
        ses_with_store,
    ))
}

const MAX_SERVICE_INFO_LOOPS: u32 = 1000;

pub(super) async fn device_service_info(
    user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    msg: messages::to2::DeviceServiceInfo,
) -> Result<(messages::to2::OwnerServiceInfo, SessionWithStore), warp::Rejection> {
    match ses_with_store.session.get::<bool>("proven_device") {
        Some(_) => {}
        None => {
            log::error!("Device attempted to skip the proving");
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::DeviceServiceInfo::message_type(),
                "Request sequence failure",
            )
            .into());
        }
    };
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

    let num_loops = match ses_with_store.session.get::<u32>("num_service_info_loops") {
        Some(v) => v,
        None => {
            ses_with_store
                .session
                .insert("num_service_info_loops", 1)
                .map_err(Error::from_error::<messages::to2::DeviceServiceInfo, _>)?;
            0
        }
    };
    if num_loops > MAX_SERVICE_INFO_LOOPS {
        log::warn!(
            "Device {:?} has attempted to perform too many ServiceInfo loops",
            device_guid
        );
        return Err(Error::new(
            ErrorCode::InvalidMessageError,
            messages::to2::DeviceServiceInfo::message_type(),
            "Too many serviceinfo loops performed",
        )
        .into());
    }
    ses_with_store
        .session
        .insert("num_service_info_loops", num_loops + 1)
        .map_err(Error::from_error::<messages::to2::DeviceServiceInfo, _>)?;

    log::trace!(
        "Device {:?} is now starting ServiceInfo loop {}",
        device_guid,
        num_loops
    );

    let resp =
        match perform_service_info(user_data, &mut ses_with_store.session, msg, num_loops).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Error during performing service info: {:?}", e);
                return Err(Error::new(
                    ErrorCode::InternalServerError,
                    messages::to2::DeviceServiceInfo::message_type(),
                    "Error handling serviceinfo",
                )
                .into());
            }
        };

    Ok((resp, ses_with_store))
}

pub(super) async fn done(
    user_data: super::OwnerServiceUDT,
    mut ses_with_store: SessionWithStore,
    msg: messages::to2::Done,
) -> Result<(messages::to2::Done2, SessionWithStore), warp::Rejection> {
    match ses_with_store.session.get::<bool>("proven_device") {
        Some(_) => {}
        None => {
            log::error!("Device attempted to skip the proving");
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::GetOVNextEntry::message_type(),
                "Request sequence failure",
            )
            .into());
        }
    };

    let nonce6: Nonce = match ses_with_store.session.get("nonce6") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::ProveDevice::message_type(),
                "Request sequence failure",
            )
            .into())
        }
    };
    if &nonce6 != msg.nonce6() {
        return Err(Error::new(
            ErrorCode::InvalidMessageError,
            messages::to2::ProveDevice::message_type(),
            "Nonce6 invalid",
        )
        .into());
    }

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
    log::info!("Device {:?} has finished its onboarding", device_guid);

    let nonce7: Nonce = match ses_with_store.session.get("nonce7") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to2::ProveDevice::message_type(),
                "Request sequence failure",
            )
            .into())
        }
    };
    ses_with_store.session.remove("nonce7");
    ses_with_store.session.destroy();

    user_data.ownership_voucher_store.store_metadata(
        &device_guid,
        &MetadataKey::Local(OwnershipVoucherStoreMetadataKey::To2Performed),
        &true,
    );
    user_data.ownership_voucher_store.destroy_metadata(
        &device_guid,
        &MetadataKey::Local(OwnershipVoucherStoreMetadataKey::To0AcceptOwnerWaitSeconds),
    );

    Ok((messages::to2::Done2::new(nonce7), ses_with_store))
}

#[derive(Debug)]
struct RtrFailure(anyhow::Error);
impl warp::reject::Reject for RtrFailure {}

pub(crate) async fn report_to_rendezvous_handler(
    udt: crate::OwnerServiceUDT,
    enabled: bool,
) -> Result<impl warp::Reply, warp::Rejection> {
    if !enabled {
        return Err(warp::reject::not_found());
    }
    crate::report_to_rendezvous(udt)
        .await
        .map_err(|e| warp::reject::custom(RtrFailure(e)))?;
    Ok(warp::reply::Response::new("ok".into()))
}
