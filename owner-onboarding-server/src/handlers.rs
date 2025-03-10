use std::{collections::HashSet, str::FromStr};

use fdo_data_formats::{
    constants::{DeviceSigType, ErrorCode, HeaderKeys},
    messages::Message,
    ownershipvoucher::OwnershipVoucher,
    types::{
        COSEHeaderMap, COSESign, CipherSuite, Guid, KeyDeriveSide, KeyExchange, Nonce,
        RendezvousInfo, SigInfo, TO2ProveDevicePayload, TO2ProveOVHdrPayload,
        TO2SetupDevicePayload,
    },
};
use fdo_data_formats::{
    constants::{FedoraIotServiceInfoModule, StandardServiceInfoModule},
    messages::{self, v11::to2::OwnerServiceInfo},
};

use fdo_http_wrapper::server::Error;
use fdo_http_wrapper::server::RequestInformation;
use fdo_http_wrapper::EncryptionKeys;
use fdo_store::MetadataKey;
use fdo_util::servers::{OwnershipVoucherStoreMetadataKey, ServiceInfoApiReply};

pub(super) async fn hello_device(
    user_data: super::OwnerServiceUDT,
    mut request_info: RequestInformation,
    msg: messages::v11::to2::HelloDevice,
) -> Result<(messages::v11::to2::ProveOVHdr, RequestInformation), warp::Rejection> {
    let mut session = request_info.session;

    // Check if we manage this device
    let ownership_voucher = match user_data
        .ownership_voucher_store
        .load_data(msg.guid())
        .await
        .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?
    {
        None => {
            return Err(Error::new(
                ErrorCode::ResourceNotFound,
                messages::v11::to2::HelloDevice::message_type(),
                "Device not found",
            )
            .into())
        }
        Some(dev) => dev,
    };
    session
        .insert("device_guid", msg.guid().to_string())
        .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;

    // Check whether we support the specific siginfo
    match msg.a_signature_info().sig_type() {
        DeviceSigType::StSECP256R1 | DeviceSigType::StSECP384R1 => {}
        _ => {
            return Err(Error::new(
                ErrorCode::MessageBodyError,
                messages::v11::to2::HelloDevice::message_type(),
                "Invalid signature info",
            )
            .into())
        }
    }
    if !msg.a_signature_info().info().is_empty() {
        return Err(Error::new(
            ErrorCode::MessageBodyError,
            messages::v11::to2::HelloDevice::message_type(),
            "Invalid signature info",
        )
        .into());
    }

    // Build kex a
    let a_key_exchange = KeyExchange::new(msg.kex_suite())
        .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;
    let nonce6 = Nonce::new().map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;
    let a_key_exchange_public = a_key_exchange
        .get_public()
        .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;

    // Now produce the result
    let res_payload = TO2ProveOVHdrPayload::new(
        ownership_voucher.header_raw(),
        ownership_voucher.num_entries(),
        ownership_voucher.header_hmac().clone(),
        msg.nonce5().clone(),
        SigInfo::new(msg.a_signature_info().sig_type(), vec![]),
        a_key_exchange_public,
        request_info.req_hash.clone(),
    )
    .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;

    // Store data
    session
        .insert("nonce6", nonce6.clone())
        .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;
    session
        .insert("ciphersuite", msg.cipher_suite())
        .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;
    session
        .insert("a_key_exchange", a_key_exchange)
        .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;

    // Continue result production
    let mut res_header = COSEHeaderMap::new();
    res_header
        .insert(HeaderKeys::CUPHNonce, &nonce6)
        .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;
    res_header
        .insert(HeaderKeys::CUPHOwnerPubKey, &user_data.owner_pubkey)
        .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;

    let res = COSESign::new(&res_payload, Some(res_header), &user_data.owner_key)
        .map_err(Error::from_error::<messages::v11::to2::HelloDevice, _>)?;
    let res = messages::v11::to2::ProveOVHdr::new(res);

    request_info.session = session;

    Ok((res, request_info))
}

pub(super) async fn get_ov_next_entry(
    user_data: super::OwnerServiceUDT,
    ses_with_store: RequestInformation,
    msg: messages::v11::to2::GetOVNextEntry,
) -> Result<(messages::v11::to2::OVNextEntry, RequestInformation), warp::Rejection> {
    let device_guid: String = match ses_with_store.session.get("device_guid") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::v11::to2::GetOVNextEntry::message_type(),
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
        .map_err(Error::from_error::<messages::v11::to2::GetOVNextEntry, _>)?
    {
        None => {
            return Err(Error::new(
                ErrorCode::ResourceNotFound,
                messages::v11::to2::GetOVNextEntry::message_type(),
                "Device not found",
            )
            .into())
        }
        Some(dev) => dev,
    };

    let entry = ownership_voucher.entry(msg.entry_num() as usize).unwrap();

    Ok((
        messages::v11::to2::OVNextEntry::new(msg.entry_num() as u16, entry),
        ses_with_store,
    ))
}

pub(super) async fn prove_device(
    user_data: super::OwnerServiceUDT,
    mut request_info: RequestInformation,
    msg: messages::v11::to2::ProveDevice,
) -> Result<(messages::v11::to2::SetupDevice, RequestInformation), warp::Rejection> {
    let mut session = request_info.session;

    let device_guid: String = match session.get("device_guid") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::v11::to2::ProveDevice::message_type(),
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
                messages::v11::to2::ProveDevice::message_type(),
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
                messages::v11::to2::ProveDevice::message_type(),
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
                messages::v11::to2::GetOVNextEntry::message_type(),
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
        .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?
    {
        None => {
            return Err(Error::new(
                ErrorCode::ResourceNotFound,
                messages::v11::to2::ProveDevice::message_type(),
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
                    messages::v11::to2::ProveDevice::message_type(),
                    "Device certificate not supported",
                )
                .into())
            }
        },
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::v11::to2::ProveDevice::message_type(),
                "Device certificate chain not supported",
            )
            .into())
        }
    };
    let dev_pubkey = &device_certificate
        .public_key()
        .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?;

    // Get device EAT
    let token = msg.into_token();
    let nonce7: Nonce = match token
        .get_unprotected_value(HeaderKeys::EUPHNonce)
        .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?
    {
        Some(n) => n,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::v11::to2::ProveDevice::message_type(),
                "Missing nonce7",
            )
            .into())
        }
    };

    let eat = token
        .get_eat(dev_pubkey.as_ref())
        .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?;

    let eat_payload: TO2ProveDevicePayload = match eat
        .payload()
        .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?
    {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::v11::to2::ProveDevice::message_type(),
                "Missing payload",
            )
            .into())
        }
    };

    // Verify the nonce
    if eat.nonce() != &nonce6 {
        return Err(Error::new(
            ErrorCode::InvalidMessageError,
            messages::v11::to2::ProveDevice::message_type(),
            "Nonce invalid",
        )
        .into());
    }
    session
        .insert("nonce7", nonce7.clone())
        .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?;

    let use_noninteroperable_kdf =
        if let Some(value) = request_info.headers.get("X-Non-Interoperable-KDF") {
            log::trace!("Got a X-Non-Interoperable-KDF header: {:?}", value);
            matches!(value.to_str(), Ok("true"))
        } else {
            false
        };

    // Derive and set the keys
    let new_keys = a_key_exchange
        .derive_key(
            KeyDeriveSide::OwnerService,
            ciphersuite,
            eat_payload.b_key_exchange(),
            use_noninteroperable_kdf,
        )
        .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?;
    let new_keys = EncryptionKeys::from_derived(ciphersuite, new_keys);
    log::trace!("Got new keys, setting: {:?}", new_keys);
    fdo_http_wrapper::server::set_encryption_keys::<messages::v11::to2::ProveDevice>(
        &mut session,
        new_keys,
    )?;

    // Generate new ephemeral SetupDevicePayload
    let new_payload = TO2SetupDevicePayload::new(
        RendezvousInfo::new(Vec::new())
            .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?,
        Guid::new().unwrap(),
        nonce7,
        user_data.owner2_pub.clone(),
    );
    let new_token = COSESign::new(&new_payload, None, &user_data.owner2_key)
        .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?;
    let resp = messages::v11::to2::SetupDevice::new(new_token);

    session
        .insert("proven_device", true)
        .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?;

    request_info.session = session;

    Ok((resp, request_info))
}

pub(super) async fn device_service_info_ready(
    _user_data: super::OwnerServiceUDT,
    ses_with_store: RequestInformation,
    _msg: messages::v11::to2::DeviceServiceInfoReady,
) -> Result<
    (
        messages::v11::to2::OwnerServiceInfoReady,
        RequestInformation,
    ),
    warp::Rejection,
> {
    match ses_with_store.session.get::<bool>("proven_device") {
        Some(_) => {}
        None => {
            log::error!("Device attempted to skip the proving");
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::v11::to2::GetOVNextEntry::message_type(),
                "Request sequence failure",
            )
            .into());
        }
    };

    Ok((
        messages::v11::to2::OwnerServiceInfoReady::new(None),
        ses_with_store,
    ))
}

const MAX_SERVICE_INFO_LOOPS: u32 = 1000;

pub(super) async fn device_service_info(
    user_data: super::OwnerServiceUDT,
    mut ses_with_store: RequestInformation,
    msg: messages::v11::to2::DeviceServiceInfo,
) -> Result<(messages::v11::to2::OwnerServiceInfo, RequestInformation), warp::Rejection> {
    match ses_with_store.session.get::<bool>("proven_device") {
        Some(_) => {}
        None => {
            log::error!("Device attempted to skip the proving");
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::v11::to2::DeviceServiceInfo::message_type(),
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
                messages::v11::to2::GetOVNextEntry::message_type(),
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
                .map_err(Error::from_error::<messages::v11::to2::DeviceServiceInfo, _>)?;
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
            messages::v11::to2::DeviceServiceInfo::message_type(),
            "Too many serviceinfo loops performed",
        )
        .into());
    }
    ses_with_store
        .session
        .insert("num_service_info_loops", num_loops + 1)
        .map_err(Error::from_error::<messages::v11::to2::DeviceServiceInfo, _>)?;

    log::trace!(
        "Device {:?} is now starting ServiceInfo loop {}",
        device_guid,
        num_loops
    );

    let resp = match perform_service_info(
        user_data,
        &mut ses_with_store.session,
        device_guid,
        msg,
        num_loops,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Error during performing service info: {:?}", e);
            return Err(Error::new(
                ErrorCode::InternalServerError,
                messages::v11::to2::DeviceServiceInfo::message_type(),
                "Error handling serviceinfo",
            )
            .into());
        }
    };

    Ok((resp, ses_with_store))
}

async fn perform_service_info(
    user_data: super::OwnerServiceUDT,
    _session: &mut fdo_http_wrapper::server::Session,
    device_guid: Guid,
    msg: messages::v11::to2::DeviceServiceInfo,
    loop_num: u32,
) -> Result<OwnerServiceInfo, anyhow::Error> {
    if loop_num != 0 {
        // Return DONE for now after the first loop.
        return Ok(messages::v11::to2::OwnerServiceInfo::new(
            false,
            true,
            Default::default(),
        ));
    }
    let in_si = msg.service_info();

    log::trace!("Received ServiceInfo loop {}: {:?}", loop_num, in_si);

    let mut module_list: Option<Vec<String>> = None;

    for (module, var, value) in in_si.iter() {
        if module == StandardServiceInfoModule::DevMod.into() && var == "modules" {
            let mut rawmodlist: Vec<serde_cbor::Value> = serde_cbor::value::from_value(value)?;
            log::trace!("Received module list: {:?}", rawmodlist);

            // Skip the first two items.... They are integers :()
            let mut modlist: HashSet<String> = HashSet::new();
            for rawmod in rawmodlist.drain(..).skip(2) {
                modlist.insert(serde_cbor::value::from_value(rawmod)?);
            }
            log::trace!("Module list: {:?}", modlist);

            module_list = Some(modlist.into_iter().collect());
        }
    }

    let module_list = match module_list {
        None => {
            log::error!("No module list found in ServiceInfo");
            anyhow::bail!("No module list found in ServiceInfo");
        }
        Some(l) => l,
    };

    let resp: ServiceInfoApiReply = user_data
        .service_info_api_client
        .send_get([
            ("serviceinfo_api_version", "1"),
            ("device_guid", &device_guid.to_string()),
            ("modules", &module_list.join(",")),
        ])
        .await?;

    log::trace!("ServiceInfo API reply: {:?}", resp);

    let mut out_si = fdo_data_formats::types::ServiceInfo::new();

    if let Some(initial_user) = resp.initial_user {
        out_si.add(FedoraIotServiceInfoModule::SSHKey, "active", &true)?;
        out_si.add(
            FedoraIotServiceInfoModule::SSHKey,
            "username",
            &initial_user.username,
        )?;
        if initial_user.password.is_some() {
            out_si.add(
                FedoraIotServiceInfoModule::SSHKey,
                "password",
                &initial_user.password,
            )?;
        }
        if initial_user.ssh_keys.is_some() {
            out_si.add(
                FedoraIotServiceInfoModule::SSHKey,
                "sshkeys",
                &(initial_user.ssh_keys.unwrap().join(";")),
            )?;
        }
    }

    if let Some(extra_commands) = resp.extra_commands {
        for (module, key, value) in extra_commands {
            if key.ends_with("|hex") {
                let value = hex::decode(
                    value
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Invalid API response: non-hex"))?,
                )?;
                let value = serde_bytes::ByteBuf::from(value);
                let key = key.replace("|hex", "");
                out_si.add(module, &key, &value)?;
            } else {
                out_si.add(module, &key, &value)?;
            }
        }
    }

    if let Some(reboot) = resp.reboot {
        out_si.add(FedoraIotServiceInfoModule::Reboot, "active", &true)?;
        out_si.add(FedoraIotServiceInfoModule::Reboot, "reboot", &reboot.reboot)?;
    }

    log::trace!("Sending ServiceInfo result: {:?}", out_si);

    Ok(messages::v11::to2::OwnerServiceInfo::new(
        false, false, out_si,
    ))
}

pub(super) async fn done(
    user_data: super::OwnerServiceUDT,
    mut ses_with_store: RequestInformation,
    msg: messages::v11::to2::Done,
) -> Result<(messages::v11::to2::Done2, RequestInformation), warp::Rejection> {
    match ses_with_store.session.get::<bool>("proven_device") {
        Some(_) => {}
        None => {
            log::error!("Device attempted to skip the proving");
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::v11::to2::GetOVNextEntry::message_type(),
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
                messages::v11::to2::ProveDevice::message_type(),
                "Request sequence failure",
            )
            .into())
        }
    };
    if &nonce6 != msg.nonce6() {
        return Err(Error::new(
            ErrorCode::InvalidMessageError,
            messages::v11::to2::ProveDevice::message_type(),
            "Nonce6 invalid",
        )
        .into());
    }

    let device_guid: String = match ses_with_store.session.get("device_guid") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::v11::to2::GetOVNextEntry::message_type(),
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
                messages::v11::to2::ProveDevice::message_type(),
                "Request sequence failure",
            )
            .into())
        }
    };

    user_data
        .ownership_voucher_store
        .store_metadata(
            &device_guid,
            &MetadataKey::Local(OwnershipVoucherStoreMetadataKey::To2Performed),
            &true,
        )
        .await
        .map_err(Error::from_error::<messages::v11::to2::ProveDevice, _>)?;

    ses_with_store.session.remove("nonce7");
    ses_with_store.session.destroy();

    Ok((messages::v11::to2::Done2::new(nonce7), ses_with_store))
}

#[derive(Debug)]
#[allow(dead_code)]
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

#[derive(Debug)]
#[allow(dead_code)]
struct ImportFailure(anyhow::Error);
impl warp::reject::Reject for ImportFailure {}

pub(crate) async fn handler_import(
    udt: crate::OwnerServiceUDT,
    bytes: bytes::Bytes,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ovs = OwnershipVoucher::many_from_pem(&bytes)
        .map_err(|e| warp::reject::custom(ImportFailure(e.into())))?;
    log::info!("Importing {} ownership voucher(s)", ovs.len());
    // TODO(runcom): handler this better in case only partial import is done
    for ov in ovs {
        let guid = ov.header().guid().clone();
        udt.ownership_voucher_store
            .store_data(guid, ov)
            .await
            .map_err(|e| warp::reject::custom(ImportFailure(e.into())))?;
    }
    Ok(warp::reply::Response::new("ok".into()))
}
