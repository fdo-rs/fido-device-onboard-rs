use fdo_data_formats::{
    constants::{DeviceSigType, ErrorCode},
    messages::{self, Message},
    types::{Guid, Nonce, SigInfo},
};

use fdo_http_wrapper::server::Error;
use fdo_http_wrapper::server::SessionWithStore;

pub(super) async fn hello_rv(
    user_data: super::RendezvousUDT,
    mut ses_with_store: SessionWithStore,
    msg: messages::to1::HelloRV,
) -> Result<(messages::to1::HelloRVAck, SessionWithStore), warp::Rejection> {
    let mut session = ses_with_store.session;

    // Check the signature info
    let a_sig_info = msg.a_signature_info();
    match a_sig_info.sig_type() {
        DeviceSigType::StSECP256R1 | DeviceSigType::StSECP384R1 => {}
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to1::HelloRV::message_type(),
                "Unsupported signature scheme",
            )
            .into())
        }
    }
    if !a_sig_info.info().is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidMessageError,
            messages::to1::HelloRV::message_type(),
            "Unsupported signature info",
        )
        .into());
    }

    // Look up device
    log::trace!("Looking up device {:?}", msg.guid());
    let dev_to1d = user_data
        .store
        .load_data(msg.guid())
        .await
        .map_err(Error::from_error::<messages::to1::HelloRV, _>)?;
    match dev_to1d {
        Some(_) => {}
        None => {
            return Err(Error::new(
                ErrorCode::ResourceNotFound,
                messages::to1::HelloRV::message_type(),
                "Device GUID not found",
            )
            .into())
        }
    }

    // Create new nonce
    let nonce4 = Nonce::new().map_err(Error::from_error::<messages::to1::HelloRV, _>)?;
    let nonce4_encoded = nonce4.to_string();

    session
        .insert("nonce4", nonce4_encoded)
        .map_err(Error::from_error::<messages::to1::HelloRV, _>)?;
    session
        .insert("device_guid", msg.guid().to_string())
        .map_err(Error::from_error::<messages::to1::HelloRV, _>)?;

    // Build return message
    let b_sig_info = SigInfo::new(a_sig_info.sig_type(), vec![]);

    let res = messages::to1::HelloRVAck::new(nonce4, b_sig_info);

    // Return message
    ses_with_store.session = session;
    Ok((res, ses_with_store))
}

pub(super) async fn prove_to_rv(
    user_data: super::RendezvousUDT,
    mut ses_with_store: SessionWithStore,
    msg: messages::to1::ProveToRV,
) -> Result<(messages::to1::RVRedirect, SessionWithStore), warp::Rejection> {
    let session = ses_with_store.session;

    let nonce4: String = match session.get("nonce4") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to0::OwnerSign::message_type(),
                "Request sequence failure",
            )
            .into())
        }
    };
    let nonce4: Nonce = nonce4.parse().unwrap();

    let device_guid: String = match session.get("device_guid") {
        Some(v) => v,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to1::ProveToRV::message_type(),
                "Request sequence failure",
            )
            .into())
        }
    };
    let device_guid = &device_guid.parse().unwrap();

    let (dev_pkey, to1d) = match user_data.store.load_data(&device_guid).await {
        Ok(Some(dev)) => dev,
        Err(e) => {
            log::trace!("Error getting device entry: {:?}", e);
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::to1::ProveToRV::message_type(),
                "Request sequence failure",
            )
            .into());
        }
        Ok(None) => {
            return Err(Error::new(
                ErrorCode::ResourceNotFound,
                messages::to1::ProveToRV::message_type(),
                "Device not found",
            )
            .into());
        }
    };

    // Check if token is signed
    let dev_pkey = dev_pkey
        .as_pkey()
        .map_err(Error::from_error::<messages::to1::ProveToRV, _>)?;
    let signed_nonce: Vec<u8> = msg.token().get_payload(&dev_pkey).map_err(|_| {
        Error::new(
            ErrorCode::InvalidMessageError,
            messages::to1::ProveToRV::message_type(),
            "Signature invaid",
        )
    })?;
    let signed_nonce = Nonce::from_value(&signed_nonce).map_err(|_| {
        Error::new(
            ErrorCode::InvalidMessageError,
            messages::to1::ProveToRV::message_type(),
            "Signature invaid",
        )
    })?;

    if nonce4 != signed_nonce {
        return Err(Error::new(
            ErrorCode::InvalidMessageError,
            messages::to1::ProveToRV::message_type(),
            "Nonce invaid",
        )
        .into());
    }

    // Okay, device is trusted! Now return their owner information
    let rv_redirect = messages::to1::RVRedirect::new(to1d);

    ses_with_store.session = session;
    Ok((rv_redirect, ses_with_store))
}
