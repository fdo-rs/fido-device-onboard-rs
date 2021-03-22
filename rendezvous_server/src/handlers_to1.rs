use core::time::Duration;

use openssl::x509::{X509VerifyResult, X509};

use fdo_data_formats::messages;
use fdo_data_formats::{
    constants::{DeviceSigType, ErrorCode},
    messages::Message,
    publickey::{PublicKey, PublicKeyBody},
    types::{Nonce, SigInfo, TO1DataPayload},
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
    let nonce4_encoded = nonce4.to_encoded();

    session
        .insert("nonce4", nonce4_encoded)
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
    todo!();
}
