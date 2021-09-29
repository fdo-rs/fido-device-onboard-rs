use core::time::Duration;
use std::convert::TryInto;

use fdo_data_formats::messages;
use fdo_data_formats::{
    constants::ErrorCode,
    messages::Message,
    types::{Nonce, TO1DataPayload},
};

use fdo_http_wrapper::server::Error;
use fdo_http_wrapper::server::SessionWithStore;

pub(super) async fn hello(
    _user_data: super::RendezvousUDT,
    mut ses_with_store: SessionWithStore,
    _msg: messages::to0::Hello,
) -> Result<(messages::to0::HelloAck, SessionWithStore), warp::Rejection> {
    let mut session = ses_with_store.session;

    let nonce3 = Nonce::new().map_err(Error::from_error::<messages::to0::Hello, _>)?;
    let nonce3_encoded = nonce3.to_string();

    session
        .insert("nonce3", nonce3_encoded)
        .map_err(Error::from_error::<messages::to0::Hello, _>)?;

    let res = messages::to0::HelloAck::new(nonce3);

    ses_with_store.session = session;

    Ok((res, ses_with_store))
}

pub(super) async fn ownersign(
    user_data: super::RendezvousUDT,
    mut ses_with_store: SessionWithStore,
    msg: messages::to0::OwnerSign,
) -> Result<(messages::to0::AcceptOwner, SessionWithStore), warp::Rejection> {
    let session = ses_with_store.session;

    // First check the easy things: whether the nonce in to0d is correct
    let correct_nonce: String = match session.get("nonce3") {
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
    let correct_nonce: Nonce = correct_nonce.parse().unwrap();
    log::trace!(
        "Matching correct nonce {:?} to received {:?}",
        correct_nonce,
        msg.to0d().nonce()
    );
    if &correct_nonce != msg.to0d().nonce() {
        return Err(Error::new(
            ErrorCode::InvalidMessageError,
            messages::to0::OwnerSign::message_type(),
            "Invalid nonce3",
        )
        .into());
    }

    // Now check the OV first public key: is it one we trust?
    let manufacturer_pubkey = msg
        .to0d()
        .ownership_voucher()
        .get_header()
        .map_err(|_| {
            Error::new(
                ErrorCode::InvalidMessageError,
                messages::to0::OwnerSign::message_type(),
                "Invalid OV",
            )
        })?
        .public_key;
    log::trace!(
        "Checking whether manufacturer key {:?} is trusted",
        manufacturer_pubkey
    );
    if !user_data
        .trusted_manufacturer_keys
        .contains_publickey(&manufacturer_pubkey)
    {
        return Err(Error::new(
            ErrorCode::InvalidOwnershipVoucher,
            messages::to0::OwnerSign::message_type(),
            "Ownership voucher manufacturer not trusted",
        )
        .into());
    }

    // Now, get the final owner key
    let ov_iter = msg
        .to0d()
        .ownership_voucher()
        .iter_entries()
        .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;
    let owner = match ov_iter.last() {
        None => {
            log::error!("No OV entries encountered");
            return Err(Error::new(
                ErrorCode::InvalidOwnershipVoucher,
                messages::to0::OwnerSign::message_type(),
                "Invalid OV",
            )
            .into());
        }
        Some(Err(e)) => {
            log::error!("Invalid OV entry encountered: {:?}", e);
            return Err(Error::new(
                ErrorCode::InvalidOwnershipVoucher,
                messages::to0::OwnerSign::message_type(),
                "Invalid OV",
            )
            .into());
        }
        Some(Ok(owner)) => owner,
    };

    // Verify the signature on to1d
    log::trace!(
        "Checking whether to1d payload is signed by owner public key {:?}",
        owner.public_key,
    );
    let to1d_payload: TO1DataPayload = match msg.to1d().get_payload(owner.public_key.pkey()) {
        Err(e) => {
            log::error!("Error verifying to1d: {:?}", e);
            return Err(Error::new(
                ErrorCode::InvalidOwnershipVoucher,
                messages::to0::OwnerSign::message_type(),
                "Invalid TO1D",
            )
            .into());
        }
        Ok(v) => v,
    };

    // Verify the to1d -> to0d hash
    let to0d_ser = serde_cbor::to_vec(&msg.to0d())
        .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;
    log::trace!(
        "Checking whether to1d->to1d hash {:?} matches data",
        to1d_payload.to1d_to_to0d_hash(),
    );
    to1d_payload
        .to1d_to_to0d_hash()
        .compare_data(&to0d_ser)
        .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;

    // Okay, wew! We can now trust the to1d payload, and the other data!
    // First, verify the device certificate chain
    let device_cert_chain = match msg.to0d().ownership_voucher().device_certificate_chain() {
        None => {
            return Err(Error::new(
                ErrorCode::InvalidOwnershipVoucher,
                messages::to0::OwnerSign::message_type(),
                "No device certificate",
            )
            .into());
        }
        Some(v) => v,
    };
    let device_pubkey = match device_cert_chain.verify_from_x5bag(&user_data.trusted_device_keys) {
        Err(cert_chain_err) => {
            log::debug!("Error verifying device certificate: {:?}", cert_chain_err);
            return Err(Error::new(
                ErrorCode::InvalidOwnershipVoucher,
                messages::to0::OwnerSign::message_type(),
                "Device certificate not trusted",
            )
            .into());
        }
        Ok(v) => v
            .clone()
            .try_into()
            .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?,
    };

    // Now compute the new wait_seconds and stuff to store
    let mut wait_seconds = msg.to0d().wait_seconds();
    if wait_seconds > user_data.max_wait_seconds {
        wait_seconds = user_data.max_wait_seconds;
    }
    let wait_seconds = wait_seconds;
    let device_guid = msg.to0d().ownership_voucher().get_header().unwrap().guid;

    // Actually store the data here
    let ttl = Duration::from_secs(wait_seconds as u64);
    log::info!(
        "Storing TO1D for device with GUID {:?} for {:?}",
        device_guid,
        ttl
    );
    user_data
        .store
        .store_data(device_guid, Some(ttl), (device_pubkey, msg.to1d().clone()))
        .await
        .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;

    ses_with_store.session = session;
    Ok((
        messages::to0::AcceptOwner::new(wait_seconds),
        ses_with_store,
    ))
}
