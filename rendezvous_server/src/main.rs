use anyhow::{bail, Context, Result};
use openssl::x509::X509;
use serde::Deserialize;
use warp::Filter;

use std::sync::Arc;

use fdo_data_formats::types::Guid;
use fdo_store::{Store, StoreDriver};

mod handlers {
    use core::time::Duration;

    use openssl::x509::{X509VerifyResult, X509};

    use fdo_data_formats::messages;
    use fdo_data_formats::{
        constants::ErrorCode,
        messages::Message,
        publickey::{PublicKey, PublicKeyBody},
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
        let nonce3_encoded = nonce3.to_encoded();

        session
            .insert("nonce3", nonce3_encoded)
            .map_err(Error::from_error::<messages::to0::Hello, _>)?;

        let res = messages::to0::HelloAck::new(nonce3);

        ses_with_store.session = session;

        Ok((res, ses_with_store))
    }

    fn is_trusted_cert(
        trusted_certs: &[X509],
        under_consideration: &PublicKey,
    ) -> Result<(), Error> {
        let (_, under_consideration) = under_consideration
            .get_body()
            .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;
        let under_consideration = match under_consideration {
            PublicKeyBody::X509(cert) => cert,
            _ => {
                return Err(Error::new(
                    ErrorCode::InternalServerError,
                    messages::to0::OwnerSign::message_type(),
                    "Unsupported public key type",
                ))
            }
        };

        for trusted_cert in trusted_certs {
            if trusted_cert.issued(&under_consideration) == X509VerifyResult::OK {
                let trusted_key = trusted_cert
                    .public_key()
                    .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;
                let verify_result = under_consideration
                    .verify(&trusted_key)
                    .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;
                if verify_result {
                    log::trace!(
                        "Valid signature on {:?} by {:?}",
                        under_consideration,
                        trusted_cert
                    );
                    return Ok(());
                } else {
                    log::error!(
                        "Certificate validation failed for {:?}",
                        under_consideration
                    );
                }
            }
        }
        Err(Error::new(
            ErrorCode::InvalidOwnershipVoucher,
            messages::to0::OwnerSign::message_type(),
            "Ownership voucher manufacturer not trusted",
        ))
    }

    const MAX_WAIT_SECONDS: u32 = 2592000;

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
        let correct_nonce = Nonce::from_encoded(&correct_nonce);
        log::trace!(
            "Matching correct nonce {:?} to received {:?}",
            correct_nonce,
            msg.to0d().nonce()
        );
        correct_nonce.compare(msg.to0d().nonce()).map_err(|_| {
            Error::new(
                ErrorCode::InvalidMessageError,
                messages::to0::OwnerSign::message_type(),
                "Invalid nonce3",
            )
        })?;

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
        is_trusted_cert(&user_data.trusted_keys, &manufacturer_pubkey)?;

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
        let owner_pubkey = match owner.public_key.as_pkey() {
            Err(e) => {
                log::error!("Error in converting OV pubkey: {:?}", e);
                return Err(Error::new(
                    ErrorCode::InvalidOwnershipVoucher,
                    messages::to0::OwnerSign::message_type(),
                    "Invalid OV",
                )
                .into());
            }
            Ok(v) => v,
        };

        // Verify the signature on to1d
        log::trace!(
            "Checking whether to1d payload is signed by owner public key {:?}",
            owner_pubkey
        );
        let to1d_payload = match msg.to1d().get_payload(Some(&owner_pubkey)) {
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
        let to1d: TO1DataPayload = serde_cbor::from_slice(&to1d_payload)
            .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;

        // Verify the to1d -> to0d hash
        let to0d_ser = serde_cbor::to_vec(&msg.to0d())
            .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;
        log::trace!(
            "Checking whether to1d->to1d hash {:?} matches data {:?}",
            to1d.to1d_to_to0d_hash(),
            to0d_ser
        );
        to1d.to1d_to_to0d_hash()
            .compare_data(&to0d_ser)
            .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;

        // Okay, wew! We can now trust the to1d payload, and the other data!
        let mut wait_seconds = msg.to0d().wait_seconds();
        if wait_seconds > MAX_WAIT_SECONDS {
            wait_seconds = MAX_WAIT_SECONDS;
        }
        let wait_seconds = wait_seconds;
        let device_guid = msg.to0d().ownership_voucher().get_header().unwrap().guid;
        let to1d = serde_cbor::to_vec(&msg.to1d())
            .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;

        // Actually store the data here
        let ttl = Duration::from_secs(wait_seconds as u64);
        log::info!(
            "Storing TO1D for device with GUID {:?} for {:?}",
            device_guid,
            ttl
        );
        user_data
            .store
            .store_data(device_guid, Some(ttl), to1d)
            .await
            .map_err(Error::from_error::<messages::to0::OwnerSign, _>)?;

        ses_with_store.session = session;
        Ok((
            messages::to0::AcceptOwner::new(wait_seconds),
            ses_with_store,
        ))
    }
}

struct RendezvousUD {
    trusted_keys: Vec<X509>,
    store: Box<dyn Store<Guid, Vec<u8>>>,
}

type RendezvousUDT = Arc<RendezvousUD>;

#[derive(Debug, Deserialize)]
struct Settings {
    // Storage info
    storage_driver: StoreDriver,
    storage_config: Option<config::Value>,

    // Session store info
    session_store_driver: StoreDriver,
    session_store_config: Option<config::Value>,

    // Trusted keys
    trusted_keys_path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("rendezvous_config"))
        .context("Loading configuration files")?
        .merge(config::Environment::with_prefix("rendezvous"))
        .context("Loading configuration from environment variables")?;
    let settings: Settings = settings.try_into().context("Error parsing configuration")?;

    // Initialize stores
    let store = settings
        .storage_driver
        .initialize(settings.storage_config)?;
    let session_store = settings
        .session_store_driver
        .initialize(settings.session_store_config)?;
    let session_store = fdo_http_wrapper::server::SessionStore::new(session_store);

    // Load X509 certs
    let trusted_keys = {
        let trusted_keys_path = settings.trusted_keys_path;
        let contents = std::fs::read(&trusted_keys_path)
            .with_context(|| format!("Error reading trusted keys at {}", &trusted_keys_path))?;
        X509::stack_from_pem(&contents).context("Error parsing trusted keys")?
    };

    // Initialize handler stores
    let user_data = Arc::new(RendezvousUD {
        store,
        trusted_keys,
    });

    // Install handlers
    let hello = warp::get().map(|| "Hello from the rendezvous server");

    let handler_hello = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::hello,
    );
    let handler_ownersign = fdo_http_wrapper::server::fdo_request_filter(
        user_data.clone(),
        session_store.clone(),
        handlers::ownersign,
    );

    let routes = warp::post()
        .and(hello.or(handler_hello).or(handler_ownersign))
        .recover(fdo_http_wrapper::server::handle_rejection)
        .with(warp::log("rendezvous_server"));

    println!("Listening on :8081");
    warp::serve(routes).run(([0, 0, 0, 0], 8081)).await;
    Ok(())
}
