use std::convert::TryInto;

use crate::{
    ManufacturingServiceUD, ManufacturingServiceUDT, DEVICE_KEY_FROM_DIUN_SES_KEY,
    PERFORMED_DIUN_SES_KEY,
};

use fdo_data_formats::{
    constants::{ErrorCode, HashType},
    messages::{self, ClientMessage, Message},
    ownershipvoucher::{OwnershipVoucher, OwnershipVoucherHeader},
    publickey::X5Chain,
    types::Guid,
    PROTOCOL_VERSION,
};

use fdo_http_wrapper::server::{Error, Session, SessionWithStore};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private, Public},
    x509::{X509Builder, X509NameBuilder, X509},
};

fn fail_if_no_di_and_not_from_diun<M>(
    session: &Session,
    user_data: &ManufacturingServiceUD,
) -> Result<(), warp::Rejection>
where
    M: ClientMessage,
{
    if !user_data.enable_di
        && session
            .get::<Option<bool>>(PERFORMED_DIUN_SES_KEY)
            .is_none()
    {
        return Err(Error::new(
            ErrorCode::InternalServerError,
            M::message_type(),
            "Plain DI is disabled",
        )
        .into());
    }
    Ok(())
}

const OV_HEADER_SES_KEY: &str = "mfg_di_ov_header";
const DEVICE_CERTIFICATE_SES_KEY: &str = "mfg_di_device_certificate";

pub(crate) async fn app_start(
    user_data: ManufacturingServiceUDT,
    mut ses_with_store: SessionWithStore,
    msg: messages::di::AppStart,
) -> Result<(messages::di::SetCredentials, SessionWithStore), warp::Rejection> {
    let mut session = ses_with_store.session;
    fail_if_no_di_and_not_from_diun::<messages::di::AppStart>(&session, &user_data)?;

    let mfg_info = match msg.mfg_info() {
        serde_cbor::Value::Text(s) => s,
        _ => {
            return Err(Error::new(
                ErrorCode::InternalServerError,
                messages::di::AppStart::message_type(),
                "MFG Info is not a string",
            )
            .into())
        }
    };

    let public_key: Option<Vec<u8>> = match session.get(DEVICE_KEY_FROM_DIUN_SES_KEY) {
        Some(key) => Some(key),
        None => match &user_data.public_key_store {
            None => None,
            Some(store) => store
                .load_data(mfg_info)
                .await
                .map_err(Error::from_error::<messages::di::AppStart, _>)?,
        },
    };
    let public_key = match public_key {
        None => {
            return Err(Error::new(
                ErrorCode::InternalServerError,
                messages::di::AppStart::message_type(),
                "No public key located",
            )
            .into());
        }
        Some(v) => {
            PKey::public_key_from_der(&v).map_err(Error::from_error::<messages::di::AppStart, _>)?
        }
    };

    // Create new device certificate chain
    let device_certificate = create_device_certificate(
        user_data
            .device_cert_chain
            .leaf_certificate()
            .as_ref()
            .unwrap(),
        &user_data.device_cert_key,
        mfg_info,
        &public_key,
    )
    .map_err(Error::from_error::<messages::di::AppStart, _>)?;
    let device_certificate_chain =
        create_device_cert_chain(&user_data.device_cert_chain, device_certificate);
    let device_certificate_chain_hash = device_certificate_chain
        .hash(HashType::Sha384)
        .map_err(Error::from_error::<messages::di::AppStart, _>)?;

    // Create new ownership voucher header
    let new_voucher_header = OwnershipVoucherHeader::new(
        PROTOCOL_VERSION,
        Guid::new().map_err(Error::from_error::<messages::di::AppStart, _>)?,
        user_data.rendezvous_info.clone(),
        mfg_info.clone(),
        user_data
            .manufacturer_cert
            .clone()
            .try_into()
            .map_err(Error::from_error::<messages::di::AppStart, _>)?,
        Some(device_certificate_chain_hash),
    );

    // Store the OV Header and device cert chain
    session
        .insert(OV_HEADER_SES_KEY, new_voucher_header.clone())
        .map_err(Error::from_error::<messages::di::AppStart, _>)?;
    session
        .insert(DEVICE_CERTIFICATE_SES_KEY, device_certificate_chain)
        .map_err(Error::from_error::<messages::di::AppStart, _>)?;

    ses_with_store.session = session;
    Ok((
        messages::di::SetCredentials::new(new_voucher_header),
        ses_with_store,
    ))
}

fn create_device_cert_chain(chain: &X5Chain, device_certificate: X509) -> X5Chain {
    let mut chain: Vec<X509> = chain.chain().to_vec();
    chain.insert(0, device_certificate);
    X5Chain::new(chain).unwrap()
}

fn create_device_certificate(
    signer: &X509,
    signer_key: &PKeyRef<Private>,
    subject_name: &str,
    public_key: &PKeyRef<Public>,
) -> Result<X509, openssl::error::ErrorStack> {
    let mut device_subject = X509NameBuilder::new()?;
    device_subject.append_entry_by_text("CN", subject_name)?;
    let device_subject = device_subject.build();

    let mut builder = X509Builder::new()?;

    builder.set_version(2)?;

    builder.set_not_after(signer.not_after())?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_issuer_name(signer.subject_name())?;
    builder.set_subject_name(&device_subject)?;
    builder.set_pubkey(public_key)?;

    // Build a new serial number
    // We are generating a random number for serial number using 64 bits of output
    //  from a CSPRNG (openssl's rand), according to section 7.1 of
    //  CA/Browser Forum Baseline Requirements, version 1.7.3
    let mut serial_buf = [0; 8];
    openssl::rand::rand_bytes(&mut serial_buf)?;
    let serial = BigNum::from_slice(&serial_buf)?;
    let serial = Asn1Integer::from_bn(&serial)?;
    builder.set_serial_number(serial.as_ref())?;

    builder.sign(signer_key, MessageDigest::sha384())?;
    Ok(builder.build())
}

pub(crate) async fn set_hmac(
    user_data: ManufacturingServiceUDT,
    mut ses_with_store: SessionWithStore,
    msg: messages::di::SetHMAC,
) -> Result<(messages::di::Done, SessionWithStore), warp::Rejection> {
    let session = ses_with_store.session;
    fail_if_no_di_and_not_from_diun::<messages::di::SetHMAC>(&session, &user_data)?;

    let ov_header: OwnershipVoucherHeader = match session.get(OV_HEADER_SES_KEY) {
        Some(header) => header,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::diun::RequestKeyParameters::message_type(),
                "Sequence error: no ownership voucher header",
            )
            .into())
        }
    };
    let device_guid = ov_header.guid().clone();
    let ov_header =
        serde_cbor::to_vec(&ov_header).map_err(Error::from_error::<messages::di::SetHMAC, _>)?;
    let device_certificate_chain: X5Chain = match session.get(DEVICE_CERTIFICATE_SES_KEY) {
        Some(val) => val,
        None => {
            return Err(Error::new(
                ErrorCode::InvalidMessageError,
                messages::diun::RequestKeyParameters::message_type(),
                "Sequence error: no device certificate",
            )
            .into())
        }
    };

    // Create new ownership voucher
    let mut ov = OwnershipVoucher::new(
        ov_header,
        msg.hmac().clone(),
        Some(device_certificate_chain),
    );

    // If intended, extend with the owner key
    if let Some(manufacturer_key) = user_data.manufacturer_key.as_ref() {
        ov.extend(
            manufacturer_key,
            None,
            user_data.owner_cert.as_ref().unwrap(),
        )
        .map_err(Error::from_error::<messages::di::SetHMAC, _>)?;
    }

    // Write Ownership Voucher out to the store
    user_data
        .ownership_voucher_store
        .store_data(device_guid, None, ov)
        .await
        .map_err(Error::from_error::<messages::di::SetHMAC, _>)?;

    ses_with_store.session = session;

    Ok((messages::di::Done::new(), ses_with_store))
}
