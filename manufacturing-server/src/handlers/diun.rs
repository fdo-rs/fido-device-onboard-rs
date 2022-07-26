use crate::{
    ManufacturingServiceUD, ManufacturingServiceUDT, DEVICE_KEY_FROM_DIUN_SES_KEY,
    PERFORMED_DIUN_SES_KEY,
};

use fdo_data_formats::{
    constants::{ErrorCode, HeaderKeys},
    messages::{self, ClientMessage, Message},
    types::{COSEHeaderMap, COSESign, KeyDeriveSide, KeyExchange},
};

use fdo_http_wrapper::{
    server::{Error, RequestInformation},
    EncryptionKeys,
};

const DIUN_KEYS_SES_KEY: &str = "mfg_diun_keys";

fn fail_if_no_diun<M>(user_data: &ManufacturingServiceUD) -> Result<(), warp::Rejection>
where
    M: ClientMessage,
{
    if user_data.diun_configuration.is_none() {
        return Err(Error::new(
            ErrorCode::InternalServerError,
            M::message_type(),
            "DIUN is disabled",
        )
        .into());
    }
    Ok(())
}

pub(crate) async fn connect(
    user_data: ManufacturingServiceUDT,
    mut request_info: RequestInformation,
    msg: messages::v11::diun::Connect,
) -> Result<(messages::v11::diun::Accept, RequestInformation), warp::Rejection> {
    fail_if_no_diun::<messages::v11::diun::Connect>(&user_data)?;

    let mut session = request_info.session;

    let use_noninteroperable_kdf =
        if let Some(value) = request_info.headers.get("X-Non-Interoperable-KDF") {
            log::trace!("Got a X-Non-Interoperable-KDF header: {:?}", value);
            matches!(value.to_str(), Ok("true"))
        } else {
            false
        };

    let b_key_exchange = KeyExchange::new(*msg.kex_suite())
        .map_err(Error::from_error::<messages::v11::diun::Connect, _>)?;

    let new_keys = b_key_exchange
        .derive_key(
            KeyDeriveSide::OwnerService,
            *msg.cipher_suite(),
            msg.key_exchange(),
            use_noninteroperable_kdf,
        )
        .map_err(Error::from_error::<messages::v11::diun::Connect, _>)?;
    let new_keys = EncryptionKeys::from_derived(*msg.cipher_suite(), new_keys);
    log::debug!("Got new keys, setting {:?}", new_keys);
    session
        .insert(DIUN_KEYS_SES_KEY, new_keys)
        .map_err(Error::from_error::<messages::v11::diun::Connect, _>)?;

    let accept_payload = messages::v11::diun::AcceptPayload::new(
        b_key_exchange
            .get_public()
            .map_err(Error::from_error::<messages::v11::diun::Connect, _>)?,
    );

    let mut accept_protected_header = COSEHeaderMap::new();
    accept_protected_header
        .insert(HeaderKeys::CUPHNonce, msg.nonce_diun_1())
        .unwrap();
    let mut accept_unprotected_header = COSEHeaderMap::new();
    accept_unprotected_header
        .insert(
            HeaderKeys::CUPHOwnerPubKey,
            &user_data.diun_configuration.as_ref().unwrap().public_keys,
        )
        .unwrap();

    let accept_payload = COSESign::new_with_protected(
        &accept_payload,
        accept_protected_header,
        Some(accept_unprotected_header),
        &user_data.diun_configuration.as_ref().unwrap().key,
    )
    .map_err(Error::from_error::<messages::v11::diun::Connect, _>)?;

    request_info.session = session;

    Ok((
        messages::v11::diun::Accept::new(accept_payload),
        request_info,
    ))
}

pub(crate) async fn request_key_parameters(
    user_data: ManufacturingServiceUDT,
    mut ses_with_store: RequestInformation,
    _msg: messages::v11::diun::RequestKeyParameters,
) -> Result<
    (
        messages::v11::diun::ProvideKeyParameters,
        RequestInformation,
    ),
    warp::Rejection,
> {
    fail_if_no_diun::<messages::v11::diun::RequestKeyParameters>(&user_data)?;

    let mut session = ses_with_store.session;

    let new_keys: Option<EncryptionKeys> = session.get(DIUN_KEYS_SES_KEY);
    if new_keys.is_none() {
        return Err(Error::new(
            ErrorCode::InvalidMessageError,
            messages::v11::diun::RequestKeyParameters::message_type(),
            "Sequence error: no diun_keys",
        )
        .into());
    }
    session.remove(DIUN_KEYS_SES_KEY);
    fdo_http_wrapper::server::set_encryption_keys::<messages::v11::diun::RequestKeyParameters>(
        &mut session,
        new_keys.unwrap(),
    )?;

    let params = messages::v11::diun::ProvideKeyParameters::new(
        user_data.diun_configuration.as_ref().unwrap().key_type,
        if user_data
            .diun_configuration
            .as_ref()
            .unwrap()
            .allowed_key_storage_types
            .is_empty()
        {
            None
        } else {
            Some(
                user_data
                    .diun_configuration
                    .as_ref()
                    .unwrap()
                    .allowed_key_storage_types
                    .clone(),
            )
        },
    );

    ses_with_store.session = session;

    Ok((params, ses_with_store))
}

pub(crate) async fn provide_key(
    user_data: ManufacturingServiceUDT,
    mut ses_with_store: RequestInformation,
    msg: messages::v11::diun::ProvideKey,
) -> Result<(messages::v11::diun::Done, RequestInformation), warp::Rejection> {
    fail_if_no_diun::<messages::v11::diun::ProvideKey>(&user_data)?;

    let mut session = ses_with_store.session;

    // Let's store the key in the session for DI
    session
        .insert(DEVICE_KEY_FROM_DIUN_SES_KEY, msg.public_key())
        .map_err(Error::from_error::<messages::v11::diun::ProvideKey, _>)?;

    // Let's tell DI the user came from DIUN
    session
        .insert(PERFORMED_DIUN_SES_KEY, true)
        .map_err(Error::from_error::<messages::v11::diun::ProvideKey, _>)?;

    ses_with_store.session = session;
    Ok((
        messages::v11::diun::Done::new(
            user_data
                .diun_configuration
                .as_ref()
                .unwrap()
                .mfg_string_type,
        ),
        ses_with_store,
    ))
}
