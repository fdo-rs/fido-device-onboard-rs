use std::{borrow::Borrow, env, fs, path::PathBuf, thread, time};

use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use thiserror::Error;

use fdo_data_formats::{
    cborparser::ParsedArray,
    constants::{
        DeviceSigType, ErrorCode, HeaderKeys, MessageType, RendezvousProtocolValue,
        TransportProtocol,
    },
    enhanced_types::{RendezvousInterpretedDirective, RendezvousInterpreterSide},
    messages,
    ownershipvoucher::{OwnershipVoucher, OwnershipVoucherHeader},
    types::{
        new_eat, COSEHeaderMap, COSESign, CipherSuite, EATokenPayload, HMac, KexSuite,
        KeyDeriveSide, KeyExchange, Nonce, PayloadCreating, SigInfo, TO1DataPayload,
        TO2AddressEntry, TO2ProveDevicePayload, TO2ProveOVHdrPayload, UnverifiedValue,
    },
    DeviceCredential, ProtocolVersion, Serializable,
};
use fdo_http_wrapper::client::{RequestResult, ServiceClient};
use fdo_util::device_credential_locations;
use fdo_util::device_credential_locations::UsableDeviceCredentialLocation;

mod reencrypt;
mod serviceinfo;

const DEVICE_ONBOARDING_EXECUTED_MARKER_FILE: &str = "/etc/device_onboarding_performed";

fn marker_file_location() -> PathBuf {
    if let Ok(path) = env::var("DEVICE_ONBOARDING_EXECUTED_MARKER_FILE_PATH") {
        PathBuf::from(path)
    } else {
        PathBuf::from(DEVICE_ONBOARDING_EXECUTED_MARKER_FILE)
    }
}

// Rendezvous delays related variables
const RV_DEFAULT_DELAY_SEC: f32 = 120.0;
const RV_DEFAULT_DELAY_OFFSET: f32 = 30.0;
const RV_USER_DEFINED_DELAY_OFFSET: f32 = 0.25;

// Encapsulates errors caused during TO1/TO2
#[derive(Debug)]
struct ErrorResult {
    e_code: ErrorCode,
    e_string: &'static str,
    message: MessageType,
    error: anyhow::Error,
}

impl ErrorResult {
    fn new(
        e_code: ErrorCode,
        e_string: &'static str,
        message: MessageType,
        error: anyhow::Error,
    ) -> Self {
        ErrorResult {
            e_code,
            e_string,
            message,
            error,
        }
    }
}

#[derive(Error, Debug)]
enum ClientError {
    #[error("Error in the response result")]
    Response(ErrorResult),
    #[error("Error with the request")]
    Request(ErrorResult),
}

async fn send_client_error(
    client: &mut fdo_http_wrapper::client::ServiceClient,
    error: &ErrorResult,
) {
    let message = messages::v11::ErrorMessage::new(
        error.e_code,
        error.message,
        error.e_string.to_string(),
        uuid::Uuid::new_v4().as_u128(),
    );
    log::trace!("{:?}", &message);
    let _: RequestResult<messages::v11::ErrorMessage> = client.send_request(message, None).await;
}

fn mark_device_onboarding_executed() -> Result<()> {
    fs::write(marker_file_location(), "executed").context("Error creating executed marker file")
}

fn get_to2_urls(entries: &[TO2AddressEntry]) -> Vec<String> {
    let mut urls = Vec::new();

    for addr_entry in entries {
        let prot_text = match addr_entry.protocol() {
            TransportProtocol::Http => "http",
            TransportProtocol::Https => "https",
            _ => continue,
        };
        if let Some(dns_name) = addr_entry.dns() {
            urls.push(format!(
                "{}://{}:{}",
                prot_text,
                dns_name,
                addr_entry.port()
            ));
        }
        if let Some(ip_address) = addr_entry.ip() {
            urls.push(format!(
                "{}://{}:{}",
                prot_text,
                ip_address,
                addr_entry.port()
            ));
        }
    }

    urls
}

async fn get_client_list(rv_entry: &RendezvousInterpretedDirective) -> Result<Vec<ServiceClient>> {
    log::trace!("Getting client list from rv_entry {:?}", rv_entry);
    let mut service_client_list = Vec::new();

    let urls = rv_entry.get_urls();
    if urls.is_empty() {
        log::trace!("No URLs found");
    }
    if rv_entry.bypass {
        bail!("Rendezvous Bypass is not yet implemented");
    }
    if rv_entry.wifi_ssid.is_some() {
        bail!("Rendezvous WiFi configuration is not yet implemented");
    }
    if rv_entry.user_input {
        bail!("Rendezvous User Input is not yet implemented");
    }
    if rv_entry.protocol != RendezvousProtocolValue::Http
        && rv_entry.protocol != RendezvousProtocolValue::Https
    {
        bail!("Non-HTTP(S) protocol is not implemented");
    }
    for url in &urls {
        service_client_list.push(fdo_http_wrapper::client::ServiceClient::new(
            ProtocolVersion::Version1_1,
            url,
        ));
    }
    log::trace!("Client list: {:?}", service_client_list);
    Ok(service_client_list)
}

/// TO1: Sends HelloRV, Receives HelloRVAck
async fn perform_hellorv(
    devcred: &dyn DeviceCredential,
    client: &mut ServiceClient,
) -> Result<COSESign, ClientError> {
    let sig_type = DeviceSigType::StSECP384R1;

    let hello_rv = messages::v11::to1::HelloRV::new(
        devcred.device_guid().clone(),
        SigInfo::new(sig_type, vec![]),
    );
    let hello_rv_ack: RequestResult<messages::v11::to1::HelloRVAck> =
        client.send_request(hello_rv, None).await;

    let hello_rv_ack = hello_rv_ack.context("Error sending HelloRV").map_err(|e| {
        ClientError::Request(ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error sending HelloRV",
            MessageType::TO1HelloRV,
            e,
        ))
    })?;
    log::trace!("Hello RV ack: {:?}", hello_rv_ack);

    let b_sig_info = hello_rv_ack.b_signature_info();
    if b_sig_info.sig_type() != sig_type {
        return Err(ClientError::Response(ErrorResult::new(
            ErrorCode::InvalidMessageError,
            "Unsupported sig type returned",
            MessageType::TO1HelloRVAck,
            anyhow!("Unsupported sig type returned"),
        )));
    }
    if !b_sig_info.info().is_empty() {
        return Err(ClientError::Response(ErrorResult::new(
            ErrorCode::InvalidMessageError,
            "Non-empty sig info returned",
            MessageType::TO1HelloRVAck,
            anyhow!("Non-empty sig info returned"),
        )));
    }
    let nonce4 = hello_rv_ack.nonce4();

    // Create EAT payload
    let eat: EATokenPayload<PayloadCreating> =
        new_eat::<bool>(None, nonce4.clone(), devcred.device_guid().clone())
            .context("Error creating EATokenPayload")
            .map_err(|e| {
                ClientError::Request(ErrorResult::new(
                    ErrorCode::InternalServerError,
                    "Error creating EATokenPayload",
                    MessageType::TO1HelloRVAck,
                    e,
                ))
            })?;

    // Create signature over nonce4
    let signer = devcred
        .get_signer()
        .context("Error getting Cose signer")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InternalServerError,
                "Error getting Cose signer",
                MessageType::TO1HelloRVAck,
                e,
            ))
        })?;
    let token = COSESign::from_eat(eat, None, signer.as_ref())
        .context("Error signing new token")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InternalServerError,
                "Error signing new token",
                MessageType::TO1HelloRVAck,
                e,
            ))
        })?;
    Ok(token)
}

/// TO1: Sends ProveToRV, Receives RVRedirect
async fn perform_provetorv(
    token: COSESign,
    client: &mut ServiceClient,
) -> Result<COSESign, ClientError> {
    let prove_to_rv = messages::v11::to1::ProveToRV::new(token);
    let rv_redirect: RequestResult<messages::v11::to1::RVRedirect> =
        client.send_request(prove_to_rv, None).await;

    let rv_redirect = rv_redirect
        .context("Error proving self to renvezvous server")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InvalidMessageError,
                "Error proving self to rendezvous server",
                MessageType::TO1RVRedirect,
                e,
            ))
        })?;
    // Done!
    Ok(rv_redirect.into_to1d())
}

async fn perform_to1(
    devcred: &dyn DeviceCredential,
    client: &mut ServiceClient,
) -> Result<COSESign> {
    log::trace!(
        "Starting TO1 with credential {:?} and client {:?}",
        devcred,
        client
    );

    // Send: HelloRV, Receive: HelloRVAck
    let token = match perform_hellorv(devcred, client).await {
        Ok(token) => token,
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(client, e.borrow()).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(client, e.borrow()).await;
                bail!(e.error);
            }
        },
    };

    // Send: ProveToRV, Receive: RVRedirect
    match perform_provetorv(token, client).await {
        Ok(to1d) => Ok(to1d),
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(client, e.borrow()).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(client, e.borrow()).await;
                bail!(e.error);
            }
        },
    }
}

fn get_rv_info(devcred: &dyn DeviceCredential) -> Result<Vec<RendezvousInterpretedDirective>> {
    // Determine RV info
    let rv_info = devcred
        .rendezvous_info()
        .to_interpreted(RendezvousInterpreterSide::Device)
        .context("Error parsing rendezvous directives")?;
    if rv_info.is_empty() {
        bail!("No rendezvous information found that's usable for the device");
    }
    log::trace!("Rendezvous info: {:?}", rv_info);
    Ok(rv_info)
}

async fn get_to1d(
    devcred: &dyn DeviceCredential,
    mut client_list: Vec<ServiceClient>,
) -> Result<COSESign> {
    for client in client_list.as_mut_slice() {
        match perform_to1(devcred, client)
            .await
            .context("Error performing TO1")
        {
            Ok(to1) => {
                return Ok(to1);
            }
            Err(e) => {
                log::error!("{} with {:?}", e, client);
                continue;
            }
        }
    }
    bail!("Couldn't get TO1 from any Rendezvous server!")
}

async fn get_ov_entries(
    client: &mut ServiceClient,
    num_entries: u16,
) -> Result<ParsedArray<fdo_data_formats::cborparser::ParsedArraySizeDynamic>> {
    let mut entries = ParsedArray::new_empty();

    for entry_num in 0..num_entries {
        let entry_result: RequestResult<messages::v11::to2::OVNextEntry> = client
            .send_request(
                messages::v11::to2::GetOVNextEntry::new(entry_num as u8),
                None,
            )
            .await;
        let entry_result =
            entry_result.with_context(|| format!("Error getting OV entry num {}", entry_num))?;

        if entry_result.entry_num() != entry_num {
            bail!(
                "Owner onboarding service returned OV entry {}, when we asked for {}",
                entry_result.entry_num(),
                entry_num
            );
        }

        let entry = entry_result.into_entry();
        entries
            .push(&entry)
            .context("Error adding Ownership Voucher entry")?;
    }

    Ok(entries)
}

async fn get_nonce(message_type: MessageType) -> Result<Nonce, ClientError> {
    Nonce::new().context("Error generating nonce").map_err(|e| {
        ClientError::Response(ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error generating nonce",
            message_type,
            e,
        ))
    })
}

/// TO2: Sends HelloDevice, Receives ProveOVHdr
async fn perform_hellodevice(
    devcred: &dyn DeviceCredential,
    client: &mut ServiceClient,
    nonce5: Nonce,
    sigtype: DeviceSigType,
    kexsuite: KexSuite,
    ciphersuite: CipherSuite,
) -> Result<(COSESign, UnverifiedValue<TO2ProveOVHdrPayload>, HMac), ClientError> {
    let prove_ov_hdr: RequestResult<messages::v11::to2::ProveOVHdr> = client
        .send_request(
            messages::v11::to2::HelloDevice::new(
                devcred.device_guid().clone(),
                nonce5.clone(),
                kexsuite,
                ciphersuite,
                SigInfo::new(sigtype, vec![]),
            ),
            None,
        )
        .await;
    let prove_ov_hdr = prove_ov_hdr
        .context("Error sending HelloDevice")
        .map_err(|e| {
            ClientError::Request(ErrorResult::new(
                ErrorCode::InternalServerError,
                "Error sending HelloDevice",
                MessageType::TO2ProveOVHdr,
                e,
            ))
        })?;
    let prove_ov_hdr = prove_ov_hdr.into_token();

    // NOTE: At this moment, we have not yet validated the signature on it...
    // We can only do so after we got all of the OV parts..
    let prove_ov_hdr_payload: UnverifiedValue<TO2ProveOVHdrPayload> = prove_ov_hdr
        .get_payload_unverified()
        .context("Error parsing unverified paylod")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::MessageBodyError,
                "Error parsing unverified payload",
                MessageType::TO2ProveOVHdr,
                e,
            ))
        })?;

    log::trace!("Got an prove OV hdr payload: {:?}", prove_ov_hdr_payload);

    // Verify the nonce5 value
    if &nonce5 != prove_ov_hdr_payload.get_unverified_value().nonce5() {
        return Err(ClientError::Response(ErrorResult::new(
            ErrorCode::InvalidMessageError,
            "Nonce5 value is mismatched",
            MessageType::TO2ProveOVHdr,
            anyhow!("Nonce5 value is mismatched"),
        )));
    }

    // Check the bSigInfo is what we expect it to be
    {
        let b_signature_info = prove_ov_hdr_payload
            .get_unverified_value()
            .b_signature_info();
        if b_signature_info.sig_type() != sigtype {
            return Err(ClientError::Response(ErrorResult::new(
                ErrorCode::InvalidMessageError,
                "Invalid signature type returned",
                MessageType::TO2ProveOVHdr,
                anyhow!("Invalid signature type returned"),
            )));
        }
        if !b_signature_info.info().is_empty() {
            return Err(ClientError::Response(ErrorResult::new(
                ErrorCode::InvalidMessageError,
                "Non-empty signature info returned",
                MessageType::TO2ProveOVHdr,
                anyhow!("Non-empty signature info returned"),
            )));
        }
    }

    // Verify the HMAC, we do this in an extra scope to not leak anything untrusted out
    let header_hmac = {
        let ov_hdr_vec = prove_ov_hdr_payload.get_unverified_value().ov_header();
        let ov_hdr_hmac = prove_ov_hdr_payload.get_unverified_value().hmac();

        devcred
            .verify_hmac(ov_hdr_vec, ov_hdr_hmac)
            .context("Error verifying ownership voucher HMAC")
            .map_err(|e| {
                ClientError::Response(ErrorResult::new(
                    ErrorCode::InvalidMessageError,
                    "Error, invalid message",
                    MessageType::TO2ProveOVHdr,
                    e,
                ))
            })?;
        log::trace!("Ownership Voucher HMAC validated");
        ov_hdr_hmac.clone()
    };

    // Validate the PubKeyHash
    {
        let header = prove_ov_hdr_payload.get_unverified_value().ov_header();
        let header = match OwnershipVoucherHeader::deserialize_data(header) {
            Ok(header) => header,
            Err(e) => {
                return Err(ClientError::Response(ErrorResult::new(
                    ErrorCode::MessageBodyError,
                    "Error deserializing OV Header",
                    MessageType::TO2ProveOVHdr,
                    anyhow!(e),
                )));
            }
        };
        let pubkey_hash = header
            .manufacturer_public_key_hash(devcred.manufacturer_pubkey_hash().get_type())
            .context("Error computing manufacturer public key hash")
            .map_err(|e| {
                ClientError::Response(ErrorResult::new(
                    ErrorCode::InvalidMessageError,
                    "Error computing manufacturer public key hash",
                    MessageType::TO2ProveOVHdr,
                    e,
                ))
            })?;
        devcred
            .manufacturer_pubkey_hash()
            .compare(&pubkey_hash)
            .context("Error comparing manufacturer public key hash")
            .map_err(|e| {
                ClientError::Response(ErrorResult::new(
                    ErrorCode::InvalidMessageError,
                    "Error comparing manufacturer public key hash",
                    MessageType::TO2ProveOVHdr,
                    e,
                ))
            })?;
    }
    Ok((prove_ov_hdr, prove_ov_hdr_payload, header_hmac))
}

async fn get_nonce6(prove_ov_hdr: &COSESign) -> Result<Nonce, ClientError> {
    // Get nonce6
    let nonce6: Nonce = {
        prove_ov_hdr
            .get_unprotected_value(HeaderKeys::CUPHNonce)
            .context("Error getting nonce6")
            .map_err(|e| {
                ClientError::Response(ErrorResult::new(
                    ErrorCode::MessageBodyError,
                    "Error getting nonce6",
                    MessageType::TO2ProveOVHdr,
                    e,
                ))
            })?
            .ok_or_else(|| {
                ClientError::Response(ErrorResult::new(
                    ErrorCode::MessageBodyError,
                    "Missing nonce6",
                    MessageType::TO2ProveOVHdr,
                    anyhow!("Missing nonce6"),
                ))
            })?
    };
    Ok(nonce6)
}

async fn get_and_verify_ov_header_signature(
    client: &mut ServiceClient,
    prove_ov_hdr: &COSESign,
    prove_ov_hdr_payload: &UnverifiedValue<TO2ProveOVHdrPayload>,
    header_hmac: HMac,
    to1d: &COSESign,
) -> Result<TO2ProveOVHdrPayload, ClientError> {
    // Get the other OV entries
    let ov_entries = get_ov_entries(
        client,
        prove_ov_hdr_payload.get_unverified_value().num_ov_entries(),
    )
    .await
    .context("Error getting remaining OV entries")
    .map_err(|e| {
        ClientError::Response(ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error getting remaining OV entries",
            MessageType::TO2OVNextEntry,
            e,
        ))
    })?;

    // At this moment, we have validated all we can, we'll check the signature later (After we get the final bits of the OV)
    let ownership_voucher = {
        let header = prove_ov_hdr_payload.get_unverified_value().ov_header();
        OwnershipVoucher::from_parts(ProtocolVersion::Version1_1, header, header_hmac, ov_entries)
    }
    .context("Error reconstructing Ownership Voucher")
    .map_err(|e| {
        ClientError::Response(ErrorResult::new(
            ErrorCode::MessageBodyError,
            "Error reconstructing Ownership Voucher",
            MessageType::TO2OVNextEntry,
            e,
        ))
    })?;
    log::trace!(
        "Reconstructed full ownership voucher: {:?}",
        ownership_voucher
    );

    // Get the last entry of the ownership voucher, this automatically validates everything (yay abstraction!)
    let ov_owner_entry = ownership_voucher
        .iter_entries()
        .context("Error initializing iterator")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InternalServerError,
                "Error initializing iterator",
                MessageType::TO2OVNextEntry,
                e,
            ))
        })?
        .last()
        .context("Error validating ownership voucher")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InvalidMessageError,
                "Error validating ownership voucher",
                MessageType::TO2OVNextEntry,
                e,
            ))
        })?
        .context("Last entry on ownership voucher was wrong")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InvalidMessageError,
                "Last entry on ownership voucher was wrong",
                MessageType::TO2OVNextEntry,
                e,
            ))
        })?;
    log::trace!("Got owner entry: {:?}", ov_owner_entry);

    // Now, we can finally verify the OV Header signature we got at the top!
    let prove_ov_hdr_payload: TO2ProveOVHdrPayload = prove_ov_hdr
        .get_payload(ov_owner_entry.public_key().pkey())
        .context("Error validating ProveOVHdr signature")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InvalidMessageError,
                "Error validating ProveOVHdr signature",
                MessageType::TO2OVNextEntry,
                e,
            ))
        })?;
    log::trace!(
        "ProveOVHdr validated with public key: {:?}",
        ov_owner_entry.public_key()
    );

    // Verify that to1d was signed by the current owner
    to1d.verify(ov_owner_entry.public_key().pkey())
        .context("Error validating to1d after receiving full ownership voucher")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InvalidMessageError,
                "Error validating to1d after receiving full ownership voucher",
                MessageType::TO2OVNextEntry,
                e,
            ))
        })?;
    Ok(prove_ov_hdr_payload)
}

async fn perform_key_derivation(
    client: &mut ServiceClient,
    prove_ov_hdr_payload: TO2ProveOVHdrPayload,
    kexsuite: KexSuite,
    ciphersuite: CipherSuite,
) -> Result<(KeyExchange, fdo_http_wrapper::EncryptionKeys), ClientError> {
    let non_interoperable_kdf_required =
        client.non_interoperable_kdf_required().ok_or_else(|| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InternalServerError,
                "Error getting non-interoperable KDF requirement",
                MessageType::TO2OVNextEntry,
                anyhow!("Error getting non-interoperable KDF requirement"),
            ))
        })?;

    // Perform the key derivation
    let a_key_exchange = prove_ov_hdr_payload.a_key_exchange();
    let b_key_exchange = KeyExchange::new(kexsuite)
        .context("Error creating device side of key exchange")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InternalServerError,
                "Error creating device side of key exchange",
                MessageType::TO2OVNextEntry,
                e,
            ))
        })?;

    let new_keys = b_key_exchange
        .derive_key(
            KeyDeriveSide::Device,
            ciphersuite,
            a_key_exchange,
            non_interoperable_kdf_required,
        )
        .context("Error performing key derivation")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InternalServerError,
                "Error performing key derivation",
                MessageType::TO2OVNextEntry,
                e,
            ))
        })?;
    let new_keys = fdo_http_wrapper::EncryptionKeys::from_derived(ciphersuite, new_keys);

    Ok((b_key_exchange, new_keys))
}

/// TO2: Sends ProveDevice, Receives SetupDevice
async fn perform_provedevice(
    devcred: &dyn DeviceCredential,
    client: &mut ServiceClient,
    b_key_exchange: KeyExchange,
    nonce6: &Nonce,
    nonce7: &Nonce,
    new_keys: fdo_http_wrapper::EncryptionKeys,
) -> Result<(), ClientError> {
    let prove_device_payload = TO2ProveDevicePayload::new(
        b_key_exchange
            .get_public()
            .context("Error building our public")
            .map_err(|e| {
                ClientError::Response(ErrorResult::new(
                    ErrorCode::InternalServerError,
                    "Error building prove device payload",
                    MessageType::TO2OVNextEntry,
                    e,
                ))
            })?,
    );
    let prove_device_eat = new_eat(
        Some(&prove_device_payload),
        nonce6.clone(),
        devcred.device_guid().clone(),
    )
    .context("Error building provedevice EAT")
    .map_err(|e| {
        ClientError::Response(ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error building provedevice EAT",
            MessageType::TO2OVNextEntry,
            e,
        ))
    })?;
    let mut prove_device_eat_unprotected = COSEHeaderMap::new();
    prove_device_eat_unprotected
        .insert(HeaderKeys::EUPHNonce, &nonce7)
        .context("Error adding nonce7 to unprotected")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::MessageBodyError,
                "Error adding nonce7 to unprotected",
                MessageType::TO2OVNextEntry,
                e,
            ))
        })?;
    let signer = devcred
        .get_signer()
        .context("Error getting Cose signer")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InternalServerError,
                "Error getting Cose signer",
                MessageType::TO2OVNextEntry,
                e,
            ))
        })?;
    let prove_device_token = COSESign::from_eat(
        prove_device_eat,
        Some(prove_device_eat_unprotected),
        signer.as_ref(),
    )
    .context("Error signing ProveDevice EAT")
    .map_err(|e| {
        ClientError::Response(ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error signing ProveDevice EAT",
            MessageType::TO2OVNextEntry,
            e,
        ))
    })?;

    log::trace!("Prepared prove_device_token: {:?}", prove_device_token);
    let prove_device_msg = messages::v11::to2::ProveDevice::new(prove_device_token);
    let setup_device: RequestResult<messages::v11::to2::SetupDevice> =
        client.send_request(prove_device_msg, Some(new_keys)).await;
    let setup_device = setup_device.context("Error proving device").map_err(|e| {
        ClientError::Response(ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error proving device",
            MessageType::TO2SetupDevice,
            e,
        ))
    })?;
    log::trace!("Got setup_device response: {:?}", setup_device);

    Ok(())
}

/// TO2: Sends DeviceServiceInfoReady, Receives OwnerService
async fn perform_deviceserviceinfoready(client: &mut ServiceClient) -> Result<(), ClientError> {
    let owner_service_info_ready: RequestResult<messages::v11::to2::OwnerServiceInfoReady> = client
        .send_request(
            messages::v11::to2::DeviceServiceInfoReady::new(None, None),
            None,
        )
        .await;
    let owner_service_info_ready = owner_service_info_ready
        .context("Error getting OwnerServiceInfoReady")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InternalServerError,
                "Error getting OwnerServiceInfoReady",
                MessageType::TO2OwnerServiceInfoReady,
                e,
            ))
        })?;
    log::trace!(
        "Received OwnerServiceInfoReady: {:?}",
        owner_service_info_ready
    );
    Ok(())
}

/// TO2: Sends Done, Receives Done2
async fn perform_done(
    nonce7: Nonce,
    nonce6: Nonce,
    client: &mut ServiceClient,
) -> Result<(), ClientError> {
    let done2: RequestResult<messages::v11::to2::Done2> = client
        .send_request(messages::v11::to2::Done::new(nonce6), None)
        .await;
    let done2 = done2.context("Error sending Done2").map_err(|e| {
        ClientError::Response(ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error sending Done2",
            MessageType::TO2Done2,
            e,
        ))
    })?;
    if &nonce7 != done2.nonce7() {
        return Err(ClientError::Response(ErrorResult::new(
            ErrorCode::InvalidMessageError,
            "Nonce7 did not match in Done2",
            MessageType::TO2Done2,
            anyhow!("Nonce7 did not match in Done2"),
        )));
    }
    Ok(())
}

async fn perform_to2(
    devcredloc: &dyn UsableDeviceCredentialLocation,
    devcred: &dyn DeviceCredential,
    url: &str,
    to1d: &COSESign,
) -> Result<()> {
    log::info!("Performing TO2 protocol, URL: {:?}", url);

    let mut client = fdo_http_wrapper::client::ServiceClient::new(ProtocolVersion::Version1_1, url);

    let nonce5 = match get_nonce(MessageType::TO1RVRedirect).await {
        Ok(nonce5) => nonce5,
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
        },
    };

    let sigtype = DeviceSigType::StSECP384R1;
    let kexsuite = KexSuite::Ecdh384;
    let ciphersuite = CipherSuite::A256Gcm;

    // Send: HelloDevice, Receive: ProveOVHdr
    let (prove_ov_hdr, prove_ov_hdr_payload, header_hmac) =
        match perform_hellodevice(devcred, &mut client, nonce5, sigtype, kexsuite, ciphersuite)
            .await
        {
            Ok(values) => values,
            Err(e) => match e {
                ClientError::Request(e) => {
                    send_client_error(&mut client, e.borrow()).await;
                    bail!(e.error);
                }
                ClientError::Response(e) => {
                    send_client_error(&mut client, e.borrow()).await;
                    bail!(e.error);
                }
            },
        };
    // Get nonce6
    let nonce6 = match get_nonce6(&prove_ov_hdr).await {
        Ok(nonce6) => nonce6,
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
        },
    };
    // Get OV and verify its signature
    let prove_ov_hdr_payload = match get_and_verify_ov_header_signature(
        &mut client,
        &prove_ov_hdr,
        &prove_ov_hdr_payload,
        header_hmac,
        to1d,
    )
    .await
    {
        Ok(payload) => payload,
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
        },
    };

    // Key derivation
    let (b_key_exchange, new_keys) = match perform_key_derivation(
        &mut client,
        prove_ov_hdr_payload,
        kexsuite,
        ciphersuite,
    )
    .await
    {
        Ok(values) => values,
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
        },
    };

    // Get nonce7
    let nonce7 = match get_nonce(MessageType::TO2OVNextEntry).await {
        Ok(nonce7) => nonce7,
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
        },
    };

    // Send: ProveDevice, Receive: SetupDevice
    match perform_provedevice(
        devcred,
        &mut client,
        b_key_exchange,
        &nonce6,
        &nonce7,
        new_keys,
    )
    .await
    {
        Ok(_) => (),
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
        },
    };

    // Send: DeviceServiceInfoReady, Receive: OwnerServiceInfoReady
    match perform_deviceserviceinfoready(&mut client).await {
        Ok(_) => (),
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
        },
    };

    // Now, the magic: performing the roundtrip! We delegated that.
    if let Err(serviceinfo_err) = serviceinfo::perform_to2_serviceinfos(&mut client).await {
        log::error!("ServiceInfo failed, error: {:?}", serviceinfo_err);
        let e_result = ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error performing the ServiceInfo roundtrips",
            MessageType::TO2OwnerServiceInfo,
            anyhow!("Error performing the ServiceInfo roundtrips"),
        );
        send_client_error(&mut client, &e_result).await;
        bail!(e_result.error);
    }

    if mark_device_onboarding_executed().is_err() {
        let e_result = ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error creating the device onboarding executed marker file",
            MessageType::TO2OwnerServiceInfo,
            anyhow!("Error creating the device onboarding executed marker file"),
        );
        send_client_error(&mut client, &e_result).await;
        bail!(e_result.error);
    }

    if devcredloc.deactivate().is_err() {
        let e_result = ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error deactivating device credential",
            MessageType::TO2OwnerServiceInfo,
            anyhow!("Error deactivating device credential"),
        );
        send_client_error(&mut client, &e_result).await;
        bail!(e_result.error);
    }

    // Send: Done, Receive: Done2
    match perform_done(nonce7, nonce6, &mut client).await {
        Ok(ok) => Ok(ok),
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(&mut client, e.borrow()).await;
                bail!(e.error);
            }
        },
    }
}

fn get_delay_between_retries(rv_entry_delay: u32) -> u64 {
    let mut rng = rand::thread_rng();
    let rv_delay_sec: f32 = if rv_entry_delay == 0 {
        rng.gen_range(
            RV_DEFAULT_DELAY_SEC - RV_DEFAULT_DELAY_OFFSET
                ..=RV_DEFAULT_DELAY_SEC + RV_DEFAULT_DELAY_OFFSET,
        )
    } else {
        let lower_delay = rv_entry_delay as f32 * (1.0 - RV_USER_DEFINED_DELAY_OFFSET);
        let upper_delay = rv_entry_delay as f32 * (1.0 + RV_USER_DEFINED_DELAY_OFFSET);
        rng.gen_range(lower_delay..=upper_delay)
    };
    rv_delay_sec as u64
}

fn sleep_between_retries(rv_entry_delay: u32) {
    let rv_delay_sec = get_delay_between_retries(rv_entry_delay);
    let sleep_time = time::Duration::from_secs(rv_delay_sec);
    log::trace!("Sleeping for {} seconds", rv_delay_sec);
    thread::sleep(sleep_time);
}

#[tokio::main]
async fn main() -> Result<()> {
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

    if !fdo_data_formats::interoperable_kdf_available()
        && std::env::var("ALLOW_NONINTEROPERABLE_KDF").is_err()
    {
        bail!("Provide environment ALLOW_NONINTEROPERABLE_KDF=1 to enable interoperable KDF");
    }

    let marker_file = marker_file_location();
    if marker_file.exists() {
        log::info!(
            "Device Onboarding marker file {:?} exists, not rerunning FDO onboarding",
            marker_file
        );
        reencrypt::perform_required_reencrypts()
            .context("Error performing required re-encrypts")?;
        return Ok(());
    }

    let devcred_location = match device_credential_locations::find() {
        None => {
            log::info!("No usable device credential located, skipping Device Onboarding");
            return Ok(());
        }
        Some(Err(e)) => {
            log::error!("Error opening device credential: {:?}", e);
            return Err(e).context("Error getting device credential at any of the known locations");
        }
        Some(Ok(dc)) => dc,
    };

    log::info!("Found device credential at {:?}", devcred_location);

    let dc = devcred_location
        .read()
        .context("Error reading device credential")?;
    log::trace!("Device credential: {:?}", dc);

    if !dc.is_active() {
        log::info!("Device credential deactivated, skipping Device Onboarding");
        return Ok(());
    }
    if dc.protocol_version() != ProtocolVersion::Version1_1 {
        bail!(
            "Device credential protocol version {} not supported",
            dc.protocol_version()
        );
    }

    // Get rv entries
    let rv_info = get_rv_info(dc.as_ref())?;

    let mut onboarding_performed = false;
    let mut rv_entry_delay = 0;

    loop {
        for rv_entry in rv_info.iter() {
            rv_entry_delay = rv_entry.delay;

            let client_list = match get_client_list(rv_entry).await {
                Ok(client_list) => client_list,
                Err(e) => {
                    log::error!(
                        "Error {:?} getting usable rendezvous client list from rv_entry {:?}",
                        e,
                        rv_entry
                    );
                    continue;
                }
            };

            // Get owner info
            let to1d = get_to1d(dc.as_ref(), client_list).await;
            let to1d = match to1d {
                Ok(to1d) => to1d,
                Err(e) => {
                    log::error!(
                        "Error {:?} getting usable To1d from rv_entry {:?}",
                        e,
                        rv_entry
                    );
                    continue;
                }
            };

            let to1d_payload: UnverifiedValue<TO1DataPayload> = match to1d.get_payload_unverified()
            {
                Ok(to1d_payload) => to1d_payload,
                Err(e) => {
                    log::trace!(
                        "Error getting TO1 payload unverified {:?} with rv_entry {:?}",
                        e,
                        rv_entry
                    );
                    continue;
                }
            };

            // Contact owner and perform ownership transfer
            let to2_addresses = to1d_payload.get_unverified_value().to2_addresses();
            let to2_addresses = get_to2_urls(to2_addresses);
            log::info!("Got TO2 addresses: {:?}", to2_addresses);

            if to2_addresses.is_empty() {
                log::trace!(
                    "No valid TO2 addresses received with rv_entry {:?}",
                    rv_entry
                );
                continue;
            }

            for to2_address in to2_addresses {
                match perform_to2(devcred_location.borrow(), dc.as_ref(), &to2_address, &to1d)
                    .await
                    .context("Error performing TO2 ownership protocol")
                {
                    Ok(_) => {
                        onboarding_performed = true;
                        break;
                    }
                    Err(e) => {
                        log::error!("{:?} with TO2 address {}", e, to2_address);
                        continue;
                    }
                }
            }
            if onboarding_performed {
                break;
            }
        }
        if onboarding_performed {
            break;
        } else {
            sleep_between_retries(rv_entry_delay);
        }
    }
    log::info!("Secure Device Onboarding DONE");
    Ok(())
}
