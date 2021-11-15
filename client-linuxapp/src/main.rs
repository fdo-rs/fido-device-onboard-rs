use std::{borrow::Borrow, env, fs, path::PathBuf, thread, time};

use anyhow::{anyhow, bail, Context, Result};

use fdo_data_formats::{
    cborparser::ParsedArray,
    constants::{DeviceSigType, HeaderKeys, TransportProtocol},
    enhanced_types::{RendezvousInterpretedDirective, RendezvousInterpreterSide},
    messages,
    ownershipvoucher::OwnershipVoucher,
    types::{
        new_eat, COSEHeaderMap, COSESign, CipherSuite, EATokenPayload, KexSuite, KeyDeriveSide,
        KeyExchange, Nonce, PayloadCreating, SigInfo, TO1DataPayload, TO2AddressEntry,
        TO2ProveDevicePayload, TO2ProveOVHdrPayload, UnverifiedValue,
    },
    DeviceCredential, Serializable,
};
use fdo_http_wrapper::client::{RequestResult, ServiceClient};

mod serviceinfo;

use fdo_util::device_credential_locations;
use fdo_util::device_credential_locations::UsableDeviceCredentialLocation;
use rand::Rng;

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

fn mark_device_onboarding_executed() -> Result<()> {
    fs::write(&marker_file_location(), "executed").context("Error creating executed marker file")
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
        todo!();
    }
    if rv_entry.wifi_ssid.is_some() {
        todo!();
    }
    if rv_entry.user_input {
        todo!();
    }
    for url in &urls {
        service_client_list.push(fdo_http_wrapper::client::ServiceClient::new(url));
    }
    log::trace!("Client list: {:?}", service_client_list);
    Ok(service_client_list)
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

    let sig_type = DeviceSigType::StSECP384R1;

    // Send: HelloRV, Receive: HelloRVAck
    let hello_rv = messages::to1::HelloRV::new(
        devcred.device_guid().clone(),
        SigInfo::new(sig_type, vec![]),
    );
    let hello_rv_ack: RequestResult<messages::to1::HelloRVAck> =
        client.send_request(hello_rv, None).await;
    let hello_rv_ack = hello_rv_ack.context("Error sending HelloRV")?;
    log::trace!("Hello RV ack: {:?}", hello_rv_ack);

    // Check ack
    let b_sig_info = hello_rv_ack.b_signature_info();
    if b_sig_info.sig_type() != sig_type {
        bail!("Unsupported sig type returned");
    }
    if !b_sig_info.info().is_empty() {
        bail!("Non-empty sig info returned");
    }
    let nonce4 = hello_rv_ack.nonce4();

    // Create EAT payload
    let eat: EATokenPayload<PayloadCreating> =
        new_eat::<bool>(None, nonce4.clone(), devcred.device_guid().clone())
            .context("Error creating EATokenPayload")?;

    // Create signature over nonce4
    let signer = devcred.get_signer().context("Error getting Cose signer")?;
    let token =
        COSESign::from_eat(eat, None, signer.as_ref()).context("Error signing new token")?;
    log::trace!("Sending token: {:?}", token);

    // Send: ProveToRV, Receive: RVRedirect
    let prove_to_rv = messages::to1::ProveToRV::new(token);
    let rv_redirect: RequestResult<messages::to1::RVRedirect> =
        client.send_request(prove_to_rv, None).await;
    let rv_redirect = rv_redirect.context("Error proving self to rendezvous server")?;

    // Done!
    Ok(rv_redirect.into_to1d())
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
                log::trace!("{} with {:?}", e, client);
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
        let entry_result: RequestResult<messages::to2::OVNextEntry> = client
            .send_request(messages::to2::GetOVNextEntry::new(entry_num as u8), None)
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

async fn perform_to2(
    devcredloc: &dyn UsableDeviceCredentialLocation,
    devcred: &dyn DeviceCredential,
    url: &str,
    to1d: &COSESign,
) -> Result<()> {
    log::info!("Performing TO2 protocol, URL: {:?}", url);

    let nonce5 = Nonce::new().context("Error generating nonce5")?;
    let sigtype = DeviceSigType::StSECP384R1;
    let kexsuite = KexSuite::Ecdh384;
    let ciphersuite = CipherSuite::A256Gcm;

    let mut client = fdo_http_wrapper::client::ServiceClient::new(url);

    // Send: HelloDevice, Receive: ProveOVHdr
    let prove_ov_hdr: RequestResult<messages::to2::ProveOVHdr> = client
        .send_request(
            messages::to2::HelloDevice::new(
                devcred.device_guid().clone(),
                nonce5.clone(),
                kexsuite,
                ciphersuite,
                SigInfo::new(sigtype, vec![]),
            ),
            None,
        )
        .await;
    let prove_ov_hdr = prove_ov_hdr.context("Error sending HelloDevice")?;
    let prove_ov_hdr = prove_ov_hdr.into_token();

    // NOTE: At this moment, we have not yet validated the signature on it...
    // We can only do so after we got all of the OV parts..
    let prove_ov_hdr_payload: UnverifiedValue<TO2ProveOVHdrPayload> = prove_ov_hdr
        .get_payload_unverified()
        .context("Error parsing unverified payload")?;

    log::trace!("Got an prove OV hdr payload: {:?}", prove_ov_hdr_payload);

    // Verify the nonce5 value
    if &nonce5 != prove_ov_hdr_payload.get_unverified_value().nonce5() {
        bail!("Nonce5 value is mismatched");
    }

    // Check the bSigInfo is what we expect it to be
    {
        let b_signature_info = prove_ov_hdr_payload
            .get_unverified_value()
            .b_signature_info();
        if b_signature_info.sig_type() != sigtype {
            bail!("Invalid signature type returned");
        }
        if !b_signature_info.info().is_empty() {
            bail!("Non-empty signature info returned");
        }
    }

    // Verify the HMAC, we do this in an extra scope to not leak anything untrusted out
    let header_hmac = {
        let ov_hdr_vec = prove_ov_hdr_payload
            .get_unverified_value()
            .ov_header()
            .serialize_data()
            .context("Error serializing Ownership Voucher header")?;
        let ov_hdr_hmac = prove_ov_hdr_payload.get_unverified_value().hmac();
        devcred
            .verify_hmac(&ov_hdr_vec, ov_hdr_hmac)
            .context("Error verifying ownership voucher HMAC")?;
        log::trace!("Ownership Voucher HMAC validated");

        ov_hdr_hmac.clone()
    };

    // Validate the PubKeyHash
    {
        let header = prove_ov_hdr_payload.get_unverified_value().ov_header();
        let pubkey_hash = header
            .manufacturer_public_key_hash(devcred.manufacturer_pubkey_hash().get_type())
            .context("Error computing manufacturer public key hash")?;
        devcred
            .manufacturer_pubkey_hash()
            .compare(&pubkey_hash)
            .context("Error comparing manufacturer public key hash")?;
    }

    // Get nonce6
    let nonce6: Nonce = {
        prove_ov_hdr
            .get_unprotected_value(HeaderKeys::CUPHNonce)
            .context("Error getting nonce6")?
            .ok_or_else(|| anyhow!("Missing nonce6"))
    }?;

    // Get the other OV entries
    let ov_entries = get_ov_entries(
        &mut client,
        prove_ov_hdr_payload.get_unverified_value().num_ov_entries(),
    )
    .await
    .context("Error getting remaining OV entries")?;

    // At this moment, we have validated all we can, we'll check the signature later (After we get the final bits of the OV)
    let ownership_voucher = {
        let header = prove_ov_hdr_payload
            .get_unverified_value()
            .ov_header()
            .clone();
        OwnershipVoucher::from_parts(header, header_hmac, ov_entries)
    }
    .context("Error reconstructing Ownership Voucher")?;
    log::trace!(
        "Reconstructed full ownership voucher: {:?}",
        ownership_voucher
    );

    // Get the last entry of the ownership voucher, this automatically validates everything (yay abstraction!)
    let ov_owner_entry = ownership_voucher
        .iter_entries()
        .context("Error initializing iterator")?
        .last()
        .context("Error validating ownership voucher")?
        .context("Last entry on ownership voucher was wrong")?;
    log::trace!("Got owner entry: {:?}", ov_owner_entry);

    // Now, we can finally verify the OV Header signature we got at the top!
    let prove_ov_hdr_payload: TO2ProveOVHdrPayload = prove_ov_hdr
        .get_payload(ov_owner_entry.public_key().pkey())
        .context("Error validating ProveOVHdr signature")?;
    log::trace!(
        "ProveOVHdr validated with public key: {:?}",
        ov_owner_entry.public_key()
    );

    // Verify that to1d was signed by the current owner
    to1d.verify(ov_owner_entry.public_key().pkey())
        .context("Error validating to1d after receiving full ownership voucher")?;

    // Perform the key derivation
    let a_key_exchange = prove_ov_hdr_payload.a_key_exchange();
    let b_key_exchange =
        KeyExchange::new(kexsuite).context("Error creating device side of key exchange")?;
    let new_keys = b_key_exchange
        .derive_key(KeyDeriveSide::Device, ciphersuite, a_key_exchange)
        .context("Error performing key derivation")?;
    let new_keys = fdo_http_wrapper::EncryptionKeys::from_derived(ciphersuite, new_keys);

    let nonce7 = Nonce::new().context("Error generating nonce7")?;

    // Send: ProveDevice, Receive: SetupDevice
    let prove_device_payload = TO2ProveDevicePayload::new(
        b_key_exchange
            .get_public()
            .context("Error building our public")?,
    );
    let prove_device_eat = new_eat(
        Some(&prove_device_payload),
        nonce6.clone(),
        devcred.device_guid().clone(),
    )
    .context("Error building provedevice EAT")?;
    let mut prove_device_eat_unprotected = COSEHeaderMap::new();
    prove_device_eat_unprotected
        .insert(HeaderKeys::EUPHNonce, &nonce7)
        .context("Error adding nonce7 to unprotected")?;
    let signer = devcred.get_signer().context("Error getting Cose signer")?;
    let prove_device_token = COSESign::from_eat(
        prove_device_eat,
        Some(prove_device_eat_unprotected),
        signer.as_ref(),
    )
    .context("Error signing ProveDevice EAT")?;

    log::trace!("Prepared prove_device_token: {:?}", prove_device_token);
    let prove_device_msg = messages::to2::ProveDevice::new(prove_device_token);
    let setup_device: RequestResult<messages::to2::SetupDevice> =
        client.send_request(prove_device_msg, Some(new_keys)).await;
    let setup_device = setup_device.context("Error proving device")?;
    log::trace!("Got setup_device response: {:?}", setup_device);

    // Send: DeviceServiceInfoReady, Receive: OwnerServiceInfoReady
    let owner_service_info_ready: RequestResult<messages::to2::OwnerServiceInfoReady> = client
        .send_request(messages::to2::DeviceServiceInfoReady::new(None, None), None)
        .await;
    let owner_service_info_ready =
        owner_service_info_ready.context("Error getting OwnerServiceInfoReady")?;
    log::trace!(
        "Received OwnerServiceInfoReady: {:?}",
        owner_service_info_ready
    );

    // Now, the magic: performing the roundtrip! We delegated that.
    serviceinfo::perform_to2_serviceinfos(&mut client)
        .await
        .context("Error performing the ServiceInfo roundtrips")?;

    mark_device_onboarding_executed()
        .context("Error creating the device onboarding executed marker file")?;

    devcredloc
        .deactivate()
        .context("Error deactivating device credential")?;

    // Send: Done, Receive: Done2
    let done2: RequestResult<messages::to2::Done2> = client
        .send_request(messages::to2::Done::new(nonce6), None)
        .await;
    let done2 = done2.context("Error sending Done2")?;

    if &nonce7 != done2.nonce7() {
        bail!("Nonce7 did not match in Done2");
    }

    Ok(())
}

fn get_delay_between_retries(rv_entry_delay: u32) -> u64 {
    let mut rng = rand::thread_rng();
    let rv_delay_sec: f32;
    if rv_entry_delay == 0 {
        rv_delay_sec = rng.gen_range(
            RV_DEFAULT_DELAY_SEC - RV_DEFAULT_DELAY_OFFSET
                ..=RV_DEFAULT_DELAY_SEC + RV_DEFAULT_DELAY_OFFSET,
        );
    } else {
        let lower_delay = rv_entry_delay as f32 * (1.0 - RV_USER_DEFINED_DELAY_OFFSET);
        let upper_delay = rv_entry_delay as f32 * (1.0 + RV_USER_DEFINED_DELAY_OFFSET);
        rv_delay_sec = rng.gen_range(lower_delay..=upper_delay);
    }
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
    fdo_http_wrapper::init_logging();

    let marker_file = marker_file_location();
    if marker_file.exists() {
        log::info!(
            "Device Onboarding marker file {:?} exists, not rerunning",
            marker_file
        );
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

    // Get rv entries
    let rv_info = get_rv_info(dc.as_ref())?;
    let rv_info_it = rv_info.iter();

    let mut onboarding_performed = false;
    let mut rv_entry_delay = 0;

    loop {
        for rv_entry in rv_info_it.clone() {
            rv_entry_delay = rv_entry.delay;

            let client_list = match get_client_list(rv_entry).await {
                Ok(client_list) => client_list,
                Err(e) => {
                    log::trace!(
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
                    log::trace!(
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
                        log::trace!("{:?} with TO2 address {}", e, to2_address);
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
