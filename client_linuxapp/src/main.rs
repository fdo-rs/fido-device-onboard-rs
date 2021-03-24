use std::env;
use std::fs;

use anyhow::{anyhow, bail, Context, Result};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

use fdo_data_formats::{
    constants::{DeviceSigType, HashType, HeaderKeys, TransportProtocol},
    enhanced_types::{RendezvousInterpretedDirective, RendezvousInterpreterSide},
    messages,
    ownershipvoucher::OwnershipVoucher,
    types::{
        new_eat, COSEHeaderMap, COSESign, CipherSuite, DeviceCredential, EATokenPayload, HMac,
        KexSuite, KeyExchange, Nonce, PayloadCreating, SigInfo, TO1DataPayload, TO2AddressEntry,
        TO2ProveDevicePayload, TO2ProveOVHdrPayload, UnverifiedValue,
    },
};
use fdo_http_wrapper::client::{RequestResult, ServiceClient};

fn get_to2_urls(entries: &[TO2AddressEntry]) -> Vec<String> {
    let mut urls = Vec::new();

    for addr_entry in entries {
        let prot_text = match addr_entry.protocol() {
            TransportProtocol::HTTP => "http",
            TransportProtocol::HTTPS => "https",
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

async fn get_client(rv_info: Vec<RendezvousInterpretedDirective>) -> Result<ServiceClient> {
    for rv_entry in rv_info {
        let urls = rv_entry.get_urls();
        if urls.is_empty() {
            continue;
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
        return Ok(fdo_http_wrapper::client::ServiceClient::new(
            &urls.first().unwrap(),
        ));
    }
    bail!("No rendezvous entries found we can construct a client for");
}

async fn perform_to1(devcred: &DeviceCredential, client: &mut ServiceClient) -> Result<COSESign> {
    log::trace!(
        "Starting TO1 with credential {:?} and client {:?}",
        devcred,
        client
    );

    let sig_type = DeviceSigType::StSECP384R1;

    // Send: HelloRV, Receive: HelloRVAck
    let hello_rv =
        messages::to1::HelloRV::new(devcred.guid.clone(), SigInfo::new(sig_type, vec![]));
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
        new_eat::<bool>(None, nonce4.clone(), devcred.guid.clone())
            .context("Error creating EATokenPayload")?;

    // Create signature over nonce4
    let privkey = PKey::private_key_from_der(&devcred.private_key)
        .context("Error loading private key from device credential")?;
    let token = COSESign::from_eat(eat, None, &privkey).context("Error signing new token")?;
    log::trace!("Sending token: {:?}", token);

    // Send: ProveToRV, Receive: RVRedirect
    let prove_to_rv = messages::to1::ProveToRV::new(token);
    let rv_redirect: RequestResult<messages::to1::RVRedirect> =
        client.send_request(prove_to_rv, None).await;
    let rv_redirect = rv_redirect.context("Error proving self to rendezvous server")?;

    // Done!
    Ok(rv_redirect.into_to1d())
}

async fn get_to1d_from_rv(devcred: &DeviceCredential) -> Result<COSESign> {
    // Determine RV info
    let rv_info = devcred
        .rvinfo
        .to_interpreted(RendezvousInterpreterSide::Device)
        .context("Error parsing rendezvous directives")?;
    if rv_info.is_empty() {
        bail!("No rendezvous information found that's usable for the device");
    }
    log::trace!("Rendezvous info: {:?}", rv_info);

    let mut client = get_client(rv_info)
        .await
        .context("Error getting usable rendezvous client")?;
    log::trace!("Got a usable client: {:?}", client);

    perform_to1(devcred, &mut client)
        .await
        .context("Error performing TO1")
}

async fn get_ov_entries(client: &mut ServiceClient, num_entries: u16) -> Result<Vec<Vec<u8>>> {
    let mut entries = Vec::new();

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

        entries.push(entry_result.entry().as_bytes().with_context(|| {
            format!("Error serializing entry {} of ownership voucher", entry_num)
        })?);
    }

    Ok(entries)
}

async fn perform_to2(devcred: &DeviceCredential, urls: &[String]) -> Result<()> {
    log::info!("Performing TO2 protocol, URLs: {:?}", urls);
    let url = urls.first().unwrap();

    let nonce5 = Nonce::new().context("Error generating nonce5")?;
    let sigtype = DeviceSigType::StSECP384R1;
    let kexsuite = KexSuite::ECDH384;
    let ciphersuite = CipherSuite::A256GCM;

    let mut client = fdo_http_wrapper::client::ServiceClient::new(&url);

    // Send: HelloDevice, Receive: ProveOVHdr
    let prove_ov_hdr: RequestResult<messages::to2::ProveOVHdr> = client
        .send_request(
            messages::to2::HelloDevice::new(
                devcred.guid.clone(),
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
        let ov_hdr_vec =
            serde_cbor::to_vec(&prove_ov_hdr_payload.get_unverified_value().ov_header())
                .context("Error parsing Ownership Voucher header")?;
        let hmac_key = PKey::hmac(&devcred.hmac_secret).context("Error building hmac key")?;
        let mut hmac_signer = Signer::new(MessageDigest::sha384(), &hmac_key)
            .context("Error creating hmac signer")?;
        hmac_signer
            .update(&ov_hdr_vec)
            .context("Error feeding OV into hmac")?;
        let ov_hmac = hmac_signer
            .sign_to_vec()
            .context("Error computing OV HMac")?;
        let ov_hmac = HMac::new_from_data(HashType::Sha384, ov_hmac);

        if &ov_hmac != prove_ov_hdr_payload.get_unverified_value().hmac() {
            bail!("HMac over ownership voucher was invalid");
        }
        log::trace!("Ownership Voucher HMAC validated");
        ov_hmac
    };

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
        let header = serde_cbor::to_vec(&prove_ov_hdr_payload.get_unverified_value().ov_header())
            .context("Error serializing the OV header")?;
        OwnershipVoucher::from_parts(header, header_hmac, ov_entries)
    };
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
    let owner_pubkey = ov_owner_entry
        .public_key
        .as_pkey()
        .context("Error parsing owner public key")?;
    let prove_ov_hdr_payload: TO2ProveOVHdrPayload = prove_ov_hdr
        .get_payload(&owner_pubkey)
        .context("Error validating ProveOVHdr signature")?;
    log::trace!("ProveOVHdr validated with public key: {:?}", owner_pubkey);

    // Perform the key derivation
    let a_key_exchange = prove_ov_hdr_payload.a_key_exchange();
    let b_key_exchange =
        KeyExchange::new(kexsuite).context("Error creating device side of key exchange")?;
    let new_keys = b_key_exchange
        .derive_key(kexsuite, ciphersuite, &a_key_exchange)
        .context("Error performing key derivation")?;
    let new_keys = fdo_http_wrapper::EncryptionKeys::from(new_keys);

    let nonce7 = Nonce::new().context("Error generating nonce7")?;

    // Send: ProveDevice, Receive: SetupDevice
    let prove_device_payload = TO2ProveDevicePayload::new(b_key_exchange.get_public());
    let prove_device_eat = new_eat(
        Some(&prove_device_payload),
        nonce6.clone(),
        devcred.guid.clone(),
    )
    .context("Error building provedevice EAT")?;
    let mut prove_device_eat_unprotected = COSEHeaderMap::new();
    prove_device_eat_unprotected
        .insert(HeaderKeys::CUPHNonce, &nonce7)
        .context("Error adding nonce7 to unprotected")?;
    let privkey = PKey::private_key_from_der(&devcred.private_key)
        .context("Error loading private key from device credential")?;
    let prove_device_token = COSESign::from_eat(
        prove_device_eat,
        Some(prove_device_eat_unprotected),
        &privkey,
    )
    .context("Error signing ProveDevice EAT")?;

    log::trace!("Prepared prove_device_token: {:?}", prove_device_token);
    let prove_device_msg = messages::to2::ProveDevice::new(prove_device_token);
    let setup_device: RequestResult<messages::to2::SetupDevice> =
        client.send_request(prove_device_msg, Some(new_keys)).await;
    let setup_device = setup_device.context("Error proving device")?;
    log::trace!("Got setup_device response: {:?}", setup_device);

    todo!();
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let devcred_path = env::var("DEVICE_CREDENTIAL")
        .context("Error getting device credential from DEVICE_CREDENTIAL environment variable")?;

    let dc: DeviceCredential = {
        let dc_file = fs::File::open(&devcred_path)
            .with_context(|| format!("Error opening device credential at {}", devcred_path))?;
        serde_cbor::from_reader(dc_file).context("Error loading device credential")?
    };
    log::trace!("Device credential: {:?}", dc);

    if !dc.active {
        log::info!("Device Onboarding not active");
        return Ok(());
    }

    // Get owner info
    let to1d = get_to1d_from_rv(&dc)
        .await
        .context("Error getting to1d from rendezvous server")?;
    log::trace!("Received a usable to1d structure:: {:?}", to1d);

    let to1d_payload: UnverifiedValue<TO1DataPayload> = to1d
        .get_payload_unverified()
        .context("Error getting the TO2 payload")?;
    let to2_addresses = to1d_payload.get_unverified_value().to2_addresses();
    let to2_addresses = get_to2_urls(&to2_addresses);
    log::info!("Got TO2 addresses: {:?}", to2_addresses);

    if to2_addresses.is_empty() {
        bail!("No valid TO2 addresses received");
    }

    perform_to2(&dc, &to2_addresses)
        .await
        .context("Error performing TO2 ownership protocol")
}
