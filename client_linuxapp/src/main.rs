use std::env;
use std::fs;

use anyhow::{bail, Context, Result};
use aws_nitro_enclaves_cose::COSESign1;
use openssl::pkey::PKey;

use fdo_data_formats::{
    constants::{DeviceSigType, TransportProtocol},
    enhanced_types::{RendezvousInterpretedDirective, RendezvousInterpreterSide},
    messages,
    types::{
        CipherSuite, DeviceCredential, KexSuite, Nonce, SigInfo, TO1DataPayload, TO2AddressEntry,
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

async fn perform_to1(devcred: &DeviceCredential, client: &mut ServiceClient) -> Result<COSESign1> {
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

    // Create signature over nonce4
    let privkey = PKey::private_key_from_der(&devcred.private_key)
        .context("Error loading private key from device credential")?;
    let token = COSESign1::new(
        nonce4.value(),
        &aws_nitro_enclaves_cose::sign::HeaderMap::new(),
        &privkey,
    )
    .context("Error signing new token")?;

    log::trace!("Sending token: {:?}", token);

    // Send: ProveToRV, Receive: RVRedirect
    let prove_to_rv = messages::to1::ProveToRV::new(token);
    let rv_redirect: RequestResult<messages::to1::RVRedirect> =
        client.send_request(prove_to_rv, None).await;
    let rv_redirect = rv_redirect.context("Error proving self to rendezvous server")?;

    // Done!
    Ok(rv_redirect.into_to1d())
}

async fn get_to1d_from_rv(devcred: &DeviceCredential) -> Result<COSESign1> {
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

async fn perform_to2(devcred: &DeviceCredential, urls: &[String]) -> Result<()> {
    log::info!("Performing TO2 protocol, URLs: {:?}", urls);
    let url = urls.first().unwrap();

    let nonce5 = Nonce::new().context("Error generating nonce5")?;

    let mut client = fdo_http_wrapper::client::ServiceClient::new(&url);

    // Send: HelloDevice, Receive: ProveOVHdr
    let prove_ov_hdr: RequestResult<messages::to2::ProveOVHdr> = client
        .send_request(
            messages::to2::HelloDevice::new(
                devcred.guid.clone(),
                nonce5,
                KexSuite::ECDH384,
                CipherSuite::A256GCM,
                SigInfo::new(DeviceSigType::StSECP384R1, vec![]),
            ),
            None,
        )
        .await;
    let prove_ov_hdr = prove_ov_hdr.context("Error sending HelloDevice")?;

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

    let to1d_payload = to1d
        .get_payload(None)
        .context("Error getting the TO2 payload")?;
    let to1d_payload: TO1DataPayload = serde_cbor::from_slice(&to1d_payload)
        .context("Error loading the TO1DataPayload out of TO1D")?;
    let to2_addresses = to1d_payload.to2_addresses();
    let to2_addresses = get_to2_urls(&to2_addresses);
    log::info!("Got TO2 addresses: {:?}", to2_addresses);

    if to2_addresses.is_empty() {
        bail!("No valid TO2 addresses received");
    }

    perform_to2(&dc, &to2_addresses)
        .await
        .context("Error performing TO2 ownership protocol")
}
