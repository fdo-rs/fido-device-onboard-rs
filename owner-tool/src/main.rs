use std::{
    convert::{TryFrom, TryInto},
    fs,
    path::Path,
    str::FromStr,
};

use anyhow::{bail, Context, Error, Result};
use clap::{App, Arg, ArgMatches, SubCommand};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, PKeyRef, Private},
    rand::rand_bytes,
    sign::Signer,
    x509::{X509Builder, X509NameBuilder, X509NameRef, X509},
};
use serde::Deserialize;
use serde_cbor::Value as CborValue;
use serde_yaml::Value;

use fdo_data_formats::{
    constants::{HashType, PublicKeyType, RendezvousVariable, TransportProtocol},
    enhanced_types::RendezvousInterpreterSide,
    messages,
    ownershipvoucher::{OwnershipVoucher, OwnershipVoucherHeader},
    publickey::{PublicKey, PublicKeyBody, X5Chain},
    types::{
        COSESign, DeviceCredential, Guid, HMac, Hash, RendezvousDirective, RendezvousInfo, TO0Data,
        TO1DataPayload, TO2AddressEntry,
    },
    PROTOCOL_VERSION,
};
use fdo_http_wrapper::client::RequestResult;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new("owner_tool")
        .version("0.1")
        .subcommand(
            SubCommand::with_name("initialize-device")
                .about("Initializes device token")
                .arg(
                    Arg::with_name("device-id")
                        .required(true)
                        .help("Identifier of the device")
                        .index(1),
                )
                .arg(
                    Arg::with_name("ownershipvoucher-out")
                        .required(true)
                        .help("Output path for ownership voucher")
                        .index(2),
                )
                .arg(
                    Arg::with_name("device-credential-out")
                        .required(true)
                        .help("Output path for device credential")
                        .index(3),
                )
                .arg(
                    Arg::with_name("manufacturer-cert")
                        .required(true)
                        .takes_value(true)
                        .help("Path to the certificate for the manufacturer")
                        .long("manufacturer-cert"),
                )
                .arg(
                    Arg::with_name("device-cert-ca-private-key")
                        .required(true)
                        .takes_value(true)
                        .help("Private key for the device certificate CA")
                        .long("device-cert-ca-private-key"),
                )
                .arg(
                    Arg::with_name("device-cert-ca-chain")
                        .required(true)
                        .takes_value(true)
                        .help("Chain with CA certificates for device certifiate")
                        .long("device-cert-ca-chain"),
                )
                .arg(
                    Arg::with_name("rendezvous-info")
                        .required(true)
                        .takes_value(true)
                        .help("Path to a TOML file containing the rendezvous information")
                        .long("rendezvous-info"),
                ),
        )
        .subcommand(
            SubCommand::with_name("dump-ownership-voucher")
                .about("Prints ownership voucher contents")
                .arg(
                    Arg::with_name("path")
                        .required(true)
                        .help("Path to the ownership voucher")
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("dump-device-credential")
                .about("Prints device credential contents")
                .arg(
                    Arg::with_name("path")
                        .required(true)
                        .help("Path to the device credential")
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("extend-ownership-voucher")
                .about("Extends an ownership voucher for a new owner")
                .arg(
                    Arg::with_name("path")
                        .required(true)
                        .help("Path to the ownership voucher")
                        .index(1),
                )
                .arg(
                    Arg::with_name("current-owner-private-key")
                        .required(true)
                        .takes_value(true)
                        .help("Path to the current owner private key")
                        .long("current-owner-private-key"),
                )
                .arg(
                    Arg::with_name("new-owner-cert")
                        .required(true)
                        .takes_value(true)
                        .help("Path to the new owner certificate")
                        .long("new-owner-cert"),
                ),
        )
        .subcommand(
            SubCommand::with_name("report-to-rendezvous")
                .about("Report to the rendezvous server, from when on it should send clients to where we want them")
                .arg(
                    Arg::with_name("ownership-voucher")
                        .required(true)
                        .takes_value(true)
                        .help("Path to the ownership voucher")
                        .long("ownership-voucher")
                )
                .arg(
                    Arg::with_name("owner-private-key")
                        .required(true)
                        .takes_value(true)
                        .help("Path to the owner private key")
                        .long("owner-private-key")
                )
                .arg(
                    Arg::with_name("owner-addresses-path")
                        .required(true)
                        .takes_value(true)
                        .help("Path to the yaml describing the addresses for the ownership server")
                        .long("owner-addresses-path")
                )
                .arg(
                    Arg::with_name("wait-time")
                        .takes_value(true)
                        .help("Wait time (in seconds) for the rendezvous server to remember this owner information")
                        .long("wait-time")
                        .default_value("2592000")
                )
        )
        .get_matches();

    match matches.subcommand() {
        ("initialize-device", Some(sub_m)) => initialize_device(sub_m),
        ("dump-ownership-voucher", Some(sub_m)) => dump_voucher(sub_m),
        ("dump-device-credential", Some(sub_m)) => dump_devcred(sub_m),
        ("extend-ownership-voucher", Some(sub_m)) => extend_voucher(sub_m),
        ("report-to-rendezvous", Some(sub_m)) => report_to_rendezvous(sub_m).await,
        _ => {
            println!("{}", matches.usage());
            Ok(())
        }
    }
}

fn load_private_key(path: &str) -> Result<PKey<Private>, Error> {
    let contents = fs::read(path)?;
    Ok(PKey::private_key_from_der(&contents)?)
}

fn load_x509(path: &str) -> Result<X509, Error> {
    let contents = fs::read(path)?;
    Ok(X509::from_pem(&contents)?)
}

fn load_x509s(path: &str) -> Result<Vec<X509>, Error> {
    let contents = fs::read(path)?;
    Ok(X509::stack_from_pem(&contents)?)
}

fn yaml_to_cbor(val: &Value) -> Result<CborValue, Error> {
    Ok(match val {
        Value::Null => CborValue::Null,
        Value::Bool(b) => CborValue::Bool(*b),
        Value::Number(nr) => {
            if let Some(nr) = nr.as_u64() {
                CborValue::Integer(nr as i128)
            } else if let Some(nr) = nr.as_i64() {
                CborValue::Integer(nr as i128)
            } else if let Some(nr) = nr.as_f64() {
                CborValue::Float(nr)
            } else {
                bail!("Invalid number encountered");
            }
        }
        Value::String(str) => CborValue::Text(str.clone()),
        Value::Sequence(seq) => CborValue::Array(
            seq.iter()
                .map(yaml_to_cbor)
                .collect::<Result<Vec<CborValue>>>()?,
        ),
        Value::Mapping(map) => CborValue::Map(
            map.iter()
                .map(|(key, val)| (yaml_to_cbor(key).unwrap(), yaml_to_cbor(val).unwrap()))
                .collect(),
        ),
    })
}

fn load_rendezvous_info(path: &str) -> Result<RendezvousInfo, Error> {
    let contents = fs::read(path)?;
    let mut info: Vec<RendezvousDirective> = Vec::new();

    let value: Value =
        serde_yaml::from_slice(&contents).context("Error parsing rendezvous info")?;
    let value = match value {
        Value::Sequence(vals) => vals,
        _ => bail!("Invalid yaml top type"),
    };

    for val in value {
        let mut entry = Vec::new();

        let val = match val {
            Value::Mapping(map) => map,
            _ => bail!("Invalid entry type"),
        };

        for (key, val) in val.iter() {
            let key = match key {
                Value::String(val) => val,
                _ => bail!("Invalid key type"),
            };
            let key = RendezvousVariable::from_str(&key)
                .with_context(|| format!("Error parsing rendezvous key '{}'", key))?;

            let val = yaml_to_cbor(val)?;
            let val = key
                .value_from_human_to_machine(val)
                .with_context(|| format!("Error parsing value for key '{:?}'", key))?;

            entry.push((key, val));
        }

        info.push(entry);
    }

    Ok(RendezvousInfo::new(info))
}

fn build_device_cert<T: openssl::pkey::HasPublic>(
    subject_name: &X509NameRef,
    device_pubkey: &PKeyRef<T>,
    signer: &PKeyRef<Private>,
    chain: &[X509],
) -> Result<X509> {
    if chain.is_empty() {
        bail!("Insufficient device CA certs in the chain");
    }
    //if chain[0].public_key()?.public_eq(signer) {
    //    bail!("Device CA issuer not first in the chain");
    //}

    // Build
    let mut builder = X509Builder::new().context("Error creating X509Builder")?;

    builder
        .set_not_after(
            Asn1Time::days_from_now(3650)
                .context("Error building not-after-time")?
                .as_ref(),
        )
        .context("Error setting not-after")?;

    builder
        .set_not_before(
            Asn1Time::days_from_now(0)
                .context("Error building not-before-time")?
                .as_ref(),
        )
        .context("Error setting not-before")?;

    builder.set_version(2).context("Error setting version")?;

    builder
        .set_issuer_name(chain[0].subject_name())
        .context("Error setting issuer name")?;

    builder
        .set_subject_name(subject_name)
        .context("Error setting subject name")?;

    builder
        .set_pubkey(device_pubkey)
        .context("Error setting device public key")?;

    // Build a new serial number
    // We are generating a random number for serial number using 64 bits of output
    //  from a CSPRNG (openssl's rand), according to section 7.1 of
    //  CA/Browser Forum Baseline Requirements, version 1.7.3
    let mut serial_buf = [0; 8];
    rand_bytes(&mut serial_buf).context("Error generating serial number")?;
    let serial = BigNum::from_slice(&serial_buf).context("Error parsing serial number")?;
    let serial = Asn1Integer::from_bn(&serial).context("Error converting serial number to asn1")?;
    builder
        .set_serial_number(&serial.as_ref())
        .context("Error setting serial number")?;

    // Sign and return
    builder
        .sign(signer, MessageDigest::sha384())
        .context("Error signing certificate")?;

    Ok(builder.build())
}

fn initialize_device(matches: &ArgMatches) -> Result<(), Error> {
    // Parse and validate arguments
    let device_id = matches.value_of("device-id").unwrap();
    let ownershipvoucher_out = matches.value_of("ownershipvoucher-out").unwrap();
    let device_credential_out = matches.value_of("device-credential-out").unwrap();
    let manufacturer_cert_path = matches.value_of("manufacturer-cert").unwrap();
    let device_cert_ca_private_key_path = matches.value_of("device-cert-ca-private-key").unwrap();
    let device_cert_ca_chain_path = matches.value_of("device-cert-ca-chain").unwrap();
    let rendezvous_info_path = matches.value_of("rendezvous-info").unwrap();

    let manufacturer_cert = load_x509(&manufacturer_cert_path).with_context(|| {
        format!(
            "Error loading manufacturer cert at {}",
            manufacturer_cert_path
        )
    })?;
    let manufacturer_cert = PublicKeyBody::X509(manufacturer_cert);
    let manufacturer_pubkey = PublicKey::new(PublicKeyType::SECP256R1, manufacturer_cert)
        .context("Error creating manufacturer public key representation")?;

    let device_cert_ca_private_key = load_private_key(&device_cert_ca_private_key_path)
        .with_context(|| {
            format!(
                "Error loading device CA private key at {}",
                device_cert_ca_private_key_path
            )
        })?;
    let device_cert_ca_chain = load_x509s(&device_cert_ca_chain_path).with_context(|| {
        format!(
            "Error loading device cert ca chain at {}",
            device_cert_ca_chain_path
        )
    })?;

    let rendezvous_info = load_rendezvous_info(&rendezvous_info_path)
        .with_context(|| format!("Error loading rendezvous info at {}", rendezvous_info_path))?;

    if Path::new(&device_credential_out).exists() {
        bail!(
            "Device credential file {} already exists",
            device_credential_out
        );
    }
    if Path::new(&ownershipvoucher_out).exists() {
        bail!(
            "Ownership voucher file {} already exists",
            ownershipvoucher_out
        );
    }

    // Build device cert
    let mut device_subject = X509NameBuilder::new().context("Error building device subject")?;
    device_subject
        .append_entry_by_text("CN", device_id)
        .context("Error building device subject")?;
    let device_subject = device_subject.build();
    let device_subject = device_subject.as_ref();
    let device_key_group =
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("Error getting nist 256 group")?;
    let device_key = EcKey::generate(&device_key_group).context("Error generating device key")?;
    let device_key =
        PKey::from_ec_key(device_key).context("Error converting device key to pkey")?;
    let device_cert = build_device_cert(
        &device_subject,
        &device_key,
        &device_cert_ca_private_key,
        &device_cert_ca_chain,
    )
    .context("Error building device certificate")?;

    // Construct device certificate chain
    let mut device_cert_chain = device_cert_ca_chain;
    device_cert_chain.insert(0, device_cert);
    let device_cert_chain = X5Chain::new(device_cert_chain);
    let device_cert_chain = device_cert_chain
        .to_vec()
        .context("Error serializing device cert chain")?;
    let device_cert_chain_hash = Hash::new(Some(HashType::Sha384), &device_cert_chain)
        .context("Error computing digest over device cert chain")?;

    // Build device HMAC key
    let mut hmac_key_buf = [0; 32];
    rand_bytes(&mut hmac_key_buf).context("Error creating random device HMAC key")?;
    let hmac_key_buf = hmac_key_buf;
    let hmac_key = PKey::hmac(&hmac_key_buf).context("Error building hmac key")?;
    let mut hmac_signer =
        Signer::new(MessageDigest::sha384(), &hmac_key).context("Error creating hmac signer")?;

    // Build device credential
    let device_guid = Guid::new().context("Error generating guid")?;
    let devcred = DeviceCredential {
        active: true,
        protver: PROTOCOL_VERSION,
        hmac_secret: hmac_key_buf.to_vec(),
        device_info: device_id.to_string(),
        guid: device_guid.clone(),
        rvinfo: rendezvous_info.clone(),
        pubkey_hash: Hash::new(None, &[]).unwrap(),
        private_key: device_key
            .private_key_to_der()
            .context("Error serializing device private key")?,
    };

    // Construct Ownership Voucher Header
    let ov_header = OwnershipVoucherHeader::new(
        PROTOCOL_VERSION,
        device_guid.clone(),
        rendezvous_info,
        device_id.to_string(),
        manufacturer_pubkey,
        Some(device_cert_chain_hash),
    );
    let ov_header = serde_cbor::to_vec(&ov_header).context("Error serializing ov header")?;

    // Compute device hash over OV Header
    hmac_signer
        .update(&ov_header)
        .context("Error computing HMAC")?;
    let ov_hmac = hmac_signer
        .sign_to_vec()
        .context("Error computing hmac signature")?;
    let ov_hmac = HMac::new_from_data(HashType::Sha384, ov_hmac);

    // Build the Ownership Voucher
    let ov = OwnershipVoucher::new(ov_header, ov_hmac, Some(device_cert_chain));

    // Write out the ownership voucher and device credential
    let ov_out =
        fs::File::create(ownershipvoucher_out).context("Error creating ownership voucher")?;
    let devcred_out =
        fs::File::create(device_credential_out).context("Error creating device credential file")?;

    serde_cbor::to_writer(ov_out, &ov).context("Error writing ownership voucher")?;
    serde_cbor::to_writer(devcred_out, &devcred).context("Error writing device credential")?;

    println!(
        "Created ownership voucher for device {}",
        device_guid.to_string()
    );

    Ok(())
}

fn dump_voucher(matches: &ArgMatches) -> Result<(), Error> {
    let ownershipvoucher_path = matches.value_of("path").unwrap();

    let ov: OwnershipVoucher = {
        let ov_file = fs::File::open(&ownershipvoucher_path).with_context(|| {
            format!(
                "Error opening ownership voucher at {}",
                ownershipvoucher_path
            )
        })?;
        serde_cbor::from_reader(ov_file).context("Error loading ownership voucher")?
    };

    let ov_header = ov.get_header().context("Error loading OV header")?;
    if ov_header.protocol_version != PROTOCOL_VERSION {
        bail!(
            "Protocol version in OV ({}) not supported ({})",
            ov_header.protocol_version,
            PROTOCOL_VERSION
        );
    }

    println!("Header:");
    println!("\tProtocol Version: {}", ov_header.protocol_version);
    println!("\tDevice GUID: {}", ov_header.guid.to_string());
    println!("\tRendezvous Info:");
    for rv_entry in ov_header.rendezvous_info.values() {
        println!("\t\t- {:?}", rv_entry);
    }
    println!("\tDevice Info: {}", ov_header.device_info);
    println!("\tManufacturer public key: {}", ov_header.public_key);
    match ov_header.device_certificate_chain_hash {
        None => println!("\tDevice certificate chain hash: <none>"),
        Some(v) => println!("\tDevice certificate chain hash: {}", v),
    }

    println!("Header HMAC: {}", ov.header_hmac());

    let dev_cert = ov
        .device_certificate()
        .context("Error parsing the device certificate")?;
    let dev_cert_signers = ov
        .device_cert_signers()
        .context("Error parsing the device certificate chain")?;
    println!("Device certificate chain:");
    if let Some(dev_cert) = dev_cert {
        println!("\tDevice certificate: {:?}", &dev_cert);
    }
    for (num, dev_cert_signer) in dev_cert_signers.iter().enumerate() {
        println!("\tSigner {}: {:?}", num, dev_cert_signer);
    }

    let ov_iter = ov.iter_entries().context("Error creating OV iterator")?;

    println!("Entries:");
    for (pos, entry) in ov_iter.enumerate() {
        let entry = entry.with_context(|| format!("Error parsing entry {}", pos))?;

        println!("\tEntry {}", pos);
        println!("\t\tPrevious entry hash: {}", entry.hash_previous_entry);
        println!("\t\tHeader info hash: {}", entry.hash_header_info);
        println!("\t\tPublic key: {}", entry.public_key);
    }

    Ok(())
}

fn dump_devcred(matches: &ArgMatches) -> Result<(), Error> {
    let devcred_path = matches.value_of("path").unwrap();

    let dc: DeviceCredential = {
        let dc_file = fs::File::open(&devcred_path)
            .with_context(|| format!("Error opening device credential at {}", devcred_path))?;
        serde_cbor::from_reader(dc_file).context("Error loading device credential")?
    };

    if dc.protver != PROTOCOL_VERSION {
        bail!(
            "Protocol version in OV ({}) not supported ({})",
            dc.protver,
            PROTOCOL_VERSION
        );
    }

    println!("Active: {}", dc.active);
    println!("Protocol Version: {}", dc.protver);
    println!("HMAC key: <secret>");
    println!("Device Info: {}", dc.device_info);
    println!("Device GUID: {}", dc.guid.to_string());
    println!("Rendezvous Info:");
    for rv_entry in dc.rvinfo.values() {
        println!("\t- {:?}", rv_entry);
    }
    println!("Public key hash: {}", dc.pubkey_hash);

    // Custom
    println!("Private key: <secret>");

    Ok(())
}

fn extend_voucher(matches: &ArgMatches) -> Result<(), Error> {
    let ownershipvoucher_path = matches.value_of("path").unwrap();
    let current_owner_private_key_path = matches.value_of("current-owner-private-key").unwrap();
    let new_owner_cert_path = matches.value_of("new-owner-cert").unwrap();

    let mut ov: OwnershipVoucher = {
        let ov_file = fs::File::open(&ownershipvoucher_path).with_context(|| {
            format!(
                "Error opening ownership voucher at {}",
                ownershipvoucher_path
            )
        })?;
        serde_cbor::from_reader(ov_file).context("Error loading ownership voucher")?
    };

    let ov_header = ov.get_header().context("Error loading OV header")?;
    if ov_header.protocol_version != PROTOCOL_VERSION {
        bail!(
            "Protocol version in OV ({}) not supported ({})",
            ov_header.protocol_version,
            PROTOCOL_VERSION
        );
    }

    let current_owner_private_key = load_private_key(&current_owner_private_key_path)
        .with_context(|| {
            format!(
                "Error loading current owner private key at {}",
                current_owner_private_key_path
            )
        })?;
    let new_owner_cert = load_x509(&new_owner_cert_path).with_context(|| {
        format!(
            "Error loading new owner certificate at {}",
            new_owner_cert_path
        )
    })?;

    let new_owner_cert = PublicKeyBody::X509(new_owner_cert);
    let new_owner_pubkey = PublicKey::new(PublicKeyType::SECP256R1, new_owner_cert)
        .context("Error creating new public key")?;

    ov.extend(&current_owner_private_key, None, &new_owner_pubkey)
        .context("Error extending ownership voucher")?;

    // Write out
    let newname = format!("{}.new", ownershipvoucher_path);
    {
        // A new scope, to ensure the file gets closed before we move it
        let ov_out = fs::File::create(&newname)
            .with_context(|| format!("Error opening new ownership voucher file at {}", newname))?;
        serde_cbor::to_writer(ov_out, &ov).context("Error writing new ownership voucher")?;
    }

    fs::rename(newname, ownershipvoucher_path)
        .context("Error moving new ownership voucher in place")?;

    Ok(())
}

#[derive(Debug, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
enum RemoteTransport {
    TCP,
    TLS,
    HTTP,
    CoAP,
    HTTPS,
    CoAPS,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RemoteAddress {
    IP { ip_address: String },
    Dns { dns_name: String },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
struct RemoteConnection {
    transport: RemoteTransport,
    addresses: Vec<RemoteAddress>,
    port: u16,
}

impl TryFrom<RemoteConnection> for Vec<TO2AddressEntry> {
    type Error = Error;

    fn try_from(rc: RemoteConnection) -> Result<Vec<TO2AddressEntry>> {
        let transport = match rc.transport {
            RemoteTransport::TCP => TransportProtocol::Tcp,
            RemoteTransport::TLS => TransportProtocol::Tls,
            RemoteTransport::HTTP => TransportProtocol::Http,
            RemoteTransport::CoAP => TransportProtocol::CoAP,
            RemoteTransport::HTTPS => TransportProtocol::Https,
            RemoteTransport::CoAPS => TransportProtocol::CoAPS,
        };

        let mut results = Vec::new();

        for addr in &rc.addresses {
            match addr {
                RemoteAddress::IP { ip_address } => {
                    let addr = std::net::IpAddr::from_str(&ip_address)
                        .with_context(|| format!("Error parsing IP address '{}'", ip_address))?;
                    results.push(TO2AddressEntry::new(
                        Some(addr.into()),
                        None,
                        rc.port,
                        transport,
                    ));
                }
                RemoteAddress::Dns { dns_name } => {
                    results.push(TO2AddressEntry::new(
                        None,
                        Some(dns_name.clone()),
                        rc.port,
                        transport,
                    ));
                }
            }
        }

        Ok(results)
    }
}

async fn report_to_rendezvous(matches: &ArgMatches<'_>) -> Result<(), Error> {
    let ownershipvoucher_path = matches.value_of("ownership-voucher").unwrap();
    let owner_private_key_path = matches.value_of("owner-private-key").unwrap();
    let owner_addresses_path = matches.value_of("owner-addresses-path").unwrap();
    let wait_time = matches.value_of("wait-time").unwrap();
    let wait_time = wait_time
        .parse::<u32>()
        .with_context(|| format!("Error parsing wait time '{}'", wait_time))?;

    let ov: OwnershipVoucher = {
        let ov_file = fs::File::open(&ownershipvoucher_path).with_context(|| {
            format!(
                "Error opening ownership voucher at {}",
                ownershipvoucher_path
            )
        })?;
        serde_cbor::from_reader(ov_file).context("Error loading ownership voucher")?
    };

    let ov_header = ov.get_header().context("Error loading OV header")?;
    if ov_header.protocol_version != PROTOCOL_VERSION {
        bail!(
            "Protocol version in OV ({}) not supported ({})",
            ov_header.protocol_version,
            PROTOCOL_VERSION
        );
    }

    let owner_private_key = load_private_key(&owner_private_key_path).with_context(|| {
        format!(
            "Error loading owner private key from {}",
            owner_private_key_path
        )
    })?;

    let mut owner_addresses: Vec<RemoteConnection> = {
        let f = fs::File::open(&owner_addresses_path)?;
        serde_yaml::from_reader(f)
    }
    .with_context(|| {
        format!(
            "Error reading owner addresses from {}",
            owner_addresses_path
        )
    })?;
    let owner_addresses: Result<Vec<Vec<TO2AddressEntry>>> =
        owner_addresses.drain(..).map(|v| v.try_into()).collect();
    let mut owner_addresses = owner_addresses.context("Error parsing owner addresses")?;
    let owner_addresses = owner_addresses.drain(..).flatten().collect();

    // Determine the RV IP
    let rv_info = ov
        .get_header()
        .context("Error getting OV header")?
        .rendezvous_info
        .to_interpreted(RendezvousInterpreterSide::Owner)
        .context("Error parsing rendezvous directives")?;
    if rv_info.is_empty() {
        bail!("No rendezvous information found that's usable for the owner");
    }
    // Use the first entry
    let rv_info = rv_info.first().unwrap();
    let rv_urls = rv_info.get_urls();
    if rv_urls.is_empty() {
        bail!("No usable rendezvous URLs were found");
    }
    let rv_url = rv_urls.first().unwrap();

    println!("Using rendezvous server at url {}", rv_url);

    let mut rv_client = fdo_http_wrapper::client::ServiceClient::new(&rv_url);

    // Send: Hello, Receive: HelloAck
    let hello_ack: RequestResult<messages::to0::HelloAck> = rv_client
        .send_request(messages::to0::Hello::new(), None)
        .await;
    let hello_ack = hello_ack.context("Error requesting nonce from rendezvous server")?;

    // Build to0d and to1d
    let to0d = TO0Data::new(ov, wait_time, hello_ack.nonce3().clone());
    let to0d_vec = serde_cbor::to_vec(&to0d).context("Error serializing to0d")?;
    let to0d_hash = Hash::new(None, &to0d_vec).context("Error hashing to0d")?;
    let to1d_payload = TO1DataPayload::new(owner_addresses, to0d_hash);
    let to1d =
        COSESign::new(&to1d_payload, None, &owner_private_key).context("Error signing to1d")?;

    // Send: OwnerSign, Receive: AcceptOwner
    let accept_owner: RequestResult<messages::to0::AcceptOwner> = rv_client
        .send_request(messages::to0::OwnerSign::new(to0d, to1d), None)
        .await;
    let accept_owner = accept_owner.context("Error registering self to rendezvous server")?;

    // Done!
    println!(
        "Rendezvous server registered us for {} seconds",
        accept_owner.wait_seconds()
    );

    Ok(())
}
