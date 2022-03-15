use std::{convert::TryFrom, fs, io::Write, path::Path, str::FromStr};

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
use serde_yaml::Value;
use tss_esapi::{structures::Public as TssPublic, traits::UnMarshall};

use fdo_data_formats::{
    constants::{HashType, RendezvousVariable},
    devicecredential::FileDeviceCredential,
    ownershipvoucher::{OwnershipVoucher, OwnershipVoucherHeader},
    publickey::{PublicKey, X5Chain},
    types::{CborSimpleType, Guid, HMac, Hash, RendezvousInfo},
    ProtocolVersion, Serializable,
};

#[tokio::main]
async fn main() -> Result<()> {
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

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
                        .help("Chain with CA certificates for device certificate")
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
                )
                .arg(
                    Arg::with_name("outform")
                        .required(false)
                        .takes_value(true)
                        .possible_values(&["pem", "cose"])
                        .help("Output format")
                        .long("outform"),
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
        .get_matches();

    match matches.subcommand() {
        ("initialize-device", Some(sub_m)) => initialize_device(sub_m),
        ("dump-ownership-voucher", Some(sub_m)) => dump_voucher(sub_m),
        ("dump-device-credential", Some(sub_m)) => dump_devcred(sub_m),
        ("extend-ownership-voucher", Some(sub_m)) => extend_voucher(sub_m),
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

fn yaml_to_cbor(val: &Value) -> Result<CborSimpleType, Error> {
    Ok(match val {
        Value::Null => CborSimpleType::Null,
        Value::Bool(b) => b.to_owned().into(),
        Value::Number(nr) => {
            if let Some(nr) = nr.as_u64() {
                nr.into()
            } else if let Some(nr) = nr.as_i64() {
                nr.into()
            } else if let Some(nr) = nr.as_f64() {
                nr.into()
            } else {
                bail!("Invalid number encountered");
            }
        }
        Value::String(str) => str.clone().into(),
        Value::Sequence(seq) => CborSimpleType::from(
            seq.iter()
                .map(yaml_to_cbor)
                .collect::<Result<Vec<CborSimpleType>>>()?,
        ),
        Value::Mapping(map) => CborSimpleType::from(
            map.iter()
                .map(|(key, val)| (yaml_to_cbor(key).unwrap(), yaml_to_cbor(val).unwrap()))
                .collect::<std::collections::BTreeMap<CborSimpleType, CborSimpleType>>(),
        ),
    })
}

fn load_rendezvous_info(path: &str) -> Result<RendezvousInfo, Error> {
    let contents = fs::read(path)?;
    let mut info = Vec::new();

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
            let key = RendezvousVariable::from_str(key)
                .with_context(|| format!("Error parsing rendezvous key '{}'", key))?;

            let val = yaml_to_cbor(val)?;
            let val = key
                .value_from_human_to_machine(val)
                .with_context(|| format!("Error parsing value for key '{:?}'", key))?;

            entry.push((key, val));
        }

        info.push(entry);
    }

    RendezvousInfo::new(info).context("Error serializing rendezvous info")
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
        .set_serial_number(serial.as_ref())
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

    let manufacturer_cert = load_x509(manufacturer_cert_path).with_context(|| {
        format!(
            "Error loading manufacturer cert at {}",
            manufacturer_cert_path
        )
    })?;
    let manufacturer_pubkey = PublicKey::try_from(manufacturer_cert)
        .context("Error creating manufacturer public key representation")?;

    let device_cert_ca_private_key = load_private_key(device_cert_ca_private_key_path)
        .with_context(|| {
            format!(
                "Error loading device CA private key at {}",
                device_cert_ca_private_key_path
            )
        })?;
    let device_cert_ca_chain = load_x509s(device_cert_ca_chain_path).with_context(|| {
        format!(
            "Error loading device cert ca chain at {}",
            device_cert_ca_chain_path
        )
    })?;

    let rendezvous_info = load_rendezvous_info(rendezvous_info_path)
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
        device_subject,
        &device_key,
        &device_cert_ca_private_key,
        &device_cert_ca_chain,
    )
    .context("Error building device certificate")?;

    // Construct device certificate chain
    let mut device_cert_chain = device_cert_ca_chain;
    device_cert_chain.insert(0, device_cert);
    let device_cert_chain = X5Chain::new(device_cert_chain).context("Error creating X5Chain")?;
    let device_cert_chain_serialized = device_cert_chain
        .serialize_data()
        .context("Error serializing device cert chain")?;
    let device_cert_chain_hash = Hash::from_data(HashType::Sha384, &device_cert_chain_serialized)
        .context("Error hashing device cert chain")?;

    // Build device HMAC key
    let mut hmac_key_buf = [0; 32];
    rand_bytes(&mut hmac_key_buf).context("Error creating random device HMAC key")?;
    let hmac_key_buf = hmac_key_buf;
    let hmac_key = PKey::hmac(&hmac_key_buf).context("Error building hmac key")?;
    let mut hmac_signer =
        Signer::new(MessageDigest::sha384(), &hmac_key).context("Error creating hmac signer")?;

    let device_guid = Guid::new().context("Error generating guid")?;

    // Construct Ownership Voucher Header
    let ov_header = OwnershipVoucherHeader::new(
        ProtocolVersion::Version1_1,
        device_guid.clone(),
        rendezvous_info.clone(),
        device_id.to_string(),
        manufacturer_pubkey,
        Some(device_cert_chain_hash),
    )
    .context("Error creating new OwnershipVoucher Header")?;
    let ov_header_ser = ov_header
        .serialize_data()
        .context("Error serializing Ownership Voucher header")?;

    // Build device credential
    let devcred = FileDeviceCredential {
        active: true,
        protver: ProtocolVersion::Version1_1,
        device_info: device_id.to_string(),
        guid: device_guid.clone(),
        rvinfo: rendezvous_info,
        pubkey_hash: ov_header
            .manufacturer_public_key_hash(HashType::Sha384)
            .context("Error computing manufacturer public key hash")?,
        key_storage: fdo_data_formats::devicecredential::file::KeyStorage::Plain {
            hmac_secret: hmac_key_buf.to_vec(),
            private_key: device_key
                .private_key_to_der()
                .context("Error serializing device private key")?,
        },
    };

    // Compute device hash over OV Header
    hmac_signer
        .update(&ov_header_ser)
        .context("Error computing HMAC")?;
    let ov_hmac = hmac_signer
        .sign_to_vec()
        .context("Error computing hmac signature")?;
    let ov_hmac = HMac::from_digest(HashType::HmacSha384, ov_hmac)?;

    // Build the Ownership Voucher
    let ov = OwnershipVoucher::new(ov_header, ov_hmac, Some(device_cert_chain))
        .context("Error building ownership voucher")?;

    // Write out the ownership voucher and device credential
    let ov = ov.to_pem().context("Error serializing device credential")?;
    let devcred = devcred
        .serialize_data()
        .context("Error serializing device credential")?;

    fs::write(&ownershipvoucher_out, &ov).context("Error writing ownership voucher")?;
    fs::write(&device_credential_out, &devcred).context("Error writing device credential")?;

    println!(
        "Created ownership voucher for device {}",
        device_guid.to_string()
    );

    Ok(())
}

fn dump_voucher(matches: &ArgMatches) -> Result<(), Error> {
    let ownershipvoucher_path = matches.value_of("path").unwrap();
    let outform = matches.value_of("outform");

    let ov = {
        let cts = fs::read(ownershipvoucher_path).context("Error reading ownership voucher")?;
        OwnershipVoucher::from_pem_or_raw(&cts).context("Error deserializing ownership voucher")?
    };

    if let Some(outform) = outform {
        let output = match outform {
            "cose" => ov
                .serialize_data()
                .context("Error serializing ownership voucher")?,
            "pem" => ov
                .to_pem()
                .context("Error serializing ownership voucher")?
                .as_bytes()
                .to_vec(),
            _ => bail!("Invalid output format"),
        };
        std::io::stdout()
            .write_all(&output)
            .context("Error writing output")?;
        return Ok(());
    }

    let ov_header = ov.header();
    if ov_header.protocol_version() != ProtocolVersion::Version1_1 {
        bail!(
            "Protocol version in OV ({}) not supported ({})",
            ov_header.protocol_version(),
            ProtocolVersion::Version1_1,
        );
    }

    println!("Header:");
    println!("\tProtocol Version: {}", ov_header.protocol_version());
    println!("\tDevice GUID: {}", ov_header.guid().to_string());
    println!("\tRendezvous Info:");
    for rv_entry in ov_header.rendezvous_info().values() {
        println!("\t\t- {:?}", rv_entry);
    }
    println!("\tDevice Info: {:?}", ov_header.device_info());
    println!(
        "\tManufacturer public key: {}",
        ov_header.manufacturer_public_key()
    );
    match &ov_header.device_certificate_chain_hash() {
        None => println!("\tDevice certificate chain hash: <none>"),
        Some(v) => println!("\tDevice certificate chain hash: {}", v),
    }

    println!("Header HMAC: {}", ov.header_hmac());

    println!("Device certificate chain:");
    match ov.device_certificate_chain() {
        None => println!("\t<none>"),
        Some(v) => {
            for (num, cert) in v.chain().iter().enumerate() {
                println!("\tCertificate {}: {:?}", num, cert);
            }
        }
    }

    let ov_iter = ov.iter_entries().context("Error creating OV iterator")?;

    println!("Entries:");
    for (pos, entry) in ov_iter.enumerate() {
        let entry = entry.with_context(|| format!("Error parsing entry {}", pos))?;

        println!("\tEntry {}", pos);
        println!("\t\tPrevious entry hash: {}", entry.hash_previous_entry());
        println!("\t\tHeader info hash: {}", entry.hash_header_info());
        if ov_header.protocol_version() >= ProtocolVersion::Version1_1 {
            println!("\t\tExtra: {:?}", entry.extra());
        }
        println!("\t\tPublic key: {}", entry.public_key());
    }

    Ok(())
}

fn dump_devcred(matches: &ArgMatches) -> Result<(), Error> {
    let devcred_path = matches.value_of("path").unwrap();

    let dc = {
        let dc = fs::read(devcred_path).context("Error reading device credential")?;
        FileDeviceCredential::deserialize_data(&dc)
            .context("Error deserializing device credential")?
    };

    if dc.protver != ProtocolVersion::Version1_1 {
        bail!(
            "Protocol version in OV ({}) not supported ({})",
            dc.protver,
            ProtocolVersion::Version1_1
        );
    }

    println!("Active: {}", dc.active);
    println!("Protocol Version: {}", dc.protver);
    println!("Device Info: {}", dc.device_info);
    println!("Device GUID: {}", dc.guid.to_string());
    println!("Rendezvous Info:");
    for rv_entry in dc.rvinfo.values() {
        println!("\t- {:?}", rv_entry);
    }
    println!("Public key hash: {}", dc.pubkey_hash);
    println!("HMAC and signing key:");
    match dc.key_storage {
        fdo_data_formats::devicecredential::file::KeyStorage::Plain { .. } => {
            println!("\tHMAC key: <secret>");
            println!("\tSigning key: <secret>");
        }
        fdo_data_formats::devicecredential::file::KeyStorage::Tpm {
            signing_public,
            hmac_public,
            ..
        } => {
            let hmac_public =
                TssPublic::unmarshall(&hmac_public).context("Error loading HMAC Public")?;
            let signing_public =
                TssPublic::unmarshall(&signing_public).context("Error loading Signing Public")?;

            println!("\tHMAC key TPM public: {:?}", hmac_public);
            println!("\tSigning key TPM public: {:?}", signing_public);
        }
    }

    Ok(())
}

fn extend_voucher(matches: &ArgMatches) -> Result<(), Error> {
    let ownershipvoucher_path = matches.value_of("path").unwrap();
    let current_owner_private_key_path = matches.value_of("current-owner-private-key").unwrap();
    let new_owner_cert_path = matches.value_of("new-owner-cert").unwrap();

    let mut ov = {
        let ov = fs::read(ownershipvoucher_path).context("Error reading ownership voucher")?;
        OwnershipVoucher::from_pem_or_raw(&ov).context("Error deserializing ownership voucher")?
    };

    let ov_header = ov.header();
    if ov_header.protocol_version() != ProtocolVersion::Version1_1 {
        bail!(
            "Protocol version in OV ({}) not supported ({})",
            ov_header.protocol_version(),
            ProtocolVersion::Version1_1,
        );
    }

    let current_owner_private_key =
        load_private_key(current_owner_private_key_path).with_context(|| {
            format!(
                "Error loading current owner private key at {}",
                current_owner_private_key_path
            )
        })?;
    let new_owner_cert = load_x509(new_owner_cert_path).with_context(|| {
        format!(
            "Error loading new owner certificate at {}",
            new_owner_cert_path
        )
    })?;
    let new_owner_pubkey =
        PublicKey::try_from(new_owner_cert).context("Error serializing owner public key")?;

    ov.extend(&current_owner_private_key, None, &new_owner_pubkey)
        .context("Error extending ownership voucher")?;

    // Write out
    let newname = format!("{}.new", ownershipvoucher_path);
    {
        // A new scope, to ensure the file gets closed before we move it
        let ov = ov.to_pem().context("Error serializing ownership voucher")?;
        fs::write(&newname, &ov).with_context(|| format!("Error writing to {}", newname))?;
    }

    fs::rename(newname, ownershipvoucher_path)
        .context("Error moving new ownership voucher in place")?;

    Ok(())
}
