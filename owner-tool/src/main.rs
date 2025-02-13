use std::io::Cursor;
use std::path::PathBuf;
use std::{convert::TryFrom, env, fs, io::Write, path::Path, str::FromStr};

use anyhow::{bail, Context, Error, Result};
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use fdo_db::models::ManufacturerOV;
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
use std::fs::File;
use tss_esapi::{structures::Public as TssPublic, traits::UnMarshall};

use std::io::prelude::*;

use fdo_data_formats::{
    constants::{HashType, RendezvousVariable},
    devicecredential::FileDeviceCredential,
    ownershipvoucher::{OwnershipVoucher, OwnershipVoucherHeader},
    publickey::{PublicKey, X5Chain},
    types::{CborSimpleType, Guid, HMac, Hash, RendezvousInfo},
    ProtocolVersion, Serializable,
};

#[derive(Parser)]
#[clap(version = "0.1")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initializes device token
    InitializeDevice(InitializeDeviceArguments),
    /// Prints ownership voucher contents
    DumpOwnershipVoucher(DumpOwnershipVoucherArguments),
    /// Prints device credential contents
    DumpDeviceCredential(DumpDeviceCredentialArguments),
    /// Extends an ownership voucher for a new owner
    ExtendOwnershipVoucher(ExtendOwnershipVoucherArguments),
    /// Exports a single or all the ownership vouchers present in the Manufacturer DB
    ExportManufacturerVouchers(ExportManufacturerVouchersArguments),
    /// Imports into the Owner DB a single ownership voucher or all the ownership vouchers present at a given path
    ImportOwnershipVouchers(ImportOwnershipVouchersArguments),
}

#[derive(Args)]
struct InitializeDeviceArguments {
    /// Identifier of the device
    device_id: String,
    /// Output path for ownership voucher
    ownershipvoucher_out: String,
    /// Output path for device credential
    device_credential_out: String,
    /// Path to the certificate for the manufacturer
    #[clap(long, action = ArgAction::Set)]
    manufacturer_cert: String,
    /// Private key for the device certificate CA
    #[clap(long, action = ArgAction::Set)]
    device_cert_ca_private_key: String,
    /// Chain with CA certificates for device certificate
    #[clap(long, action = ArgAction::Set)]
    device_cert_ca_chain: String,
    /// Path to a TOML file containing the rendezvous information
    #[clap(long, action = ArgAction::Set)]
    rendezvous_info: String,
}

#[derive(Copy, Clone, ValueEnum)]
enum OutputFormat {
    Pem,
    Cose,
}

#[derive(Args)]
struct DumpOwnershipVoucherArguments {
    /// Path to the ownership voucher
    path: String,
    /// Output format
    #[clap(value_enum, long, required = false, action = ArgAction::Set)]
    outform: Option<OutputFormat>,
}

#[derive(Args)]
struct DumpDeviceCredentialArguments {
    /// Path to the device credential
    path: String,
}

#[derive(Args)]
struct ExtendOwnershipVoucherArguments {
    /// Path to the ownership voucher
    path: String,
    /// Path to the current owner private key
    #[clap(long, action = ArgAction::Set)]
    current_owner_private_key: String,
    /// Path to the new owner certificate
    #[clap(long, action = ArgAction::Set)]
    new_owner_cert: String,
}

#[derive(Args)]
struct ExportManufacturerVouchersArguments {
    /// Manufacturer server URL
    manufacturer_server_url: String,
    /// GUID of the voucher to be exported, if no GUID is given all the OVs will be exported
    #[clap(long, action = ArgAction::Set)]
    device_guid: Option<String>,
    /// Path to dir where the OVs will be exported, or the current working directory
    #[clap(long, action = ArgAction::Set)]
    path: Option<PathBuf>,
}

#[derive(Copy, Clone, ValueEnum)]
enum DBType {
    Sqlite,
    Postgres,
}

#[derive(Args)]
struct ImportOwnershipVouchersArguments {
    /// Owner server URL
    owner_server_url: String,
    /// Path to the OV(s)
    path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

    match Cli::parse().command {
        Commands::InitializeDevice(args) => initialize_device(&args),
        Commands::DumpOwnershipVoucher(args) => dump_voucher(&args),
        Commands::DumpDeviceCredential(args) => dump_devcred(&args),
        Commands::ExtendOwnershipVoucher(args) => extend_voucher(&args),
        Commands::ExportManufacturerVouchers(args) => export_manufacturer_vouchers(&args).await,
        Commands::ImportOwnershipVouchers(args) => import_ownership_vouchers(&args).await,
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
        Value::Tagged(_) => bail!("YAML tags are unsupported"),
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
                .with_context(|| format!("Error parsing rendezvous key '{key}'"))?;

            let val = yaml_to_cbor(val)?;
            let val = key
                .value_from_human_to_machine(val)
                .with_context(|| format!("Error parsing value for key '{key:?}'"))?;

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

fn initialize_device(args: &InitializeDeviceArguments) -> Result<(), Error> {
    let manufacturer_cert = load_x509(&args.manufacturer_cert).with_context(|| {
        format!(
            "Error loading manufacturer cert at {}",
            args.manufacturer_cert
        )
    })?;
    let manufacturer_pubkey = PublicKey::try_from(manufacturer_cert)
        .context("Error creating manufacturer public key representation")?;

    let device_cert_ca_private_key = load_private_key(&args.device_cert_ca_private_key)
        .with_context(|| {
            format!(
                "Error loading device CA private key at {}",
                args.device_cert_ca_private_key
            )
        })?;
    let device_cert_ca_chain = load_x509s(&args.device_cert_ca_chain).with_context(|| {
        format!(
            "Error loading device cert ca chain at {}",
            args.device_cert_ca_chain
        )
    })?;

    let rendezvous_info = load_rendezvous_info(&args.rendezvous_info)
        .with_context(|| format!("Error loading rendezvous info at {}", args.rendezvous_info))?;

    if Path::new(&args.device_credential_out).exists() {
        bail!(
            "Device credential file {} already exists",
            args.device_credential_out
        );
    }
    if Path::new(&args.ownershipvoucher_out).exists() {
        bail!(
            "Ownership voucher file {} already exists",
            args.ownershipvoucher_out
        );
    }

    // Build device cert
    let mut device_subject = X509NameBuilder::new().context("Error building device subject")?;
    device_subject
        .append_entry_by_text("CN", &args.device_id)
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
        .chain()
        .iter()
        .try_fold(vec![], |mut bytes, cert| {
            cert.to_der().map(|der| {
                bytes.extend(der);
                bytes
            })
        })
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
        args.device_id.clone(),
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
        device_info: args.device_id.clone(),
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

    fs::write(&args.ownershipvoucher_out, ov).context("Error writing ownership voucher")?;
    fs::write(&args.device_credential_out, devcred).context("Error writing device credential")?;

    println!("Created ownership voucher for device {}", device_guid);

    Ok(())
}

fn dump_voucher(args: &DumpOwnershipVoucherArguments) -> Result<(), Error> {
    let ov = {
        let cts = fs::read(args.path.clone()).context("Error reading ownership voucher")?;
        OwnershipVoucher::from_pem_or_raw(&cts).context("Error deserializing ownership voucher")?
    };

    let outform = args.outform;
    if let Some(outform) = outform {
        let output = match outform {
            OutputFormat::Cose => ov
                .serialize_data()
                .context("Error serializing ownership voucher")?,
            OutputFormat::Pem => ov
                .to_pem()
                .context("Error serializing ownership voucher")?
                .as_bytes()
                .to_vec(),
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
    println!("\tDevice GUID: {}", ov_header.guid());
    println!("\tRendezvous Info:");
    for rv_entry in ov_header.rendezvous_info().values() {
        println!("\t\t- {rv_entry:?}");
    }
    println!("\tDevice Info: {:?}", ov_header.device_info());
    println!(
        "\tManufacturer public key: {}",
        ov_header.manufacturer_public_key()
    );
    match &ov_header.device_certificate_chain_hash() {
        None => println!("\tDevice certificate chain hash: <none>"),
        Some(v) => println!("\tDevice certificate chain hash: {v}"),
    }

    println!("Header HMAC: {}", ov.header_hmac());

    println!("Device certificate chain:");
    match ov.device_certificate_chain() {
        None => println!("\t<none>"),
        Some(v) => {
            for (num, cert) in v.chain().iter().enumerate() {
                println!("\tCertificate {num}: {cert:?}");
            }
        }
    }

    let ov_iter = ov.iter_entries().context("Error creating OV iterator")?;

    println!("Entries:");
    for (pos, entry) in ov_iter.enumerate() {
        let entry = entry.with_context(|| format!("Error parsing entry {pos}"))?;

        println!("\tEntry {pos}");
        println!("\t\tPrevious entry hash: {}", entry.hash_previous_entry());
        println!("\t\tHeader info hash: {}", entry.hash_header_info());
        if ov_header.protocol_version() >= ProtocolVersion::Version1_1 {
            println!("\t\tExtra: {:?}", entry.extra());
        }
        println!("\t\tPublic key: {}", entry.public_key());
    }

    Ok(())
}

fn dump_devcred(args: &DumpDeviceCredentialArguments) -> Result<(), Error> {
    let dc = {
        let dc = fs::read(args.path.clone()).context("Error reading device credential")?;
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
    println!("Device GUID: {}", dc.guid);
    println!("Rendezvous Info:");
    for rv_entry in dc.rvinfo.values() {
        println!("\t- {rv_entry:?}");
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

            println!("\tHMAC key TPM public: {hmac_public:?}");
            println!("\tSigning key TPM public: {signing_public:?}");
        }
    }

    Ok(())
}

fn extend_voucher(args: &ExtendOwnershipVoucherArguments) -> Result<(), Error> {
    let mut ov = {
        let ov = fs::read(args.path.clone()).context("Error reading ownership voucher")?;
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

    let current_owner_private_key = load_private_key(&args.current_owner_private_key)
        .with_context(|| {
            format!(
                "Error loading current owner private key at {}",
                args.current_owner_private_key
            )
        })?;
    let new_owner_cert = load_x509(&args.new_owner_cert).with_context(|| {
        format!(
            "Error loading new owner certificate at {}",
            args.new_owner_cert
        )
    })?;
    let new_owner_pubkey =
        PublicKey::try_from(new_owner_cert).context("Error serializing owner public key")?;

    ov.extend(&current_owner_private_key, None, &new_owner_pubkey)
        .context("Error extending ownership voucher")?;

    // Write out
    let newname = format!("{}.new", args.path);
    {
        // A new scope, to ensure the file gets closed before we move it
        let ov = ov.to_pem().context("Error serializing ownership voucher")?;
        fs::write(&newname, ov).with_context(|| format!("Error writing to {newname}"))?;
    }

    fs::rename(newname, args.path.clone())
        .context("Error moving new ownership voucher in place")?;

    Ok(())
}

fn _write_ov_to_disk(db_ov: &ManufacturerOV, path: &Path) -> Result<()> {
    let new_path = path.join(&db_ov.guid);
    let file = File::create(new_path)?;
    let ov = OwnershipVoucher::from_pem_or_raw(&db_ov.contents).expect("Error serializing OV");
    OwnershipVoucher::serialize_to_writer(&ov, &file)?;
    Ok(())
}

async fn export_manufacturer_vouchers(args: &ExportManufacturerVouchersArguments) -> Result<()> {
    let path = &args.path.clone().unwrap_or(env::current_dir()?);
    if !path.is_dir() {
        bail!("Please provide a path to a valid directory.");
    }
    let client = reqwest::Client::new();
    if let Some(device_guid) = &args.device_guid {
        let ov_path = path.join(device_guid);
        let mut ov_file = File::create(ov_path)?;
        let ov = client
            .get(format!(
                "{}/ov/{}",
                &args.manufacturer_server_url, device_guid
            ))
            .send()
            .await?
            .text()
            .await?;
        ov_file.write_all(ov.as_bytes())?;
        println!("OV {device_guid} exported.")
    } else {
        let ovs_tar_path = path.join("export.tar");
        let mut ovs_tar = File::create(ovs_tar_path)?;
        let ovs = client
            .post(format!("{}/export", &args.manufacturer_server_url))
            .send()
            .await?
            .bytes()
            .await?;
        let mut content = Cursor::new(ovs);
        std::io::copy(&mut content, &mut ovs_tar)?;
        println!("OV/s exported.");
    }
    Ok(())
}

async fn import_ownership_vouchers(args: &ImportOwnershipVouchersArguments) -> Result<()> {
    let mut file = File::open(&args.path)?;
    let mut data: Vec<u8> = Vec::new();
    file.read_to_end(&mut data)?;
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/import", &args.owner_server_url))
        .body(data)
        .send()
        .await?
        .text()
        .await?;
    println!("Import result: {}", res);
    Ok(())
}
