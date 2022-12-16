use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

use anyhow::{bail, Error, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509Name, X509};
use std::env;

mod aio;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Subject {
    Diun,
    Manufacturer,
    DeviceCA,
    Owner,
}

impl Subject {
    fn common_name(&self) -> &str {
        match self {
            Subject::Diun => "DIUN",
            Subject::Manufacturer => "Manufacturer",
            Subject::DeviceCA => "Device",
            Subject::Owner => "Owner",
        }
    }
    fn file_name(&self) -> &str {
        match self {
            Subject::Diun => "diun",
            Subject::Manufacturer => "manufacturer",
            Subject::DeviceCA => "device_ca",
            Subject::Owner => "owner",
        }
    }
}

fn generate_key_and_cert(args: &GenerateKeyAndCertArguments) -> Result<(), Error> {
    let subject = args.subject;
    let organization_name = &args.organization;
    let country_name = &args.country;
    let destination_dir = &args.destination_dir;
    let mut destination_dir_path = PathBuf::from(destination_dir);
    if !destination_dir_path.is_absolute() {
        destination_dir_path = env::current_dir()?;
        destination_dir_path.push(destination_dir);
    }
    if !destination_dir_path.is_dir() {
        bail!("{:?} is not a directory", destination_dir_path)
    }

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = EcKey::generate(&group)?;

    let pkey = PKey::from_ec_key(key.clone())?;

    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, subject.common_name())?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, organization_name)?;
    name.append_entry_by_nid(Nid::COUNTRYNAME, country_name)?;
    let name = name.build();

    let mut builder = X509::builder()?;
    let mut serial_buf = [0; 8];
    openssl::rand::rand_bytes(&mut serial_buf)?;
    let serial = BigNum::from_slice(&serial_buf)?;
    let serial = Asn1Integer::from_bn(&serial)?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_pubkey(&pkey)?;
    builder.sign(&pkey, MessageDigest::sha256())?;

    let mut der_path = destination_dir_path.clone();
    der_path.push(format!("{}_key.der", subject.file_name()));
    let mut file = File::create(der_path)?;
    file.write_all(&key.private_key_to_der()?)?;

    let mut pem_path = destination_dir_path.clone();
    pem_path.push(format!("{}_cert.pem", subject.file_name()));
    let mut file = File::create(pem_path)?;
    file.write_all(&builder.build().to_pem()?)?;

    Ok(())
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(value_enum, short, long, default_value_t = LogLevel::Info)]
    log_level: LogLevel,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Off,
}

impl LogLevel {
    fn to_log(self) -> log::LevelFilter {
        match self {
            LogLevel::Trace => log::LevelFilter::Trace,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Off => log::LevelFilter::Off,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    GenerateKeyAndCert(GenerateKeyAndCertArguments),
    Aio(Box<crate::aio::AioArgs>),
}

#[derive(Args)]
struct GenerateKeyAndCertArguments {
    /// Subject of the key and certificate
    #[clap(value_enum)]
    subject: Subject,
    /// Organization name for the certificate
    #[clap(long, default_value_t = String::from("Example"))]
    organization: String,
    /// Country name for the certificate
    #[clap(long, default_value_t = String::from("US"))]
    country: String,
    /// Writes key and certificate to the given path
    #[clap(long, default_value_t = String::from("keys"))]
    destination_dir: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    pretty_env_logger::formatted_builder()
        .filter_level(cli.log_level.to_log())
        .init();

    match cli.command {
        Commands::GenerateKeyAndCert(args) => generate_key_and_cert(&args),
        Commands::Aio(args) => aio::run_aio_subcommand(*args).await,
    }
}
