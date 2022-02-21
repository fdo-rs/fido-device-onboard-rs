use anyhow::{bail, Error, Result};
use clap::{App, Arg, ArgMatches, SubCommand};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509Name, X509};
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

enum Subject {
    Diun,
    Manufacturer,
    DeviceCA,
    Owner,
}

impl Subject {
    fn to_common_name(&self) -> &str {
        match self {
            Subject::Diun => "DIUN",
            Subject::Manufacturer => "Manufacturer",
            Subject::DeviceCA => "Device",
            Subject::Owner => "Owner",
        }
    }
    fn to_file_name(&self) -> &str {
        match self {
            Subject::Diun => "diun",
            Subject::Manufacturer => "manufacturer",
            Subject::DeviceCA => "device_ca",
            Subject::Owner => "owner",
        }
    }
}

fn match_to_subject(s: &str) -> Result<Subject> {
    match s {
        "diun" => Ok(Subject::Diun),
        "manufacturer" => Ok(Subject::Manufacturer),
        "device_ca" => Ok(Subject::DeviceCA),
        "owner" => Ok(Subject::Owner),
        _ => bail!("{} is not a valid subject", s),
    }
}

fn generate_key_and_cert(matches: &ArgMatches) -> Result<(), Error> {
    let subject = match_to_subject(matches.value_of("subject").unwrap())?;
    let organization_name = matches.value_of("organization").unwrap();
    let country_name = matches.value_of("country").unwrap();
    let destination_dir = matches.value_of("destination-dir").unwrap();
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
    name.append_entry_by_nid(Nid::COMMONNAME, subject.to_common_name())?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, organization_name)?;
    name.append_entry_by_nid(Nid::COUNTRYNAME, country_name)?;
    let name = name.build();

    let mut builder = X509::builder()?;
    let serial = BigNum::from_u32(42)?;
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
    der_path.push(format!("{}_key.der", subject.to_file_name()));
    let mut file = File::create(der_path)?;
    file.write_all(&key.private_key_to_der()?)?;

    let mut pem_path = destination_dir_path.clone();
    pem_path.push(format!("{}_cert.pem", subject.to_file_name()));
    let mut file = File::create(pem_path)?;
    file.write_all(&builder.build().to_pem()?)?;

    Ok(())
}

fn main() -> Result<()> {
    let matches = App::new("admin-tool")
        .subcommand(
            SubCommand::with_name("generate-key-and-cert")
                .about("Generate key and certificate")
                .arg(
                    Arg::with_name("subject")
                        .required(true)
                        .possible_values(&["diun", "manufacturer", "device_ca", "owner"])
                        .help("Subject of the key and certificate")
                        .index(1),
                )
                .arg(
                    Arg::with_name("organization")
                        .takes_value(true)
                        .default_value("Example")
                        .help("Organization name for the certificate")
                        .long("organization"),
                )
                .arg(
                    Arg::with_name("country")
                        .takes_value(true)
                        .default_value("US")
                        .help("Country name for the certificate")
                        .long("country"),
                )
                .arg(
                    Arg::with_name("destination-dir")
                        .takes_value(true)
                        .help("Writes key and certificate to the given path")
                        .default_value("keys")
                        .long("destination-dir"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("generate-key-and-cert", Some(sub_m)) => generate_key_and_cert(sub_m),
        _ => {
            println!("{}", matches.usage());
            Ok(())
        }
    }
}
