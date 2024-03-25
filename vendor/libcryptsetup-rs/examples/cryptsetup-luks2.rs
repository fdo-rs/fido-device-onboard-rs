// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    env::args,
    io,
    path::{Path, PathBuf},
};

use libcryptsetup_rs::{
    consts::{
        flags::{CryptActivate, CryptDeactivate, CryptVolumeKey},
        vals::EncryptionFormat,
    },
    CryptInit, LibcryptErr,
};

enum CryptCommand {
    Encrypt(PathBuf),
    Open(PathBuf, String),
    Deactivate(PathBuf, String),
}

fn parse_args() -> Result<CryptCommand, LibcryptErr> {
    let mut args = args();
    let _ = args.next();
    let command = args.next();
    match command.as_deref() {
        Some("encrypt") => {
            let dev = PathBuf::from(match args.next() {
                Some(p) => p,
                None => {
                    return Err(LibcryptErr::Other(
                        "Device path for device to be encrypted is required".to_string(),
                    ))
                }
            });
            if dev.exists() {
                Ok(CryptCommand::Encrypt(dev))
            } else {
                Err(LibcryptErr::IOError(io::Error::from(
                    io::ErrorKind::NotFound,
                )))
            }
        }
        Some("open") => {
            let dev = PathBuf::from(match args.next() {
                Some(p) => p,
                None => {
                    return Err(LibcryptErr::Other(
                        "Device path for device to be opened is required".to_string(),
                    ))
                }
            });
            if !dev.exists() {
                return Err(LibcryptErr::IOError(io::Error::from(
                    io::ErrorKind::NotFound,
                )));
            }
            let name = args.next().ok_or_else(|| {
                LibcryptErr::Other("Name for mapped device is required".to_string())
            })?;
            Ok(CryptCommand::Open(dev, name))
        }
        Some("close") => {
            let dev = PathBuf::from(match args.next() {
                Some(p) => p,
                None => {
                    return Err(LibcryptErr::Other(
                        "Device path for device to be closed is required".to_string(),
                    ))
                }
            });
            if !dev.exists() {
                return Err(LibcryptErr::IOError(io::Error::from(
                    io::ErrorKind::NotFound,
                )));
            }
            let name = args.next().ok_or_else(|| {
                LibcryptErr::Other("Name for mapped device is required".to_string())
            })?;
            Ok(CryptCommand::Deactivate(dev, name))
        }
        Some(s) => Err(LibcryptErr::Other(format!("Unrecognized command {s}"))),
        None => Err(LibcryptErr::Other("Missing command".to_string())),
    }
}

fn encrypt(path: &Path) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(path)?;
    device.context_handle().format::<()>(
        EncryptionFormat::Luks2,
        ("aes", "xts-plain"),
        None,
        libcryptsetup_rs::Either::Right(256 / 8),
        None,
    )?;
    device
        .keyslot_handle()
        .add_by_key(None, None, b"changeme", CryptVolumeKey::empty())?;
    Ok(())
}

fn activate(path: &Path, name: &str) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(path)?;
    device
        .context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)?;
    device.activate_handle().activate_by_passphrase(
        Some(name),
        None,
        b"changeme",
        CryptActivate::empty(),
    )?;
    Ok(())
}

fn deactivate(path: &Path, name: &str) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(path)?;
    device
        .context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)?;
    device
        .activate_handle()
        .deactivate(name, CryptDeactivate::empty())?;
    Ok(())
}

fn main() -> Result<(), LibcryptErr> {
    let args = parse_args()?;
    if let CryptCommand::Encrypt(ref path) = args {
        encrypt(path)?;
    } else if let CryptCommand::Open(ref path, ref name) = args {
        activate(path, name)?;
    } else if let CryptCommand::Deactivate(ref path, ref name) = args {
        deactivate(path, name)?;
    }
    Ok(())
}
