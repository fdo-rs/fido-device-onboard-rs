use std::{
    env::args,
    path::{Path, PathBuf},
};

use libcryptsetup_rs::{
    c_uint,
    consts::{flags::CryptVolumeKey, vals::EncryptionFormat},
    CryptInit, LibcryptErr, TokenInput,
};

#[macro_use]
extern crate serde_json;
use uuid::Uuid;

fn usage() -> &'static str {
    "Usage: format-luks2-with-token <DEVICE_PATH> <KEY_DESCRIPTION> <openable|unopenable>\n\
     \tDEVICE_PATH: Path to device to format\n\
     \tKEY_DESCRIPTION: Kernel keyring key description\n\
     \tKEY_DATA: Kernel keyring key data\n\
     \topenable|unopenable: openable to write the openable LUKS2 token to the keyslot"
}

enum Openable {
    Yes,
    No,
}

impl TryFrom<&String> for Openable {
    type Error = &'static str;

    fn try_from(v: &String) -> Result<Self, &'static str> {
        match v.as_str() {
            "openable" => Ok(Openable::Yes),
            "unopenable" => Ok(Openable::No),
            _ => Err("Unrecognized option for whether device should be openable"),
        }
    }
}

fn parse_args() -> Result<(PathBuf, String, String, Openable), &'static str> {
    let args: Vec<_> = args().collect();
    if args.len() != usage().split('\n').count() {
        println!("{}", usage());
        return Err("Incorrect arguments provided");
    }

    let device_string = args
        .get(1)
        .ok_or("Could not get the device path for the device node to be encrypted")?;
    let device_path = PathBuf::from(device_string);
    if !device_path.exists() {
        return Err("Device does not exist");
    }

    let key_description = args
        .get(2)
        .ok_or("No kernel keyring key description was provided")?;

    let key_data = args
        .get(3)
        .ok_or("No kernel keyring key data was provided")?;

    let openable_string = args
        .get(4)
        .ok_or("Could not determine whether device should be openable or not")?;
    let openable = Openable::try_from(openable_string)?;

    Ok((
        device_path,
        key_description.to_string(),
        key_data.to_string(),
        openable,
    ))
}

fn format(dev: &Path, key_data: &str) -> Result<c_uint, LibcryptErr> {
    let mut device = CryptInit::init(dev)?;
    device.context_handle().format::<()>(
        EncryptionFormat::Luks2,
        ("aes", "xts-plain"),
        None,
        libcryptsetup_rs::Either::Right(256 / 8),
        None,
    )?;
    let keyslot = device.keyslot_handle().add_by_key(
        None,
        None,
        key_data.as_bytes(),
        CryptVolumeKey::empty(),
    )?;

    Ok(keyslot)
}

fn luks2_token_handler(
    dev: &Path,
    key_description: &str,
    keyslot: c_uint,
) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(dev)?;
    device
        .context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)?;
    let mut token = device.token_handle();
    let token_num = token.luks2_keyring_set(None, key_description)?;
    token.assign_keyslot(token_num, Some(keyslot))?;
    Ok(())
}

fn proto_token_handler(dev: &Path, key_description: &str) -> Result<(), LibcryptErr> {
    let mut device = CryptInit::init(dev)?;
    device
        .context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)?;
    let mut token = device.token_handle();
    let _ = token.json_set(TokenInput::AddToken(&json!({
        "type": "proto",
        "keyslots": [],
        "a_uuid": Uuid::new_v4().as_simple().to_string(),
        "key_description": key_description
    })));
    Ok(())
}

fn main() -> Result<(), String> {
    let (path, key_description, key_data, openable) = parse_args()?;
    let keyslot = format(&path, &key_data).map_err(|e| e.to_string())?;
    luks2_token_handler(&path, &key_description, keyslot).map_err(|e| e.to_string())?;
    if let Openable::Yes = openable {
        proto_token_handler(&path, &key_description).map_err(|e| e.to_string())?;
    };
    Ok(())
}
