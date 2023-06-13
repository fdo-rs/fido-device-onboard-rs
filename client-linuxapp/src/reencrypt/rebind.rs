use std::{io::Write, process::Command};

use anyhow::{anyhow, bail, Context, Result};
use libcryptsetup_rs::CryptDevice;
use secrecy::{ExposeSecret, Secret};

fn get_clevis_token(dev: &mut CryptDevice) -> Result<u32> {
    let mut clevis_token = None;
    let mut handle = dev.token_handle();

    for i in 0..10 {
        match handle.status(i).context("Error getting token status")? {
            libcryptsetup_rs::CryptTokenInfo::ExternalUnknown(name) if name == "clevis" => {
                if clevis_token.is_some() {
                    bail!("Multiple clevis tokens encountered");
                }
                clevis_token = Some(i);
            }
            libcryptsetup_rs::CryptTokenInfo::ExternalUnknown(name) => {
                log::trace!("External(unknown) token encountered with name {:?}", name)
            }
            libcryptsetup_rs::CryptTokenInfo::External(name) => {
                log::trace!("External token encountered with name {:?}", name)
            }
            libcryptsetup_rs::CryptTokenInfo::InternalUnknown(name) => {
                log::trace!("Internal(unknown) token encountered with name {:?}", name)
            }
            libcryptsetup_rs::CryptTokenInfo::Internal(name) => {
                log::trace!("Internal token encountered with name {:?}", name)
            }
            libcryptsetup_rs::CryptTokenInfo::Invalid => log::trace!("Invalid token encountered"),
            libcryptsetup_rs::CryptTokenInfo::Inactive => {}
        }
    }

    log::trace!("Clevis token is at {:?}", clevis_token);

    clevis_token.ok_or_else(|| anyhow!("No clevis token found"))
}

fn get_clevis_keyslot(dev: &mut CryptDevice, clevis_token: u32) -> Result<u32> {
    dev.token_handle()
        .json_get(clevis_token)
        .context("Error getting clevis token json")?
        .as_object()
        .ok_or_else(|| anyhow!("Invalid JSON type returned from clevis token"))?
        .get("keyslots")
        .ok_or_else(|| anyhow!("No keyslots found in clevis token"))?
        .as_array()
        .ok_or_else(|| anyhow!("Invalid JSON type returned from clevis token keyslots"))?
        .get(0)
        .ok_or_else(|| anyhow!("No keyslots found in clevis token"))?
        .as_str()
        .ok_or_else(|| anyhow!("Invalid JSON type returned from clevis token keyslot"))?
        .parse()
        .context("Error parsing clevis token keyslot")
}

pub(super) fn get_clevis_token_slot_pass(
    dev: &mut CryptDevice,
) -> Result<(u32, u32, Secret<Vec<u8>>)> {
    let clevis_token = get_clevis_token(dev).context("Error getting clevis token ID")?;
    let clevis_slot =
        get_clevis_keyslot(dev, clevis_token).context("error getting clevis keyslot")?;

    log::trace!("Clevis slot: {}", clevis_slot);

    let path = dev
        .status_handle()
        .get_device_path()
        .context("Error getting device path")?
        .to_path_buf();

    let output = Command::new("clevis")
        .arg("luks")
        .arg("pass")
        .arg("-d")
        .arg(path)
        .arg("-s")
        .arg(clevis_slot.to_string())
        .output()
        .context("Error calling clevis to get password")?;

    let pass = secrecy::Secret::new(output.stdout);

    if !output.status.success() {
        bail!(
            "Error getting password from Clevis, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    log::trace!("Retrieved clevis password");

    Ok((clevis_token, clevis_slot, pass))
}

fn clevis_bind(
    dev: &mut CryptDevice,
    password: &[u8],
    new_pin: &str,
    new_pin_config: &str,
) -> Result<()> {
    let path = dev
        .status_handle()
        .get_device_path()
        .context("Error getting device path")?
        .to_path_buf();

    log::trace!("Initiating clevis bind");

    let mut child = Command::new("clevis")
        .arg("luks")
        .arg("bind")
        .arg("-d")
        .arg(path)
        .arg(new_pin)
        .arg(new_pin_config)
        .arg("-y")
        .arg("-k")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Error calling clevis to bind")?;

    log::trace!("Sending clevis password");
    // Extra scope so that the ChildStdin gets dropped, which closes the pipe
    {
        let mut stdin = child.stdin.take().context("Error taking stdin")?;
        stdin
            .write_all(password)
            .context("Error writing password to clevis")?;
        writeln!(stdin).context("Error writing newline to clevis")?;
        stdin.flush().context("Error flushing clevis stdin")?;
    }

    let output = child
        .wait_with_output()
        .context("Error waiting for clevis to bind")?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Failed to bind clevis: {:?}, stdout: {}, stderr: {}",
            output.status,
            stdout,
            stderr
        );
    }

    log::trace!("Clevis bind successful");

    dev.context_handle()
        .load::<()>(None, None)
        .context("Error re-loading device context")?;

    log::trace!("Reloaded device context");

    Ok(())
}

fn delete_clevis_token_and_slot(
    dev: &mut CryptDevice,
    clevis_token: u32,
    clevis_slot: u32,
) -> Result<()> {
    log::trace!(
        "Deleting clevis token: {}, slot: {}",
        clevis_token,
        clevis_slot
    );

    dev.token_handle()
        .json_set(libcryptsetup_rs::TokenInput::RemoveToken(clevis_token))
        .context("Error removing clevis token")?;
    dev.keyslot_handle()
        .destroy(clevis_slot)
        .context("Error removing clevis slot")?;

    log::trace!("Clevis token and slot removed");

    Ok(())
}

pub(crate) fn rebind_clevis(
    dev: &mut CryptDevice,
    new_pin: &str,
    new_pin_config: &str,
) -> Result<()> {
    let (clevis_token, clevis_slot, clevis_pass) =
        get_clevis_token_slot_pass(dev).context("Error getting clevis password")?;
    clevis_bind(dev, clevis_pass.expose_secret(), new_pin, new_pin_config)
        .context("Error binding clevis")?;
    delete_clevis_token_and_slot(dev, clevis_token, clevis_slot)
        .context("Error deleting old clevis token and slot")?;

    Ok(())
}
