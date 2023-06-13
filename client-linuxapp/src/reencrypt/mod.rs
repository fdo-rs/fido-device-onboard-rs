use std::{io::Write, process::Command};

use anyhow::{bail, Context, Result};
use libcryptsetup_rs::CryptDevice;
use secrecy::ExposeSecret;

pub(crate) mod rebind;

pub(crate) fn initiate_reencrypt(mut dev: CryptDevice) -> Result<()> {
    let (_, clevis_slot, clevis_pass) = rebind::get_clevis_token_slot_pass(&mut dev)
        .context("Error getting new clevis password")?;
    let path = dev
        .status_handle()
        .get_device_path()
        .context("Error getting device path")?
        .to_path_buf();
    log::debug!("Reencrypting device {}", path.display());

    let mut child = Command::new("cryptsetup")
        .arg("reencrypt")
        .arg("--init-only")
        .arg(path)
        .arg("--key-file")
        .arg("-")
        .arg("--key-slot")
        .arg(clevis_slot.to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Error starting cryptsetup for reencrypt")?;

    // Extra scope so that the ChildStdin gets dropped, which closes the pipe
    {
        let mut stdin = child.stdin.take().context("Error taking stdin")?;
        stdin
            .write_all(clevis_pass.expose_secret())
            .context("Error writing password to clevis")?;
        stdin.flush().context("Error flushing clevis stdin")?;
    }

    let output = child
        .wait_with_output()
        .context("Error waiting for clevis to bind")?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Failed to initialize reencrypt: {:?}, stdout: {}, stderr: {}",
            output.status,
            stdout,
            stderr
        );
    }

    Ok(())
}

fn perform_reencrypt(dev_name: &str) -> Result<()> {
    log::debug!("Checking if reencrypt is in progress");

    let mut dev = libcryptsetup_rs::CryptInit::init_by_name_and_header(dev_name, None)
        .context("Error opening device")?;

    dev.context_handle()
        .load::<()>(None, None)
        .context("Error loading device context")?;

    let status = dev
        .reencrypt_handle()
        .status(libcryptsetup_rs::CryptParamsReencrypt {
            mode: libcryptsetup_rs::consts::vals::CryptReencryptModeInfo::Reencrypt,
            direction: libcryptsetup_rs::consts::vals::CryptReencryptDirectionInfo::Forward,
            resilience: String::from("journal"),
            hash: String::from("sha256"),
            data_shift: 0,
            max_hotzone_size: 0,
            device_size: 0,
            luks2: libcryptsetup_rs::CryptParamsLuks2 {
                pbkdf: None,
                integrity: None,
                integrity_params: None,
                data_alignment: 0,
                data_device: None,
                sector_size: 0,
                label: None,
                subsystem: None,
            },
            flags: libcryptsetup_rs::consts::flags::CryptReencrypt::empty(),
        })
        .context("Error getting reencryption status")?;

    if !matches!(
        status,
        libcryptsetup_rs::consts::vals::CryptReencryptInfo::None
    ) {
        log::info!("Reencryption of {} in progress, resuming", dev_name);

        let (_, _, clevis_pass) = rebind::get_clevis_token_slot_pass(&mut dev)
            .context("Error getting new clevis password")?;

        let mut child = Command::new("cryptsetup")
            .arg("reencrypt")
            .arg("--resume-only")
            .arg("--active-name")
            .arg(dev_name)
            .arg("--key-file")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("Error starting cryptsetup for reencrypt")?;

        // Extra scope so that the ChildStdin gets dropped, which closes the pipe
        {
            let mut stdin = child.stdin.take().context("Error taking stdin")?;
            stdin
                .write_all(clevis_pass.expose_secret())
                .context("Error writing password to clevis")?;
            stdin.flush().context("Error flushing clevis stdin")?;
        }
        let output = child
            .wait_with_output()
            .context("Error waiting for reencrypt resume")?;

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "Failed to resume reencrypt: {:?}, stdout: {}, stderr: {}",
                output.status,
                stdout,
                stderr
            );
        }
    } else {
        log::debug!("Re-encryption not required");
    }

    Ok(())
}

pub(super) fn perform_required_reencrypts() -> Result<()> {
    log::debug!("Checking for required reencrypts");

    let dm_ctx = devicemapper::DM::new().context("Error getting device mapper context")?;

    for (dm_name, _, _) in dm_ctx
        .list_devices()
        .context("Error getting device mapper devices")?
    {
        let dm_display_name = String::from_utf8_lossy(dm_name.as_bytes());
        log::debug!("Checking device: {}", dm_display_name);

        let dev_info = dm_ctx
            .device_info(&devicemapper::DevId::Name(&dm_name))
            .context("Error getting device mapper device info")?;
        if let Some(uuid) = dev_info.uuid() {
            let uuid = String::from_utf8_lossy(uuid.as_bytes());
            if uuid.starts_with("CRYPT-LUKS2-") {
                perform_reencrypt(&dm_display_name)?;
            }
        }
    }

    Ok(())
}
