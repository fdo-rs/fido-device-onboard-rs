use anyhow::{bail, Result};

/// Checks whether the given string is sound to be a device identifier
// The device identification string ends up in the CN field of the X509
// certificate, which allows up to 64 characters.
// See https://github.com/fedora-iot/fido-device-onboard-rs/issues/447
pub fn check_device_identifier(identifier: &String) -> Result<()> {
    if identifier.len() > 64 {
        bail!(format!("{identifier} has more than 64 characters"));
    }
    Ok(())
}
