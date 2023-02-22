mod common;
use anyhow::{bail, Context, Result};
use common::{Binary, LogSide, TestContext};
use lazy_static::lazy_static;
use regex::Regex;
use std::time::Duration;

const L: LogSide = LogSide::Test;

#[tokio::test]
async fn test_device_info_serialnumber_ext() -> Result<()> {
    let mut ctx = TestContext::new().context("Error building test context")?;

    //Important to add cfg serial_number_format as StructuredDeviceInfo to test this feature
    let mfg_server = ctx
        .start_test_server(
            Binary::ManufacturingServer,
            |cfg| {
                cfg.prepare_config_file(None, |cfg| {
                    cfg.insert("rendezvous_port", "1337");
                    cfg.insert("diun_key_type", "FileSystem");
                    cfg.insert("serial_number_format", "StructuredDeviceInfo");
                    Ok(())
                })
            },
            |_| Ok(()),
        )
        .context("Error creating manufacturing server")?;
    ctx.wait_until_servers_ready()
        .await
        .context("Error waiting for servers to start")?;

    let diun_cert_path = ctx
        .keys_path()
        .join("diun_cert.pem")
        .to_string_lossy()
        .to_string();

    let client_result = ctx
        .run_client(
            Binary::ManufacturingClient,
            Some(&mfg_server),
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL_FILENAME", "devicecredential.dc")
                    .env("DIUN_PUB_KEY_INSECURE", "true")
                    .env("DIUN_PUB_KEY_ROOTCERTS", diun_cert_path);
                Ok(())
            },
            Duration::from_secs(5),
        )
        .context("Error running manufacturing client")?;
    client_result
        .expect_success()
        .context("Manufacturing client failed")?;

    let dc_path = client_result.client_path().join("devicecredential.dc");
    L.l(format!("Device Credential should be in {:?}", dc_path));

    let owner_output = ctx
        .run_owner_tool(
            client_result.client_path(),
            &["dump-device-credential", dc_path.to_str().unwrap()],
        )
        .context("Error running dump-device-credential")?;
    owner_output
        .expect_success()
        .context("Dump-device-credential failed")?;

    if owner_output.raw_stdout().is_empty() {
        bail!("test_device_info_serialnumber_ext failed:dump-device-credential is empty ");
    }
    for line in owner_output.raw_stdout().split(|&b| b == b'\n') {
        if let Ok(line_str) = std::str::from_utf8(line) {
            if line_str.starts_with("Device Info:") {
                lazy_static! {
                    static ref MAC_REGEX: Regex =
                        Regex::new(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$").unwrap();
                }

                for item in line_str.split(';') {
                    if let Some(iface) = item.strip_prefix("IFACE_") {
                        let parts: Vec<&str> = iface.split('=').collect();
                        let mac_address = parts[1];
                        if MAC_REGEX.is_match(mac_address) {
                            L.l(format!(
                                "Found valid MAC address: test_device_info_serial_number passes {}",
                                mac_address
                            ));
                        } else {
                            bail!(
                                "Invalid MAC address: test_device_info_serial_number failed {}",
                                mac_address
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
