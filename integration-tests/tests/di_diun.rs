mod common;
use common::{Binary, LogSide, TestContext};
use lazy_static::lazy_static;
use regex::Regex;
use std::path::Path;
use std::time::Duration;

use fdo_util::device_identification::check_device_identifier;

use anyhow::{bail, Context, Result};

use std::fs;

const L: LogSide = LogSide::Test;

#[tokio::test]
async fn test_device_credentials_already_active() -> Result<()> {
    let mut ctx = TestContext::new().context("Error building test context")?;
    let mfg_server = ctx
        .start_test_server(
            Binary::ManufacturingServer,
            |cfg| {
                Ok(cfg.prepare_config_file(None, |cfg| {
                    cfg.insert("rendezvous_port", "1337");
                    cfg.insert("diun_key_type", "FileSystem");
                    cfg.insert("device_identification_format", "SerialNumber");
                    cfg.insert("plain_di", "false"); // TODO
                    Ok(())
                })?)
            },
            |_| Ok(()),
        )
        .context("Error creating manufacturing server")?;
    ctx.wait_until_servers_ready()
        .await
        .context("Error waiting for servers to start")?;

    let client_result = ctx
        .run_client(
            Binary::ManufacturingClient,
            Some(&mfg_server),
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL_FILENAME", "devicecredential.dc")
                    .env("MANUFACTURING_INFO", "testdevice")
                    .env("DIUN_PUB_KEY_INSECURE", "true");
                Ok(())
            },
            Duration::from_secs(5),
        )
        .context("Error running manufacturing client")?;
    client_result
        .expect_success()
        .context("Manufacturing client failed")?;
    client_result.expect_stderr_line("Trusting any certificate as root")?;

    let dc_path = client_result.client_path().join("devicecredential.dc");
    L.l(format!("Device Credential should be in {:?}", dc_path));

    let client_result = ctx
        .run_client(
            Binary::ManufacturingClient,
            Some(&mfg_server),
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL_FILENAME", "devicecredential.dc")
                    .env("MANUFACTURING_INFO", "testdevice")
                    .env("DEVICE_CREDENTIAL", dc_path)
                    .env("DIUN_PUB_KEY_INSECURE", "true");
                Ok(())
            },
            Duration::from_secs(5),
        )
        .context("Error running manufacturing client")?;
    client_result
        .expect_success()
        .context("Manufacturing client failed")?;
    client_result.expect_stderr_line("Device credential already active")?;

    Ok(())
}

#[tokio::test]
async fn test_device_identifiers() -> Result<()> {
    // Check the different device identifiers that we use
    // MAC
    let (_, mac) = get_valid_iface_and_mac().await?;
    assert!(check_device_identifier(&mac).is_ok());
    // Serial number
    let serial_number = fs::read_to_string("/sys/devices/virtual/dmi/id/product_serial")
        .or_else(|_| fs::read_to_string("/sys/devices/virtual/dmi/id/chassis_serial"));
    if serial_number.is_ok() {
        assert!(check_device_identifier(&serial_number.unwrap()).is_ok());
    }
    // this one should error
    let more_than_64_characters =
        "invaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaalid".to_string();
    assert!(check_device_identifier(&more_than_64_characters).is_err());
    Ok(())
}

#[tokio::test]
async fn test_device_credentials_generated_with_mac_address() -> Result<()> {
    let mut ctx = TestContext::new().context("Error building test context")?;

    let mfg_server = ctx
        .start_test_server(
            Binary::ManufacturingServer,
            |cfg| {
                Ok(cfg.prepare_config_file(None, |cfg| {
                    cfg.insert("rendezvous_port", "1337");
                    cfg.insert("diun_key_type", "FileSystem");
                    cfg.insert("device_identification_format", "MACAddress");
                    cfg.insert("plain_di", "false"); // TODO
                    Ok(())
                })?)
            },
            |_| Ok(()),
        )
        .context("Error creating manufacturing server")?;
    ctx.wait_until_servers_ready()
        .await
        .context("Error waiting for servers to start")?;

    // loopback should have an invalid MAC Address, we expect failure in this case
    let client_result = ctx
        .run_client(
            Binary::ManufacturingClient,
            Some(&mfg_server),
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL_FILENAME", "devicecredential.dc")
                    .env("DI_MFG_STRING_TYPE", "mac_address")
                    .env("DI_MFG_STRING_TYPE_MAC_IFACE", "lo")
                    .env("DIUN_PUB_KEY_INSECURE", "true");
                Ok(())
            },
            Duration::from_secs(5),
        )
        .context("Error running manufacturing client")?;
    client_result.expect_failure()?;

    // Generate device credentials with MAC address as the device identification
    // method
    let (iface, _) = get_valid_iface_and_mac().await?;
    let client_result = ctx
        .run_client(
            Binary::ManufacturingClient,
            Some(&mfg_server),
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL_FILENAME", "devicecredential.dc")
                    .env("DI_MFG_STRING_TYPE", "mac_address")
                    .env("DI_MFG_STRING_TYPE_MAC_IFACE", iface)
                    .env("DIUN_PUB_KEY_INSECURE", "true");
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
    assert!(Path::new(&dc_path).exists());

    Ok(())
}

async fn get_valid_iface_and_mac() -> Result<(String, String)> {
    let paths = fs::read_dir("/sys/class/net").context("No /sys/class/net dir found")?;
    let ifaces = paths
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect::<Vec<String>>();
    for iface in ifaces {
        let mac = fs::read_to_string(format!("/sys/class/net/{iface}/address"))
            .context("Error reading MAC address")?;
        let mac = mac.as_str().trim();
        lazy_static! {
            static ref RE: Regex =
                Regex::new(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$").unwrap();
        }
        if RE.is_match(mac) && !mac.eq("00:00:00:00:00:00") {
            L.l(format!("Selected iface {iface} with MAC address {mac}"));
            return Ok((iface, mac.to_string()));
        }
    }
    bail!("No valid iface found")
}

// This is a same test with test_device_credentials_already_active but just using plain-di.
#[tokio::test]
async fn test_plain_di() -> Result<()> {
    let mut ctx = TestContext::new().context("Error building test context")?;
    let mfg_server = ctx
        .start_test_server(
            Binary::ManufacturingServer,
            |cfg| {
                let result = cfg.prepare_config_file(None, |cfg| {
                    cfg.insert("rendezvous_port", "1337");
                    cfg.insert("diun_key_type", "FileSystem");
                    cfg.insert("device_identification_format", "SerialNumber");
                    cfg.insert("plain_di", "true");
                    Ok(())
                })?;
                return Ok(result);
            },
            |_| Ok(()),
        )
        .context("Error creating manufacturing server")?;
    ctx.wait_until_servers_ready()
        .await
        .context("Error waiting for servers to start")?;

    let diun_cert = ctx.keys_path().join("diun_key.der");
    let hmac_cert = ctx.keys_path().join("diun_key.der");

    let client_result = ctx
        .run_client(
            Binary::ManufacturingClient,
            Some(&mfg_server),
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL_FILENAME", "devicecredential.dc")
                    //.env("MANUFACTURING_INFO", "diun_cert.pem")
                    .env("MANUFACTURING_INFO", "testdevice")
                    .env("DIUN_PUB_KEY_INSECURE", "true")
                    .env("USE_PLAIN_DI", "true")
                    .env("DI_KEY_STORAGE_TYPE", "FileSystem")
                    .env("DI_SIGN_KEY_PATH", diun_cert)
                    .env("DI_HMAC_KEY_PATH", hmac_cert)
                    ;
                Ok(())
            },
            Duration::from_secs(5),
        )
        .context("Error running manufacturing client")?;
    client_result
        .expect_success()
        .context("Manufacturing client failed")?;

    // No log in plain-di.
    // client_result.expect_stderr_line("Trusting any certificate as root")?;

    let dc_path = client_result.client_path().join("devicecredential.dc");
    L.l(format!("Device Credential should be in {:?}", dc_path));

    let client_result = ctx
        .run_client(
            Binary::ManufacturingClient,
            Some(&mfg_server),
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL_FILENAME", "devicecredential.dc")
                    //.env("MANUFACTURING_INFO", "diun_cert.pem")
                    .env("MANUFACTURING_INFO", "testdevice")
                    .env("DEVICE_CREDENTIAL", dc_path)
                    .env("DIUN_PUB_KEY_INSECURE", "true");
                Ok(())
            },
            Duration::from_secs(5),
        )
        .context("Error running manufacturing client")?;
    client_result
        .expect_success()
        .context("Manufacturing client failed")?;
    client_result.expect_stderr_line("Device credential already active")?;

    Ok(())
}
