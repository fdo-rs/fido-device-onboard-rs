mod common;
use std::time::Duration;

use common::{Binary, LogSide, TestContext};

use anyhow::{Context, Result};

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
                    cfg.insert("serial_number_format", "SerialNumber");
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
                    .env("MANUFACTURING_INFO", "testdevicetestdevicetestdevicetestdevicetestdevicetestdevicetestdevice")
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
                    .env("MANUFACTURING_INFO", "testdevicetestdevicetestdevicetestdevicetestdevicetestdevicetestdevice")
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
