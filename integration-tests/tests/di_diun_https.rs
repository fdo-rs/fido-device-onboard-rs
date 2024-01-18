mod common;
use anyhow::{Context, Result};
use common::{Binary, LogSide, TestContext};
use std::path::Path;
use std::time::Duration;
const L: LogSide = LogSide::Test;

#[tokio::test]
async fn di_diun_https_test() -> Result<()> {
    let mut ctx = TestContext::new().context("Error building test context")?;

    let mfg_server = ctx
        .start_test_server(
            Binary::ManufacturingServer,
            |cfg| {
                Ok(cfg.prepare_config_file(None, |cfg| {
                    cfg.insert("rendezvous_port", "1337");
                    cfg.insert("diun_key_type", "FileSystem");
                    cfg.insert("device_identification_format", "SerialNumber");
                    //  cfg.insert("manufacturing_server_https_cert_path", "/workspaces/fido-device-onboard-rs/integration-tests/tests/test-data/https-test");
                    //  cfg.insert("manufacturing_server_https_key_path", "/workspaces/fido-device-onboard-rs/integration-tests/tests/test-data/https-test");
                    // cfg.insert("bind_http", "8085");
                    // cfg.insert("bind_https", &("127.0.0.1:{}" ));
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
                    .env("MANUFACTURING_SERVER_URL", "https://localhost:8086")
                    .env("DEV_ENVIRONMENT", "1")
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
