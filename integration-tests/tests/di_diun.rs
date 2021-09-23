mod common;
use common::*;

use anyhow::{bail, Context, Result};
#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

const L: LogSide = LogSide::Test;

#[tokio::test]
async fn test_diun() -> Result<()> {
    let mut ctx = TestContext::new().context("Error building test context")?;

    let mfg_server = ctx
        .start_test_server(
            Binary::ManufacturingServer,
            |cfg| {
                cfg.prepare_config_file(None, |_| Ok(()))?;
                cfg.create_empty_storage_folder("sessions")?;
                cfg.create_empty_storage_folder("ownership_vouchers")?;
                Ok(())
            },
            |_| Ok(()),
        )
        .context("Error creating manufacturing server")?;
    ctx.wait_until_servers_ready()
        .await
        .context("Error waiting for servers to start")?;

    let client_result = ctx
        .run_client(Binary::ManufacturingClient, Some(&mfg_server), |cfg| {
            cfg.env("DEVICE_CREDENTIAL_FILENAME", "devicecredential.dc")
                .env("MANUFACTURING_INFO", "testdevice")
                .env("DIUN_PUB_KEY_INSECURE", "true");
            Ok(())
        })
        .context("Error running manufacturing client")?;
    client_result
        .expect_success()
        .context("Manufacturing client failed")?;
    client_result.expect_stderr_line("Trusting any certificate as root")?;

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
    owner_output.expect_stdout_line("Active: true")?;

    let ov_dir = ctx
        .testpath()
        .join(mfg_server.name())
        .join("ownership_vouchers");
    let mut ov_files =
        std::fs::read_dir(ov_dir).context("Error reading ownership voucher directory")?;
    L.l(format!("Ownership Voucher files: {:?}", &ov_files));
    let ov_file = ov_files.next();
    if ov_file.is_none() {
        bail!("No ownership voucher files found");
    }
    let ov_file = ov_file
        .unwrap()
        .context("Error reading OV file directory")?;
    let num_count = ov_files.count() + 1; // The +1 is because we consumed the first item
    if num_count != 1 {
        bail!(
            "Invalid number of ownership vouchers: {}, expected 1",
            num_count
        );
    }
    L.l(format!("Ownership voucher path: {:?}", ov_file));

    let owner_output = ctx
        .run_owner_tool(
            client_result.client_path(),
            &["dump-ownership-voucher", ov_file.path().to_str().unwrap()],
        )
        .context("Error running dump-ownership-voucher")?;
    owner_output
        .expect_success()
        .context("Dump-ownership-voucher failed")?;
    owner_output.expect_stdout_line("Protocol Version: 100")?;
    owner_output.expect_stdout_line("Device Info: testdevice")?;
    owner_output.expect_stdout_line("commonName = \"testdevice\"")?;
    // It should have been extended to the "owner" time by the manufacturer
    owner_output.expect_stdout_line("Entry 0")?;

    Ok(())
}
