mod common;
use std::{fs, path::Path, time::Duration};

use common::{Binary, LogSide, TestContext};

use anyhow::{Context, Result};
use fdo_data_formats::{devicecredential::FileDeviceCredential, types::Guid};

const L: LogSide = LogSide::Test;

#[tokio::test]
async fn test_to() -> Result<()> {
    let mut ctx = TestContext::new().context("Error building test context")?;

    let rendezvous_server = ctx
        .start_test_server(
            Binary::RendezvousServer,
            |cfg| Ok(cfg.prepare_config_file(None, |_| Ok(()))?),
            |_| Ok(()),
        )
        .context("Error creating rendezvous server")?;
    let owner_onboarding_server = ctx
        .start_test_server(
            Binary::OwnerOnboardingServer,
            |cfg| Ok(cfg.prepare_config_file(None, |_| Ok(()))?),
            |_| Ok(()),
        )
        .context("Error creating rendezvous server")?;
    ctx.wait_until_servers_ready()
        .await
        .context("Error waiting for servers to start")?;

    let dc_path = ctx.testpath().join("testdevice.dc");
    let ov_path = ctx.testpath().join("testdevice.ov");
    let rendezvous_info_path = ctx.testpath().join("rendezvous-info.yml");
    let owner_address_path = ctx.testpath().join("owner-addresses.yml");
    let key_path = ctx.keys_path();

    L.l("Generating configuration files");
    ctx.generate_config_file(&rendezvous_info_path, "rendezvous-info.yml", |cfg| {
        cfg.insert("rendezvous_port", &rendezvous_server.server_port().unwrap());
        Ok(())
    })
    .context("Error generating rendezvous-info.yml")?;
    ctx.generate_config_file(&owner_address_path, "owner-addresses.yml", |cfg| {
        cfg.insert(
            "owner_port",
            &owner_onboarding_server.server_port().unwrap(),
        );
        Ok(())
    })
    .context("Error generating owner-addresses.yml")?;

    let owner_output = ctx
        .run_owner_tool(
            &key_path,
            &[
                "initialize-device",
                &format!(
                    "--device-cert-ca-chain={}",
                    key_path.join("device_ca_cert.pem").to_str().unwrap()
                ),
                &format!(
                    "--device-cert-ca-private-key={}",
                    key_path.join("device_ca_key.der").to_str().unwrap()
                ),
                &format!(
                    "--manufacturer-cert={}",
                    key_path.join("manufacturer_cert.pem").to_str().unwrap()
                ),
                &format!(
                    "--rendezvous-info={}",
                    rendezvous_info_path.to_str().unwrap()
                ),
                "testdevice",
                ov_path.to_str().unwrap(),
                dc_path.to_str().unwrap(),
            ],
        )
        .context("Error running initialize-device")?;
    owner_output
        .expect_success()
        .context("initialize-device failed")?;

    for (source, target) in &[("manufacturer", "reseller"), ("reseller", "owner")] {
        let owner_output = ctx
            .run_owner_tool(
                &key_path,
                &[
                    "extend-ownership-voucher",
                    ov_path.to_str().unwrap(),
                    &format!(
                        "--current-owner-private-key={}",
                        key_path
                            .join(format!("{}_key.der", source))
                            .to_str()
                            .unwrap()
                    ),
                    &format!(
                        "--new-owner-cert={}",
                        key_path
                            .join(format!("{}_cert.pem", target))
                            .to_str()
                            .unwrap()
                    ),
                ],
            )
            .with_context(|| {
                format!(
                    "Error running extend-ownership-voucher ({} -> {})",
                    source, target
                )
            })?;
        owner_output.expect_success().with_context(|| {
            format!("extend-ownership-voucher ({} -> {}) failed", source, target)
        })?;
    }

    let owner_output = ctx
        .run_owner_tool(
            &key_path,
            &[
                "report-to-rendezvous",
                &format!("--ownership-voucher={}", ov_path.to_str().unwrap()),
                &format!(
                    "--owner-private-key={}",
                    key_path.join("owner_key.der").to_str().unwrap()
                ),
                &format!(
                    "--owner-addresses-path={}",
                    owner_address_path.to_str().unwrap()
                ),
                "--wait-time=600",
            ],
        )
        .context("Error running report-to-rendezvous")?;
    owner_output
        .expect_success()
        .context("report-to-rendezvous failed")?;

    let device_guid = determine_device_credential_guid(&dc_path)
        .context("Error determining device GUID")?
        .to_string();
    L.l(format!("Device GUID: {:?}", device_guid));

    let ov_to = ctx
        .runner_path(&owner_onboarding_server)
        .join("ownership_vouchers")
        .join(&device_guid);
    L.l(format!(
        "Copying Ownership Voucher {:?} -> {:?}",
        ov_path, ov_to
    ));
    fs::copy(&ov_path, &ov_to).context("Error copying ownership voucher")?;

    let ssh_authorized_keys_path = ctx.testpath().join("authorized_keys");
    let marker_file_path = ctx.testpath().join("marker");
    let output = ctx
        .run_client(
            Binary::ClientLinuxapp,
            None,
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL", dc_path.to_str().unwrap())
                    .env("SSH_KEY_PATH", &ssh_authorized_keys_path.to_str().unwrap())
                    .env(
                        "DEVICE_ONBOARDING_EXECUTED_MARKER_FILE_PATH",
                        &marker_file_path.to_str().unwrap(),
                    );
                Ok(())
            },
            Duration::from_secs(5),
        )
        .context("Error running client")?;
    output.expect_success().context("client failed")?;

    pretty_assertions::assert_eq!(
        fs::read_to_string(&marker_file_path).context("Error reading marker file")?,
        "executed"
    );
    pretty_assertions::assert_eq!(
        fs::read_to_string(&ssh_authorized_keys_path)
            .context("Error reading authorized SSH keys")?,
        "
# These keys are installed by FIDO Device Onboarding
testkey
# End of FIDO Device Onboarding keys
"
    );

    Ok(())
}

fn determine_device_credential_guid(path: &Path) -> Result<Guid> {
    let dc_contents = fs::read(path).context("Error reading device credential")?;
    let dc: FileDeviceCredential =
        serde_cbor::from_slice(&dc_contents).context("Error deserializing device credential")?;
    Ok(dc.guid)
}
