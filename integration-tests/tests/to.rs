mod common;
use std::{fs, os::unix::prelude::PermissionsExt, path::Path, time::Duration};

use common::{Binary, LogSide, TestContext};

use anyhow::{bail, Context, Result};
use fdo_data_formats::{devicecredential::FileDeviceCredential, types::Guid};

const L: LogSide = LogSide::Test;

#[tokio::test]
async fn test_to() -> Result<()> {
    let mut failed = Vec::new();

    for client_noninteroperable_kdf in [true, false] {
        for server_noninteroperable_kdf in [true, false] {
            L.l(format!("Starting test case, client_noninteroperable_kdf: {:?}, server_noninteroperable_kdf: {:?}", client_noninteroperable_kdf, server_noninteroperable_kdf));
            L.l("********************************************************============================================================");
            if let Err(e) =
                test_to_impl(client_noninteroperable_kdf, server_noninteroperable_kdf).await
            {
                L.l(format!("Test FAILED: {:?}", e));
                failed.push(TestCase {
                    client_noninteroperable_kdf,
                    server_noninteroperable_kdf,
                    error: e,
                });
            } else {
                L.l("Test passed");
            }
        }
    }

    if failed.is_empty() {
        Ok(())
    } else {
        for failed_case in failed {
            eprintln!("Failed test: {:?}", failed_case);
        }
        bail!("Some test cases failed");
    }
}

#[derive(Debug)]
struct TestCase {
    #[allow(dead_code)]
    client_noninteroperable_kdf: bool,
    #[allow(dead_code)]
    server_noninteroperable_kdf: bool,
    #[allow(dead_code)]
    error: anyhow::Error,
}

async fn test_to_impl(
    client_noninteroperable_kdf: bool,
    server_noninteroperable_kdf: bool,
) -> Result<()> {
    let mut ctx = TestContext::new().context("Error building test context")?;

    let rendezvous_server = ctx
        .start_test_server(
            Binary::RendezvousServer,
            |cfg| Ok(cfg.prepare_config_file(None, |_| Ok(()))?),
            |_| Ok(()),
        )
        .context("Error creating rendezvous server")?;
    let serviceinfo_api_server = ctx
        .start_test_server(
            Binary::ServiceInfoApiServer,
            |cfg| Ok(cfg.prepare_config_file(None, |_| Ok(()))?),
            |_| Ok(()),
        )
        .context("Error creating serviceinfo API dev server")?;
    let owner_onboarding_server = ctx
        .start_test_server(
            Binary::OwnerOnboardingServer,
            |cfg| {
                Ok(cfg.prepare_config_file(None, |cfg| {
                    cfg.insert(
                        "serviceinfo_api_server_port",
                        &serviceinfo_api_server.server_port().unwrap(),
                    );
                    Ok(())
                })?)
            },
            |cmd| {
                cmd.env("ALLOW_NONINTEROPERABLE_KDF", &"1");
                if server_noninteroperable_kdf {
                    cmd.env("FORCE_NONINTEROPERABLE_KDF", &"true");
                }
                Ok(())
            },
        )
        .context("Error creating owner server")?;
    ctx.wait_until_servers_ready()
        .await
        .context("Error waiting for servers to start")?;

    let dc_path = ctx.testpath().join("testdevice.dc");
    let ov_path = ctx.testpath().join("testdevice.ov");
    let rendezvous_info_path = ctx.testpath().join("rendezvous-info.yml");
    let key_path = ctx.keys_path();

    L.l("Generating configuration files");
    ctx.generate_config_file(&rendezvous_info_path, "rendezvous-info.yml", |cfg| {
        cfg.insert("rendezvous_port", &rendezvous_server.server_port().unwrap());
        Ok(())
    })
    .context("Error generating rendezvous-info.yml")?;

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

    let device_guid = determine_device_credential_guid(&dc_path)
        .context("Error determining device GUID")?
        .to_string();
    L.l(format!("Device GUID: {:?}", device_guid));

    let ov_to = ctx.testpath().join("ownership_vouchers").join(&device_guid);
    L.l(format!(
        "Converting Ownership Voucher {:?}(pem) -> {:?}(cose)",
        ov_path, ov_to
    ));

    let dump_output = ctx
        .run_owner_tool(
            &key_path,
            &[
                "dump-ownership-voucher",
                ov_path.to_str().unwrap(),
                "--outform",
                "cose",
            ],
        )
        .context("Error running dump-ownership-voucher")?;
    dump_output
        .expect_success()
        .context("dump-ownership-voucher failed")?;
    fs::write(ov_to, dump_output.raw_stdout())
        .context("Error writing ownership voucher to disk")?;

    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "http://localhost:{}/report-to-rendezvous", //DevSkim: ignore DS137138
            owner_onboarding_server.server_port().unwrap()
        ))
        .send()
        .await?;
    L.l(format!("Status code report-to-rendezvous {}", res.status()));

    let ssh_authorized_keys_path = ctx.testpath().join("authorized_keys");
    let marker_file_path = ctx.testpath().join("marker");
    let binary_file_path_prefix = ctx.testpath().join("binary_files");

    std::fs::create_dir(&binary_file_path_prefix).context("Error creating binary_files dir")?;

    let output = ctx
        .run_client(
            Binary::ClientLinuxapp,
            None,
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL", dc_path.to_str().unwrap())
                    .env("SSH_KEY_PATH", &ssh_authorized_keys_path.to_str().unwrap())
                    .env(
                        "BINARYFILE_PATH_PREFIX",
                        binary_file_path_prefix.to_str().unwrap(),
                    )
                    .env(
                        "DEVICE_ONBOARDING_EXECUTED_MARKER_FILE_PATH",
                        &marker_file_path.to_str().unwrap(),
                    )
                    .env("ALLOW_NONINTEROPERABLE_KDF", &"1");
                if client_noninteroperable_kdf {
                    cfg.env("FORCE_NONINTEROPERABLE_KDF", &"true");
                }
                Ok(())
            },
            Duration::from_secs(5),
        )
        .context("Error running client")?;
    output.expect_success().context("client failed")?;
    if client_noninteroperable_kdf {
        output.expect_stderr_line(
            "Forcing the use of non-interoperable KDF via environment variable",
        )?;
    }
    if client_noninteroperable_kdf || server_noninteroperable_kdf {
        output.expect_stderr_line("Using non-interoperable KDF")?;
    }
    if !client_noninteroperable_kdf && !server_noninteroperable_kdf {
        output.expect_stderr_line("Using fully interoperable KDF")?;
    }

    pretty_assertions::assert_eq!(
        fs::read_to_string(&marker_file_path).context("Error reading marker file")?,
        "executed"
    );
    pretty_assertions::assert_eq!(
        fs::read_to_string(&ssh_authorized_keys_path)
            .context("Error reading authorized SSH keys")?,
        "
# These keys are installed by FIDO Device Onboarding
ssh-ed25519 sshkey_default user@example.com
# End of FIDO Device Onboarding keys

# These keys are installed by FIDO Device Onboarding
ssh-ed25519 sshkey_default user@example2.com
# End of FIDO Device Onboarding keys
"
    );

    assert!(binary_file_path_prefix.join("etc/resolv.conf").exists());
    let resolv_conf_metadata = binary_file_path_prefix
        .join("etc/resolv.conf")
        .metadata()
        .context("Error reading hosts file")?;
    assert_eq!(resolv_conf_metadata.permissions().mode() & 0o777, 0o600);
    assert!(binary_file_path_prefix.join("etc/hosts").exists());
    let hosts_metadata = binary_file_path_prefix
        .join("etc/hosts")
        .metadata()
        .context("Error reading hosts file")?;
    assert_eq!(hosts_metadata.permissions().mode() & 0o777, 0o644);

    assert!(key_path.join("command-testfile").exists());

    Ok(())
}

fn determine_device_credential_guid(path: &Path) -> Result<Guid> {
    let dc_contents = fs::read(path).context("Error reading device credential")?;
    let dc: FileDeviceCredential = ciborium::de::from_reader(dc_contents.as_slice())
        .context("Error deserializing device credential")?;
    Ok(dc.guid)
}
