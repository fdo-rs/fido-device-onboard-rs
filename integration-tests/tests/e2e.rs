mod common;
use std::env;
#[allow(unused_imports)]
use std::{fs, io::Write, process::Command, time::Duration};

use common::{Binary, LogSide, TestContext};

use anyhow::{bail, Context, Result};

use sha_crypt::sha256_check;

const L: LogSide = LogSide::Test;

#[tokio::test]
async fn test_e2e() -> Result<()> {
    let diun_verification_methods: &[(
        &'static str,
        Box<dyn Fn(&TestContext) -> Result<(&'static str, String, &'static str)>>,
    )] = &[
        (
            "insecure",
            Box::new(|_| {
                Ok((
                    "DIUN_PUB_KEY_INSECURE",
                    "true".to_string(),
                    "Trusting any certificate as root",
                ))
            }),
        ),
        (
            "hash",
            Box::new(|ctx| {
                let diun_cert = std::fs::read(ctx.keys_path().join("diun_cert.pem"))?;
                let diun_cert = openssl::x509::X509::from_pem(&diun_cert)?;
                let diun_cert_hash = diun_cert.digest(openssl::hash::MessageDigest::sha256())?;
                Ok((
                    "DIUN_PUB_KEY_HASH",
                    format!("sha256:{}", hex::encode(&diun_cert_hash)),
                    "Checking digest",
                ))
            }),
        ),
        (
            "rootcert",
            Box::new(|ctx| {
                Ok((
                    "DIUN_PUB_KEY_ROOTCERTS",
                    ctx.keys_path()
                        .join("diun_cert.pem")
                        .to_string_lossy()
                        .to_string(),
                    "Checking for cert",
                ))
            }),
        ),
    ];
    let mut diun_key_types = vec!["FileSystem"];
    // Verify if the file exists and has read permission.
    if std::fs::File::open("/dev/tpm0").is_ok() {
        env::set_var("TEST_TCTI", "device:/dev/tpm0");
        diun_key_types.push("Tpm");
    } else {
        println!("skipping test with TPM as /dev/tpm0 does not exist or no read permission")
    }

    let mut failed = Vec::new();

    env::set_var("PER_DEVICE_SERVICEINFO", "false");

    for (diun_verification_method_name, diun_verification_method_generator) in
        &diun_verification_methods[1..2]
    {
        // for default serviceinfo
        for diun_key_type in &diun_key_types {
            match test_e2e_impl_default_serviceinfo(
                diun_verification_method_generator,
                diun_key_type,
            )
            .await
            {
                Ok(()) => (),
                Err(e) => {
                    failed.push(TestCase {
                        diun_verification_method_name: diun_verification_method_name,
                        diun_key_type: diun_key_type,
                        error: e,
                    });
                }
            }
        }

        // for per_device serviceinfo
        for diun_key_type in &diun_key_types {
            match test_e2e_impl_per_device_serviceinfo(
                diun_verification_method_generator,
                diun_key_type,
            )
            .await
            {
                Ok(()) => (),
                Err(e) => {
                    failed.push(TestCase {
                        diun_verification_method_name: diun_verification_method_name,
                        diun_key_type: diun_key_type,
                        error: e,
                    });
                }
            }
        }
    }

    if failed.is_empty() {
        Ok(())
    } else {
        for failed_case in failed {
            eprintln!("Failed test: {:?}", failed_case);
        }
        bail!("Some tests failed");
    }
}

#[derive(Debug)]
struct TestCase {
    #[allow(dead_code)]
    diun_verification_method_name: &'static str,
    #[allow(dead_code)]
    diun_key_type: &'static str,
    #[allow(dead_code)]
    error: anyhow::Error,
}

async fn test_e2e_impl_default_serviceinfo<F>(
    verification_generator: F,
    diun_key_type: &str,
) -> Result<()>
where
    F: Fn(&TestContext) -> Result<(&'static str, String, &'static str)>,
{
    let ci = env::var("FDO_PRIVILEGED").is_ok();
    env::set_var("PER_DEVICE_SERVICEINFO", "false");
    let mut ctx = TestContext::new().context("Error building test context")?;
    let new_user: &str = "testuser"; // new user to be created during onboarding
    let new_pw: &str = "testpassword"; // new password to accompany new user during onboarding
    let encrypted_disk_loc = ctx.testpath().join("encrypted.img");
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
            |cfg| {
                Ok(cfg.prepare_config_file(None, |cfg| {
                    cfg.insert(
                        "encrypted_disk_label",
                        &encrypted_disk_loc.to_string_lossy(),
                    );
                    if ci {
                        cfg.insert("user", new_user);
                        cfg.insert("password", new_pw);
                    };
                    Ok(())
                })?)
            },
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
                Ok(())
            },
        )
        .context("Error creating owner server")?;
    let mfg_server = ctx
        .start_test_server(
            Binary::ManufacturingServer,
            |cfg| {
                Ok(cfg.prepare_config_file(None, |cfg| {
                    cfg.insert("diun_key_type", diun_key_type);
                    cfg.insert("rendezvous_port", &rendezvous_server.server_port().unwrap());
                    cfg.insert("device_identification_format", "SerialNumber");
                    Ok(())
                })?)
            },
            |_| Ok(()),
        )
        .context("Error creating manufacturing server")?;
    ctx.wait_until_servers_ready()
        .await
        .context("Error waiting for servers to start")?;

    let (verification_key, verification_value, verification_searchstr) =
        verification_generator(&ctx).context("Error generating verification information")?;

    // Execute the DI(UN) protocols
    let client_result = ctx
        .run_client(
            Binary::ManufacturingClient,
            Some(&mfg_server),
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL_FILENAME", "devicecredential.dc")
                    .env("MANUFACTURING_INFO", "testdevice")
                    .env(&verification_key, &verification_value);
                Ok(())
            },
            Duration::from_secs(5),
        )
        .context("Error running manufacturing client")?;
    client_result
        .expect_success()
        .context("Manufacturing client failed")?;
    client_result.expect_stderr_line(verification_searchstr)?;

    // Execute some tests on the device credential and ownership voucher
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
    match diun_key_type {
        "Tpm" => {
            owner_output.expect_stdout_line("HMAC key TPM public: KeyedHash")?;
            owner_output.expect_stdout_line("Signing key TPM public: Ecc")?;
        }
        "FileSystem" => {
            owner_output.expect_stdout_line("HMAC key: <secret>")?;
            owner_output.expect_stdout_line("Signing key: <secret>")?;
        }
        _ => bail!("Unknown DIUN key type: {}", diun_key_type),
    }

    let ov_dir = ctx.testpath().join("ownership_vouchers");
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
    let device_guid = ov_file.file_name().to_str().unwrap().to_string();
    L.l(format!("Device GUID: {}", device_guid));

    let owner_output = ctx
        .run_owner_tool(
            client_result.client_path(),
            &["dump-ownership-voucher", ov_file.path().to_str().unwrap()],
        )
        .context("Error running dump-ownership-voucher")?;
    owner_output
        .expect_success()
        .context("Dump-ownership-voucher failed")?;
    owner_output.expect_stdout_line("Device Info: \"testdevice\"")?;
    owner_output.expect_stdout_line("commonName = \"testdevice\"")?;
    // It should have been extended to the "owner" time by the manufacturer
    owner_output.expect_stdout_line("Entry 0")?;

    L.l("Adding disk encryption tests");
    L.l("Creating empty disk image");
    if !Command::new("truncate")
        .arg("-s")
        .arg("1G")
        .arg(&encrypted_disk_loc)
        .status()
        .context("Error running truncate")?
        .success()
    {
        bail!("Error creating empty disk image");
    }

    L.l("Encrypting disk image");
    let mut child = Command::new("cryptsetup")
        .arg("luksFormat")
        .arg(&encrypted_disk_loc)
        .arg("--force-password")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("Error starting cryptsetup luksFormat")?;
    {
        let mut stdin = child.stdin.take().context("Error taking stdin")?;
        writeln!(stdin, "testpassword")?;
        stdin.flush()?;
    }

    let output = child.wait().context("Error waiting for cryptsetup")?;
    if !output.success() {
        bail!("Failed to call cryptsetup");
    }

    L.l("Binding disk image");
    let mut child = Command::new("clevis")
        .arg("luks")
        .arg("bind")
        .arg("-d")
        .arg(&encrypted_disk_loc)
        .arg("test")
        .arg("{}")
        .env("PATH", ctx.get_path_env()?)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("Error starting clevis luks bind")?;
    {
        let mut stdin = child.stdin.take().context("Error taking stdin")?;
        writeln!(stdin, "testpassword")?;
        stdin.flush()?;
    }

    let output = child.wait().context("Error waiting for clevis to bind")?;
    if !output.success() {
        bail!("Failed to call clevis luks bind");
    }

    let client = reqwest::Client::new();

    // Ensure TO0 is executed
    let res = client
        .post(format!(
            "http://localhost:{}/report-to-rendezvous", // DevSkim: ignore DS137138
            owner_onboarding_server.server_port().unwrap()
        ))
        .send()
        .await?;
    L.l(format!("Status code report-to-rendezvous {}", res.status()));

    // Execute TO1/TO2 protocols
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
                Ok(())
            },
            Duration::from_secs(60),
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
sshkey_default
# End of FIDO Device Onboarding keys
"
    );
    if ci {
        L.l("Running create initial user validation");
        pretty_assertions::assert_eq!(
            passwd::Passwd::from_name(new_user).is_some(),
            true,
            "User: {} is not created during onboarding",
            &new_user
        );
        if let Some(test_user) = shadow::Shadow::from_name(new_user) {
            pretty_assertions::assert_eq!(
                test_user.password.is_empty(),
                false,
                "Password not created during onboarding"
            );
            assert!(sha256_check("testpassword", &test_user.password).is_ok());
        }
    } else {
        L.l("Skipped create initial user validation
        To validate set env variable FDO_PRIVILEGED and run test as superuser");
    }

    L.l("Checking encrypted disk image");
    let output = Command::new("cryptsetup")
        .arg("luksDump")
        .arg(encrypted_disk_loc)
        .output()
        .context("Error running cryptsetup")?;
    if !output.status.success() {
        bail!("Failed to call cryptsetup");
    }
    let luksdump_stdout =
        String::from_utf8(output.stdout).context("Error reading luksDump stdout")?;
    L.l(format!("Cryptsetup luksDump output: {:?}", luksdump_stdout));
    let mut found_ds_backup_final = false;
    let mut found_reencrypt_unbound = false;
    for stdout_line in luksdump_stdout.split('\n') {
        if stdout_line.contains("flags") && stdout_line.contains("backup-final") {
            found_ds_backup_final = true;
            continue;
        }
        if stdout_line.contains("reencrypt (unbound)") {
            found_reencrypt_unbound = true;
            continue;
        }
    }
    if !found_ds_backup_final {
        bail!("Failed to find backup-final flag in cryptsetup output");
    }
    if !found_reencrypt_unbound {
        bail!("Failed to find reencrypt (unbound) flag in cryptsetup output");
    }

    Ok(())
}

async fn test_e2e_impl_per_device_serviceinfo<F>(
    verification_generator: F,
    diun_key_type: &str,
) -> Result<()>
where
    F: Fn(&TestContext) -> Result<(&'static str, String, &'static str)>,
{
    env::set_var("PER_DEVICE_SERVICEINFO", "true");
    let mut ctx = TestContext::new().context("Error building test context")?;
    let encrypted_disk_loc = ctx.testpath().join("encrypted2.img");
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
            |cfg| {
                Ok(cfg.prepare_config_file(None, |cfg| {
                    cfg.insert(
                        "encrypted_disk_label",
                        &encrypted_disk_loc.to_string_lossy(),
                    );
                    Ok(())
                })?)
            },
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
                Ok(())
            },
        )
        .context("Error creating owner server")?;
    let mfg_server = ctx
        .start_test_server(
            Binary::ManufacturingServer,
            |cfg| {
                Ok(cfg.prepare_config_file(None, |cfg| {
                    cfg.insert("diun_key_type", diun_key_type);
                    cfg.insert("rendezvous_port", &rendezvous_server.server_port().unwrap());
                    cfg.insert("device_identification_format", "SerialNumber");
                    Ok(())
                })?)
            },
            |_| Ok(()),
        )
        .context("Error creating manufacturing server")?;
    ctx.wait_until_servers_ready()
        .await
        .context("Error waiting for servers to start")?;

    let (verification_key, verification_value, verification_searchstr) =
        verification_generator(&ctx).context("Error generating verification information")?;

    // Execute the DI(UN) protocols
    let client_result = ctx
        .run_client(
            Binary::ManufacturingClient,
            Some(&mfg_server),
            |cfg| {
                cfg.env("DEVICE_CREDENTIAL_FILENAME", "devicecredential.dc")
                    .env("MANUFACTURING_INFO", "testdevice")
                    .env(&verification_key, &verification_value);
                Ok(())
            },
            Duration::from_secs(5),
        )
        .context("Error running manufacturing client")?;
    client_result
        .expect_success()
        .context("Manufacturing client failed")?;
    client_result.expect_stderr_line(verification_searchstr)?;

    let dc_path = client_result.client_path().join("devicecredential.dc");
    let client = reqwest::Client::new();

    L.l("Adding disk encryption tests");
    L.l("Creating empty disk image");
    if !Command::new("truncate")
        .arg("-s")
        .arg("1G")
        .arg(&encrypted_disk_loc)
        .status()
        .context("Error running truncate")?
        .success()
    {
        bail!("Error creating empty disk image");
    }

    L.l("Encrypting disk image");
    let mut child = Command::new("cryptsetup")
        .arg("luksFormat")
        .arg(&encrypted_disk_loc)
        .arg("--force-password")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("Error starting cryptsetup luksFormat")?;
    {
        let mut stdin = child.stdin.take().context("Error taking stdin")?;
        writeln!(stdin, "testpassword")?;
        stdin.flush()?;
    }

    let output = child.wait().context("Error waiting for cryptsetup")?;
    if !output.success() {
        bail!("Failed to call cryptsetup");
    }

    L.l("Binding disk image");
    let mut child = Command::new("clevis")
        .arg("luks")
        .arg("bind")
        .arg("-d")
        .arg(&encrypted_disk_loc)
        .arg("test")
        .arg("{}")
        .env("PATH", ctx.get_path_env()?)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("Error starting clevis luks bind")?;
    {
        let mut stdin = child.stdin.take().context("Error taking stdin")?;
        writeln!(stdin, "testpassword")?;
        stdin.flush()?;
    }

    let output = child.wait().context("Error waiting for clevis to bind")?;
    if !output.success() {
        bail!("Failed to call clevis luks bind");
    }

    // Ensure TO0 is executed
    let res = client
        .post(format!(
            "http://localhost:{}/report-to-rendezvous", // DevSkim: ignore DS137138
            owner_onboarding_server.server_port().unwrap()
        ))
        .send()
        .await?;
    L.l(format!("Status code report-to-rendezvous {}", res.status()));

    // Execute TO1/TO2 protocols
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
                Ok(())
            },
            Duration::from_secs(60),
        )
        .context("Error running client")?;
    output.expect_success().context("client failed")?;

    pretty_assertions::assert_eq!(
        fs::read_to_string(&marker_file_path).context("Error reading marker file")?,
        "executed"
    );
    pretty_assertions::assert_eq!(
        fs::read_to_string(&ssh_authorized_keys_path)
            .context("Error reading authorized per device SSH keys")?,
        "
# These keys are installed by FIDO Device Onboarding
sshkey_per_device
# End of FIDO Device Onboarding keys
"
    );

    env::set_var("PER_DEVICE_SERVICEINFO", "false");
    Ok(())
}
