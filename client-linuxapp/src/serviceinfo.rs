use std::process::Command;
use std::{
    collections::HashSet,
    fs::{File, Permissions},
    io::Write,
    path::Path,
};
use std::{env, fs};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use fdo_data_formats::{
    constants::HashType,
    messages::to2::{DeviceServiceInfo, OwnerServiceInfo},
    types::{CborSimpleTypeExt, Hash, ServiceInfo},
};
use fdo_http_wrapper::client::{RequestResult, ServiceClient};

const MAX_SERVICE_INFO_LOOPS: u32 = 1000;

fn find_available_modules() -> Result<Vec<String>> {
    let mut module_list = vec![
        // These modules are always here
        "devmod".to_string(),
        "sshkey".to_string(),
        "binaryfile".to_string(),
    ];

    // See if we add RHSM
    if Path::new("/usr/sbin/subscription-manager").exists() {
        module_list.push("rhsm".to_string());
    }

    Ok(module_list)
}

fn set_perm_mode(path: &Path, mode: u32) -> Result<()> {
    let mut perms = fs::metadata(&path)
        .context("Error getting directory metadata")?
        .permissions();
    perms.set_mode(mode);
    fs::set_permissions(&path, perms).context("Error setting permissions")?;
    Ok(())
}

fn install_ssh_key(user: &str, key: &str) -> Result<()> {
    let user_info = passwd::Passwd::from_name(user);
    if user_info.is_none() {
        bail!("User {} for SSH key installation missing", user);
    }
    let user_info = user_info.unwrap();
    let uid = nix::unistd::Uid::from_raw(user_info.uid);
    let gid = nix::unistd::Gid::from_raw(user_info.gid);
    let key_path = if let Ok(val) = env::var("SSH_KEY_PATH") {
        PathBuf::from(&val)
    } else {
        let ssh_dir = Path::new(&user_info.home_dir).join(".ssh");
        if !ssh_dir.exists() {
            log::debug!("Creating SSH directory at {}", ssh_dir.display());
            fs::create_dir(&ssh_dir).context("Error creating SSH key directory")?;
            set_perm_mode(&ssh_dir, 0o700).with_context(|| {
                format!(
                    "Error setting permissions on SSH key directory {}",
                    ssh_dir.display()
                )
            })?;
            nix::unistd::chown(&ssh_dir, Some(uid), Some(gid))?;
        }
        ssh_dir.join("authorized_keys")
    };
    log::debug!("Writing SSH keys to {:?}", key_path);
    let contents = if key_path.exists() {
        log::debug!(
            "SSH authorized keys {} file exists, appending",
            key_path.display()
        );
        fs::read_to_string(&key_path).context("Error reading current file")?
    } else {
        log::debug!("Creating SSH authorized keys {}", key_path.display());
        "".to_string()
    };
    let contents = format!(
        "{}\n# These keys are installed by FIDO Device Onboarding\n{}\n# End of FIDO Device Onboarding keys\n",
        contents, key
    );
    fs::write(&key_path, contents.as_bytes()).context("Error writing SSH keys")?;
    set_perm_mode(&key_path, 0o600).with_context(|| {
        format!(
            "Error setting permissions on authorized keys file {}",
            key_path.display()
        )
    })?;
    nix::unistd::chown(&key_path, Some(uid), Some(gid))?;

    Ok(())
}

fn perform_rhsm(organization_id: &str, activation_key: &str, perform_insights: bool) -> Result<()> {
    log::info!("Executing subscription-manager registration");
    Command::new("subscription-manager")
        .arg("register")
        .arg(format!("--org={}", organization_id))
        .arg(format!("--activationkey={}", activation_key))
        .spawn()
        .context("Error spawning subscription-manager")?
        .wait()
        .context("Error running subscription-manager")?;

    if perform_insights {
        log::info!("Executing insights-client registration");
        Command::new("insights-client")
            .arg("--register")
            .spawn()
            .context("Error spawning insights-client")?
            .wait()
            .context("Error running insights-client")?;
    }

    Ok(())
}

fn deploy_binaryfile(file: BinaryFileInProgress) -> Result<()> {
    let path = file.path.as_ref().unwrap();

    let path = if let Ok(val) = env::var("BINARYFILE_PATH_PREFIX") {
        PathBuf::from(&val).join(path)
    } else {
        PathBuf::from(path)
    };

    if !path.is_absolute() {
        bail!("Binaryfile path must be absolute");
    }

    let contents = file.contents.as_ref().unwrap();
    let mode = file.mode.unwrap_or(0o600);

    log::info!(
        "Creating file {:?} with {} bytes (mode {:?})",
        path,
        file.length.unwrap(),
        mode
    );

    let mut file = File::create(path).context("Error creating file")?;
    file.write_all(contents).context("Error writing file")?;
    file.set_permissions(Permissions::from_mode(mode))
        .context("Error setting file permissions")?;
    file.sync_all().context("Error syncing file")?;

    Ok(())
}

#[derive(Debug)]
struct BinaryFileInProgress {
    path: Option<String>,
    length: Option<u64>,
    contents: Option<Vec<u8>>,
    mode: Option<u32>,
    digest: Option<Hash>,
}

impl BinaryFileInProgress {
    fn new() -> Self {
        BinaryFileInProgress {
            path: None,
            length: None,
            contents: None,
            mode: None,
            digest: None,
        }
    }
}

async fn process_serviceinfo_in(si_in: &ServiceInfo) -> Result<()> {
    let mut active_modules: HashSet<String> = HashSet::new();

    let mut sshkey_user: Option<String> = None;
    let mut sshkey_key: Option<String> = None;

    let mut rhsm_organization_id: Option<String> = None;
    let mut rhsm_activation_key: Option<String> = None;
    let mut rhsm_perform_insights: Option<bool> = None;

    let mut binary_file_in_progress = BinaryFileInProgress::new();

    for (module, key, value) in si_in.iter() {
        log::trace!("Got module {}, command {}, value {:?}", module, key, value);
        if key == "active" {
            let value = value.as_bool().context("Error parsing active value")?;
            if value {
                log::trace!("Activating module {}", module);
                active_modules.insert(module.to_string());
            } else {
                log::trace!("Deactivating module {}", module);
                active_modules.remove(&module);
            }
            continue;
        }
        if !active_modules.contains(&module) {
            log::trace!("Skipping non-activated module {}", module);
            bail!("Non-activated module {} got request", module);
        }
        if module == "sshkey" {
            let value = value.as_str().context("Error parsing sshkey value")?;
            if key == "username" {
                sshkey_user = Some(value.to_string());
            } else if key == "key" {
                sshkey_key = Some(value.to_string());
            }
        } else if module == "rhsm" {
            if key == "organization_id" {
                let value = value
                    .as_str()
                    .with_context(|| format!("Error parsing rhsm {} value", key))?;
                rhsm_organization_id = Some(value.to_string());
            } else if key == "activation_key" {
                let value = value
                    .as_str()
                    .with_context(|| format!("Error parsing rhsm {} value", key))?;
                rhsm_activation_key = Some(value.to_string());
            } else if key == "perform_insights" {
                let value = value
                    .as_bool()
                    .with_context(|| format!("Error parsing rhsm {} value", key))?;
                rhsm_perform_insights = Some(value);
            }
        } else if module == "binaryfile" {
            if key == "name" {
                if binary_file_in_progress.path.is_some() {
                    bail!(
                        "Got binaryfile path {:?} after path {:?}",
                        value,
                        binary_file_in_progress.path
                    );
                }
                binary_file_in_progress.path = Some(
                    value
                        .as_str()
                        .context("Error parsing binaryfile name")?
                        .to_string(),
                );
            } else if key == "length" {
                if binary_file_in_progress.length.is_some() {
                    bail!(
                        "Got binaryfile length {:?} after length {:?}",
                        value,
                        binary_file_in_progress.length
                    );
                }
                binary_file_in_progress.length =
                    Some(value.as_u64().context("Error parsing binaryfile length")?);
                binary_file_in_progress.contents = Some(Vec::with_capacity(
                    binary_file_in_progress.length.unwrap() as usize,
                ));
            } else if key.starts_with("data") {
                if binary_file_in_progress.contents.is_none() {
                    bail!("Got binaryfile data before length {:?}", value);
                }
                binary_file_in_progress
                    .contents
                    .as_mut()
                    .unwrap()
                    .extend_from_slice(value.as_bytes().context("Error parsing binaryfile data")?);
            } else if key == "mode" {
                if binary_file_in_progress.mode.is_some() {
                    bail!(
                        "Got binaryfile mode {:?} after mode {:?}",
                        value,
                        binary_file_in_progress.mode
                    );
                }
                binary_file_in_progress.mode =
                    Some(value.as_u32().context("Error parsing binaryfile mode")?);
            } else if key.starts_with("sha-") {
                let sha_type = key.split('-').nth(1).unwrap();
                let sha_value = value
                    .as_bytes()
                    .with_context(|| format!("Error parsing binaryfile sha-{} value", sha_type))?;
                let hasher = match sha_type {
                    "256" => HashType::Sha256,
                    "384" => HashType::Sha384,
                    _ => {
                        bail!("Unknown sha-{}", sha_type);
                    }
                };
                binary_file_in_progress.digest =
                    Some(Hash::from_digest(hasher, sha_value.to_vec())?);

                // We got the full file, check it and add it to the files to get deployed
                if binary_file_in_progress.path.is_none() {
                    bail!("Got binaryfile sha-{} before name", sha_type);
                }
                if binary_file_in_progress.length.is_none() {
                    bail!("Got binaryfile sha-{} before length", sha_type);
                }
                let read_bytes = binary_file_in_progress.contents.as_ref().unwrap().len();
                if read_bytes != binary_file_in_progress.length.unwrap() as usize {
                    bail!(
                        "Got binaryfile (path {}) with length {} but only {} bytes of data",
                        binary_file_in_progress.path.as_ref().unwrap(),
                        binary_file_in_progress.length.unwrap(),
                        read_bytes
                    );
                }
                if let Err(e) = binary_file_in_progress
                    .digest
                    .as_ref()
                    .unwrap()
                    .compare_data(&binary_file_in_progress.contents.as_ref().unwrap())
                {
                    bail!(
                        "Got binaryfile (path {}) with invalid digest: {:?}",
                        binary_file_in_progress.path.as_ref().unwrap(),
                        e
                    );
                }

                deploy_binaryfile(binary_file_in_progress).context("Error deploying binaryfile")?;
                binary_file_in_progress = BinaryFileInProgress::new();
            }
        }
    }

    // Do SSH
    if active_modules.contains("sshkey") {
        log::debug!("SSHkey module was active, installing SSH key");
        if sshkey_user.is_none() || sshkey_key.is_none() {
            bail!("SSHkey module missing username or key");
        }
        install_ssh_key(sshkey_user.as_ref().unwrap(), sshkey_key.as_ref().unwrap())
            .context("Error installing SSH key")?;
    }

    // Perform RHSM
    if active_modules.contains("rhsm") {
        log::debug!("RHSM module was active, running RHSM");
        if rhsm_organization_id.is_none()
            || rhsm_activation_key.is_none()
            || rhsm_perform_insights.is_none()
        {
            bail!("Missing one of the RHSM module configurations");
        }
        perform_rhsm(
            rhsm_organization_id.as_ref().unwrap(),
            rhsm_activation_key.as_ref().unwrap(),
            rhsm_perform_insights.unwrap(),
        )
        .context("Error performing RHSM enrollment")?;
    }

    Ok(())
}

pub(crate) async fn perform_to2_serviceinfos(client: &mut ServiceClient) -> Result<()> {
    let mut loop_num = 0;
    while loop_num < MAX_SERVICE_INFO_LOOPS {
        let mut out_si = ServiceInfo::new();

        if loop_num == 0 {
            let modules = find_available_modules().context("Error getting list of modules")?;
            let sysinfo = sys_info::linux_os_release()
                .context("Error getting operating system information")?;

            // We just blindly send the devmod module
            out_si.add("devmod", "active", &true)?;
            out_si.add("devmod", "os", &std::env::consts::OS)?;
            out_si.add("devmod", "arch", &std::env::consts::ARCH)?;
            out_si.add("devmod", "version", &sysinfo.pretty_name.unwrap())?;
            out_si.add("devmod", "device", &"unused")?;
            out_si.add("devmod", "sep", &":")?;
            out_si.add("devmod", "bin", &std::env::consts::ARCH)?;
            out_si.add_modules(&modules)?;
        }

        let out_si = DeviceServiceInfo::new(false, out_si);
        log::trace!("Sending ServiceInfo loop {}: {:?}", loop_num, out_si);

        let return_si: RequestResult<OwnerServiceInfo> = client.send_request(out_si, None).await;
        let return_si =
            return_si.with_context(|| format!("Error during ServiceInfo loop {}", loop_num))?;
        log::trace!("Got ServiceInfo loop {}: {:?}", loop_num, return_si);

        if return_si.is_done() {
            log::trace!("ServiceInfo loops done, number taken: {}", loop_num);
            return Ok(());
        }
        if return_si.is_more_service_info() {
            // TODO
            bail!("OwnerServiceInfo indicated it has more for us.. we don't support that yet");
        }

        // Process
        process_serviceinfo_in(return_si.service_info())
            .await
            .context("Error processing returned serviceinfo")?;

        loop_num += 1;
    }
    Err(anyhow!(
        "Maximum number of ServiceInfo loops ({}) exceeded",
        MAX_SERVICE_INFO_LOOPS
    ))
}
