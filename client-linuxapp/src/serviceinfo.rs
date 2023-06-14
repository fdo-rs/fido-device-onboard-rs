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
    constants::{
        FedoraIotServiceInfoModule, HashType, RedHatComServiceInfoModule, ServiceInfoModule,
        StandardServiceInfoModule,
    },
    messages::v11::to2::{DeviceServiceInfo, OwnerServiceInfo},
    types::{CborSimpleTypeExt, Hash, ServiceInfo},
};
use fdo_http_wrapper::client::{RequestResult, ServiceClient};

const MAX_SERVICE_INFO_LOOPS: u32 = 1000;

fn find_available_modules() -> Result<Vec<ServiceInfoModule>> {
    let mut module_list = vec![
        // These modules are always here
        StandardServiceInfoModule::DevMod.into(),
        FedoraIotServiceInfoModule::SSHKey.into(),
        FedoraIotServiceInfoModule::BinaryFile.into(),
        FedoraIotServiceInfoModule::Command.into(),
        FedoraIotServiceInfoModule::Reboot.into(),
    ];

    // See if we add RHSM
    if Path::new("/usr/sbin/subscription-manager").exists() {
        module_list.push(RedHatComServiceInfoModule::SubscriptionManager.into());
    }

    if Path::new("/usr/bin/clevis").exists() {
        module_list.push(FedoraIotServiceInfoModule::DiskEncryptionClevis.into());
    }

    Ok(module_list)
}

fn set_perm_mode(path: &Path, mode: u32) -> Result<()> {
    let mut perms = fs::metadata(path)
        .context("Error getting directory metadata")?
        .permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms).context("Error setting permissions")?;
    Ok(())
}

fn create_user(user: &str) -> Result<()> {
    let user_info = passwd::Passwd::from_name(user);
    if user_info.is_some() {
        log::info!("User: {} already present", user);
        return Ok(());
    }
    log::info!("Creating user: {}", user);
    Command::new("useradd")
        .arg("-m")
        .arg(user)
        .spawn()
        .context("Error spawning new user command")?
        .wait()
        .context("Error creating new user")?;
    Ok(())
}

fn set_passwordless_login(user: &str) -> Result<()> {
    let user_info = passwd::Passwd::from_name(user);
    if user_info.is_none() {
        bail!("User {} for passwordless login missing", user);
    }
    log::info!("Setting passwordless login for user: {}", user);
    Command::new("passwd")
        .arg("-d")
        .arg(user)
        .spawn()
        .context("Error spawning passwordless setup command")?
        .wait()
        .context(format!(
            "Error setting up passwordless login for user {}",
            user
        ))?;
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
        "{contents}\n# These keys are installed by FIDO Device Onboarding\n{key}\n# End of FIDO Device Onboarding keys\n"
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
        .arg(format!("--org={organization_id}"))
        .arg(format!("--activationkey={activation_key}"))
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

#[derive(Debug)]
struct BinaryFileInProgress<'a> {
    path: Option<String>,
    prefix: Option<&'a str>,
    length: Option<u64>,
    contents: Option<Vec<u8>>,
    mode: Option<u32>,
    digest: Option<Hash>,
}

impl<'a> BinaryFileInProgress<'a> {
    fn new(prefix: Option<&'a str>) -> Self {
        BinaryFileInProgress {
            path: None,
            prefix,
            length: None,
            contents: None,
            mode: None,
            digest: None,
        }
    }

    #[cfg(not(unix))]
    compile_error!("This root splitting would need to get fixed for non-unix systems");
    fn destination_path(path_str: &str, prefix: Option<&str>) -> Result<PathBuf> {
        let path = PathBuf::from(path_str);

        if !path.is_absolute() {
            bail!("Binary file path must be absolute");
        }

        if let Some(val) = prefix {
            // make sure we drop the first slash or PathBuf returns the join'ed absolute path
            Ok(PathBuf::from(val).join(&path_str[1..path_str.len()]))
        } else {
            Ok(path)
        }
    }

    fn deploy(self) -> Result<()> {
        let path =
            BinaryFileInProgress::destination_path(self.path.as_ref().unwrap(), self.prefix)?;

        let contents = self.contents.as_ref().unwrap();
        let mode = self.mode.unwrap_or(0o600);

        log::info!(
            "Creating file {:?} with {} bytes (mode {:?})",
            path,
            self.length.unwrap(),
            mode
        );

        fs::create_dir_all(path.parent().unwrap()).context("Error creating file's directory")?;

        let mut file = File::create(path).context("Error creating file")?;
        file.write_all(contents).context("Error writing file")?;
        file.set_permissions(Permissions::from_mode(mode))
            .context("Error setting file permissions")?;
        file.sync_all().context("Error syncing file")?;

        Ok(())
    }
}

#[derive(Debug)]
struct DiskEncryptionInProgress {
    disk_label: Option<String>,
    pin: Option<String>,
    config: Option<String>,
    reencrypt: bool,
}

impl DiskEncryptionInProgress {
    fn new() -> Self {
        Self {
            disk_label: None,
            pin: None,
            config: None,
            reencrypt: false,
        }
    }

    fn execute_with_values(
        si_out: &mut ServiceInfo,
        disk_label: &str,
        pin: &str,
        config: &str,
        reencrypt: bool,
    ) -> Result<()> {
        log::info!(
            "Initiating disk re-encryption, disk-label: {}, pin: {}, config: {}, reencrypt: {}",
            disk_label,
            pin,
            config,
            reencrypt
        );

        let mut dev = if disk_label.starts_with('/') {
            libcryptsetup_rs::CryptInit::init(&std::path::PathBuf::from(disk_label))
        } else {
            libcryptsetup_rs::CryptInit::init_by_name_and_header(disk_label, None)
        }
        .with_context(|| format!("Error opening device {disk_label}"))?;

        log::debug!("Device initiated");

        dev.context_handle()
            .load::<()>(None, None)
            .context("Error loading device context")?;

        log::debug!("Device information loaded");

        si_out.add(
            FedoraIotServiceInfoModule::DiskEncryptionClevis,
            "disk-label",
            &disk_label,
        )?;

        log::debug!("Rebinding clevis");
        crate::reencrypt::rebind::rebind_clevis(&mut dev, pin, config)
            .context("Error rebinding clevis")?;
        si_out.add(
            FedoraIotServiceInfoModule::DiskEncryptionClevis,
            "bound",
            &true,
        )?;
        if reencrypt {
            log::debug!("Initiating re-encryption");
            crate::reencrypt::initiate_reencrypt(dev).context("Error initiating reencryption")?;
        }
        log::debug!("Re-encryption initiated");
        si_out.add(
            FedoraIotServiceInfoModule::DiskEncryptionClevis,
            "reencrypt-initiated",
            &reencrypt,
        )?;

        Ok(())
    }

    fn execute(self, si_out: &mut ServiceInfo) -> Result<()> {
        let disk_label = self
            .disk_label
            .ok_or_else(|| anyhow!("Disk label not set"))?;
        let pin = self
            .pin
            .ok_or_else(|| anyhow!("Disk encryption PIN not set"))?;
        let config = self
            .config
            .ok_or_else(|| anyhow!("Disk encryption config not set"))?;
        let reencrypt = self.reencrypt;

        Self::execute_with_values(si_out, &disk_label, &pin, &config, reencrypt)
            .with_context(|| format!("Error executing disk encryption for disk label {disk_label}"))
    }
}

#[derive(Debug)]
struct CommandInProgress {
    command: Option<String>,
    args: Vec<String>,
    may_fail: bool,
    return_stdout: bool,
    return_stderr: bool,
}

impl CommandInProgress {
    fn new() -> Self {
        CommandInProgress {
            command: None,
            args: Vec::new(),
            may_fail: false,
            return_stdout: false,
            return_stderr: false,
        }
    }

    fn execute(self, si_out: &mut ServiceInfo) -> Result<()> {
        si_out.add(
            FedoraIotServiceInfoModule::Command,
            "command",
            self.command.as_ref().unwrap(),
        )?;
        si_out.add(FedoraIotServiceInfoModule::Command, "args", &self.args)?;

        let mut cmd = Command::new(self.command.as_ref().unwrap());
        cmd.args(&self.args);

        let output = cmd.output().context("Error running command")?;

        if self.return_stdout {
            si_out.add(
                FedoraIotServiceInfoModule::Command,
                "stdout",
                &serde_bytes::Bytes::new(&output.stdout),
            )?;
        }
        if self.return_stderr {
            si_out.add(
                FedoraIotServiceInfoModule::Command,
                "stderr",
                &serde_bytes::Bytes::new(&output.stderr),
            )?;
        }
        si_out.add(
            FedoraIotServiceInfoModule::Command,
            "exit_code",
            &output.status.code(),
        )?;

        if self.may_fail || output.status.success() {
            Ok(())
        } else {
            bail!(
                "Command failed {} {:?} stderr: {}",
                self.command.as_ref().unwrap(),
                self.args,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

async fn process_serviceinfo_in(si_in: &ServiceInfo, si_out: &mut ServiceInfo) -> Result<bool> {
    let mut active_modules: HashSet<ServiceInfoModule> = HashSet::new();

    let mut sshkey_user: Option<String> = None;
    let mut sshkey_key: Option<String> = None;

    let mut rhsm_organization_id: Option<String> = None;
    let mut rhsm_activation_key: Option<String> = None;
    let mut rhsm_perform_insights: Option<bool> = None;

    let binary_file_prefix_owned = env::var("BINARYFILE_PATH_PREFIX").ok();
    let mut binary_file_in_progress =
        BinaryFileInProgress::new(binary_file_prefix_owned.as_deref());
    let mut command_in_progress = CommandInProgress::new();
    let mut disk_encryption_in_progress = DiskEncryptionInProgress::new();

    let mut reboot_requested = false;

    for (module, key, value) in si_in.iter() {
        log::trace!("Got module {}, command {}, value {:?}", module, key, value);
        if key == "active" {
            let value = value.as_bool().context("Error parsing active value")?;
            if value {
                log::trace!("Activating module {}", module);
                active_modules.insert(module);
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
        if module == FedoraIotServiceInfoModule::SSHKey.into() {
            let value = value.as_str().context("Error parsing sshkey value")?;
            if key == "username" {
                sshkey_user = Some(value.to_string());
            } else if key == "key" {
                sshkey_key = Some(value.to_string());
            }
        } else if module == FedoraIotServiceInfoModule::Reboot.into() {
            if key == "reboot" {
                let value = value.as_bool().context("Error parsing reboot value")?;
                reboot_requested = value;
                log::trace!("Got reboot value: {value}");
            }
        } else if module == RedHatComServiceInfoModule::SubscriptionManager.into() {
            if key == "organization_id" {
                let value = value
                    .as_str()
                    .with_context(|| format!("Error parsing rhsm {key} value"))?;
                rhsm_organization_id = Some(value.to_string());
            } else if key == "activation_key" {
                let value = value
                    .as_str()
                    .with_context(|| format!("Error parsing rhsm {key} value"))?;
                rhsm_activation_key = Some(value.to_string());
            } else if key == "perform_insights" {
                let value = value
                    .as_bool()
                    .with_context(|| format!("Error parsing rhsm {key} value"))?;
                rhsm_perform_insights = Some(value);
            }
        } else if module == FedoraIotServiceInfoModule::BinaryFile.into() {
            if key == "name" {
                if binary_file_in_progress.path.is_some() {
                    bail!(
                        "Got binary file path {:?} after path {:?}",
                        value,
                        binary_file_in_progress.path
                    );
                }
                binary_file_in_progress.path = Some(
                    value
                        .as_str()
                        .context("Error parsing binary file name")?
                        .to_string(),
                );
            } else if key == "length" {
                if binary_file_in_progress.length.is_some() {
                    bail!(
                        "Got binary file length {:?} after length {:?}",
                        value,
                        binary_file_in_progress.length
                    );
                }
                binary_file_in_progress.length =
                    Some(value.as_u64().context("Error parsing binary file length")?);
                binary_file_in_progress.contents = Some(Vec::with_capacity(
                    binary_file_in_progress.length.unwrap() as usize,
                ));
            } else if key.starts_with("data") {
                if binary_file_in_progress.contents.is_none() {
                    bail!("Got binary file data before length {:?}", value);
                }
                binary_file_in_progress
                    .contents
                    .as_mut()
                    .unwrap()
                    .extend_from_slice(value.as_bytes().context("Error parsing binary file data")?);
            } else if key == "mode" {
                if binary_file_in_progress.mode.is_some() {
                    bail!(
                        "Got binary file mode {:?} after mode {:?}",
                        value,
                        binary_file_in_progress.mode
                    );
                }
                binary_file_in_progress.mode =
                    Some(value.as_u32().context("Error parsing binary file mode")?);
            } else if key.starts_with("sha-") {
                let sha_type = key.split('-').nth(1).unwrap();
                let sha_value = value
                    .as_bytes()
                    .with_context(|| format!("Error parsing binary file sha-{sha_type} value"))?;
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
                    bail!("Got binary file sha-{} before name", sha_type);
                }
                if binary_file_in_progress.length.is_none() {
                    bail!("Got binary file sha-{} before length", sha_type);
                }
                let read_bytes = binary_file_in_progress.contents.as_ref().unwrap().len();
                if read_bytes != binary_file_in_progress.length.unwrap() as usize {
                    bail!(
                        "Got binary file (path {}) with length {} but only {} bytes of data",
                        binary_file_in_progress.path.as_ref().unwrap(),
                        binary_file_in_progress.length.unwrap(),
                        read_bytes
                    );
                }
                if let Err(e) = binary_file_in_progress
                    .digest
                    .as_ref()
                    .unwrap()
                    .compare_data(binary_file_in_progress.contents.as_ref().unwrap())
                {
                    bail!(
                        "Got binary file (path {}) with invalid digest: {:?}",
                        binary_file_in_progress.path.as_ref().unwrap(),
                        e
                    );
                }

                binary_file_in_progress
                    .deploy()
                    .context("Error deploying binary file")?;
                binary_file_in_progress =
                    BinaryFileInProgress::new(binary_file_prefix_owned.as_deref());
            }
        } else if module == FedoraIotServiceInfoModule::Command.into() {
            if key == "command" {
                if command_in_progress.command.is_some() {
                    bail!(
                        "Got command {:?} after command {:?}",
                        value,
                        command_in_progress.command
                    );
                }
                command_in_progress.command =
                    Some(value.as_str().context("Error parsing command")?.to_string());
            } else if key == "args" {
                command_in_progress.args =
                    value.as_str_array().context("Error parsing command args")?;
            } else if key == "may_fail" {
                command_in_progress.may_fail =
                    value.as_bool().context("Error parsing command may_fail")?;
            } else if key == "return_stdout" {
                command_in_progress.return_stdout = value
                    .as_bool()
                    .context("Error parsing command return_stdout")?;
            } else if key == "return_stderr" {
                command_in_progress.return_stderr = value
                    .as_bool()
                    .context("Error parsing command return_stderr")?;
            } else if key == "execute" {
                command_in_progress
                    .execute(si_out)
                    .context("Error executing command")?;
                command_in_progress = CommandInProgress::new();
            }
        } else if module == FedoraIotServiceInfoModule::DiskEncryptionClevis.into() {
            if key == "disk-label" {
                if disk_encryption_in_progress.disk_label.is_some() {
                    bail!(
                        "Got clevis disk-label {:?} after disk-label {:?}",
                        value,
                        disk_encryption_in_progress.disk_label
                    );
                }
                disk_encryption_in_progress.disk_label = Some(
                    value
                        .as_str()
                        .context("Error parsing clevis disk-label")?
                        .to_string(),
                );
            } else if key == "pin" {
                if disk_encryption_in_progress.pin.is_some() {
                    bail!(
                        "Got clevis pin {:?} after pin {:?}",
                        value,
                        disk_encryption_in_progress.pin
                    );
                }
                disk_encryption_in_progress.pin = Some(
                    value
                        .as_str()
                        .context("Error parsing clevis pin")?
                        .to_string(),
                );
            } else if key == "config" {
                if disk_encryption_in_progress.config.is_some() {
                    bail!(
                        "Got clevis config {:?} after config {:?}",
                        value,
                        disk_encryption_in_progress.config
                    );
                }
                disk_encryption_in_progress.config = Some(
                    value
                        .as_str()
                        .context("Error parsing clevis pin config")?
                        .to_string(),
                );
            } else if key == "reencrypt" {
                disk_encryption_in_progress.reencrypt =
                    value.as_bool().context("Error parsing clevis reencrypt")?;
            } else if key == "execute" {
                disk_encryption_in_progress
                    .execute(si_out)
                    .context("Error executing clevis")?;
                disk_encryption_in_progress = DiskEncryptionInProgress::new();
            }
        }
    }

    // Do SSH
    if active_modules.contains(&FedoraIotServiceInfoModule::SSHKey.into()) {
        log::debug!("SSHkey module was active, installing SSH key");
        if sshkey_user.is_none() || sshkey_key.is_none() {
            bail!("SSHkey module missing username or key");
        }
        create_user(sshkey_user.as_ref().unwrap()).context(format!(
            "Error creating new user: {}",
            sshkey_user.as_ref().unwrap()
        ))?;
        install_ssh_key(sshkey_user.as_ref().unwrap(), sshkey_key.as_ref().unwrap())
            .context("Error installing SSH key")?;
        set_passwordless_login(sshkey_user.as_ref().unwrap())
            .context("Error setting up passwordless login")?;
    }

    // Perform RHSM
    if active_modules.contains(&RedHatComServiceInfoModule::SubscriptionManager.into()) {
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

    Ok(reboot_requested)
}

pub(crate) async fn perform_to2_serviceinfos(client: &mut ServiceClient) -> Result<bool> {
    let mut loop_num = 0;
    let mut out_si = ServiceInfo::new();
    let mut reboot_required = false;

    while loop_num < MAX_SERVICE_INFO_LOOPS {
        if loop_num == 0 {
            let modules = find_available_modules().context("Error getting list of modules")?;
            let sysinfo = sys_info::linux_os_release()
                .context("Error getting operating system information")?;

            // We just blindly send the devmod module
            out_si.add(StandardServiceInfoModule::DevMod, "active", &true)?;
            out_si.add(
                StandardServiceInfoModule::DevMod,
                "os",
                &std::env::consts::OS,
            )?;
            out_si.add(
                StandardServiceInfoModule::DevMod,
                "arch",
                &std::env::consts::ARCH,
            )?;
            out_si.add(
                StandardServiceInfoModule::DevMod,
                "version",
                &sysinfo.pretty_name.unwrap(),
            )?;
            out_si.add(StandardServiceInfoModule::DevMod, "device", &"unused")?;
            out_si.add(StandardServiceInfoModule::DevMod, "sep", &":")?;
            out_si.add(
                StandardServiceInfoModule::DevMod,
                "bin",
                &std::env::consts::ARCH,
            )?;
            out_si.add_modules(&modules)?;
        }

        let send_si = DeviceServiceInfo::new(false, out_si);
        out_si = ServiceInfo::new();
        log::trace!("Sending ServiceInfo loop {}: {:?}", loop_num, send_si);

        let return_si: RequestResult<OwnerServiceInfo> = client.send_request(send_si, None).await;
        let return_si =
            return_si.with_context(|| format!("Error during ServiceInfo loop {loop_num}"))?;
        log::trace!("Got ServiceInfo loop {}: {:?}", loop_num, return_si);

        if return_si.is_done() {
            log::trace!("ServiceInfo loops done, number taken: {}", loop_num);
            return Ok(reboot_required);
        }
        if return_si.is_more_service_info() {
            // TODO
            bail!("OwnerServiceInfo indicated it has more for us.. we don't support that yet");
        }

        // Process
        let reboot_si = process_serviceinfo_in(return_si.service_info(), &mut out_si)
            .await
            .context("Error processing returned serviceinfo")?;
        if !reboot_required {
            reboot_required = reboot_si;
        }

        loop_num += 1;
    }
    Err(anyhow!(
        "Maximum number of ServiceInfo loops ({}) exceeded",
        MAX_SERVICE_INFO_LOOPS
    ))
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use super::BinaryFileInProgress;

    #[test]
    fn test_binaryfileinprogress_destination_path() {
        assert_eq!(
            BinaryFileInProgress::destination_path(
                &String::from("/etc/something"),
                Some("/usr/prefix")
            )
            .unwrap(),
            PathBuf::from("/usr/prefix/etc/something")
        );
        assert_eq!(
            BinaryFileInProgress::destination_path(&String::from("/etc/something"), None).unwrap(),
            PathBuf::from("/etc/something")
        );
    }
}
