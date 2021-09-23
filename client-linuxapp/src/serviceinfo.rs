use std::path::Path;
use std::process::Command;
use std::{env, fs};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use fdo_data_formats::{
    messages::to2::{DeviceServiceInfo, OwnerServiceInfo},
    types::ServiceInfo,
};
use fdo_http_wrapper::client::{RequestResult, ServiceClient};

const MAX_SERVICE_INFO_LOOPS: u32 = 1000;

fn find_available_modules() -> Result<Vec<String>> {
    let mut module_list = vec![
        // These modules are always here
        "devmod".to_string(),
        "sshkey".to_string(),
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
    let key_path = if let Ok(val) = env::var("SSH_KEY_PATH") {
        PathBuf::from(&val)
    } else {
        let user_info = passwd::Passwd::from_name(user);
        if user_info.is_none() {
            bail!("User {} for SSH key installation missing", user);
        }
        let user_info = user_info.unwrap();
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

async fn process_serviceinfo_in(si_in: &ServiceInfo) -> Result<()> {
    let mut active_modules: Vec<String> = Vec::new();

    let mut sshkey_user: Option<String> = None;
    let mut sshkey_key: Option<String> = None;

    let mut rhsm_organization_id: Option<String> = None;
    let mut rhsm_activation_key: Option<String> = None;
    let mut rhsm_perform_insights: Option<bool> = None;

    for (module, key, value) in si_in.iter() {
        log::trace!("Got module {}, command {}, value {:?}", module, key, value);
        if key == "active" {
            let value: bool =
                serde_cbor::value::from_value(value).context("Error parsing active value")?;
            if value {
                log::trace!("Activating module {}", module);
                active_modules.push(module.to_string());
            } else {
                log::trace!("Deactivating module {}", module);
            }
            continue;
        }
        if module == "sshkey" {
            let value: String = serde_cbor::value::from_value(value)
                .with_context(|| format!("Error parsing sshkey {} value", key))?;
            if key == "username" {
                sshkey_user = Some(value);
            } else if key == "key" {
                sshkey_key = Some(value);
            }
        } else if module == "rhsm" {
            if key == "organization_id" {
                let value: String = serde_cbor::value::from_value(value)
                    .with_context(|| format!("Error parsing rhsm {} value", key))?;
                rhsm_organization_id = Some(value);
            } else if key == "activation_key" {
                let value: String = serde_cbor::value::from_value(value)
                    .with_context(|| format!("Error parsing rhsm {} value", key))?;
                rhsm_activation_key = Some(value);
            } else if key == "perform_insights" {
                let value: bool = serde_cbor::value::from_value(value)
                    .with_context(|| format!("Error parsing rhsm {} value", key))?;
                rhsm_perform_insights = Some(value);
            }
        }
    }

    // Do SSH
    if active_modules.iter().any(|name| name == "sshkey") {
        log::debug!("SSHkey module was active, installing SSH key");
        if sshkey_user.is_none() || sshkey_key.is_none() {
            bail!("SSHkey module missing username or key");
        }
        install_ssh_key(sshkey_user.as_ref().unwrap(), sshkey_key.as_ref().unwrap())
            .context("Error installing SSH key")?;
    }

    // Perform RHSM
    if active_modules.iter().any(|name| name == "rhsm") {
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
