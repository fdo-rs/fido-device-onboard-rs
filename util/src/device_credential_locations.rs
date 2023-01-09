use std::env;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};

use fdo_data_formats::{devicecredential::FileDeviceCredential, DeviceCredential, Serializable};

pub fn find() -> Option<Result<Box<dyn UsableDeviceCredentialLocation>>> {
    let device_credential_locations: &[Box<dyn DeviceCredentialLocation>] = &[
        Box::new(FileSystemPath {
            path: "/sys/firmware/qemu_fw_cfg/by_name/opt/device_onboarding/devicecredential/raw"
                .to_string(),
            deactivation_method: DeactivationMethod::None,
        }),
        Box::new(FileSystemPathEnv {
            env_var: "DEVICE_CREDENTIAL".to_string(),
        }),
        Box::new(FileSystemPath {
            path: "/etc/device-credentials".to_string(),
            deactivation_method: DeactivationMethod::Deactivate,
        }),
    ];

    for devcredloc in device_credential_locations {
        log::trace!("Checking for device credential at {:?}", devcredloc);
        if let Some(v) = devcredloc.resolve() {
            log::trace!("Resolved to: {:?}", v);
            return Some(v);
        }
    }

    None
}

#[derive(Debug, Clone, Copy)]
enum DeactivationMethod {
    None,
    Delete,
    Deactivate,
}

pub trait DeviceCredentialLocation: std::fmt::Debug {
    fn resolve(&self) -> Option<Result<Box<dyn UsableDeviceCredentialLocation>>>;
}

pub trait UsableDeviceCredentialLocation: DeviceCredentialLocation {
    fn read(&self) -> Result<Box<dyn DeviceCredential>>;
    fn deactivate(&self) -> Result<()>;
}

#[derive(Debug, Clone)]
struct FileSystemPath {
    path: String,
    deactivation_method: DeactivationMethod,
}

impl DeviceCredentialLocation for FileSystemPath {
    fn resolve(&self) -> Option<Result<Box<dyn UsableDeviceCredentialLocation>>> {
        if Path::new(&self.path).exists() {
            Some(Ok(Box::new(self.clone())))
        } else {
            log::trace!("No (device credential) file exists at {}", &self.path);
            None
        }
    }
}

impl UsableDeviceCredentialLocation for FileSystemPath {
    fn read(&self) -> Result<Box<dyn DeviceCredential>> {
        let contents = fs::read(&self.path)
            .with_context(|| format!("Error reading (device credential) file at {}", &self.path))?;
        let fdc = FileDeviceCredential::deserialize_data(&contents)
            .with_context(|| format!("Error parsing device credential from {}", &self.path))?;
        Ok(Box::new(fdc))
    }

    fn deactivate(&self) -> Result<()> {
        match self.deactivation_method {
            DeactivationMethod::None => Ok(()),
            DeactivationMethod::Delete => fs::remove_file(&self.path)
                .with_context(|| format!("Error deleting file at {}", &self.path)),
            DeactivationMethod::Deactivate => self.perform_deactivation(),
        }
    }
}

impl FileSystemPath {
    fn perform_deactivation(&self) -> Result<()> {
        let contents = fs::read(&self.path)
            .with_context(|| format!("Error reading (device credential) file at {}", &self.path))?;
        let mut fdc = FileDeviceCredential::deserialize_data(&contents)
            .with_context(|| format!("Error parsing device credential from {}", &self.path))?;

        fdc.active = false;
        let new_dc_contents = fdc
            .serialize_data()
            .context("Error serializing deactivating device credential")?;
        self.write(new_dc_contents)
            .context("Error writing out new device credential for deactivation")
    }

    fn write(&self, new_contents: Vec<u8>) -> Result<()> {
        fs::write(&self.path, new_contents)
            .with_context(|| format!("Error writing to file at {}", &self.path))
    }
}

#[derive(Debug)]
struct FileSystemPathEnv {
    env_var: String,
}

impl DeviceCredentialLocation for FileSystemPathEnv {
    fn resolve(&self) -> Option<Result<Box<dyn UsableDeviceCredentialLocation>>> {
        let env_val = match env::var_os(&self.env_var) {
            None => return None,
            Some(v) => match v.into_string() {
                Ok(s) => s,
                Err(_) => return Some(Err(anyhow!("Invalid environment variable value"))),
            },
        };
        let deactivation_method = match env::var_os(format!("{}_DELETE", &self.env_var)) {
            None => match env::var_os(format!("{}_DEACTIVATE", &self.env_var)) {
                None => DeactivationMethod::None,
                Some(_) => DeactivationMethod::Deactivate,
            },
            Some(_) => DeactivationMethod::Delete,
        };
        log::trace!(
            "Resolved environment variable {} to filesystem path {} (deactivation method {:?})",
            &self.env_var,
            &env_val,
            &deactivation_method,
        );

        FileSystemPath {
            path: env_val,
            deactivation_method,
        }
        .resolve()
    }
}
