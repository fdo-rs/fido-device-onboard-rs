use anyhow::{Error, Result};
use serde::Deserialize;

use fdo_data_formats::{messages, types::ServiceInfo};
use fdo_http_wrapper::server::Session;

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceInfoSettings {
    rhsm_organization_id: Option<String>,
    rhsm_activation_key: Option<String>,
    rhsm_run_insights: Option<bool>,

    sshkey_user: Option<String>,
    sshkey_key: Option<String>,
}

#[derive(Debug)]
pub struct ServiceInfoConfiguration {
    settings: ServiceInfoSettings,
}

impl ServiceInfoConfiguration {
    pub(crate) fn from_settings(settings: ServiceInfoSettings) -> Result<Self> {
        Ok(ServiceInfoConfiguration { settings })
    }
}

pub(crate) async fn perform_service_info(
    user_data: super::OwnerServiceUDT,
    _session: &mut Session,
    msg: messages::to2::DeviceServiceInfo,
    loop_num: u32,
) -> Result<messages::to2::OwnerServiceInfo, Error> {
    let in_si = msg.service_info();
    let mut out_si = ServiceInfo::new();
    let is_done = loop_num != 0;

    log::trace!("Received ServiceInfo loop {}: {:?}", loop_num, in_si);

    for (module, var, value) in in_si.iter() {
        log::trace!("Received module {}, var {}, value {:?}", module, var, value);
        if module == "devmod" && var == "modules" {
            let mut rawmodlist: Vec<serde_cbor::Value> = serde_cbor::value::from_value(value)?;
            log::trace!("Received module list: {:?}", rawmodlist);

            // Skip the first two items.... They are integers :()
            let mut modlist: Vec<String> = Vec::new();
            for rawmod in rawmodlist.drain(..).skip(2) {
                modlist.push(serde_cbor::value::from_value(rawmod)?);
            }
            log::trace!("Module list: {:?}", modlist);

            if modlist.iter().any(|name| name == "sshkey")
                && user_data
                    .service_info_configuration
                    .settings
                    .sshkey_user
                    .is_some()
            {
                log::trace!("Found SSH key module, sending SSH key information");

                out_si.add("sshkey", "active", &true)?;
                out_si.add(
                    "sshkey",
                    "username",
                    &user_data
                        .service_info_configuration
                        .settings
                        .sshkey_user
                        .as_ref()
                        .unwrap(),
                )?;
                out_si.add(
                    "sshkey",
                    "key",
                    &user_data
                        .service_info_configuration
                        .settings
                        .sshkey_key
                        .as_ref()
                        .unwrap(),
                )?;
            }

            if modlist.iter().any(|name| name == "rhsm")
                && user_data
                    .service_info_configuration
                    .settings
                    .rhsm_organization_id
                    .is_some()
            {
                log::trace!("Found RHSM module, sending RHSM information");

                out_si.add("rhsm", "active", &true)?;
                out_si.add(
                    "rhsm",
                    "organization_id",
                    &user_data
                        .service_info_configuration
                        .settings
                        .rhsm_organization_id
                        .as_ref()
                        .unwrap(),
                )?;
                out_si.add(
                    "rhsm",
                    "activation_key",
                    &user_data
                        .service_info_configuration
                        .settings
                        .rhsm_activation_key
                        .as_ref()
                        .unwrap(),
                )?;
                out_si.add(
                    "rhsm",
                    "perform_insights",
                    &user_data
                        .service_info_configuration
                        .settings
                        .rhsm_run_insights
                        .as_ref()
                        .unwrap(),
                )?;
            }
        }
    }

    log::trace!("Sending ServiceInfo loop {}: {:?}", loop_num, out_si);
    Ok(messages::to2::OwnerServiceInfo::new(false, is_done, out_si))
}
