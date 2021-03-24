use anyhow::{anyhow, bail, Context, Result};

use fdo_data_formats::{
    messages::to2::{DeviceServiceInfo, OwnerServiceInfo},
    types::{CborSimpleType, ServiceInfo},
};
use fdo_http_wrapper::client::{RequestResult, ServiceClient};

const MAX_SERVICE_INFO_LOOPS: u32 = 1000;
const MODULES: &[&str] = &["devmod"];

pub(crate) async fn perform_to2_serviceinfos(client: &mut ServiceClient) -> Result<()> {
    let mut loop_num = 0;
    while loop_num < MAX_SERVICE_INFO_LOOPS {
        let mut out_si = ServiceInfo::new();

        if loop_num == 0 {
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
            out_si.add_modules(&MODULES)?;
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
        for service_info in return_si.service_info().iter() {
            // TODO
        }

        loop_num += 1;
    }
    Err(anyhow!(
        "Maximum number of ServiceInfo loops ({}) exceeded",
        MAX_SERVICE_INFO_LOOPS
    ))
}
