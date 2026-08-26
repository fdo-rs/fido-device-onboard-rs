# Testing

## End-to-End (E2E)Testing setup:
Please follow this document if you would like to test FDO end-to-end scenario 
i.e. building the rhel for edge image using simplified installer and then provisioning & onboarding the system using FDO.

### Pre-requisite : 
In order to test the end to end FDO scenario (i.e. building simplified iso image ,booting it in a vm and performing FIDO Device Onboarding) you need to have simplified installer image already built .Please follow README.md document from https://github.com/osbuild/rhel-for-edge-demo to built simplified installer image. You will need a Rhel system (or a vm if you are on other linux/mac machine).

Note: Please make a note while building simplified installer, provide the same manufacturing server ip that you will use in qemu command. In this case it is 10.0.2.2 .(which is used in installer.toml blueprint).

Now to start with FDO on-boarding , we need to install the simplified installer image. This also can be done using different tools, this document mentions use of qemu to install and boot virtual machine. Qemu can be used on both Linux and Mac machines. (Virt-install is also an option if you are on Linux/RHEL machine)
- Create a disk image where simplified installer iso will be installed. 
``` bash
qemu-img create -f qcow2 rhel.qcow2 20G
```
- You need to have uefi firmware installed on your system before using the below install command.
For mac download two files OVMF_CODE.fd, OVMF_VARS.fd from https://aur.archlinux.org/packages/edk2-ovmf-macos .
Install command:
``` bash
qemu-system-x86_64 \
-machine q35 \
-M accel=hvf \
-m 4096 \
-cpu max \
-cdrom simplified-installer.iso \
-drive file=rhel.qcow2,format=qcow2,index=0,media=disk,if=virtio \
-drive if=pflash,format=raw,readonly=on,file=/<path/to/>/ovmf/OVMF_CODE.fd \
-drive if=pflash,format=raw,file=/<path/to>/ovmf/OVMF_VARS.fd \
-device virtio-net-pci,netdev=n0,mac=FE:30:2E:2B:71:95 \
-netdev user,id=n0,net=10.0.2.0/24,hostfwd=tcp::8080-:8080 \
-rtc base=localtime
```

- After installation, qemu window closes and you can now boot into installed system with qemu boot command.
- Before that make sure you are running FDO servers. And you have updated config files for contacting servers.

### Running FDO servers
- Follow 'Developing / building' section in CONTRIBUTING.md file ,after successful build run below command inside vscode container to run FDO servers.
```bash
./target/debug/fdo-admin-tool aio --directory aio-dir
```
/target/debug folder contains all the fdo stack and generated binaries.
aio stands for All-In-One command, which basically can be used with fdo-admin-tool to configure & run manufacturing server, rendezvous server and owner-onboarding server. ‘Aio-dir’ is the directory you can provide where all this configs, keys and logs are generated.

On running this command output looks like this, if servers are running successfully.
```
 INFO  fdo_admin_tool::aio::execute > Starting AIO
 INFO  fdo_admin_tool::aio::execute > Waiting until services are ready
 INFO  fdo_admin_tool::aio::execute > All services are ready
 INFO  fdo_admin_tool::aio::execute > AIO running
```

### Updating config files
1. aio_configuration file 
```
contact_addresses:
    IpAddr: 10.0.2.2
    IpAddr: 172.17.0.3
```
You need to provide the same ip address which you used for manufacturing server ip while building a simplified installer image. 172.17.0.3 is the default created ip.
2. manufacturing_server.yml
```
rendezvous_info:
   deviceport: 8082
   ip_address: 10.0.2.2
   ownerport: 8082
   protocol: http
  deviceport: 8082
   ip_address: 172.17.0.3
   ownerport: 8082
   protocol: http
```
3. owner_onboarding_sever.yml
```
owner_addresses:
  transport: http
   addresses:
      ip_address: 10.0.2.2
      ip_address: 172.17.0.3
   port: 8081
```

In case you land up on an emergency shell upon booting into a simplified installer , you can run ‘ip route’ command to check if the manufacturing ip is the correct one that's mentioned in above config files.
Also you can use curl command to check connectivity with manufacturing server.
```bash
curl --request POST 'http://<ip>:8080/ping'
```
reply should be pong. 

- Boot command:
```bash
qemu-system-x86_64 \
-boot c \
-machine q35 \
-M accel=hvf \
-m 4096 \
-cpu max \
-cdrom simplified-installer.iso \
-drive file=rhel.qcow2,format=qcow2,index=0,media=disk,if=virtio \
-drive if=pflash,format=raw,readonly=on,file=/<path/to/>/ovmf/OVMF_CODE.fd \
-drive if=pflash,format=raw,file=/<path/to/>/ovmf/OVMF_VARS.fd \
-device virtio-net-pci,netdev=n0,mac=FE:30:2E:2B:71:95 \
-netdev user,id=n0,net=10.0.2.0/24,hostfwd=tcp::8080-:8080,hostfwd=tcp::2222-:22 \
-rtc base=localtime
```

qemu sometimes crashes ,so consider running the command again.
Now after booting you will be asked to enter username & password. This is the same you provided in the blueprint while creating edge-container.tar image. 

- Check if on-boarding has been done successfully. You will see device-credentials and device_onboarding_performed under /etc folder.
Also journalctl logs can be checked to see all the onboarding messages.
- You can also open ssh terminal which is easier to work with than the qemu console. 
```bash
ssh -p 2222 admin@localhost
```
- Mock onboarding: For testing purposes FDO onboarding can be mimicked by removing device_onboarding_performed from /etc and moving device-credentials file back to /boot folder.
Also on server side :
Check file attributes of OV (ownership voucher) under aio-dir/stores/owner_vouchers/ folder and reset them.
```bash
setfattr -x user.fdo.to0_accept_owner_wait_seconds aio-dir/stores/owner_vouchers/ 
setfattr -x user.fdo.to2_performed aio-dir/stores/owner_vouchers/ 
```
Now re-run the fdo servers and restart fdo-client-linuxapp.service on the virtual machine.


## Quick Onboarding Demo

This small demo demonstrates an Onbarding scenario were the Device that we want
to onboard will end up with a configuration file as part of the onboarding
process. 

For demo purposes everything will happen in a single machine and we will be
using the `aio` tool to spin up all the servers.

Running this demo with the production servers (`fdo-manufacturing-server`,
`fdo-owner-onboarding-server`, `fdo-rendezvous-server` and
`fdo-serviceinfo-api-server`) and configuring them to your specific needs
is left as an exercise to the reader.

1. Setting up the servers and configuration files.

   Run:
   
   ```bash
   fdo-admin-tool aio --directory aio-dir
   ```
   
   Once you see an output like this:
   ```
   INFO  fdo_admin_tool::aio > AIO directory not configured, creating it with default configuration
   INFO  fdo_admin_tool::aio::execute > Starting AIO
   INFO  fdo_admin_tool::aio::execute > Waiting until services are ready
   INFO  fdo_admin_tool::aio::execute > All services are ready
   INFO  fdo_admin_tool::aio::execute > AIO running
   ```
   
   kill the process. You'll end up with a directory structure as follows:
   
   ```
   aio-dir/
   ├── aio_configuration
   ├── configs
   │   ├── manufacturing_server.yml
   │   ├── owner_onboarding_server.yml
   │   ├── rendezvous_server.yml
   │   └── serviceinfo_api_server.yml
   ├── keys
   │   ├── device_ca_cert.pem
   │   ├── device_ca_key.der
   │   ├── diun_cert.pem
   │   ├── diun_key.der
   │   ├── manufacturer_cert.pem
   │   ├── manufacturer_key.der
   │   ├── owner_cert.pem
   │   └── owner_key.der
   ├── logs
   │   ├── fdo-manufacturing-server.stderr.log
   │   ├── fdo-manufacturing-server.stdout.log
   │   ├── fdo-owner-onboarding-server.stderr.log
   │   ├── fdo-owner-onboarding-server.stdout.log
   │   ├── fdo-rendezvous-server.stderr.log
   │   ├── fdo-rendezvous-server.stdout.log
   │   ├── fdo-serviceinfo-api-server.stderr.log
   │   └── fdo-serviceinfo-api-server.stdout.log
   ├── stores
   │   ├── manufacturer_keys
   │   ├── manufacturing_sessions
   │   ├── mfg_sessions
   │   ├── owner_onboarding_sessions
   │   ├── owner_sessions
   │   ├── owner_vouchers
   │   ├── rendezvous_registered
   │   ├── rendezvous_sessions
   │   ├── serviceinfo_api_devices
   │   └── serviceinfo_api_per_device
   └── work
   ```
   
   If you look in `aio-dir/configs` you'll have all the configuration files
   needed by servers already configured with some defaults for you.
   
2. Modify `serviceinfo_api_server.yml`.

   We'll modify that configuration file to specify what we want to do in the
   onboarding process, in this case we will put a file in the Device to be
   onbarded.
   
   Edit the `service_info:` `files:` section in `serviceinfo_api_server.yml` so
   that it looks like this:
   
   ```yaml
   files:
   - path: /home/fedora/destination-dir/the-file-has-moved-here
     permissions: 644
     source_path: /home/fedora/source-dir/configuration-file.config
   ```
   
   be mindful of the spaces and replace `/home/fedora/` in both paths with your
   home directory.
   
   You can look at [examples/config/service-info-api-server.yml](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/config/serviceinfo-api-server.yml)
   for a more detailed example.

3. Create the required directories and file.

   ```bash
   mkdir ~/destination-dir
   mkdir ~/source-dir
   echo "some configuration" > ~/source-dir/configuration-file.config
   ```
   
   In this demo `~/destination-dir` represents a directory in the Device, but
   for the sake of this demo it lives in your current machine. Similarly
   `~/source-dir/configuration-file.config` is a file that would exist in the
   `serviceinfo-api` server in production, but for demo purposes, this file is
   also located in your system.
   
3. Device set-up.
   
   Your system will also represent the Device that we will onboard during this
   demo, so we need to set it up. This process represents what would be done
   during the manufacturing supply line.
   
   Create the `rendezvous_info.yml` file.
   
   Copy the `rendezvous_info:` section of the
   `aio-dir/confi/manufacturing_server.yml` into a file named
   `rendezvous_info.yml` and modify it so it has this same structure:
   
   ```yaml
   ---
   - deviceport: 8082
     ip_address: 192.168.122.44
     ownerport: 8082
     protocol: http
   ```
   be mindful of the spaces. Your `ip_address` and `deviceport` may change but
   the structure should follow the given example.
   
   Generate an OV and a `device_credential`.
   
   ```bash
   fdo-owner-tool initialize-device 54321 ov device_credential \
   --device-cert-ca-chain ./aio-dir/keys/device_ca_cert.pem \
   --device-cert-ca-private-key ./aio-dir/keys/device_ca_key.der \
   --manufacturer-cert ./aio-dir/keys/manufacturer_cert.pem \
   --rendezvous-info rendezvous_info.yml 
   
   
   Created ownership voucher for device 9d8dcc63-f5af-ae2a-6841-a532b5c73175
   ```
   
   This will generate an OV named `ov` with the device credential file
   `file_credential`. `54321` is a random device id chosen for this example.
   The resulting OV will have the information of the `rendezvous_info.yml` file
   that we created before embedded into it.
   
   Note the device GUID that is returned as part of the output of the command,
   in this case `9d8dcc63-f5af-ae2a-6841-a532b5c73175`.
   
   Extend the OV with the owner certificate.
   ```bash
   fdo-owner-tool extend-ownership-voucher ov \
   --current-owner-private-key ./aio-dir/keys/manufacturer_key.der \
   --new-owner-cert ./aio-dir/keys/owner_cert.pem 
   ```
   
   Transform the OV to COSE format:
   ```bash
   fdo-owner-tool dump-ownership-voucher ov --outform cose > ov.cose
   ```
   
   Rename the OV in COSE format to the GUID that we got when we generated the
   `ov` and the `device_credential`:
   ```bash
   mv ov.cose 9d8dcc63-f5af-ae2a-6841-a532b5c73175
   ```
   
4. Configure the `owner-onboarding-server`.

   Copy the extended-ov-in-cose-format-renamed-to-the-GUID created in the
   previous step to the owner-onbarding server's storage:
   
   ```bash
   cp 9d8dcc63-f5af-ae2a-6841-a532b5c73175 ./aio-dir/stores/owner_vouchers/
   ```

5. Run the client and the servers.

   In one terminal tab, run the `aio` tool again:
   ```bash
   fdo-admin-tool aio --directory aio-dir
   ```
   leave that tab open. You might want to `tail -f` the different outputs
   generated by the servers' logs so that you can follow what is happening. The
   interesting logs are at `aio-dir/logs/*.stderr.log`.
   
   In another terminal tab, we will run `fdo-client-linuxapp` which is what
   the Device wanting to be onboarded would run, but first export the
   `device_credential` file that we created before so that the tool can find
   it:
   ```bash
   sudo export DEVICE_CREDENTIAL=device_credential
   sudo fdo-client-linuxapp
   ```
   
6. Check that `/home/fedora/destination-dir/the-file-has-moved-here` exists and
   that the device has successfully onboarded.
