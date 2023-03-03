### End-to-End (E2E)Testing setup:
Please follow this document if you would like to test FDO end-to-end scenario 
i.e. building the rhel for edge image using simplified installer and then provisioning & onboarding the system using FDO.

##### Pre-requisite : 
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

##### Running FDO servers
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

##### Updating config files
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
