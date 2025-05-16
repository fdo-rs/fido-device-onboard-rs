#!/bin/bash
set -euox pipefail

# Local variables
VM_NAME="fdo-disk-image"
GUEST_ADDRESS=192.168.100.50
SSH_USER="admin"
# FDO packages folder built by Packit Automation
FDO_PKG_FOLDER="/var/share/test-artifacts"

# Set up temporary files.
TEMPDIR=$(mktemp -d)

# SSH setup.
SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)
SSH_KEY=rhel-edge/key/ostree_key
EDGE_USER_PASSWORD=foobar

function clean_up {
    greenprint "🧼 Cleaning up"
    sudo rm -rf ./{Containerfile,output,config.toml}
    sudo podman logout registry.stage.redhat.io
    sudo podman rmi -a -f
    sudo rm -rf /var/lib/libvirt/images/{fdo-iso.qcow2,install.iso}
    sudo virsh net-destroy integration && sudo virsh net-undefine integration
    VM_STATUS=$(sudo virsh list --all | awk '{print $3}' | tail -n 2)
    if [[ $VM_STATUS == running ]]; then
        sudo virsh destroy "${VM_NAME}"
    fi
    sudo virsh undefine "${VM_NAME}" --nvram
    # TO DO: Remove tag from quay.io registry
    # skopeo delete --creds "${QUAY_USERNAME}:${QUAY_PASSWORD}" "${QUAY_REPO_URL}:${QUAY_REPO_TAG}"
}

# Colorful output.
function greenprint {
    echo -e "\033[1;32m${1}\033[0m"
}

wait_for_ssh_up () {
    SSH_STATUS=$(sudo ssh "${SSH_OPTIONS[@]}" -i "${SSH_KEY}" "${SSH_USER}@${1}" '/bin/bash -c "echo -n READY"')
    if [[ $SSH_STATUS == READY ]]; then
        echo 1
    else
        echo 0
    fi
}

check_result () {
    greenprint "🎏 Checking for test result"
    if [[ $RESULTS == 1 ]]; then
        greenprint "💚 Success"
    else
        greenprint "❌ Failed"
        clean_up
        exit 1
    fi
}

trap clean_up EXIT

sudo dnf install -y \
    cargo \
    openssl \
    openssl-devel \
    git \
    make \
    systemd \
    krb5-devel \
    python3-docutils \
    gpgme-devel \
    libassuan-devel \
    systemd-rpm-macros \
    rpmdevtools \
    golang \
    go-rpm-macros \
    python3-devel \
    selinux-policy-devel \
    device-mapper-devel \
    podman \
    qemu-img \
    qemu-kvm \
    libvirt-client \
    libvirt-daemon-kvm \
    libvirt-daemon \
    virt-install

# Manufacturing server setup
# Clone downstream repo custom branch (fdo simplified installer setup skipping disk encryption)
git clone -b fdo-man-server-infra https://github.com/mcattamoredhat/rhel-edge.git && cd rhel-edge
DOWNLOAD_NODE="${DOWNLOAD_NODE}" ./ostree-simplified-installer.sh
cd ..

# Login to Stage registry
sudo podman login -u "${STAGE_REDHAT_IO_USERNAME}" -p "${STAGE_REDHAT_IO_TOKEN}" registry.stage.redhat.io

# Register the system to be able to install missing packages
sudo subscription-manager register --username "${REDHAT_IO_USERNAME}" --password "${REDHAT_IO_TOKEN}"

# Prepare Containerfile
tee Containerfile > /dev/null << STOPHERE
FROM registry.stage.redhat.io/rhel10/rhel-bootc:10.0
RUN echo 'root' | passwd --stdin root

# Copy the local RPM files into the container
COPY "${FDO_PKG_FOLDER}/*" /tmp/

# Install packages
RUN dnf install -y \
    /tmp/fido-device-onboard-debuginfo-*.el10.x86_64.rpm \
    /tmp/fido-device-onboard-debugsource-*.el10.x86_64.rpm \
    /tmp/fdo-init-debuginfo-*.el10.x86_64.rpm \
    /tmp/fdo-init-*.el10.x86_64.rpm \
    /tmp/fdo-client-debuginfo-*.el10.x86_64.rpm \
    /tmp/fdo-client-*.el10.x86_64.rpm \
    clevis \
    clevis-dracut \
    clevis-luks \
    clevis-pin-tpm2 \
    clevis-systemd

RUN systemctl enable fdo-client-linuxapp.service
STOPHERE

# Create container image
sudo podman build -f Containerfile -t quay.io/"${QUAY_USERNAME}"/test-repository/rhel10-bootc:latest

# Push to quay.io
sudo podman push rhel10-bootc --creds="${QUAY_USERNAME}":"${QUAY_PASSWORD}" quay.io/"${QUAY_USERNAME}"/test-repository/rhel10-bootc:latest

mkdir -pv output

# Create config.toml with kickstart information
tee config.toml > /dev/null << STOPHERE
[customizations.installer.kickstart]
contents = """
text
lang en_US.UTF-8
keyboard us
timezone --utc Etc/UTC
selinux --enforcing
rootpw --plaintext root
user --name=admin --groups=wheel --iscrypted --password=\$6\$1LgwKw9aOoAi/Zy9\$Pn3ErY1E8/yEanJ98evqKEW.DZp24HTuqXPJl6GYCm8uuobAmwxLv7rGCvTRZhxtcYdmC0.XnYRSR9Sh6de3p0
sshkey --username=admin "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzxo5dEcS+LDK/OFAfHo6740EyoDM8aYaCkBala0FnWfMMTOq7PQe04ahB0eFLS3IlQtK5bpgzxBdFGVqF6uT5z4hhaPjQec0G3+BD5Pxo6V+SxShKZo+ZNGU3HVrF9p2V7QH0YFQj5B8F6AicA3fYh2BVUFECTPuMpy5A52ufWu0r4xOFmbU7SIhRQRAQz2u4yjXqBsrpYptAvyzzoN4gjUhNnwOHSPsvFpWoBFkWmqn0ytgHg3Vv9DlHW+45P02QH1UFedXR2MqLnwRI30qqtaOkVS+9rE/dhnR+XPpHHG+hv2TgMDAuQ3IK7Ab5m/yCbN73cxFifH4LST0vVG3Jx45xn+GTeHHhfkAfBSCtya6191jixbqyovpRunCBKexI5cfRPtWOitM3m7Mq26r7LpobMM+oOLUm4p0KKNIthWcmK9tYwXWSuGGfUQ+Y8gt7E0G06ZGbCPHOrxJ8lYQqXsif04piONPA/c9Hq43O99KPNGShONCS9oPFdOLRT3U= ostree-image-test"
bootloader --timeout=1 --append="net.ifnames=0 modprobe.blacklist=vc4"
network --bootproto=dhcp --device=link --activate --onboot=on
zerombr
clearpart --all --initlabel --disklabel=msdos
autopart --nohome --noswap --type=plain
poweroff
%post --log=/var/log/anaconda/post-install.log --erroronfail
export MANUFACTURING_SERVER_URL="http://192.168.100.1:8080"
export DIUN_PUB_KEY_INSECURE="true"
/usr/libexec/fdo/fdo-manufacturing-client
# no sudo password for SSH user
echo -e 'admin\tALL=(ALL)\tNOPASSWD: ALL' >> /etc/sudoers
# Remove any persistent NIC rules generated by udev
rm -vf /etc/udev/rules.d/*persistent-net*.rules
# And ensure that we will do DHCP on eth0 on startup
cat > /etc/sysconfig/network-scripts/ifcfg-eth0 << EOF
DEVICE="eth0"
BOOTPROTO="dhcp"
ONBOOT="yes"
TYPE="Ethernet"
PERSISTENT_DHCLIENT="yes"
EOF
echo "Packages within this iot or edge image:"
echo "-----------------------------------------------------------------------"
rpm -qa | sort
echo "-----------------------------------------------------------------------"
# Note that running rpm recreates the rpm db files which aren't needed/wanted
rm -f /var/lib/rpm/__db*
echo "Zeroing out empty space."
# This forces the filesystem to reclaim space from deleted files
dd bs=1M if=/dev/zero of=/var/tmp/zeros || :
rm -f /var/tmp/zeros
echo "(Don't worry -- that out-of-space error was expected.)"
%end
"""
STOPHERE

# Ensure the image has been fetched
sudo podman pull --creds="${QUAY_USERNAME}":"${QUAY_PASSWORD}" quay.io/"${QUAY_USERNAME}"/test-repository/rhel10-bootc

# Generate disk image using bib
sudo podman run \
    --rm \
    -it \
    --privileged \
    --pull=newer \
    --security-opt label=type:unconfined_t \
    -v $(pwd)/config.toml:/config.toml:ro \
    -v $(pwd)/output:/output \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    registry.stage.redhat.io/rhel10/bootc-image-builder:10.0 \
    --type iso \
    --local \
    --config /config.toml \
    quay.io/"${QUAY_USERNAME}"/test-repository/rhel10-bootc

sudo qemu-img create -f qcow2 /var/lib/libvirt/images/fdo-iso.qcow2 20G
sudo cp output/bootiso/install.iso /var/lib/libvirt/images/
sudo restorecon -Rv /var/lib/libvirt/images/
sudo virt-install  --name="${VM_NAME}" \
                --disk path=/var/lib/libvirt/images/fdo-iso.qcow2,format=qcow2 \
                --ram 3072 \
                --vcpus 2 \
                --network network=integration,mac=34:49:22:B0:83:30 \
                --os-type linux \
                --os-variant rhel10-unknown \
                --cdrom /var/lib/libvirt/images/install.iso \
                --boot uefi \
                --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb \
                --nographics \
                --noautoconsole \
                --wait=-1 \
                --noreboot

# Start VM.
greenprint "Start VM"
sudo virsh start "${VM_NAME}"

# Check for ssh ready to go.
greenprint "🛃 Checking for SSH is ready to go"
for _ in $(seq 0 30); do
    RESULTS="$(wait_for_ssh_up $GUEST_ADDRESS)"
    if [[ $RESULTS == 1 ]]; then
        echo "SSH is ready now! 🥳"
        break
    fi
    sleep 10
done

# Check image installation result
check_result

# Add instance IP address into /etc/ansible/hosts
tee "${TEMPDIR}"/inventory > /dev/null << EOF
[image_mode_guest]
${GUEST_ADDRESS}

[image_mode_guest:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_user=${SSH_USER}
ansible_private_key_file=${SSH_KEY}
ansible_ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
ansible_become=yes
ansible_become_method=sudo
ansible_become_pass=${EDGE_USER_PASSWORD}
EOF

# Test IoT/Edge OS
podman run --network=host --annotation run.oci.keep_original_groups=1 -v "$(pwd)":/work:z -v "${TEMPDIR}":/tmp:z --rm quay.io/rhel-edge/ansible-runner:latest ansible-playbook -v -i /tmp/inventory -e fdo_credential="true" check-fido-device-onboard.yaml || RESULTS=0

# Check test result
check_result

exit 0
