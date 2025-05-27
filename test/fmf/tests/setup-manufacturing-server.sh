#!/bin/bash
set -euox pipefail

# Provision the software under test.
./setup.sh

# Get OS data.
source /etc/os-release
ARCH=$(uname -m)

# Generate key and cert used by FDO
sudo mkdir -p /etc/fdo/keys
for obj in diun manufacturer device-ca owner; do
    sudo fdo-admin-tool generate-key-and-cert --destination-dir /etc/fdo/keys "$obj"
done

# Copy configuration files
sudo mkdir -p \
    /etc/fdo/manufacturing-server.conf.d/ \
    /etc/fdo/owner-onboarding-server.conf.d/ \
    /etc/fdo/rendezvous-server.conf.d/ \
    /etc/fdo/serviceinfo-api-server.conf.d/

sudo cp files/fdo/manufacturing-server.yml /etc/fdo/manufacturing-server.conf.d/
sudo cp files/fdo/owner-onboarding-server.yml /etc/fdo/owner-onboarding-server.conf.d/
sudo cp files/fdo/rendezvous-server.yml /etc/fdo/rendezvous-server.conf.d/
sudo cp files/fdo/serviceinfo-api-server.yml /etc/fdo/serviceinfo-api-server.conf.d/

# Install yq to modify service api server config yaml file
# Workaround - https://issues.redhat.com/browse/RHEL-21528
if [[ "${ID}-${VERSION_ID}" == "rhel-8.8" ]] || [[ "${ID}-${VERSION_ID}" == "rhel-8.6" ]]; then
    sudo yum update -y platform-python
fi
# end workaround

sudo pip3 install yq
echo "Change vda4 to vda3 for fedora in serviceinfo config file"
sudo sed -i 's/vda4/vda3/' /etc/fdo/serviceinfo-api-server.conf.d/serviceinfo-api-server.yml

sudo systemctl start \
    fdo-owner-onboarding-server.service \
    fdo-rendezvous-server.service \
    fdo-manufacturing-server.service \
    fdo-serviceinfo-api-server.service

# Set up variables.
FDO_SERVER_ADDRESS=192.168.100.1
FDO_USER_ONBOARDING="true"

if [[ "$FDO_USER_ONBOARDING" == "true" ]]; then
    # FDO user does not have password, use ssh key and no sudo password instead
    sudo /usr/local/bin/yq -iy '.service_info.initial_user |= {username: "fdouser", sshkeys: ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzxo5dEcS+LDK/OFAfHo6740EyoDM8aYaCkBala0FnWfMMTOq7PQe04ahB0eFLS3IlQtK5bpgzxBdFGVqF6uT5z4hhaPjQec0G3+BD5Pxo6V+SxShKZo+ZNGU3HVrF9p2V7QH0YFQj5B8F6AicA3fYh2BVUFECTPuMpy5A52ufWu0r4xOFmbU7SIhRQRAQz2u4yjXqBsrpYptAvyzzoN4gjUhNnwOHSPsvFpWoBFkWmqn0ytgHg3Vv9DlHW+45P02QH1UFedXR2MqLnwRI30qqtaOkVS+9rE/dhnR+XPpHHG+hv2TgMDAuQ3IK7Ab5m/yCbN73cxFifH4LST0vVG3Jx45xn+GTeHHhfkAfBSCtya6191jixbqyovpRunCBKexI5cfRPtWOitM3m7Mq26r7LpobMM+oOLUm4p0KKNIthWcmK9tYwXWSuGGfUQ+Y8gt7E0G06ZGbCPHOrxJ8lYQqXsif04piONPA/c9Hq43O99KPNGShONCS9oPFdOLRT3U= ostree-image-test"]}' /etc/fdo/serviceinfo-api-server.conf.d/serviceinfo-api-server.yml
    # No sudo password required by ansible
    # Change to /etc/fdo folder to workaround issue https://bugzilla.redhat.com/show_bug.cgi?id=2026795#c24
    sudo tee /var/lib/fdo/fdouser > /dev/null << EOF
fdouser ALL=(ALL) NOPASSWD: ALL
EOF
    sudo /usr/local/bin/yq -iy '.service_info.files |= [{path: "/etc/sudoers.d/fdouser", source_path: "/var/lib/fdo/fdouser"}]' /etc/fdo/serviceinfo-api-server.conf.d/serviceinfo-api-server.yml

    # Restart fdo-serviceinfo-api-server.service
    sudo systemctl restart fdo-serviceinfo-api-server.service
fi

# Wait for fdo server to be running
until [ "$(curl -X POST http://${FDO_SERVER_ADDRESS}:8080/ping)" == "pong" ]; do
    sleep 1;
done;

exit 0
