#! /bin/bash

set -xeuo pipefail

CONF_DIR="/etc/fdo"
KEYS_DIR="${CONF_DIR}/keys"
STORES_DIR="${CONF_DIR}/stores"
MIGRATIONS_BASE_DIR=/usr/share/doc/fdo/migrations/
PRIMARY_IP=127.0.0.1
DEVICE_CREDENTIAL=/etc/device-credentials
ONBOARDING_PERFORMED=/etc/device_onboarding_performed

OWNER_DATABASE="owner_onboarding"
MANUFACTURER_DATABASE="manufacturing"
RENDEZVOUS_DATABASE="rendezvous"
DATABASES="${MANUFACTURER_DATABASE} ${OWNER_DATABASE} ${RENDEZVOUS_DATABASE}"

OV_STORE_DRIVER="${OV_STORE_DRIVER:-Directory}"

SERVICE_INFO_DIR="/var/lib/fdo/service-info/files"

DATABASE_DRIVER="None"
[ "${OV_STORE_DRIVER}" != "Postgres" ] || DATABASE_DRIVER="postgresql"
[ "${OV_STORE_DRIVER}" != "Sqlite" ] || DATABASE_DRIVER="sqlite"

DATABASE_DIR=/var/lib/fdo
DATABASE_USER="fdo"
DATABASE_PASSWORD="redhat"

[ "$DATABASE_DRIVER" != "postgresql" ] || DATABASE_URL="${DATABASE_DRIVER}://${DATABASE_USER}:${DATABASE_PASSWORD}@127.0.0.1/fdo"
[ "$DATABASE_DRIVER" != "sqlite" ] || DATABASE_URL="${DATABASE_DRIVER}://${DATABASE_DIR}/fido-device-onboard.db"

generate_fdo_certificates() {
  ORGANIZATION="Red Hat"
  COUNTRY="US"
  VALIDITY="3650"
  for SUBJECT in diun manufacturer device-ca owner; do
     fdo-admin-tool generate-key-and-cert --organization "${ORGANIZATION}" \
                                          --country "${COUNTRY}" \
                                          --validity-ends "${VALIDITY}" \
                                          --destination-dir "${KEYS_DIR}" \
                                          $SUBJECT
  done
}

generate_serviceinfo_files() {
  mkdir -p ${SERVICE_INFO_DIR}/etc/{sudoers.d,pki/ca-trust/source/anchors}
  cat > "${SERVICE_INFO_DIR}/etc/hosts" <<EOF
127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4
::1 localhost localhost.localdomain localhost6 localhost6.localdomain6
EOF
  cat > "${SERVICE_INFO_DIR}/etc/sudoers.d/edge" <<EOF
edge ALL=(ALL) NOPASSWD: ALL
EOF
  cat > "${SERVICE_INFO_DIR}/etc/pki/ca-trust/source/anchors/isrg-root-x2-cross-signed.crt" <<EOF
-----BEGIN CERTIFICATE-----
MIIEYDCCAkigAwIBAgIQB55JKIY3b9QISMI/xjHkYzANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFy
Y2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yMDA5MDQwMDAwMDBa
Fw0yNTA5MTUxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5l
dCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgy
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0H
ttwW+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7
AlF9ItgKbppbd9/w+kHsOdx1ymgHDB/qo4HlMIHiMA4GA1UdDwEB/wQEAwIBBjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR8Qpau3ktIO/qS+J6Mz22LqXI3lTAf
BgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcBAQQmMCQw
IgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wJwYDVR0fBCAwHjAc
oBqgGIYWaHR0cDovL3gxLmMubGVuY3Iub3JnLzAiBgNVHSAEGzAZMAgGBmeBDAEC
ATANBgsrBgEEAYLfEwEBATANBgkqhkiG9w0BAQsFAAOCAgEAG38lK5B6CHYAdxjh
wy6KNkxBfr8XS+Mw11sMfpyWmG97sGjAJETM4vL80erb0p8B+RdNDJ1V/aWtbdIv
P0tywC6uc8clFlfCPhWt4DHRCoSEbGJ4QjEiRhrtekC/lxaBRHfKbHtdIVwH8hGR
Ib/hL8Lvbv0FIOS093nzLbs3KvDGsaysUfUfs1oeZs5YBxg4f3GpPIO617yCnpp2
D56wKf3L84kHSBv+q5MuFCENX6+Ot1SrXQ7UW0xx0JLqPaM2m3wf4DtVudhTU8yD
ZrtK3IEGABiL9LPXSLETQbnEtp7PLHeOQiALgH6fxatI27xvBI1sRikCDXCKHfES
c7ZGJEKeKhcY46zHmMJyzG0tdm3dLCsmlqXPIQgb5dovy++fc5Ou+DZfR4+XKM6r
4pgmmIv97igyIintTJUJxCD6B+GGLET2gUfA5GIy7R3YPEiIlsNekbave1mk7uOG
nMeIWMooKmZVm4WAuR3YQCvJHBM8qevemcIWQPb1pK4qJWxSuscETLQyu/w4XKAM
YXtX7HdOUM+vBqIPN4zhDtLTLxq9nHE+zOH40aijvQT2GcD5hq/1DhqqlWvvykdx
S2McTZbbVSMKnQ+BdaDmQPVkRgNuzvpqfQbspDQGdNpT2Lm4xiN9qfgqLaSCpi4t
EcrmzTFYeYXmchynn9NM0GbQp7s=
-----END CERTIFICATE-----
EOF

}


generate_ssh_key() {
  SSH_KEY_TMP_DIR=$(mktemp -d)
  SSH_KEY_FILE="${SSH_KEY_TMP_DIR}/ssh_key"
  SSH_PUB_KEY_FILE="${SSH_KEY_FILE}.pub"
  ssh-keygen -q -N '' -f "${SSH_KEY_FILE}"
  cat "${SSH_PUB_KEY_FILE}"
  rm -rf "${SSH_KEY_TMP_DIR}"
}

setup_postgresql() {
  systemctl stop postgresql.service
  rm -rf /var/lib/pgsql/data
  postgresql-setup --initdb
  sed -ie 's|^host\(\s*\)all\(\s*\)all\(.*\)ident|host\1all\2all\3password|' /var/lib/pgsql/data/pg_hba.conf
  systemctl enable --now postgresql.service
  su - postgres -c "dropuser -e --if-exists ${DATABASE_USER}"
  su - postgres -c "createuser -e ${DATABASE_USER}"
  su - postgres -c "psql -e -c \"ALTER USER ${DATABASE_USER} WITH PASSWORD '${DATABASE_PASSWORD}'\""
  su - postgres -c "dropdb -e --if-exists fdo"
  su - postgres -c "createdb -e -O ${DATABASE_USER} fdo"
  for DATABASE in ${DATABASES}; do
    su - postgres -c "PGPASSWORD=${DATABASE_PASSWORD} psql --host 127.0.0.1 --username ${DATABASE_USER} --echo-queries fdo < ${MIGRATIONS_BASE_DIR}/migrations_${DATABASE}_server_postgres/up.sql"
  done
}

setup_sqlite() {
  mkdir -p ${DATABASE_DIR}
  DATABASE_FILE="${DATABASE_DIR}/fido-device-onboard.db"
  true > ${DATABASE_FILE}
  for DATABASE in ${DATABASES}; do
    sqlite3 ${DATABASE_FILE} < "${MIGRATIONS_BASE_DIR}/migrations_${DATABASE}_server_sqlite/up.sql"
  done
}

setup_manufacturing() {
  [ "${OV_STORE_DRIVER}" != "Directory" ] || OV_STORE_DRIVER_CONF=$(echo -e "${OV_STORE_DRIVER}:\n    path: ${STORES_DIR}/owner_vouchers")
  [ "${OV_STORE_DRIVER}"  = "Directory" ] || OV_STORE_DRIVER_CONF=$(echo -e "${OV_STORE_DRIVER}:\n    server: Manufacturer\n    url: ${DATABASE_URL}")
  tee "${CONF_DIR}/manufacturing-server.yml" <<EOF
---
session_store_driver:
  Directory:
    path: ${STORES_DIR}/manufacturing_sessions
ownership_voucher_store_driver:
  ${OV_STORE_DRIVER_CONF}
public_key_store_driver:
  Directory:
    path: ${STORES_DIR}/manufacturer_keys
bind: "0.0.0.0:8080"
protocols:
  plain_di: false
  diun:
    mfg_string_type: SerialNumber
    key_type: SECP384R1
    allowed_key_storage_types:
      - FileSystem
    key_path: ${KEYS_DIR}/diun_key.der
    cert_path: ${KEYS_DIR}/diun_cert.pem
rendezvous_info:
  - deviceport: 8082
    ip_address: ${PRIMARY_IP}
    ownerport: 8082
    protocol: http
manufacturing:
  manufacturer_cert_path: ${KEYS_DIR}/manufacturer_cert.pem
  device_cert_ca_private_key: ${KEYS_DIR}/device_ca_key.der
  device_cert_ca_chain: ${KEYS_DIR}/device_ca_cert.pem
  owner_cert_path: ${KEYS_DIR}/owner_cert.pem
  manufacturer_private_key: ${KEYS_DIR}/manufacturer_key.der
...
EOF
}

setup_owner() {
  [ "${OV_STORE_DRIVER}" != "Directory" ] || OV_STORE_DRIVER_CONF=$(echo -e "${OV_STORE_DRIVER}:\n    path: ${STORES_DIR}/owner_vouchers")
  [ "${OV_STORE_DRIVER}"  = "Directory" ] || OV_STORE_DRIVER_CONF=$(echo -e "${OV_STORE_DRIVER}:\n    server: Owner\n    url: ${DATABASE_URL}")
  tee "${CONF_DIR}/owner-onboarding-server.yml" <<EOF
---
ownership_voucher_store_driver:
  ${OV_STORE_DRIVER_CONF}
session_store_driver:
  Directory:
    path: ${STORES_DIR}/owner_onboarding_sessions
trusted_device_keys_path: ${KEYS_DIR}/device_ca_cert.pem
owner_private_key_path: ${KEYS_DIR}/owner_key.der
owner_public_key_path: ${KEYS_DIR}/owner_cert.pem
bind: "0.0.0.0:8081"
service_info_api_url: "http://${PRIMARY_IP}:8083/device_info"
service_info_api_authentication:
  BearerToken:
    token: 2IOtlXsSqfcGjnhBLZjPiHIteskzZEW3lncRzpEmgqI=
owner_addresses:
  - transport: http
    addresses:
      - ip_address: ${PRIMARY_IP}
    port: 8081
report_to_rendezvous_endpoint_enabled: true
...
EOF
}

setup_rendezvous() {
  [ "${OV_STORE_DRIVER}" != "Directory" ] || OV_STORE_DRIVER_CONF=$(echo -e "${OV_STORE_DRIVER}:\n    path: ${STORES_DIR}/rendezvous_registered")
  [ "${OV_STORE_DRIVER}"  = "Directory" ] || OV_STORE_DRIVER_CONF=$(echo -e "${OV_STORE_DRIVER}:\n    server: Rendezvous\n    url: ${DATABASE_URL}")
  tee "${CONF_DIR}/rendezvous-server.yml" <<EOF
---
storage_driver:
  ${OV_STORE_DRIVER_CONF}
session_store_driver:
  Directory:
    path: ${STORES_DIR}/rendezvous_sessions
trusted_manufacturer_keys_path: ${KEYS_DIR}/manufacturer_cert.pem
trusted_device_keys_path: ${KEYS_DIR}/device_ca_cert.pem
max_wait_seconds: ~
bind: "0.0.0.0:8082"
EOF
}

setup_serviceinfo() {
 tee "${CONF_DIR}/serviceinfo-api-server.yml" <<EOF
---
service_info:
  initial_user:
    username: edge
    sshkeys:
    - "${SSH_PUB_KEY}"
  commands:
  - command: touch
    args:
    - /etc/command-testfile1
  - command: bash
    args:
    - -c
    - echo command-testfile1-content1 > /etc/command-testfile1
  - command: bash
    args:
    - -c
    - echo command-testfile1-content2 >> /etc/command-testfile1
  - command: mkdir
    args:
    - -p
    - /etc/commands
  - command: mv
    args:
    - /etc/command-testfile1
    - /etc/commands/
  - command: bash
    args:
    - -c
    - echo command-testfile2-content1 > /etc/commands/command-testfile2
  - command: bash
    args:
    - -c
    - echo command-testfile2-content2 >> /etc/commands/command-testfile2
  - command: rm
    args:
    - -rf
    - /etc/commands
  - command: find
    args:
    - /etc
    - /var
    - -type
    - f
    - -exec
    - touch {}
    - ;
  - command: mkdir
    args:
    - -p
    - /etc/sudoers.d /var/fdo /var/lib/fdo /var/fdo-test /var/lib/fdo-test
  - command: /usr/bin/sed
    args:
    - -i
    - -e
    - s/^#PasswordAuthentication yes/PasswordAuthentication no/
    - /etc/ssh/sshd_config
    may_fail: false
    return_stdout: true
    return_stderr: true
  - command: systemctl
    args:
    - restart
    - sshd
    return_stdout: true
    return_stderr: true
  - command: systemctl
    args:
    - daemon-reload
    return_stdout: true
    return_stderr: true
  files:
  - path: /etc/hosts
    permissions: 644
    source_path: ${SERVICE_INFO_DIR}/etc/hosts
  - path: /etc/sudoers.d/edge
    source_path: ${SERVICE_INFO_DIR}/etc/sudoers.d/edge
  - path: /etc/pki/ca-trust/source/anchors/isrg-root-x2-cross-signed.crt
    source_path: ${SERVICE_INFO_DIR}/etc/pki/ca-trust/source/anchors/isrg-root-x2-cross-signed.crt
#  diskencryption_clevis:
#  - disk_label: /dev/vda
#    binding:
#      pin: test
#      config: "{}"
#    reencrypt: true
#  after_onboarding_reboot: true
bind: 0.0.0.0:8083
service_info_auth_token: 2IOtlXsSqfcGjnhBLZjPiHIteskzZEW3lncRzpEmgqI=
admin_auth_token: Va40bSkLcxwnfml1pmIuaWaOZG96mSMB6fu0xuzcueg=
device_specific_store_driver:
  Directory:
    path: ${STORES_DIR}/serviceinfo_api_devices
EOF
}

export_import_vouchers() {
  MANUFACTURER_EXPORT_DIR="${STORES_DIR}/manufacturer_export_dir"
  rm -rf "${MANUFACTURER_EXPORT_DIR}"
  mkdir -p "${MANUFACTURER_EXPORT_DIR}"
  fdo-owner-tool export-manufacturer-vouchers "http://${PRIMARY_IP}:8080" --path "${MANUFACTURER_EXPORT_DIR}"
  sudo tar xvf "${MANUFACTURER_EXPORT_DIR}"/export.tar -C "${MANUFACTURER_EXPORT_DIR}"
  sudo rm -rf "${MANUFACTURER_EXPORT_DIR}"/export.tar
  fdo-owner-tool import-ownership-vouchers "$(tr "[:upper:]" "[:lower:]" <<< "${OV_STORE_DRIVER}")" "${DATABASE_URL}" "${MANUFACTURER_EXPORT_DIR}"
}

perform_no_plain_di() {
  rm -f "${DEVICE_CREDENTIAL}" "${ONBOARDING_PERFORMED}"
  LOG_LEVEL=trace /usr/libexec/fdo/fdo-manufacturing-client no-plain-di \
                                                            --manufacturing-server-url http://${PRIMARY_IP}:8080 \
                                                            --rootcerts ${KEYS_DIR}/diun_cert.pem
}

onboard() {
  LOG_LEVEL=trace /usr/libexec/fdo/fdo-client-linuxapp
}

[ "${OV_STORE_DRIVER}" != "Sqlite" ] || setup_sqlite
[ "${OV_STORE_DRIVER}" != "Postgres" ] || setup_postgresql
SSH_PUB_KEY=$(generate_ssh_key)
generate_fdo_certificates
setup_manufacturing
setup_owner
setup_rendezvous
generate_serviceinfo_files
setup_serviceinfo
systemctl restart fdo-{manufacturing,owner-onboarding,rendezvous,serviceinfo-api}-server.service
# Wait for servers to be up and running
for PORT in 808{0..3}; do
  until [ "$(curl -s -X POST http://${PRIMARY_IP}:${PORT}/ping)" == "pong" ]; do
      sleep 1;
  done;
done
perform_no_plain_di
[ "${OV_STORE_DRIVER}" = "Directory" ] || export_import_vouchers
sleep 60
onboard
