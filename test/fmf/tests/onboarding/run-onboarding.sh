#! /bin/bash

set -xeuo pipefail

CONF_DIR="/etc/fdo"
KEYS_DIR="${CONF_DIR}/keys"
STORES_DIR="${CONF_DIR}/stores"
MIGRATIONS_BASE_DIR=/usr/share/doc/fdo/migrations/
PRIMARY_IP=$(hostname -I | cut -f 1 -d ' ')
DEVICE_CREDENTIAL=/etc/device-credentials
ONBOARDIG_PERFORMED=/etc/device_onboarding_performed

OWNER_DATABASE="owner_onboarding"
MANUFACTURER_DATABASE="manufacturing"
RENDEZVOUS_DATABASE="rendezvous"
DATABASES="${MANUFACTURER_DATABASE} ${OWNER_DATABASE} ${RENDEZVOUS_DATABASE}"

OV_STORE_DRIVER="${OV_STORE_DRIVER:-Directory}"

DATABASE_DRIVER="None"
[ "${OV_STORE_DRIVER}" != "Postgres" ] || DATABASE_DRIVER="postgresql"
[ "${OV_STORE_DRIVER}" != "Sqlite" ] || DATABASE_DRIVER="sqlite"

DATABASE_DIR=/var/lib/fdo
DATABASE_USER="fdo"
DATABASE_PASSWORD="redhat"

generate_keys() {
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

setup_postgresql() {
  systemctl stop postgresql.service
  rm -rf /var/lib/pgsql/data
  postgresql-setup --initdb
  sed -ie 's|^host\(\s*\)all\(\s*\)all\(.*\)ident|host\1all\2all\3password|' /var/lib/pgsql/data/pg_hba.conf
  systemctl enable --now postgresql.service
  su - postgres -c "dropuser -e --if-exists ${DATABASE_USER}"
  su - postgres -c "createuser -e ${DATABASE_USER}"
  su - postgres -c "psql -e -c \"ALTER USER ${DATABASE_USER} WITH PASSWORD '${DATABASE_PASSWORD}'\""
  for DATABASE in ${DATABASES}; do
    su - postgres -c "dropdb -e --if-exists ${DATABASE}"
    su - postgres -c "createdb -e -O ${DATABASE_USER} ${DATABASE}"
    su - postgres -c "PGPASSWORD=${DATABASE_PASSWORD} psql --host 127.0.0.1 --username ${DATABASE_USER} --echo-queries $DATABASE < ${MIGRATIONS_BASE_DIR}/migrations_${DATABASE}_server_postgres/up.sql"
  done
}

setup_sqlite() {
  mkdir -p ${DATABASE_DIR}
  for DATABASE in ${DATABASES}; do
    DATABASE_FILE="${DATABASE_DIR}/${DATABASE}.db"
    > ${DATABASE_FILE}
    sqlite3 ${DATABASE_FILE} < "${MIGRATIONS_BASE_DIR}/migrations_${DATABASE}_server_sqlite/up.sql"
  done
}

setup_systemd() {
  for DATABASE in ${DATABASES}; do
    SYSTEMD_OVERWRITE_DIR=/etc/systemd/system/fdo-${DATABASE/_/-}-server.service.d/
    rm -rf "$SYSTEMD_OVERWRITE_DIR}"
    if [ "${OV_STORE_DRIVER}" != "Directory" ]; then
      mkdir -p "${SYSTEMD_OVERWRITE_DIR}"
      DATABASE_ENV_VAR="$(tr [:lower:] [:upper:] <<<${OV_STORE_DRIVER})_$(tr [:lower:] [:upper:] <<<$DATABASE |sed -e 's|MANUFACTURING|MANUFACTURER|' -e 's|OWNER_ONBOARDING|OWNER|')_DATABASE_URL"
      [ "$DATABASE_DRIVER" != "postgresql" ] || DATABASE_URL="${DATABASE_DRIVER}://${DATABASE_USER}:${DATABASE_PASSWORD}@127.0.0.1/${DATABASE}"
      [ "$DATABASE_DRIVER" != "sqlite" ] || DATABASE_URL="${DATABASE_DRIVER}://${DATABASE_DIR}/${DATABASE}.db"
      tee "$SYSTEMD_OVERWRITE_DIR/override.conf" <<EOF
[Service]
Environment=${DATABASE_ENV_VAR}=${DATABASE_URL}
EOF
    fi
  done
  systemctl daemon-reload
}

setup_manufacturing() {
  [ "${OV_STORE_DRIVER}" != "Directory" ] || OV_STORE_DRIVER_CONF=$(echo -e "${OV_STORE_DRIVER}:\n    path: ${STORES_DIR}/owner_vouchers")
  [ "${OV_STORE_DRIVER}"  = "Directory" ] || OV_STORE_DRIVER_CONF=$(echo -e "${OV_STORE_DRIVER}:\n    Manufacturer")
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
  [ "${OV_STORE_DRIVER}"  = "Directory" ] || OV_STORE_DRIVER_CONF=$(echo -e "${OV_STORE_DRIVER}:\n    Owner")
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
  [ "${OV_STORE_DRIVER}"  = "Directory" ] || OV_STORE_DRIVER_CONF=$(echo -e "${OV_STORE_DRIVER}:\n    Rendezvous")
  tee "${CONF_DIR}/rendezvous-server.yml" <<EOF
---
storage_driver:
  ${OV_STORE_DRIVER_CONF}
session_store_driver:
  Directory:
    path: ${STORES_DIR}/rendezvous_sessions
trusted_manufacturer_keys_path: ${KEYS_DIR}/manufacturer_cert.pem
max_wait_seconds: ~
bind: "0.0.0.0:8082"
EOF
}

setup_serviceinfo() {
 tee "${CONF_DIR}/serviceinfo-api-server.yml" <<EOF
---
service_info:
  initial_user: null
  files: null
  commands: null
  diskencryption_clevis: null
  additional_serviceinfo: null
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
  [ "$DATABASE_DRIVER" != "postgresql" ] || MANUFACTURER_DATABASE_URL="${DATABASE_DRIVER}://${DATABASE_USER}:${DATABASE_PASSWORD}@127.0.0.1/${MANUFACTURER_DATABASE}"
  [ "$DATABASE_DRIVER" != "postgresql" ] || OWNER_DATABASE_URL="${DATABASE_DRIVER}://${DATABASE_USER}:${DATABASE_PASSWORD}@127.0.0.1/${OWNER_DATABASE}"
  [ "$DATABASE_DRIVER" != "sqlite" ]     || MANUFACTURER_DATABASE_URL="${DATABASE_DRIVER}://${DATABASE_DIR}/${MANUFACTURER_DATABASE}.db"
  [ "$DATABASE_DRIVER" != "sqlite" ]     || OWNER_DATABASE_URL="${DATABASE_DRIVER}://${DATABASE_DIR}/${OWNER_DATABASE}.db"
  fdo-owner-tool export-manufacturer-vouchers "$(tr [:upper:] [:lower:] <<< ${OV_STORE_DRIVER})" "${MANUFACTURER_DATABASE_URL}" "${MANUFACTURER_EXPORT_DIR}"
  fdo-owner-tool import-ownership-vouchers "$(tr [:upper:] [:lower:] <<< ${OV_STORE_DRIVER})" "${OWNER_DATABASE_URL}" "${MANUFACTURER_EXPORT_DIR}"
}

perform_no_plain_di() {
  rm -f "${DEVICE_CREDENTIAL}" "${ONBOARDIG_PERFORMED}"
  /usr/libexec/fdo/fdo-manufacturing-client no-plain-di \
                                            --manufacturing-server-url http://${PRIMARY_IP}:8080 \
                                            --rootcerts ${KEYS_DIR}/diun_cert.pem
}

onboard() {
  /usr/libexec/fdo/fdo-client-linuxapp
}

fix_selinux_policies() {
  SELINUX_MODULE="fdo-db"
  SELINUX_TE_FILE="${SELINUX_MODULE}.te"
  SELINUX_MOD_FILE="${SELINUX_MODULE}.mod"
  SELINUX_POLICY_FILE="${SELINUX_MODULE}.pp"
  semodule -l | grep -q "${SELINUX_MODULE}" || (tee "${SELINUX_TE_FILE}" <<EOF
module fdo-db 1.0;

require {
	type postgresql_port_t;
	type fdo_conf_t;
	type fdo_t;
	type etc_t;
	type krb5_keytab_t;
	type sssd_var_run_t;
	type fdo_var_lib_t;
	type sssd_t;
	class tcp_socket name_connect;
	class dir { add_name remove_name search write };
	class sock_file write;
	class unix_stream_socket connectto;
	class file { append create rename setattr unlink write };
}

#============= fdo_t ==============

allow fdo_t etc_t:file write;

allow fdo_t fdo_conf_t:file { append create rename setattr unlink write };

allow fdo_t fdo_var_lib_t:dir { add_name remove_name write };

allow fdo_t fdo_var_lib_t:file { create setattr unlink write };

allow fdo_t krb5_keytab_t:dir search;

allow fdo_t postgresql_port_t:tcp_socket name_connect;

allow fdo_t sssd_t:unix_stream_socket connectto;

allow fdo_t sssd_var_run_t:sock_file write;
EOF
  checkmodule -M -m -o ${SELINUX_MOD_FILE} ${SELINUX_TE_FILE}
  semodule_package -o ${SELINUX_POLICY_FILE} -m ${SELINUX_MOD_FILE}
  semodule -i ${SELINUX_POLICY_FILE})

}

[ "${OV_STORE_DRIVER}" != "Sqlite" ] || setup_sqlite
[ "${OV_STORE_DRIVER}" != "Postgres" ] || setup_postgresql
fix_selinux_policies
generate_keys
setup_systemd
setup_manufacturing
setup_owner
setup_rendezvous
setup_serviceinfo
systemctl restart fdo-{manufacturing,owner-onboarding,rendezvous,serviceinfo-api}-server.service
perform_no_plain_di
[ "${OV_STORE_DRIVER}" = "Directory" ] || export_import_vouchers
sleep 60
onboard
