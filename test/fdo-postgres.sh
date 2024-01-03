#!/bin/bash
set -euox pipefail

# Colorful output.
function greenprint {
    echo -e "\033[1;32m${1}\033[0m"
}

POSTGRES_IP=192.168.200.2
FDO_MANUFACTURING_ADDRESS=192.168.200.50
FDO_OWNER_ONBOARDING_ADDRESS=192.168.200.51
FDO_RENDEZVOUS_ADDRESS=192.168.200.52

POSTGRES_USERNAME=postgres
POSTGRES_PASSWORD=foobar
POSTGRES_DB=postgres

# Prepare stage repo network
greenprint "🔧 Prepare stage repo network"
sudo podman network inspect edge >/dev/null 2>&1 || sudo podman network create --driver=bridge --subnet=192.168.200.0/24 --gateway=192.168.200.254 edge

# Build FDO and clients container image
greenprint "🔧 Build FDO and clients container image"
sudo buildah build -f contrib/containers/build -t fdo-build:latest .
sudo buildah build -f contrib/containers/manufacturing-server --build-arg BUILDID=latest -t manufacturing-server:latest .
sudo buildah build -f contrib/containers/rendezvous-server --build-arg BUILDID=latest -t rendezvous-server:latest .
sudo buildah build -f contrib/containers/owner-onboarding-server --build-arg BUILDID=latest -t owner-onboarding-server:latest .
sudo buildah build -f contrib/containers/aio --build-arg BUILDID=latest -t aio:latest .
sudo buildah build -f test/files/clients --build-arg BUILDID=latest -t clients:latest .
sudo buildah images

##########################################################
##
## Prepare FDO containers
##
##########################################################
greenprint "🔧 Generate FDO key and configuration files"
sudo mkdir aio
sudo podman run --rm \
    -v "$PWD"/aio/:/aio:z \
    "localhost/aio:latest" \
    aio --directory aio generate-configs-and-keys --contact-hostname "$FDO_MANUFACTURING_ADDRESS"

# Prepare FDO config files
greenprint "🔧 Prepare FDO key and configuration files for FDO containers"
sudo cp -r aio/keys test/fdo/
sudo rm -rf aio

# Set servers store driver to postgres
greenprint "🔧 Set servers store driver to postgres"
sudo pip3 install yq
# Configure manufacturing server db
yq -yi 'del(.ownership_voucher_store_driver.Directory)' test/fdo/manufacturing-server.yml
yq -yi '.ownership_voucher_store_driver += {"Postgres": "Manufacturer"}' test/fdo/manufacturing-server.yml
# Configure owner onboarding server db
yq -yi 'del(.ownership_voucher_store_driver.Directory)' test/fdo/owner-onboarding-server.yml
yq -yi '.ownership_voucher_store_driver += {"Postgres": "Owner"}' test/fdo/owner-onboarding-server.yml
# Configure rendezvous server db
yq -yi 'del(.storage_driver.Directory)' test/fdo/rendezvous-server.yml
yq -yi '.storage_driver += {"Postgres": "Rendezvous"}' test/fdo/rendezvous-server.yml

# Prepare postgres db init sql script
greenprint "🔧 Prepare postgres db init sql script"
mkdir -p initdb
cp migrations_manufacturing_server_postgres/2023-10-03-152801_create_db/up.sql initdb/manufacturing.sql
cp migrations_owner_onboarding_server_postgres/2023-10-03-152801_create_db/up.sql initdb/owner-onboarding.sql
cp migrations_rendezvous_server_postgres/2023-10-03-152801_create_db/up.sql initdb/rendezvous.sql

greenprint "🔧 Starting postgres"
sudo podman run -d \
  --ip "$POSTGRES_IP" \
  --name postgres \
  --network edge \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  -v "$PWD"/initdb/:/docker-entrypoint-initdb.d/:z \
  "quay.io/xiaofwan/postgres"

greenprint "🔧 Starting fdo manufacture server"
sudo podman run -d \
  --ip "$FDO_MANUFACTURING_ADDRESS" \
  --name manufacture-server \
  --network edge \
  -v "$PWD"/test/fdo/:/etc/fdo/:z \
  -p 8080:8080 \
  -e POSTGRES_MANUFACTURER_DATABASE_URL="postgresql://${POSTGRES_USERNAME}:${POSTGRES_PASSWORD}@${POSTGRES_IP}/${POSTGRES_DB}" \
  "localhost/manufacturing-server:latest"

greenprint "🔧 Starting fdo owner onboarding server"
sudo podman run -d \
  --ip "$FDO_OWNER_ONBOARDING_ADDRESS" \
  --name owner-onboarding-server \
  --network edge \
  -v "$PWD"/test/fdo/:/etc/fdo/:z \
  -p 8081:8081 \
  -e POSTGRES_OWNER_DATABASE_URL="postgresql://${POSTGRES_USERNAME}:${POSTGRES_PASSWORD}@${POSTGRES_IP}/${POSTGRES_DB}" \
  "localhost/owner-onboarding-server:latest"

greenprint "🔧 Starting fdo rendezvous server"
sudo podman run -d \
  --ip "$FDO_RENDEZVOUS_ADDRESS" \
  --name rendezvous-server \
  --network edge \
  -v "$PWD"/test/fdo/:/etc/fdo/:z \
  -p 8082:8082 \
  -e POSTGRES_RENDEZVOUS_DATABASE_URL="postgresql://${POSTGRES_USERNAME}:${POSTGRES_PASSWORD}@${POSTGRES_IP}/${POSTGRES_DB}" \
  "localhost/rendezvous-server:latest"

# Wait for fdo containers to be up and running
until [ "$(curl -X POST http://${FDO_MANUFACTURING_ADDRESS}:8080/ping)" == "pong" ]; do
    sleep 1;
done;

until [ "$(curl -X POST http://${FDO_OWNER_ONBOARDING_ADDRESS}:8081/ping)" == "pong" ]; do
    sleep 1;
done;

until [ "$(curl -X POST http://${FDO_RENDEZVOUS_ADDRESS}:8082/ping)" == "pong" ]; do
    sleep 1;
done;


greenprint "🔧 Check container running status"
sudo podman ps -a

greenprint "🔧 Collecting container logs"
sudo podman logs postgres manufacture-server owner-onboarding-server rendezvous-server

greenprint "🔧 Check db tables"
sudo podman exec \
    postgres \
    psql \
    --username="${POSTGRES_USERNAME}" \
    -c "\dt" | grep "3 rows"

greenprint "🔧 Generate OV"
sudo podman run \
    --rm \
    --network edge \
    --privileged \
    localhost/clients \
    fdo-manufacturing-client no-plain-di --insecure --manufacturing-server-url "http://${FDO_MANUFACTURING_ADDRESS}:8080"

greenprint "🔧 Check manufacturing server db for new OV"
sudo podman exec \
    postgres \
    psql \
    --username="${POSTGRES_USERNAME}" \
    -c "SELECT * FROM manufacturer_vouchers ;" | grep "1 row"

greenprint "🔧 Check container running status"
sudo podman ps -a

greenprint "🔧 Export OV"
mkdir export-ov
sudo podman run \
    --rm \
    --network edge \
    --privileged \
    -v "$PWD"/export-ov:/export-ov:z \
    localhost/clients \
    fdo-owner-tool export-manufacturer-vouchers postgres "postgresql://${POSTGRES_USERNAME}:${POSTGRES_PASSWORD}@${POSTGRES_IP}/${POSTGRES_DB}" /export-ov/ | grep "exported"
EXPORTED_FILE=$(ls -1 export-ov)
greenprint "🔧 Import OV into owner db"
sudo podman run \
    --rm \
    --network edge \
    --privileged \
    -v "$PWD"/export-ov:/export-ov:z \
    localhost/clients \
    fdo-owner-tool import-ownership-vouchers postgres "postgresql://${POSTGRES_USERNAME}:${POSTGRES_PASSWORD}@${POSTGRES_IP}/${POSTGRES_DB}" "/export-ov/${EXPORTED_FILE}" | grep "OV import finished"

greenprint "🔧 Check owner db for imported OV"
sudo podman exec \
    postgres \
    psql \
    --username="${POSTGRES_USERNAME}" \
    -c "SELECT * FROM owner_vouchers ;" | grep "1 row"

greenprint "🔧 Sleep 60 seconds to sync with rendezvous db"
sleep 60

greenprint "🔧 Check rendezvous db for synced OV"
sudo podman exec \
    postgres \
    psql \
    --username="${POSTGRES_USERNAME}" \
    -c "SELECT * FROM rendezvous_vouchers ;" | grep "1 row"

greenprint "🔧 Check container running status"
sudo podman ps -a

greenprint "🔧 Collecting container logs"
sudo podman logs rendezvous-server

rm -rf initdb export-ov
exit 0
