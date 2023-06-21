# Using the FIDO-Device-Onboard-RS containers 
## Generating the Certificates and keys 

Generate all the certificates and keys to be used with the various FDO
containers.

``` bash 
 mkdir keys
 for i in "diun" "manufacturer" "device-ca" "owner"; do fdo-admin-tool generate-key-and-cert $i; done
```
# Copy and edit the configuration files

Copy the configuration file from the examples provided and edit as needed. 

- [manufacturing-server.yml](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/config/manufacturing-server.yml)
- [owner-onboarding-server.yml](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/config/owner-onboarding-server.yml)
- [rendezvous-server.yml](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/config/rendezvous-server.yml)
- [serviceinfo-api-server.yml](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/config/serviceinfo-api-server.yml)

## Running the FDO containers

### manufacturing-server 

``` bash
podman pull quay.io/fido-fdo/manufacturing-server

podman run -d \
    --name manufacturing-server \
    -p 8080:8080 \
    -v /local/path/to/keys/:/etc/fdo/keys:Z \
    -v /local/path/to/config:/etc/fdo/manufacturing-server.conf.d/:Z \
    quay.io/fido-fdo/manufacturing-server
```

### owner-onboarding-server

``` bash
podman pull quay.io/fido-fdo/owner-onboarding-server

podman run -d \
    --name owner-onboarding-server \
    -p 8081:8081 \
    -v /local/path/to/keys/:/etc/fdo/keys:Z \
    -v /local/path/to/config:/etc/fdo/owner-onboarding-server.conf.d/:Z \
    quay.io/fido-fdo/owner-onboarding-server
```

### rendezvous-server

``` bash
podman pull quay.io/fido-fdo/rendezvous-server

podman run -d \
    --name rendezvous-server \
    -p 8082:8082 \
    -v /local/path/to/keys/:/etc/fdo/keys:Z \
    -v /local/path/to/config:/etc/fdo/rendezvous-server.conf.d/:Z \
    quay.io/fido-fdo/rendezvous-server
```

### serviceinfo-api-server

``` bash
podman pull quay.io/fido-fdo/serviceinfo-api-server

podman run -d \
    --name serviceinfo-api-server \
    -p 8083:8083 \
    -v /local/path/to/config:/etc/fdo/serviceinfo-api-server.conf.d/:Z \
    -v /local/path/to/device_specific_serviceinfo:/etc/fdo/device_specific_serviceinfo/:Z \
    quay.io/fido-fdo/serviceinfo-api-server
```
