# General How-To Documentation for FIDO-Device-Onboard-RS

- Pre-requisites
- How-Tos
  - How to generate keys and certificates
  - How to generate an Ownership Voucher (OV) and Credential for a Device
    (Device Initialization)
  - How to get information about an OV
  - How to extend an OV with the Owner's Certificate
  - How to convert a PEM (plain-text) format OV to a COSE (binary) format OV
- Configuration Files
  - `manufacturing_server.yml`
    - `rendezvous_info` field and `rendezvous_info.yml`
  - `owner_onboarding_server.yml`
  - `rendezvous_server.yml`
  - `serviceinfo_api_server.yml`
- How to run the servers
  - Manufacturing Server
  - Owner Onboarding Server
  - Rendezvous Server
  - Service Info API Server
- How to run the Client

## Pre-requisites

- You need to build this crate with the `--release` profile, see
[CONTRIBUTING.md:
Developing/building](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/CONTRIBUTING.md#developing--building).

  These how-tos assume that you have successfully built the different FIDO
  infrastructure binaries: `fdo-admin-tool`, `fdo-client-linuxapp`,
  `fdo-manufacturing-client`, `fdo-manufacturing-server`,
  `fdo-owner-onboarding-server`, `fdo-owner-tool`, `fdo-rendezvous-server` and
  `fdo-serviceinfo-api-server`.

- You need to have a general knowledge of the [FIDO Device Onboard
  Specification](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.1-20211214/).

## How-Tos

### How to generate keys and certificates

Use `fdo-admin-tool generate-key-and-cert` to generate the required keys for
`diun`, `manufacturer`, `device-ca` or `owner`. 

```bash
USAGE:
    fdo-admin-tool generate-key-and-cert [OPTIONS] <SUBJECT>

ARGS:
    <SUBJECT>    Subject of the key and certificate [possible values: diun, manufacturer,
                 device-ca, owner]

OPTIONS:
        --country <COUNTRY>
            Country name for the certificate [default: US]

        --destination-dir <DESTINATION_DIR>
            Writes key and certificate to the given path [default: keys]

    -h, --help
            Print help information

        --organization <ORGANIZATION>
            Organization name for the certificate [default: Example]

    -V, --version
            Print version information
```

Note in the results that `.der` indicate private keys and `.pem` certificates.

### How to generate an Ownership Voucher (OV) and Credential for a Device (Device Initialization)

Use `fdo-owner-tool initialize-device`:

```
USAGE:
    fdo-owner-tool initialize-device <device-id> <ownershipvoucher-out> <device-credential-out> --device-cert-ca-chain <device-cert-ca-chain> --device-cert-ca-private-key <device-cert-ca-private-key> --manufacturer-cert <manufacturer-cert> --rendezvous-info <rendezvous-info>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --device-cert-ca-chain <device-cert-ca-chain>                Chain with CA certificates for device certificate
        --device-cert-ca-private-key <device-cert-ca-private-key>    Private key for the device certificate CA
        --manufacturer-cert <manufacturer-cert>                      Path to the certificate for the manufacturer
        --rendezvous-info <rendezvous-info>
            Path to a TOML file containing the rendezvous information


ARGS:
    <device-id>                Identifier of the device
    <ownershipvoucher-out>     Output path for ownership voucher
    <device-credential-out>    Output path for device credential
```

Where the arguments for `--device-cert-ca-chain`,
`--device-cert-ca-private-key` and `--manufacturer-cert` have been generated as
seen in [How To Generate Keys and
Certificates](#how-to-generate-keys-and-certificates) and the argument for
`--rendezvous-info` is a YAML file containing a list of contact information for the
different Rendezvous Servers (see [Configuration
Files/rendezvous_info.yml](#rendezvous_info-field-and-rendezvous_infoyml)).

```bash
  $ fdo-owner-tool initialize-device \
  1234 \
  /path/to/resulting/ownership_voucher \
  /path/to/resulting/device_credential \
  --device-cert-ca-chain ./keys/device_ca_cert.pem \
  --device-cert-ca-private-key ./keys/device_ca_key.der \
  --manufacturer-cert ./keys/manufacturer_cert.pem \
  --rendezvous-info /usr/share/fdo/rendezvous-info.yml

  Created ownership voucher for device 2466056e-b71d-4a09-fb57-8aa49f003686
  ```

The generated OV is in PEM (plain-text) format, but if you are using this OV in the
`owner-onboarding-server` you will need to convert it to COSE format, plus the
OV will need to be extended with the Owner's Certificate.

### How to get information about an OV

Use `fdo-owner-tool dump-ownership-voucher` to get all the available
information about an OV. The input OV can be in PEM or COSE format.

```
USAGE:
    fdo-owner-tool dump-ownership-voucher [OPTIONS] <path>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --outform <outform>    Output format [possible values: pem, cose]

ARGS:
    <path>    Path to the ownership voucher
```

```
$ fdo-owner-tool dump-ownership-voucher ov.cose 
Header:
	Protocol Version: 101
	Device GUID: a57db382-2179-e74f-f113-b2c3d99a3001
	Rendezvous Info:
		- [(DevicePort, [25, 31, 146])]
		- [(IPAddress, [68, 192, 168, 122, 1])]
		- [(OwnerPort, [25, 31, 146])]
		- [(Protocol, [1])]
	Device Info: "1234"
	Manufacturer public key: Public key (SECP256R1): [48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 177, 50, 81, 193, 198, 167, 231, 21, 155, 186, 109, 78, 249, 235, 144, 143, 242, 82, 102, 244, 248, 180, 165, 220, 136, 86, 53, 167, 210, 220, 2, 55, 75, 19, 29, 48, 111, 185, 86, 231, 177, 137, 27, 186, 215, 62, 52, 251, 221, 11, 186, 127, 127, 0, 212, 236, 17, 139, 55, 202, 87, 152, 221, 214] (chain: None)
	Device certificate chain hash: e2ad64d82b257a5aae8b55d92414c8b3bde2f68bc930721cf494dae33961f89b1e0d32d15753c784686b65378c5f3d0c (Sha384)
Header HMAC: d9f066d469d778fc7085685a552d71a7201d188ec6690edd9f8524257481f415f9067e147618d701e4cf9944e88291dc (HmacSha384)
Device certificate chain:
	Certificate 0: X509 { serial_number: "CBBCCD123E795871", signature_algorithm: ecdsa-with-SHA384, issuer: [commonName = "Device", organizationName = "Example", countryName = "US"], subject: [commonName = "1234"], not_before: Sep  7 14:51:48 2022 GMT, not_after: Sep  4 14:51:48 2032 GMT, public_key: PKey { algorithm: "EC" } }
	Certificate 1: X509 { serial_number: "F1561657AC7CC6C8", signature_algorithm: ecdsa-with-SHA256, issuer: [commonName = "Device", organizationName = "Example", countryName = "US"], subject: [commonName = "Device", organizationName = "Example", countryName = "US"], not_before: Sep  7 14:47:53 2022 GMT, not_after: Sep  7 14:47:53 2023 GMT, public_key: PKey { algorithm: "EC" } }
Entries:
```

For an explanation of each field refer to [Ownership
Voucher](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.1-20211214/#OwnershipVoucher). 

### How to extend an OV with the Owner's Certificate

Use `fdo-owner-tool extend-ownership-voucher`:

```
USAGE:
    fdo-owner-tool extend-ownership-voucher <path> --current-owner-private-key <current-owner-private-key> --new-owner-cert <new-owner-cert>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --current-owner-private-key <current-owner-private-key>    Path to the current owner private key
        --new-owner-cert <new-owner-cert>                          Path to the new owner certificate

ARGS:
    <path>    Path to the ownership voucher
```

```
$ fdo-owner-tool extend-ownership-voucher ov \
    --current-owner-private-key ./keys/manufacturer_key.der \
    --new-owner-cert ./keys/owner_cert.pem
```

You can check that the OV has been properly extended using `fdo-owner-tool
dump-ownership-voucher` and checking the `Entries` field, it should contain the
Owner's public key:

```
....
Entries:
	Entry 0
		Previous entry hash: 9c07c4d2a879911abdd9363688fa4d4ae94414c0497431b16555dde504cbd74ea1f1f7174a48e65c13c60f7cde8317f0 (Sha384)
		Header info hash: 893a30e1b85391818195c9c7caaf6fe5fa1b9b833b8d7e1511060c4501cbfc977d3cad83d7b08e882aa8d8606d1426d7 (Sha384)
		Extra: None
		Public key: Public key (SECP256R1): [48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 8, 127, 162, 248, 37, 134, 145, 249, 198, 77, 184, 125, 223, 41, 164, 83, 143, 100, 175, 69, 104, 128, 53, 36, 195, 196, 100, 105, 206, 49, 205, 190, 233, 111, 168, 2, 90, 82, 187, 84, 91, 98, 37, 103, 138, 202, 148, 99, 6, 144, 227, 45, 102, 248, 252, 88, 232, 66, 232, 138, 79, 222, 253, 10] (chain: None)
```

### How to convert a PEM (plain-text) format OV to a COSE (binary) format OV

Use `fdo-owner-tool dump-ownership-voucher`:

```bash
fdo-owner-tool dump-ownership-voucher your_ownership_voucher --outform cose > your_ownership_voucher.cose
```

## Configuration Files

This project uses
[YAML](https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html)
syntax for its configuration files.

Example configuration files like the ones used in this section can be found in
the
[examples/config](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/config/)
directory of this project.

- When a field is optional `[OPTIONAL]` will be listed next to it, otherwise
  treat it as required.
- When a field is required but its sub-fields are all optional you may put a
  null value (`~`) there.

### `manufacturing_server.yml`

The most up-to-date configuration settings will be on [util/src/servers/configuration/manufacturing_server.rs](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/util/src/servers/configuration/manufacturing_server.rs).

```yml
---
session_store_driver:
  Directory:
    path: /path/to/sessions/
ownership_voucher_store_driver:
  Directory:
    path: /path/to/ownership_vouchers/
public_key_store_driver:
  Directory:
    path: /path/to/manufacturer_keys
bind: 0.0.0.0:8080
rendezvous_info:
- dns: fdo.example.com
  device_port: 8082
  owner_port: 8082
  protocol: http
- ip: 127.0.0.1
  device_port: 8084
  owner_port: 8084
  protocol: http
protocols:
  diun:
    key_path: /path/to/keys/diun_key.der
    cert_path: /path/to/keys/diun_cert.pem
    key_type: SECP256R1
    mfg_string_type: SerialNumber
    allowed_key_storage_types:
    - FileSystem
    - Tpm
manufacturing:
  manufacturer_cert_path: /path/to/keys/manufacturer_cert.pem
  manufacturer_private_key: /path/to/keys/manufacturer_key.der
  owner_cert_path: /path/to/keys/owner_cert.pem
  device_cert_ca_private_key: /path/to/keys/device_ca_key.der
  device_cert_ca_chain: /path/to/keys/device_ca_cert.pem
```

Where:

- `session_store_driver`: path to a directory that will hold session
  information.
- `ownership_voucher_store_driver`: path to a directory that will hold OVs.
- `public_key_store_driver:` [OPTIONAL] path to a directory that will hold the
  Manufacturer's public keys.
- `bind`: IP address and port that this server will take.
- `protocols`: configures the protocol settings:
  - `plain_di`: [OPTIONAL] boolean.
  - `diun`: [OPTIONAL]
    - `mfg_string_type`: device serial number
    - `key_type`: SECP256R1 or SECP384R1 (up-to-date list of options
      [here](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/util/src/servers/configuration/manufacturing_server.rs#L71). 
    - `allowed_key_storage_types`: list of allowed storage types. Possible
      values: `FileSystem`, `Tpm` (up-to-date list of options
      [here](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/util/src/servers/configuration/manufacturing_server.rs#L86))
    - `key_path`: path to the diun key.
    - `pub_cert_path`: path to the diun certificate.
- `rendezvous_info`: indicates how the Device and the Owner will find the
  Rendezvous Server.
  - `ip`/`ipaddress`/`ip_address` or `dns`: IP address or DNS url.
  - `device_port`/`deviceport`: [OPTIONAL] port for the Device.
  - `owner_port`/`ownerport`: [OPTIONAL] port for the Owner.
  - `protocol`: [OPTIONAL] transport protocol: `tcp`, `tls`, `http`, `coap`,
    `https` or `coaps` (default `tls`).
  - `device_only`/`deviceonly`: [OPTIONAL]
  - `owner_only`/`owneronly`: [OPTIONAL]
  - `server_cert_hash`/`servercerthash`: [NOT IMPLEMENTED]
  - `ca_cert_hash`/`cacerthash`: [NOT IMPLEMENTED]
  - `user_input`/`userinput`: [OPTIONAL]
  - `wifi_ssid`/`wifissid`: [OPTIONAL]
  - `wifi_pw`/`wifipw`: [OPTIONAL]
  - `medium`: [NOT IMPLEMENTED]
  - `delay_sec`/`delaysec`: [OPTIONAL] default 0.
  - `bypass`: [OPTIONAL]
- `manufacturing`: extra settings for this Manufacturing Server :
  - `manufacturer_cert_path`: path to the Manufacturer's certificate.
  - `manufacturer_private_key`: [OPTIONAL] path to the Manufacturer's private
      key.
  - `device_cert_ca_private_key`: path to the private key of the Device.
  - `device_cert_ca_chain`: path to the certificate of the Device.
  - `owner_cert_path`: [OPTIONAL] path to the Owner's certificate of this
    Manufacturing server.

#### `rendezvous_info` field and `rendezvous_info.yml`

The `rendezvous_info` field was previously named `rendezvous_info_path`, which
instead of containing a list of contact methods to reach different Rendezvous
Servers it contained the path to a configuration file (`rendezvous_info.yml`)
that had this same info.

If you are using the `fdo-owner-tool` to initialize a device you will need to
pass a `rendezvous_info.yml` YAML file (not to be confused with the
`rendezvous_server.yml`) as one of the configuration parameters.

```yml
---
- ip_address: 192.168.122.1
  deviceport: 8082
  ownerport: 8082
  protocol: http
- dns: fdo.example.com
  device_port: 8082
  owner_port: 8082
  protocol: http
```

The fields of this `rendezvous_info.yml` file are the same ones that can be
found in the `rendezvous_info` field of the `manufacturing_server.yml`.

### `owner_onboarding_server.yml`

```yml
---
session_store_driver:
  Directory:
    path: /path/to/sessions/
ownership_voucher_store_driver:
  Directory:
    path: /path/to/ownership_vouchers/
trusted_device_keys_path: /path/to/keys/device_ca_cert.pem
owner_private_key_path: /path/to/keys/owner_key.der
owner_public_key_path: /path/to/keys/owner_cert.pem
owner_addresses:
- transport: HTTP
  port: 8081
  addresses:
    - dns_name: fdo.example.com
    - ip_address: 192.168.122.1
report_to_rendezvous_endpoint_enabled: false
bind: 0.0.0.0:8081
service_info_api_url: "http://localhost:8089/device_info"
service_info_api_authentication: None
```

Where:

- `ownership_voucher_store_driver`: path to a directory that will hold the OVs
  owned by this server.
- `session_store_driver`: path to a directory that will hold session
  information.
- `trusted_device_keys_path`: path to the Device Certificate Authority
  certificate.
- `owner_private_key_path`: path to the Owner's private key.
- `owner_public_key_path`: path to the Owner's public key certificate.
- `bind`: IP address and port that this server will take.
- `service_info_api_url`: url to the Service Info API server.
- `service_info_api_authentication`: if the Service Info API server needs
  authentication (JSON authentication) provide a `BearerToken` or a
  `ClientCertificate` (both fields explained below); if it doesn't need
  authentication place `None` in this field.
  - `BearerToken`:
    - `token`: bearer token.
  - `ClientCertificate`:
    - `client_certificate`: the client certificate.
    - `password`: password.
- `owner_addresses`: owner's addresses.
  - `transport`: transport protocol: `tcp`, `tls`, `http`,
        `coap`, ` https` or `coaps`.
  - `addresses`: list of addresses.
    - `ip_address`/`dns_name`: IP address or DNS.
  - `port`: connection port.
- `report_to_rendezvous_endpoint_enabled`: whether reporting to the Rendezvous
  Server is enabled or not, boolean.

### `rendezvous_server.yml`

```yml
---
storage_driver:
  Directory:
    path: /path/to/stores/rendezvous_registered
session_store_driver:
  Directory:
    path: /path/to/stores/rendezvous_sessions
trusted_manufacturer_keys_path: /path/to/keys/manufacturer_cert.pem
max_wait_seconds: ~
bind: "0.0.0.0:8082"
```

Where:

- `storage_driver`: path to a directory that will hold OVs registered with the
  Rendezvous Server.
- `session_store_driver`: path to a directory that will hold session
  information.
- `trusted_manufacturer_keys_path`: path to the Manufacturer Certificate.
- `max_wait_seconds`: [OPTIONAL] maximum wait time in seconds for the TO0 and
  TO1 protocols (default 2592000).
- `bind`: IP address and port that the Rendezvous Server will take.

### `serviceinfo_api_server.yml`

```yml
---
bind: 0.0.0.0:8083
device_specific_store_driver:
  Directory:
    path: /path/to/device_specific_serviceinfo
service_info_auth_token: TestAuthToken
admin_auth_token: TestAdminToken
service_info:
  initial_user:
    username: admin
    sshkeys:
    - "testkey"
  files:
  - path: /device/etc/hosts
    permissions: 644
    source_path: /server/local/etc/hosts
  - path: /device/etc/resolv.conf
    source_path: /server/local/etc/resolv.conf
  commands:
  - command: ls
    args:
    - /etc/hosts
    return_stdout: true
    return_stderr: true
  - command: ls
    args:
    - /etc/doesnotexist/whatever.foo
    may_fail: true
    return_stdout: true
    return_stderr: true
  - command: touch
    args:
    - /etc/command-testfile
  diskencryption_clevis:
  - disk_label: /dev/vda
    binding:
      pin: test
      config: "{}"
    reencrypt: true
  after_onboarding_reboot: true
```

Where:
- `bind`: IP address and port that the Service Info API Server will take.
- `service_info_auth_token`: [OPTIONAL] Authorization token (default no authentication
   is needed).
- `admin_auth_token`: [OPTIONAL] Admin's authorization token.
- `device_specific_store_driver`: path to a directory that will hold
  device-specific info.
- `service_info`: list of settings for the `service_info` optional
  modules. Each module provides an specific functionality and their
  configuration are a series of key-values. These specific `service_info`
  modules are not part of the FIDO Device Onboard Standard.
  - `initial_user`: [OPTIONAL] creates an initial user on the device and adds
    the given ssh key to the user.
    - `username`: name of the user
    - `sshkeys`: ssh key to copy.
  - `files`: [OPTIONAL] transfers files to a device.
    - `path`: destination path.
    - `permissions`: permissions to set on the file.
    - `source_path`: source file path.
  - `commands`: [OPTIONAL] executes the given list of commands on the device.
      - `command`: command to execute.
      - `args`: list of arguments for the command.
      - `may_fail`: [OPTIONAL] whether the command may fail or not, boolean
        (default false).
      - `return_stdout`: [OPTIONAL] whether the device should return stdout,
        boolean (default false).
      - `return_stderr`: [OPTIONAL] whether the device should return stderr,
        boolean (default false).
  - `diskencryption_clevis`: [OPTIONAL] performs disk encryption using Clevis.
    - `disk_label`: disk label to apply the encryption on the device
    - `binding`:
        - `pin`: encryption method (e.g. `tpm2`)
        - `config`: configuration that the `pin` may need, (e.g. empty config:
          `{}`; sample configuration for `tpm2`: `'{"pcr_bank": "sha256",
          "prc_id": "1.7"}'`)
    - `reencrypt`: boolean, whether re-encryption should be done.
  - `after_onboarding_reboot`: [OPTIONAL] specifies if the device should be
    rebooted after onboarding has completed, boolean (default false).
  - `additional_service_info`: [OPTIONAL]

## How to run the servers

Please mind how the configuration file must be specifically named (e.g. `-` VS
`_`).

### Manufacturing Server

1. Generate the required keys/certificates for the Manufacturing Server, see
   [How to generate keys and certificates](#how-to-generate-keys-and-certificates).

   You will need the Manufacturers private key and certificate, the Owner's
   certificate and the Device's private key and certificate.

2. Configure `manufacturing-server.yml`, see [Configuration
   Files/manufacturing_server.yml](#manufacturing_serveryml) and place it either in
   `/usr/share/fdo`, `/etc/fdo/` or
   `/etc/fdo/manufacturing-serverr.conf.d/`. The paths will be checked in that
   same order.

3. Execute `fdo-manufacturing-server` or run it as a service, see sample
   file in
   [examples/systemd](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/systemd/fdo-manufacturing-server.service).

### Owner Onboarding Server

1. Generate the required keys/certificates for the Owner, see [How to generate
   keys and certificates](#how-to-generate-keys-and-certificates).

2. Configure `owner-onboarding-server.yml`, see [Configuration
   Files/owner_onboarding_server.yml](#owner_onboarding_serveryml) and place it
   either in `/usr/share/fdo`, `/etc/fdo/` or
   `/etc/fdo/owner-onboarding-server.conf.d/`. The paths will be checked in
   that same order.

3. Generate an Ownership Voucher (see [How to generate an Ownership
   Voucher](#how-to-generate-an-ownership-voucher-ov-and-credential-for-a-device-device-initialization)),
   extend it with the Owner's Certificate (see [How to extend an OV with the
   Owner's Certificate](#how-to-extend-an-ov-with-the-owners-certificate)) and
   convert it to COSE format (see [How to convert a PEM (plain-text) format OV
   to a COSE (binary) format OV](#how-to-convert-a-pem-plain-text-format-ov-to-a-cose-binary-format-ov)).
   
   Rename the generated OV to its Device GUID (see [How to get information about an
   OV](#how-to-get-information-about-an-ov) to identify its Device GUID) and
   store it in the path given to the `ownership_voucher_store_driver` field in
   the `owner_onboarding_server.yml` of the previous step.

4. Execute `fdo-owner-onboarding-server` or run it as a service, see sample
   file in [examples/systemd](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/systemd/fdo-owner-onboarding-server.service).

### Rendezvous Server

1. Configure `rendezvous-server.yml`, see [Configuration
   Files/rendezvous_server.yml](#rendezvous_serveryml) and place it either in
   `/usr/share/fdo`, `/etc/fdo/` or `/etc/fdo/rendezvous-server.conf.d/`. The
   paths will be checked in that same order.

2. Execute `fdo-rendezvous-server` or run it as a service, see sample file in
   [examples/systemd](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/systemd/fdo-rendezvous-server.service).

### Service Info API Server

1. Configure `serviceinfo-api-server.yml`, see [Configuration
   Files/serviceinfo_api_server.yml](#serviceinfo_api_serveryml), and place it either in
   `/usr/share/fdo`, `/etc/fdo/` or `/etc/fdo/serviceinfo-api-server.conf.d/`. The
   paths will be checked in that same order.

2. Execute `fdo-serviceinfo-api-server` or run it as a service, see sample file
   in
   [examples/systemd](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/systemd/fdo-serviceinfo-api-server.service).

## How to run the Client

1. Initialize the Device, see [How to generate an Ownership Voucher (OV) and
    Credential for a Device (Device
    Initialization)](#how-to-generate-an-ownership-voucher-ov-and-credential-for-a-device-device-initialization).

2. The client will look for the Device Credential created during the previous
  step. It will look for in on
  `/sys/firmware/qemu_fw_cfg/by_name/opt/device_onboarding/devicecredential/raw`,
  in the location specified by the `DEVICE_CREDENTIAL` environment variable, or
  in `/etc/device-credentials`, in that order.

    ```bash
    export DEVICE_CREDENTIAL=/path/to/device_credential
    ```

3. Run the client: `fdo-client-linuxappp`
