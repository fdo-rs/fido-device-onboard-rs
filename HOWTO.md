# General How-To Documentation for FIDO-Device-Onboard-RS

- Pre-requisites
- How-Tos
  - How to generate keys and certificates
  - How to generate an Ownership Voucher (OV) and Credential for a Device
    (Device Initialization)
  - How to get information about an OV
  - How to extend an OV with the Owner's Certificate
  - How to convert a PEM (plain-text) format OV to a COSE (binary) format OV
  - How to export OVs from the Manufacturer Server (Database specific)
  - How to import OVs into the Owner Onboarding Server (Database specific)
- Configuration Files
  - `manufacturing-server.yml`
    - `rendezvous_info` field and `rendezvous-info.yml`
  - `owner-onboarding-server.yml`
  - `rendezvous-server.yml`
  - `serviceinfo-api-server.yml`
- Database management
- How to run the servers:
  - Manufacturing Server
  - Owner Onboarding Server
  - Rendezvous Server
  - Service Info API Server
- How to run the clients:
  - Linuxapp client
  - Manufacturing client
- How to use Features:
  - How to use the `per-device serviceinfo` feature

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
Usage: fdo-admin-tool generate-key-and-cert [OPTIONS] <SUBJECT>

Arguments:
  <SUBJECT>  Subject of the key and certificate [possible values: diun, manufacturer, device-ca, owner]

Options:
      --organization <ORGANIZATION>
          Organization name for the certificate [default: Example]
      --country <COUNTRY>
          Country name for the certificate [default: US]
      --validity-ends <VALIDITY_ENDS>
          Number of days the certificate is going to be valid [default: 365]
      --destination-dir <DESTINATION_DIR>
          Writes key and certificate to the given path [default: keys]
  -h, --help
          Print help
  -V, --version
          Print version
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
Files/rendezvous-info.yml](#rendezvous_info-field-and-rendezvous-infoyml)).

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

### How to export OVs from the Manufacturer Server (Database specific)

Use `fdo-owner-tool export-manufacturer-vouchers`:

```
$ fdo-owner-tool export-manufacturer-vouchers --help
Exports a single or all the ownership vouchers present in the Manufacturer DB

Usage: fdo-owner-tool export-manufacturer-vouchers <DB_TYPE> <DB_URL> <PATH> [GUID]

Arguments:
  <DB_TYPE>  Type of the Manufacturer DB holding the OVs [possible values: sqlite, postgres]
  <DB_URL>   DB connection URL, or path to the DB file
  <PATH>     Path to dir where the OVs will be exported
  [GUID]     GUID of the voucher to be exported, if no GUID is given all the OVs will be exported
```

For example:

```bash
fdo-owner-tool export-manufacturer-vouchers postgres \
postgresql://test:test@localhost/test_manufacturer \
/path/to/manufacturer-exports/
```

### How to import OVs into the Owner Onboarding Server (Database specific)

```
$ fdo-owner-tool import-ownership-vouchers --help
Imports into the Owner DB a single ownership voucher or all the ownership vouchers present at a given path

Usage: fdo-owner-tool import-ownership-vouchers <DB_TYPE> <DB_URL> <SOURCE_PATH>

Arguments:
  <DB_TYPE>      Type of the Owner DB to import the OVs [possible values: sqlite, postgres]
  <DB_URL>       DB connection URL or path to DB file
  <SOURCE_PATH>  Path to the OV to be imported, or path to a directory where all the OVs to be imported are located

Options:
  -h, --help  Print help
```

When importing OVs the tool will attempt to import each OV once, ignoring all
possible errors and then giving a summary of which OVs couldn't be imported.

For example:

```
fdo-owner-tool import-ownership-vouchers postgres postgresql://test:test@localhost/test_owner /path/to/ovs/to/import/
Unable to import all OVs. OV import operations yielded the following error/s:

- Error Some(duplicate key value violates unique constraint "owner_vouchers_pkey") inserting OV d5bc48f8-b603-a1c0-e8b9-ae4d9bdf1570 from path "/path/to/ovs/to/import/d5bc48f8-b603-a1c0-e8b9-ae4d9bdf1570"
- Error Empty data serializing OV contents at path "/path/to/ovs/to/import/this-is-not-an-OV"
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

### `manufacturing-server.yml`

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
- `ownership_voucher_store_driver`: this selects the ownership voucher storage
  method. Select between `Directory`, `Sqlite` or `Postgres`.
    - `Directory`: expects a `path` to the directory that will hold the OVs.
      For example:
      ```
      ownership_voucher_store_driver:
        Directory:
          path: /home/fedora/ownership_vouchers
      ```
    - `Sqlite`: will use a Sqlite database to store the ownership vouchers.
      When using this option you must set `Manufacturer` as the DB type as
      shown below as well as a connection url (including username/password/port if needed):
      ```
      ownership_voucher_store_driver:
        Sqlite:
          server: Manufacturer
          url: sqlite:///path/to/db/sqlite
      ```
      Please refer to the [Database management section](#database-management) on how to initialize databases.
    - `Postgres`: will use a Postgres database to store the ownership vouchers.
      When using this option you must set `Manufacturer` as the DB type as
      shown below as well as a connection url (including username/password/port if needed):
      ```
      ownership_voucher_store_driver:
        Postgres:
          server: Manufacturer
          url: postgresql://username:password@host:5432/database_name?option1=value1&option2=value2
      ```
      Please refer to the [Database management section](#database-management) on how to initialize databases.
- `public_key_store_driver:` [OPTIONAL] path to a directory that will hold the
  Manufacturer's public keys.
- `bind`: IP address and port that this server will take.
- `protocols`: configures the protocol settings:
  - `plain_di`: [OPTIONAL] boolean.
  - `diun`: [OPTIONAL]
    - `mfg_string_type`: sets which type of identification is expected to be
    used in the devices. Possible values: `SerialNumer` or `MACAddress`
    (up-to-date list of options
    [here](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/data-formats/src/constants/mod.rs#L427)). 
    - `key_type`: SECP256R1 or SECP384R1 (up-to-date list of options
      [here](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/util/src/servers/configuration/manufacturing_server.rs#L71). 
    - `allowed_key_storage_types`: list of allowed storage types. Possible
      values: `FileSystem`, `Tpm` (up-to-date list of options
      [here](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/util/src/servers/configuration/manufacturing_server.rs#L86)).
      
      In order to use the `Tpm` option you must have the kernel TPM 2 resource
      manager (`/dev/tpmrm0`) available, or you must set your TPM 2
      configuration via the `TPM2TOOLS_TCTI`, `TCTI` or `TEST_TCTI` environment
      variables.
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

#### `rendezvous_info` field and `rendezvous-info.yml`

The `rendezvous_info` field was previously named `rendezvous_info_path`, which
instead of containing a list of contact methods to reach different Rendezvous
Servers it contained the path to a configuration file (`rendezvous-info.yml`)
that had this same info.

If you are using the `fdo-owner-tool` to initialize a device you will need to
pass a `rendezvous-info.yml` YAML file (not to be confused with the
`rendezvous-server.yml`) as one of the configuration parameters.

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

The fields of this `rendezvous-info.yml` file are the same ones that can be
found in the `rendezvous_info` field of the `manufacturing-server.yml`.

### `owner-onboarding-server.yml`

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
ov_registration_period: 600
ov_re_registration_window: 61
bind: 0.0.0.0:8081
service_info_api_url: "http://localhost:8083/device_info"
service_info_api_authentication: None
```

Where:

- `ownership_voucher_store_driver`: this selects the ownership voucher storage
  method. Select between `Directory`, `Sqlite` or `Postgres`.
    - `Directory`: expects a `path` to the directory that will hold the OVs.
      For example:
      ```
      ownership_voucher_store_driver:
        Directory:
          path: /home/fedora/ownership_vouchers
      ```
    - `Sqlite`: will use a Sqlite database to store the ownership vouchers.
      When using this option you must set `Owner` as the DB type as
      shown below as well as a connection url (including username/password/port if needed):
      ```
      ownership_voucher_store_driver:
        Sqlite:
          server: Owner
          url: sqlite:///path/to/db/sqlite
      ```
      Please refer to the [Database management section](#database-management) on how to initialize databases.
    - `Postgres`: will use a Postgres database to store the ownership vouchers.
      When using this option you must set `Owner` as the DB type as
      shown below as well as a connection url (including username/password/port if needed):
      ```
      ownership_voucher_store_driver:
        Postgres:
          server: Owner
          url: postgresql://username:password@host:5432/database_name?option1=value1&option2=value2
      ```
      Please refer to the [Database management section](#database-management) on how to initialize databases.
- `session_store_driver`: path to a directory that will hold session
  information.
- `trusted_device_keys_path` [OPTIONAL]: path to the CA certificates
used for device certificate chain verification.
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
- `ov_registration_period`: optional value that sets how many seconds OVs are
  going to be registered into the Rendezvous server.
- `ov_re_registration_window`: optional value that sets the minimum amount of
  seconds left in the `ov_registration_period` for the Owner server to trigger
  a re-registration within the Rendezvous server. This option can only be used
  with database backends.

### `rendezvous-server.yml`

```yml
---
storage_driver:
  Directory:
    path: /path/to/stores/rendezvous_registered
session_store_driver:
  Directory:
    path: /path/to/stores/rendezvous_sessions
trusted_manufacturer_keys_path: /path/to/keys/manufacturer_cert.pem
trusted_device_keys_path: /path/to/keys/device_ca_cert.pem
max_wait_seconds: ~
bind: "0.0.0.0:8082"
```

Where:

- `storage_driver`: this selects the server's storage method. Select between
  `Directory`, `Sqlite` or `Postgres`. 
    - `Directory`: expects a `path` to the directory that will serve as the
      server's storage.
      For example:
      ```
      storage_driver:
        Directory:
          path: /home/fedora/rendezvous_storage
      ```
    - `Sqlite`: will use a Sqlite database as the server's storage.
      When using this option you must set `Rendezvous` as the DB type as
      shown below as well as a connection url (including username/password/port if needed):
      ```
      storage_driver:
        Sqlite:
          server: Rendezvous
          url: sqlite:///path/to/db/sqlite
      ```
      Please refer to the [Database management section](#database-management) on how to initialize databases.
    - `Postgres`: will use a Sqlite database as the server's storage.
      When using this option you must set `Rendezvous` as the DB type as
      shown below as well as a connection url (including username/password/port if needed):
      ```
      storage_driver:
        Postgres:
          server: Rendezvous
          url: postgresql://username:password@host:5432/database_name?option1=value1&option2=value2
      ```
      Please refer to the [Database management section](#database-management) on how to initialize databases.
- `session_store_driver`: path to a directory that will hold session
  information.
- `trusted_manufacturer_keys_path` [OPTIONAL]: path to the Manufacturer Certificate.
- `trusted_device_keys_path` [OPTIONAL]: path to the CA certificates used for
device certificate chain verification.
- `max_wait_seconds`: [OPTIONAL] maximum wait time in seconds for the TO0 and
  TO1 protocols (default 2592000).
- `bind`: IP address and port that the Rendezvous Server will take.

### `serviceinfo-api-server.yml`

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
  - path: /var/lib/fdo/service-info-api/files/hosts
    permissions: 644
    source_path: /server/local/etc/hosts
  - path: /var/lib/fdo/service-info-api/files/resolv.conf
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

## Database management

When using the `Sqlite` or `Postgres` storage driver configuration you are able
to use Sqlite or Postgres databases to serve as the storage driver of the
Manufacturing, Owner and/or Rendezvous servers.

You are able to use different database systems for each server (e.g. Sqlite for
the Manufacturing server and Postgres for the rest), or even mix
database storage in some servers with filesystem storage in other servers
(e.g. filesystem storage for the Manufacturing server and Postgres for the
rest).

### Dependencies

Install the following packages:

```bash
dnf install -y sqlite sqlite-devel libpq libpq-devel
```

and the `diesel` tool for schema management:

```bash
cargo install --force diesel_cli --no-default-features --features "postgres sqlite"
```

### Creating the databases

When using databases you need to initialize the database based on the FDO
server and database type that you'll be using. 

All the databases are initialized running

```bash
diesel migration run --migration-dir $MIGRATION_DIRECTORY \
--database-url $DATABASE_URL
```

where `$MIGRATION_DIRECTORY` is one of the `migration_*` directories that
matches your server type and database type combo
(`migrations_manufacturing_server_postgres`,
`migrations_manufacturing_server_sqlite`,
`migrations_owner_onboarding_server_postgres`,
`migrations_owner_onboarding_server_sqlite`,
`migrations_rendezvous_server_postgres`,
`migrations_rendezvous_server_sqlite`); the `$DATABASE_URL` is the Postgres
connection URL or  a path to the location where the Sqlite database will be
located based on if you'll be using Postgres or Sqlite, respectively.

> **NOTE:** if you are using Fedora IoT along with the Sqlite DB, you must
> create the DB in a writable location, for instance `/var/lib/fdo`.

## How to run the servers

Please mind how the configuration file must be specifically named (e.g. `-` VS
`_`).

### Manufacturing Server

1. Generate the required keys/certificates for the Manufacturing Server, see
   [How to generate keys and certificates](#how-to-generate-keys-and-certificates).

   You will need the Manufacturers private key and certificate, the Owner's
   certificate and the Device's private key and certificate.

2. Configure `manufacturing-server.yml`, see [Configuration
   Files/manufacturing-server.yml](#manufacturing-serveryml) and place it either in
   `/usr/share/fdo`, `/etc/fdo/` or
   `/etc/fdo/manufacturing-server.conf.d/`. The paths will be checked in that
   same order.
   
   Additionally, set up the `MANUFACTURING_SERVER_CONF` environment variable to point
   to the path of the configuration file if running in a dev container.

3. Execute `fdo-manufacturing-server` or run it as a service, see sample
   file in
   [examples/systemd](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/systemd/fdo-manufacturing-server.service).

### Owner Onboarding Server

1. Generate the required keys/certificates for the Owner, see [How to generate
   keys and certificates](#how-to-generate-keys-and-certificates).

2. Configure `owner-onboarding-server.yml`, see [Configuration
   Files/owner-onboarding-server.yml](#owner-onboarding-serveryml) and place it
   either in `/usr/share/fdo`, `/etc/fdo/` or
   `/etc/fdo/owner-onboarding-server.conf.d/`. The paths will be checked in
   that same order.
   
   Additionally, set up the `OWNER_ONBOARDING_SERVER_CONF` environment variable to point
   to the path of the configuration file if running in a dev container.

3. Generate an Ownership Voucher (see [How to generate an Ownership
   Voucher](#how-to-generate-an-ownership-voucher-ov-and-credential-for-a-device-device-initialization)),
   extend it with the Owner's Certificate (see [How to extend an OV with the
   Owner's Certificate](#how-to-extend-an-ov-with-the-owners-certificate)) and
   convert it to COSE format (see [How to convert a PEM (plain-text) format OV
   to a COSE (binary) format OV](#how-to-convert-a-pem-plain-text-format-ov-to-a-cose-binary-format-ov)).
   
   Rename the generated OV to its Device GUID (see [How to get information about an
   OV](#how-to-get-information-about-an-ov) to identify its Device GUID) and
   store it in the path given to the `ownership_voucher_store_driver` field in
   the `owner-onboarding-server.yml` of the previous step.

4. Execute `fdo-owner-onboarding-server` or run it as a service, see sample
   file in [examples/systemd](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/systemd/fdo-owner-onboarding-server.service).

### Rendezvous Server

1. Configure `rendezvous-server.yml`, see [Configuration
   Files/rendezvous-server.yml](#rendezvous-serveryml) and place it either in
   `/usr/share/fdo`, `/etc/fdo/` or `/etc/fdo/rendezvous-server.conf.d/`. The
   paths will be checked in that same order.
   
   Additionally, set up the `RENDEZVOUS_SERVER_CONF` environment variable to point
   to the path of the configuration file if running in a dev container.

2. Execute `fdo-rendezvous-server` or run it as a service, see sample file in
   [examples/systemd](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/systemd/fdo-rendezvous-server.service).

### Service Info API Server

1. Configure `serviceinfo-api-server.yml`, see [Configuration
   Files/serviceinfo-api-server.yml](#serviceinfo-api-serveryml), and place it either in
   `/usr/share/fdo`, `/etc/fdo/` or `/etc/fdo/serviceinfo-api-server.conf.d/`. The
   paths will be checked in that same order.
      
   Additionally, set up the `SERVICEINFO_API_SERVER_CONF` environment variable to point
   to the path of the configuration file if running in a dev container.

2. Execute `fdo-serviceinfo-api-server` or run it as a service, see sample file
   in
   [examples/systemd](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/systemd/fdo-serviceinfo-api-server.service).

## How to run the clients

### Linuxapp client

1. Initialize the Device, see [How to generate an Ownership Voucher (OV) and
    Credential for a Device (Device
    Initialization)](#how-to-generate-an-ownership-voucher-ov-and-credential-for-a-device-device-initialization).

2. The client will look for the Device Credential created during the previous
  step. It will look for it on
  `/sys/firmware/qemu_fw_cfg/by_name/opt/device_onboarding/devicecredential/raw`,
  in the location specified by the `DEVICE_CREDENTIAL` environment variable, or
  in `/etc/device-credentials`, in that order.

    ```bash
    export DEVICE_CREDENTIAL=/path/to/device_credential
    ```

3. Run the client: `fdo-client-linuxappp`

### Manufacturing client

You can run the `fdo-manufacturing-client` using the [provided
CLI mode](#cli-mode) or setting up [environment
variables](#environment-variables-mode).

For both cases, the Manufacturing client will only run if no Device Credentials
are found in any of the default locations:
`/sys/firmware/qemu_fw_cfg/by_name/opt/device_onboarding/devicecredential/raw`,
a location previously set up by the `DEVICE_CREDENTIAL` environment variable,
or `/etc/device-credentials`.

#### Environment variables mode

Please note that the environment variables shown in this section and
subsections are *required* unless said otherwise. 

* `MANUFACTURING_SERVER_URL`: URL of the manufacturing server.
* `USE_PLAIN_DI`: [optional] sets the Device Identification mode to `plain-di`
  or `no-plain-di`, by default `no-plain-di`.
  
The Manufacturing client will then operate in one of these two different modes:
`plain-di` or `no-plain-di`, which require a different set of environment
variables: 

##### `no-plain-di`

With this mode the Manufacturing server will request a specific Device
Identification method to the device.

1. Select the DIUN Public Key Verification Mode using *one* of the following
   environment variables and configuring it with the required value:
   
   - `DIUN_PUB_KEY_ROOTCERTS`: X509 certificate-based DIUN Public Key
     Verification Mode. Requires a path to the certificate.
   - `DIUN_PUB_KEY_HASH`: hash-based DIUN Public Key Verification
     Mode. Available options: `sha256` or `sha384`.
   - `DIUN_PUB_KEY_INSECURE`: (boolean) sets Public Key Verification Mode to
     `insecure`.
   
   If more than one environment variable is set the first one in the following
   order will take precedence: `DIUN_PUB_KEY_ROOTCERTS`, `DIUN_PUB_KEY_HASH`
   and `DIUN_PUB_KEY_INSECURE`.
   
2. If the Manufacturing server is specifically configured with a
   `mfg_string_type` set to `MACAddress` in its `diun` configuration section it
   will ask the device to identify itself with a MAC Address, in order to do so
   the user has an option to set `DI_MFG_STRING_TYPE_MAC_IFACE` [optional] to
   a valid interface.
  Valid interfaces are those which do not result in a `00:00:00:00:00:00` MAC Address.
   
   Please note that this `DI_MFG_STRING_TYPE_MAC_IFACE` environment variable is
   *optional* and will only be read if the server requests a `MACAddress`
   identification mode. If the Manufacturing server is configured as
   described and the environment variable `DI_MFG_STRING_TYPE_MAC_IFACE` is not set
   then the default active network interface will be used. This is obtained from 
   kernel's routing table file (`/proc/net/route`).
  
   
3. Run the client: `fdo-manufacturing-client`.

##### `plain-di`

The Device will have to configure all the required options for its
identification with the Manufacturing server.

1. `DI_MFG_STRING_TYPE`: [optional] selects the Device Identification string
   type; by default `serial_number`, other possible value is `mac_address`.
   
   If `mac_address` is selected as `DI_MFG_STRING_TYPE` then the user has an option
   to specify a valid interface to read the MAC Address from with
   `DI_MFG_STRING_TYPE_MAC_IFACE` [optional] env variable. 
   Valid interfaces are those which do not result in a `00:00:00:00:00:00` MAC Address.
   If the user has not specified which network interface to be used then the default 
   active network interface will be used. This is obtained from kernel's routing table 
   file (`/proc/net/route`).
  
   
2. `DI_KEY_STORAGE_TYPE`: selects the storage type for the Device
   Identification keys, valid values: `filesystem` (`tpm` not yet
   implemented).
   
3. `DI_SIGN_KEY_PATH`:

4. `DI_HMAC_KEY_PATH`:

5. `DEVICE_CREDENTIAL_FILENAME`: [optional] filepath specified by the user to
   store the device credentials, by default `/etc/device-credentials`.

6. Run the client: `fdo-manufacturing-client`.

#### CLI mode

The command-line interface also operates on `no-plain-di` and `plain-di` mode:

##### `no-plain-di`

```
Usage: fdo-manufacturing-client no-plain-di [OPTIONS] --manufacturing-server-url <MANUFACTURING_SERVER_URL> <--rootcerts <PATH>|--hash <HASH_TYPE>|--insecure>

Options:
  -m, --manufacturing-server-url <MANUFACTURING_SERVER_URL>
          URL of the manufacturing server
      --rootcerts <PATH>
          X509 certificate-based DIUN Public Key Verification Mode. Requires path to certificate
      --hash <HASH_TYPE>
          Hash-based DIUN Public Key Verification Mode. Available values: sha256, sha384
      --insecure
          Insecure DIUN Public Key Verification Mode
      --iface <IFACE>
          iface name for the MACAddress Device Identification string type
  -h, --help
          Print help
```

##### `plain-di`

```
Usage: fdo-manufacturing-client plain-di [OPTIONS] --manufacturing-server-url <MANUFACTURING_SERVER_URL> --mfg-string-type <MFG_STRING_TYPE> --key-ref <KEY_REF>

Options:
  -m, --manufacturing-server-url <MANUFACTURING_SERVER_URL>
          URL of the manufacturing server
      --mfg-string-type <MFG_STRING_TYPE>
          Device Identification string type. Available values: SerialNumber or MACAddress (requires iface selection with --iface)
      --iface <IFACE>
          iface name for the MACAddress Device Identification string type
      --key-ref <KEY_REF>
          Key reference. Available values: filesystem, tpm
  -h, --help
          Print help
```

Please note that in this mode there are some environment variables that are
still required to be set by the user (`DI_SIGN_KEY_PATH`, `DI_HMAC_KEY_PATH`).

## How to use Features

### How to use the `per-device serviceinfo` feature

  Using this feature the user can choose to apply different serviceinfo settings on different devices.
  For that the user needs to provide a path to a `per-device serviceinfo` file under the `device_specific_store_driver` field
  present in the `serviceinfo-api-server.yml` file.
  If other devices do not have their `per-device serviceinfo` file under `device_specific_store_driver` they will get onboarded
  with settings from the main file, which is `serviceinfo-api-server.yml`.
  
  1. Initialize the device as mentioned in [How to generate an Ownership Voucher and Credential for a Device](#how-to-generate-an-ownership-voucher-ov-and-credential-for-a-device-device-initialization).

  2. Dump the `device-credentials`
  ```bash
  fdo-owner-tool dump-device-credential /path/to/device-credentials
  ```

  3. Note the GUID of the device and create a .yml file with same name as the `guid` under directory path `device_specific_store_driver`.

  4. You can refer to [per_device_serviceinfo.yml](https://github.com/fedora-iot/fido-device-onboard-rs/blob/main/examples/config/device_specific_serviceinfo.yml) as an example.

  5. Follow the onboarding procedure and this particular device will get the serviceinfo settings as mentioned in the above file.
