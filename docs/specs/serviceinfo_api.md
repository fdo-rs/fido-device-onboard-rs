---
layout: default
title: Service Info API
parent: Specifications
---

## Service Info API

**STATUS: Draft**

This specification describes a protocol that is used by the Owner Onboarding Service to retrieve information provided to the Device as part of the TO2 protocol.
This means that the Owner Onboarding Service, during the ServiceInfo phase of Transfer Ownership 2, will reach out to a server via this API to retrieve the information to provision on the device.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
RFC 2119.

### General Features

#### Encoding

Requests and responses for the Management API use JSON encoding, instead of the CBOR encoding used throughout the FIDO specification.

#### Authentication

For this protocol, the FDO Owner Onboarding Server will authenticate to the server of this API, via any of the authentication methods defined in the [OV Management API specification](./ov_management_api.md#authentication).

### Endpoint

This API consists of a single endpoint, the URL of which is configurable.
The URL will have configurable fields for the api version, device GUID, and the list of supported modules.
The API version for this specification is `1`.
The modules are comma-separated.

Whether a response is deemed successful is determined purely by the HTTP status code.
If any status other than 200 is returned, the Owner Onboarding Server will cancel the onboarding procedure, and the device will retry later.

A successful response will be a JSON object.
The server can send as many keys of the following list as it has available: every key is optional.
Additionally, the server is free to send more keys, and the FDO Owner Onboarding Server will ignore any keys that it does not recognize.

#### Supported response keys

The following keys are defined for the response to this endpoint:

- `com.redhat.subscription_identity_certificate`: a string containing a PEM-encoded identity certificate for the system.
- `initial_user`: a JSON object containing information about an initial user to be configured. Supported sub-keys are:
  - `username`: the username of the user to configure.
  - `ssh_keys`: a list of strings containing SSH keys to configure for this user.
- `extra_commands`: a JSON list containing additional ServiceInfo commands that the Owner Onboarding Server does not have special support for. For further explanation, see the next section.

##### `extra_commands`

The `extra_commands` list can be used to send ServiceInfo commands to the Device that the Owner Onboarding Server does not have explicit support for.

The entries of this list are lists themselves, with the following fields:

- Module name: JSON string
- Command name: JSON string
- Value: any JSON value

There is one special handling of this: if the `command` value ends in `|hex`, the value should be a hex-encoded string, which will be converted to binary data before being sent to the Device.
This is to overcome the lack of support for binary strings in JSON.

#### Examples

This assumes the URL is configured as `/device_info?serviceinfo_api_version=*api_version*&device_guid=*device_guid*&modules=*modules*`.

##### Request

``` HTTP
GET /device_info?serviceinfo_api_version=1&device_guid=ab9dee81-65d4-40f4-9844-ed4208fbd852&modules=devmod,com.example.sshkey
Host: deviceinfo.example.com
User-Agent: FDO-Owner-Onboarding-Server/1.0
Authorization: Bearer some-token-here
Accept: application/json
```

##### Successful response

The JSON in this example is broken up in multiple lines for visibility, the server should handle either with or without this breaking.

``` HTTP
HTTP/1.1 200 OK
Content-Type: application/json
Server: FDO-ServiceInfo-Server/1.0

{
  "com.redhat.subscription_identity_certificate": "-----BEGIN CERTIFICATE-----\n......\n-----END CERTIFICATE-----",
  "initial_user": {
    "username": "root",
    "ssh_keys": ["ssh-rsa ...."]
  },
  "undefined": "something_ignored",
  "extra_commands": [
    ["binaryfile", "active", "true"],
    ["binaryfile", "name", "/etc/foo"],
    ["binaryfile", "length", 40],
    ["binaryfile", "mode", "0644"],
    ["binaryfile", "data001|hex", "39582abcd...."],
    ["binaryfile", "sha-384|hex", "48204bdef...."],
    ["command", "active", "true"],
    ["command", "command", "/usr/bin/touch"],
    ["command", "args", ["/etc/bar"]],
    ...
  ]
}
```
