---
layout: default
title: Ownership Voucher Management API
parent: Specifications
---

## Ownership Voucher Management API

**STATUS: Draft**

This specification describes a protocol that (authenticated) external parties can use to manage the Ownership Vouchers (OV) and Owner Onboarding Server tracks.
This protocol will be called the "Ownership Voucher Management API", or in the scope of this document, the "Management API".

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
RFC 2119.

### General Features

#### Encoding

Requests and responses for the Management API use JSON encoding, instead of the CBOR encoding used throughout the FIDO specification.

#### Authentication

Multiple authentication methods are specified in this document, and a server can support any combination of them.
Clients will need to interact with Management API server operators to determine which authentication method to use, and to obtain credentials.
The server will log who performs actions, and which authentication method was used, but it is not required to store this information in its data stores.
The method by which clients are provided with credentials is outside the scope of this specification.

##### X.509 Client Certificate

In this authentication method, a client will send its certificate as part of the TLS connection handshake.
For this, the certificate needs to be signed by a Certificate Authority that the server trusts.
The `username` in the protocol is the value of the `CN` field in the `Subject` of the certificate.

##### OAuth2 Bearer token in Authorization header

In this authentication method, the client will send an OAuth2 Bearer token, as per [RFC6750, section 2.1](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1).
How the server determines a `username` for this authentication method is outside the scope of this specification.

#### Responses

Requests that got parsed and executed successfully will have a Status code in the Successful range ([section 6.3, RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231#section-6.3)).
If an error occurred during processing, a Status code in either the Client Error ([section 6.5, RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231#section-6.5)) or Server Error ([section 6.6, RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231#section-6.6)) will be returned.

Responses will have `Content-Type: application/json` and consist of JSON strings.

##### Error responses

Error responses will consist of JSON objects, with at least the following keys:

- `error_code`: An operation-specific string error code.
- `error_details`: A JSON object with keys defined by the specific `error_code` value.

### Ownership Voucher upload

HTTP Request context: `POST $base/v1/ownership_voucher`.

This endpoint can be used to upload a batch of new ownership vouchers.
A header is sent with the number of vouchers to be uploaded, so the Owner Onboarding Service can verify that it did in fact receive (and process) every ownership voucher.
This endpoint will accept either raw ownership vouchers (CBOR encoding), or PEM wrapper ownership vouchers, with the `OWNERSHIP VOUCHER` type, which one will be parsed/expected is determined by the `Content-Type` request header: `application/cbor` for CBOR, and `application/x-pem-file` for PEM.
In the case of CBOR encoded vouchers, they should just be appended to each other as a byte stream.
In the case of PEM encoded vouchers, vouchers should be appended to each other, adding a newline between the different entries.
The request SHOULD contain a header `X-Number-Of-Vouchers`, containing the number of Ownership Vouchers being uploaded.
If this number diverges from the number of vouchers the server parsed, they should refuse the entire request.

A successful response will contain a JSON list containing objects, which each have at least the following keys:

- `guid`: the FDO GUID of the Ownership Voucher.

#### Error codes

- `incomplete_voucher`: when an uploaded voucher was incomplete. `error_details` contains at least the key `parsed_correctly`, containing the number of Ownership Vouchers successfully parsed.
- `parse_error`: when an Ownership Voucher was uploaded that is structurally invalid. `error_details` contains the key `parsed_correctly`, containing the number of Ownership Vouchers successfully parsed, and the key `description`, containing a string with a description of the parse failure.
- `invalid_number_of_vouchers`: when the value of `X-Number-Of-Vouchers` does not match the number of parsed Ownership Vouchers. `error_details` contains the key `parsed`, with an integer containing the number of Ownership Vouhcers that were encountered.
- `unowned_voucher`: when an Ownership Voucher was uploaded for which the current Owner is not the Owner key of the server. `error_details` contains the key `unowned`, which is a list of indexes of Ownership Vouchers that have invalid ownership.
- `invalid_voucher_signatures`: when an Ownership Voucher was uploaded for which one of the cryptographic verifications failed. `error_details` contains the key `invalid`, which contains a list of objects with the key `index` describing the index of the failing voucher, and `description` containing a string description of what failed to verify on the voucher.


#### Example

This assumes a URI base of `/management`, and an authentication method of `OAuth2 bearer token`.

##### Request

``` HTTP
POST /management/v1/ownership_voucher HTTP/1.1
Host: fdo.example.com
User-Agent: FDO-Client/1.0
Authorization: Bearer some-token-here
X-Number-Of-Vouchers: 3
Content-Type: application/cbor
Accept: application/json

<voucher-1-bytes><voucher-2-bytes><voucher-3-bytes>
```

##### Successful response

``` HTTP
HTTP/1.1 201 Created
Content-Type: application/json
Server: FDO-Owner-Server/1.0

[{“guid”: “ec1c2515-98f4-40f6-a880-8db987a423c1”}, {“guid”: “d2e4fc0e-fc0b-42a0-8767-6e82bb58dd86”,}, {“guid”: “ccb05292-cba6-484f-b803-55d66c50887b”}]
```

##### Failed response: incomplete_voucher

``` HTTP
HTTP/1.1 400 Bad Request
Content-Type: application/json
Server: FDO-Owner-Server/1.0

{"error_code": "incomplete_voucher", "error_details": {"parsed_correctly": 2}}
```

##### Failed response: unowned_voucher

``` HTTP
HTTP/1.1 400 Bad Request
Content-Type: application/json
Server: FDO-Owner-Server/1.0

{"error_code": "unowned_voucher", "error_details": {"unowned": ["4fd43ba9-12ec-4f32-bda0-d5c0956a19be"]}}
```

### Ownership Voucher delete

HTTP Request context: `POST $base/v1/ownership_voucher/delete`.

This endpoint can be used to request the Owner Onboarding Server to delete a set of Ownership Vouchers, and to stop taking ownership of the devices.
The request body consists of a JSON list of GUIDs for which the Ownership Vouchers should get deleted.

A successful response contains an empty body.

#### Error codes

- `unknown_device`: at least one of the GUIDs that were submitted were unknown to this Owner Onboarding Service. `error_details` contains the key `unknown`, which contains a JSON list of GUIDs that were unknown to this server.

#### Example

This assumes a URI base of `/management`, and an authentication method of `OAuth2 bearer token`.

##### Request

``` HTTP
POST /management/v1/ownership_voucher/delete HTTP/1.1
Host: fdo.example.com
User-Agent: FDO-Client/1.0
Authorization: Bearer some-token-here
Content-Type: application/json
Accept: application/json

[“a9bcd683-a7e4-46ed-80b2-6e55e8610d04”, “1ea69fcb-b784-4d0f-ab4d-94589c6cc7ad”]
```

##### Successful response

``` HTTP
HTTP/1.1 200 OK
Content-Type: application/json
Server: FDO-Owner-Server/1.0
```

##### Failed response: unknown_device

``` HTTP
HTTP/1.1 400 Bad Request
Content-Type: application/json
Server: FDO-Owner-Server/1.0

{"error_code": "unknown_device", "error_details": {"unknown": [“1ea69fcb-b784-4d0f-ab4d-94589c6cc7ad”"]}}
```
