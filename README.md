# fido-device-onboard-rs
An implementation of the FIDO Device Onboard Specification written in rust.

The current implementation targets specification version: [1.1 20211214](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.1-20211214/FIDO-device-onboard-spec-v1.1-rd-20211214.html).

## Components
The fido-fdo-rs implements all core components of the FIDO Device Onboard Specification including:
- [Client](https://github.com/fedora-iot/fido-device-onboard-rs/tree/main/client-linuxapp)
- [Rendezvous Server](https://github.com/fedora-iot/fido-device-onboard-rs/tree/main/rendezvous-server)
- [Onboarding Server](https://github.com/fedora-iot/fido-device-onboard-rs/tree/main/owner-onboarding-server)
- Manufacturing Tool both [client](https://github.com/fedora-iot/fido-device-onboard-rs/tree/main/manufacturing-client) and [server](https://github.com/fedora-iot/fido-device-onboard-rs/tree/main/manufacturing-server)

## Protocols
- [Device Initialize Protocol (DI)](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.1-20211214/FIDO-device-onboard-spec-v1.1-rd-20211214.html#device-initialize-protocol-di)
- [Transfer Ownership Protocol 0 (TO0)](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.1-20211214/FIDO-device-onboard-spec-v1.1-rd-20211214.html#transfer-ownership-protocol-0-to0)
- [Transfer Ownership Protocol 1 (TO1)](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.1-20211214/FIDO-device-onboard-spec-v1.1-rd-20211214.html#transfer-ownership-protocol-1-to1)
- [Transfer Ownership Protocol 2 (TO2)](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.1-20211214/FIDO-device-onboard-spec-v1.1-rd-20211214.html#transfer-ownership-protocol-2-to2)

## Crates and parts
- `fdo-client-linuxapp`: Performs TO1 and TO2 client side protocols.
- `fdo-data-formats`: [DI, TO0, TO1, TO2]: Implements the different low-level messaging formats used.
- `fdo-http-wrapper`: Helpers for HTTP operations in both FDO server and client.
- `fdo-integration-tests`: This crate contains the integration testing.
- `fdo-libfdo-data`: C wrapper around `fdo-data-formats`, allowing code in other languages to parse Ownership Vouchers, and possibly other data formats in the future.
- `fdo-manufacturing-client`: Client side implementation of Device Initialize and Device Initialize over
Untrusted Networks (DIUN) protocols.
- `fdo-manufacturing-server`: Server side implementation of Device Initialize protocol. It supports as well Untrusted Networks (DIUN) protocols, that can be used for local prototypes.
- `fdo-owner-onboarding-server`: Onboarding server, server side of TO2 protocol.
- `fdo-owner-tool`: Tool for initializing devices, dump ownership vouchers, dump device credentials, extend ownership vouchers and report the device to the rendezvous service.
- `fdo-rendezvous-server`: Rendezvous server implementation.
- `fdo-store`: Implementation of different backend datastores for services.
- `fdo-util`: Utilities/helpers for server (and, in the future client) crates.
- `fdo-iot-stream-message`: Implements the stream message creation/parsing of StreamMsg. Currently not implemented.
- `fdo-serviceinfo-api-server`: Service Info API Server implementation. The specification is written in [serviceinfo_api.md](./docs/specs/serviceinfo_api.md).

## RPMs and containers

This project currently releases RPMs and containers tracking the `main` branch. RPMs are available in [COPR](https://copr.fedorainfracloud.org/coprs/g/fedora-iot/fedora-iot/). Containers are available on [Quay.io](https://quay.io/organization/fido-fdo).
