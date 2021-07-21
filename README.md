# fido-device-onboard-rs
An implementation of the FIDO Device Onboard Specification written in rust.

The current implementation targets specification version: [v1.0 20210323a](https://fidoalliance.org/specs/FDO/fido-device-onboard-v1.0-ps-20210323/fido-device-onboard-v1.0-ps-20210323.html).

## Components
The fido-fdo-rs implements all core components of the FIDO Device Onboard Specification including:
- Client
- Rendezvous Server
- Onboarding Server
- Manufacturing Tool

## Protocols
- Device Initialize Protocol (DI)
- Transfer Ownership Protocol 0 (TO0)
- Transfer Ownership Protocol 1 (TO1)
- Transfer Ownership Protocol 2 (TO2)

## Crates and parts
- fdo-iot-stream-message: Implements the stream message creation/parsing of StreamMsg. Currently not implemented
- fdo-iot-data-formats: [DI, TO0, TO1, TO2]: Implements the different low-level messaging formats used.
- fdo-data-formats:
- fdo-http-wrapper:
- fdo-store:
- fdo-owner-onboarding-service:
- fdo-owner-tool:
- fdo-rendezvous-server:
- fdo-client-linuxapp:

## Building

To build on Fedora/RHEL/CentOS you can do the following:
````
sudo yum install -y cargo git-core openssl-devel
git clone https://github.com/fedora-iot/fido-device-onboard-rs.git
cd fido-device-onboard-rs
cargo build --release
````
