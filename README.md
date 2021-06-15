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
- *fido-iot-stream-message*: Implements the stream message creation/parsing of StreamMsg. Currently not implemented
- *fido-iot-data-formats* [DI, TO0, TO1, TO2]: Implements the different low-level messaging formats used.

### fido-iot-data-formats
