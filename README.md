# fido-iot-rs
FIDO IoT Rust crates

This intends to implement the FIDO IoT draft specification.
Current specification version target: v1.0 20200730.

## Protocols
- Device Initialize Protocol (DI)
- Transfer Ownership Protocol 0 (TO0)
- Transfer Ownership Protocol 1 (TO1)
- Transfer Ownership Protocol 2 (TO2)

## Crates and parts
- *fido-iot-data-formats* [DI, TO0, TO1, TO2]: Implements the different low-level messaging formats used.
