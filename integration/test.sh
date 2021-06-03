#!/usr/bin/env bash

cd integration/testdata

cargo run --bin fdo-owner-tool initialize-device --device-cert-ca-chain keys/device_ca_cert.pem --device-cert-ca-private-key keys/device_ca_key.der --manufacturer-cert keys/manufacturer_cert.pem testdevice1 testdevice1.ov testdevice1.dc --rendezvous-info rendezvous-info.yml
cargo run --bin fdo-owner-tool extend-ownership-voucher testdevice1.ov --current-owner-private-key keys/manufacturer_key.der --new-owner-cert keys/reseller_cert.pem
cargo run --bin fdo-owner-tool extend-ownership-voucher testdevice1.ov --current-owner-private-key keys/reseller_key.der --new-owner-cert keys/owner_cert.pem
cargo run --bin fdo-owner-tool report-to-rendezvous --ownership-voucher testdevice1.ov --owner-private-key keys/owner_key.der --owner-addresses-path owner-addresses.yml  --wait-time 600
GUUID=$(find rendezvous_registered/ -type f -printf "%f\n")
cp testdevice1.ov ownership_vouchers/${GUUID}
DEVICE_CREDENTIAL=testdevice1.dc RUST_LOG=trace cargo run --bin fdo-client-linuxapp
cat /root/.ssh/authorized_keys | grep testkey
