#!/usr/bin/bash
rm -rf integration/testdata/{keys,ownership_vouchers,rendezvous_registered}/
mkdir integration/testdata/keys
openssl ecparam -name prime256v1 -genkey -out integration/testdata/keys/manufacturer_key.der -outform der
openssl req -x509 -key integration/testdata/keys/manufacturer_key.der -keyform der -out integration/testdata/keys/manufacturer_cert.pem -days 365 -subj "/C=US/O=RHEL for Edge/CN=FIDO Manufacturer"
openssl ecparam -name prime256v1 -genkey -out integration/testdata/keys/device_ca_key.der -outform der
openssl req -x509 -key integration/testdata/keys/device_ca_key.der -keyform der -out integration/testdata/keys/device_ca_cert.pem -days 365 -subj "/C=US/O=RHEL for Edge/CN=Device"
openssl ecparam -name prime256v1 -genkey -out integration/testdata/keys/owner_key.der -outform der
openssl req -x509 -key integration/testdata/keys/owner_key.der -keyform der -out integration/testdata/keys/owner_cert.pem -days 365 -subj "/C=US/O=RHEL for Edge/CN=Owner"
openssl ecparam -name prime256v1 -genkey -out integration/testdata/keys/reseller_key.der -outform der
openssl req -x509 -key integration/testdata/keys/reseller_key.der -keyform der -out integration/testdata/keys/reseller_cert.pem -days 365 -subj "/C=US/O=RHEL for Edge/CN=Reseller"
mkdir integration/testdata/ownership_vouchers
mkdir integration/testdata/rendezvous_registered
