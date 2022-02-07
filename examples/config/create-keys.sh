#!/bin/bash

mkdir -p keys
# manufacturer key & cert
openssl ecparam -name prime256v1 -genkey -out keys/manufacturer_key.der -outform der
openssl req -x509 -key keys/manufacturer_key.der -keyform der -out keys/manufacturer_cert.pem -days 365 -subj "/C=US/O=Example/CN=Manufacturer"
# device key & cert
openssl ecparam -name prime256v1 -genkey -out keys/device_ca_key.der -outform der
openssl req -x509 -key keys/device_ca_key.der -keyform der -out keys/device_ca_cert.pem -days 365 -subj "/C=US/O=Example/CN=Device"
# owner key & cert
openssl ecparam -name prime256v1 -genkey -out keys/owner_key.der -outform der
openssl req -x509 -key keys/owner_key.der -keyform der -out keys/owner_cert.pem -days 365 -subj "/C=US/O=Example/CN=Owner"
# diun keys
openssl ecparam -name prime256v1 -genkey -out keys/diun_key.der -outform der
openssl req -x509 -key keys/diun_key.der -keyform der -out keys/diun_cert.pem -days 365 -subj "/C=US/O=Example/CN=DIUN"
