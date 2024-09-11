# rust-openssl-kdf

Wrappers for the KDF functionality of OpenSSL.

This is a wrapper around difference KDF implementations in OpenSSL.
At this moment, it supports the EVP_KDF functionality as backported into Fedora/RHEL.

This implements Rust wrappers for the EVP_KDF functionality in OpenSSL, among which is KBKDF, as specified in [NIST SP800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf).

## Example use (KBKDF in Counter mode with HMAC-SHA256 as PRF)

``` rust
use openssl_kdf::{KdfArgument, KdfKbMode, KdfMacType, KdfType, perform_kdf};
use openssl::hash::MessageDigest;

let args = [
    &KdfArgument::KbMode(KdfKbMode::Counter),
    &KdfArgument::Mac(KdfMacType::Hmac(MessageDigest::sha256())),
    // Set the salt (called "Label" in SP800-108)
    &KdfArgument::Salt(&[0x12, 0x34]),
    // Set the kb info (called "Context" in SP800-108)
    &KdfArgument::KbInfo(&[0x9a, 0xbc]),
    // Set the key (called "Ki" in SP800-108)
    &KdfArgument::Key(&[0x56, 0x78]),
];

let key_out = perform_kdf(KdfType::KeyBased, &args, 20).unwrap();
```
