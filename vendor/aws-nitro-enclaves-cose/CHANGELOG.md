
# Changelog

## 0.4.0
* Abstract signing support: provide traits to abstract private and public keys.
* Support signing with a TPM-backed private key via the `key_tpm` feature.

## 0.3.0

* **Breaking change**: Use upper case acronyms as advised by clippy
* **New Feature**: COSE encryption is now available. Thank you @runcom for the patches.
* Allow access to CoseSign1 headers, to allow algorithms to use read and set them. Thank you @puiterwijk.
* Minor fixes and version bumps.

## 0.2.0

* Bump `serde_with` version.
* CBOR tags support: can add and verify tags on COSESign1.
* Use PKey instead of EcKey. Just an interface change, RSA not supported yet. (thanks @puiterwijk)
This will likely change again in the future to support https://github.com/awslabs/aws-nitro-enclaves-cose/issues/5.
* Implement std::error::Error for COSEError (thanks @puiterwijk)

## 0.1.0

Initial Release
