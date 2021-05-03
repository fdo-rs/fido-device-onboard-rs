use openssl::symm::Crypter;
use serde::{Deserialize, Serialize};

use fdo_data_formats::types::{CipherSuite, DerivedKeys};

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionKeys {
    cipher_suite: Option<CipherSuite>,
    keys: Option<DerivedKeys>,
}

#[derive(Debug)]
pub struct CryptoError;

impl EncryptionKeys {
    pub fn unencrypted() -> Self {
        EncryptionKeys {
            cipher_suite: None,
            keys: None,
        }
    }

    pub fn from_derived(cipher_suite: CipherSuite, derived_keys: DerivedKeys) -> Self {
        EncryptionKeys {
            cipher_suite: Some(cipher_suite),
            keys: Some(derived_keys),
        }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.cipher_suite.is_none() {
            Ok(plaintext.to_vec())
        } else {
            log::error!("WARNING: ENCRYPTION KEY CRYPTO NOT IMPLEMENTED!");
            let mut res = plaintext.to_vec();
            res.insert(0, 42);
            Ok(res)
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.cipher_suite.is_none() {
            Ok(ciphertext.to_vec())
        } else {
            log::error!("WARNING: ENCRYPTION KEY CRYPTO NOT IMPLEMENTED!");
            if ciphertext[0] != 42 {
                return Err(CryptoError);
            }
            Ok(ciphertext[1..].to_vec())
        }
    }
}
