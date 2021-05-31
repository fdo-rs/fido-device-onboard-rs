use serde::{Deserialize, Serialize};

use fdo_data_formats::types::{CipherSuite, DerivedKeys};
use aws_nitro_enclaves_cose::COSEEncrypt0;
use aws_nitro_enclaves_cose::error::COSEError;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionKeys {
    cipher_suite: Option<CipherSuite>,
    keys: Option<DerivedKeys>,
}

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

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, COSEError> {
        if self.cipher_suite.is_none() {
            Ok(plaintext.to_vec())
        } else {
            let k = match &self.keys {
                Some(DerivedKeys::Combined{sevk: k}) => k,
                _ => panic!()
            };
            COSEEncrypt0::new(
                plaintext,
                self.cipher_suite.unwrap().openssl_cipher(),
                &k[..],
            ).map(|c| c.as_bytes(true))?
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, COSEError> {
        if self.cipher_suite.is_none() {
            Ok(ciphertext.to_vec())
        } else {
            let k = match &self.keys {
                Some(DerivedKeys::Combined{sevk: k}) => k,
                _ => panic!(),
            };
            match COSEEncrypt0::from_bytes(ciphertext) {
                Ok(v) => {
                    match v.decrypt(k) {
                        Ok((_, _, payload)) => Ok(payload),
                        Err(e) => Err(e)
                    }
                },
                Err(e) => Err(e)
            }
        }
    }
}
