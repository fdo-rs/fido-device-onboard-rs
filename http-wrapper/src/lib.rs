use openssl::symm::{encrypt, Cipher};
use serde::{Deserialize, Serialize};

use fdo_data_formats::types::DerivedKeys;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

#[derive(Serialize, Deserialize)]
pub enum EncryptionKeys {
    None,
    AEAD(Vec<u8>),
    Separate(Vec<u8>, Vec<u8>),
}

impl From<DerivedKeys> for EncryptionKeys {
    fn from(dk: DerivedKeys) -> Self {
        match dk {
            DerivedKeys::SEVK(sevk) => EncryptionKeys::AEAD(sevk),
            DerivedKeys::Split { sek, svk } => EncryptionKeys::Separate(sek, svk),
        }
    }
}

impl std::fmt::Debug for EncryptionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[[ ENCRYPTIONKEYS: REDACTED ]]")
    }
}

#[derive(Debug)]
pub struct CryptoError;

impl EncryptionKeys {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            EncryptionKeys::None => Ok(plaintext.to_vec()),
            EncryptionKeys::AEAD(_) => {
                log::error!("WARNING: ENCRYPTION KEY CRYPTO NOT IMPLEMENTED!");
                let mut res = plaintext.to_vec();
                res.insert(0, 42);
                Ok(res)
            }
            _ => todo!(),
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            EncryptionKeys::None => Ok(ciphertext.to_vec()),
            EncryptionKeys::AEAD(_) => {
                log::error!("WARNING: ENCRYPTION KEY CRYPTO NOT IMPLEMENTED!");
                if ciphertext[0] != 42 {
                    return Err(CryptoError);
                }
                Ok(ciphertext[1..].to_vec())
            }
            _ => todo!(),
        }
    }
}
