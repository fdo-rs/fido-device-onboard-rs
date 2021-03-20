use openssl::symm::{encrypt, Cipher};
use serde::{Deserialize, Serialize};

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

#[derive(Debug, Serialize, Deserialize)]
pub enum EncryptionKeys {
    None,
    AEAD(Vec<u8>),
    Separate(Vec<u8>, Vec<u8>),
}

#[derive(Debug)]
pub struct CryptoError;

impl EncryptionKeys {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            EncryptionKeys::None => Ok(plaintext.to_vec()),
            EncryptionKeys::AEAD(_) => {
                println!("Intended to encrypt");
                // Do a fake encrypt
                let mut ciphertext = plaintext.to_vec();
                ciphertext.insert(0, b'E');
                Ok(ciphertext)
            }
            _ => todo!(),
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            EncryptionKeys::None => Ok(ciphertext.to_vec()),
            EncryptionKeys::AEAD(_) => {
                println!("Intended to decrypt");
                // Do a fake decrypt
                if ciphertext[0] != b'E' {
                    return Err(CryptoError);
                }
                let plaintext = ciphertext[1..].to_vec();
                Ok(plaintext)
            }
            _ => todo!(),
        }
    }
}
