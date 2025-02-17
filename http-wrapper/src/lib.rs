use serde::{Deserialize, Serialize};

use aws_nitro_enclaves_cose::crypto::Openssl;
use aws_nitro_enclaves_cose::error::CoseError;
use aws_nitro_enclaves_cose::{CipherConfiguration, CoseEncrypt0};
use fdo_data_formats::types::{CipherSuite, DerivedKeys};

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

pub fn init_logging() {
    let filter = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    pretty_env_logger::formatted_timed_builder()
        .filter_level(log::LevelFilter::Info)
        .parse_filters(&filter)
        .init();
}

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

    pub fn is_none(&self) -> bool {
        self.cipher_suite.is_none() || self.keys.is_none()
    }

    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    pub fn from_derived(cipher_suite: CipherSuite, derived_keys: DerivedKeys) -> Self {
        EncryptionKeys {
            cipher_suite: Some(cipher_suite),
            keys: Some(derived_keys),
        }
    }

    #[allow(clippy::panic)]
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CoseError> {
        if self.cipher_suite.is_none() {
            Ok(plaintext.to_vec())
        } else {
            let k = match &self.keys {
                Some(DerivedKeys::Combined { sevk: k }) => k,
                _ => panic!(),
            };
            CoseEncrypt0::new::<Openssl>(plaintext, CipherConfiguration::Gcm, &k[..])
                .map(|c| c.as_bytes(true))?
        }
    }

    #[allow(clippy::panic)]
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CoseError> {
        if self.cipher_suite.is_none() {
            Ok(ciphertext.to_vec())
        } else {
            let k = match &self.keys {
                Some(DerivedKeys::Combined { sevk: k }) => k,
                _ => panic!(),
            };
            match CoseEncrypt0::from_bytes(ciphertext) {
                Ok(v) => match v.decrypt::<Openssl>(k) {
                    Ok((_, _, payload)) => Ok(payload),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            }
        }
    }
}
