use std::{
    cell::RefCell,
    convert::{TryFrom, TryInto},
};

use crate::{
    constants::HashType,
    errors::Error,
    types::HMac,
    types::{Guid, Hash, RendezvousInfo},
    DeviceCredential, ProtocolVersion,
};

use aws_nitro_enclaves_cose::error::CoseError;
use openssl::{pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize};
use serde_tuple::Serialize_tuple;
use tss_esapi::{
    attributes::ObjectAttributesBuilder, structures::PublicBuilder, traits::UnMarshall,
};

#[derive(Debug, Serialize, Deserialize)]
pub enum KeyStorage {
    Plain {
        hmac_secret: Vec<u8>,
        private_key: Vec<u8>,
    },
    Tpm {
        signing_public: Vec<u8>,
        signing_private: Vec<u8>,
        hmac_public: Vec<u8>,
        hmac_private: Vec<u8>,
    },
}

fn get_semi_tpm_ctx_and_primary(
) -> Result<(tss_esapi::Context, tss_esapi::handles::KeyHandle), Error> {
    let tcti_conf = tss_esapi::tcti_ldr::TctiNameConf::from_environment_variable()
        .unwrap_or_else(|_| tss_esapi::tcti_ldr::TctiNameConf::Tabrmd(Default::default()));
    let mut tss_context = tss_esapi::Context::new(tcti_conf)?;

    let primary_template = semi_tpm_primary_key_template()?;
    let primary_handle = tss_context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                tss_esapi::interface_types::resource_handles::Hierarchy::Owner,
                primary_template,
                None,
                None,
                None,
                None,
            )
        })?
        .key_handle;
    Ok((tss_context, primary_handle))
}

impl KeyStorage {
    pub fn perform_hmac(&self, data: &[u8], hmac_type: HashType) -> Result<HMac, Error> {
        match self {
            KeyStorage::Plain {
                ref hmac_secret, ..
            } => {
                let hmac_key = PKey::hmac(hmac_secret)?;
                let mut hmac_signer = Signer::new(hmac_type.get_md(), &hmac_key)?;
                hmac_signer.update(data)?;
                let ov_hmac = hmac_signer.sign_to_vec()?;
                HMac::from_digest(hmac_type, ov_hmac)
            }
            KeyStorage::Tpm {
                hmac_public,
                hmac_private,
                ..
            } => {
                let (mut tss_context, primary_handle) = get_semi_tpm_ctx_and_primary()?;
                let hmac_public = tss_esapi::structures::Public::unmarshall(hmac_public)?;
                let hash_algo = match hmac_public {
                    tss_esapi::structures::Public::KeyedHash { parameters, .. } => {
                        let parameters: tss_esapi::tss2_esys::TPMS_KEYEDHASH_PARMS =
                            parameters.into();
                        let scheme = parameters.scheme;
                        match tss_esapi::constants::AlgorithmIdentifier::try_from(scheme.scheme)? {
                            tss_esapi::constants::AlgorithmIdentifier::Hmac => {}
                            _ => return Err(Error::UnsupportedAlgorithm),
                        }
                        let details = unsafe { scheme.details.hmac }.hashAlg;
                        let details = tss_esapi::constants::AlgorithmIdentifier::try_from(details)?;

                        match details {
                            tss_esapi::constants::AlgorithmIdentifier::Sha256 => {
                                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256
                            }
                            tss_esapi::constants::AlgorithmIdentifier::Sha384 => {
                                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha384
                            }
                            _ => return Err(Error::UnsupportedAlgorithm),
                        }
                    }
                    _ => return Err(Error::UnsupportedAlgorithm),
                };
                let hash_type = match hash_algo {
                    tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256 => {
                        HashType::Sha256
                    }
                    tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha384 => {
                        HashType::Sha384
                    }
                    _ => return Err(Error::UnsupportedAlgorithm),
                };

                let hmac_handle = tss_context.execute_with_nullauth_session(|ctx| {
                    ctx.load(
                        primary_handle,
                        hmac_private.as_slice().try_into()?,
                        hmac_public.clone(),
                    )
                })?;
                let data = data.try_into()?;

                let hmac = tss_context.execute_with_nullauth_session(|ctx| {
                    ctx.execute_with_temporary_object(hmac_handle.into(), |ctx, hmac_key| {
                        ctx.hmac(hmac_key, data, hash_algo)
                    })
                })?;
                Ok(HMac::from_digest(hash_type, hmac.to_vec())?)
            }
        }
    }
}

pub fn semi_tpm_primary_key_template() -> Result<tss_esapi::structures::Public, Error> {
    let primary_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_user_with_auth(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Ecc)
        .with_object_attributes(primary_attributes)
        .with_name_hashing_algorithm(
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
        )
        .with_ecc_parameters(tss_esapi::structures::PublicEccParameters::new(
            tss_esapi::structures::SymmetricDefinitionObject::Aes {
                key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes128,
                mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
            },
            tss_esapi::structures::EccScheme::Null,
            tss_esapi::interface_types::ecc::EccCurve::NistP256,
            tss_esapi::structures::KeyDerivationFunctionScheme::Null,
        ))
        .with_ecc_unique_identifier(Default::default())
        .build()
        .map_err(Error::from)
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct FileDeviceCredential {
    pub active: bool,             // Active
    pub protver: ProtocolVersion, // ProtVer
    pub device_info: String,      // DeviceInfo
    pub guid: Guid,               // Guid
    pub rvinfo: RendezvousInfo,   // RVInfo
    pub pubkey_hash: Hash,        // PubKeyHash

    pub key_storage: KeyStorage,
}

impl DeviceCredential for FileDeviceCredential {
    fn is_active(&self) -> bool {
        self.active
    }

    fn protocol_version(&self) -> ProtocolVersion {
        self.protver
    }

    fn verify_hmac(&self, data: &[u8], hmac: &HMac) -> Result<(), Error> {
        if hmac != &self.key_storage.perform_hmac(data, hmac.get_type())? {
            Err(Error::IncorrectHash)
        } else {
            Ok(())
        }
    }

    fn device_info(&self) -> &str {
        &self.device_info
    }

    fn device_guid(&self) -> &Guid {
        &self.guid
    }

    fn rendezvous_info(&self) -> &RendezvousInfo {
        &self.rvinfo
    }

    fn manufacturer_pubkey_hash(&self) -> &Hash {
        &self.pubkey_hash
    }

    fn get_signer(
        &self,
    ) -> Result<Box<dyn aws_nitro_enclaves_cose::crypto::SigningPrivateKey>, Error> {
        match self.key_storage {
            KeyStorage::Plain {
                ref private_key, ..
            } => Ok(Box::new(PKey::private_key_from_der(private_key)?)),
            KeyStorage::Tpm {
                ref signing_public,
                ref signing_private,
                ..
            } => {
                let (mut tss_context, primary_handle) = get_semi_tpm_ctx_and_primary()?;
                let signing_public = tss_esapi::structures::Public::unmarshall(signing_public)?;

                let signing_handle = tss_context.execute_with_nullauth_session(|ctx| {
                    ctx.load(
                        primary_handle,
                        signing_private.as_slice().try_into()?,
                        signing_public.clone(),
                    )
                })?;

                Ok(Box::new(TpmCoseSigner {
                    tss_context: RefCell::new(tss_context),
                    _primary_handle: primary_handle,
                    signing_handle,
                    signing_public,
                }))
            }
        }
    }
}

struct TpmCoseSigner {
    tss_context: RefCell<tss_esapi::Context>,
    // This is here for the lifetime of the KeyHandle, so it won't be dropped
    _primary_handle: tss_esapi::handles::KeyHandle,
    signing_handle: tss_esapi::handles::KeyHandle,
    signing_public: tss_esapi::structures::Public,
}

impl TpmCoseSigner {
    fn public_to_parameters(
        public: &tss_esapi::structures::Public,
    ) -> Result<
        (
            (
                aws_nitro_enclaves_cose::crypto::SignatureAlgorithm,
                aws_nitro_enclaves_cose::crypto::MessageDigest,
            ),
            tss_esapi::interface_types::algorithm::HashingAlgorithm,
            usize,
        ),
        aws_nitro_enclaves_cose::error::CoseError,
    > {
        match public {
            tss_esapi::structures::Public::Rsa { .. } => unimplemented!(),
            tss_esapi::structures::Public::Ecc { parameters, .. } => {
                let hash_alg = match parameters.ecc_scheme() {
                    tss_esapi::structures::EccScheme::EcDsa(sig_alg) => sig_alg.hashing_algorithm(),
                    _ => return Err(CoseError::UnsupportedError("Unsupported ECC scheme".into())),
                };
                let param_hash_alg = match hash_alg {
                    tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256 => {
                        aws_nitro_enclaves_cose::crypto::MessageDigest::Sha256
                    }
                    tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha384 => {
                        aws_nitro_enclaves_cose::crypto::MessageDigest::Sha384
                    }
                    tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha512 => {
                        aws_nitro_enclaves_cose::crypto::MessageDigest::Sha512
                    }
                    _ => {
                        return Err(CoseError::UnsupportedError(
                            "Unsupported hashing algorithm".into(),
                        ))
                    }
                };
                let (sig_alg, correct_hash_alg, key_length) = match parameters.ecc_curve() {
                    tss_esapi::interface_types::ecc::EccCurve::NistP256 => (
                        aws_nitro_enclaves_cose::crypto::SignatureAlgorithm::ES256,
                        tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
                        32,
                    ),
                    tss_esapi::interface_types::ecc::EccCurve::NistP384 => (
                        aws_nitro_enclaves_cose::crypto::SignatureAlgorithm::ES384,
                        tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha384,
                        48,
                    ),
                    tss_esapi::interface_types::ecc::EccCurve::NistP521 => (
                        aws_nitro_enclaves_cose::crypto::SignatureAlgorithm::ES512,
                        tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha512,
                        66,
                    ),
                    _ => {
                        return Err(CoseError::UnsupportedError(
                            "Unsupported ECC curve used".into(),
                        ))
                    }
                };
                if hash_alg != correct_hash_alg {
                    return Err(CoseError::SpecificationError(
                        "Invalid hash algorithm".into(),
                    ));
                }
                Ok(((sig_alg, param_hash_alg), hash_alg, key_length))
            }
            _ => unimplemented!(),
        }
    }
}

impl aws_nitro_enclaves_cose::crypto::SigningPublicKey for TpmCoseSigner {
    fn get_parameters(
        &self,
    ) -> Result<
        (
            aws_nitro_enclaves_cose::crypto::SignatureAlgorithm,
            aws_nitro_enclaves_cose::crypto::MessageDigest,
            // openssl::hash::MessageDigest,
        ),
        CoseError,
    > {
        Ok(TpmCoseSigner::public_to_parameters(&self.signing_public)?.0)
    }

    fn verify(&self, _digest: &[u8], _signature: &[u8]) -> Result<bool, CoseError> {
        // In a Device Credential, we don't care about verifying signatures with the TPM
        unimplemented!()
    }
}

fn merge_ec_signature(bytes_r: &[u8], bytes_s: &[u8], key_length: usize) -> Vec<u8> {
    assert!(bytes_r.len() <= key_length);
    assert!(bytes_s.len() <= key_length);

    let mut signature_bytes = vec![0u8; key_length * 2];

    // This is big-endian encoding so padding might be added at the start if the factor is
    // too short.
    let offset_copy = key_length - bytes_r.len();
    signature_bytes[offset_copy..offset_copy + bytes_r.len()].copy_from_slice(bytes_r);

    // This is big-endian encoding so padding might be added at the start if the factor is
    // too short.
    let offset_copy = key_length - bytes_s.len() + key_length;
    signature_bytes[offset_copy..offset_copy + bytes_s.len()].copy_from_slice(bytes_s);

    signature_bytes
}

impl aws_nitro_enclaves_cose::crypto::SigningPrivateKey for TpmCoseSigner {
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        let key_length = Self::public_to_parameters(&self.signing_public)?.2;
        let validation = tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
            tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
            hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
            digest: Default::default(),
        }
        .try_into()
        .map_err(|_| {
            CoseError::UnsupportedError("Error converting TPMT_TK_HASHCHECK".to_string())
        })?;
        let data = tss_esapi::structures::Digest::try_from(digest).map_err(|_| {
            CoseError::UnsupportedError("Invalid data signing attempted".to_string())
        })?;

        // Special scope to not leak the context
        let signature = {
            let mut ctx = self.tss_context.borrow_mut();
            ctx.execute_with_nullauth_session(|ctx| {
                ctx.sign(
                    self.signing_handle,
                    data,
                    tss_esapi::structures::SignatureScheme::Null,
                    validation,
                )
            })
            .map_err(|e| CoseError::UnsupportedError(format!("Error signing: {e}")))?
        };
        match signature {
            tss_esapi::structures::Signature::EcDsa(signature) => Ok(merge_ec_signature(
                signature.signature_r().value(),
                signature.signature_s().value(),
                key_length,
            )),
            _ => Err(CoseError::UnsupportedError(
                "Invalid signature type".to_string(),
            )),
        }
    }
}
