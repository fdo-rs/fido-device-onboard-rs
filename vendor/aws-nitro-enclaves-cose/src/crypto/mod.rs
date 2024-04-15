//! (Signing) cryptography abstraction

use openssl::{hash::MessageDigest, nid::Nid};

use crate::{error::CoseError, sign::SignatureAlgorithm};

#[cfg(feature = "key_openssl_pkey")]
mod openssl_pkey;
#[cfg(feature = "key_tpm")]
pub mod tpm;

/// A public key that can verify an existing signature
pub trait SigningPublicKey {
    /// This returns the signature algorithm and message digest to be used for this
    /// public key.
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError>;

    /// Given a digest and a signature, returns a boolean whether the signature
    /// was valid.
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError>;
}

/// Follows the recommandations put in place by the RFC and doesn't deal with potential
/// mismatches: https://tools.ietf.org/html/rfc8152#section-8.1.
pub fn ec_curve_to_parameters(
    curve_name: Nid,
) -> Result<(SignatureAlgorithm, MessageDigest, usize), CoseError> {
    let sig_alg = match curve_name {
        // Recommended to use with SHA256
        Nid::X9_62_PRIME256V1 => SignatureAlgorithm::ES256,
        // Recommended to use with SHA384
        Nid::SECP384R1 => SignatureAlgorithm::ES384,
        // Recommended to use with SHA512
        Nid::SECP521R1 => SignatureAlgorithm::ES512,
        _ => {
            return Err(CoseError::UnsupportedError(format!(
                "Curve name {:?} is not supported",
                curve_name
            )))
        }
    };

    Ok((
        sig_alg,
        sig_alg.suggested_message_digest(),
        sig_alg.key_length(),
    ))
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

/// A private key that can produce new signatures
pub trait SigningPrivateKey: SigningPublicKey {
    /// Given a digest, returns a signature
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError>;
}
