//! OpenSSL PKey(Ref) implementation for cryptography

use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    pkey::{HasPrivate, HasPublic, PKey, PKeyRef},
};

use crate::{
    crypto::{ec_curve_to_parameters, SigningPrivateKey, SigningPublicKey},
    error::CoseError,
    sign::SignatureAlgorithm,
};

impl<T> SigningPublicKey for PKey<T>
where
    T: HasPublic,
{
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        self.as_ref().get_parameters()
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        self.as_ref().verify(digest, signature)
    }
}

impl<T> SigningPublicKey for PKeyRef<T>
where
    T: HasPublic,
{
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        let curve_name = self
            .ec_key()
            .map_err(|_| CoseError::UnsupportedError("Non-EC keys are not supported".to_string()))?
            .group()
            .curve_name()
            .ok_or_else(|| {
                CoseError::UnsupportedError("Anonymous EC keys are not supported".to_string())
            })?;

        let curve_parameters = ec_curve_to_parameters(curve_name)?;

        Ok((curve_parameters.0, curve_parameters.1))
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        let key = self.ec_key().map_err(|_| {
            CoseError::UnsupportedError("Non-EC keys are not yet supported".to_string())
        })?;

        let curve_name = key.group().curve_name().ok_or_else(|| {
            CoseError::UnsupportedError("Anonymous EC keys are not supported".to_string())
        })?;

        let (_, _, key_length) = ec_curve_to_parameters(curve_name)?;

        // Recover the R and S factors from the signature contained in the object
        let (bytes_r, bytes_s) = signature.split_at(key_length);

        let r = BigNum::from_slice(bytes_r).map_err(CoseError::SignatureError)?;
        let s = BigNum::from_slice(bytes_s).map_err(CoseError::SignatureError)?;

        let sig = EcdsaSig::from_private_components(r, s).map_err(CoseError::SignatureError)?;
        sig.verify(digest, &key).map_err(CoseError::SignatureError)
    }
}

impl<T> SigningPrivateKey for PKey<T>
where
    T: HasPrivate,
{
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        self.as_ref().sign(digest)
    }
}

impl<T> SigningPrivateKey for PKeyRef<T>
where
    T: HasPrivate,
{
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        let key = self.ec_key().map_err(|_| {
            CoseError::UnsupportedError("Non-EC keys are not yet supported".to_string())
        })?;

        let curve_name = key.group().curve_name().ok_or_else(|| {
            CoseError::UnsupportedError("Anonymous EC keys are not supported".to_string())
        })?;

        let (_, _, key_length) = ec_curve_to_parameters(curve_name)?;

        // The spec defines the signature as:
        // Signature = I2OSP(R, n) | I2OSP(S, n), where n = ceiling(key_length / 8)
        // The Signer interface doesn't provide this, so this will use EcdsaSig interface instead
        // and concatenate R and S.
        // See https://tools.ietf.org/html/rfc8017#section-4.1 for details.
        let signature = EcdsaSig::sign(digest, &key).map_err(CoseError::SignatureError)?;
        let bytes_r = signature.r().to_vec();
        let bytes_s = signature.s().to_vec();

        Ok(super::merge_ec_signature(&bytes_r, &bytes_s, key_length))
    }
}
