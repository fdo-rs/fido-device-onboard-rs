//! COSE Encryption

use openssl::rand::rand_bytes;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use serde::{ser::SerializeSeq, Deserialize, Serialize, Serializer};
use serde_bytes::ByteBuf;
use serde_cbor::Error as CborError;
use serde_cbor::Value as CborValue;

use crate::error::CoseError;
use crate::header_map::{map_to_empty_or_serialized, HeaderMap};

const KTY: i8 = 1;
const IV: i8 = 5;

/// Holds the cipher configuration to be used
pub enum CipherConfiguration {
    /// AES-GCM mode, key length is derived from the key
    Gcm,
}

impl CipherConfiguration {
    fn cose_alg(&self, key: &[u8]) -> Option<COSEAlgorithm> {
        Some(match self {
            CipherConfiguration::Gcm => match key.len() {
                16 => COSEAlgorithm::AesGcm96_128_128,
                24 => COSEAlgorithm::AesGcm96_128_192,
                32 => COSEAlgorithm::AesGcm96_128_256,
                _ => return None,
            },
        })
    }
}

enum COSEAlgorithm {
    /// AES-GCM mode w/ 128-bit key, 128-bit tag
    AesGcm96_128_128,
    /// AES-GCM mode w/ 192-bit key, 128-bit tag
    AesGcm96_128_192,
    /// AES-GCM mode w/ 256-bit key, 128-bit tag
    AesGcm96_128_256,
}

impl COSEAlgorithm {
    fn value(&self) -> usize {
        match self {
            COSEAlgorithm::AesGcm96_128_128 => 1,
            COSEAlgorithm::AesGcm96_128_192 => 2,
            COSEAlgorithm::AesGcm96_128_256 => 3,
        }
    }

    fn from_value(value: i8) -> Option<COSEAlgorithm> {
        Some(match value {
            1 => COSEAlgorithm::AesGcm96_128_128,
            2 => COSEAlgorithm::AesGcm96_128_192,
            3 => COSEAlgorithm::AesGcm96_128_256,
            _ => return None,
        })
    }

    // Returns the tag size for the given algorithm in bytes.
    fn tag_size(&self) -> usize {
        match self {
            COSEAlgorithm::AesGcm96_128_128 => 16,
            COSEAlgorithm::AesGcm96_128_192 => 16,
            COSEAlgorithm::AesGcm96_128_256 => 16,
        }
    }

    fn openssl_cipher(&self) -> Cipher {
        match self {
            COSEAlgorithm::AesGcm96_128_128 => Cipher::aes_128_gcm(),
            COSEAlgorithm::AesGcm96_128_192 => Cipher::aes_192_gcm(),
            COSEAlgorithm::AesGcm96_128_256 => Cipher::aes_256_gcm(),
        }
    }
}

///  Implementation of the Enc_structure structure as defined in
///  [RFC8152](https://tools.ietf.org/html/rfc8152#section-5.3).
///
///  The encryption algorithm for AEAD algorithms is fairly simple.  The
///  first step is to create a consistent byte stream for the
///  authenticated data structure.  For this purpose, we use an
///  Enc_structure.  The Enc_structure is a CBOR array.  The fields of the
///  Enc_structure in order are:
///
///  1.  A text string identifying the context of the authenticated data
///      structure.  The context string is:
///
///         "Encrypt0" for the content encryption of a COSE_Encrypt0 data
///         structure.
///
///         "Encrypt" for the first layer of a COSE_Encrypt data structure
///         (i.e., for content encryption).
///
///         "Enc_Recipient" for a recipient encoding to be placed in an
///         COSE_Encrypt data structure.
///
///         "Mac_Recipient" for a recipient encoding to be placed in a
///         MACed message structure.
///
///         "Rec_Recipient" for a recipient encoding to be placed in a
///         recipient structure.
///
///  2.  The protected attributes from the body structure encoded in a
///      bstr type.  If there are no protected attributes, a bstr of
///      length zero is used.
///
///  3.  The protected attributes from the application encoded in a bstr
///      type.  If this field is not supplied, it defaults to a zero-
///      length bstr.  (See Section 4.3 for application guidance on
///      constructing this field.)
///
///  The CDDL fragment that describes the above text is:
///
///  Enc_structure = [
///      context : "Encrypt" / "Encrypt0" / "Enc_Recipient" /
///          "Mac_Recipient" / "Rec_Recipient",
///      protected : empty_or_serialized_map,
///      external_aad : bstr
///  ]
#[derive(Debug, Clone, Deserialize)]
struct EncStructure {
    /// context: "Encrypt0" / "Encrypt" / "Enc_Recipient" / "Mac_Recipient" / "Rec_Recipient"
    context: String,
    /// protected : empty_or_serialized_map,
    protected: ByteBuf,
    /// external_aad : bstr,
    external_aad: ByteBuf,
}

impl Serialize for EncStructure {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(3))?;
        seq.serialize_element(&self.context)?;
        seq.serialize_element(&self.protected)?;
        seq.serialize_element(&self.external_aad)?;
        seq.end()
    }
}

impl EncStructure {
    fn new_encrypt0(protected: &[u8]) -> Result<Self, CborError> {
        Ok(EncStructure {
            context: String::from("Encrypt0"),
            protected: ByteBuf::from(protected.to_vec()),
            external_aad: ByteBuf::new(),
        })
    }

    /// Serializes the EncStructure to . We don't care about deserialization, since
    /// both sides are supposed to compute the EncStructure and compare.
    fn as_bytes(&self) -> Result<Vec<u8>, CborError> {
        serde_cbor::to_vec(self)
    }
}

///  Implementation of the COSE_Encrypt0 structure as defined in
///  [RFC8152](https://tools.ietf.org/html/rfc8152#section-5.2).
///
///  The COSE_Encrypt0 encrypted structure does not have the ability to
///  specify recipients of the message.  The structure assumes that the
///  recipient of the object will already know the identity of the key to
///  be used in order to decrypt the message.  If a key needs to be
///  identified to the recipient, the enveloped structure ought to be
///  used.
///
///  The COSE_Encrypt0 structure can be encoded as either tagged or
///  untagged depending on the context it will be used in.  A tagged
///  COSE_Encrypt0 structure is identified by the CBOR tag 16.  The CDDL
///  fragment that represents this is:
///
///  COSE_Encrypt0_Tagged = #6.16(COSE_Encrypt0)
///
///  The COSE_Encrypt0 structure is a CBOR array.  The fields of the array in
///  order are:
///
///  protected:  This is as described in Section 3.
///
///  unprotected:  This is as described in Section 3.
///
///  ciphertext:  This is as described in Section 5.1.
///
///  The CDDL fragment that represents the above text for COSE_Encrypt0
///  follows.
///
///  COSE_Encrypt0 = [
///      Headers,
///      ciphertext : bstr / nil,
///  ]
#[derive(Debug, Clone, Deserialize)]
pub struct CoseEncrypt0 {
    /// protected: empty_or_serialized_map,
    protected: ByteBuf,
    /// unprotected: HeaderMap
    unprotected: HeaderMap,
    /// ciphertext: bstr
    /// The spec allows ciphertext to be nil and transported separately, but it's not useful at the
    /// moment, so this is just a ByteBuf for simplicity.
    ciphertext: ByteBuf,
}

impl Serialize for CoseEncrypt0 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(3))?;
        seq.serialize_element(&self.protected)?;
        seq.serialize_element(&self.unprotected)?;
        seq.serialize_element(&self.ciphertext)?;
        seq.end()
    }
}

impl CoseEncrypt0 {
    /// Creates a new instance of the COSE_Encrypt0 structure and encrypts the provided payload.
    /// https://datatracker.ietf.org/doc/html/rfc8152#section-5.3
    pub fn new(
        payload: &[u8],
        cipher_config: CipherConfiguration,
        key: &[u8],
    ) -> Result<Self, CoseError> {
        let cose_alg = match cipher_config.cose_alg(key) {
            Some(v) => v,
            None => {
                return Err(CoseError::UnsupportedError(
                    "Unsupported encryption algorithm".to_string(),
                ))
            }
        };
        let cipher = cose_alg.openssl_cipher();
        let mut iv = vec![0; cipher.iv_len().unwrap()];
        rand_bytes(&mut iv).unwrap();

        let cose_alg_value = cose_alg.value();
        let mut protected = HeaderMap::new();
        protected.insert(KTY.into(), CborValue::Integer(cose_alg_value as i128));
        let mut unprotected = HeaderMap::new();
        unprotected.insert(IV.into(), CborValue::Bytes(iv.to_owned()));

        let protected_bytes =
            map_to_empty_or_serialized(&protected).map_err(CoseError::SerializationError)?;

        let enc_structure =
            EncStructure::new_encrypt0(&protected_bytes).map_err(CoseError::SerializationError)?;

        let mut tag = vec![0; cose_alg.tag_size()];
        let mut ciphertext = encrypt_aead(
            cipher,
            key,
            Some(&iv[..]),
            &enc_structure
                .as_bytes()
                .map_err(CoseError::SerializationError)?,
            payload,
            &mut tag,
        )
        .map_err(CoseError::EncryptionError)?;

        ciphertext.append(&mut tag);

        Ok(CoseEncrypt0 {
            protected: ByteBuf::from(protected_bytes),
            unprotected,
            ciphertext: ByteBuf::from(ciphertext),
        })
    }

    /// Decrypt the ciphertext in the COSE_Encrypt0 structure and returns both
    /// the protected and unprotected HeaderMap(s).
    /// https://datatracker.ietf.org/doc/html/rfc8152#section-5.3
    pub fn decrypt(&self, key: &[u8]) -> Result<(HeaderMap, &HeaderMap, Vec<u8>), CoseError> {
        let protected: HeaderMap =
            HeaderMap::from_bytes(&self.protected).map_err(CoseError::SerializationError)?;

        let protected_enc_alg = match protected.get(&CborValue::Integer(1)) {
            Some(CborValue::Integer(val)) => val,
            _ => {
                return Err(CoseError::SpecificationError(
                    "Protected Header contains invalid Encryption Algorithm specification"
                        .to_string(),
                ))
            }
        };

        let cose_alg = match COSEAlgorithm::from_value(*protected_enc_alg as i8) {
            Some(v) => v,
            None => {
                return Err(CoseError::UnsupportedError(
                    "Unsupported encryption algorithm".to_string(),
                ))
            }
        };

        let protected_bytes =
            map_to_empty_or_serialized(&protected).map_err(CoseError::SerializationError)?;

        let enc_structure =
            EncStructure::new_encrypt0(&protected_bytes).map_err(CoseError::SerializationError)?;

        let iv = match self.unprotected.get(&CborValue::Integer(5)) {
            Some(CborValue::Bytes(val)) => val,
            _ => {
                return Err(CoseError::SpecificationError(
                    "Unprotected Header contains invalid IV specification".to_string(),
                ))
            }
        };

        let (ciphertext, tag) = self
            .ciphertext
            .split_at(self.ciphertext.len() - cose_alg.tag_size());

        let payload = decrypt_aead(
            cose_alg.openssl_cipher(),
            key,
            Some(iv),
            &enc_structure
                .as_bytes()
                .map_err(CoseError::SerializationError)?,
            ciphertext,
            tag,
        )
        .map_err(CoseError::EncryptionError)?;

        Ok((protected, &self.unprotected, payload))
    }

    /// Serializes the structure for transport / storage. If `tagged` is true, the optional #6.16
    /// tag is added to the output.
    pub fn as_bytes(&self, tagged: bool) -> Result<Vec<u8>, CoseError> {
        let bytes = if tagged {
            serde_cbor::to_vec(&serde_cbor::tags::Tagged::new(Some(16), &self))
        } else {
            serde_cbor::to_vec(&self)
        };
        bytes.map_err(CoseError::SerializationError)
    }

    /// This function deserializes the structure, but doesn't check the contents for correctness
    /// at all. Accepts untagged structures or structures with tag 16.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoseError> {
        let coseencrypt0: serde_cbor::tags::Tagged<Self> =
            serde_cbor::from_slice(bytes).map_err(CoseError::SerializationError)?;

        match coseencrypt0.tag {
            None | Some(16) => (),
            Some(tag) => return Err(CoseError::TagError(Some(tag))),
        }
        let protected = coseencrypt0.value.protected.as_slice();
        let _: HeaderMap =
            serde_cbor::from_slice(protected).map_err(CoseError::SerializationError)?;
        Ok(coseencrypt0.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let plaintext = b"\x12\x34\x56\x78\x90\x12\x34\x56\x12\x34\x56\x78\x90\x12\x34\x56";
        let cencrypt0 = CoseEncrypt0::new(plaintext, CipherConfiguration::Gcm, key).unwrap();
        let (_, _, dec) = cencrypt0.decrypt(key).unwrap();
        assert_eq!(dec, plaintext);
        assert_ne!(
            plaintext.to_vec(),
            serde_cbor::to_vec(&cencrypt0.ciphertext).unwrap()
        );
        let fromb = CoseEncrypt0::from_bytes(&cencrypt0.as_bytes(true).unwrap()[..]).unwrap();
        let (_, _, dec) = fromb.decrypt(key).unwrap();
        assert_eq!(dec, plaintext);
        assert_ne!(
            plaintext.to_vec(),
            serde_cbor::to_vec(&fromb.ciphertext).unwrap()
        );
    }

    #[test]
    fn test_encrypt_unsupported_alg() {
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x56\x56";
        let plaintext = b"\x12\x34\x56\x78\x90\x12\x34\x56\x12\x34\x56\x78\x90\x12\x34\x56";
        let cencrypt0 = CoseEncrypt0::new(plaintext, CipherConfiguration::Gcm, key);
        match cencrypt0.unwrap_err() {
            CoseError::UnsupportedError(_) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_decrypt_invalid_alg_spec() {
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let plaintext = b"\x12\x34\x56\x78\x90\x12\x34\x56\x12\x34\x56\x78\x90\x12\x34\x56";
        let mut cencrypt0 = CoseEncrypt0::new(plaintext, CipherConfiguration::Gcm, key).unwrap();
        let mut protected = HeaderMap::new();
        protected.insert(KTY.into(), CborValue::Text("invalid".to_string()));
        let protected_bytes = map_to_empty_or_serialized(&protected)
            .map_err(CoseError::SerializationError)
            .unwrap();
        cencrypt0.protected = ByteBuf::from(protected_bytes);
        match cencrypt0.decrypt(key).unwrap_err() {
            CoseError::SpecificationError(_) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_decrypt_unsupported_openssl_cipher() {
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let plaintext = b"\x12\x34\x56\x78\x90\x12\x34\x56\x12\x34\x56\x78\x90\x12\x34\x56";
        let mut cencrypt0 = CoseEncrypt0::new(plaintext, CipherConfiguration::Gcm, key).unwrap();
        let mut protected = HeaderMap::new();
        protected.insert(KTY.into(), CborValue::Integer(42));
        let protected_bytes = map_to_empty_or_serialized(&protected)
            .map_err(CoseError::SerializationError)
            .unwrap();
        cencrypt0.protected = ByteBuf::from(protected_bytes);
        match cencrypt0.decrypt(key).unwrap_err() {
            CoseError::UnsupportedError(_) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_decrypt_invalid_iv() {
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let plaintext = b"\x12\x34\x56\x78\x90\x12\x34\x56\x12\x34\x56\x78\x90\x12\x34\x56";
        let mut cencrypt0 = CoseEncrypt0::new(plaintext, CipherConfiguration::Gcm, key).unwrap();
        let mut unprotected = HeaderMap::new();
        unprotected.insert(IV.into(), CborValue::Integer(42));
        cencrypt0.unprotected = unprotected;
        match cencrypt0.decrypt(key).unwrap_err() {
            CoseError::SpecificationError(_) => (),
            _ => panic!(),
        }
    }
}
