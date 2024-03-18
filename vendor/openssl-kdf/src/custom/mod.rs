use openssl::{hash::MessageDigest, nid::Nid, pkey::PKey, sign::Signer, symm::Cipher};

use crate::{KdfArgument, KdfError, KdfKbMode, KdfMacType, KdfType};

fn get_digest_length_bytes(digest_method: MessageDigest) -> Result<usize, KdfError> {
    match digest_method.type_() {
        Nid::SHA1 => Ok(20),
        Nid::SHA224 => Ok(28),
        Nid::SHA256 => Ok(32),
        Nid::SHA384 => Ok(48),
        Nid::SHA512 => Ok(64),
        _ => Err(KdfError::Unimplemented("Invalid digest method")),
    }
}

fn get_cipher_length_bytes(cipher: Cipher) -> Result<usize, KdfError> {
    match cipher.nid() {
        Nid::AES_128_CBC => Ok(16),
        Nid::AES_192_CBC => Ok(16),
        Nid::AES_256_CBC => Ok(16),
        _ => Err(KdfError::Unimplemented("Invalid cipher")),
    }
}

pub(crate) const IMPLEMENTATION: crate::Implementation = crate::Implementation {
    supports_args: &supports_args,
    func: &perform,
};

fn supports_args<'a>(args: &[&'a KdfArgument]) -> bool {
    use crate::KdfArgument::*;
    for arg in args {
        match arg {
            Key(_) => {}
            Salt(_) => {}
            KbInfo(_) => {}
            R(_) => {}
            UseSeparator(_) => {}
            UseL(_) => {}
            LBits(_) => {}
            Mac(mac) => match mac {
                KdfMacType::Hmac(mac) => match get_digest_length_bytes(*mac) {
                    Ok(_) => {}
                    Err(_) => return false,
                },
                KdfMacType::Cmac(cipher) => match get_cipher_length_bytes(*cipher) {
                    Ok(_) => {}
                    Err(_) => return false,
                },
            },
            KbMode(mode) => match mode {
                KdfKbMode::Counter => {}
                KdfKbMode::Feedback => return false,
            },
            KbSeed(_) => return false,
        }
    }

    true
}

fn perform<'a>(
    type_: crate::KdfType,
    args: &[&'a KdfArgument],
    length: usize,
) -> Result<Vec<u8>, KdfError> {
    #[cfg(feature = "warn_custom")]
    eprintln!("Using custom KDF");

    if !matches!(type_, KdfType::KeyBased) {
        return Err(KdfError::Unimplemented("Non-keybased KDF"));
    }

    let mut use_separator = true;
    let mut use_l = true;
    let mut r: u64 = 32;
    let mut lbits: u8 = 32;
    let mut key: Option<&'a [u8]> = None;
    let mut label: Option<&'a [u8]> = None;
    let mut context: Option<&'a [u8]> = None;
    let mut h: Option<usize> = None;

    let mut prf: Option<
        Box<
            dyn Fn(
                &[u8],
            ) -> Result<
                Box<dyn Fn(&[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack>>,
                openssl::error::ErrorStack,
            >,
        >,
    > = None;

    for arg in args {
        match arg {
            KdfArgument::Key(new_key) => {
                key = Some(new_key);
            }
            KdfArgument::Salt(new_salt) => {
                label = Some(new_salt);
            }
            KdfArgument::KbInfo(new_kb_info) => {
                context = Some(new_kb_info);
            }
            KdfArgument::R(new_r) => {
                r = *new_r as u64;
            }
            KdfArgument::LBits(new_lbits) => {
                lbits = *new_lbits;
            }
            KdfArgument::UseL(new_use_l) => {
                use_l = *new_use_l;
            }
            KdfArgument::UseSeparator(new_use_separator) => {
                use_separator = *new_use_separator;
            }
            KdfArgument::Mac(mac) => match mac {
                KdfMacType::Hmac(md) => {
                    h = Some(get_digest_length_bytes(*md)? * 8);
                    prf = Some(Box::new(move |key| {
                        let hmac_key = PKey::hmac(key)?;
                        Ok(Box::new(move |input| {
                            let mut signer = Signer::new(*md, &hmac_key)?;
                            signer.update(input)?;
                            signer.sign_to_vec()
                        }))
                    }));
                }
                KdfMacType::Cmac(cipher) => {
                    h = Some(get_cipher_length_bytes(*cipher)? * 8);
                    prf = Some(Box::new(move |key| {
                        let cmac_key = PKey::cmac(cipher, key)?;
                        Ok(Box::new(move |input| {
                            let mut signer = Signer::new_without_digest(&cmac_key)?;
                            signer.update(input)?;
                            signer.sign_to_vec()
                        }))
                    }));
                }
            },
            KdfArgument::KbMode(mode) => match mode {
                KdfKbMode::Counter => {}
                KdfKbMode::Feedback => {
                    return Err(KdfError::Unimplemented("Feedback mode"));
                }
            },
            KdfArgument::KbSeed(_) => {
                return Err(KdfError::Unimplemented("KB-Seed"));
            }
        }
    }

    let key = key.ok_or(KdfError::MissingArgument("Key"))?;
    let prf = prf.ok_or(KdfError::MissingArgument("Mac"))?;
    let h = h.ok_or(KdfError::MissingArgument("h"))?;

    let n = ((length * 8) as f32 / h as f32).ceil() as u64;

    if n > ((2 ^ r) - 1) {
        return Err(KdfError::InvalidOption("length too long for r"));
    }
    // This is the place where to start in the counter buffer (which is always be u64)
    let start_pos: usize = 8 - (r / 8) as usize;

    let lstart = ((64 - lbits) / 8) as usize;
    let l2 = &((length * 8) as u64).to_be_bytes()[lstart..];

    let mut output = Vec::new();

    let prf = prf(key)?;

    for i in 1..=n {
        let mut block = Vec::new();

        block.extend_from_slice(&i.to_be_bytes()[start_pos..]);
        if let Some(label) = label {
            block.extend_from_slice(label);
        }
        if use_separator {
            block.extend_from_slice(&[00]);
        }
        if let Some(context) = context {
            block.extend_from_slice(context);
        }
        if use_l {
            block.extend_from_slice(l2);
        }

        output.extend_from_slice(&prf(&block)?);
    }

    output.truncate(length);
    Ok(output)
}
