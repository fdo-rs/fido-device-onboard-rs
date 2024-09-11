mod sys;
#[macro_use]
mod utils;
use utils::{cvt, cvt_p};

use crate::{KdfArgument, KdfError, KdfType};

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
            KbSeed(_) => {}
            R(_) => return false,
            UseSeparator(_) => return false,
            UseL(_) => return false,
            LBits(_) => return false,
            Mac(_) => {}
            KbMode(_) => {}
        }
    }

    true
}

fn perform<'a>(
    type_: crate::KdfType,
    args: &[&'a KdfArgument],
    length: usize,
) -> core::result::Result<Vec<u8>, KdfError> {
    let mut kdf = Kdf::new(type_)?;

    for arg in args {
        match arg {
            KdfArgument::Key(key) => {
                kdf.set_key(key)?;
            }
            KdfArgument::Salt(salt) => {
                kdf.set_salt(salt)?;
            }
            KdfArgument::KbInfo(kb_info) => {
                kdf.set_kb_info(kb_info)?;
            }
            KdfArgument::KbSeed(kb_seed) => {
                kdf.set_kb_seed(kb_seed)?;
            }
            KdfArgument::KbMode(mode) => {
                kdf.set_kb_mode((*mode).into())?;
            }
            KdfArgument::Mac(mac) => {
                kdf.set_kb_mac_type((*mac).into())?;
                if mac.has_md() {
                    kdf.set_digest(*mac.get_md().unwrap())?;
                }
                if mac.has_cipher() {
                    kdf.set_cipher(*mac.get_cipher().unwrap())?;
                }
            }
            KdfArgument::R(_) => {
                return Err(KdfError::UnsupportedOption("R".to_string()));
            }
            KdfArgument::UseSeparator(_) => {
                return Err(KdfError::UnsupportedOption("UseSeparator".to_string()));
            }
            KdfArgument::UseL(_) => {
                return Err(KdfError::UnsupportedOption("UseL".to_string()));
            }
            KdfArgument::LBits(_) => {
                return Err(KdfError::UnsupportedOption("LBits".to_string()));
            }
        }
    }

    kdf.derive(length).map_err(KdfError::from)
}

use openssl::{hash::MessageDigest, symm::Cipher};

type Result<T> = core::result::Result<T, openssl::error::ErrorStack>;

foreign_type_and_impl_send_sync! {
    type CType = sys::KDF;
    fn drop = sys::EVP_KDF_CTX_free;

    pub struct Kdf;

    pub struct KdfRef;
}

#[allow(unused)]
#[derive(Debug)]
#[repr(i32)]
enum KdfControlOption {
    SetPass = 0x01,
    SetSalt = 0x02,
    SetIter = 0x03,
    SetMd = 0x04,
    SetKey = 0x05,
    SetMaxmemBytes = 0x06,
    SetTlsSecret = 0x07,
    ResetTlsSeed = 0x08,
    AddTlsSeed = 0x09,
    ResetHkdfInfo = 0x0a,
    AddHkdfInfo = 0x0b,
    SetHkdfMode = 0x0c,
    SetScryptN = 0x0d,
    SetScryptR = 0x0e,
    SetScryptP = 0x0f,
    SetSshkdfXcghash = 0x10,
    SetSshkdfSessionId = 0x11,
    SetSshkdfType = 0x12,
    SetKbMode = 0x13,
    SetKbMacType = 0x14,
    SetCipher = 0x15,
    SetKbInfo = 0x16,
    SetKbSeed = 0x17,
    SetKrb5kdfConstant = 0x18,
    SetSskdfInfo = 0x19,
}

#[derive(Debug)]
#[repr(i32)]
enum KdfKbMode {
    Counter = 0,
    Feedback = 1,
}

impl From<crate::KdfKbMode> for KdfKbMode {
    fn from(mode: crate::KdfKbMode) -> Self {
        match mode {
            crate::KdfKbMode::Counter => KdfKbMode::Counter,
            crate::KdfKbMode::Feedback => KdfKbMode::Feedback,
        }
    }
}

impl KdfType {
    fn type_id(&self) -> i32 {
        match self {
            KdfType::KeyBased => 1204,
        }
    }
}

#[derive(Debug)]
#[repr(i32)]
enum KdfMacType {
    Hmac = 0,
    Cmac = 1,
}

impl From<crate::KdfMacType> for KdfMacType {
    fn from(value: crate::KdfMacType) -> Self {
        match value {
            crate::KdfMacType::Hmac(_) => KdfMacType::Hmac,
            crate::KdfMacType::Cmac(_) => KdfMacType::Cmac,
        }
    }
}

impl Kdf {
    fn new(type_: KdfType) -> Result<Self> {
        unsafe {
            let kdf = Kdf::from_ptr(cvt_p(sys::EVP_KDF_CTX_new_id(type_.type_id()))?);
            Ok(kdf)
        }
    }

    #[allow(unused)]
    fn reset(&mut self) {
        unsafe { sys::EVP_KDF_reset(self.as_ptr()) }
    }

    fn set_kb_mode(&mut self, mode: KdfKbMode) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKbMode as i32,
                mode as i32,
            ))
        }
    }

    fn set_kb_mac_type(&mut self, mac_type: KdfMacType) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKbMacType as i32,
                mac_type as i32,
            ))
        }
    }

    fn set_salt(&mut self, salt: &[u8]) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetSalt as i32,
                salt.as_ptr(),
                salt.len(),
            ))
        }
    }

    fn set_kb_info(&mut self, context: &[u8]) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKbInfo as i32,
                context.as_ptr(),
                context.len(),
            ))
        }
    }

    fn set_kb_seed(&mut self, kb_seed: &[u8]) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKbSeed as i32,
                kb_seed.as_ptr(),
                kb_seed.len(),
            ))
        }
    }

    fn set_key(&mut self, key: &[u8]) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKey as i32,
                key.as_ptr(),
                key.len(),
            ))
        }
    }

    fn set_cipher(&mut self, cipher: Cipher) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetCipher as i32,
                cipher.as_ptr(),
            ))
        }
    }

    fn set_digest(&mut self, digest: MessageDigest) -> Result<i32> {
        unsafe {
            cvt(sys::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetMd as i32,
                digest.as_ptr(),
            ))
        }
    }

    fn derive(&mut self, key_len: usize) -> Result<Vec<u8>> {
        unsafe {
            let mut key_out: Vec<u8> = vec![0; key_len];
            cvt(sys::EVP_KDF_derive(
                self.as_ptr(),
                key_out.as_mut_ptr(),
                key_len,
            ))?;
            Ok(key_out)
        }
    }
}
