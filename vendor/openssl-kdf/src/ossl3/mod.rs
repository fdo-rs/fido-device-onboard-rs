use std::ffi::{CStr, CString};

use libc::c_char;

use crate::{KdfArgument, KdfError};

mod params;
mod sys;
mod utils;

use params::ParamsBuilder;
use utils::{cvt, cvt_cp, cvt_p};

impl crate::KdfKbMode {
    fn to_param(&self) -> &'static [u8] {
        use crate::KdfKbMode::*;
        match self {
            Counter => b"counter\0",
            Feedback => b"feedback\0",
        }
    }
}

impl crate::KdfMacType {
    fn to_param(&self) -> &'static [u8] {
        use crate::KdfMacType::*;
        match self {
            Hmac(_) => b"HMAC\0",
            Cmac(_) => b"CMAC\0",
        }
    }
}

impl crate::KdfType {
    fn to_name(&self) -> CString {
        use crate::KdfType::*;
        match self {
            KeyBased => CString::new("KBKDF").unwrap(),
        }
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
            KbSeed(_) => {}
            R(_) => {
                #[cfg(not(ossl3_supported = "kbkdf_r"))]
                return false;
            }
            UseSeparator(_) => {}
            UseL(_) => {}
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
) -> Result<Vec<u8>, KdfError> {
    let mut builder = ParamsBuilder::with_capacity(args.len());

    for arg in args {
        match arg {
            KdfArgument::Key(key) => builder.add_slice(sys::OSSL_KDF_PARAM_KEY, key)?,
            KdfArgument::Salt(salt) => builder.add_slice(sys::OSSL_KDF_PARAM_SALT, salt)?,
            KdfArgument::KbInfo(kbinfo) => builder.add_slice(sys::OSSL_KDF_PARAM_INFO, kbinfo)?,
            KdfArgument::KbSeed(kbseed) => builder.add_slice(sys::OSSL_KDF_PARAM_SEED, kbseed)?,
            KdfArgument::R(r) => {
                builder.add_i32(sys::OSSL_KDF_PARAM_KBKDF_R, *r as i32)?;
            }
            KdfArgument::UseSeparator(use_separator) => builder.add_i32(
                sys::OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR,
                if *use_separator { 1 } else { 0 },
            )?,
            KdfArgument::UseL(use_l) => {
                builder.add_i32(sys::OSSL_KDF_PARAM_KBKDF_USE_L, if *use_l { 1 } else { 0 })?
            }
            KdfArgument::Mac(mac_type) => {
                builder.add_string(sys::OSSL_KDF_PARAM_MAC, mac_type.to_param())?;
                match mac_type {
                    crate::KdfMacType::Hmac(md) => {
                        let md_name = unsafe { cvt_cp(sys::EVP_MD_get0_name(md.as_ptr())) }?;
                        let md_name = unsafe { CStr::from_ptr(md_name) };
                        builder
                            .add_string(sys::OSSL_KDF_PARAM_DIGEST, md_name.to_bytes_with_nul())?;
                    }
                    crate::KdfMacType::Cmac(cipher) => {
                        let cipher_name =
                            unsafe { cvt_cp(sys::EVP_CIPHER_get0_name(cipher.as_ptr())) }?;
                        let cipher_name = unsafe { CStr::from_ptr(cipher_name) };
                        builder.add_string(
                            sys::OSSL_KDF_PARAM_CIPHER,
                            cipher_name.to_bytes_with_nul(),
                        )?;
                    }
                }
            }
            KdfArgument::KbMode(kb_mode) => {
                builder.add_string(sys::OSSL_KDF_PARAM_MODE, kb_mode.to_param())?
            }
            KdfArgument::LBits(_) => {
                return Err(KdfError::UnsupportedOption("LBits".to_string()));
            }
        }
    }
    let mut params = builder.build();

    let name = type_.to_name();
    let name = name.as_bytes_with_nul();
    let kdf_ptr = unsafe {
        let ptr = sys::EVP_KDF_fetch(
            std::ptr::null_mut(),
            name.as_ptr() as *const c_char,
            std::ptr::null(),
        );
        if ptr.is_null() {
            Err(KdfError::UnsupportedOption("No such KDF".to_string()))
        } else {
            Ok(ptr)
        }
    }?;

    let mut output = vec![0; length];

    let mut ctx = KDFContext::new(kdf_ptr)?;
    ctx.check_all_parameters(&params)?;
    unsafe {
        cvt(sys::EVP_KDF_derive(
            ctx.as_mut_ptr(),
            output.as_mut_ptr(),
            output.len(),
            params.as_ptr(),
        ))?
    };
    drop(params);

    Ok(output)
}

const DUBIOUS_PARAMS: &[&str] = &["r"];

struct KDFContext {
    kdf: *mut sys::EVP_KDF,
    ctx: *mut sys::EVP_KDF_CTX,
}

const MAX_NUMBER_OF_PARAMS: usize = 42;

impl KDFContext {
    fn new(kdf: *mut sys::EVP_KDF) -> Result<Self, KdfError> {
        let ctx = unsafe { cvt_p(sys::EVP_KDF_CTX_new(kdf))? };
        Ok(KDFContext { kdf, ctx })
    }

    fn check_all_parameters(&self, params: &params::Params) -> Result<(), KdfError> {
        let mut dubious_params = Vec::new();

        for param_name in params.names() {
            if DUBIOUS_PARAMS.contains(&param_name.as_ref()) {
                dubious_params.push(param_name);
            }
        }

        if !dubious_params.is_empty() {
            let supported_params = unsafe { cvt_cp(sys::EVP_KDF_CTX_settable_params(self.ctx)) }?;

            // WARNING: the length of the slice isn't actually checked at this point.
            // This is actually okay, because we know to stop at the first occurence of the
            // terminator (all-null)
            let all_params = unsafe {
                std::slice::from_raw_parts(
                    supported_params as *mut sys::OSSL_PARAM,
                    MAX_NUMBER_OF_PARAMS,
                )
            };
            for i in 0..MAX_NUMBER_OF_PARAMS {
                let supported_param = &all_params[i];
                if supported_param.data_type == 0 {
                    break;
                }
                let name = unsafe { CStr::from_ptr(supported_param.key) };
                let name = name.to_str().unwrap();
                dubious_params.retain(|x| x != name);
            }
        }

        if !dubious_params.is_empty() {
            return Err(KdfError::UnsupportedOption(format!(
                "Not supported options: {}",
                dubious_params.join(", ")
            )));
        }

        Ok(())
    }
}

impl KDFContext {
    fn as_mut_ptr(&mut self) -> *mut sys::EVP_KDF_CTX {
        self.ctx
    }
}

impl Drop for KDFContext {
    fn drop(&mut self) {
        unsafe { sys::EVP_KDF_CTX_free(self.ctx) };
        unsafe { sys::EVP_KDF_free(self.kdf) };
    }
}
