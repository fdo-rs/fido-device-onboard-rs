// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::ptr;

use crate::{consts::flags::CryptActivate, device::CryptDevice, err::LibcryptErr};

use libc::{c_char, c_int, c_uint, c_void};

/// Type representing the token status. This type wraps the `CRYPT_TOKEN_*` values and the optional corresponding token type as a string.
pub enum CryptTokenInfo {
    /// Token invalid
    Invalid,
    /// Token is free (empty)
    Inactive,
    /// Active internal token with driver
    Internal(String),
    /// Active internal token (reserved name) with missing token driver
    InternalUnknown(String),
    /// Active external (user defined) token with driver
    External(String),
    /// Active external (user defined) token with missing token driver
    ExternalUnknown(String),
}

impl CryptTokenInfo {
    /// Convert a token status code into `CryptTokenInfo`
    pub fn from_status(code: c_uint, type_: Option<String>) -> Result<Self, LibcryptErr> {
        Ok(match code {
            libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INVALID => CryptTokenInfo::Invalid,
            libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INACTIVE => CryptTokenInfo::Inactive,
            libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INTERNAL => {
                CryptTokenInfo::Internal(type_.ok_or(LibcryptErr::InvalidConversion)?)
            }
            libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INTERNAL_UNKNOWN => {
                CryptTokenInfo::InternalUnknown(type_.ok_or(LibcryptErr::InvalidConversion)?)
            }
            libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_EXTERNAL => {
                CryptTokenInfo::External(type_.ok_or(LibcryptErr::InvalidConversion)?)
            }
            libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_EXTERNAL_UNKNOWN => {
                CryptTokenInfo::ExternalUnknown(type_.ok_or(LibcryptErr::InvalidConversion)?)
            }
            _ => return Err(LibcryptErr::InvalidConversion),
        })
    }
}

#[allow(clippy::from_over_into)]
impl Into<u32> for CryptTokenInfo {
    fn into(self) -> u32 {
        match self {
            CryptTokenInfo::Invalid => libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INVALID,
            CryptTokenInfo::Inactive => libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INACTIVE,
            CryptTokenInfo::Internal(_) => {
                libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INTERNAL
            }
            CryptTokenInfo::InternalUnknown(_) => {
                libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_INTERNAL_UNKNOWN
            }
            CryptTokenInfo::External(_) => {
                libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_EXTERNAL
            }
            CryptTokenInfo::ExternalUnknown(_) => {
                libcryptsetup_rs_sys::crypt_token_info_CRYPT_TOKEN_EXTERNAL_UNKNOWN
            }
        }
    }
}

/// Token input for `CryptLuks2Token::json_set`
pub enum TokenInput<'a> {
    /// Add a new token to any free slot
    AddToken(&'a serde_json::Value),
    /// Replace the specified token
    ReplaceToken(c_uint, &'a serde_json::Value),
    /// Remove the specified token
    RemoveToken(c_uint),
}

/// Handle for LUKS2 token operations
pub struct CryptLuks2TokenHandle<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptLuks2TokenHandle<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptLuks2TokenHandle { reference }
    }

    /// Get contents of a token in JSON format
    pub fn json_get(&mut self, token: c_uint) -> Result<serde_json::Value, LibcryptErr> {
        let mut ptr: *const c_char = std::ptr::null();
        errno_int_success!(mutex!(libcryptsetup_rs_sys::crypt_token_json_get(
            self.reference.as_ptr(),
            token as c_int,
            &mut ptr as *mut _,
        )))
        .and_then(|_| from_str_ptr!(ptr))
        .and_then(|s| serde_json::from_str(s).map_err(LibcryptErr::JsonError))
    }

    /// Set contents of a token in JSON format
    pub fn json_set(&mut self, input: TokenInput<'_>) -> Result<c_uint, LibcryptErr> {
        let (token, json) = match input {
            TokenInput::AddToken(json) => (libcryptsetup_rs_sys::CRYPT_ANY_TOKEN, Some(json)),
            TokenInput::ReplaceToken(token, json) => (token as i32, Some(json)),
            TokenInput::RemoveToken(token) => (token as i32, None),
        };
        let json_cstring = match json {
            Some(j) => Some(
                serde_json::to_string(j)
                    .map_err(LibcryptErr::JsonError)
                    .and_then(|s| to_cstring!(s))?,
            ),
            None => None,
        };
        errno_int_success!(mutex!(libcryptsetup_rs_sys::crypt_token_json_set(
            self.reference.as_ptr(),
            token,
            json_cstring
                .as_ref()
                .map(|cs| cs.as_ptr())
                .unwrap_or(ptr::null()),
        )))
        .map(|rc| rc as c_uint)
    }

    /// Get the token info for a specific token
    pub fn status(&mut self, token: c_uint) -> Result<CryptTokenInfo, LibcryptErr> {
        let mut ptr: *const c_char = std::ptr::null();
        let code = mutex!(libcryptsetup_rs_sys::crypt_token_status(
            self.reference.as_ptr(),
            token as c_int,
            &mut ptr as *mut _,
        ));
        CryptTokenInfo::from_status(
            code,
            match ptr_to_option!(ptr) {
                Some(p) => Some(from_str_ptr_to_owned!(p)?),
                None => None,
            },
        )
    }

    /// Create new LUKS2 keyring token
    pub fn luks2_keyring_set(
        &mut self,
        token: Option<c_uint>,
        key_description: &str,
    ) -> Result<c_uint, LibcryptErr> {
        let description_cstring = to_cstring!(key_description)?;
        errno_int_success!(mutex!(libcryptsetup_rs_sys::crypt_token_luks2_keyring_set(
            self.reference.as_ptr(),
            token
                .map(|t| t as c_int)
                .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_TOKEN),
            &libcryptsetup_rs_sys::crypt_token_params_luks2_keyring {
                key_description: description_cstring.as_ptr(),
            } as *const _,
        )))
        .map(|rc| rc as c_uint)
    }

    /// Get LUKS2 keyring token description
    pub fn luks2_keyring_get(&mut self, token: c_uint) -> Result<String, LibcryptErr> {
        let mut params = libcryptsetup_rs_sys::crypt_token_params_luks2_keyring {
            key_description: std::ptr::null(),
        };
        errno_int_success!(mutex!(libcryptsetup_rs_sys::crypt_token_luks2_keyring_get(
            self.reference.as_ptr(),
            token as c_int,
            &mut params as *mut _,
        )))
        .and_then(|_| from_str_ptr!(params.key_description).map(|s| s.to_string()))
    }

    /// Assign token to keyslot
    ///
    /// `None` for keyslot assigns all keyslots to the token
    pub fn assign_keyslot(
        &mut self,
        token: c_uint,
        keyslot: Option<c_uint>,
    ) -> Result<(), LibcryptErr> {
        errno_int_success!(mutex!(libcryptsetup_rs_sys::crypt_token_assign_keyslot(
            self.reference.as_ptr(),
            token as c_int,
            keyslot
                .map(|k| k as c_int)
                .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
        )))
        .map(|_| ())
    }

    /// Unassign token from keyslot
    ///
    /// `None` for keyslot unassigns the token from all active keyslots
    pub fn unassign_keyslot(
        &mut self,
        token: c_uint,
        keyslot: Option<c_uint>,
    ) -> Result<(), LibcryptErr> {
        errno_int_success!(mutex!(libcryptsetup_rs_sys::crypt_token_unassign_keyslot(
            self.reference.as_ptr(),
            token as c_int,
            keyslot
                .map(|k| k as c_int)
                .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_SLOT),
        )))
        .map(|_| ())
    }

    /// Check if token is assigned
    #[allow(clippy::wrong_self_convention)]
    pub fn is_assigned(&mut self, token: c_uint, keyslot: c_uint) -> Result<bool, LibcryptErr> {
        let rc = mutex!(libcryptsetup_rs_sys::crypt_token_is_assigned(
            self.reference.as_ptr(),
            token as c_int,
            keyslot as c_int,
        ));
        if rc == 0 {
            Ok(true)
        } else if rc == libc::ENOENT {
            Ok(false)
        } else {
            Err(LibcryptErr::IOError(std::io::Error::from_raw_os_error(-rc)))
        }
    }

    /// Activate device or check key using a token
    pub fn activate_by_token<T>(
        &mut self,
        name: Option<&str>,
        token: Option<c_uint>,
        usrdata: Option<&mut T>,
        flags: CryptActivate,
    ) -> Result<c_uint, LibcryptErr> {
        let name_cstring_option = match name {
            Some(n) => Some(to_cstring!(n)?),
            None => None,
        };
        let usrdata_ptr = match usrdata {
            Some(reference) => (reference as *mut T).cast::<c_void>(),
            None => ptr::null_mut(),
        };
        errno_int_success!(mutex!(libcryptsetup_rs_sys::crypt_activate_by_token(
            self.reference.as_ptr(),
            match name_cstring_option {
                Some(ref s) => s.as_ptr(),
                None => std::ptr::null(),
            },
            token
                .map(|t| t as c_int)
                .unwrap_or(libcryptsetup_rs_sys::CRYPT_ANY_TOKEN),
            usrdata_ptr,
            flags.bits(),
        )))
        .map(|rc| rc as c_uint)
    }
}

/// Register token handler
pub fn register(
    name: &'static str,
    open: libcryptsetup_rs_sys::crypt_token_open_func,
    buffer_free: libcryptsetup_rs_sys::crypt_token_buffer_free_func,
    validate: libcryptsetup_rs_sys::crypt_token_validate_func,
    dump: libcryptsetup_rs_sys::crypt_token_dump_func,
) -> Result<(), LibcryptErr> {
    if name.get(name.len() - 1..) != Some("\0") {
        return Err(LibcryptErr::NoNull(name));
    }
    let handler = libcryptsetup_rs_sys::crypt_token_handler {
        name: name.as_ptr().cast::<c_char>(),
        open,
        buffer_free,
        validate,
        dump,
    };
    errno!(mutex!(libcryptsetup_rs_sys::crypt_token_register(
        &handler as *const libcryptsetup_rs_sys::crypt_token_handler,
    )))
}
