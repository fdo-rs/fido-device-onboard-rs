// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::marker::PhantomData;

use crate::{
    consts::{
        flags::{CryptActivate, CryptRequirement},
        vals::CryptFlagsType,
    },
    device::CryptDevice,
    err::LibcryptErr,
};

/// Handle for LUKS2 persistent flag operations
pub struct CryptLuks2FlagsHandle<'a, T> {
    reference: &'a mut CryptDevice,
    data: PhantomData<T>,
}

impl<'a, T> CryptLuks2FlagsHandle<'a, T> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptLuks2FlagsHandle {
            reference,
            data: PhantomData,
        }
    }
}

impl<'a> CryptLuks2FlagsHandle<'a, CryptActivate> {
    /// Implementation for setting persistent flags for activation
    pub fn persistent_flags_set(&mut self, flags: CryptActivate) -> Result<(), LibcryptErr> {
        errno!(mutex!(libcryptsetup_rs_sys::crypt_persistent_flags_set(
            self.reference.as_ptr(),
            CryptFlagsType::Activation as u32,
            flags.bits(),
        )))
    }

    /// Implementation for getting persistent flags for activation
    pub fn persistent_flags_get(&mut self) -> Result<CryptActivate, LibcryptErr> {
        let mut flags_u32 = 0u32;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_persistent_flags_get(
                self.reference.as_ptr(),
                CryptFlagsType::Activation as u32,
                &mut flags_u32 as *mut _,
            )
        })
        .and_then(|_| CryptActivate::from_bits(flags_u32).ok_or(LibcryptErr::InvalidConversion))
    }
}

impl<'a> CryptLuks2FlagsHandle<'a, CryptRequirement> {
    /// Implementation for setting persistent flags for requirements
    pub fn persistent_flags_set(&mut self, flags: CryptRequirement) -> Result<(), LibcryptErr> {
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_persistent_flags_set(
                self.reference.as_ptr(),
                CryptFlagsType::Requirements as u32,
                flags.bits(),
            )
        })
    }

    /// Implementation for getting persistent flags for requirements
    pub fn persistent_flags_get(&mut self) -> Result<CryptRequirement, LibcryptErr> {
        let mut flags_u32 = 0u32;
        errno!(unsafe {
            libcryptsetup_rs_sys::crypt_persistent_flags_get(
                self.reference.as_ptr(),
                CryptFlagsType::Requirements as u32,
                &mut flags_u32 as *mut _,
            )
        })
        .and_then(|_| CryptRequirement::from_bits(flags_u32).ok_or(LibcryptErr::InvalidConversion))
    }
}
