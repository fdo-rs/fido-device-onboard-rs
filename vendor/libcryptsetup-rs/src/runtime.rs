// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::{consts::flags::CryptActivate, device::CryptDevice, err::LibcryptErr};

/// Record containing data on the given active device
pub struct ActiveDevice {
    /// Device offset
    pub offset: u64,
    /// Initialization vector offset
    pub iv_offset: u64,
    /// Size of the device
    pub size: u64,
    /// Flags with activation options
    pub flags: CryptActivate,
}

impl<'a> TryFrom<&'a libcryptsetup_rs_sys::crypt_active_device> for ActiveDevice {
    type Error = LibcryptErr;

    fn try_from(v: &'a libcryptsetup_rs_sys::crypt_active_device) -> Result<Self, Self::Error> {
        Ok(ActiveDevice {
            offset: v.offset,
            iv_offset: v.iv_offset,
            size: v.size,
            flags: CryptActivate::from_bits(v.flags).ok_or(LibcryptErr::InvalidConversion)?,
        })
    }
}

/// Handle for runtime attribute options
pub struct CryptRuntimeHandle<'a> {
    reference: &'a mut CryptDevice,
    name: &'a str,
}

impl<'a> CryptRuntimeHandle<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice, name: &'a str) -> Self {
        CryptRuntimeHandle { reference, name }
    }

    /// Get active crypt device attributes
    pub fn get_active_device(&mut self) -> Result<ActiveDevice, LibcryptErr> {
        let mut cad = libcryptsetup_rs_sys::crypt_active_device {
            offset: 0,
            iv_offset: 0,
            size: 0,
            flags: 0,
        };
        let name_cstring = to_cstring!(self.name)?;
        errno!(mutex!(libcryptsetup_rs_sys::crypt_get_active_device(
            self.reference.as_ptr(),
            name_cstring.as_ptr(),
            &mut cad as *mut _,
        )))
        .and_then(|_| ActiveDevice::try_from(&cad))
    }

    /// Get detected number of integrity failures
    pub fn get_active_integrity_failures(&mut self) -> Result<u64, LibcryptErr> {
        let name_cstring = to_cstring!(self.name)?;
        Ok(mutex!(
            libcryptsetup_rs_sys::crypt_get_active_integrity_failures(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
            )
        ))
    }
}
