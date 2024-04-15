// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{path::Path, ptr};

use libc::{c_char, c_void};

use crate::{
    consts::flags::CryptKeyfile, device::CryptDevice, err::LibcryptErr, mem::SafeMemHandle,
};

/// Contents of a keyfile that have been read
pub struct CryptKeyfileContents {
    key_mem: SafeMemHandle,
}

impl AsRef<[u8]> for CryptKeyfileContents {
    fn as_ref(&self) -> &[u8] {
        self.key_mem.as_ref()
    }
}

/// Handle for keyfile operations
pub struct CryptKeyfileHandle<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptKeyfileHandle<'a> {
    /// Create a new keyfile operation handle
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptKeyfileHandle { reference }
    }

    /// Read keyfile into memory - these bindings will automatically
    /// safely clean it up after `CryptKeyfileContents` is dropped
    pub fn device_read(
        &mut self,
        keyfile: &Path,
        keyfile_offset: u64,
        key_size: Option<crate::size_t>,
        flags: CryptKeyfile,
    ) -> Result<CryptKeyfileContents, LibcryptErr> {
        let keyfile_cstring = path_to_cstring!(keyfile)?;
        let keyfile_size = match key_size {
            Some(i) => i,
            None => std::fs::metadata(keyfile)
                .map_err(LibcryptErr::IOError)?
                .len() as crate::size_t,
        };

        let mut key: *mut c_char = ptr::null_mut();
        let mut size: crate::size_t = 0;
        errno!(mutex!(libcryptsetup_rs_sys::crypt_keyfile_device_read(
            self.reference.as_ptr(),
            keyfile_cstring.as_ptr(),
            &mut key as *mut *mut c_char,
            &mut size as *mut crate::size_t,
            keyfile_offset,
            keyfile_size,
            flags.bits(),
        )))?;
        Ok(CryptKeyfileContents {
            key_mem: unsafe { SafeMemHandle::from_ptr(key.cast::<c_void>(), size) },
        })
    }
}
