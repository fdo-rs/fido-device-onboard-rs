// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    os::raw::{c_int, c_void},
    path::Path,
};

use crate::{
    consts::{flags::CryptWipe, vals::CryptWipePattern},
    device::CryptDevice,
    err::LibcryptErr,
};

type WipeProgressCallback =
    unsafe extern "C" fn(size: u64, offset: u64, usrptr: *mut c_void) -> c_int;

/// Handle for volume key operations
pub struct CryptWipeHandle<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptWipeHandle<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptWipeHandle { reference }
    }

    /// Wipe a device with the selected pattern
    #[allow(clippy::too_many_arguments)]
    pub fn wipe<T>(
        &mut self,
        dev_path: &Path,
        pattern: CryptWipePattern,
        offset: u64,
        length: u64,
        wipe_block_size: crate::size_t,
        flags: CryptWipe,
        callback: Option<WipeProgressCallback>,
        usrptr: Option<&mut T>,
    ) -> Result<(), LibcryptErr> {
        let dev_path_cstring = path_to_cstring!(dev_path)?;
        errno!(mutex!(libcryptsetup_rs_sys::crypt_wipe(
            self.reference.as_ptr(),
            dev_path_cstring.as_ptr(),
            pattern.into(),
            offset,
            length,
            wipe_block_size,
            flags.bits(),
            callback,
            match usrptr {
                Some(up) => (up as *mut T).cast::<c_void>(),
                None => std::ptr::null_mut(),
            },
        )))
    }
}
