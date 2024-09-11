// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::os::raw::{c_int, c_uint};

use crate::{device::CryptDevice, err::LibcryptErr};

/// Handle for volume key operations
pub struct CryptVolumeKeyHandle<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptVolumeKeyHandle<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptVolumeKeyHandle { reference }
    }

    /// Get volume key from crypt device - first tuple element is key slot, second is volume key
    /// size
    pub fn get(
        &mut self,
        keyslot: c_uint,
        volume_key: &mut [u8],
        passphrase: &[u8],
    ) -> Result<(c_int, crate::size_t), LibcryptErr> {
        let mut volume_key_size_t = volume_key.len();
        errno_int_success!(mutex!(libcryptsetup_rs_sys::crypt_volume_key_get(
            self.reference.as_ptr(),
            keyslot as c_int,
            to_mut_byte_ptr!(volume_key),
            &mut volume_key_size_t as *mut _,
            to_byte_ptr!(passphrase),
            passphrase.len(),
        )))
        .map(|i| (i, volume_key_size_t))
    }

    /// Verify that volume key is valid for crypt device
    pub fn verify(&mut self, volume_key: &[u8]) -> Result<(), LibcryptErr> {
        errno!(mutex!(libcryptsetup_rs_sys::crypt_volume_key_verify(
            self.reference.as_ptr(),
            to_byte_ptr!(volume_key),
            volume_key.len(),
        )))
    }
}
