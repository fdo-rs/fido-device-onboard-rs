// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{path::Path, ptr};

use crate::{consts::vals::EncryptionFormat, device::CryptDevice, err::LibcryptErr};

/// Handle for backup operations on a device
pub struct CryptBackupHandle<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptBackupHandle<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptBackupHandle { reference }
    }

    /// Back up header and keyslots to a file
    pub fn header_backup(
        &mut self,
        requested_type: Option<EncryptionFormat>,
        backup_file: &Path,
    ) -> Result<(), LibcryptErr> {
        let backup_file_cstring = path_to_cstring!(backup_file)?;
        errno!(mutex!(libcryptsetup_rs_sys::crypt_header_backup(
            self.reference.as_ptr(),
            requested_type
                .map(|ty| ty.as_ptr())
                .unwrap_or_else(ptr::null),
            backup_file_cstring.as_ptr(),
        )))
    }

    /// Restore header and keyslots from a file
    pub fn header_restore(
        &mut self,
        requested_type: Option<EncryptionFormat>,
        backup_file: &Path,
    ) -> Result<(), LibcryptErr> {
        let backup_file_cstring = path_to_cstring!(backup_file)?;
        errno!(mutex!(libcryptsetup_rs_sys::crypt_header_restore(
            self.reference.as_ptr(),
            requested_type
                .map(|ty| ty.as_ptr())
                .unwrap_or_else(ptr::null),
            backup_file_cstring.as_ptr(),
        )))
    }
}
