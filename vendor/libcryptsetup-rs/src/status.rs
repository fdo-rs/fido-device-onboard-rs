// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{os::raw::c_int, path::Path, ptr, str::FromStr};

use crate::{
    consts::vals::CryptStatusInfo,
    device::CryptDevice,
    err::LibcryptErr,
    format::{CryptParamsIntegrity, CryptParamsVerity},
};

use uuid::Uuid;

/// Handle for crypt device status operations
pub struct CryptDeviceStatusHandle<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptDeviceStatusHandle<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptDeviceStatusHandle { reference }
    }

    /// Dump text info about device to log output
    pub fn dump(&mut self) -> Result<(), LibcryptErr> {
        errno!(mutex!(libcryptsetup_rs_sys::crypt_dump(
            self.reference.as_ptr()
        )))
    }

    /// Get cipher used by device
    pub fn get_cipher(&mut self) -> Result<String, LibcryptErr> {
        from_str_ptr_to_owned!(libcryptsetup_rs_sys::crypt_get_cipher(
            self.reference.as_ptr()
        ))
    }

    /// Get cipher mode used by device
    pub fn get_cipher_mode(&mut self) -> Result<String, LibcryptErr> {
        from_str_ptr_to_owned!(libcryptsetup_rs_sys::crypt_get_cipher_mode(
            self.reference.as_ptr()
        ))
    }

    /// Get device UUID
    pub fn get_uuid(&mut self) -> Result<Uuid, LibcryptErr> {
        from_str_ptr!(libcryptsetup_rs_sys::crypt_get_uuid(
            self.reference.as_ptr()
        ))
        .and_then(|e| Uuid::from_str(e).map_err(LibcryptErr::UuidError))
    }

    /// Get path to underlying device
    pub fn get_device_path(&mut self) -> Result<&Path, LibcryptErr> {
        from_str_ptr!(libcryptsetup_rs_sys::crypt_get_device_name(
            self.reference.as_ptr()
        ))
        .map(Path::new)
    }

    /// Get path to detached metadata device or `None` if it is attached
    pub fn get_metadata_device_path(&mut self) -> Result<Option<&Path>, LibcryptErr> {
        let ptr = mutex!(libcryptsetup_rs_sys::crypt_get_metadata_device_name(
            self.reference.as_ptr()
        ));
        if ptr.is_null() {
            return Ok(None);
        }
        from_str_ptr!(ptr).map(|s| Some(Path::new(s)))
    }

    /// Get offset in 512-byte sectors where real data starts
    pub fn get_data_offset(&mut self) -> u64 {
        mutex!(libcryptsetup_rs_sys::crypt_get_data_offset(
            self.reference.as_ptr()
        ))
    }

    /// Get IV location offset in 512-byte sectors
    pub fn get_iv_offset(&mut self) -> u64 {
        mutex!(libcryptsetup_rs_sys::crypt_get_iv_offset(
            self.reference.as_ptr()
        ))
    }

    /// Get size in bytes of volume key
    pub fn get_volume_key_size(&mut self) -> c_int {
        mutex!(libcryptsetup_rs_sys::crypt_get_volume_key_size(
            self.reference.as_ptr()
        ))
    }

    /// Get Verity device parameters
    pub fn get_verity_info(&mut self) -> Result<CryptParamsVerity, LibcryptErr> {
        let mut verity = libcryptsetup_rs_sys::crypt_params_verity {
            hash_name: std::ptr::null(),
            data_device: std::ptr::null(),
            hash_device: std::ptr::null(),
            fec_device: std::ptr::null(),
            salt: std::ptr::null(),
            salt_size: 0,
            hash_type: 0,
            data_block_size: 0,
            hash_block_size: 0,
            data_size: 0,
            hash_area_offset: 0,
            fec_area_offset: 0,
            fec_roots: 0,
            flags: 0,
        };
        errno!(mutex!(libcryptsetup_rs_sys::crypt_get_verity_info(
            self.reference.as_ptr(),
            &mut verity as *mut _,
        )))
        .and_then(|_| CryptParamsVerity::try_from(&verity))
    }

    /// Get Integrity device parameters
    pub fn get_integrity_info(&mut self) -> Result<CryptParamsIntegrity, LibcryptErr> {
        let mut integrity = libcryptsetup_rs_sys::crypt_params_integrity {
            journal_size: 0,
            journal_watermark: 0,
            journal_commit_time: 0,
            interleave_sectors: 0,
            tag_size: 0,
            sector_size: 0,
            buffer_sectors: 0,
            integrity: std::ptr::null(),
            integrity_key_size: 0,
            journal_integrity: std::ptr::null(),
            journal_integrity_key: std::ptr::null(),
            journal_integrity_key_size: 0,
            journal_crypt: std::ptr::null(),
            journal_crypt_key: std::ptr::null(),
            journal_crypt_key_size: 0,
        };
        errno!(mutex!(libcryptsetup_rs_sys::crypt_get_integrity_info(
            self.reference.as_ptr(),
            &mut integrity as *mut _,
        )))
        .and_then(|_| CryptParamsIntegrity::try_from(&integrity))
    }
}

/// Get status info from device name
pub fn status(
    device: Option<&mut CryptDevice>,
    name: &str,
) -> Result<CryptStatusInfo, LibcryptErr> {
    let name_cstring = to_cstring!(name)?;
    try_int_to_return!(
        mutex!(libcryptsetup_rs_sys::crypt_status(
            match device {
                Some(d) => d.as_ptr(),
                None => std::ptr::null_mut(),
            },
            name_cstring.as_ptr(),
        )),
        CryptStatusInfo
    )
}

/// Get size of encryption sectors in bytes
pub fn get_sector_size(device: Option<&mut CryptDevice>) -> c_int {
    mutex!(libcryptsetup_rs_sys::crypt_get_sector_size(
        device.map(|d| d.as_ptr()).unwrap_or(ptr::null_mut()),
    ))
}
