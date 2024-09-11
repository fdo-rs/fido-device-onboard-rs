// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{os::raw::c_int, path::Path, ptr};

use crate::{
    consts::vals::EncryptionFormat, device::CryptDevice, err::LibcryptErr, format::CryptParams,
};

use either::Either;
use uuid::Uuid;

/// Cryptographic context for device
pub struct CryptContextHandle<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptContextHandle<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptContextHandle { reference }
    }

    /// Format and encrypt the given device with the requested encryption
    /// algorithm and key or key length.
    ///
    /// For `volume_key` parameter, either the volume key or the desired length of
    /// the generated volume key can be specified.
    ///
    /// For the `volume_key` parameter, the value in `Either::Right` must be in
    /// units of bytes. For a common key length such as 512 bits, the value passed
    /// to the `Either::Right` variant would be `512 / 8`.
    pub fn format<T: CryptParams>(
        &mut self,
        type_: EncryptionFormat,
        cipher_and_mode: (&str, &str),
        uuid: Option<Uuid>,
        volume_key: Either<&[u8], usize>,
        params: Option<&mut T>,
    ) -> Result<(), LibcryptErr> {
        let uuid_c_string = match uuid {
            Some(u) => Some(to_cstring!(u.to_string())?),
            None => None,
        };
        let (volume_key_ptr, volume_key_len) = match volume_key {
            Either::Left(vk) => (to_byte_ptr!(vk), vk.len()),
            Either::Right(len) => (ptr::null(), len),
        };
        let (cipher, cipher_mode) = cipher_and_mode;
        let cipher_cstring = to_cstring!(cipher)?;
        let cipher_mode_cstring = to_cstring!(cipher_mode)?;
        errno!(mutex!(libcryptsetup_rs_sys::crypt_format(
            self.reference.as_ptr(),
            type_.as_ptr(),
            cipher_cstring.as_ptr(),
            cipher_mode_cstring.as_ptr(),
            uuid_c_string
                .as_ref()
                .map(|cs| cs.as_ptr())
                .unwrap_or_else(ptr::null),
            volume_key_ptr,
            volume_key_len,
            params.map(|p| p.as_ptr()).unwrap_or(ptr::null_mut()),
        )))?;
        Ok(())
    }

    /// Convert to new format type
    pub fn convert<T: CryptParams>(
        &mut self,
        type_: EncryptionFormat,
        params: Option<&mut T>,
    ) -> Result<(), LibcryptErr> {
        errno!(mutex!(libcryptsetup_rs_sys::crypt_convert(
            self.reference.as_ptr(),
            type_.as_ptr(),
            params.map(|p| p.as_ptr()).unwrap_or(ptr::null_mut()),
        )))
    }

    /// Set UUID of crypt device
    pub fn set_uuid(&mut self, uuid: Option<Uuid>) -> Result<(), LibcryptErr> {
        let c_string = match uuid {
            Some(u) => Some(to_cstring!(u.to_string())?),
            None => None,
        };
        errno!(mutex!(libcryptsetup_rs_sys::crypt_set_uuid(
            self.reference.as_ptr(),
            c_string
                .as_ref()
                .map(|cs| cs.as_ptr())
                .unwrap_or_else(ptr::null)
        )))
    }

    /// Set LUKS2 device label
    pub fn set_label(
        &mut self,
        label: Option<&str>,
        subsystem_label: Option<&str>,
    ) -> Result<(), LibcryptErr> {
        let (lcstring, slcstring) = match (label, subsystem_label) {
            (Some(l), Some(sl)) => (Some(to_cstring!(l)?), Some(to_cstring!(sl)?)),
            (Some(l), _) => (Some(to_cstring!(l)?), None),
            (_, Some(sl)) => (None, Some(to_cstring!(sl)?)),
            (_, _) => (None, None),
        };
        errno!(mutex!(libcryptsetup_rs_sys::crypt_set_label(
            self.reference.as_ptr(),
            lcstring
                .as_ref()
                .map(|cs| cs.as_ptr())
                .unwrap_or(ptr::null()),
            slcstring
                .as_ref()
                .map(|cs| cs.as_ptr())
                .unwrap_or(ptr::null()),
        )))
    }

    /// Set policty on loading volume keys via kernel keyring
    pub fn volume_key_keyring(&mut self, enable: bool) -> Result<(), LibcryptErr> {
        errno!(mutex!(libcryptsetup_rs_sys::crypt_volume_key_keyring(
            self.reference.as_ptr(),
            enable as c_int
        )))
    }

    /// Load on-disk header parameters based on provided type
    pub fn load<T: CryptParams>(
        &mut self,
        type_: Option<EncryptionFormat>,
        params: Option<&mut T>,
    ) -> Result<(), LibcryptErr> {
        errno!(mutex!(libcryptsetup_rs_sys::crypt_load(
            self.reference.as_ptr(),
            type_.map(|t| t.as_ptr()).unwrap_or(ptr::null()),
            params.map(|p| p.as_ptr()).unwrap_or(ptr::null_mut()),
        )))?;
        Ok(())
    }

    /// Repair crypt device header if invalid
    pub fn repair<T: CryptParams>(
        &mut self,
        type_: EncryptionFormat,
        params: Option<&mut T>,
    ) -> Result<(), LibcryptErr> {
        errno!(mutex!(libcryptsetup_rs_sys::crypt_repair(
            self.reference.as_ptr(),
            type_.as_ptr(),
            params.map(|p| p.as_ptr()).unwrap_or(ptr::null_mut()),
        )))
    }

    /// Resize crypt device
    pub fn resize(&mut self, name: &str, new_size: u64) -> Result<(), LibcryptErr> {
        let name_cstring = to_cstring!(name)?;
        errno!(mutex!(libcryptsetup_rs_sys::crypt_resize(
            self.reference.as_ptr(),
            name_cstring.as_ptr(),
            new_size,
        )))
    }

    /// Suspend crypt device
    pub fn suspend(&mut self, name: &str) -> Result<(), LibcryptErr> {
        let name_cstring = to_cstring!(name)?;
        errno!(mutex!(libcryptsetup_rs_sys::crypt_suspend(
            self.reference.as_ptr(),
            name_cstring.as_ptr()
        )))
    }

    /// Resume crypt device using a passphrase
    pub fn resume_by_passphrase(
        &mut self,
        name: &str,
        keyslot: c_int,
        passphrase: &str,
    ) -> Result<c_int, LibcryptErr> {
        let name_cstring = to_cstring!(name)?;
        let passphrase_cstring = to_cstring!(passphrase)?;
        errno_int_success!(mutex!(libcryptsetup_rs_sys::crypt_resume_by_passphrase(
            self.reference.as_ptr(),
            name_cstring.as_ptr(),
            keyslot,
            passphrase_cstring.as_ptr(),
            passphrase.len() as crate::size_t,
        )))
    }

    /// Resume crypt device using a key file at an offset on disk
    pub fn resume_by_keyfile_device_offset(
        &mut self,
        name: &str,
        keyslot: c_int,
        keyfile: &Path,
        keyfile_size: crate::size_t,
        keyfile_offset: u64,
    ) -> Result<c_int, LibcryptErr> {
        let name_cstring = to_cstring!(name)?;
        let keyfile_cstring = path_to_cstring!(keyfile)?;
        errno_int_success!(mutex!(
            libcryptsetup_rs_sys::crypt_resume_by_keyfile_device_offset(
                self.reference.as_ptr(),
                name_cstring.as_ptr(),
                keyslot,
                keyfile_cstring.as_ptr(),
                keyfile_size,
                keyfile_offset,
            )
        ))
    }
}
