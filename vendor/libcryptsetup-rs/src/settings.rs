// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{ffi::CString, marker::PhantomData, os::raw::c_int};

use libcryptsetup_rs_sys::crypt_pbkdf_type;

use crate::{
    consts::{
        flags::CryptPbkdf,
        vals::{CryptKdf, CryptRng, KeyslotsSize, LockState, LuksType, MetadataSize},
    },
    device::CryptDevice,
    err::LibcryptErr,
};

/// Rust representation of `crypt_pbkdf_type`
pub struct CryptPbkdfType {
    #[allow(missing_docs)]
    pub type_: CryptKdf,
    #[allow(missing_docs)]
    pub hash: String,
    #[allow(missing_docs)]
    pub time_ms: u32,
    #[allow(missing_docs)]
    pub iterations: u32,
    #[allow(missing_docs)]
    pub max_memory_kb: u32,
    #[allow(missing_docs)]
    pub parallel_threads: u32,
    #[allow(missing_docs)]
    pub flags: CryptPbkdf,
}

impl TryFrom<libcryptsetup_rs_sys::crypt_pbkdf_type> for CryptPbkdfType {
    type Error = LibcryptErr;

    fn try_from(
        type_: libcryptsetup_rs_sys::crypt_pbkdf_type,
    ) -> Result<CryptPbkdfType, LibcryptErr> {
        Ok(CryptPbkdfType {
            type_: CryptKdf::from_ptr(type_.type_)?,
            hash: String::from(from_str_ptr!(type_.hash)?),
            time_ms: type_.time_ms,
            iterations: type_.iterations,
            max_memory_kb: type_.max_memory_kb,
            parallel_threads: type_.parallel_threads,
            flags: CryptPbkdf::from_bits(type_.flags).ok_or(LibcryptErr::InvalidConversion)?,
        })
    }
}

impl<'a> TryFrom<&'a libcryptsetup_rs_sys::crypt_pbkdf_type> for CryptPbkdfType {
    type Error = LibcryptErr;

    fn try_from(v: &'a libcryptsetup_rs_sys::crypt_pbkdf_type) -> Result<Self, Self::Error> {
        Ok(CryptPbkdfType {
            type_: CryptKdf::from_ptr(v.type_)?,
            hash: from_str_ptr!(v.hash)?.to_string(),
            time_ms: v.time_ms,
            iterations: v.iterations,
            max_memory_kb: v.max_memory_kb,
            parallel_threads: v.parallel_threads,
            flags: CryptPbkdf::from_bits(v.flags).ok_or(LibcryptErr::InvalidConversion)?,
        })
    }
}

/// A type wrapping a PBKDF type with pointers derived from Rust data types and lifetimes to ensure
/// pointer validity
pub struct CryptPbkdfTypeRef<'a> {
    /// Field containing a `crypt_pbkdf_type` that contains pointers valid for the supplied struct lifetime
    pub inner: crypt_pbkdf_type,
    #[allow(dead_code)]
    hash_cstring: CString,
    phantomdata: PhantomData<&'a ()>,
}

impl<'a> TryInto<CryptPbkdfTypeRef<'a>> for &'a CryptPbkdfType {
    type Error = LibcryptErr;

    fn try_into(self) -> Result<CryptPbkdfTypeRef<'a>, Self::Error> {
        let hash_cstring = CString::new(self.hash.as_bytes()).map_err(LibcryptErr::NullError)?;
        let inner = libcryptsetup_rs_sys::crypt_pbkdf_type {
            type_: self.type_.as_ptr(),
            hash: hash_cstring.as_ptr(),
            time_ms: self.time_ms,
            iterations: self.iterations,
            max_memory_kb: self.max_memory_kb,
            parallel_threads: self.parallel_threads,
            flags: self.flags.bits(),
        };
        Ok(CryptPbkdfTypeRef {
            inner,
            hash_cstring,
            phantomdata: PhantomData,
        })
    }
}

/// Handle to operate on cryptsetup device settings
pub struct CryptSettingsHandle<'a> {
    reference: &'a mut CryptDevice,
}

impl<'a> CryptSettingsHandle<'a> {
    pub(crate) fn new(reference: &'a mut CryptDevice) -> Self {
        CryptSettingsHandle { reference }
    }

    /// Set random number generator type
    pub fn set_rng_type(&mut self, rng_type: CryptRng) {
        let rng_u32: u32 = rng_type.into();
        mutex!(libcryptsetup_rs_sys::crypt_set_rng_type(
            self.reference.as_ptr(),
            rng_u32 as c_int
        ))
    }

    /// Get random number generator type
    pub fn get_rng_type(&mut self) -> Result<CryptRng, LibcryptErr> {
        CryptRng::try_from(mutex!(libcryptsetup_rs_sys::crypt_get_rng_type(
            self.reference.as_ptr()
        )) as u32)
    }

    /// Set PBKDF type
    pub fn set_pbkdf_type<'b>(
        &mut self,
        pbkdf_type: &'b CryptPbkdfType,
    ) -> Result<(), LibcryptErr> {
        let type_: CryptPbkdfTypeRef<'b> = pbkdf_type.try_into()?;
        errno!(mutex!(libcryptsetup_rs_sys::crypt_set_pbkdf_type(
            self.reference.as_ptr(),
            &type_.inner as *const crypt_pbkdf_type,
        )))
    }

    /// Get PBKDF parameters
    pub fn get_pbkdf_type_params(pbkdf_type: &CryptKdf) -> Result<CryptPbkdfType, LibcryptErr> {
        let type_ = ptr_to_result_with_reference!(mutex!(
            libcryptsetup_rs_sys::crypt_get_pbkdf_type_params(pbkdf_type.as_ptr())
        ))?;
        CryptPbkdfType::try_from(type_)
    }

    /// Get PBKDF default type
    pub fn get_pbkdf_default(luks_type: &LuksType) -> Result<CryptPbkdfType, LibcryptErr> {
        let default = ptr_to_result_with_reference!(mutex!(
            libcryptsetup_rs_sys::crypt_get_pbkdf_default(luks_type.as_ptr())
        ))?;
        CryptPbkdfType::try_from(default)
    }

    /// Get PBKDF type
    pub fn get_pbkdf_type(&mut self) -> Result<CryptPbkdfType, LibcryptErr> {
        let type_ = ptr_to_result_with_reference!(mutex!(
            libcryptsetup_rs_sys::crypt_get_pbkdf_type(self.reference.as_ptr())
        ))?;
        CryptPbkdfType::try_from(type_)
    }

    /// Set the iteration time in milliseconds
    pub fn set_iteration_time(&mut self, iteration_time_ms: u64) {
        mutex!(libcryptsetup_rs_sys::crypt_set_iteration_time(
            self.reference.as_ptr(),
            iteration_time_ms,
        ))
    }

    /// Lock or unlock memory
    pub fn memory_lock(&mut self, lock: LockState) -> LockState {
        int_to_return!(
            mutex!(libcryptsetup_rs_sys::crypt_memory_lock(
                self.reference.as_ptr(),
                lock as c_int
            )),
            LockState
        )
    }

    /// Lock or unlock the metadata
    pub fn metadata_locking(&mut self, enable: bool) -> Result<(), LibcryptErr> {
        errno!(mutex!(libcryptsetup_rs_sys::crypt_metadata_locking(
            self.reference.as_ptr(),
            enable as c_int
        )))
    }

    /// Set the metadata size and keyslot size
    pub fn set_metadata_size(
        &mut self,
        metadata_size: MetadataSize,
        keyslots_size: KeyslotsSize,
    ) -> Result<(), LibcryptErr> {
        errno!(mutex!(libcryptsetup_rs_sys::crypt_set_metadata_size(
            self.reference.as_ptr(),
            *metadata_size,
            *keyslots_size,
        )))
    }

    /// Get the metadata size and keyslot size
    pub fn get_metadata_size(&mut self) -> Result<(MetadataSize, KeyslotsSize), LibcryptErr> {
        let mut metadata_size = 0u64;
        let mut keyslots_size = 0u64;
        errno!(mutex!(libcryptsetup_rs_sys::crypt_get_metadata_size(
            self.reference.as_ptr(),
            &mut metadata_size as *mut u64,
            &mut keyslots_size as *mut u64,
        )))?;
        let msize = MetadataSize::try_from(metadata_size)?;
        let ksize = KeyslotsSize::try_from(keyslots_size)?;
        Ok((msize, ksize))
    }
}
