// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! This is a wrapper library for libcryptsetup. The intention is to provide as much safety as
//! possible when crossing FFI boundaries to the cryptsetup C library.

// Keyfile reading functions are supported through a workaround in these bindings due
// to how memory is handled in these functions - memory for keys is allocated
// and the corresponding free functions are not part of the public API.
// The function is copied and pasted from libcryptsetup and compiled into the bindings
// for now to work around this. This will be supported by libcryptsetup at a later
// time.

pub use either::Either;

#[macro_use]
mod macros;

mod activate;
mod backup;
pub mod consts;
mod context;
mod debug;
mod device;
mod err;
mod format;
mod key;
mod keyfile;
mod keyslot;
mod log;
mod luks2;
mod mem;
#[cfg(feature = "mutex")]
mod mutex;
mod runtime;
mod settings;
mod status;
#[cfg(test)]
mod tests;
mod wipe;

#[cfg(cryptsetup23supported)]
pub use crate::mem::{SafeBorrowedMemZero, SafeMemzero, SafeOwnedMemZero};
pub use crate::{
    activate::CryptActivationHandle,
    backup::CryptBackupHandle,
    context::CryptContextHandle,
    debug::set_debug_level,
    device::{CryptDevice, CryptInit},
    err::LibcryptErr,
    format::{
        CryptFormatHandle, CryptParamsIntegrity, CryptParamsIntegrityRef, CryptParamsLoopaes,
        CryptParamsLoopaesRef, CryptParamsLuks1, CryptParamsLuks1Ref, CryptParamsLuks2,
        CryptParamsLuks2Ref, CryptParamsPlain, CryptParamsPlainRef, CryptParamsTcrypt,
        CryptParamsTcryptRef, CryptParamsVerity, CryptParamsVerityRef,
    },
    key::CryptVolumeKeyHandle,
    keyfile::{CryptKeyfileContents, CryptKeyfileHandle},
    keyslot::CryptKeyslotHandle,
    log::{log, set_log_callback},
    luks2::{
        flags::CryptLuks2FlagsHandle,
        reencrypt::{CryptLuks2ReencryptHandle, CryptParamsReencrypt, CryptParamsReencryptRef},
        token::{register, CryptLuks2TokenHandle, CryptTokenInfo, TokenInput},
    },
    mem::SafeMemHandle,
    runtime::{ActiveDevice, CryptRuntimeHandle},
    settings::{CryptPbkdfType, CryptPbkdfTypeRef, CryptSettingsHandle},
    status::{get_sector_size, status, CryptDeviceStatusHandle},
    wipe::CryptWipeHandle,
};

/// Re-exports `libc` types in API
pub use libc::{c_int, c_uint, size_t};

/// Result type to be used with `libcryptsetup-rs`
pub type Result<T> = std::result::Result<T, LibcryptErr>;

#[cfg(feature = "mutex")]
lazy_static::lazy_static! {
    static ref MUTEX: crate::mutex::PerThreadMutex = crate::mutex::PerThreadMutex::default();
}

#[cfg(not(feature = "mutex"))]
lazy_static::lazy_static! {
    static ref THREAD_ID: std::thread::ThreadId = std::thread::current().id();
}

#[cfg(test)]
mod test {
    use crate::tests;

    #[ignore]
    #[test]
    fn test_encrypt_by_password() {
        tests::encrypt::test_encrypt_by_password();
    }

    #[ignore]
    #[test]
    fn test_encrypt_by_keyfile() {
        tests::encrypt::test_encrypt_by_keyfile();
    }

    #[ignore]
    #[test]
    fn test_encrypt_by_password_without_explicit_format() {
        tests::encrypt::test_encrypt_by_password_without_explicit_format();
    }

    #[ignore]
    #[test]
    fn test_unencrypted() {
        tests::encrypt::test_unencrypted();
    }

    #[ignore]
    #[test]
    fn test_crypt_setup_free_exists() {
        tests::keyfile::test_keyfile_cleanup();
    }
}
