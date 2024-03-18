// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{ffi::CStr, ops::Deref};

use libc::{c_char, c_int};

use crate::err::LibcryptErr;

consts_to_from_enum!(
    /// Debug log level
    CryptDebugLevel, c_int,
    All => libcryptsetup_rs_sys::CRYPT_DEBUG_ALL as c_int,
    Json => libcryptsetup_rs_sys::CRYPT_DEBUG_JSON as c_int,
    None => libcryptsetup_rs_sys::CRYPT_DEBUG_NONE as c_int
);

/// Device formatting type options
#[derive(Debug, Eq, PartialEq)]
pub enum EncryptionFormat {
    #[allow(missing_docs)]
    Plain,
    #[allow(missing_docs)]
    Luks1,
    #[allow(missing_docs)]
    Luks2,
    #[allow(missing_docs)]
    Loopaes,
    #[allow(missing_docs)]
    Verity,
    #[allow(missing_docs)]
    Tcrypt,
    #[allow(missing_docs)]
    Integrity,
}

impl EncryptionFormat {
    /// Get `EncryptionFormat` as a char pointer
    pub(crate) fn as_ptr(&self) -> *const c_char {
        match *self {
            EncryptionFormat::Plain => libcryptsetup_rs_sys::CRYPT_PLAIN.as_ptr().cast::<c_char>(),
            EncryptionFormat::Luks1 => libcryptsetup_rs_sys::CRYPT_LUKS1.as_ptr().cast::<c_char>(),
            EncryptionFormat::Luks2 => libcryptsetup_rs_sys::CRYPT_LUKS2.as_ptr().cast::<c_char>(),
            EncryptionFormat::Loopaes => libcryptsetup_rs_sys::CRYPT_LOOPAES
                .as_ptr()
                .cast::<c_char>(),
            EncryptionFormat::Verity => {
                libcryptsetup_rs_sys::CRYPT_VERITY.as_ptr().cast::<c_char>()
            }
            EncryptionFormat::Tcrypt => {
                libcryptsetup_rs_sys::CRYPT_TCRYPT.as_ptr().cast::<c_char>()
            }
            EncryptionFormat::Integrity => libcryptsetup_rs_sys::CRYPT_INTEGRITY
                .as_ptr()
                .cast::<c_char>(),
        }
    }

    /// Get `EncryptionFormat` from a char pointer
    pub(crate) fn from_ptr(p: *const c_char) -> Result<Self, LibcryptErr> {
        let p_bytes = unsafe { CStr::from_ptr(p) }.to_bytes_with_nul();
        if libcryptsetup_rs_sys::CRYPT_PLAIN == p_bytes {
            Ok(EncryptionFormat::Plain)
        } else if libcryptsetup_rs_sys::CRYPT_LUKS1 == p_bytes {
            Ok(EncryptionFormat::Luks1)
        } else if libcryptsetup_rs_sys::CRYPT_LUKS2 == p_bytes {
            Ok(EncryptionFormat::Luks2)
        } else if libcryptsetup_rs_sys::CRYPT_LOOPAES == p_bytes {
            Ok(EncryptionFormat::Loopaes)
        } else if libcryptsetup_rs_sys::CRYPT_VERITY == p_bytes {
            Ok(EncryptionFormat::Verity)
        } else if libcryptsetup_rs_sys::CRYPT_TCRYPT == p_bytes {
            Ok(EncryptionFormat::Tcrypt)
        } else if libcryptsetup_rs_sys::CRYPT_INTEGRITY == p_bytes {
            Ok(EncryptionFormat::Integrity)
        } else {
            Err(LibcryptErr::InvalidConversion)
        }
    }
}

consts_to_from_enum!(
    /// Value indicating the status of a keyslot
    KeyslotInfo,
    u32,
    Invalid => libcryptsetup_rs_sys::crypt_keyslot_info_CRYPT_SLOT_INVALID,
    Inactive => libcryptsetup_rs_sys::crypt_keyslot_info_CRYPT_SLOT_INACTIVE,
    Active => libcryptsetup_rs_sys::crypt_keyslot_info_CRYPT_SLOT_ACTIVE,
    ActiveLast => libcryptsetup_rs_sys::crypt_keyslot_info_CRYPT_SLOT_ACTIVE_LAST,
    Unbound => libcryptsetup_rs_sys::crypt_keyslot_info_CRYPT_SLOT_UNBOUND
);

consts_to_from_enum!(
    /// Value indicating the priority of a keyslot
    KeyslotPriority,
    i32,
    Invalid => libcryptsetup_rs_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_INVALID,
    Ignore => libcryptsetup_rs_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_IGNORE,
    Normal => libcryptsetup_rs_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_NORMAL,
    Prefer => libcryptsetup_rs_sys::crypt_keyslot_priority_CRYPT_SLOT_PRIORITY_PREFER
);

/// Logging levels
#[derive(Debug, Eq, PartialEq)]
pub enum CryptLogLevel {
    #[allow(missing_docs)]
    Normal = libcryptsetup_rs_sys::CRYPT_LOG_NORMAL as isize,
    #[allow(missing_docs)]
    Error = libcryptsetup_rs_sys::CRYPT_LOG_ERROR as isize,
    #[allow(missing_docs)]
    Verbose = libcryptsetup_rs_sys::CRYPT_LOG_VERBOSE as isize,
    #[allow(missing_docs)]
    Debug = libcryptsetup_rs_sys::CRYPT_LOG_DEBUG as isize,
    #[allow(missing_docs)]
    DebugJson = libcryptsetup_rs_sys::CRYPT_LOG_DEBUG_JSON as isize,
}

impl TryFrom<c_int> for CryptLogLevel {
    type Error = LibcryptErr;

    fn try_from(v: c_int) -> Result<Self, <Self as TryFrom<c_int>>::Error> {
        let level = match v {
            i if i == CryptLogLevel::Normal as c_int => CryptLogLevel::Normal,
            i if i == CryptLogLevel::Error as c_int => CryptLogLevel::Error,
            i if i == CryptLogLevel::Verbose as c_int => CryptLogLevel::Verbose,
            i if i == CryptLogLevel::Debug as c_int => CryptLogLevel::Debug,
            i if i == CryptLogLevel::DebugJson as c_int => CryptLogLevel::DebugJson,
            _ => return Err(LibcryptErr::InvalidConversion),
        };
        Ok(level)
    }
}

pub(crate) enum CryptFlagsType {
    Activation = libcryptsetup_rs_sys::crypt_flags_type_CRYPT_FLAGS_ACTIVATION as isize,
    Requirements = libcryptsetup_rs_sys::crypt_flags_type_CRYPT_FLAGS_REQUIREMENTS as isize,
}

consts_to_from_enum!(
    /// Encryption mode flags
    CryptReencryptInfo,
    u32,
    None => libcryptsetup_rs_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_NONE,
    Clean => libcryptsetup_rs_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_CLEAN,
    Crash => libcryptsetup_rs_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_CRASH,
    Invalid => libcryptsetup_rs_sys::crypt_reencrypt_info_CRYPT_REENCRYPT_INVALID
);

consts_to_from_enum!(
    /// Encryption mode flags
    CryptReencryptModeInfo,
    u32,
    Reencrypt => libcryptsetup_rs_sys::crypt_reencrypt_mode_info_CRYPT_REENCRYPT_REENCRYPT,
    Encrypt => libcryptsetup_rs_sys::crypt_reencrypt_mode_info_CRYPT_REENCRYPT_ENCRYPT,
    Decrypt => libcryptsetup_rs_sys::crypt_reencrypt_mode_info_CRYPT_REENCRYPT_DECRYPT
);

consts_to_from_enum!(
    /// Reencryption direction flags
    CryptReencryptDirectionInfo,
    u32,
    Forward => libcryptsetup_rs_sys::crypt_reencrypt_direction_info_CRYPT_REENCRYPT_FORWARD,
    Backward => libcryptsetup_rs_sys::crypt_reencrypt_direction_info_CRYPT_REENCRYPT_BACKWARD
);

/// Rust representation of key generator enum
#[derive(Debug, Eq, PartialEq)]
pub enum CryptKdf {
    #[allow(missing_docs)]
    Pbkdf2,
    #[allow(missing_docs)]
    Argon2I,
    #[allow(missing_docs)]
    Argon2Id,
}

impl CryptKdf {
    /// Convert to a `char *` for C
    pub(crate) fn as_ptr(&self) -> *const c_char {
        match *self {
            CryptKdf::Pbkdf2 => libcryptsetup_rs_sys::CRYPT_KDF_PBKDF2
                .as_ptr()
                .cast::<c_char>(),
            CryptKdf::Argon2I => libcryptsetup_rs_sys::CRYPT_KDF_ARGON2I
                .as_ptr()
                .cast::<c_char>(),
            CryptKdf::Argon2Id => libcryptsetup_rs_sys::CRYPT_KDF_ARGON2ID
                .as_ptr()
                .cast::<c_char>(),
        }
    }

    /// Convert from a C `char *`
    pub(crate) fn from_ptr(ptr: *const c_char) -> Result<Self, LibcryptErr> {
        if libcryptsetup_rs_sys::CRYPT_KDF_PBKDF2 == unsafe { CStr::from_ptr(ptr) }.to_bytes() {
            Ok(CryptKdf::Pbkdf2)
        } else if libcryptsetup_rs_sys::CRYPT_KDF_ARGON2I
            == unsafe { CStr::from_ptr(ptr) }.to_bytes()
        {
            Ok(CryptKdf::Argon2I)
        } else if libcryptsetup_rs_sys::CRYPT_KDF_ARGON2ID
            == unsafe { CStr::from_ptr(ptr) }.to_bytes()
        {
            Ok(CryptKdf::Argon2Id)
        } else {
            Err(LibcryptErr::InvalidConversion)
        }
    }
}

consts_to_from_enum!(
    /// Rust representation of random number generator enum
    CryptRng,
    u32,
    Urandom => libcryptsetup_rs_sys::CRYPT_RNG_URANDOM,
    Random => libcryptsetup_rs_sys::CRYPT_RNG_RANDOM
);

/// LUKS type (1 or 2)
#[derive(Debug, Eq, PartialEq)]
pub enum LuksType {
    #[allow(missing_docs)]
    Luks1,
    #[allow(missing_docs)]
    Luks2,
}

impl LuksType {
    /// Convert Rust expression to an equivalent C pointer
    pub(crate) fn as_ptr(&self) -> *const c_char {
        match *self {
            LuksType::Luks1 => libcryptsetup_rs_sys::CRYPT_LUKS1.as_ptr().cast::<c_char>(),
            LuksType::Luks2 => libcryptsetup_rs_sys::CRYPT_LUKS2.as_ptr().cast::<c_char>(),
        }
    }
}

consts_to_from_enum!(
    /// Status of a crypt device
    CryptStatusInfo, u32,
    Invalid => libcryptsetup_rs_sys::crypt_status_info_CRYPT_INVALID,
    Inactive => libcryptsetup_rs_sys::crypt_status_info_CRYPT_INACTIVE,
    Active => libcryptsetup_rs_sys::crypt_status_info_CRYPT_ACTIVE,
    Busy => libcryptsetup_rs_sys::crypt_status_info_CRYPT_BUSY
);

consts_to_from_enum!(
    /// Pattern for disk wipe
    CryptWipePattern, u32,
    Zero => libcryptsetup_rs_sys::crypt_wipe_pattern_CRYPT_WIPE_ZERO,
    Random => libcryptsetup_rs_sys::crypt_wipe_pattern_CRYPT_WIPE_RANDOM,
    EncryptedZero => libcryptsetup_rs_sys::crypt_wipe_pattern_CRYPT_WIPE_ENCRYPTED_ZERO,
    Special => libcryptsetup_rs_sys::crypt_wipe_pattern_CRYPT_WIPE_SPECIAL
);

/// Size allocated for metadata
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum MetadataSize {
    #[allow(missing_docs)]
    Kb16,
    #[allow(missing_docs)]
    Kb32,
    #[allow(missing_docs)]
    Kb64,
    #[allow(missing_docs)]
    Kb128,
    #[allow(missing_docs)]
    Kb256,
    #[allow(missing_docs)]
    Kb512,
    #[allow(missing_docs)]
    Kb1024,
    #[allow(missing_docs)]
    Kb2048,
    #[allow(missing_docs)]
    Kb4096,
}

impl TryFrom<u64> for MetadataSize {
    type Error = LibcryptErr;

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        let size = match v {
            i if i == *MetadataSize::Kb16 => MetadataSize::Kb16,
            i if i == *MetadataSize::Kb32 => MetadataSize::Kb32,
            i if i == *MetadataSize::Kb64 => MetadataSize::Kb64,
            i if i == *MetadataSize::Kb128 => MetadataSize::Kb128,
            i if i == *MetadataSize::Kb256 => MetadataSize::Kb256,
            i if i == *MetadataSize::Kb512 => MetadataSize::Kb512,
            i if i == *MetadataSize::Kb1024 => MetadataSize::Kb1024,
            i if i == *MetadataSize::Kb2048 => MetadataSize::Kb2048,
            i if i == *MetadataSize::Kb4096 => MetadataSize::Kb4096,
            _ => return Err(LibcryptErr::InvalidConversion),
        };
        Ok(size)
    }
}

impl Deref for MetadataSize {
    type Target = u64;

    fn deref(&self) -> &u64 {
        match *self {
            MetadataSize::Kb16 => &0x4000,
            MetadataSize::Kb32 => &0x8000,
            MetadataSize::Kb64 => &0x10000,
            MetadataSize::Kb128 => &0x20000,
            MetadataSize::Kb256 => &0x40000,
            MetadataSize::Kb512 => &0x80000,
            MetadataSize::Kb1024 => &0x100000,
            MetadataSize::Kb2048 => &0x200000,
            MetadataSize::Kb4096 => &0x400000,
        }
    }
}

/// Size in bytes for the keyslots.
///
/// The value must be divisible by a 4KB block and no larger than
/// 128MB.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct KeyslotsSize(u64);

impl KeyslotsSize {
    // 4KB block size in bytes
    const FOUR_KB: u64 = 1 << 12;
    // 128MB max size in bytes
    const MAX_MB: u64 = 1 << 27;
}

impl Deref for KeyslotsSize {
    type Target = u64;

    fn deref(&self) -> &u64 {
        &self.0
    }
}

impl TryFrom<u64> for KeyslotsSize {
    type Error = LibcryptErr;

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        // Must be divisible by 4KB and less than or equal to 128MB
        if v > Self::MAX_MB || v % Self::FOUR_KB != 0 {
            return Err(LibcryptErr::InvalidConversion);
        }

        Ok(KeyslotsSize(v))
    }
}

/// State of memory lock
#[derive(Debug, Eq, PartialEq)]
pub enum LockState {
    #[allow(missing_docs)]
    Unlocked = 0,
    #[allow(missing_docs)]
    Locked = 1,
}

impl From<c_int> for LockState {
    fn from(v: c_int) -> Self {
        match v {
            i if i == LockState::Unlocked as c_int => LockState::Unlocked,
            _ => LockState::Locked,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_metadata_size() {
        assert_eq!(MetadataSize::try_from(0x4000).unwrap(), MetadataSize::Kb16);
        assert_eq!(MetadataSize::try_from(0x10000).unwrap(), MetadataSize::Kb64);
        assert!(MetadataSize::try_from(0x10001).is_err());
    }

    #[test]
    fn test_keyslots_size() {
        // Exactly 128MB
        assert!(KeyslotsSize::try_from(1 << 27).is_ok());
        // Greater than 128MB
        assert!(KeyslotsSize::try_from(1 << 28).is_err());
        // Less than 4KB
        assert!(KeyslotsSize::try_from(1 << 11).is_err());
        // Exactly 4KB
        assert!(KeyslotsSize::try_from(1 << 12).is_ok());
        // Greater than 4KB and not divisible by 4KB
        assert!(KeyslotsSize::try_from(4097).is_err());

        // Assert that derefs are equal to the starting value
        assert!(*KeyslotsSize::try_from(1 << 27).unwrap() == (1 << 27));
    }
}
