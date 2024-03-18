// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use bitflags::bitflags;

bitflags! {
    /// Crypt device activation flags.
    pub struct CryptActivate: u32 {
        const READONLY = libcryptsetup_rs_sys::crypt_activate_readonly;
        const NO_UUID = libcryptsetup_rs_sys::crypt_activate_no_uuid;
        const SHARED = libcryptsetup_rs_sys::crypt_activate_shared;
        const ALLOW_DISCARDS = libcryptsetup_rs_sys::crypt_activate_allow_discards;
        const PRIVATE = libcryptsetup_rs_sys::crypt_activate_private;
        const CORRUPTED = libcryptsetup_rs_sys::crypt_activate_corrupted;
        const SAME_CPU_CRYPT = libcryptsetup_rs_sys::crypt_activate_same_cpu_crypt;
        const SUBMIT_FROM_CRYPT_CPUS = libcryptsetup_rs_sys::crypt_activate_submit_from_crypt_cpus;
        const IGNORE_CORRUPTION = libcryptsetup_rs_sys::crypt_activate_ignore_corruption;
        const RESTART_ON_CORRUPTION = libcryptsetup_rs_sys::crypt_activate_restart_on_corruption;
        const IGNORE_ZERO_BLOCKS = libcryptsetup_rs_sys::crypt_activate_ignore_zero_blocks;
        const KEYRING_KEY = libcryptsetup_rs_sys::crypt_activate_keyring_key;
        const NO_JOURNAL = libcryptsetup_rs_sys::crypt_activate_no_journal;
        const RECOVERY = libcryptsetup_rs_sys::crypt_activate_recovery;
        const IGNORE_PERSISTENT = libcryptsetup_rs_sys::crypt_activate_ignore_persistent;
        const CHECK_AT_MOST_ONCE = libcryptsetup_rs_sys::crypt_activate_check_at_most_once;
        const ALLOW_UNBOUND_KEY = libcryptsetup_rs_sys::crypt_activate_allow_unbound_key;
        const RECALCULATE = libcryptsetup_rs_sys::crypt_activate_recalculate;
        const REFRESH = libcryptsetup_rs_sys::crypt_activate_refresh;
        const SERIALIZE_MEMORY_HARD_PBKDF = libcryptsetup_rs_sys::crypt_activate_serialize_memory_hard_pbkdf;
        const NO_JOURNAL_BITMAP = libcryptsetup_rs_sys::crypt_activate_no_journal_bitmap;
        #[cfg(cryptsetup23supported)]
        const SUSPENDED = libcryptsetup_rs_sys::crypt_activate_suspended;
        #[cfg(cryptsetup24supported)]
        const IV_LARGE_SECTORS = libcryptsetup_rs_sys::crypt_activate_iv_large_sectors;
        #[cfg(cryptsetup24supported)]
        const PANIC_ON_CORRUPTION = libcryptsetup_rs_sys::crypt_activate_panic_on_corruption;
        #[cfg(cryptsetup24supported)]
        const NO_READ_WORKQUEUE = libcryptsetup_rs_sys::crypt_activate_no_read_workqueue;
        #[cfg(cryptsetup24supported)]
        const NO_WRITE_WORKQUEUE = libcryptsetup_rs_sys::crypt_activate_no_write_workqueue;
        #[cfg(cryptsetup24supported)]
        const RECALCULATE_RESET = libcryptsetup_rs_sys::crypt_activate_recalculate_reset;
    }
}

bitflags! {
    /// Flags for crypt deactivate operations
    pub struct CryptDeactivate: u32 {
        const DEFERRED = libcryptsetup_rs_sys::crypt_deactivate_deferred;
        const FORCE = libcryptsetup_rs_sys::crypt_deactivate_force;
    }
}

bitflags! {
    /// Verity format flags
    pub struct CryptVerity: u32 {
        const NO_HEADER = libcryptsetup_rs_sys::crypt_verity_no_header;
        const CHECK_HASH = libcryptsetup_rs_sys::crypt_verity_check_hash;
        const CREATE_HASH = libcryptsetup_rs_sys::crypt_verity_create_hash;
    }
}

bitflags! {
    /// tcrypt format flags
    pub struct CryptTcrypt: u32 {
        const LEGACY_MODES = libcryptsetup_rs_sys::crypt_tcrypt_legacy_modes;
        const HIDDEN_HEADER = libcryptsetup_rs_sys::crypt_tcrypt_hidden_header;
        const BACKUP_HEADER = libcryptsetup_rs_sys::crypt_tcrypt_backup_header;
        const SYSTEM_HEADER = libcryptsetup_rs_sys::crypt_tcrypt_system_header;
        const VERA_MODES = libcryptsetup_rs_sys::crypt_tcrypt_vera_modes;
    }
}

bitflags! {
    /// Flags for reading keyfiles
    pub struct CryptKeyfile: u32 {
        const STOP_EOL = libcryptsetup_rs_sys::crypt_keyfile_stop_eol;
    }
}

bitflags! {
    /// Flags for tunable options when operating with volume keys
    pub struct CryptVolumeKey: u32 {
        const NO_SEGMENT = libcryptsetup_rs_sys::crypt_volume_key_no_segment;
        const SET = libcryptsetup_rs_sys::crypt_volume_key_set;
        const DIGEST_REUSE = libcryptsetup_rs_sys::crypt_volume_key_digest_reuse;
    }
}

bitflags! {
    /// Requirement flags
    pub struct CryptRequirement: u32 {
        const OFFLINE_REENCRYPT = libcryptsetup_rs_sys::crypt_requirement_offline_reencrypt;
        const ONLINE_REENCRYPT = libcryptsetup_rs_sys::crypt_requirement_online_reencrypt;
        const UNKNOWN = libcryptsetup_rs_sys::crypt_requirement_unknown;
    }
}

bitflags! {
    /// Reencryption flags
    pub struct CryptReencrypt: u32 {
        const INITIALIZE_ONLY = libcryptsetup_rs_sys::crypt_reencrypt_initialize_only;
        const MOVE_FIRST_SEGMENT = libcryptsetup_rs_sys::crypt_reencrypt_move_first_segment;
        const RESUME_ONLY = libcryptsetup_rs_sys::crypt_reencrypt_resume_only;
        const RECOVERY = libcryptsetup_rs_sys::crypt_reencrypt_recovery;
    }
}

bitflags! {
    /// PBKDF flags
    pub struct CryptPbkdf: u32 {
        const ITER_TIME_SET = libcryptsetup_rs_sys::crypt_pbkdf_iter_time_set;
        const NO_BENCHMARK = libcryptsetup_rs_sys::crypt_pbkdf_no_benchmark;
    }
}

bitflags! {
    /// Flags for crypt wipe operations
    pub struct CryptWipe: u32 {
        const NO_DIRECT_IO = libcryptsetup_rs_sys::crypt_wipe_no_direct_io;
    }
}
