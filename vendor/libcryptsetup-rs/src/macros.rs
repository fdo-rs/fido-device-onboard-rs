// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/// Wrap all libcryptsetup_rs_sys calls in the macro. It will expand to a
/// feature-flagged mutex lock call. If the `mutex` feature is not enabled, it is
/// a no-op.
macro_rules! mutex {
    ( $libcryptsetup_call:expr ) => {{
        #[cfg(feature = "mutex")]
        #[allow(unused_variables)]
        let lock = $crate::MUTEX.acquire();

        #[cfg(not(feature = "mutex"))]
        if *$crate::THREAD_ID != std::thread::current().id() {
            panic!("Enable the mutex feature for this crate to allow calling libcryptsetup methods from multiple threads");
        }

        unsafe { $libcryptsetup_call }
    }};
}

/// Convert an errno-zero-success return pattern into a `Result<(), LibcryptErr>`
macro_rules! errno {
    ( $rc:expr ) => {
        match $rc {
            i if i < 0 => {
                return Err($crate::err::LibcryptErr::IOError(
                    std::io::Error::from_raw_os_error(-i),
                ))
            }
            i if i > 0 => panic!("Unexpected return value {}", i),
            _ => Result::<(), $crate::err::LibcryptErr>::Ok(()),
        }
    };
}

/// Convert an errno-positive-int-success return pattern into a `Result<std::os::raw::c_int, LibcryptErr>`
macro_rules! errno_int_success {
    ( $rc:expr ) => {
        match $rc {
            i if i < 0 => {
                return Err($crate::err::LibcryptErr::IOError(
                    std::io::Error::from_raw_os_error(-i),
                ))
            }
            i => Result::<_, $crate::err::LibcryptErr>::Ok(i),
        }
    };
}

/// Convert an integer return value into specified type
macro_rules! int_to_return {
    ( $rc:expr, $type:ty ) => {
        <$type>::from($rc)
    };
}

/// Try converting an integer return value into specified type
macro_rules! try_int_to_return {
    ( $rc:expr, $type:ty ) => {
        <$type>::try_from($rc)
    };
}

/// Convert a pointer to an `Option` containing a pointer
macro_rules! ptr_to_option {
    ( $ptr:expr ) => {{
        let p = $ptr;
        if p.is_null() {
            None
        } else {
            Some(p)
        }
    }};
}

/// Convert a pointer to a `Option` containing a reference
macro_rules! ptr_to_option_with_reference {
    ( $ptr:expr ) => {{
        let p = $ptr;
        unsafe { p.as_ref() }
    }};
}

/// Convert a pointer to an `Result` containing a pointer
macro_rules! ptr_to_result {
    ( $ptr:expr ) => {{
        ptr_to_option!($ptr).ok_or($crate::err::LibcryptErr::NullPtr)
    }};
}

/// Convert a pointer to a `Result` containing a reference
macro_rules! ptr_to_result_with_reference {
    ( $ptr:expr ) => {{
        let p = $ptr;
        unsafe { p.as_ref() }.ok_or($crate::err::LibcryptErr::NullPtr)
    }};
}

/// Convert a `Path` type into `CString`
macro_rules! path_to_cstring {
    ( $path:expr ) => {
        match $path
            .to_str()
            .ok_or_else(|| LibcryptErr::InvalidConversion)
            .and_then(|s| std::ffi::CString::new(s).map_err(LibcryptErr::NullError))
        {
            Ok(s) => Ok(s),
            Err(e) => Err(e),
        }
    };
}

/// Convert a string type into `CString`
macro_rules! to_cstring {
    ( $str:expr ) => {
        match std::ffi::CString::new($str.as_bytes()) {
            Ok(s) => Ok(s),
            Err(e) => Err($crate::err::LibcryptErr::NullError(e)),
        }
    };
}

/// Convert a byte slice into `*const c_char`
macro_rules! to_byte_ptr {
    ( $bytes:expr ) => {
        $bytes.as_ptr().cast::<std::os::raw::c_char>()
    };
}

/// Convert a byte slice into `*mut c_char`
macro_rules! to_mut_byte_ptr {
    ( $bytes:expr ) => {
        $bytes.as_mut_ptr().cast::<std::os::raw::c_char>()
    };
}

/// Convert a `*const c_char` into a `&str` type
#[macro_export]
macro_rules! from_str_ptr {
    ( $str_ptr:expr ) => {
        unsafe { ::std::ffi::CStr::from_ptr($str_ptr) }
            .to_str()
            .map_err($crate::LibcryptErr::Utf8Error)
    };
}

/// Convert a `*const c_char` into a `String` type
macro_rules! from_str_ptr_to_owned {
    ( $str_ptr:expr ) => {
        unsafe { ::std::ffi::CStr::from_ptr($str_ptr) }
            .to_str()
            .map_err($crate::err::LibcryptErr::Utf8Error)
            .map(|s| s.to_string())
    };
}

/// Convert constants to and from a flag enum
macro_rules! consts_to_from_enum {
    ( #[$meta:meta] $flag_enum:ident, $flag_type:ty, $( $name:ident => $constant:expr ),* ) => {
        #[$meta]
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        pub enum $flag_enum {
            $(
                #[allow(missing_docs)]
                $name,
            )*
        }

        #[allow(clippy::from_over_into)]
        impl std::convert::Into<$flag_type> for $flag_enum {
            fn into(self) -> $flag_type {
                match self {
                    $(
                        $flag_enum::$name => $constant,
                    )*
                }
            }
        }

        impl std::convert::TryFrom<$flag_type> for $flag_enum {
            type Error = $crate::err::LibcryptErr;

            fn try_from(v: $flag_type) -> Result<Self, Self::Error> {
                Ok(match v {
                    $(
                        i if i == $constant => $flag_enum::$name,
                    )*
                    _ => return Err($crate::err::LibcryptErr::InvalidConversion),
                })
            }
        }
    };
}

#[macro_export]
/// Create a C-compatible static string with a null byte
macro_rules! c_str {
    ( $str:tt ) => {
        concat!($str, "\0")
    };
}

#[macro_export]
/// Create a C-compatible callback to determine user confirmation which wraps safe Rust code
macro_rules! c_confirm_callback {
    ( $fn_name:ident, $type:ty, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(
            msg: *const std::os::raw::c_char,
            usrptr: *mut std::os::raw::c_void,
        ) -> std::os::raw::c_int {
            let msg_str =
                $crate::from_str_ptr!(msg).expect("Invalid message string passed to cryptsetup-rs");
            let generic_ptr = usrptr.cast::<$type>();
            let generic_ref = unsafe { generic_ptr.as_mut() };

            $safe_fn_name(msg_str, generic_ref) as std::os::raw::c_int
        }
    };
}

#[macro_export]
/// Create a C-compatible logging callback which wraps safe Rust code
macro_rules! c_logging_callback {
    ( $fn_name:ident, $type:ty, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(
            level: std::os::raw::c_int,
            msg: *const std::os::raw::c_char,
            usrptr: *mut std::os::raw::c_void,
        ) {
            let level = <$crate::consts::vals::CryptLogLevel as std::convert::TryFrom<
                std::os::raw::c_int,
            >>::try_from(level)
            .expect("Invalid logging level passed to cryptsetup-rs");
            let msg_str = $crate::from_str_ptr!(msg)
                .expect("Invalid message string passed to cryptsetup-rs")
                .trim();
            let generic_ptr = usrptr.cast::<$type>();
            let generic_ref = unsafe { generic_ptr.as_mut() };

            $safe_fn_name(level, msg_str, generic_ref);
        }
    };
}

#[macro_export]
/// Create a C-compatible progress callback for wiping a device which wraps safe Rust code
macro_rules! c_progress_callback {
    ( $fn_name:ident, $type:ty, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(
            size: u64,
            offset: u64,
            usrptr: *mut std::os::raw::c_void,
        ) -> std::os::raw::c_int {
            let generic_ptr = usrptr.cast::<$type>();
            let generic_ref = unsafe { generic_ptr.as_mut() };

            $safe_fn_name(size, offset, generic_ref) as std::os::raw::c_int
        }
    };
}

#[macro_export]
/// Create a C-compatible open callback compatible with `CryptTokenHandler`
macro_rules! c_token_handler_open {
    ( $fn_name:ident, $type:ty, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(
            cd: *mut libcryptsetup_rs_sys::crypt_device,
            token_id: std::os::raw::c_int,
            buffer: *mut *mut std::os::raw::c_char,
            buffer_len: *mut $crate::SizeT,
            usrptr: *mut std::os::raw::c_void,
        ) -> std::os::raw::c_int {
            let device = $crate::device::CryptDevice::from_ptr(cd);
            let generic_ptr = usrptr as *mut $type;
            let generic_ref = unsafe { generic_ptr.as_mut() };

            let buffer: Result<Box<[u8]>, $crate::LibcryptErr> =
                $safe_fn_name(device, token_id, generic_ref);
            match buffer {
                Ok(()) => {
                    *buffer = Box::into_raw(buffer) as *mut std::os::raw::c_char;
                    0
                }
                Err(_) => -1,
            }
        }
    };
}

#[macro_export]
/// Create a C-compatible callback for free compatible with `CryptTokenHandler`
macro_rules! c_token_handler_free {
    ( $fn_name:ident, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(buffer: *mut std::os::raw::c_void, buffer_len: $crate::SizeT) {
            let boxed_slice = unsafe {
                Box::from_raw(std::slice::from_raw_parts_mut(
                    buffer as *mut u8,
                    buffer_len as usize,
                ))
            };

            $safe_fn_name(boxed_slice)
        }
    };
}

#[macro_export]
/// Create a C-compatible callback for validate compatible with `CryptTokenHandler`
macro_rules! c_token_handler_validate {
    ( $fn_name:ident, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(
            cd: *mut libcryptsetup_rs_sys::crypt_device,
            json: *mut std::os::raw::c_char,
        ) -> std::os::raw::c_int {
            let device = $crate::device::CryptDevice::from_ptr(cd);
            let s = match $crate::from_str_ptr!(json) {
                Ok(s) => s,
                Err(_) => return -1,
            };
            let json_obj = match serde_json::from_str(s) {
                Ok(j) => j,
                Err(_) => return -1,
            };

            let rc: Result<(), $crate::LibcryptErr> = $safe_fn_name(device, json_obj);
            match rc {
                Ok(()) => 0,
                Err(_) => -1,
            }
        }
    };
}

#[macro_export]
/// Create a C-compatible callback for compatible with `CryptTokenHandler`
macro_rules! c_token_handler_dump {
    ( $fn_name:ident, $safe_fn_name:ident ) => {
        extern "C" fn $fn_name(
            cd: *mut libcryptsetup_rs_sys::crypt_device,
            json: *mut std::os::raw::c_char,
        ) {
            let device = $crate::device::CryptDevice::from_ptr(cd);
            let s = match $crate::from_str_ptr!(json) {
                Ok(s) => s,
                Err(_) => return,
            };
            let json_obj = match serde_json::from_str(s) {
                Ok(j) => j,
                Err(_) => return,
            };

            $safe_fn_name(device, json_obj)
        }
    };
}

#[cfg(test)]
mod test {
    use crate::consts::vals::CryptLogLevel;

    fn safe_confirm_callback(_msg: &str, usrdata: Option<&mut u32>) -> bool {
        *usrdata.unwrap() != 0
    }

    c_confirm_callback!(confirm_callback, u32, safe_confirm_callback);

    fn safe_logging_callback(_level: CryptLogLevel, _msg: &str, _usrdata: Option<&mut u32>) {}

    c_logging_callback!(logging_callback, u32, safe_logging_callback);

    fn safe_progress_callback(_size: u64, _offset: u64, usrdata: Option<&mut u32>) -> bool {
        *usrdata.unwrap() != 0
    }

    c_progress_callback!(progress_callback, u32, safe_progress_callback);

    #[test]
    fn test_c_confirm_callback() {
        let ret = confirm_callback(
            "\0".as_ptr().cast::<std::os::raw::c_char>(),
            (&mut 1u32 as *mut u32).cast::<std::os::raw::c_void>(),
        );
        assert_eq!(1, ret);

        let ret = confirm_callback(
            "\0".as_ptr().cast::<std::os::raw::c_char>(),
            (&mut 0u32 as *mut u32).cast::<std::os::raw::c_void>(),
        );
        assert_eq!(0, ret);
    }

    #[test]
    fn test_c_logging_callback() {
        logging_callback(
            libcryptsetup_rs_sys::CRYPT_LOG_ERROR as i32,
            "\0".as_ptr().cast::<std::os::raw::c_char>(),
            (&mut 1u32 as *mut u32).cast::<std::os::raw::c_void>(),
        );

        logging_callback(
            libcryptsetup_rs_sys::CRYPT_LOG_DEBUG,
            "\0".as_ptr().cast::<std::os::raw::c_char>(),
            (&mut 0u32 as *mut u32).cast::<std::os::raw::c_void>(),
        );
    }

    #[test]
    fn test_c_progress_callback() {
        let ret = progress_callback(0, 0, (&mut 1u32 as *mut u32).cast::<std::os::raw::c_void>());
        assert_eq!(1, ret);

        let ret = progress_callback(0, 0, (&mut 0u32 as *mut u32).cast::<std::os::raw::c_void>());
        assert_eq!(0, ret);
    }

    consts_to_from_enum!(
        /// An enum for testing `PartialEq`
        PETestEnum,
        u16,
        This => 0,
        Can => 1,
        Use => 2,
        PartialEq => 3
    );

    #[test]
    fn test_enum_partial_eq() {
        assert_eq!(PETestEnum::This, PETestEnum::try_from(0).unwrap());
        assert_eq!(PETestEnum::Can, PETestEnum::try_from(1).unwrap());
        assert_eq!(PETestEnum::Use, PETestEnum::try_from(2).unwrap());
        assert_eq!(PETestEnum::PartialEq, PETestEnum::try_from(3).unwrap());
    }

    #[cfg(not(feature = "mutex"))]
    #[test]
    #[should_panic(expected = "Enable the mutex feature")]
    fn test_multiple_threads_no_mutex_feature() {
        std::thread::spawn(|| {
            crate::get_sector_size(None);
        })
        .join()
        .unwrap();
        crate::get_sector_size(None);
    }
}
