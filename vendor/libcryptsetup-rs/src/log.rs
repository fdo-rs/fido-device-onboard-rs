// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    os::raw::{c_char, c_int, c_void},
    ptr,
};

use crate::{consts::vals::CryptLogLevel, err::LibcryptErr};

type LoggingCallback = unsafe extern "C" fn(level: c_int, msg: *const c_char, usrptr: *mut c_void);

/// Generate a log entry
pub fn log(level: CryptLogLevel, msg: &str) -> Result<(), LibcryptErr> {
    let msg_cstring = to_cstring!(msg)?;
    mutex!(libcryptsetup_rs_sys::crypt_log(
        ptr::null_mut(),
        level as c_int,
        msg_cstring.as_ptr(),
    ));
    Ok(())
}

/// Set the callback to be executed on logging events
pub fn set_log_callback<T>(callback: Option<LoggingCallback>, usrdata: Option<&mut T>) {
    mutex!(libcryptsetup_rs_sys::crypt_set_log_callback(
        ptr::null_mut(),
        callback,
        match usrdata {
            Some(ud) => (ud as *mut T).cast::<c_void>(),
            None => ptr::null_mut(),
        },
    ))
}
