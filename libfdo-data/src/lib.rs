use libc::c_char;
use std::{ffi::CString, ptr::null_mut};

#[cfg(test)]
mod test_common;

mod ownershipvoucher;

static mut LAST_ERROR: Option<String> = None;

fn clear_last_error() {
    unsafe {
        LAST_ERROR = None;
    }
}

fn set_last_error<T>(err: T)
where
    T: ToString,
{
    unsafe {
        LAST_ERROR = Some(err.to_string());
    }
}

/// Free a string returned by libfdo-data functions
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn fdo_free_string(s: *mut c_char) {
    clear_last_error();

    if s.is_null() {
        return;
    }
    drop(CString::from_raw(s));
}

/// Returns a string describing the last error that occured
///
/// Note: The returned string ownership is transferred to the caller, and should
/// be freed with `fdo_free_string`
#[no_mangle]
pub extern "C" fn fdo_get_last_error() -> *mut c_char {
    match unsafe { &LAST_ERROR } {
        None => null_mut(),
        Some(e) => CString::new(e.as_bytes()).unwrap().into_raw(),
    }
}
