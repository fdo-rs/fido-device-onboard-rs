use libc::c_char;
use std::ffi::CString;

#[cfg(test)]
mod test_common;

mod ownershipvoucher;

/// Free a string returned by libfdo-data functions
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn fdo_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(CString::from_raw(s));
}
