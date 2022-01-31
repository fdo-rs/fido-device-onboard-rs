use libc::c_char;
use std::{
    ffi::CString,
    ptr::{null, null_mut},
    slice,
};

use fdo_data_formats::Serializable;
pub use fdo_data_formats::{ownershipvoucher::OwnershipVoucher, DeserializableMany};

use super::{clear_last_error, set_last_error};

/// A list of Ownership Vouchers
#[repr(C)]
pub struct OwnershipVoucherList {
    contents: Box<[OwnershipVoucher]>,
}

#[no_mangle]
/// Returns a single Ownership Voucher from a list of Ownership Vouchers
///
/// Note: the return Ownership Voucher is still owned by the list, and should
/// *NOT* be freed by the caller.
///
/// Return value:
/// NULL if index is out of bounds
/// Pointer to an OwnershipVoucher on success
pub extern "C" fn fdo_ownershipvoucher_list_get(
    list: *const OwnershipVoucherList,
    index: u64,
) -> *const OwnershipVoucher {
    clear_last_error();

    if list.is_null() {
        set_last_error("fdo_ownership_voucher_list_get_item: list is null");
        return null();
    }

    let list = unsafe { &*list };

    list.contents
        .get(index as usize)
        .map_or(null(), |item| item as *const _)
}

#[no_mangle]
/// Returns the length of an Ownership Voucher List
pub extern "C" fn fdo_ownershipvoucher_list_len(list: *const OwnershipVoucherList) -> u64 {
    clear_last_error();

    if list.is_null() {
        set_last_error("fdo_ownership_voucher_list_len: list is null");
        return 0;
    }

    let list = unsafe { &*list };

    list.contents.len() as u64
}

#[no_mangle]
/// Frees an Ownership Voucher List
pub extern "C" fn fdo_ownershipvoucher_list_free(list: *mut OwnershipVoucherList) {
    clear_last_error();

    if list.is_null() {
        set_last_error("fdo_ownership_voucher_list_free: list is null");
        return;
    }

    unsafe {
        drop(Box::from_raw(list));
    }
}

#[no_mangle]
/// Creates an Ownership Voucher List from raw data of appended vouchers
///
/// Return value:
/// NULL on error (last error is set)
/// Pointer to an OwnershipVoucherList on success
pub extern "C" fn fdo_ownershipvoucher_many_from_data(
    data: *const std::ffi::c_void,
    len: libc::size_t,
) -> *const OwnershipVoucherList {
    clear_last_error();

    if data.is_null() {
        set_last_error("fdo_ownershipvoucher_many_from_data: data is null");
        return null();
    }

    let data = unsafe { slice::from_raw_parts(data as *const u8, len) };

    match OwnershipVoucher::deserialize_many_from_reader(data) {
        Ok(contents) => {
            let contents = Box::new(contents);
            Box::into_raw(Box::new(OwnershipVoucherList {
                contents: contents.into_boxed_slice(),
            }))
        }
        Err(err) => {
            set_last_error(err);
            null()
        }
    }
}

#[no_mangle]
/// Creates a new OwnershipVoucher from raw data
///
/// Return value:
/// NULL on error (last error is set)
/// Pointer to an FdoOwnershipVoucher on success
pub extern "C" fn fdo_ownershipvoucher_from_data(
    data: *const std::ffi::c_void,
    len: libc::size_t,
) -> *mut OwnershipVoucher {
    clear_last_error();

    if data.is_null() {
        set_last_error("fdo_ownershipvoucher_from_data: data is null");

        return null_mut();
    }
    let data = unsafe { slice::from_raw_parts(data as *const u8, len) };
    match OwnershipVoucher::deserialize_data(data) {
        Ok(voucher) => Box::into_raw(Box::new(voucher)),
        Err(e) => {
            set_last_error(e);
            null_mut()
        }
    }
}

#[no_mangle]
/// Frees an OwnershipVoucher
pub extern "C" fn fdo_ownershipvoucher_free(v: *mut OwnershipVoucher) {
    clear_last_error();

    if v.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(v));
    }
}

#[no_mangle]
/// Returns the protocol version in the ownership voucher
///
/// Return value:
/// -1 on error (last error is set)
/// protocol version on success
pub extern "C" fn fdo_ownershipvoucher_header_get_protocol_version(
    v: *const OwnershipVoucher,
) -> i32 {
    clear_last_error();

    if v.is_null() {
        return -1;
    }
    let voucher = unsafe { &*v };
    voucher.header().protocol_version() as i32
}

#[no_mangle]
/// Returns the GUID of the ownership voucher
///
/// Return value:
/// NULL on error (last error is set)
/// Pointer to a string containing the GUID on success
///
/// Note: The returned string ownership is transferred to the caller, and should
/// be freed with `fdo_free_string`
pub extern "C" fn fdo_ownershipvoucher_header_get_guid(
    v: *const OwnershipVoucher,
) -> *const c_char {
    clear_last_error();

    if v.is_null() {
        return null();
    }
    let voucher = unsafe { &*v };
    let guid = voucher.header().guid().to_string();
    match CString::new(guid) {
        Err(_) => null(),
        Ok(cstr) => cstr.into_raw(),
    }
}

#[no_mangle]
/// Returns the device info of the ownership voucher if it is a string
///
/// Return value:
/// NULL on error or if Device Info is not a string
/// Pointer to a string containing the Device Info on success
///
/// Note: The returned string ownership is transferred to the caller, and should
/// be freed with `fdo_free_string`
pub extern "C" fn fdo_ownershipvoucher_header_get_device_info_string(
    v: *const OwnershipVoucher,
) -> *const c_char {
    clear_last_error();

    if v.is_null() {
        return null();
    }
    let voucher = unsafe { &*v };
    match CString::new(voucher.header().device_info()) {
        Err(e) => {
            set_last_error(e);
            null()
        }
        Ok(cstr) => cstr.into_raw(),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_common as TC;
    use crate::test_common::OutputExt;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_ownershipvoucher_parsing() {
        let ov_path = TC::test_asset_path("testdevice1.ov");

        let result = TC::run_external("ownershipvoucher", &[ov_path.to_str().unwrap()]);

        assert!(result.status.success());
        result.stdout_equals(
            "Protocol version: 101
Device GUID: 18907279-a41d-049a-ae3c-4da4ce61c14b
Device Info: testdevice",
        );
        result.stderr_equals("");
    }

    #[test]
    #[serial]
    fn test_ownershipvoucher_parsing_many() {
        let ov_path = TC::test_asset_path("testdevice1.ov");
        let ov_path = ov_path.to_str().unwrap();

        let result = TC::run_external("ownershipvoucher_many", &[&ov_path, &ov_path]);

        assert!(result.status.success());
        result.stdout_equals(
            "Device 0
    Protocol version: 101
    Device GUID: 18907279-a41d-049a-ae3c-4da4ce61c14b
    Device Info: testdevice
Device 1
    Protocol version: 101
    Device GUID: 18907279-a41d-049a-ae3c-4da4ce61c14b
    Device Info: testdevice",
        );
        result.stderr_equals("");
    }

    #[test]
    #[serial]
    fn dont_crash_on_empty_ov() {
        let result = TC::run_external("ownershipvoucher", &["/dev/null"]);

        assert!(result.status.success());
        result.stdout_equals("failed to parse: Array parse error: No data to be deserialized");
        result.stderr_equals("");
    }
}
