// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use libcryptsetup_rs::c_confirm_callback;

fn safe_confirm_callback(_msg: &str, usrdata: Option<&mut u32>) -> bool {
    *usrdata.unwrap() != 0
}

c_confirm_callback!(confirm_callback, u32, safe_confirm_callback);

fn main() {
    assert!(
        confirm_callback(
            "Would you like to proceed?\0"
                .as_ptr()
                .cast::<libc::c_char>(),
            (&mut 0u32 as *mut u32).cast::<libc::c_void>(),
        ) == 0
    )
}
