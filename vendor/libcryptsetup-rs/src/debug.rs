// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::consts::vals::CryptDebugLevel;

/// Set library debug level
pub fn set_debug_level(level: CryptDebugLevel) {
    mutex!(libcryptsetup_rs_sys::crypt_set_debug_level(level.into()))
}
