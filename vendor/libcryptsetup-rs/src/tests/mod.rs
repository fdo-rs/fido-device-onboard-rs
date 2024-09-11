// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::env::var;

pub mod encrypt;
pub mod keyfile;
pub mod loopback;

fn format_with_zeros() -> bool {
    var("FORMAT_WITH_ZEROS")
        .ok()
        .and_then(|env| env.parse::<bool>().ok())
        .unwrap_or(true)
}

fn do_cleanup() -> bool {
    var("DO_CLEANUP")
        .ok()
        .and_then(|env| env.parse::<bool>().ok())
        .unwrap_or(true)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_format_with_zeros() {
        std::env::remove_var("FORMAT_WITH_ZEROS");
        assert!(format_with_zeros());
        std::env::set_var("FORMAT_WITH_ZEROS", "false");
        assert!(!format_with_zeros());
        std::env::remove_var("FORMAT_WITH_ZEROS");
    }

    #[test]
    fn test_do_cleanup() {
        std::env::remove_var("DO_CLEANUP");
        assert!(do_cleanup());
        std::env::set_var("DO_CLEANUP", "false");
        assert!(!do_cleanup());
        std::env::remove_var("DO_CLEANUP");
    }
}
