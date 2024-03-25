// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    error::Error,
    ffi::NulError,
    fmt::{self, Display},
    io,
    str::Utf8Error,
};

#[derive(Debug)]
/// Error returned from any libcryptsetup-rs function
pub enum LibcryptErr {
    /// Wrapper for `io::Error`
    IOError(io::Error),
    /// Wrapper for `uuid::parser::ParseError`
    UuidError(uuid::Error),
    /// Wrapper for `ffi::NulError`
    NullError(NulError),
    /// Wrapper for `str::Utf8Error`
    Utf8Error(Utf8Error),
    /// Wrapper for `serde_json::Error`
    JsonError(serde_json::Error),
    /// Indicates that a Rust/C conversion was unsuccessful
    InvalidConversion,
    /// Indicates that a pointer returned was null signifying an error
    NullPtr,
    /// Indicates that a `&'static str` was not created with `c_str!()` macro
    NoNull(&'static str),
    /// Custom message
    Other(String),
}

impl Display for LibcryptErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            LibcryptErr::IOError(ref e) => write!(f, "IO error occurred: {e}"),
            LibcryptErr::UuidError(ref e) => write!(f, "Failed to parse UUID from C string: {e}"),
            LibcryptErr::NullError(ref e) => {
                write!(f, "Null error occurred when handling &str conversion: {e}")
            }
            LibcryptErr::Utf8Error(ref e) => {
                write!(f, "UTF8 error occurred when handling &str conversion: {e}")
            }
            LibcryptErr::JsonError(ref e) => {
                write!(f, "Failed to parse the provided string into JSON: {e}")
            }
            LibcryptErr::InvalidConversion => {
                write!(f, "Failed to perform the specified conversion")
            }
            LibcryptErr::NullPtr => write!(f, "Cryptsetup returned a null pointer"),
            LibcryptErr::NoNull(s) => {
                write!(f, "Static string {s} was not created with c_str!() macro")
            }
            LibcryptErr::Other(ref s) => write!(f, "Failed with error: {s}"),
        }
    }
}

impl Error for LibcryptErr {}
