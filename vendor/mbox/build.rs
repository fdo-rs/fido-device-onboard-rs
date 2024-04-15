extern crate rustc_version;

use rustc_version::{version_meta, Channel};

pub fn main() {
    let meta = version_meta().unwrap();

    if let Channel::Dev | Channel::Nightly = meta.channel {
        println!("cargo:rustc-cfg=feature=\"nightly\"");
    }
}
