// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    env,
    fs::{remove_file, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

use base64::Engine;
use loopdev::LoopControl;
use rand::random;

use crate::err::LibcryptErr;

fn setup_backing_file(size_in_bytes: usize, with_zeros: bool) -> Result<PathBuf, io::Error> {
    let mut i = 0;

    let b64_string = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::GeneralPurposeConfig::new().with_encode_padding(false),
    )
    .encode(random::<[u8; 12]>());
    let directory = PathBuf::from(env::var("TEST_DIR").unwrap_or_else(|_| "/tmp".to_string()));
    assert!(directory.exists() && directory.is_dir());
    let mut file_path = PathBuf::new();
    file_path.push(directory);
    file_path.push(b64_string);

    let mut f = File::create(&file_path)?;
    while i < size_in_bytes {
        let len = if with_zeros {
            f.write(&[0; 4096])?
        } else {
            let buf: Vec<_> = (0..4096).map(|_| random::<u8>()).collect();
            f.write(&buf)?
        };
        assert_eq!(len, 4096);
        i += len;
    }
    Ok(file_path)
}

pub fn use_loopback<F>(
    file_size: usize,
    with_zeros: bool,
    cleanup: bool,
    func: F,
) -> Result<(), LibcryptErr>
where
    F: Fn(&Path, &Path) -> Result<(), LibcryptErr>,
{
    if !nix::unistd::Uid::effective().is_root() {
        panic!("Must be root to run tests");
    }
    let ctrl = LoopControl::open();
    let dev = ctrl
        .and_then(|ref c| c.next_free())
        .map_err(LibcryptErr::IOError)?;

    let path = setup_backing_file(file_size, with_zeros).map_err(LibcryptErr::IOError)?;
    let attach_result = dev.attach_file(&path);
    let test_result = attach_result
        .map_err(LibcryptErr::IOError)
        .and_then(|_| match dev.path() {
            Some(ref d) => func(d, &path),
            _ => Err(LibcryptErr::IOError(io::Error::from(
                io::ErrorKind::NotFound,
            ))),
        });
    let detach_result = if cleanup { dev.detach() } else { Ok(()) };
    detach_result
        .and_then(|_| if cleanup { remove_file(&path) } else { Ok(()) })
        .map_err(LibcryptErr::IOError)
        .and(test_result)
}
