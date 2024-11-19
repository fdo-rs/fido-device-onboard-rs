use std::{env, fs::File, io::Write, path::PathBuf};

use super::loopback;

use crate::{consts::flags::CryptKeyfile, CryptInit, LibcryptErr};

pub fn test_keyfile_cleanup() {
    loopback::use_loopback(
        50 * 1024 * 1024,
        super::format_with_zeros(),
        super::do_cleanup(),
        |dev_path, _file_path| {
            let mut device = CryptInit::init(dev_path)?;
            let mut key_path =
                PathBuf::from(env::var("TEST_DIR").unwrap_or_else(|_| "/tmp".to_string()));
            key_path.push("safe-free-test-keyfile");
            let mut f = File::create(&key_path).map_err(LibcryptErr::IOError)?;
            f.write(b"this is a test password")
                .map_err(LibcryptErr::IOError)?;
            let keyfile_contents =
                device
                    .keyfile_handle()
                    .device_read(&key_path, 0, None, CryptKeyfile::empty());
            std::fs::remove_file(&key_path).map_err(LibcryptErr::IOError)?;
            let (keyfile_ptr, keyfile_len) = {
                let keyfile_contents = keyfile_contents?;

                let keyfile_ref = keyfile_contents.as_ref();
                assert_eq!(keyfile_ref, b"this is a test password" as &[u8]);

                (keyfile_ref.as_ptr(), keyfile_ref.len())
            };

            let dangling_buffer =
                unsafe { std::slice::from_raw_parts(keyfile_ptr.cast::<u8>(), keyfile_len) };
            if dangling_buffer == b"this is a test password" {
                panic!("Key was not cleaned up!");
            }

            Ok(())
        },
    )
    .expect("Should succeed");
}
