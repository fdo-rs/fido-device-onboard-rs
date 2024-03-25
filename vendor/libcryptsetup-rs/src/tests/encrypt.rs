// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    path::{Path, PathBuf},
    ptr, slice,
};

use crate::{
    consts::{
        flags::{CryptActivate, CryptDeactivate, CryptKeyfile, CryptVolumeKey},
        vals::EncryptionFormat,
    },
    device::CryptInit,
    err::LibcryptErr,
    tests::loopback,
    Either,
};

use libc::c_uint;
use rand::random;

/// Size of the sliding window used to search for random bytes on encrypted
/// and unencrypted devices.
const WINDOW_SIZE: usize = 1024 * 1024;

fn init(dev_path: &Path, passphrase: &str) -> Result<c_uint, LibcryptErr> {
    let mut dev = CryptInit::init(dev_path)?;
    dev.context_handle().format::<()>(
        EncryptionFormat::Luks2,
        ("aes", "xts-plain"),
        None,
        Either::Right(512 / 8),
        None,
    )?;
    dev.keyslot_handle()
        .add_by_key(None, None, passphrase.as_bytes(), CryptVolumeKey::empty())
}

/// This method initializes the device with no encryption as a way to test
/// that the plaintext can be read vs. the plaintext not being found due to
/// proper encryption in the other tests.
fn init_null_cipher(dev_path: &Path) -> Result<c_uint, LibcryptErr> {
    let mut dev = CryptInit::init(dev_path)?;
    dev.context_handle().format::<()>(
        EncryptionFormat::Luks1,
        ("cipher_null", "ecb"),
        None,
        Either::Right(32),
        None,
    )?;
    dev.keyslot_handle().add_by_passphrase(None, b"", b"")
}

fn init_by_keyfile(dev_path: &Path, keyfile_path: &Path) -> Result<c_uint, LibcryptErr> {
    let mut dev = CryptInit::init(dev_path)?;
    dev.context_handle().format::<()>(
        EncryptionFormat::Luks2,
        ("aes", "xts-plain"),
        None,
        Either::Right(512 / 8),
        None,
    )?;
    let keyfile_contents = {
        let mut kf_handle = dev.keyfile_handle();
        kf_handle.device_read(keyfile_path, 0, None, CryptKeyfile::empty())?
    };
    dev.keyslot_handle().add_by_key(
        None,
        None,
        keyfile_contents.as_ref(),
        CryptVolumeKey::empty(),
    )
}

fn activate_without_explicit_format(
    dev_path: &Path,
    device_name: &'static str,
    keyslot: c_uint,
    passphrase: &'static str,
) -> Result<(), LibcryptErr> {
    let mut dev = CryptInit::init(dev_path)?;
    dev.context_handle().load::<()>(None, None)?;
    dev.activate_handle().activate_by_passphrase(
        Some(device_name),
        Some(keyslot),
        passphrase.as_bytes(),
        CryptActivate::empty(),
    )?;
    Ok(())
}

fn activate_by_passphrase(
    dev_path: &Path,
    device_name: &'static str,
    keyslot: c_uint,
    passphrase: &'static str,
) -> Result<(), LibcryptErr> {
    let mut dev = CryptInit::init(dev_path)?;
    dev.context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)?;
    dev.activate_handle().activate_by_passphrase(
        Some(device_name),
        Some(keyslot),
        passphrase.as_bytes(),
        CryptActivate::empty(),
    )?;
    Ok(())
}

fn create_keyfile(loopback_file_path: &Path) -> Result<PathBuf, LibcryptErr> {
    let path = PathBuf::from(format!("{}-key", loopback_file_path.display()));
    let mut f = File::create(&path).map_err(LibcryptErr::IOError)?;
    let random: Vec<_> = (0..4096).map(|_| random::<u8>()).collect();
    f.write(&random).map_err(LibcryptErr::IOError)?;
    Ok(path)
}

fn activate_by_keyfile(
    dev_path: &Path,
    device_name: &'static str,
    keyslot: c_uint,
    keyfile_path: &Path,
    keyfile_size: Option<crate::size_t>,
) -> Result<(), LibcryptErr> {
    let mut dev = CryptInit::init(dev_path)?;
    dev.context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)?;
    dev.activate_handle().activate_by_keyfile_device_offset(
        Some(device_name),
        Some(keyslot),
        keyfile_path,
        keyfile_size,
        0,
        CryptActivate::empty(),
    )?;
    Ok(())
}

fn activate_null_cipher(dev_path: &Path, device_name: &'static str) -> Result<(), LibcryptErr> {
    let mut dev = CryptInit::init(dev_path)?;
    dev.context_handle().load::<()>(None, None)?;
    dev.activate_handle().activate_by_passphrase(
        Some(device_name),
        None,
        b"",
        CryptActivate::empty(),
    )?;
    Ok(())
}

fn write_random(device_name: &str) -> Result<Box<[u8]>, io::Error> {
    let mapped_device_path = PathBuf::from(format!("/dev/mapper/{device_name}"));
    let mut random_buffer = Box::new([0; WINDOW_SIZE]);
    File::open("/dev/urandom")?.read_exact(&mut (*random_buffer))?;
    let mut device = OpenOptions::new().write(true).open(mapped_device_path)?;
    device.write_all(random_buffer.as_ref())?;
    Ok(random_buffer)
}

fn test_existence(file_path: &Path, buffer: &[u8]) -> Result<bool, io::Error> {
    let file_path_cstring =
        CString::new(file_path.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Failed to convert path to string")
        })?)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let fd = unsafe { libc::open(file_path_cstring.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut stat: MaybeUninit<libc::stat> = MaybeUninit::zeroed();
    let fstat_result = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
    if fstat_result < 0 {
        return Err(io::Error::last_os_error());
    }
    let device_size = unsafe { stat.assume_init() }.st_size as usize;
    let mapped_ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            device_size,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if mapped_ptr.is_null() {
        return Err(io::Error::new(io::ErrorKind::Other, "mmap failed"));
    }

    {
        let disk_bytes = unsafe { slice::from_raw_parts(mapped_ptr as *const u8, device_size) };
        for chunk in disk_bytes.windows(WINDOW_SIZE) {
            if chunk == buffer {
                unsafe {
                    libc::munmap(mapped_ptr, device_size);
                    libc::close(fd);
                }
                return Ok(true);
            }
        }
    }

    unsafe {
        libc::munmap(mapped_ptr, device_size);
        libc::close(fd);
    }
    Ok(false)
}

/// Run a test on whether the plaintext could be found or not. Return a boolean
/// as we actually want to see the plaintext in some cases and not in others.
fn run_plaintext_test(dev_path: &Path, device_name: &str) -> Result<bool, LibcryptErr> {
    let write_result = write_random(device_name);

    if super::do_cleanup() {
        let mut dev = CryptInit::init_by_name_and_header(device_name, None)?;
        dev.activate_handle()
            .deactivate(device_name, CryptDeactivate::empty())?;
    }

    let buffer = write_result.map_err(|e| LibcryptErr::Other(e.to_string()))?;

    test_existence(dev_path, &buffer).map_err(|e| LibcryptErr::Other(e.to_string()))
}

pub fn test_encrypt_by_password() {
    loopback::use_loopback(
        1024 * 1024 * 1024,
        super::format_with_zeros(),
        super::do_cleanup(),
        |dev_path, file_path| {
            let device_name = "test-device";
            let passphrase = "abadpassphrase";

            let keyslot = init(dev_path, passphrase)?;
            activate_by_passphrase(dev_path, device_name, keyslot, passphrase)?;
            if run_plaintext_test(file_path, device_name)? {
                return Err(LibcryptErr::Other("Should not find plaintext".to_string()));
            }

            Ok(())
        },
    )
    .expect("Should succeed");
}

pub fn test_encrypt_by_keyfile() {
    loopback::use_loopback(
        1024 * 1024 * 1024,
        super::format_with_zeros(),
        super::do_cleanup(),
        |dev_path, file_path| {
            let device_name = "test-device";

            let keyfile_path = create_keyfile(file_path)?;
            let keyslot = init_by_keyfile(dev_path, keyfile_path.as_path())?;
            activate_by_keyfile(dev_path, device_name, keyslot, keyfile_path.as_path(), None)?;
            if run_plaintext_test(file_path, device_name)? {
                return Err(LibcryptErr::Other("Should not find plaintext".to_string()));
            }

            Ok(())
        },
    )
    .expect("Should succeed");
}

pub fn test_encrypt_by_password_without_explicit_format() {
    loopback::use_loopback(
        1024 * 1024 * 1024,
        super::format_with_zeros(),
        super::do_cleanup(),
        |dev_path, file_path| {
            let device_name = "test-device";
            let passphrase = "abadpassphrase";

            let keyslot = init(dev_path, passphrase)?;
            activate_without_explicit_format(dev_path, device_name, keyslot, passphrase)?;
            if run_plaintext_test(file_path, device_name)? {
                return Err(LibcryptErr::Other("Should not find plaintext".to_string()));
            }

            Ok(())
        },
    )
    .expect("Should succeed");
}

pub fn test_unencrypted() {
    loopback::use_loopback(
        1024 * 1024 * 1024,
        super::format_with_zeros(),
        super::do_cleanup(),
        |dev_path, file_path| {
            let device_name = "test-device";

            init_null_cipher(dev_path)?;
            activate_null_cipher(dev_path, device_name)?;
            if !run_plaintext_test(file_path, device_name)? {
                return Err(LibcryptErr::Other("Should find plaintext".to_string()));
            }

            Ok(())
        },
    )
    .expect("Should succeed");
}
