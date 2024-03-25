use std::{env::args, ffi::CString, io};

use libc::syscall;

fn usage() -> &'static str {
    "Usage: add-to-persistent-keyring <KEY_DESCRIPTION> <KEY_DATA>\n\
     \tKEY_DESCRIPTION: Kernel keyring key description\n\
     \tKEY_DATA: Secret data associated with the key description"
}

fn parse_args() -> Result<(String, String), &'static str> {
    let args: Vec<_> = args().collect();
    if args.len() != 3 {
        println!("{}", usage());
        return Err("Incorrect arguments provided");
    }

    let key_desc = args.get(1).ok_or("No key description provided")?;

    let key_data = args.get(2).ok_or("No key data provided")?;

    Ok((key_desc.to_owned(), key_data.to_owned()))
}

fn add_to_persistent_keyring(key_desc: String, key_data: String) -> Result<(), io::Error> {
    let persistent_id = match unsafe {
        syscall(
            libc::SYS_keyctl,
            libc::KEYCTL_GET_PERSISTENT,
            0,
            libc::KEY_SPEC_SESSION_KEYRING,
        )
    } {
        i if i < 0 => return Err(io::Error::last_os_error()),
        i => i,
    };
    if unsafe { syscall(libc::SYS_keyctl, libc::KEYCTL_CLEAR, persistent_id) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let key_desc_cstring = CString::new(key_desc)?;
    if unsafe {
        libc::syscall(
            libc::SYS_add_key,
            concat!("user", "\0").as_ptr(),
            key_desc_cstring.as_ptr(),
            key_data.as_ptr(),
            key_data.len(),
            persistent_id,
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn main() -> Result<(), String> {
    let (key_desc, key_data) = parse_args()?;
    add_to_persistent_keyring(key_desc, key_data).map_err(|e| e.to_string())?;
    Ok(())
}
