use anyhow::{bail, Result};
use std::fs;

/// Checks whether an entry for the given user name 'username' exists in
/// /etc/passwd
pub fn is_user_in_passwd(username: &str) -> Result<bool> {
    for line in fs::read_to_string("/etc/passwd")?.lines() {
        let contents: Vec<&str> = line.split(':').collect();
        if !contents.is_empty() && contents[0] == username {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Returns the uid, gid and home of the given user or Error if user does not
/// exist in /etc/passwd.
pub fn get_user_uid_gid_home(username: &str) -> Result<(u32, u32, String)> {
    for line in fs::read_to_string("/etc/passwd")?.lines() {
        let contents: Vec<&str> = line.split(':').collect();
        if !contents.is_empty() && contents[0] == username {
            return Ok((
                contents[2].parse::<u32>()?,
                contents[3].parse::<u32>()?,
                contents[5].to_string(),
            ));
        }
    }
    bail!("User {username} not found")
}

/// Returns the password of a given user. Errors if the user does not exist
/// in /etc/shadow.
pub fn get_user_passwd(username: &str) -> Result<String> {
    for line in fs::read_to_string("/etc/shadow")?.lines() {
        let contents: Vec<&str> = line.split(':').collect();
        if !contents.is_empty() && contents[0] == username {
            return Ok(contents[1].to_string());
        }
    }
    bail!("User {username} not found")
}
