use std::process::Command;

pub fn get_current_user_name() -> String {
    String::from_utf8(
        Command::new("id")
            .arg("-u")
            .arg("-n")
            .output()
            .expect("Unable to run `id` command")
            .stdout,
    )
    .expect("Unable to read current user name")
    .trim()
    .to_string()
}
