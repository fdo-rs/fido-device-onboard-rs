use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const ROOT_DIR: &str = env!("CARGO_MANIFEST_DIR");
fn root_dir() -> &'static Path {
    Path::new(ROOT_DIR)
}

pub trait OutputExt {
    fn stdout_equals(&self, expected: &str);
    fn stderr_equals(&self, expected: &str);
}

fn out_equals(text: &[u8], expected: &str) {
    let text = std::str::from_utf8(text).unwrap();
    assert_str::assert_str_trim_eq!(text, expected,);
}

impl OutputExt for Output {
    fn stdout_equals(&self, expected: &str) {
        out_equals(&self.stdout, expected)
    }

    fn stderr_equals(&self, expected: &str) {
        out_equals(&self.stderr, expected)
    }
}

pub fn run_external(script: &str, args: &[&str]) -> Result<Output, String> {
    let descrip = format!("test script {}.go, with args {:?}", script, args);
    let script_path_location = root_dir().join("test_scripts");
    let script_path = script_path_location.join(format!("{}.go", script));

    // Try to remove the old symlink, handle error gracefully
    if let Err(e) = std::fs::remove_file(format!(
        "{}/../target/debug/libfdo_data.so.{}",
        ROOT_DIR,
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap()
    )) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(format!("Failed to remove libfdo_data.so.0 symlink {:?}", e));
        }
    }

    // Try to create a new symlink, handle error gracefully
    if let Err(e) = std::os::unix::fs::symlink(
        format!("{}/../target/debug/libfdo_data.so", ROOT_DIR),
        format!(
            "{}/../target/debug/libfdo_data.so.{}",
            ROOT_DIR,
            std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap()
        ),
    ) {
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(format!("Failed to create libfdo_data.so.0 symlink {:?}", e));
        }
    }

    // Run the command, returning an error if it fails
    let result = Command::new("go")
        .arg("run")
        .args(["-tags", "localbuild"])
        .arg(script_path)
        .args(args)
        .current_dir(&script_path_location)
        .output()
        .map_err(|_| format!("Failed to run {}", descrip))?;

    println!("Result of {}: {:?}", descrip, result);

    Ok(result) // Return the result as Ok if everything succeeded
}

pub fn test_asset_path(asset_name: &str) -> PathBuf {
    root_dir().join("test_assets").join(asset_name)
}
