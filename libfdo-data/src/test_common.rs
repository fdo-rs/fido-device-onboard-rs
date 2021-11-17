use std::{
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

pub fn run_external(script: &str, args: &[&str]) -> Output {
    let descrip = format!("test script {}.go, with args {:?}", script, args);
    let script_path = root_dir()
        .join("test_scripts")
        .join(format!("{}.go", script));

    match std::fs::remove_file(format!(
        "{}/../target/debug/libfdo_data.so.{}",
        ROOT_DIR,
        std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap()
    )) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!("Failed to remove libfdo_data.so.0 symlink {:?}", e),
    }

    match std::os::unix::fs::symlink(
        format!("{}/../target/debug/libfdo_data.so", ROOT_DIR),
        format!(
            "{}/../target/debug/libfdo_data.so.{}",
            ROOT_DIR,
            std::env::var("CARGO_PKG_VERSION_MAJOR").unwrap()
        ),
    ) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => panic!("Failed to create libfdo_data.so.0 symlink {:?}", e),
    }

    let result = Command::new("go")
        .arg("run")
        .arg(script_path)
        .args(args)
        .output()
        .expect(&format!("Failed to run {}", descrip,));

    println!("Result of {}: {:?}", descrip, result);

    result
}

pub fn test_asset_path(asset_name: &str) -> PathBuf {
    root_dir().join("test_assets").join(asset_name)
}
