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
