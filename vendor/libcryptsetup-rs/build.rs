use pkg_config::Config;
use semver::Version;

static SUPPORTED_VERSIONS: &[&str] = &["2.2.0", "2.3.0", "2.4.0"];

// This build script will set a cfg directive in the form of
// "cryptsetup[MAJOR][MINOR]supported" for every version up until and including
// the current system version installed. There is currently no good way to
// compare whether a version is equal to or greater than from the macro
// context of #[cfg(...)] so instead, the current best option is to enable all
// minor versions corresponding to a major version that are less than or equal
// to the current minor version.
fn main() {
    let version = match Config::new()
        .atleast_version("2.2.0")
        .probe("libcryptsetup")
    {
        Ok(l) => Version::parse(&l.version).unwrap(),
        Err(e) => panic!("Bindings require at least cryptsetup-2.2.0: {e}"),
    };
    for ver in SUPPORTED_VERSIONS.iter().take_while(|ver_string| {
        let iter_version = Version::parse(ver_string).expect("Could not parse version");
        version >= iter_version
    }) {
        println!(
            "cargo:rustc-cfg=cryptsetup{}supported",
            ver.split('.').take(2).collect::<Vec<_>>().join("")
        );
    }
}
