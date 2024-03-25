use std::env;

use pkg_config::Config;
use semver::Version;

use std::path::PathBuf;

fn get_version() -> Version {
    match Config::new().atleast_version("2.2.0").probe("libcryptsetup") {
        Ok(l) => Version::parse(&l.version).expect("Could not parse version"),
        Err(e) => panic!("Bindings require at least cryptsetup-2.2.0: {e}"),
    }
}

fn safe_free_is_needed() -> bool {
    let version = get_version();
    version < Version::new(2, 3, 0)
}

fn build_safe_free() {
    cc::Build::new().file("safe_free.c").compile("safe_free");

    println!("cargo:rustc-link-lib=cryptsetup");
}

fn generate_bindings(safe_free_is_needed: bool) {
    let builder = bindgen::Builder::default().header("header.h").size_t_is_usize(true);
    #[cfg(target_arch = "x86")]
    let builder = builder.blocklist_type("max_align_t");
    let builder_with_safe_free = if safe_free_is_needed {
        builder.header("safe_free.h")
    } else {
        builder
    };
    let bindings = builder_with_safe_free
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}

fn main() {
    let safe_free_is_needed = safe_free_is_needed();
    if safe_free_is_needed {
        build_safe_free();
    }
    generate_bindings(safe_free_is_needed);
    println!("cargo:rerun-if-changed=header.h");
}
