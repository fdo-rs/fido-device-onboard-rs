#[cfg(feature="pkg-config")]
extern crate pkg_config;

#[cfg(target_env = "msvc")]
extern crate vcpkg;

use std::process::Command;
use std::env;
use std::path::PathBuf;
use std::fmt::{self, Display};

enum LinkType {
    Static,
    Dynamic
}

impl Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LinkType::Static => write!(f, "static"),
            LinkType::Dynamic => write!(f, "dylib"),
        }
    }
}

struct LinkingOptions {
    linking_type: Option<LinkType>,
    lib_name: &'static str,
}

impl LinkingOptions {
    fn from_name_and_type(lib_name: &'static str, tpe: LinkType) -> Self {
        LinkingOptions {
            linking_type: Some(tpe),
            lib_name
        }
    }
    fn from_name(lib_name: &'static str) -> Self {
        LinkingOptions {
            linking_type: None,
            lib_name
        }
    }

    fn from_env() -> Self {
        // On Windows-MSVC, always link dynamically
        if cfg!(all(windows, target_env="msvc")) {
            return LinkingOptions::from_name_and_type("libpq", LinkType::Dynamic);
        }

        // Link unconditionally statically
        if env::var_os("PQ_LIB_STATIC").is_some() {
            return LinkingOptions::from_name_and_type("pq", LinkType::Static);
        }

        // Examine the per-target env vars
        if let Ok(target) = env::var("TARGET") {
            let pg_config_for_target = format!("PQ_LIB_STATIC_{}", target.to_ascii_uppercase().replace("-", "_"));
            println!("cargo:rerun-if-env-changed={}", pg_config_for_target);
            if env::var_os(&pg_config_for_target).is_some() {
                return LinkingOptions::from_name_and_type("pq", LinkType::Static);
            }
        }

        // Otherwise, don't specify
        LinkingOptions::from_name("pq")
    }
}

impl Display for LinkingOptions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref t) = self.linking_type {
            write!(f, "{}=", t)?;
        }
        write!(f, "{}", self.lib_name)
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=PQ_LIB_STATIC");
    println!("cargo:rerun-if-env-changed=TARGET");

    // if target is specified the more concrete pq_lib_dir overwrites a more general one
    let lib_dir = if let Ok(target) = env::var("TARGET") {
        let pq_lib_dir_for_target = format!("PQ_LIB_DIR_{}", target.to_ascii_uppercase().replace("-", "_"));
        check_and_use_lib_dir(&pq_lib_dir_for_target).or_else(|_| check_and_use_lib_dir("PQ_LIB_DIR"))
    }
    else{
        check_and_use_lib_dir("PQ_LIB_DIR")
    };

    if let Ok(lib_dir) = lib_dir {
        println!("cargo:rustc-link-search=native={}", lib_dir);
    } else if configured_by_pkg_config() {
        return // pkg_config does everything for us, including output for cargo
    } else if configured_by_vcpkg() {
        return // vcpkg does everything for us, including output for cargo
    } else if let Some(path) = pg_config_output("--libdir") {
        let path = replace_homebrew_path_on_mac(path);
        println!("cargo:rustc-link-search=native={}", path);
    }
    println!("cargo:rustc-link-lib={}", LinkingOptions::from_env());
}

#[cfg(feature = "pkg-config")]
fn configured_by_pkg_config() -> bool {
    pkg_config::probe_library("libpq").is_ok()
}

#[cfg(not(feature = "pkg-config"))]
fn configured_by_pkg_config() -> bool {
    false
}

#[cfg(target_env = "msvc")]
fn configured_by_vcpkg() -> bool {
    vcpkg::find_package("libpq").map(|_| {
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=gdi32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=secur32");
        println!("cargo:rustc-link-lib=shell32");
        println!("cargo:rustc-link-lib=wldap32");
    }).is_ok()
}

#[cfg(not(target_env = "msvc"))]
fn configured_by_vcpkg() -> bool {
    false
}

fn check_and_use_lib_dir(var_name: &str) -> Result<String, env::VarError>{
    println!("cargo:rerun-if-env-changed={:?}", var_name);
    println!("{:?} = {:?}", var_name , env::var(var_name));

    let pq_lib_dir = env::var(var_name);
    if let Ok(pg_lib_path) = pq_lib_dir.clone() {
        let path =  PathBuf::from(&pg_lib_path);
        if !path.exists() {
            panic!("Folder {:?} doesn't exist in the configured path: {:?}", var_name, path);
        }
    }
    pq_lib_dir
}

fn pg_config_path() -> PathBuf {
    if let Ok(target) = env::var("TARGET") {
        let pg_config_for_target = &format!("PG_CONFIG_{}", target.to_ascii_uppercase().replace("-", "_"));
        println!("cargo:rerun-if-env-changed={}", pg_config_for_target);
        if let Some(pg_config_path) = env::var_os(pg_config_for_target) {

            let path =  PathBuf::from(&pg_config_path);

            if !path.exists() {
                panic!("pg_config doesn't exist in the configured path: {:?}", path);
            }

            return path;
        }
    }
    PathBuf::from("pg_config")
}

fn pg_config_output(command: &str) -> Option<String> {
    Command::new(pg_config_path())
        .arg(command)
        .output()
        .ok()
        .into_iter()
        .filter(|output| output.status.success())
        .flat_map(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_string())
        .next()
}

#[cfg(not(target_os = "macos"))]
fn replace_homebrew_path_on_mac(path: String) -> String {
    path
}

#[cfg(target_os = "macos")]
fn replace_homebrew_path_on_mac(path: String) -> String {
    if path == "/usr/local/lib" {
        Command::new("brew")
            .arg("--prefix")
            .arg("postgres")
            .output()
            .ok()
            .into_iter()
            .filter(|output| output.status.success())
            .flat_map(|output| String::from_utf8(output.stdout).ok())
            .map(|output| format!("{}/lib", output.trim()))
            .next()
            .unwrap_or(path)
    } else {
        path
    }
}
