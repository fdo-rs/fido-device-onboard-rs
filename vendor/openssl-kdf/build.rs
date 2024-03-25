#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
enum Implementation {
    Ossl11,
    Ossl3,
    Custom,
}

impl ToString for Implementation {
    fn to_string(&self) -> String {
        match self {
            Implementation::Ossl11 => "ossl11",
            Implementation::Ossl3 => "ossl3",
            Implementation::Custom => "custom",
        }
        .to_string()
    }
}

fn read_header(lib: &pkg_config::Library, path_rel: &str) -> std::io::Result<String> {
    for dir in lib
        .include_paths
        .iter()
        .map(|p| p.as_path())
        .chain(std::iter::once(std::path::Path::new("/usr/include")))
    {
        match std::fs::read_to_string(dir.join(path_rel)) {
            Ok(r) => return Ok(r),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }

    return Err(std::io::ErrorKind::NotFound.into());
}

#[allow(unreachable_code)]
fn main() {
    #[allow(unused_mut)]
    let mut available_implementations: Vec<Implementation> = vec![];

    #[cfg(not(feature = "force_custom"))]
    {
        let openssl = pkg_config::probe_library("openssl").unwrap();
        let openssl_version = &openssl.version;
        if openssl_version.starts_with("1.") {
            // Determine if this version of OpenSSL has the requisite patch backported
            let kdf_h_cts = read_header(&openssl, "openssl/kdf.h").unwrap();
            if kdf_h_cts.contains("KDF_CTX_new_id") {
                available_implementations.push(Implementation::Ossl11);
            }
        } else if openssl_version.starts_with("3.") {
            available_implementations.push(Implementation::Ossl3);
            let core_names_h = read_header(&openssl, "openssl/core_names.h").unwrap();
            if core_names_h.contains("OSSL_KDF_PARAM_KBKDF_R") {
                println!("cargo:rustc-cfg=ossl3_supported=\"kbkdf_r\"");
            }
        }
    }

    #[cfg(all(feature = "allow_custom", not(feature = "deny_custom")))]
    {
        eprintln!("WARNING: Custom rust-openssl-kdf implementation is enabled");
        available_implementations.push(Implementation::Custom);
    }

    if available_implementations.is_empty() {
        panic!(
            "No OpenSSL implementations available.\n\
            Please use a version of OpenSSL that has the necessary patch backported, or\n\
            use the `allow_custom` feature to allow the use of the custom implementation."
        );
    }

    for implementation in available_implementations {
        println!(
            "cargo:rustc-cfg=implementation=\"{}\"",
            implementation.to_string()
        );
    }
    println!("cargo:rustc-link-lib=crypto");
}
