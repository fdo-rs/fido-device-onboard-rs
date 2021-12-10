pub mod device_credential_locations;
pub mod servers;

pub fn maybe_print_version(
    name: &'static str,
    major: &'static str,
    minor: &'static str,
    patch: &'static str,
    pre: &'static str,
) {
    let mut args = std::env::args();
    if args.len() == 2 && args.nth(1).unwrap() == "--version" {
        println!("{} {}.{}.{} {}", name, major, minor, patch, pre);
        if !fdo_data_formats::INTEROPERABLE_KDF {
            println!("WARNING: This version of {} is not interoperable with FDO as it is using a non-interoperable KDF implementation",
                     name);
        }
        std::process::exit(0);
    }
}

#[macro_export]
macro_rules! add_version {
    () => {
        fdo_util::maybe_print_version(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION_MAJOR"),
            env!("CARGO_PKG_VERSION_MINOR"),
            env!("CARGO_PKG_VERSION_PATCH"),
            env!("CARGO_PKG_VERSION_PRE"),
        );
    };
}
