use anyhow::{bail, Context, Error};
use clap::{App, Arg, ArgMatches, SubCommand};

fn main() -> Result<(), Error> {
    let matches = App::new("owner_tool")
        .version("0.1")
        .subcommand(
            SubCommand::with_name("dump-ownership-voucher")
                .about("Prints ownership voucher contents")
                .arg(
                    Arg::with_name("path")
                        .required(true)
                        .help("Path to the ownership voucher")
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("extend-ownership-voucher")
                .about("Extends an ownership voucher for a new owner")
                .arg(
                    Arg::with_name("path")
                        .required(true)
                        .help("Path to the ownership voucher")
                        .index(1),
                )
                .arg(
                    Arg::with_name("current-owner-key")
                        .required(true)
                        .help("Path to the current owner key")
                        .long("current-owner-key"),
                )
                .arg(
                    Arg::with_name("new-owner-public-key")
                        .required(true)
                        .help("Path to the new owner public key")
                        .long("new-owner-key"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("dump-ownership-voucher", Some(sub_m)) => dump_voucher(sub_m),
        ("extend-ownership-voucher", Some(sub_m)) => extend_voucher(sub_m),
        _ => Ok(()),
    }
}

fn dump_voucher(matches: &ArgMatches) -> Result<(), Error> {
    todo!();
}

fn extend_voucher(matches: &ArgMatches) -> Result<(), Error> {
    todo!();
}
