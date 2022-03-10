use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Error, Result};
use clap::{Args, Subcommand};

const DEFAULT_AIO_DIRECTORY: &str = "/etc/fdo/aio";

mod configure;
mod device;
mod execute;

const POSSIBLE_BINARY_PATHS: &[&str] = &[
    "/usr/bin",
    #[cfg(debug_assertions)]
    "./target/debug",
    #[cfg(debug_assertions)]
    "../target/debug",
];

const ALL_BINARIES: &[ChildBinary] = &[
    ChildBinary::ManufacturingServer,
    ChildBinary::OwnerOnboardingServer,
    ChildBinary::RendezvousServer,
    ChildBinary::ServiceInfoApiServer,
    ChildBinary::ClientLinuxapp,
    ChildBinary::ManufacturingClient,
    ChildBinary::OwnerTool,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildBinary {
    ManufacturingServer,
    OwnerOnboardingServer,
    RendezvousServer,
    ServiceInfoApiServer,
    ClientLinuxapp,
    ManufacturingClient,
    OwnerTool,
}

impl ChildBinary {
    fn binary_name(&self) -> &'static str {
        match self {
            ChildBinary::ManufacturingServer => "fdo-manufacturing-server",
            ChildBinary::OwnerOnboardingServer => "fdo-owner-onboarding-server",
            ChildBinary::RendezvousServer => "fdo-rendezvous-server",
            ChildBinary::ServiceInfoApiServer => "fdo-serviceinfo-api-server",
            ChildBinary::ClientLinuxapp => "fdo-client-linuxapp",
            ChildBinary::ManufacturingClient => "fdo-manufacturing-client",
            ChildBinary::OwnerTool => "fdo-owner-tool",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct AioArgs {
    /// The directory to execute the AIO in
    #[clap(long)]
    directory: Option<PathBuf>,

    /// The directory from where to execute the binaries
    #[clap(long)]
    binary_path: Option<PathBuf>,

    #[clap(skip)]
    configuration: configure::Configuration,

    /// The subcommand to execute
    #[clap(subcommand)]
    command: Option<AioSubcommands>,
}

impl AioArgs {
    fn is_valid_binary_path(possible_path: &Path) -> bool {
        for binary in ALL_BINARIES {
            if !possible_path.join(binary.binary_name()).exists() {
                log::debug!(
                    "Binary {:?} not found in {:?}",
                    binary.binary_name(),
                    possible_path
                );
                return false;
            }
            log::trace!(
                "Found binary {:?} in {:?}",
                binary.binary_name(),
                possible_path
            );
        }
        true
    }

    fn find_binary_path(&mut self) -> Result<()> {
        if let Some(binary_path) = &self.binary_path {
            let binary_path = binary_path
                .canonicalize()
                .context("Error canonicalizing binary path")?;
            if !Self::is_valid_binary_path(&binary_path) {
                bail!("Invalid binary path: {:?}", binary_path);
            }
            self.binary_path = Some(binary_path);
            return Ok(());
        }

        for possible_path in POSSIBLE_BINARY_PATHS {
            let possible_path = match PathBuf::from(possible_path).canonicalize() {
                Ok(path) => path,
                Err(e) => {
                    log::debug!("Error canonicalizing path {:?}: {:?}", possible_path, e);
                    continue;
                }
            };

            if !Self::is_valid_binary_path(&possible_path) {
                continue;
            }

            self.binary_path = Some(possible_path);
            return Ok(());
        }
        anyhow::bail!(
            "Unable to find a directory with all binaries in {:?}",
            POSSIBLE_BINARY_PATHS
        );
    }
}

#[derive(Debug, Subcommand)]
enum AioSubcommands {
    /// Generate the configurations and keys
    GenerateConfigsAndKeys(configure::Configuration),

    /// Run the All-In-One
    Run,

    Device(device::DeviceArgs),
}

pub(crate) async fn run_aio_subcommand(args: AioArgs) -> Result<(), Error> {
    let mut args = args;
    args.find_binary_path()
        .context("Unable to find binaries for AIO")?;

    if args.directory.is_none() {
        if Path::new(DEFAULT_AIO_DIRECTORY).exists() {
            args.directory = Some(PathBuf::from(DEFAULT_AIO_DIRECTORY));
        } else {
            bail!("No AIO directory found, please specify with --directory");
        }
    }
    if args.directory.as_ref().unwrap().exists() {
        args.directory = Some(
            args.directory
                .as_ref()
                .unwrap()
                .canonicalize()
                .context("Error canonicalizing AIO directory")?,
        );
        if !args.directory.as_ref().unwrap().is_dir() {
            bail!("{:?} is not a directory", args.directory.as_ref());
        }
    }

    if let Some(AioSubcommands::GenerateConfigsAndKeys(ref config_args)) = &args.command {
        configure::generate_configs_and_keys(
            args.directory.as_ref().unwrap(),
            Some(config_args.clone()),
        )
        .context("Error generating configuration")?;
        log::info!("Configuration completed");
        return Ok(());
    }

    if !args
        .directory
        .as_ref()
        .unwrap()
        .join("aio_configuration")
        .exists()
    {
        log::info!("AIO directory not configured, creating it with default configuration");
        configure::generate_configs_and_keys(args.directory.as_ref().unwrap(), None)
            .context("Error creating configuration")?;
    }

    args.configuration = {
        let cfg_file =
            std::fs::File::open(args.directory.as_ref().unwrap().join("aio_configuration"))
                .context("Error opening AIO configuration")?;
        serde_yaml::from_reader(cfg_file).context("Error parsing AIO configuration")?
    };
    args.directory = Some(
        args.directory
            .as_ref()
            .unwrap()
            .canonicalize()
            .context("Error canonicalizing AIO directory")?,
    );

    let args = args;
    log::debug!("AIO arguments: {:#?}", args);

    match &args.command.unwrap_or(AioSubcommands::Run) {
        // GenerateConfigsAndKeys is handled up above
        AioSubcommands::GenerateConfigsAndKeys(_) => unreachable!(),
        AioSubcommands::Run => {
            execute::execute_aio(
                args.directory.unwrap(),
                args.binary_path.unwrap(),
                &args.configuration,
            )
            .await
        }
        AioSubcommands::Device(device_args) => {
            device::run_device_subcommand(
                args.directory.unwrap(),
                args.binary_path.unwrap(),
                &args.configuration,
                device_args,
            )
            .await
        }
    }
}
