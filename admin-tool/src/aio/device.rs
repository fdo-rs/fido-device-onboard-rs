use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};

use super::{configure::Configuration, ChildBinary};

#[derive(Debug, Args)]
pub(super) struct DeviceArgs {
    #[clap(subcommand)]
    command: DeviceSubcommand,

    #[clap(long)]
    device_credential_location: PathBuf,
}

#[derive(Debug, Subcommand)]
enum DeviceSubcommand {
    Manufacture(DeviceManufactureArgs),
    Analyze,
    Run(DeviceRunArgs),
}

#[derive(Debug, Args)]
struct DeviceManufactureArgs {
    #[clap(long)]
    device_info: String,
}

#[derive(Debug, Args)]
struct DeviceRunArgs {
    #[clap(long)]
    allow_noninteroperable_kdf: bool,
}

async fn run_device(
    _aio_dir: PathBuf,
    binary_path: PathBuf,
    _configuration: &Configuration,
    args: &DeviceArgs,
    run_args: &DeviceRunArgs,
) -> Result<()> {
    let marker_location = format!(
        "{}.marker",
        args.device_credential_location.to_string_lossy()
    );

    println!("========== STARTING CLIENT ==========");
    let mut command =
        tokio::process::Command::new(binary_path.join(ChildBinary::ClientLinuxapp.binary_name()));
    command
        .env("LOG_LEVEL", "trace")
        .env("DEVICE_CREDENTIAL", &args.device_credential_location)
        .env(
            "DEVICE_ONBOARDING_EXECUTED_MARKER_FILE_PATH",
            &marker_location,
        )
        .kill_on_drop(true);

    if run_args.allow_noninteroperable_kdf {
        command.env("ALLOW_NONINTEROPERABLE_KDF", "true");
    }

    let status = command
        .status()
        .await
        .context("Error starting the client")?;
    println!("========== CLIENT ENDED WITH STATUS: {status:?} ==========",);

    if status.success() {
        log::info!("Device onboarding completed");
        Ok(())
    } else {
        bail!("Client failed with status: {:?}", status);
    }
}

async fn manufacture_device(
    aio_dir: PathBuf,
    binary_path: PathBuf,
    configuration: &Configuration,
    args: &DeviceArgs,
    mfg_args: &DeviceManufactureArgs,
) -> Result<()> {
    println!("========== STARTING MANUFACTURING CLIENT ==========");
    let status = tokio::process::Command::new(
        binary_path.join(ChildBinary::ManufacturingClient.binary_name()),
    )
    .env("LOG_LEVEL", "trace")
    .env(
        "DIUN_PUB_KEY_ROOTCERTS",
        aio_dir.join("keys").join("diun_cert.pem"),
    )
    .env(
        "MANUFACTURING_SERVER_URL",
        format!(
            "http://localhost:{}", //DevSkim: ignore DS137138
            configuration.listen_port_manufacturing_server
        ),
    )
    .env("DI_MFG_STRING_TYPE", "serialnumber")
    .env("MANUFACTURING_INFO", &mfg_args.device_info)
    .env(
        "DEVICE_CREDENTIAL_FILENAME",
        &args.device_credential_location,
    )
    .kill_on_drop(true)
    .status()
    .await
    .context("Error running manufacturing client")?;
    println!("========== MANUFACTURING CLIENT ENDED WITH STATUS: {status:?} ==========");

    if status.success() {
        log::info!("Device manufacturing completed");
        print_device_credential(binary_path, &args.device_credential_location).await
    } else {
        bail!("Manufacturing client failed with status: {:?}", status);
    }
}

async fn print_device_credential(
    binary_path: PathBuf,
    device_credential_path: &Path,
) -> Result<()> {
    let status =
        tokio::process::Command::new(binary_path.join(ChildBinary::OwnerTool.binary_name()))
            .arg("dump-device-credential")
            .args(device_credential_path)
            .status()
            .await
            .context("Error running owner-tool to dump device credential")?;

    if status.success() {
        Ok(())
    } else {
        bail!("Owner-tool failed with status: {:?}", status)
    }
}

pub(super) async fn run_device_subcommand(
    aio_dir: PathBuf,
    binary_path: PathBuf,
    configuration: &Configuration,
    args: &DeviceArgs,
) -> Result<()> {
    match &args.command {
        DeviceSubcommand::Manufacture(mfg_args) => {
            manufacture_device(aio_dir, binary_path, configuration, args, mfg_args)
                .await
                .context("Error manufacturing device")
        }
        DeviceSubcommand::Analyze => {
            print_device_credential(binary_path, &args.device_credential_location)
                .await
                .context("Error analyzing device credential")
        }
        DeviceSubcommand::Run(run_args) => {
            run_device(aio_dir, binary_path, configuration, args, run_args)
                .await
                .context("Error running device client")
        }
    }
}
