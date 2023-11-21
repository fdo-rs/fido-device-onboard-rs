use std::{io::Write, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use tokio::{
    process::{Child, Command},
    signal::unix::{signal, SignalKind},
};

use super::{configure::Configuration, ChildBinary};
use time::OffsetDateTime;

const ALL_DAEMON_BINARIES: &[ChildBinary] = &[
    ChildBinary::ManufacturingServer,
    ChildBinary::OwnerOnboardingServer,
    ChildBinary::RendezvousServer,
    ChildBinary::ServiceInfoApiServer,
];
const MAX_WAIT_FOR_READY: Duration = Duration::from_secs(2);
const WAIT_BETWEEN_READY_TESTS: Duration = Duration::from_millis(500);

#[derive(Debug)]
struct RunningAioContext {
    starttime: time::OffsetDateTime,

    configuration: Configuration,

    directory: PathBuf,

    binary_path: PathBuf,

    childs: Vec<RunningChild>,
}

impl RunningAioContext {
    fn new(directory: PathBuf, binary_path: PathBuf, configuration: Configuration) -> Result<Self> {
        Ok(RunningAioContext {
            directory,
            binary_path,
            configuration,
            childs: Vec::new(),
            starttime: OffsetDateTime::now_utc(),
        })
    }

    fn start_binary(&mut self, binary: ChildBinary) -> Result<()> {
        log::debug!("Starting binary: {:?}", binary);

        let log_stdout = self
            .directory
            .join("logs")
            .join(format!("{}.stdout.log", binary.binary_name()));
        let mut log_stdout = std::fs::File::options()
            .create(true)
            .append(true)
            .open(log_stdout)
            .context("Unable to open stdout log file")?;
        writeln!(log_stdout, "==== NEW START AT {} ====", self.starttime)
            .context("Unable to write to stdout log file")?;

        let log_stderr = self
            .directory
            .join("logs")
            .join(format!("{}.stderr.log", binary.binary_name()));
        let mut log_stderr = std::fs::File::options()
            .create(true)
            .append(true)
            .open(log_stderr)
            .context("Unable to open stderr log file")?;
        writeln!(log_stderr, "==== NEW START AT {} ====", self.starttime)
            .context("Unable to write to stderr log file")?;

        let child = Command::new(self.binary_path.join(binary.binary_name()))
            .current_dir(self.directory.join("work"))
            .env("LOG_LEVEL", "trace")
            .env(
                binary.configuration_env_name(),
                self.directory
                    .join("configs")
                    .join(binary.configuration_file_name())
                    .to_str()
                    .unwrap(),
            )
            .stdout(log_stdout)
            .stderr(log_stderr)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("Error spawning process")?;

        self.childs.push(RunningChild { child, binary });

        Ok(())
    }

    async fn wait_until_ready(&mut self) -> Result<()> {
        log::info!("Waiting until services are ready");
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();

        'daemonloop: for daemon in ALL_DAEMON_BINARIES {
            log::debug!(
                "Waiting at most {:?} until {:?} is done",
                MAX_WAIT_FOR_READY,
                daemon
            );

            let url = format!(
                "http://localhost:{}/ping", //DevSkim: ignore DS137138
                daemon.port(&self.configuration),
            );

            loop {
                let res = client.post(&url).send().await;

                if res.is_ok() {
                    log::debug!("{:?} is ready", daemon);
                    continue 'daemonloop;
                }
                if start.elapsed() > MAX_WAIT_FOR_READY {
                    bail!("{:?} failed to start in time", daemon);
                }
                match self
                    .childs
                    .iter_mut()
                    .find(|c| c.binary == *daemon)
                    .expect("Daemon not found?")
                    .child
                    .try_wait()
                {
                    Ok(None) => {
                        log::trace!(
                            "{:?} is not yet ready, process is live, waiting {:?}",
                            daemon,
                            WAIT_BETWEEN_READY_TESTS
                        );
                        tokio::time::sleep(WAIT_BETWEEN_READY_TESTS).await;
                    }
                    Ok(Some(status)) => {
                        bail!("{:?} failed to start: exit code: {:?}", daemon, status)
                    }
                    Err(e) => bail!(
                        "{:?} failed to start: error checking process: {:?}",
                        daemon,
                        e
                    ),
                }
            }
        }

        log::info!("All services are ready");

        Ok(())
    }

    async fn wait_until_done(&mut self) -> Result<()> {
        log::info!("AIO running");

        let names = self
            .childs
            .iter()
            .map(|child| child.binary.binary_name())
            .collect::<Vec<_>>();

        let child_futures = self
            .childs
            .iter_mut()
            .map(|child| Box::pin(child.child.wait()));
        match futures::future::select_all(child_futures).await {
            (Ok(status), idx, _) => {
                log::info!("Child {} finished with status {:?}", names[idx], status);
            }
            (Err(e), idx, _) => {
                log::error!("Failed to check status of child {}: {:?}", names[idx], e);
            }
        }

        log::info!("Part of AIO has shut down");
        Ok(())
    }
}

impl ChildBinary {
    fn configuration_env_name(&self) -> &'static str {
        match self {
            ChildBinary::ManufacturingServer => "MANUFACTURING_SERVER_CONF",
            ChildBinary::OwnerOnboardingServer => "OWNER_ONBOARDING_SERVER_CONF",
            ChildBinary::RendezvousServer => "RENDEZVOUS_SERVER_CONF",
            ChildBinary::ServiceInfoApiServer => "SERVICEINFO_API_SERVER_CONF",
            _ => unreachable!(),
        }
    }

    fn configuration_file_name(&self) -> &'static str {
        match self {
            ChildBinary::ManufacturingServer => "manufacturing_server.yml",
            ChildBinary::OwnerOnboardingServer => "owner_onboarding_server.yml",
            ChildBinary::RendezvousServer => "rendezvous_server.yml",
            ChildBinary::ServiceInfoApiServer => "serviceinfo_api_server.yml",
            _ => unreachable!(),
        }
    }

    fn port(&self, config: &Configuration) -> u16 {
        match self {
            ChildBinary::ManufacturingServer => config.listen_port_http_manufacturing_server,
            ChildBinary::OwnerOnboardingServer => config.listen_port_owner_onboarding_server,
            ChildBinary::RendezvousServer => config.listen_port_rendezvous_server,
            ChildBinary::ServiceInfoApiServer => config.listen_port_serviceinfo_api_server,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct RunningChild {
    binary: ChildBinary,
    child: Child,
}

pub(super) async fn execute_aio(
    aio_dir: PathBuf,
    binary_path: PathBuf,
    configuration: &Configuration,
) -> Result<()> {
    log::info!("Starting AIO");

    let mut ctx = RunningAioContext::new(aio_dir, binary_path, configuration.clone())
        .context("Error creating AIO context")?;
    log::debug!("AIO context: {:?}", ctx);

    for binary in ALL_DAEMON_BINARIES {
        ctx.start_binary(*binary)
            .with_context(|| format!("Error starting binary {binary:?}"))?;
    }

    ctx.wait_until_ready()
        .await
        .context("Error waiting until daemons are ready")?;

    let mut signal_handler =
        signal(SignalKind::interrupt()).context("Error waiting for terminate signal")?;
    let signal_handler = signal_handler.recv();

    #[allow(clippy::panic)]
    {
        tokio::select! {
            _ = signal_handler => {
                log::info!("Shutting down");
                #[allow(clippy::let_underscore_future)]
                let _ = futures::future::join_all(ctx.childs.iter_mut().map(|child| {
                    Box::pin(child.child.kill())
                }));
                Ok(())
            },
            res = ctx.wait_until_done() => {
                res.context("Error waiting until all childs are done")
            }
        }
    }
}
