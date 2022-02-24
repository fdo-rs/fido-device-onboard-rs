#![allow(dead_code)]

use std::{
    env,
    fs::{self, create_dir, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    time::{Duration, Instant},
};

use anyhow::{bail, Context as _, Result};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{X509Builder, X509NameBuilder},
};

use fdo_util::servers::format_conf_env;

const PORT_BASE: u16 = 5080;

lazy_static::lazy_static! {
    static ref CURRENT_PORT: std::sync::Mutex<u16> = std::sync::Mutex::new(PORT_BASE);
}

const TARGET_TMPDIR: &str = env!("CARGO_TARGET_TMPDIR");
const KEY_NAMES: &[&str] = &[
    "manufacturer",
    "device_ca",
    "owner",
    "reseller",
    "diun",
    "reseller",
];

const MAX_WAIT_FOR_OWNER_TOOL: Duration = Duration::from_millis(200);
const MAX_WAIT_FOR_READY: Duration = Duration::from_secs(2);
const WAIT_BETWEEN_READY_TESTS: Duration = Duration::from_millis(500);
const WAIT_BETWEEN_DEADLINE: Duration = Duration::from_millis(500);

lazy_static::lazy_static! {
    static ref TEMPLATES: tera::Tera = {
        let tera = match tera::Tera::new("templates/*") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };
        tera
    };
}

#[derive(Debug, Clone, Copy)]
pub enum Binary {
    ClientLinuxapp,
    ManufacturingClient,
    ManufacturingServer,
    OwnerOnboardingServer,
    OwnerTool,
    RendezvousServer,
}

impl Binary {
    fn target_name(&self) -> &str {
        match self {
            Binary::ClientLinuxapp => "fdo-client-linuxapp",
            Binary::ManufacturingClient => "fdo-manufacturing-client",
            Binary::ManufacturingServer => "fdo-manufacturing-server",
            Binary::OwnerOnboardingServer => "fdo-owner-onboarding-server",
            Binary::OwnerTool => "fdo-owner-tool",
            Binary::RendezvousServer => "fdo-rendezvous-server",
        }
    }

    fn config_file_name(&self) -> Option<&str> {
        match self {
            Binary::ManufacturingServer => Some("manufacturing-server.yml"),
            Binary::OwnerOnboardingServer => Some("owner-onboarding-server.yml"),
            Binary::RendezvousServer => Some("rendezvous-server.yml"),
            _ => None,
        }
    }

    fn is_server(&self) -> bool {
        matches!(
            self,
            Binary::OwnerOnboardingServer | Binary::ManufacturingServer | Binary::RendezvousServer
        )
    }

    fn url_environment_variable(&self) -> Option<&str> {
        match self {
            Binary::ManufacturingClient => Some("MANUFACTURING_SERVER_URL"),
            _ => None,
        }
    }
}

impl std::fmt::Display for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.target_name())
    }
}

#[derive(Debug)]
struct TestBinaryNumberGenerator(u16);

impl TestBinaryNumberGenerator {
    fn new() -> Self {
        Self(0)
    }

    fn next(&mut self, binary: Binary) -> TestBinaryNumber {
        self.0 += 1;
        TestBinaryNumber::new(binary, self.0)
    }
}

#[derive(Debug, Clone)]
pub struct TestBinaryNumber {
    binary: Binary,
    number: u16,
    name: String,
    server_port: Option<u16>,
}

impl TestBinaryNumber {
    fn new(binary: Binary, number: u16) -> Self {
        let name = format!("{}-{}", binary, number);
        let server_port = if binary.is_server() {
            let mut current = CURRENT_PORT.lock().unwrap();
            let port = *current;
            *current += 1;
            L.l(&format!("{} is a server, using port {}", name, port));
            Some(port)
        } else {
            None
        };
        TestBinaryNumber {
            binary,
            number,
            name,
            server_port,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn server_port(&self) -> Option<u16> {
        self.server_port
    }

    fn server_url(&self) -> Option<String> {
        if self.binary.is_server() {
            Some(format!("http://localhost:{}", self.server_port().unwrap()))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LogSide {
    Common,
    Test,
}

impl LogSide {
    pub fn l<M>(&self, msg: M)
    where
        M: std::fmt::Display,
    {
        println!("{:?}: {}", self, msg);
    }
}

const L: LogSide = LogSide::Common;

#[derive(Debug)]
pub struct TestContext {
    testpath: PathBuf,

    target_directory: PathBuf,

    test_servers: Vec<TestServer>,
    test_servers_ready: bool,

    test_binary_number_generator: TestBinaryNumberGenerator,

    // This is here just to make sure the destructor is called.
    // This is also at the end, to make sure that everything else gets to use
    //  the testpath before it gets dropped.
    #[allow(dead_code)]
    testdir: Option<tempfile::TempDir>,
}

impl TestContext {
    pub fn new() -> Result<Self> {
        let testdir = tempfile::Builder::new()
            .prefix("fido-device-onboard-integration-test-")
            .tempdir_in(&TARGET_TMPDIR)
            .context("Error creating temporary directory")?;
        let (testdir, testpath) = if env::var("INTEGRATION_TEST_KEEP_FOLDER").is_ok() {
            L.l(format!("Keeping test folder at {:?}", testdir.path()));
            (None, testdir.into_path())
        } else {
            let path = testdir.path().to_owned();
            (Some(testdir), path)
        };

        let target_directory =
            TestContext::find_target_directory().context("Unable to find target directory")?;

        let new_context = TestContext {
            testdir,
            testpath,
            target_directory,
            test_servers: Vec::new(),
            test_servers_ready: true,
            test_binary_number_generator: TestBinaryNumberGenerator::new(),
        };

        new_context.create_keys().context("Error creating keys")?;

        Ok(new_context)
    }

    fn find_target_directory() -> Result<PathBuf> {
        Path::new(env!("CARGO_BIN_EXE_test-locator"))
            .parent()
            .context("No target directory located")
            .map(PathBuf::from)
    }

    pub fn keys_path(&self) -> PathBuf {
        self.testpath.join("keys")
    }

    pub fn runner_path(&self, number: &TestBinaryNumber) -> PathBuf {
        self.testpath.join(number.name())
    }

    fn create_keys(&self) -> Result<()> {
        let keys_path = self.keys_path();
        create_dir(&keys_path).context("Error creating keys directory")?;

        let key_group =
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).context("Error creating EcGroup")?;

        for key_name in KEY_NAMES {
            // First create a new private key
            let private_key =
                EcKey::generate(&key_group).context("Error generating private key")?;
            let private_key =
                PKey::from_ec_key(private_key).context("Error converting private key to PKey")?;

            // Now create a certificate over (and with) the key
            let mut subject_name =
                X509NameBuilder::new().context("Error creating X509NameBuilder")?;
            subject_name
                .append_entry_by_text("CN", key_name)
                .context("Error adding CN")?;
            let subject_name = subject_name.build();

            let serial_number = BigNum::from_u32(42).context("Error creating serial number")?;
            let serial_number = Asn1Integer::from_bn(&serial_number)
                .context("Error converting serial number to ASN1Integer")?;

            let mut cert_builder = X509Builder::new().context("Error creating X509Builder")?;
            cert_builder
                .set_version(2)
                .context("Error setting version")?;
            cert_builder
                .set_not_after(
                    Asn1Time::days_from_now(1)
                        .context("Error creating Asn1Time")?
                        .as_ref(),
                )
                .context("Error setting not after")?;
            cert_builder
                .set_not_before(
                    Asn1Time::days_from_now(0)
                        .context("Error creating Asn1Time")?
                        .as_ref(),
                )
                .context("Error setting not before")?;
            cert_builder
                .set_issuer_name(&subject_name)
                .context("Error setting issuer name")?;
            cert_builder
                .set_subject_name(&subject_name)
                .context("Error setting issuer name")?;
            cert_builder
                .set_pubkey(&private_key)
                .context("Error setting public key")?;
            cert_builder
                .set_serial_number(&serial_number)
                .context("Error setting serial number")?;

            cert_builder
                .sign(&private_key, MessageDigest::sha384())
                .context("Error signing certificate")?;
            let cert = cert_builder.build();

            // Now serialize the key and certificate
            let private_key = private_key
                .private_key_to_der()
                .context("Error converting private key to DER")?;
            let cert = cert
                .to_pem()
                .context("Error converting certificate to PEM")?;

            // Now write them to disk
            fs::write(keys_path.join(format!("{}_key.der", key_name)), private_key)
                .context("Error writing private key")?;
            fs::write(keys_path.join(format!("{}_cert.pem", key_name)), cert)
                .context("Error writing certificate")?;
        }

        Ok(())
    }

    pub fn testpath(&self) -> &Path {
        &self.testpath
    }

    pub fn start_test_server<F1, F2>(
        &mut self,
        binary: Binary,
        config_configurator: F1,
        cmd_configurator: F2,
    ) -> Result<TestBinaryNumber>
    where
        F1: FnOnce(&mut TestServerConfigurator) -> Result<PathBuf>,
        F2: FnOnce(&mut Command) -> Result<()>,
    {
        self.test_servers_ready = false;

        let test_server_number = self.test_binary_number_generator.next(binary);

        let server_path = self.runner_path(&test_server_number);
        create_dir(&server_path).context("Error creating directory")?;

        // Create the config file
        let config_path = config_configurator(&mut TestServerConfigurator::new(
            binary,
            &self,
            &test_server_number,
        ))
        .context("Error configuring server")?;

        // Create the Command
        let cmd_path = self.target_directory.join(binary.target_name());
        let mut cmd = Command::new(&cmd_path);

        // Do initial configuration: everything can be overridden by the configurator
        cmd.current_dir(&server_path)
            .env("LOG_LEVEL", "trace")
            .env(
                format_conf_env(&String::from(binary.target_name()).replace("fdo-", "")),
                config_path,
            )
            .stdout(File::create(server_path.join("stdout")).context("Error creating stdout")?)
            .stderr(File::create(server_path.join("stderr")).context("Error creating stdout")?);

        // Call Command configurator
        cmd_configurator(&mut cmd).context("Error configuring server command")?;

        L.l(format!(
            "Spawning server {}, path: {:?}, server_path: {:?}, command: {:?}",
            test_server_number.name(),
            cmd_path,
            server_path,
            cmd
        ));

        let child = cmd
            .spawn()
            .with_context(|| format!("Error spawning test server for {:?}", binary))?;

        let test_server = TestServer::new(server_path, test_server_number.clone(), child)
            .with_context(|| format!("Error creating test server for {:?}", binary))?;

        self.test_servers.push(test_server);

        Ok(test_server_number)
    }

    pub async fn wait_until_servers_ready(&mut self) -> Result<()> {
        for test_server in &mut self.test_servers {
            test_server.wait_until_ready().await.with_context(|| {
                format!(
                    "Error waiting for server {} to start",
                    test_server.server_number.name()
                )
            })?;
        }
        self.test_servers_ready = true;
        Ok(())
    }

    fn check_test_servers_ready(&self) -> Result<()> {
        if self.test_servers_ready {
            Ok(())
        } else {
            bail!("Test servers are not yet ready");
        }
    }

    pub fn run_owner_tool(
        &mut self,
        working_dir: &Path,
        args: &[&str],
    ) -> Result<TestClientResult> {
        self.run_client(
            Binary::OwnerTool,
            None,
            |cfg| {
                cfg.current_dir(working_dir).args(args);

                Ok(())
            },
            MAX_WAIT_FOR_OWNER_TOOL,
        )
    }

    pub fn run_client<F>(
        &mut self,
        binary: Binary,
        server: Option<&TestBinaryNumber>,
        configurator: F,
        deadline: Duration,
    ) -> Result<TestClientResult>
    where
        F: FnOnce(&mut Command) -> Result<()>,
    {
        self.check_test_servers_ready()?;

        let client_number = self.test_binary_number_generator.next(binary);
        let client_path = self.runner_path(&client_number);
        let stdout_path = client_path.join("stdout");
        let stderr_path = client_path.join("stderr");

        create_dir(&client_path).context("Error creating directory")?;

        let cmd_path = self.target_directory.join(binary.target_name());
        let mut cmd = Command::new(&cmd_path);

        L.l(format!(
            "Running client {}, path: {:?}, client_path: {:?}, command: {:?}, deadline: {:?}",
            client_number.name(),
            cmd_path,
            client_path,
            cmd,
            deadline,
        ));

        // Do initial configuration: everything can be overridden by the configurator
        cmd.current_dir(&client_path)
            .env("LOG_LEVEL", "trace")
            .stdout(File::create(&stdout_path).context("Error creating stdout")?)
            .stderr(File::create(&stderr_path).context("Error creating stderr")?);

        if let Some(server) = server {
            if let Some(url_variable) = binary.url_environment_variable() {
                if let Some(server_url) = server.server_url() {
                    L.l(format!(
                        "Setting client env var {} to server url {}",
                        url_variable, server_url
                    ));
                    cmd.env(url_variable, server_url);
                } else {
                    bail!("Server URL not found for {}", server.name());
                }
            } else {
                bail!("Requested to pass along server URL, but no clue what that is");
            }
        }

        // Call Command configurator
        configurator(&mut cmd).context("Error configuring client command")?;

        let start = Instant::now();
        L.l(format!("Starting client at {:?}", start));

        let mut child = cmd.spawn().context("Error spawning client")?;
        let exit_code = loop {
            if start.elapsed() > deadline {
                L.l("Client timed out!");
                child.kill().context("Error killing client")?;
                break child.wait().context("Error waiting for client")?;
            }

            let exit_code = child.try_wait().context("Error waiting for client")?;
            if exit_code.is_some() {
                break exit_code.unwrap();
            }
            L.l(format!(
                "Client did not finish yet, waiting {:?}",
                WAIT_BETWEEN_DEADLINE
            ));
            std::thread::sleep(WAIT_BETWEEN_DEADLINE);
        };

        TestClientResult::new(client_number, client_path, exit_code)
    }

    pub fn generate_config_file<F>(
        &self,
        output_path: &Path,
        config_file_name: &str,
        context_configurator: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut tera::Context) -> Result<()>,
    {
        L.l(format!(
            "Preparing configuration file {:?} to {:?}",
            config_file_name, output_path,
        ));

        let mut template_context = tera::Context::new();

        // TODO: Insert defaults
        template_context.insert("keys_path", &self.keys_path());

        context_configurator(&mut template_context)
            .context("Error running context configurator")?;

        let config = TEMPLATES
            .render(&format!("{}.j2", config_file_name), &template_context)
            .context("Error rendering configuration template")?;
        fs::write(&output_path, config).context("Error writing configuration file")
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        L.l("Starting clean-up");
    }
}

#[derive(Debug)]
pub struct TestClientResult {
    client_number: TestBinaryNumber,
    client_path: PathBuf,
    status: ExitStatus,
    raw_stdout: Vec<u8>,
    stdout: Option<Vec<String>>,
    stderr: Vec<String>,
}

impl TestClientResult {
    fn new(
        client_number: TestBinaryNumber,
        client_path: PathBuf,
        exit_status: ExitStatus,
    ) -> Result<Self> {
        L.l(format!(
            "Client {} succeeded: {}",
            client_number.name(),
            exit_status.success()
        ));

        let raw_stdout = fs::read(&client_path.join("stdout")).context("Error reading stdout")?;
        let stdout = String::from_utf8(raw_stdout.clone())
            .ok()
            .map(|s| s.lines().map(|s| s.to_string()).collect());

        let stderr: Vec<String> = fs::read_to_string(client_path.join("stderr"))
            .context("Error reading client stderr")?
            .split('\n')
            .map(String::from)
            .collect();

        L.l(format!("Stdout for client {}:", client_number.name()));
        L.l("=========================================");
        if let Some(stdout) = &stdout {
            for line in stdout {
                L.l(line);
            }
        } else {
            L.l(format!("Binary contents: {}", hex::encode(&raw_stdout)));
        }
        L.l("=========================================");
        L.l(format!("Stderr for client {}:", client_number.name()));
        L.l("=========================================");
        for line in &stderr {
            L.l(line);
        }
        L.l("=========================================");
        L.l("");

        Ok(TestClientResult {
            client_number,
            client_path,
            status: exit_status,
            raw_stdout,
            stdout,
            stderr,
        })
    }

    pub fn expect_success(&self) -> Result<()> {
        if self.status.success() {
            Ok(())
        } else {
            bail!("Client {} failed", self.client_number.name());
        }
    }

    pub fn expect_failure(&self) -> Result<()> {
        if self.status.success() {
            bail!(
                "Client {} succeeded unexpectedly",
                self.client_number.name()
            );
        } else {
            Ok(())
        }
    }

    pub fn client_path(&self) -> &Path {
        &self.client_path
    }

    fn expect_line(&self, output: &[String], line: &str) -> Result<()> {
        for outputline in output {
            if outputline.contains(line) {
                L.l("Line found");
                return Ok(());
            }
        }
        L.l("Line not found");
        bail!("Expected line {} not found in output", line);
    }

    fn expect_not_line(&self, output: &[String], line: &str) -> Result<()> {
        if self.expect_line(output, line).is_ok() {
            bail!("Expected line {} found in output", line);
        } else {
            Ok(())
        }
    }

    pub fn expect_stderr_line(&self, line: &str) -> Result<()> {
        L.l(format!(
            "Checking for line {} in {} stderr to occur",
            line,
            self.client_number.name()
        ));
        self.expect_line(&self.stderr, line)
    }

    pub fn expect_not_stderr_line(&self, line: &str) -> Result<()> {
        L.l(format!(
            "Checking for line {} in {} stderr to NOT occur",
            line,
            self.client_number.name()
        ));
        self.expect_not_line(&self.stderr, line)
    }

    pub fn expect_stdout_line(&self, line: &str) -> Result<()> {
        if self.stdout.is_none() {
            bail!("Can only perform expect on non-binary stdout");
        }
        L.l(format!(
            "Checking for line {} in {} stdout to occur",
            line,
            self.client_number.name()
        ));
        self.expect_line(self.stdout.as_ref().unwrap(), line)
    }

    pub fn expect_not_stdout_line(&self, line: &str) -> Result<()> {
        if self.stdout.is_none() {
            bail!("Can only perform expect on non-binary stdout");
        }
        L.l(format!(
            "Checking for line {} in {} stdout to NOT occur",
            line,
            self.client_number.name()
        ));
        self.expect_not_line(self.stdout.as_ref().unwrap(), line)
    }

    pub fn raw_stdout(&self) -> &[u8] {
        &self.raw_stdout
    }
}

#[derive(Debug)]
pub struct TestServerConfigurator<'a> {
    binary: Binary,
    test_context: &'a TestContext,
    server_number: &'a TestBinaryNumber,
}

impl<'a> TestServerConfigurator<'a> {
    fn new(
        binary: Binary,
        test_context: &'a TestContext,
        server_number: &'a TestBinaryNumber,
    ) -> Self {
        TestServerConfigurator {
            binary,
            test_context,
            server_number,
        }
    }

    pub fn prepare_config_file<F>(
        &self,
        config_file_name: Option<&str>,
        context_configurator: F,
    ) -> Result<PathBuf>
    where
        F: FnOnce(&mut tera::Context) -> Result<()>,
    {
        let config_file_name =
            config_file_name.unwrap_or_else(|| self.binary.config_file_name().unwrap());
        let output_path = self
            .test_context
            .runner_path(&self.server_number)
            .join(config_file_name);

        self.test_context
            .generate_config_file(&output_path, config_file_name, |cfg| {
                cfg.insert(
                    "bind",
                    &format!("127.0.0.1:{}", self.server_number.server_port().unwrap()),
                );
                cfg.insert("test_dir", &self.test_context.testpath());
                cfg.insert("owner_port", &self.server_number.server_port().unwrap());
                cfg.insert(
                    "config_dir",
                    &self.test_context.runner_path(&self.server_number),
                );
                cfg.insert(
                    "user",
                    users::get_current_username().unwrap().to_str().unwrap(),
                );
                // TODO: Insert more defaults

                context_configurator(cfg)
            })?;

        Ok(output_path)
    }
}

#[derive(Debug)]
struct TestServer {
    server_path: PathBuf,
    server_number: TestBinaryNumber,
    child: Child,
}

impl TestServer {
    fn new(server_path: PathBuf, server_number: TestBinaryNumber, child: Child) -> Result<Self> {
        Ok(TestServer {
            server_path,
            server_number,
            child,
        })
    }

    async fn wait_until_ready(&mut self) -> Result<()> {
        let start = Instant::now();
        let client = reqwest::Client::new();
        loop {
            let res = client
                .post(&format!(
                    "http://localhost:{}/ping",
                    self.server_number.server_port().unwrap()
                ))
                .send()
                .await;
            if res.is_ok() {
                L.l("Server is ready");
                return Ok(());
            }
            L.l(format!("Server was not yet ready: {:?}", res));
            if start.elapsed() > MAX_WAIT_FOR_READY {
                bail!("Server failed to start");
            }
            if self
                .child
                .try_wait()
                .context("Failed to check for child status")?
                .is_some()
            {
                bail!("Server child failed to start");
            }
            L.l(format!(
                "Server is not yet ready, waiting {:?}",
                WAIT_BETWEEN_READY_TESTS
            ));
            std::thread::sleep(WAIT_BETWEEN_READY_TESTS);
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };

        match self.child.wait() {
            Err(e) => L.l(format!(
                "Error waiting for server {}: {:?}",
                self.server_number.name(),
                e
            )),
            Ok(v) if v.success() => L.l(format!(
                "Server {} exited with code {:?} (SUCCESS)",
                self.server_number.name(),
                v.code()
            )),
            Ok(v) => L.l(format!(
                "Server {} exited with code {:?} (NON-SUCCESS)",
                self.server_number.name(),
                v.code()
            )),
        }

        for outfile in ["stdout", "stderr"] {
            let path = self.server_path.join(outfile);
            L.l(format!(
                "{} for server {}:",
                outfile,
                self.server_number.name()
            ));
            L.l("=========================================");
            match File::open(&path) {
                Err(e) => L.l(format!("Error opening {} ({:?}): {:?}", outfile, path, e)),
                Ok(mut file) => {
                    let bufreader = BufReader::new(&mut file);
                    for line in bufreader.lines() {
                        L.l(line.unwrap());
                    }
                }
            }
            L.l("=========================================");
            L.l("");
        }
    }
}
