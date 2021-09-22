#![allow(dead_code)]

use std::{
    env,
    fs::{create_dir, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output},
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
#[allow(unused_imports)]
use pretty_assertions::{assert_eq, assert_ne};

const TARGET_TMPDIR: &str = env!("CARGO_TARGET_TMPDIR");
const KEY_NAMES: &[&str] = &["manufacturer", "device_ca", "owner", "reseller", "diun"];

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
            Binary::ManufacturingServer => "fdo-manufacturing-service",
            Binary::OwnerOnboardingServer => "fdo-owner-onboarding-service",
            Binary::OwnerTool => "fdo-owner-tool",
            Binary::RendezvousServer => "fdo-rendezvous-server",
        }
    }

    fn config_file_name(&self) -> Option<&str> {
        match self {
            Binary::ManufacturingServer => Some("manufacturing-service.yml"),
            Binary::OwnerOnboardingServer => Some("owner-onboarding-service.yml"),
            Binary::RendezvousServer => Some("rendezvous-service.yml"),
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
            Binary::ManufacturingClient => Some("MANUFACTURING_SERVICE_URL"),
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
}

impl TestBinaryNumber {
    fn new(binary: Binary, number: u16) -> Self {
        let name = format!("{}-{}", binary, number);
        TestBinaryNumber {
            binary,
            number,
            name,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn server_port(&self) -> Option<u16> {
        if self.binary.is_server() {
            Some(8080 + self.number)
        } else {
            None
        }
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

    fn create_keys(&self) -> Result<()> {
        let keys_path = self.testpath.join("keys");
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
            std::fs::write(keys_path.join(format!("{}_key.der", key_name)), private_key)
                .context("Error writing private key")?;
            std::fs::write(keys_path.join(format!("{}_cert.pem", key_name)), cert)
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
        F1: FnOnce(&mut TestServerConfigurator) -> Result<()>,
        F2: FnOnce(&mut Command) -> Result<()>,
    {
        self.test_servers_ready = false;

        let test_server_number = self.test_binary_number_generator.next(binary);

        let server_path = self.testpath.join(test_server_number.name());
        create_dir(&server_path).context("Error creating directory")?;

        // Create the config file
        config_configurator(&mut TestServerConfigurator::new(
            binary,
            self.testpath(),
            &server_path,
            &test_server_number,
        ))
        .context("Error configuring server")?;

        // Create the Command
        let cmd_path = self.target_directory.join(binary.target_name());
        let mut cmd = Command::new(&cmd_path);

        // Do initial configuration: everything can be overridden by the configurator
        cmd.current_dir(&server_path)
            .env("LOG_LEVEL", "trace")
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
        self.run_client(Binary::OwnerTool, None, |cfg| {
            cfg.current_dir(working_dir).args(args);

            Ok(())
        })
    }

    pub fn run_client<F>(
        &mut self,
        binary: Binary,
        server: Option<&TestBinaryNumber>,
        configurator: F,
    ) -> Result<TestClientResult>
    where
        F: FnOnce(&mut Command) -> Result<()>,
    {
        self.check_test_servers_ready()?;

        let client_number = self.test_binary_number_generator.next(binary);
        let client_path = self.testpath.join(client_number.name());

        create_dir(&client_path).context("Error creating directory")?;

        let cmd_path = self.target_directory.join(binary.target_name());
        let mut cmd = Command::new(&cmd_path);

        L.l(format!(
            "Running client {}, path: {:?}, client_path: {:?}, command: {:?}",
            client_number.name(),
            cmd_path,
            client_path,
            cmd
        ));

        // Do initial configuration: everything can be overridden by the configurator
        cmd.current_dir(&client_path).env("LOG_LEVEL", "trace");

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

        let output = cmd.output().context("Error running client")?;
        let result = TestClientResult::new(client_number, client_path, output);

        Ok(result)
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
    stdout: Vec<String>,
    stderr: Vec<String>,
}

impl TestClientResult {
    fn new(client_number: TestBinaryNumber, client_path: PathBuf, output: Output) -> Self {
        L.l(format!(
            "Client {} succeeded: {}",
            client_number.name(),
            output.status.success()
        ));

        let status = output.status;
        let stdout: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .split('\n')
            .map(String::from)
            .collect();
        let stderr: Vec<String> = String::from_utf8_lossy(&output.stderr)
            .split('\n')
            .map(String::from)
            .collect();

        L.l(format!("Stdout for client {}:", client_number.name()));
        L.l("=========================================");
        for line in &stdout {
            L.l(line);
        }
        L.l("=========================================");
        L.l(format!("Stderr for client {}:", client_number.name()));
        L.l("=========================================");
        for line in &stderr {
            L.l(line);
        }
        L.l("=========================================");
        L.l("");

        TestClientResult {
            client_number,
            client_path,
            status,
            stdout,
            stderr,
        }
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
        L.l(format!(
            "Checking for line {} in {} stdout to occur",
            line,
            self.client_number.name()
        ));
        self.expect_line(&self.stdout, line)
    }

    pub fn expect_not_stdout_line(&self, line: &str) -> Result<()> {
        L.l(format!(
            "Checking for line {} in {} stdout to NOT occur",
            line,
            self.client_number.name()
        ));
        self.expect_not_line(&self.stdout, line)
    }
}

#[derive(Debug)]
pub struct TestServerConfigurator<'a> {
    binary: Binary,
    test_path: &'a Path,
    server_path: &'a Path,
    server_number: &'a TestBinaryNumber,
}

impl<'a> TestServerConfigurator<'a> {
    fn new(
        binary: Binary,
        test_path: &'a Path,
        server_path: &'a Path,
        server_number: &'a TestBinaryNumber,
    ) -> Self {
        TestServerConfigurator {
            binary,
            test_path,
            server_path,
            server_number,
        }
    }

    pub fn prepare_config_file<F>(
        &self,
        config_file_name: Option<&str>,
        context_configurator: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut tera::Context) -> Result<()>,
    {
        L.l(format!(
            "Preparing configuration file {:?} for {}",
            config_file_name,
            self.server_number.name(),
        ));
        let config_file_name =
            config_file_name.unwrap_or_else(|| self.binary.config_file_name().unwrap());

        let mut template_context = tera::Context::new();

        // TODO: Insert defaults
        template_context.insert("keys_path", &self.test_path.join("keys"));
        template_context.insert(
            "bind",
            &format!("127.0.0.1:{}", self.server_number.server_port().unwrap()),
        );

        context_configurator(&mut template_context)
            .context("Error running context configurator")?;

        let config = TEMPLATES
            .render(&format!("{}.j2", config_file_name), &template_context)
            .context("Error rendering configuration template")?;
        std::fs::write(self.server_path.join(config_file_name), config)
            .context("Error writing configuration file")
    }

    pub fn create_empty_storage_folder(&self, name: &str) -> Result<()> {
        create_dir(self.server_path.join(&name))
            .with_context(|| format!("Error creating empty storage folder: {}", name))
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
        let mut attempts = 0;
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
                return Ok(());
            }
            L.l(format!("Server was not yet ready: {:?}", res));
            attempts += 1;
            if attempts > 10 {
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
            L.l("Server is not yet ready, waiting 1 second");
            std::thread::sleep(std::time::Duration::from_secs(1));
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
