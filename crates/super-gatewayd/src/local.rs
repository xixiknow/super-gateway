//! Self-contained local `PostgreSQL` lifecycle and startup preparation.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context as _, bail};
use gateway_domain::SecretValue;
use gateway_storage::{MigrationReport, PgStorage, RuntimeRolePolicy};
use tokio::process::Command;

use crate::config::{GatewayConfig, ensure_local_secret};

const LOCAL_DATABASE_NAME: &str = "super_gateway";
const LOCAL_DATABASE_USER: &str = "super_gateway_local";
const POSTGRES_TRANSITION_TIMEOUT: Duration = Duration::from_secs(45);
const POSTGRES_TRANSITION_POLL_INTERVAL: Duration = Duration::from_millis(500);

pub(crate) struct LocalRuntime {
    config: Option<GatewayConfig>,
    postgres: ManagedPostgres,
    migration_report: MigrationReport,
    state_dir: PathBuf,
}

impl LocalRuntime {
    pub(crate) async fn prepare() -> anyhow::Result<Self> {
        let _dotenv_result = dotenvy::dotenv();
        let state_dir = std::env::var_os("GATEWAY_LOCAL_STATE_DIR")
            .map_or_else(|| PathBuf::from(".super-gateway-local"), PathBuf::from);
        let state_dir = if state_dir.is_absolute() {
            state_dir
        } else {
            std::env::current_dir()
                .context("local working directory is unavailable")?
                .join(state_dir)
        };
        std::fs::create_dir_all(&state_dir).context("local state directory initialization failed")?;
        let requested_port = std::env::var("GATEWAY_LOCAL_POSTGRES_PORT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("local PostgreSQL port is invalid"))
            })
            .transpose()?;
        let postgres = ManagedPostgres::start(&state_dir, requested_port).await?;
        let migration_report = PgStorage::provision_and_migrate(postgres.database_url())
            .await
            .context("local database initialization and migration failed")?;
        let storage = PgStorage::connect(postgres.database_url(), RuntimeRolePolicy::AllowPrivilegedLocal)
            .await
            .context("local database connection failed after migration")?;
        crate::local_bundle::ensure_local_bundle(&state_dir, &storage.pool())
            .await
            .context("local Bundle initialization failed")?;
        storage.pool().close().await;
        let config = GatewayConfig::load_local(&state_dir, postgres.database_url())
            .context("local gateway configuration initialization failed")?;
        config
            .ensure_runtime_supported()
            .context("local gateway configuration selects an unavailable runtime adapter")?;
        Ok(Self {
            config: Some(config),
            postgres,
            migration_report,
            state_dir,
        })
    }

    pub(crate) fn take_config(&mut self) -> anyhow::Result<GatewayConfig> {
        self.config
            .take()
            .context("local gateway configuration was already consumed")
    }

    pub(crate) fn print_summary(&self) {
        println!(
            "local database ready: schema_version={}, applied_migrations={}",
            self.migration_report.current_version, self.migration_report.applied_count
        );
        println!("local admin username: admin");
        println!("local PostgreSQL: 127.0.0.1:{}", self.postgres.port);
        println!(
            "local built-in Bundle: {}",
            self.state_dir
                .join("bundles")
                .join("windows-claude-code-2.1.241-h1.json")
                .display()
        );
        println!(
            "local admin password file: {}",
            self.state_dir.join("admin-password").display()
        );
        println!("local management console: http://127.0.0.1:8081/admin/");
    }

    pub(crate) async fn shutdown(&mut self) {
        if let Err(error) = self.postgres.stop().await {
            tracing::warn!(error = %error, "local PostgreSQL shutdown failed");
        }
    }
}

struct ManagedPostgres {
    bin_dir: PathBuf,
    data_dir: PathBuf,
    database_url: SecretValue,
    port: u16,
    started_by_this_process: bool,
}

impl ManagedPostgres {
    async fn start(state_dir: &Path, requested_port: Option<u16>) -> anyhow::Result<Self> {
        let data_dir = state_dir.join("postgres-data");
        let bin_dir = discover_postgres_bin(&data_dir)?;
        let password_file = state_dir.join("postgres-superuser-password");
        let password =
            ensure_local_secret(&password_file).context("local PostgreSQL password initialization failed")?;
        if !data_dir.join("PG_VERSION").exists() {
            let initdb = postgres_tool(&bin_dir, "initdb");
            run_checked(
                &initdb,
                [
                    "--pgdata".into(),
                    data_dir.as_os_str().to_owned(),
                    "--username".into(),
                    LOCAL_DATABASE_USER.into(),
                    "--pwfile".into(),
                    password_file.as_os_str().to_owned(),
                    "--auth-host".into(),
                    "scram-sha-256".into(),
                    "--auth-local".into(),
                    "trust".into(),
                    "--encoding".into(),
                    "UTF8".into(),
                    "--no-locale".into(),
                ],
                "initdb",
            )
            .await
            .context("local PostgreSQL cluster initialization failed")?;
        }

        let pg_ctl = postgres_tool(&bin_dir, "pg_ctl");
        let status = Command::new(&pg_ctl)
            .arg("status")
            .arg("--pgdata")
            .arg(&data_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .context("local PostgreSQL status check failed")?;
        let port_file = state_dir.join("postgres-port");
        let port = if status.success() {
            let persisted = std::fs::read_to_string(&port_file)
                .context("running local PostgreSQL has no persisted port")?
                .trim()
                .parse::<u16>()
                .context("persisted local PostgreSQL port is invalid")?;
            if requested_port.is_some_and(|requested| requested != persisted) {
                bail!("running local PostgreSQL uses a different port than GATEWAY_LOCAL_POSTGRES_PORT");
            }
            persisted
        } else {
            let selected = requested_port.map_or_else(select_loopback_port, Ok)?;
            std::fs::write(&port_file, selected.to_string()).context("local PostgreSQL port persistence failed")?;
            selected
        };
        let should_start = if status.success() {
            match wait_for_postgres_transition(&bin_dir, &data_dir, port).await? {
                PostgresTransition::AcceptingConnections => false,
                PostgresTransition::Stopped => true,
            }
        } else {
            true
        };
        let started_by_this_process = if should_start {
            let log_file = state_dir.join("postgres.log");
            run_status_checked(
                &pg_ctl,
                [
                    "start".into(),
                    "--pgdata".into(),
                    data_dir.as_os_str().to_owned(),
                    "--log".into(),
                    log_file.as_os_str().to_owned(),
                    "--options".into(),
                    format!("-h 127.0.0.1 -p {port}").into(),
                    "--wait".into(),
                ],
                "pg_ctl start",
            )
            .await
            .with_context(|| format!("local PostgreSQL start failed; inspect {}", log_file.display()))?;
            true
        } else {
            false
        };
        let database_url = SecretValue::new(format!(
            "postgres://{LOCAL_DATABASE_USER}:{}@127.0.0.1:{port}/{LOCAL_DATABASE_NAME}",
            password.expose()
        ));
        Ok(Self {
            bin_dir,
            data_dir,
            database_url,
            port,
            started_by_this_process,
        })
    }

    fn database_url(&self) -> &SecretValue {
        &self.database_url
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if !self.started_by_this_process {
            return Ok(());
        }
        let pg_ctl = postgres_tool(&self.bin_dir, "pg_ctl");
        run_checked(
            &pg_ctl,
            [
                "stop".into(),
                "--pgdata".into(),
                self.data_dir.as_os_str().to_owned(),
                "--mode".into(),
                "fast".into(),
                "--wait".into(),
            ],
            "pg_ctl stop",
        )
        .await?;
        self.started_by_this_process = false;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PostgresTransition {
    AcceptingConnections,
    Stopped,
}

async fn wait_for_postgres_transition(
    bin_dir: &Path,
    data_dir: &Path,
    port: u16,
) -> anyhow::Result<PostgresTransition> {
    let pg_isready = postgres_tool(bin_dir, "pg_isready");
    let pg_ctl = postgres_tool(bin_dir, "pg_ctl");
    let started_at = Instant::now();
    tracing::info!(port, "waiting for local PostgreSQL startup or shutdown transition");
    loop {
        let ready = Command::new(&pg_isready)
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--timeout")
            .arg("1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .context("local PostgreSQL readiness check failed")?;
        if ready.success() {
            return Ok(PostgresTransition::AcceptingConnections);
        }

        let status = Command::new(&pg_ctl)
            .arg("status")
            .arg("--pgdata")
            .arg(data_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .context("local PostgreSQL transition status check failed")?;
        if !status.success() {
            return Ok(PostgresTransition::Stopped);
        }
        if started_at.elapsed() >= POSTGRES_TRANSITION_TIMEOUT {
            bail!(
                "local PostgreSQL remained unavailable on port {port} for {} seconds",
                POSTGRES_TRANSITION_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(POSTGRES_TRANSITION_POLL_INTERVAL).await;
    }
}

fn select_loopback_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .context("no local PostgreSQL port is available")?;
    listener
        .local_addr()
        .map(|address| address.port())
        .context("local PostgreSQL port selection failed")
}

impl Drop for ManagedPostgres {
    fn drop(&mut self) {
        if !self.started_by_this_process {
            return;
        }
        let _status = std::process::Command::new(postgres_tool(&self.bin_dir, "pg_ctl"))
            .arg("stop")
            .arg("--pgdata")
            .arg(&self.data_dir)
            .arg("--mode")
            .arg("fast")
            .arg("--wait")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn run_checked<I>(program: &Path, args: I, label: &str) -> anyhow::Result<()>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("{label} could not be started"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        bail!("{label} exited unsuccessfully: {}", detail.trim());
    }
    Ok(())
}

async fn run_status_checked<I>(program: &Path, args: I, label: &str) -> anyhow::Result<()>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let status = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .with_context(|| format!("{label} could not be started"))?;
    if !status.success() {
        bail!("{label} exited unsuccessfully");
    }
    Ok(())
}

#[cfg_attr(not(target_os = "windows"), allow(unused_variables))]
fn discover_postgres_bin(data_dir: &Path) -> anyhow::Result<PathBuf> {
    if let Some(configured) = std::env::var_os("GATEWAY_LOCAL_POSTGRES_BIN") {
        let configured = PathBuf::from(configured);
        validate_postgres_bin(&configured)?;
        return Ok(configured);
    }
    #[cfg(target_os = "windows")]
    let required_major = std::fs::read_to_string(data_dir.join("PG_VERSION"))
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());

    #[cfg(target_os = "windows")]
    {
        let program_files =
            std::env::var_os("ProgramFiles").map_or_else(|| PathBuf::from(r"C:\Program Files"), PathBuf::from);
        let root = program_files.join("PostgreSQL");
        let mut candidates = std::fs::read_dir(&root)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let major = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
                (major >= 16 && required_major.is_none_or(|required| required == major))
                    .then(|| (major, entry.path().join("bin")))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(major, _)| std::cmp::Reverse(*major));
        if let Some((_, candidate)) = candidates
            .into_iter()
            .find(|(_, path)| validate_postgres_bin(path).is_ok())
        {
            return Ok(candidate);
        }
    }

    let path_candidate = PathBuf::new();
    if validate_postgres_bin(&path_candidate).is_ok() {
        return Ok(path_candidate);
    }
    bail!(
        "PostgreSQL 16+ tools were not found; set GATEWAY_LOCAL_POSTGRES_BIN to the directory containing initdb, pg_ctl, and pg_isready"
    )
}

fn validate_postgres_bin(bin_dir: &Path) -> anyhow::Result<()> {
    for tool in ["initdb", "pg_ctl", "pg_isready"] {
        let path = postgres_tool(bin_dir, tool);
        if !path.is_file() && !bin_dir.as_os_str().is_empty() {
            bail!("required PostgreSQL tool is missing: {}", path.display());
        }
    }
    Ok(())
}

fn postgres_tool(bin_dir: &Path, name: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    let name = format!("{name}.exe");
    #[cfg(not(target_os = "windows"))]
    let name = name.to_owned();
    bin_dir.join(name)
}
