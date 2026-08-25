#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use capture_schema::{
    CAPTURE_SCHEMA_VERSION, CaptureBatch, CaptureEvent, CaptureLane, ConnectionPhase, Direction,
    DnsMode, EnvironmentDescriptor, NetworkDescriptor, NetworkPath, ScenarioDescriptor,
    TargetDescriptor,
};
use clap::{Parser, Subcommand};
use controlled_h2_capture::{ControlledH2Result, ControlledH2Server};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use tls_tap::{
    ConnectTlsTapConfig, ConnectTlsTapListener, ParsedClientHello, UpstreamHttpProxy,
    parse_client_hello,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    task::JoinHandle,
};
use uuid::Uuid;
use wire_normalizer::{NormalizedCapture, normalize_capture};

const CONTROLLED_AUTH_PREFIX: &str = "capture-synthetic-";
const CONNECTION_ID: &str = "claude-capture-connection";

#[derive(Debug, Parser)]
#[command(about = "Run privacy-safe Claude Code transport evidence captures")]
struct Cli {
    #[arg(long, global = true, default_value = "claude")]
    claude_bin: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, global = true)]
    capture_run_id: Option<Uuid>,
    #[arg(long, global = true, default_value_t = 45)]
    timeout_seconds: u64,
    #[command(subcommand)]
    command: CaptureCommand,
}

#[derive(Debug, Subcommand)]
enum CaptureCommand {
    /// Capture real Claude Code HTTP/2 behavior against a local synthetic endpoint.
    Controlled {
        #[arg(long, default_value = "Reply with exactly: capture complete")]
        prompt: String,
        #[arg(long, default_value = "sonnet")]
        model: String,
    },
    /// Repeats the controlled capture in isolated Claude processes and writes
    /// a secret-free stability report plus one normalized artifact per success.
    ControlledBatch {
        #[arg(long, default_value_t = 20)]
        iterations: usize,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "Reply with exactly: capture complete")]
        prompt: String,
        #[arg(long, default_value = "sonnet")]
        model: String,
    },
    /// Capture only the TLS `ClientHello` sent to the official Anthropic endpoint.
    OfficialTls {
        #[arg(long, conflicts_with = "synthetic_auth")]
        execute_paid_request: bool,
        /// Use an ephemeral invalid token: captures official TLS without model usage.
        #[arg(long, conflicts_with = "execute_paid_request")]
        synthetic_auth: bool,
        #[arg(long, default_value = "Reply with exactly: capture complete")]
        prompt: String,
        #[arg(long, default_value = "sonnet")]
        model: String,
        #[arg(long, default_value_t = 8)]
        max_rejected_tunnels: usize,
    },
}

#[derive(Debug, Serialize)]
struct RunSummary {
    capture_run_id: Uuid,
    capture_artifact_id: Uuid,
    lane: CaptureLane,
    output: PathBuf,
    event_count: usize,
    normalized_sha256: String,
    claude_exit_code: Option<i32>,
    claude_stdout_bytes: usize,
    claude_stderr_bytes: usize,
    claude_timed_out: bool,
    claude_protocol: ChildProtocolSummary,
}

#[derive(Debug, Serialize)]
struct BatchArtifactSummary {
    iteration: usize,
    file_name: String,
    normalized_sha256: String,
    event_count: usize,
}

#[derive(Debug, Serialize)]
struct ControlledBatchReport {
    schema_version: u32,
    observed_at: String,
    claude_code_version: String,
    requested_iterations: usize,
    successful_iterations: usize,
    failed_iterations: usize,
    failure_categories: BTreeMap<String, usize>,
    artifacts: Vec<BatchArtifactSummary>,
    decision: String,
    report_sha256: String,
}

#[derive(Debug)]
struct ChildSummary {
    exit_code: Option<i32>,
    stdout_bytes: usize,
    stderr_bytes: usize,
    timed_out: bool,
    protocol: ChildProtocolSummary,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ChildProtocolSummary {
    init_events: usize,
    assistant_events: usize,
    result_events: usize,
    result_success_events: usize,
    result_error_events: usize,
    result_subtypes: BTreeMap<String, usize>,
    result_field_names: BTreeMap<String, usize>,
    result_error_categories: BTreeMap<String, usize>,
    assistant_models: BTreeMap<String, usize>,
    assistant_stop_reasons: BTreeMap<String, usize>,
    assistant_content_types: BTreeMap<String, usize>,
    api_retry_events: usize,
    api_retry_statuses: BTreeMap<String, usize>,
    api_retry_error_categories: BTreeMap<String, usize>,
    api_retry_field_names: BTreeMap<String, usize>,
    rate_limit_events: usize,
    rate_limit_field_names: BTreeMap<String, usize>,
    stream_events: usize,
    stream_event_types: BTreeMap<String, usize>,
    usage_input_tokens: u64,
    usage_output_tokens: u64,
    usage_cache_creation_input_tokens: u64,
    usage_cache_read_input_tokens: u64,
    other_json_events: usize,
    invalid_json_lines: usize,
    diagnostic_prefix_truncated: bool,
}

#[derive(Debug)]
struct DrainedOutput {
    total_bytes: usize,
    diagnostic_prefix: Vec<u8>,
    truncated: bool,
}

struct OfficialCaptureOptions<'a> {
    prompt: &'a str,
    model: &'a str,
    timeout: Duration,
    max_rejected_tunnels: usize,
    synthetic_auth: bool,
    require_completed_exchange: bool,
}

struct ControlledBatchOptions<'a> {
    prompt: &'a str,
    model: &'a str,
    iterations: usize,
    output_dir: &'a Path,
    report_path: &'a Path,
    timeout: Duration,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(cli.timeout_seconds > 0, "timeout-seconds must be positive");
    let timeout = Duration::from_secs(cli.timeout_seconds);
    let capture_run_id = cli.capture_run_id.unwrap_or_else(Uuid::new_v4);
    let environment = inspect_environment(&cli.claude_bin, timeout).await?;
    let (normalized, child) = match cli.command {
        CaptureCommand::Controlled { prompt, model } => {
            run_controlled(
                &cli.claude_bin,
                &prompt,
                &model,
                capture_run_id,
                environment,
                timeout,
            )
            .await?
        }
        CaptureCommand::ControlledBatch {
            iterations,
            output_dir,
            prompt,
            model,
        } => {
            return run_controlled_batch(
                &cli.claude_bin,
                environment,
                ControlledBatchOptions {
                    prompt: &prompt,
                    model: &model,
                    iterations,
                    output_dir: &output_dir,
                    report_path: &cli.output,
                    timeout,
                },
            )
            .await;
        }
        CaptureCommand::OfficialTls {
            execute_paid_request,
            synthetic_auth,
            prompt,
            model,
            max_rejected_tunnels,
        } => {
            ensure!(
                execute_paid_request || synthetic_auth,
                "official-tls requires either --synthetic-auth or --execute-paid-request"
            );
            run_official_tls(
                &cli.claude_bin,
                capture_run_id,
                environment,
                OfficialCaptureOptions {
                    prompt: &prompt,
                    model: &model,
                    timeout,
                    max_rejected_tunnels,
                    synthetic_auth,
                    require_completed_exchange: execute_paid_request,
                },
            )
            .await?
        }
    };
    persist_normalized(&cli.output, &normalized)?;
    let summary = RunSummary {
        capture_run_id,
        capture_artifact_id: normalized.capture_artifact_id,
        lane: normalized.lane.clone(),
        output: cli.output,
        event_count: normalized.event_count(),
        normalized_sha256: normalized.normalized_sha256.clone(),
        claude_exit_code: child.exit_code,
        claude_stdout_bytes: child.stdout_bytes,
        claude_stderr_bytes: child.stderr_bytes,
        claude_timed_out: child.timed_out,
        claude_protocol: child.protocol,
    };
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn run_controlled_batch(
    claude_bin: &Path,
    environment: EnvironmentDescriptor,
    options: ControlledBatchOptions<'_>,
) -> Result<()> {
    ensure!(options.iterations > 0, "iterations must be positive");
    ensure!(
        !options.report_path.exists(),
        "batch report already exists: {}",
        options.report_path.display()
    );
    std::fs::create_dir_all(options.output_dir).with_context(|| {
        format!(
            "create batch output directory {}",
            options.output_dir.display()
        )
    })?;
    let mut artifacts = Vec::with_capacity(options.iterations);
    let mut failure_categories = BTreeMap::new();
    for iteration in 1..=options.iterations {
        let capture_run_id = Uuid::new_v4();
        match run_controlled(
            claude_bin,
            options.prompt,
            options.model,
            capture_run_id,
            environment.clone(),
            options.timeout,
        )
        .await
        {
            Ok((normalized, _child)) => {
                let file_name = format!("{iteration:02}-controlled.normalized.json");
                let output = options.output_dir.join(&file_name);
                persist_normalized(&output, &normalized)?;
                artifacts.push(BatchArtifactSummary {
                    iteration,
                    file_name,
                    normalized_sha256: normalized.normalized_sha256.clone(),
                    event_count: normalized.event_count(),
                });
            }
            Err(error) => {
                let category = classify_batch_failure(&error);
                *failure_categories.entry(category.to_owned()).or_insert(0) += 1;
            }
        }
    }
    let successful_iterations = artifacts.len();
    let failed_iterations = options.iterations.saturating_sub(successful_iterations);
    let mut report = ControlledBatchReport {
        schema_version: 1,
        observed_at: observed_at(),
        claude_code_version: environment.claude_code_version,
        requested_iterations: options.iterations,
        successful_iterations,
        failed_iterations,
        failure_categories,
        artifacts,
        decision: if failed_iterations == 0 {
            "pass"
        } else {
            "fail"
        }
        .to_owned(),
        report_sha256: String::new(),
    };
    report.report_sha256 = controlled_batch_report_sha256(&report)?;
    persist_json(options.report_path, &report)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    ensure!(
        failed_iterations == 0,
        "controlled batch completed with {failed_iterations} failed iteration(s)"
    );
    Ok(())
}

fn classify_batch_failure(error: &anyhow::Error) -> &'static str {
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("connection reset") || message.contains("10054") {
        "connection_reset"
    } else if message.contains("timed out") || message.contains("timeout") {
        "timeout"
    } else if message.contains("tls") {
        "tls"
    } else if message.contains("http") {
        "http"
    } else {
        "other"
    }
}

fn controlled_batch_report_sha256(report: &ControlledBatchReport) -> Result<String> {
    let value = serde_json::to_value(report)?;
    let mut object = value
        .as_object()
        .cloned()
        .context("controlled batch report is not an object")?;
    object.insert(
        "report_sha256".to_owned(),
        serde_json::Value::String(String::new()),
    );
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&object)?)))
}

async fn run_controlled(
    claude_bin: &Path,
    prompt: &str,
    model: &str,
    capture_run_id: Uuid,
    environment: EnvironmentDescriptor,
    timeout: Duration,
) -> Result<(NormalizedCapture, ChildSummary)> {
    let synthetic_token = format!("{CONTROLLED_AUTH_PREFIX}{}", Uuid::new_v4());
    let server = ControlledH2Server::bind_claude_messages(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        "127.0.0.1",
        timeout,
        4 * 1024 * 1024,
        synthetic_token.clone(),
        4 * 1024 * 1024,
    )
    .await
    .context("bind controlled Claude Messages endpoint")?;
    let endpoint = server
        .local_addr()
        .context("read controlled endpoint address")?;
    let temp = tempfile::tempdir().context("create isolated Claude workspace")?;
    let ca_path = temp.path().join("capture-ca.pem");
    tokio::fs::write(&ca_path, server.ca_pem())
        .await
        .context("write ephemeral capture CA")?;
    let base_url = format!("https://127.0.0.1:{}", endpoint.port());
    let config_dir = temp.path().join("claude-config");
    tokio::fs::create_dir(&config_dir)
        .await
        .context("create isolated Claude configuration")?;
    let settings_path = temp.path().join("capture-settings.json");
    let settings = serde_json::json!({
        "env": {
            "ANTHROPIC_BASE_URL": base_url,
            "ANTHROPIC_AUTH_TOKEN": synthetic_token,
            "NODE_EXTRA_CA_CERTS": ca_path,
            "SSL_CERT_FILE": ca_path,
            "DISABLE_AUTOUPDATER": "1"
        }
    });
    tokio::fs::write(&settings_path, serde_json::to_vec(&settings)?)
        .await
        .context("write ephemeral Claude capture settings")?;
    let capture_task = tokio::spawn(server.capture_one());
    let child = run_claude(
        claude_bin,
        prompt,
        model,
        temp.path(),
        timeout.min(Duration::from_secs(15)),
        |command| {
            scrub_controlled_environment(command);
            command
                .env("ANTHROPIC_BASE_URL", &base_url)
                .env("ANTHROPIC_AUTH_TOKEN", &synthetic_token)
                .env("NODE_EXTRA_CA_CERTS", &ca_path)
                .env("SSL_CERT_FILE", &ca_path)
                .env("CLAUDE_CONFIG_DIR", &config_dir)
                .arg("--settings")
                .arg(&settings_path)
                .arg("--setting-sources")
                .arg("")
                .arg("--strict-mcp-config")
                .arg("--disable-slash-commands");
        },
    )
    .await;
    let result = join_capture(capture_task).await?;
    let child = child.context("run Claude Code against controlled endpoint")?;
    let summary = result
        .request_summary
        .as_ref()
        .ok_or_else(|| anyhow!("controlled endpoint did not observe a Messages request"))?;
    ensure!(summary.body_bytes > 0, "controlled Messages body was empty");
    ensure!(
        summary.synthetic_authorization_matched,
        "controlled endpoint did not receive its generated synthetic credential"
    );
    eprintln!("privacy-safe controlled request shape: {summary:#?}");
    eprintln!(
        "recognized and answered {} non-essential background request(s) before the main request",
        result.skipped_background_requests
    );
    ensure!(
        !child.timed_out
            && child.exit_code == Some(0)
            && child.protocol.assistant_events > 0
            && child.protocol.result_success_events > 0
            && child.protocol.result_error_events == 0
            && child.protocol.api_retry_events == 0,
        "controlled capture child did not complete a retry-free assistant/result exchange"
    );
    let batch = controlled_batch(capture_run_id, environment, &result);
    Ok((normalize_capture(&batch)?, child))
}

fn controlled_batch(
    capture_run_id: Uuid,
    environment: EnvironmentDescriptor,
    result: &ControlledH2Result,
) -> CaptureBatch {
    CaptureBatch {
        schema_version: CAPTURE_SCHEMA_VERSION,
        capture_artifact_id: Uuid::new_v4(),
        capture_run_id,
        lane: CaptureLane::ReferenceControlledEndpoint,
        observed_at: observed_at(),
        environment,
        target: TargetDescriptor {
            authority: "127.0.0.1".to_owned(),
            official_anthropic: false,
        },
        network: NetworkDescriptor {
            path: NetworkPath::Direct,
            dns_mode: DnsMode::Local,
            proxy_software: None,
            proxy_version: None,
        },
        scenario: ScenarioDescriptor {
            id: "T01-real-claude-minimal-message".to_owned(),
            fresh_connection: true,
            expected_protocol: result.negotiated_alpn.clone(),
            concurrent_streams: 1,
            request_shape: "real-claude-minimal-message".to_owned(),
        },
        events: controlled_events(result),
    }
}

async fn run_official_tls(
    claude_bin: &Path,
    capture_run_id: Uuid,
    environment: EnvironmentDescriptor,
    options: OfficialCaptureOptions<'_>,
) -> Result<(NormalizedCapture, ChildSummary)> {
    let OfficialCaptureOptions {
        prompt,
        model,
        timeout,
        max_rejected_tunnels,
        synthetic_auth,
        require_completed_exchange,
    } = options;
    let upstream_http_proxy = inherited_http_proxy()?;
    let chained_upstream_proxy = upstream_http_proxy.is_some();
    let tap = ConnectTlsTapListener::bind(ConnectTlsTapConfig {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        allowed_host: "api.anthropic.com".to_owned(),
        allowed_port: 443,
        max_connect_header_bytes: 16 * 1024,
        max_capture_bytes: 256 * 1024,
        session_timeout: timeout,
        upstream_http_proxy,
    })
    .await
    .context("bind official TLS CONNECT capture")?;
    let proxy_addr = tap.local_addr().context("read CONNECT capture address")?;
    let temp = tempfile::tempdir().context("create isolated Claude workspace")?;
    let capture_task = tokio::spawn(tap.capture_allowed(max_rejected_tunnels));
    let proxy_url = format!("http://{proxy_addr}");
    let settings_path = temp.path().join("official-capture-settings.json");
    let settings = official_proxy_settings(&proxy_url);
    tokio::fs::write(&settings_path, serde_json::to_vec(&settings)?)
        .await
        .context("write ephemeral official capture settings")?;
    let synthetic_token =
        synthetic_auth.then(|| format!("{CONTROLLED_AUTH_PREFIX}official-{}", Uuid::new_v4()));
    let child = run_claude(claude_bin, prompt, model, temp.path(), timeout, |command| {
        command
            .env_remove("ANTHROPIC_BASE_URL")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("ANTHROPIC_AUTH_TOKEN")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env("HTTPS_PROXY", &proxy_url)
            .env("HTTP_PROXY", &proxy_url)
            .env("https_proxy", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
            .arg("--settings")
            .arg(&settings_path);
        if let Some(token) = &synthetic_token {
            command.env("ANTHROPIC_AUTH_TOKEN", token);
        }
    })
    .await;
    eprintln!("privacy-safe official route: chained_upstream_proxy={chained_upstream_proxy}");
    if let Ok(summary) = &child {
        eprintln!(
            "privacy-safe official child summary: exit_code={:?}, timed_out={}, stdout_bytes={}, stderr_bytes={}, protocol={:?}",
            summary.exit_code,
            summary.timed_out,
            summary.stdout_bytes,
            summary.stderr_bytes,
            summary.protocol
        );
    }
    let captured = join_capture(capture_task).await?;
    let child = child.context("run Claude Code against official endpoint")?;
    if require_completed_exchange {
        ensure!(
            !child.timed_out
                && child.exit_code == Some(0)
                && child.protocol.assistant_events > 0
                && child.protocol.result_success_events > 0
                && child.protocol.result_error_events == 0
                && child.protocol.api_retry_events == 0,
            "official subscription capture child did not complete a retry-free assistant/result exchange"
        );
    }
    let hello = parse_client_hello(&captured).context("parse official TLS ClientHello")?;
    let batch = official_batch(capture_run_id, environment, hello);
    Ok((normalize_capture(&batch)?, child))
}

fn inherited_http_proxy() -> Result<Option<UpstreamHttpProxy>> {
    for name in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"] {
        let Some(value) = std::env::var_os(name) else {
            continue;
        };
        let value = value.to_string_lossy();
        if value.trim().is_empty() {
            continue;
        }
        return parse_upstream_http_proxy(&value).map(Some);
    }
    Ok(None)
}

fn parse_upstream_http_proxy(value: &str) -> Result<UpstreamHttpProxy> {
    let authority = value
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("inherited upstream proxy must use the http scheme"))?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    ensure!(
        !authority.is_empty()
            && !authority.contains(['/', '\\', '?', '#'])
            && !authority.chars().any(char::is_whitespace),
        "inherited upstream proxy URL contains unsupported path or whitespace"
    );
    let (userinfo, endpoint) = if let Some((userinfo, endpoint)) = authority.rsplit_once('@') {
        ensure!(
            !userinfo.contains('@') && !userinfo.is_empty(),
            "inherited upstream proxy userinfo is invalid"
        );
        (Some(userinfo), endpoint)
    } else {
        (None, authority)
    };
    let (host, port) = parse_proxy_endpoint(endpoint)?;
    let authorization = if let Some(userinfo) = userinfo {
        let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        ensure!(
            !username.is_empty(),
            "inherited upstream proxy username is empty"
        );
        let username = percent_encoding::percent_decode_str(username)
            .decode_utf8()
            .context("decode inherited upstream proxy username")?;
        let password = percent_encoding::percent_decode_str(password)
            .decode_utf8()
            .context("decode inherited upstream proxy password")?;
        Some(format!(
            "Basic {}",
            STANDARD.encode(format!("{username}:{password}"))
        ))
    } else {
        None
    };
    Ok(UpstreamHttpProxy {
        host,
        port,
        authorization,
    })
}

fn parse_proxy_endpoint(endpoint: &str) -> Result<(String, u16)> {
    if let Some(bracketed) = endpoint.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| anyhow!("inherited upstream proxy IPv6 host is invalid"))?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            80
        } else {
            suffix
                .strip_prefix(':')
                .ok_or_else(|| anyhow!("inherited upstream proxy IPv6 port is invalid"))?
                .parse::<u16>()
                .context("parse inherited upstream proxy port")?
        };
        ensure!(
            !host.is_empty() && port > 0,
            "inherited upstream proxy endpoint is empty"
        );
        return Ok((host.to_owned(), port));
    }
    ensure!(
        endpoint.matches(':').count() <= 1,
        "inherited upstream proxy IPv6 host must use brackets"
    );
    let (host, port) = endpoint.rsplit_once(':').map_or_else(
        || Ok::<_, anyhow::Error>((endpoint, 80)),
        |(host, port)| {
            Ok((
                host,
                port.parse::<u16>()
                    .context("parse inherited upstream proxy port")?,
            ))
        },
    )?;
    ensure!(
        !host.is_empty() && port > 0,
        "inherited upstream proxy endpoint is empty"
    );
    Ok((host.to_owned(), port))
}

fn official_proxy_settings(proxy_url: &str) -> serde_json::Value {
    serde_json::json!({
        "env": {
            "HTTPS_PROXY": proxy_url,
            "HTTP_PROXY": proxy_url,
            "https_proxy": proxy_url,
            "http_proxy": proxy_url,
            "NO_PROXY": "",
            "no_proxy": "",
            "DISABLE_AUTOUPDATER": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
        }
    })
}

fn official_batch(
    capture_run_id: Uuid,
    environment: EnvironmentDescriptor,
    hello: ParsedClientHello,
) -> CaptureBatch {
    CaptureBatch {
        schema_version: CAPTURE_SCHEMA_VERSION,
        capture_artifact_id: Uuid::new_v4(),
        capture_run_id,
        lane: CaptureLane::ReferenceOfficialTls,
        observed_at: observed_at(),
        environment,
        target: TargetDescriptor {
            authority: "api.anthropic.com".to_owned(),
            official_anthropic: true,
        },
        network: NetworkDescriptor {
            path: NetworkPath::HttpConnect,
            dns_mode: DnsMode::Local,
            proxy_software: Some("claude-capture-runner-connect-tap".to_owned()),
            proxy_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        },
        scenario: ScenarioDescriptor {
            id: "T01-real-claude-minimal-message".to_owned(),
            fresh_connection: true,
            expected_protocol: "h2".to_owned(),
            concurrent_streams: 1,
            request_shape: "real-claude-minimal-message".to_owned(),
        },
        events: vec![
            CaptureEvent::ConnectionLifecycle {
                connection_id: CONNECTION_ID.to_owned(),
                phase: ConnectionPhase::ProxyTunnelEstablished,
                offset_micros: 0,
                negotiated_protocol: None,
                resumed: None,
            },
            CaptureEvent::ConnectionLifecycle {
                connection_id: CONNECTION_ID.to_owned(),
                phase: ConnectionPhase::TlsStarted,
                offset_micros: 1,
                negotiated_protocol: None,
                resumed: None,
            },
            CaptureEvent::TlsClientHello {
                connection_id: CONNECTION_ID.to_owned(),
                record_version: hello.record_version,
                legacy_version: hello.legacy_version,
                cipher_suites: hello.cipher_suites,
                extensions: hello.extensions,
                alpn: hello.alpn,
                client_hello_len: hello.client_hello_len,
                record_lengths: hello.record_lengths,
            },
        ],
    }
}

fn controlled_events(result: &ControlledH2Result) -> Vec<CaptureEvent> {
    let mut events = vec![CaptureEvent::ConnectionLifecycle {
        connection_id: CONNECTION_ID.to_owned(),
        phase: ConnectionPhase::TlsEstablished,
        offset_micros: 0,
        negotiated_protocol: Some(result.negotiated_alpn.clone()),
        resumed: None,
    }];
    events.push(CaptureEvent::ConnectionLifecycle {
        connection_id: CONNECTION_ID.to_owned(),
        phase: if result.negotiated_alpn == "h2" {
            ConnectionPhase::Http2PrefaceSent
        } else {
            ConnectionPhase::Ready
        },
        offset_micros: 1,
        negotiated_protocol: Some(result.negotiated_alpn.clone()),
        resumed: None,
    });
    if let Some(request) = &result.http1_request {
        events.push(CaptureEvent::Http1Request {
            connection_id: CONNECTION_ID.to_owned(),
            method: request.method.clone(),
            path: request.path.clone(),
            version: request.version.clone(),
            headers: request.headers.clone(),
            body_bytes: request.body_bytes,
        });
    }
    events.extend(result.frames.iter().map(|frame| CaptureEvent::Http2Frame {
        connection_id: CONNECTION_ID.to_owned(),
        direction: Direction::ClientToServer,
        sequence: frame.sequence,
        stream_id: frame.stream_id,
        frame_type: frame.frame_type.clone(),
        flags: frame.flags.clone(),
        length: frame.length,
        detail: frame.detail.clone(),
    }));
    events.extend(
        result
            .response_sse_chunk_lengths
            .iter()
            .enumerate()
            .map(|(index, length)| CaptureEvent::SseChunk {
                connection_id: CONNECTION_ID.to_owned(),
                stream_id: u32::from(result.http1_request.is_none()),
                sequence: u64::try_from(index).unwrap_or(u64::MAX) + 1,
                byte_len: *length,
                content_sha256: None,
                event_type: Some("synthetic_claude_event_sequence".to_owned()),
            }),
    );
    events
}

async fn run_claude<F>(
    claude_bin: &Path,
    prompt: &str,
    model: &str,
    working_dir: &Path,
    timeout: Duration,
    configure: F,
) -> Result<ChildSummary>
where
    F: FnOnce(&mut Command),
{
    let mut command = Command::new(claude_bin);
    command
        .arg("-p")
        .arg(prompt)
        .arg("--model")
        .arg(model)
        .arg("--output-format")
        .arg("stream-json")
        .arg("--include-partial-messages")
        .arg("--verbose")
        .arg("--no-session-persistence")
        .arg("--safe-mode")
        .arg("--tools")
        .arg("")
        .arg("--prompt-suggestions")
        .arg("false")
        .current_dir(working_dir)
        .env("DISABLE_AUTOUPDATER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure(&mut command);
    let mut child = command.spawn().context("spawn Claude Code child")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Claude Code stdout pipe is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("Claude Code stderr pipe is unavailable"))?;
    let stdout_task = tokio::spawn(drain_output(stdout));
    let stderr_task = tokio::spawn(drain_output(stderr));
    let (status, timed_out) = if let Ok(status) = tokio::time::timeout(timeout, child.wait()).await
    {
        (status?, false)
    } else {
        let _ = child.kill().await;
        (child.wait().await?, true)
    };
    let stdout = stdout_task.await.context("join Claude stdout drain")??;
    let stderr = stderr_task.await.context("join Claude stderr drain")??;
    let mut protocol = summarize_child_protocol(&stdout.diagnostic_prefix);
    protocol.diagnostic_prefix_truncated = stdout.truncated;
    Ok(ChildSummary {
        exit_code: (!timed_out).then(|| status.code()).flatten(),
        stdout_bytes: stdout.total_bytes,
        stderr_bytes: stderr.total_bytes,
        timed_out,
        protocol,
    })
}

async fn drain_output<R>(mut reader: R) -> Result<DrainedOutput>
where
    R: AsyncRead + Unpin,
{
    const DIAGNOSTIC_PREFIX_LIMIT: usize = 2 * 1024 * 1024;
    let mut total_bytes = 0_usize;
    let mut diagnostic_prefix = Vec::new();
    let mut buffer = vec![0_u8; 16 * 1024].into_boxed_slice();
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(read);
        if diagnostic_prefix.len() < DIAGNOSTIC_PREFIX_LIMIT {
            let remaining = DIAGNOSTIC_PREFIX_LIMIT - diagnostic_prefix.len();
            diagnostic_prefix.extend_from_slice(&buffer[..read.min(remaining)]);
        }
    }
    Ok(DrainedOutput {
        total_bytes,
        truncated: total_bytes > diagnostic_prefix.len(),
        diagnostic_prefix,
    })
}

fn summarize_child_protocol(output: &[u8]) -> ChildProtocolSummary {
    let mut summary = ChildProtocolSummary::default();
    for line in output.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            summary.invalid_json_lines += 1;
            continue;
        };
        match value.get("type").and_then(serde_json::Value::as_str) {
            Some("system")
                if value.get("subtype").and_then(serde_json::Value::as_str) == Some("init") =>
            {
                summary.init_events += 1;
            }
            Some("system")
                if value.get("subtype").and_then(serde_json::Value::as_str)
                    == Some("api_retry") =>
            {
                record_api_retry(&mut summary, &value);
            }
            Some("assistant") => record_assistant(&mut summary, &value),
            Some("result") => record_result(&mut summary, &value),
            Some("rate_limit_event") => record_rate_limit(&mut summary, &value),
            Some("stream_event") => record_stream_event(&mut summary, &value),
            Some(_) => summary.other_json_events += 1,
            None => summary.invalid_json_lines += 1,
        }
    }
    summary
}

fn record_api_retry(summary: &mut ChildProtocolSummary, value: &serde_json::Value) {
    summary.api_retry_events += 1;
    record_field_names(&mut summary.api_retry_field_names, value);
    let status = value
        .get("error_status")
        .and_then(serde_json::Value::as_u64)
        .map(|status| status.to_string())
        .or_else(|| {
            value
                .get("error_status")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_owned());
    *summary.api_retry_statuses.entry(status).or_default() += 1;
    let error = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| "missing".to_owned(), classify_retry_error);
    *summary.api_retry_error_categories.entry(error).or_default() += 1;
}

fn record_result(summary: &mut ChildProtocolSummary, value: &serde_json::Value) {
    summary.result_events += 1;
    record_field_names(&mut summary.result_field_names, value);
    let is_error = value
        .get("is_error")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    if is_error {
        summary.result_error_events += 1;
    } else {
        summary.result_success_events += 1;
    }
    let subtype = value
        .get("subtype")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing");
    *summary
        .result_subtypes
        .entry(subtype.to_owned())
        .or_default() += 1;
    if is_error && let Some(error) = value.get("result").and_then(serde_json::Value::as_str) {
        let category = classify_protocol_error(error);
        *summary.result_error_categories.entry(category).or_default() += 1;
    }
    let Some(usage) = value.get("usage") else {
        return;
    };
    summary.usage_input_tokens = summary
        .usage_input_tokens
        .saturating_add(json_u64(usage, "input_tokens"));
    summary.usage_output_tokens = summary
        .usage_output_tokens
        .saturating_add(json_u64(usage, "output_tokens"));
    summary.usage_cache_creation_input_tokens = summary
        .usage_cache_creation_input_tokens
        .saturating_add(json_u64(usage, "cache_creation_input_tokens"));
    summary.usage_cache_read_input_tokens = summary
        .usage_cache_read_input_tokens
        .saturating_add(json_u64(usage, "cache_read_input_tokens"));
}

fn record_assistant(summary: &mut ChildProtocolSummary, value: &serde_json::Value) {
    summary.assistant_events += 1;
    let Some(message) = value.get("message") else {
        return;
    };
    let model = message
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing");
    *summary
        .assistant_models
        .entry(model.to_owned())
        .or_default() += 1;
    let stop_reason = message
        .get("stop_reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing");
    *summary
        .assistant_stop_reasons
        .entry(stop_reason.to_owned())
        .or_default() += 1;
    if let Some(content) = message.get("content").and_then(serde_json::Value::as_array) {
        for block in content {
            let block_type = block
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("missing");
            *summary
                .assistant_content_types
                .entry(block_type.to_owned())
                .or_default() += 1;
        }
    }
}

fn record_rate_limit(summary: &mut ChildProtocolSummary, value: &serde_json::Value) {
    summary.rate_limit_events += 1;
    record_field_names(&mut summary.rate_limit_field_names, value);
}

fn record_stream_event(summary: &mut ChildProtocolSummary, value: &serde_json::Value) {
    summary.stream_events += 1;
    let event_type = value
        .get("event")
        .and_then(|event| event.get("type"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing");
    *summary
        .stream_event_types
        .entry(event_type.to_owned())
        .or_default() += 1;
}

fn record_field_names(fields: &mut BTreeMap<String, usize>, value: &serde_json::Value) {
    if let Some(object) = value.as_object() {
        for name in object.keys() {
            *fields.entry(name.clone()).or_default() += 1;
        }
    }
}

fn json_u64(value: &serde_json::Value, field: &str) -> u64 {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default()
}

fn classify_protocol_error(error: &str) -> String {
    let normalized = error.to_ascii_lowercase();
    let category = if normalized.contains("401")
        || normalized.contains("authentication")
        || normalized.contains("unauthorized")
    {
        "authentication"
    } else if normalized.contains("403") || normalized.contains("permission") {
        "permission"
    } else if normalized.contains("429") || normalized.contains("rate limit") {
        "rate_limit"
    } else if normalized.contains("400") || normalized.contains("invalid request") {
        "invalid_request"
    } else if normalized.contains("certificate") || normalized.contains("tls") {
        "tls"
    } else if normalized.contains("timeout") || normalized.contains("timed out") {
        "timeout"
    } else if normalized.contains("connection")
        || normalized.contains("fetch failed")
        || normalized.contains("econn")
    {
        "connection"
    } else if normalized.contains("model") {
        "model"
    } else if normalized.contains("stream") || normalized.contains("sse") {
        "stream_protocol"
    } else {
        "other"
    };
    category.to_owned()
}

fn classify_retry_error(error: &str) -> String {
    let normalized = error.to_ascii_lowercase();
    let category =
        if normalized.contains("econnrefused") || normalized.contains("connection refused") {
            "connection_refused"
        } else if normalized.contains("fetch failed") {
            "fetch_failed"
        } else if normalized.contains("terminated") || normalized.contains("closed") {
            "connection_closed"
        } else if normalized.contains("stream") || normalized.contains("sse") {
            "stream_protocol"
        } else if normalized.contains("json") || normalized.contains("parse") {
            "response_parse"
        } else if normalized.contains("server_error") {
            "server_error"
        } else if normalized.contains("timeout") || normalized.contains("timed out") {
            "timeout"
        } else if normalized.contains("certificate") || normalized.contains("tls") {
            "tls"
        } else if normalized.len() <= 80
            && normalized.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-' | b'.' | b':')
            })
        {
            return format!("literal:{normalized}");
        } else {
            "other"
        };
    category.to_owned()
}

fn scrub_controlled_environment(command: &mut Command) {
    const NAMES: &[&str] = &[
        "ANTHROPIC_API_KEY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "AWS_BEARER_TOKEN_BEDROCK",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ];
    for name in NAMES {
        command.env_remove(name);
    }
}

async fn join_capture<T, E>(task: JoinHandle<Result<T, E>>) -> Result<T>
where
    E: std::error::Error + Send + Sync + 'static,
{
    task.await.context("join capture task")?.map_err(Into::into)
}

async fn inspect_environment(
    claude_bin: &Path,
    timeout: Duration,
) -> Result<EnvironmentDescriptor> {
    let version_output = tokio::time::timeout(
        timeout.min(Duration::from_secs(10)),
        Command::new(claude_bin).arg("--version").output(),
    )
    .await
    .map_err(|_| anyhow!("Claude Code version probe timed out"))??;
    ensure!(
        version_output.status.success(),
        "Claude Code version probe exited unsuccessfully"
    );
    let claude_version = String::from_utf8_lossy(&version_output.stdout)
        .trim()
        .to_owned();
    ensure!(
        !claude_version.is_empty(),
        "Claude Code returned an empty version"
    );
    let (os_version, kernel) = os_details().await?;
    let binary_sha256 = if claude_bin.is_file() {
        Some(hash_file(claude_bin.to_owned()).await?)
    } else {
        None
    };
    Ok(EnvironmentDescriptor {
        os_name: std::env::consts::OS.to_owned(),
        os_version,
        os_build: None,
        arch: std::env::consts::ARCH.to_owned(),
        kernel,
        claude_code_version: claude_version.clone(),
        runtime_name: "claude-code-native".to_owned(),
        runtime_version: claude_version,
        binary_sha256,
        labels: BTreeMap::new(),
    })
}

#[cfg(windows)]
async fn os_details() -> Result<(String, Option<String>)> {
    let output = Command::new("cmd").args(["/C", "ver"]).output().await?;
    ensure!(output.status.success(), "Windows version probe failed");
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok((version, None))
}

#[cfg(not(windows))]
async fn os_details() -> Result<(String, Option<String>)> {
    let output = Command::new("uname").args(["-sr"]).output().await?;
    ensure!(output.status.success(), "uname version probe failed");
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let mut parts = value.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or(std::env::consts::OS).to_owned();
    let release = parts.next().unwrap_or("unknown").trim().to_owned();
    Ok((release, Some(name)))
}

async fn hash_file(path: PathBuf) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        let mut file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok::<_, anyhow::Error>(hex::encode(hasher.finalize()))
    })
    .await
    .context("join executable hash task")?
}

fn persist_normalized(path: &Path, normalized: &NormalizedCapture) -> Result<()> {
    if path.exists() {
        bail!("capture output already exists: {}", path.display());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create capture output directory {}", parent.display()))?;
    let mut temp = NamedTempFile::new_in(parent).context("create atomic capture output")?;
    serde_json::to_writer_pretty(&mut temp, normalized).context("serialize normalized capture")?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("persist normalized capture {}", path.display()))?;
    Ok(())
}

fn persist_json<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    if path.exists() {
        bail!("output already exists: {}", path.display());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create output directory {}", parent.display()))?;
    let mut temp = NamedTempFile::new_in(parent).context("create atomic JSON output")?;
    serde_json::to_writer_pretty(&mut temp, value).context("serialize JSON output")?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("persist JSON output {}", path.display()))?;
    Ok(())
}

fn observed_at() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("unix-ms:{millis}")
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, official_proxy_settings, parse_upstream_http_proxy, summarize_child_protocol,
    };
    use clap::CommandFactory;

    #[test]
    fn command_line_contract_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn official_proxy_settings_pin_both_proxy_name_variants() {
        let settings = official_proxy_settings("http://127.0.0.1:12345");
        let env = settings
            .get("env")
            .and_then(serde_json::Value::as_object)
            .expect("settings env object");
        for name in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"] {
            assert_eq!(
                env.get(name).and_then(serde_json::Value::as_str),
                Some("http://127.0.0.1:12345")
            );
        }
        assert_eq!(
            env.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC")
                .and_then(serde_json::Value::as_str),
            Some("1")
        );
    }

    #[test]
    fn inherited_proxy_parser_decodes_basic_auth_without_debug_exposure() {
        let proxy = parse_upstream_http_proxy("http://user:p%40ss@127.0.0.1:7890")
            .expect("parse fixture proxy");
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 7890);
        assert_eq!(proxy.authorization.as_deref(), Some("Basic dXNlcjpwQHNz"));
        let debug = format!("{proxy:?}");
        assert!(!debug.contains("dXNlcjpwQHNz"));
        assert!(!debug.contains("p@ss"));
    }

    #[test]
    fn child_summary_keeps_only_protocol_and_usage_shape() {
        let output = br#"{"type":"stream_event","event":{"type":"message_start","message":{"content":"secret"}}}
{"type":"rate_limit_event","rate_limit_info":{"utilization":0.1}}
{"type":"assistant","message":{"content":[{"type":"text","text":"secret"}]}}
{"type":"result","subtype":"success","is_error":false,"usage":{"input_tokens":12,"output_tokens":3,"cache_creation_input_tokens":4,"cache_read_input_tokens":5}}
"#;
        let summary = summarize_child_protocol(output);
        assert_eq!(summary.stream_events, 1);
        assert_eq!(summary.stream_event_types.get("message_start"), Some(&1));
        assert_eq!(summary.rate_limit_events, 1);
        assert_eq!(summary.assistant_events, 1);
        assert_eq!(summary.assistant_content_types.get("text"), Some(&1));
        assert_eq!(summary.result_success_events, 1);
        assert_eq!(summary.result_error_events, 0);
        assert_eq!(summary.usage_input_tokens, 12);
        assert_eq!(summary.usage_output_tokens, 3);
        assert_eq!(summary.usage_cache_creation_input_tokens, 4);
        assert_eq!(summary.usage_cache_read_input_tokens, 5);
    }
}
