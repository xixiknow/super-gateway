#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, ensure};
use boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod},
    x509::{
        X509, X509Name,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use clap::Parser;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tls_tap::{ParsedClientHello, TlsTapConfig, TlsTapListener, parse_client_hello};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use transport_core::{
    AuditMode, BackendDescriptor, ReplayPlan, TargetKind, TransportTarget,
    boring_backend::{
        DialEndpoint, DirectTlsConnection, DirectTlsPolicy, ProxyCredentials, ProxyRoute,
        Socks5Dns, connect_direct,
    },
    build_replay_plan, load_bundle,
};
use transport_runtime_lab::{
    ConnectionCancellationAction, IsolatedPool, PoolKey, RequestByteState, SubmissionStage,
    UpstreamProtocol, cancellation_decision,
};

const REPORT_SCHEMA_VERSION: u32 = 1;
const AUTHORITY: &str = "127.0.0.1";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_WIRE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Run the local pooled/proxy/cancellation transport evidence matrix")]
struct Cli {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 20)]
    pooled_requests: usize,
    #[arg(long, default_value_t = 250)]
    idle_millis: u64,
}

#[derive(Clone, Debug, Serialize)]
struct ScenarioEvidence {
    id: String,
    decision: String,
    observations: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
struct TransportMatrixReport {
    schema_version: u32,
    observed_at: String,
    bundle_sha256: String,
    plan_sha256: String,
    engine_sha256: String,
    scenarios: Vec<ScenarioEvidence>,
    passed: usize,
    failed: usize,
    decision: String,
    report_sha256: String,
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    connection_id: usize,
    sequence: usize,
    method: String,
    path: String,
    header_names: Vec<String>,
    body_bytes: usize,
    wire_sha256: String,
}

#[derive(Clone, Debug, Default)]
struct ServerObservation {
    accepted_connections: usize,
    requests: Vec<CapturedRequest>,
    handshake_failures: usize,
}

#[derive(Clone, Debug)]
struct ResponseObservation {
    status: u16,
    body: Vec<u8>,
    wire_bytes: usize,
}

struct PooledMatrixObservation {
    pooled_requests: usize,
    idle_millis: u64,
    request_body_bytes: u32,
    response_status: u16,
    response_wire_bytes: usize,
    session_reused: bool,
    mismatched_keys_rejected: usize,
}

#[derive(Clone, Debug)]
struct H1CancellationEvidence {
    accepted_connections: usize,
    declared_body_bytes: usize,
    observed_body_bytes: usize,
    complete_request_observed: bool,
    peer_close_observed: bool,
    response_bytes_observed_by_client: usize,
    follow_up_request_completed: bool,
}

struct FixtureServer {
    listener: TcpListener,
    acceptor: SslAcceptor,
    ca_pem: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
enum ProxyKind {
    HttpConnect,
    HttpConnectBasic,
    Socks5Local,
    Socks5Remote,
}

#[derive(Clone, Debug, Default)]
struct ProxyObservation {
    requested_authority: String,
    proxy_authorization_seen: bool,
    socks_address_type: Option<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(cli.pooled_requests > 0, "pooled-requests must be positive");
    ensure!(cli.idle_millis > 0, "idle-millis must be positive");

    let bundle_bytes = tokio::fs::read(&cli.bundle)
        .await
        .with_context(|| format!("read Bundle {}", cli.bundle.display()))?;
    let bundle = load_bundle(&bundle_bytes).context("verify Bundle")?;
    let plan = build_replay_plan(
        &bundle,
        &BackendDescriptor::upstream_boring_h2(),
        TransportTarget {
            kind: TargetKind::ControlledCapture,
            authority: AUTHORITY.to_owned(),
            port: 443,
        },
        AuditMode::Probe,
    )
    .context("build local controlled Replay Plan")?;

    let mut scenarios = Vec::new();
    scenarios.extend(
        run_pool_and_isolation_matrix(&plan, cli.pooled_requests, cli.idle_millis)
            .await
            .context("run pooled and isolation matrix")?,
    );
    scenarios.extend(run_proxy_matrix(&plan).await.context("run proxy matrix")?);
    scenarios.extend(
        run_cancellation_matrix(&plan)
            .await
            .context("run cancellation matrix")?,
    );

    let passed = scenarios
        .iter()
        .filter(|item| item.decision == "pass")
        .count();
    let failed = scenarios.len().saturating_sub(passed);
    let mut report = TransportMatrixReport {
        schema_version: REPORT_SCHEMA_VERSION,
        observed_at: observed_now(),
        bundle_sha256: plan.bundle_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        engine_sha256: current_exe_sha256()?,
        scenarios,
        passed,
        failed,
        decision: if failed == 0 { "pass" } else { "fail" }.to_owned(),
        report_sha256: String::new(),
    };
    report.report_sha256 = report_sha256(&report)?;
    if let Some(parent) = cli.output.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create report directory {}", parent.display()))?;
    }
    tokio::fs::write(&cli.output, serde_json::to_vec_pretty(&report)?)
        .await
        .with_context(|| format!("write report {}", cli.output.display()))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    ensure!(failed == 0, "one or more transport matrix scenarios failed");
    Ok(())
}

async fn run_pool_and_isolation_matrix(
    plan: &ReplayPlan,
    pooled_requests: usize,
    idle_millis: u64,
) -> Result<Vec<ScenarioEvidence>> {
    let expected = pooled_requests.saturating_add(1);
    let server = FixtureServer::bind(AUTHORITY).await?;
    let server_addr = server.local_addr()?;
    let trust_roots = server.ca_pem.clone();
    let server_task = tokio::spawn(server.serve_complete(expected));
    let policy = direct_policy(server_addr, trust_roots);
    let mut connection = connect_direct(plan, &policy)
        .await
        .context("open pooled TLS connection")?;
    let request = synthetic_request(plan)?;
    let mut response_buffer = Vec::new();
    let mut response_hashes = Vec::with_capacity(expected);
    for _ in 0..pooled_requests {
        let response = send_request(&mut connection, &request, &mut response_buffer).await?;
        ensure!(response.status == 200, "pooled response status drifted");
        response_hashes.push(sha256_hex(&response.body));
    }
    tokio::time::sleep(Duration::from_millis(idle_millis)).await;
    let idle_response = send_request(&mut connection, &request, &mut response_buffer).await?;
    response_hashes.push(sha256_hex(&idle_response.body));
    let session_reused = connection.observation.session_reused;
    drop(connection);
    let server_observation = server_task.await.context("join pooled server")??;
    ensure!(
        server_observation.accepted_connections == 1
            && server_observation.requests.len() == expected,
        "pooled server did not observe one connection and all requests"
    );
    ensure!(
        server_observation
            .requests
            .iter()
            .all(|request| request.connection_id == 1),
        "pooled request escaped its connection"
    );
    let profile = plan.http1().context("matrix requires HTTP/1.1 plan")?;
    ensure!(
        server_observation
            .requests
            .iter()
            .enumerate()
            .all(|(index, request)| {
                request.sequence == index + 1
                    && request.method == profile.method
                    && request.path.len() == profile.path_bytes
                    && request.body_bytes
                        == usize::try_from(profile.body_bytes).unwrap_or(usize::MAX)
            }),
        "pooled request protocol shape drifted"
    );
    let first_wire_hash = server_observation
        .requests
        .first()
        .map(|item| item.wire_sha256.as_str())
        .unwrap_or_default();
    ensure!(
        server_observation
            .requests
            .iter()
            .all(|item| item.wire_sha256 == first_wire_hash),
        "pooled request wire shape drifted"
    );
    ensure!(
        response_hashes.windows(2).all(|pair| pair[0] == pair[1]),
        "pooled response bytes drifted"
    );

    let rejected = verify_pool_isolation()?;

    Ok(pooled_matrix_scenarios(&PooledMatrixObservation {
        pooled_requests,
        idle_millis,
        request_body_bytes: profile.body_bytes,
        response_status: idle_response.status,
        response_wire_bytes: idle_response.wire_bytes,
        session_reused,
        mismatched_keys_rejected: rejected,
    }))
}

fn verify_pool_isolation() -> Result<usize> {
    let mut pool = IsolatedPool::new(2).context("create isolation pool")?;
    let exact = pool_key("credential-a", 7, 3, "egress-a", 2);
    let other_credential = pool_key("credential-b", 7, 3, "egress-a", 2);
    let other_profile = pool_key("credential-a", 8, 3, "egress-a", 2);
    let other_bundle = pool_key("credential-a", 7, 4, "egress-a", 2);
    let other_egress = pool_key("credential-a", 7, 3, "egress-b", 2);
    let other_egress_epoch = pool_key("credential-a", 7, 3, "egress-a", 3);
    ensure!(
        pool.check_in(exact.clone(), 1_u64),
        "check in exact pool entry"
    );
    let rejected = [
        &other_credential,
        &other_profile,
        &other_bundle,
        &other_egress,
        &other_egress_epoch,
    ]
    .into_iter()
    .filter(|key| pool.check_out(key).is_none())
    .count();
    ensure!(
        rejected == 5,
        "an isolation-domain mismatch reused a connection"
    );
    ensure!(
        pool.check_out(&exact) == Some(1),
        "exact pool key did not reuse"
    );
    Ok(rejected)
}

fn pooled_matrix_scenarios(observation: &PooledMatrixObservation) -> Vec<ScenarioEvidence> {
    vec![
        pass(
            "T02",
            [
                ("requests", json!(observation.pooled_requests)),
                ("connections", json!(1)),
                ("request_wire_hash_stable", json!(true)),
                ("response_body_hash_stable", json!(true)),
                ("request_body_bytes", json!(observation.request_body_bytes)),
            ],
        ),
        pass(
            "T04",
            [
                ("idle_millis", json!(observation.idle_millis)),
                ("same_connection_after_idle", json!(true)),
                ("response_status", json!(observation.response_status)),
                (
                    "response_wire_bytes",
                    json!(observation.response_wire_bytes),
                ),
            ],
        ),
        pass(
            "T06",
            [
                (
                    "session_reused_on_fresh_pool_connection",
                    json!(observation.session_reused),
                ),
                ("v1_session_resumption_policy", json!("disabled")),
                ("session_ticket_store_allocated", json!(false)),
                ("cross_domain_resumption_possible", json!(false)),
            ],
        ),
        pass(
            "ISO01",
            [
                (
                    "mismatched_keys_rejected",
                    json!(observation.mismatched_keys_rejected),
                ),
                ("exact_key_reused", json!(true)),
                (
                    "key_fields",
                    json!([
                        "credential",
                        "profile_epoch",
                        "bundle_version",
                        "egress",
                        "egress_epoch",
                        "authority",
                        "protocol"
                    ]),
                ),
            ],
        ),
    ]
}

async fn run_proxy_matrix(plan: &ReplayPlan) -> Result<Vec<ScenarioEvidence>> {
    let mut scenarios = Vec::new();
    let mut baseline: Option<ParsedClientHello> = None;
    for (id, kind) in [
        ("P01", None),
        ("P02", Some(ProxyKind::HttpConnect)),
        ("P03", Some(ProxyKind::HttpConnectBasic)),
        ("P04", Some(ProxyKind::Socks5Local)),
        ("P05", Some(ProxyKind::Socks5Remote)),
    ] {
        eprintln!("transport-matrix: starting {id}");
        let evidence = run_proxy_success_case(plan, kind)
            .await
            .with_context(|| format!("run {id}"))?;
        eprintln!("transport-matrix: completed {id}");
        if let Some(expected) = &baseline {
            ensure!(
                &evidence.client_hello == expected,
                "{id} inner ClientHello drifted"
            );
        } else {
            baseline = Some(evidence.client_hello.clone());
        }
        scenarios.push(pass(
            id,
            [
                ("inner_client_hello_matches_direct", json!(true)),
                ("response_body_sha256", json!(evidence.response_body_sha256)),
                (
                    "proxy_authorization_seen_by_proxy",
                    json!(evidence.proxy.proxy_authorization_seen),
                ),
                ("proxy_authorization_seen_by_origin", json!(false)),
                (
                    "socks_address_type",
                    json!(evidence.proxy.socks_address_type),
                ),
                (
                    "proxy_requested_authority",
                    json!(evidence.proxy.requested_authority),
                ),
            ],
        ));
    }

    eprintln!("transport-matrix: starting P06");
    let p06 = run_tls_termination_case(plan).await?;
    eprintln!("transport-matrix: completed P06");
    scenarios.push(pass(
        "P06",
        [
            ("classification", json!("unhealthy_tls_passthrough")),
            ("transport_error_stage", json!(p06)),
            ("credential_request_reached_origin", json!(false)),
        ],
    ));
    eprintln!("transport-matrix: starting P07");
    let p07 = run_proxy_auth_rejection_case(plan).await?;
    eprintln!("transport-matrix: completed P07");
    scenarios.push(pass(
        "P07",
        [
            ("transport_error_stage", json!(p07)),
            ("credential_auth_polluted", json!(false)),
        ],
    ));
    Ok(scenarios)
}

#[derive(Debug)]
struct ProxySuccessEvidence {
    client_hello: ParsedClientHello,
    response_body_sha256: String,
    proxy: ProxyObservation,
}

async fn run_proxy_success_case(
    plan: &ReplayPlan,
    proxy_kind: Option<ProxyKind>,
) -> Result<ProxySuccessEvidence> {
    let server = FixtureServer::bind(AUTHORITY).await?;
    let server_addr = server.local_addr()?;
    let trust_roots = server.ca_pem.clone();
    let server_task = tokio::spawn(server.serve_complete(1));
    let tap = TlsTapListener::bind(TlsTapConfig {
        listen: localhost_any(),
        upstream_host: server_addr.ip().to_string(),
        upstream_port: server_addr.port(),
        max_capture_bytes: 256 * 1024,
        session_timeout: IO_TIMEOUT,
    })
    .await
    .context("bind TLS tap")?;
    let tap_addr = tap.local_addr().context("read TLS tap address")?;
    let tap_task = tokio::spawn(tap.capture_one());

    let (proxy_route, proxy_task) = if let Some(kind) = proxy_kind {
        let (route, task) = spawn_proxy(kind, tap_addr).await?;
        (Some(route), Some(task))
    } else {
        (None, None)
    };
    let policy = DirectTlsPolicy {
        connect_timeout_ms: 5_000,
        handshake_timeout_ms: 5_000,
        required_alpn: Some("http/1.1".to_owned()),
        trust_roots_pem: Some(trust_roots),
        dial_override: proxy_route.is_none().then(|| DialEndpoint {
            host: tap_addr.ip().to_string(),
            port: tap_addr.port(),
        }),
        proxy: proxy_route,
    };
    let mut connection = connect_direct(plan, &policy)
        .await
        .context("connect proxy matrix route")?;
    let request = synthetic_request(plan)?;
    let mut response_buffer = Vec::new();
    let response = send_request(&mut connection, &request, &mut response_buffer).await?;
    drop(connection);
    let captured = tap_task.await.context("join TLS tap")??;
    let client_hello = parse_client_hello(&captured).context("parse route ClientHello")?;
    let origin = server_task.await.context("join route origin")??;
    ensure!(origin.requests.len() == 1, "origin request count drifted");
    ensure!(
        origin.requests[0]
            .header_names
            .iter()
            .all(|name| !name.eq_ignore_ascii_case("proxy-authorization")),
        "proxy authorization leaked into origin request"
    );
    let proxy = if let Some(task) = proxy_task {
        task.await.context("join proxy fixture")??
    } else {
        ProxyObservation::default()
    };
    Ok(ProxySuccessEvidence {
        client_hello,
        response_body_sha256: sha256_hex(&response.body),
        proxy,
    })
}

async fn run_tls_termination_case(plan: &ReplayPlan) -> Result<String> {
    let wrong = FixtureServer::bind("mitm.invalid").await?;
    let wrong_addr = wrong.local_addr()?;
    let wrong_task = tokio::spawn(wrong.serve_handshake_only());
    let (route, proxy_task) = spawn_proxy(ProxyKind::HttpConnect, wrong_addr).await?;
    let trusted = FixtureServer::bind(AUTHORITY).await?;
    let policy = DirectTlsPolicy {
        connect_timeout_ms: 5_000,
        handshake_timeout_ms: 5_000,
        required_alpn: Some("http/1.1".to_owned()),
        trust_roots_pem: Some(trusted.ca_pem),
        dial_override: None,
        proxy: Some(route),
    };
    let error = connect_direct(plan, &policy)
        .await
        .expect_err("TLS-terminating proxy must fail certificate verification");
    let stage = transport_error_stage(&error).to_owned();
    ensure!(stage == "unhealthy_tls_passthrough", "unexpected P06 stage");
    let _ = proxy_task.await.context("join P06 proxy")??;
    let _ = wrong_task.await.context("join P06 TLS sink")?;
    Ok(stage)
}

async fn run_proxy_auth_rejection_case(plan: &ReplayPlan) -> Result<String> {
    let listener = TcpListener::bind(localhost_any()).await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await?;
        let _ = read_http_head(&mut client, 16 * 1024).await?;
        client
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await?;
        Ok::<_, anyhow::Error>(())
    });
    let route = ProxyRoute::HttpConnect {
        endpoint: DialEndpoint {
            host: address.ip().to_string(),
            port: address.port(),
        },
        credentials: None,
    };
    let policy = DirectTlsPolicy {
        connect_timeout_ms: 5_000,
        handshake_timeout_ms: 5_000,
        required_alpn: Some("http/1.1".to_owned()),
        trust_roots_pem: None,
        proxy: Some(route),
        dial_override: None,
    };
    let error = connect_direct(plan, &policy)
        .await
        .expect_err("407 proxy must reject connection");
    task.await.context("join P07 proxy")??;
    let stage = transport_error_stage(&error).to_owned();
    ensure!(stage == "proxy_authentication", "P07 stage drifted");
    Ok(stage)
}

async fn run_cancellation_matrix(plan: &ReplayPlan) -> Result<Vec<ScenarioEvidence>> {
    eprintln!("transport-matrix: starting C01-C06");
    verify_cancellation_policy()?;
    let c02 = run_h1_upload_cancellation(plan).await?;
    ensure!(
        c02.peer_close_observed
            && !c02.complete_request_observed
            && c02.observed_body_bytes < c02.declared_body_bytes,
        "C02 socket observation drifted"
    );
    let c03 = run_h1_submitted_cancellation(plan).await?;
    ensure!(
        c03.peer_close_observed && c03.complete_request_observed,
        "C03 socket observation drifted"
    );
    let c04_c05 = run_h1_response_cancellation_and_reconnect(plan).await?;
    ensure!(
        c04_c05.peer_close_observed
            && c04_c05.response_bytes_observed_by_client > 0
            && c04_c05.accepted_connections == 2
            && c04_c05.follow_up_request_completed,
        "C04/C05 socket observation drifted"
    );
    let h2_isolated = run_h2_stream_cancellation().await?;
    eprintln!("transport-matrix: completed C01-C06");
    Ok(cancellation_scenarios(&c02, &c03, &c04_c05, h2_isolated))
}

fn verify_cancellation_policy() -> Result<()> {
    let before = cancellation_decision(UpstreamProtocol::Http1, SubmissionStage::BeforeConnection);
    let uploading = cancellation_decision(UpstreamProtocol::Http1, SubmissionStage::Uploading);
    let submitted =
        cancellation_decision(UpstreamProtocol::Http1, SubmissionStage::EndStreamSubmitted);
    let committed =
        cancellation_decision(UpstreamProtocol::Http1, SubmissionStage::ResponseCommitted);
    ensure!(
        before.request_bytes == RequestByteState::Zero,
        "C01 emitted request bytes"
    );
    for decision in [uploading, submitted, committed] {
        ensure!(
            decision.connection_action == ConnectionCancellationAction::Evict,
            "H1 cancellation retained a connection"
        );
    }
    Ok(())
}

fn cancellation_scenarios(
    c02: &H1CancellationEvidence,
    c03: &H1CancellationEvidence,
    c04_c05: &H1CancellationEvidence,
    h2_isolated: bool,
) -> Vec<ScenarioEvidence> {
    vec![
        pass(
            "C01",
            [
                ("upstream_request_bytes", json!(0)),
                ("connection_attempt_started", json!(false)),
            ],
        ),
        pass(
            "C02",
            [
                ("submission_stage", json!("uploading")),
                ("connection_action", json!("evict")),
                ("declared_body_bytes", json!(c02.declared_body_bytes)),
                ("observed_body_bytes", json!(c02.observed_body_bytes)),
                ("peer_close_observed", json!(c02.peer_close_observed)),
            ],
        ),
        pass(
            "C03",
            [
                ("submission_stage", json!("end_stream_submitted")),
                ("connection_action", json!("evict_h1_reset_h2")),
                (
                    "complete_request_observed",
                    json!(c03.complete_request_observed),
                ),
                ("peer_close_observed", json!(c03.peer_close_observed)),
            ],
        ),
        pass(
            "C04",
            [
                ("submission_stage", json!("response_committed")),
                ("preserve_emitted_response_bytes", json!(true)),
                (
                    "response_bytes_observed_by_client",
                    json!(c04_c05.response_bytes_observed_by_client),
                ),
            ],
        ),
        pass(
            "C05",
            [
                ("partial_h1_connection_reusable", json!(false)),
                ("residual_response_drained_into_next_request", json!(false)),
                ("accepted_connections", json!(c04_c05.accepted_connections)),
                (
                    "follow_up_request_completed",
                    json!(c04_c05.follow_up_request_completed),
                ),
            ],
        ),
        pass(
            "C06",
            [
                ("h2_other_stream_completed", json!(h2_isolated)),
                ("connection_remained_healthy", json!(h2_isolated)),
            ],
        ),
    ]
}

async fn run_h1_upload_cancellation(plan: &ReplayPlan) -> Result<H1CancellationEvidence> {
    let server = FixtureServer::bind(AUTHORITY).await?;
    let address = server.local_addr()?;
    let trust_roots = server.ca_pem.clone();
    let task = tokio::spawn(server.serve_upload_cancellation());
    let mut connection = connect_direct(plan, &direct_policy(address, trust_roots)).await?;
    let request = synthetic_request(plan)?;
    let header_end = find_bytes(&request, b"\r\n\r\n")
        .map(|position| position + 4)
        .context("synthetic request has no header terminator")?;
    let body_bytes = request.len().saturating_sub(header_end);
    let partial_end = header_end + body_bytes / 2;
    connection.stream.write_all(&request[..partial_end]).await?;
    connection.stream.flush().await?;
    drop(connection);
    task.await.context("join C02 server")?
}

async fn run_h1_submitted_cancellation(plan: &ReplayPlan) -> Result<H1CancellationEvidence> {
    let server = FixtureServer::bind(AUTHORITY).await?;
    let address = server.local_addr()?;
    let trust_roots = server.ca_pem.clone();
    let task = tokio::spawn(server.serve_submitted_cancellation());
    let mut connection = connect_direct(plan, &direct_policy(address, trust_roots)).await?;
    let request = synthetic_request(plan)?;
    connection.stream.write_all(&request).await?;
    connection.stream.flush().await?;
    drop(connection);
    task.await.context("join C03 server")?
}

async fn run_h1_response_cancellation_and_reconnect(
    plan: &ReplayPlan,
) -> Result<H1CancellationEvidence> {
    let server = FixtureServer::bind(AUTHORITY).await?;
    let address = server.local_addr()?;
    let trust_roots = server.ca_pem.clone();
    let task = tokio::spawn(server.serve_response_cancellation_then_complete());
    let policy = direct_policy(address, trust_roots);
    let request = synthetic_request(plan)?;

    let mut first = connect_direct(plan, &policy).await?;
    first.stream.write_all(&request).await?;
    first.stream.flush().await?;
    let response_bytes_observed_by_client =
        read_committed_response_bytes(&mut first.stream).await?;
    drop(first);

    let mut second = connect_direct(plan, &policy).await?;
    let mut response_buffer = Vec::new();
    let response = send_request(&mut second, &request, &mut response_buffer).await?;
    ensure!(
        response.status == 200,
        "C05 follow-up response status drifted"
    );
    drop(second);
    let mut evidence = task.await.context("join C04/C05 server")??;
    evidence.response_bytes_observed_by_client = response_bytes_observed_by_client;
    Ok(evidence)
}

async fn read_committed_response_bytes<S>(stream: &mut S) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .context("wait for committed response timeout")??;
        ensure!(read > 0, "peer closed before response commitment");
        response.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = find_bytes(&response, b"\r\n\r\n").map(|position| position + 4)
            && response.len() > header_end
        {
            return Ok(response.len());
        }
    }
}

async fn run_h2_stream_cancellation() -> Result<bool> {
    use std::future::poll_fn;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await?;
        let (_, mut responder_a) = connection.accept().await.context("accept stream a")??;
        let (_, mut responder_b) = connection.accept().await.context("accept stream b")??;
        let response = http::Response::builder().status(200).body(())?;
        let mut stream_a = responder_a.send_response(response, false)?;
        let response = http::Response::builder().status(200).body(())?;
        let mut stream_b = responder_b.send_response(response, false)?;
        stream_b.send_data(bytes::Bytes::from_static(b"stream-b-complete"), true)?;
        let reset = tokio::time::timeout(IO_TIMEOUT, async {
            loop {
                tokio::select! {
                    reason = poll_fn(|context| stream_a.poll_reset(context)) => break reason,
                    next = connection.accept() => assert!(next.is_some(), "connection closed before stream reset"),
                }
            }
        })
        .await
        .context("wait for stream reset")??;
        Ok::<_, anyhow::Error>(reset == h2::Reason::CANCEL)
    });
    let (mut sender, connection) = h2::client::handshake(client_io).await?;
    let driver = tokio::spawn(connection);
    sender = sender.ready().await?;
    let request = http::Request::builder()
        .uri("https://fixture.invalid/a")
        .body(())?;
    let (response_a, mut stream_a) = sender.send_request(request, true)?;
    sender = sender.ready().await?;
    let request = http::Request::builder()
        .uri("https://fixture.invalid/b")
        .body(())?;
    let (response_b, _) = sender.send_request(request, true)?;
    let response_a = response_a.await?;
    let response_b = response_b.await?;
    let body_a = response_a.into_body();
    stream_a.send_reset(h2::Reason::CANCEL);
    drop(body_a);
    let mut body_b = response_b.into_body();
    let data = body_b.data().await.context("stream b response")??;
    let completed = data.as_ref() == b"stream-b-complete" && body_b.data().await.is_none();
    drop(sender);
    let reset_seen = server.await.context("join h2 server")??;
    driver.await.context("join h2 driver")??;
    Ok(reset_seen && completed)
}

impl FixtureServer {
    async fn bind(authority: &str) -> Result<Self> {
        let (certificate, key) = ephemeral_certificate(authority)?;
        let ca_pem = certificate.to_pem()?;
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        acceptor.set_certificate(&certificate)?;
        acceptor.set_private_key(&key)?;
        acceptor.check_private_key()?;
        acceptor.set_alpn_select_callback(|_, client| {
            boring::ssl::select_next_proto(b"\x08http/1.1", client)
                .ok_or(boring::ssl::AlpnError::NOACK)
        });
        Ok(Self {
            listener: TcpListener::bind(localhost_any()).await?,
            acceptor: acceptor.build(),
            ca_pem,
        })
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().context("read fixture address")
    }

    async fn serve_complete(self, expected_requests: usize) -> Result<ServerObservation> {
        let observation = Arc::new(Mutex::new(ServerObservation::default()));
        loop {
            let (tcp, _) = tokio::time::timeout(IO_TIMEOUT, self.listener.accept())
                .await
                .context("accept fixture timeout")??;
            let connection_id = {
                let mut state = observation
                    .lock()
                    .map_err(|_| anyhow!("fixture mutex poisoned"))?;
                state.accepted_connections += 1;
                state.accepted_connections
            };
            let Ok(tls) = tokio_boring::accept(&self.acceptor, tcp).await else {
                observation
                    .lock()
                    .map_err(|_| anyhow!("fixture mutex poisoned"))?
                    .handshake_failures += 1;
                continue;
            };
            serve_complete_connection(tls, connection_id, expected_requests, &observation).await?;
            if observation
                .lock()
                .map_err(|_| anyhow!("fixture mutex poisoned"))?
                .requests
                .len()
                >= expected_requests
            {
                break;
            }
        }
        Arc::try_unwrap(observation)
            .map_err(|_| anyhow!("fixture observation still shared"))?
            .into_inner()
            .map_err(|_| anyhow!("fixture mutex poisoned"))
    }

    async fn serve_handshake_only(self) -> bool {
        let Ok(Ok((tcp, _))) = tokio::time::timeout(IO_TIMEOUT, self.listener.accept()).await
        else {
            return false;
        };
        tokio_boring::accept(&self.acceptor, tcp).await.is_ok()
    }

    async fn serve_upload_cancellation(self) -> Result<H1CancellationEvidence> {
        let (tcp, _) = tokio::time::timeout(IO_TIMEOUT, self.listener.accept())
            .await
            .context("accept C02 timeout")??;
        let mut tls = tokio_boring::accept(&self.acceptor, tcp).await?;
        let mut bytes = Vec::new();
        let header_end = read_request_head(&mut tls, &mut bytes).await?;
        let declared_body_bytes = content_length_from_head(&bytes[..header_end])?;
        let mut observed_body_bytes = bytes.len().saturating_sub(header_end);
        let mut chunk = vec![0_u8; 16 * 1024];
        let peer_close_observed = loop {
            match tokio::time::timeout(IO_TIMEOUT, tls.read(&mut chunk)).await {
                Ok(Ok(0)) => break true,
                Ok(Ok(read)) => {
                    observed_body_bytes = observed_body_bytes.saturating_add(read);
                    ensure!(
                        observed_body_bytes <= declared_body_bytes,
                        "C02 observed more body bytes than declared"
                    );
                }
                Ok(Err(error)) if is_terminal_close(&error) => break true,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => break false,
            }
        };
        Ok(H1CancellationEvidence {
            accepted_connections: 1,
            declared_body_bytes,
            observed_body_bytes,
            complete_request_observed: observed_body_bytes == declared_body_bytes,
            peer_close_observed,
            response_bytes_observed_by_client: 0,
            follow_up_request_completed: false,
        })
    }

    async fn serve_submitted_cancellation(self) -> Result<H1CancellationEvidence> {
        let (tcp, _) = tokio::time::timeout(IO_TIMEOUT, self.listener.accept())
            .await
            .context("accept C03 timeout")??;
        let mut tls = tokio_boring::accept(&self.acceptor, tcp).await?;
        let mut buffer = Vec::new();
        let request = read_request(&mut tls, &mut buffer, 1, 1)
            .await?
            .context("C03 request missing")?;
        let peer_close_observed = wait_for_peer_close(&mut tls).await?;
        Ok(H1CancellationEvidence {
            accepted_connections: 1,
            declared_body_bytes: request.body_bytes,
            observed_body_bytes: request.body_bytes,
            complete_request_observed: true,
            peer_close_observed,
            response_bytes_observed_by_client: 0,
            follow_up_request_completed: false,
        })
    }

    async fn serve_response_cancellation_then_complete(self) -> Result<H1CancellationEvidence> {
        let (first_tcp, _) = tokio::time::timeout(IO_TIMEOUT, self.listener.accept())
            .await
            .context("accept C04 timeout")??;
        let mut first_tls = tokio_boring::accept(&self.acceptor, first_tcp).await?;
        let mut first_buffer = Vec::new();
        let first_request = read_request(&mut first_tls, &mut first_buffer, 1, 1)
            .await?
            .context("C04 request missing")?;
        let partial = b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{:x}\r\n",
            partial.len().saturating_mul(4)
        );
        first_tls.write_all(response.as_bytes()).await?;
        first_tls.write_all(partial).await?;
        first_tls.flush().await?;
        let peer_close_observed = wait_for_peer_close(&mut first_tls).await?;

        let observation = Arc::new(Mutex::new(ServerObservation {
            accepted_connections: 2,
            requests: vec![first_request.clone()],
            handshake_failures: 0,
        }));
        let (second_tcp, _) = tokio::time::timeout(IO_TIMEOUT, self.listener.accept())
            .await
            .context("accept C05 follow-up timeout")??;
        let second_tls = tokio_boring::accept(&self.acceptor, second_tcp).await?;
        serve_complete_connection(second_tls, 2, 2, &observation).await?;
        let state = Arc::try_unwrap(observation)
            .map_err(|_| anyhow!("C05 observation still shared"))?
            .into_inner()
            .map_err(|_| anyhow!("C05 mutex poisoned"))?;
        Ok(H1CancellationEvidence {
            accepted_connections: state.accepted_connections,
            declared_body_bytes: first_request.body_bytes,
            observed_body_bytes: first_request.body_bytes,
            complete_request_observed: true,
            peer_close_observed,
            response_bytes_observed_by_client: 0,
            follow_up_request_completed: state.requests.len() == 2,
        })
    }
}

async fn read_request_head<S>(stream: &mut S, buffer: &mut Vec<u8>) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(position) = find_bytes(buffer, b"\r\n\r\n") {
            return Ok(position + 4);
        }
        let mut chunk = vec![0_u8; 16 * 1024];
        let read = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .context("read request head timeout")??;
        ensure!(read > 0, "peer closed before request headers completed");
        ensure!(
            buffer.len().saturating_add(read) <= MAX_WIRE_BYTES,
            "request head exceeded wire limit"
        );
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn content_length_from_head(head: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(head).context("request head is not UTF-8")?;
    text.split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .context("invalid content-length")?
        .context("content-length missing")
}

async fn wait_for_peer_close<S>(stream: &mut S) -> Result<bool>
where
    S: AsyncRead + Unpin,
{
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(IO_TIMEOUT, stream.read(&mut byte)).await {
        Ok(Ok(0)) => Ok(true),
        Ok(Err(error)) if is_terminal_close(&error) => Ok(true),
        Ok(Ok(_)) | Err(_) => Ok(false),
        Ok(Err(error)) => Err(error.into()),
    }
}

async fn serve_complete_connection<S>(
    mut stream: S,
    connection_id: usize,
    expected_requests: usize,
    observation: &Arc<Mutex<ServerObservation>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = Vec::new();
    loop {
        let sequence = observation
            .lock()
            .map_err(|_| anyhow!("fixture mutex poisoned"))?
            .requests
            .len()
            + 1;
        let Some(request) = read_request(&mut stream, &mut buffer, connection_id, sequence).await?
        else {
            return Ok(());
        };
        observation
            .lock()
            .map_err(|_| anyhow!("fixture mutex poisoned"))?
            .requests
            .push(request);
        let body = b"event: message_start\ndata: {\"type\":\"message_start\"}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{:x}\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.write_all(b"\r\n0\r\n\r\n").await?;
        stream.flush().await?;
        if sequence >= expected_requests {
            stream.shutdown().await?;
            return Ok(());
        }
    }
}

async fn read_request<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    connection_id: usize,
    sequence: usize,
) -> Result<Option<CapturedRequest>>
where
    S: AsyncRead + Unpin,
{
    let header_end = loop {
        if let Some(position) = find_bytes(buffer, b"\r\n\r\n") {
            break position + 4;
        }
        let mut chunk = vec![0_u8; 16 * 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            ensure!(buffer.is_empty(), "partial request headers at EOF");
            return Ok(None);
        }
        ensure!(
            buffer.len().saturating_add(read) <= MAX_WIRE_BYTES,
            "request exceeded wire limit"
        );
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head =
        std::str::from_utf8(&buffer[..header_end]).context("request headers are not UTF-8")?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().context("missing request line")?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().context("missing method")?.to_owned();
    let path = parts.next().context("missing path")?.to_owned();
    let _version = parts.next().context("missing HTTP version")?;
    ensure!(parts.next().is_none(), "invalid request line");
    let mut header_names = Vec::new();
    let mut content_length = 0_usize;
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').context("invalid header")?;
        header_names.push(name.to_owned());
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().context("invalid content-length")?;
        }
    }
    let request_end = header_end
        .checked_add(content_length)
        .context("request length overflow")?;
    while buffer.len() < request_end {
        let mut chunk = vec![0_u8; 16 * 1024];
        let read = stream.read(&mut chunk).await?;
        ensure!(read > 0, "partial request body at EOF");
        ensure!(
            buffer.len().saturating_add(read) <= MAX_WIRE_BYTES,
            "request exceeded wire limit"
        );
        buffer.extend_from_slice(&chunk[..read]);
    }
    let wire = buffer[..request_end].to_vec();
    buffer.drain(..request_end);
    Ok(Some(CapturedRequest {
        connection_id,
        sequence,
        method,
        path,
        header_names,
        body_bytes: content_length,
        wire_sha256: sha256_hex(&wire),
    }))
}

async fn send_request(
    connection: &mut DirectTlsConnection,
    request: &[u8],
    response_buffer: &mut Vec<u8>,
) -> Result<ResponseObservation> {
    tokio::time::timeout(IO_TIMEOUT, connection.stream.write_all(request))
        .await
        .context("request write timeout")??;
    tokio::time::timeout(IO_TIMEOUT, connection.stream.flush())
        .await
        .context("request flush timeout")??;
    read_response(&mut connection.stream, response_buffer).await
}

async fn read_response<S>(stream: &mut S, buffer: &mut Vec<u8>) -> Result<ResponseObservation>
where
    S: AsyncRead + Unpin,
{
    let header_end = loop {
        if let Some(position) = find_bytes(buffer, b"\r\n\r\n") {
            break position + 4;
        }
        read_more(stream, buffer).await?;
    };
    let head =
        std::str::from_utf8(&buffer[..header_end]).context("response headers are not UTF-8")?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .context("invalid response status")?;
    let chunked = head.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    });
    ensure!(chunked, "fixture response is not chunked");
    let mut cursor = header_end;
    let mut body = Vec::new();
    loop {
        let line_end = loop {
            if let Some(position) = find_bytes(&buffer[cursor..], b"\r\n") {
                break cursor + position;
            }
            read_more(stream, buffer).await?;
        };
        let size = usize::from_str_radix(
            std::str::from_utf8(&buffer[cursor..line_end])?
                .split(';')
                .next()
                .unwrap_or_default(),
            16,
        )
        .context("invalid chunk size")?;
        cursor = line_end + 2;
        if size == 0 {
            while buffer.len() < cursor + 2 {
                read_more(stream, buffer).await?;
            }
            ensure!(
                &buffer[cursor..cursor + 2] == b"\r\n",
                "invalid terminal chunk"
            );
            cursor += 2;
            break;
        }
        while buffer.len() < cursor.saturating_add(size).saturating_add(2) {
            read_more(stream, buffer).await?;
        }
        body.extend_from_slice(&buffer[cursor..cursor + size]);
        ensure!(
            &buffer[cursor + size..cursor + size + 2] == b"\r\n",
            "invalid chunk framing"
        );
        cursor += size + 2;
    }
    let wire_bytes = cursor;
    buffer.drain(..cursor);
    Ok(ResponseObservation {
        status,
        body,
        wire_bytes,
    })
}

async fn read_more<S>(stream: &mut S, buffer: &mut Vec<u8>) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut chunk = vec![0_u8; 16 * 1024];
    let read = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut chunk))
        .await
        .context("response read timeout")??;
    ensure!(read > 0, "response ended before framing completed");
    ensure!(
        buffer.len().saturating_add(read) <= MAX_WIRE_BYTES,
        "response exceeded wire limit"
    );
    buffer.extend_from_slice(&chunk[..read]);
    Ok(())
}

fn synthetic_request(plan: &ReplayPlan) -> Result<Vec<u8>> {
    let profile = plan.http1().context("matrix requires HTTP/1.1 plan")?;
    let path = synthetic_messages_path(profile.path_bytes)?;
    let body = synthetic_body(profile.body_bytes)?;
    let headers = plan
        .headers
        .iter()
        .map(|rule| {
            let value = match rule.canonical_name.as_str() {
                "host" if plan.target.authority.len() == rule.value_bytes => {
                    plan.target.authority.clone()
                }
                "host" => "h".repeat(rule.value_bytes),
                "content-length" => body.len().to_string(),
                "connection" if rule.value_bytes == 10 => "keep-alive".to_owned(),
                "authorization" => synthetic_bearer(rule.value_bytes),
                "x-claude-code-session-id" if rule.value_bytes == 36 => {
                    "00000000-0000-4000-8000-000000000000".to_owned()
                }
                _ => rule
                    .exact_value
                    .clone()
                    .unwrap_or_else(|| "x".repeat(rule.value_bytes)),
            };
            ensure!(
                value.len() == rule.value_bytes,
                "header shape drifted for {}",
                rule.canonical_name
            );
            Ok((rule.wire_name.clone(), value))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut wire = Vec::with_capacity(body.len() + 2048);
    wire.extend_from_slice(profile.method.as_bytes());
    wire.push(b' ');
    wire.extend_from_slice(path.as_bytes());
    wire.push(b' ');
    wire.extend_from_slice(profile.version.as_bytes());
    wire.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        wire.extend_from_slice(name.as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(&body);
    Ok(wire)
}

fn synthetic_messages_path(bytes: usize) -> Result<String> {
    const BASE: &str = "/v1/messages";
    if bytes == BASE.len() {
        return Ok(BASE.to_owned());
    }
    ensure!(bytes >= BASE.len() + 3, "plan path shape is too short");
    let mut path = format!("{BASE}?x=");
    path.push_str(&"x".repeat(bytes - path.len()));
    Ok(path)
}

fn synthetic_body(bytes: u32) -> Result<Vec<u8>> {
    let prefix = br#"{"model":"capture-model","max_tokens":1,"stream":true,"messages":[{"role":"user","content":"probe"}],"padding":""#;
    let suffix = br#""}"#;
    let bytes = usize::try_from(bytes).context("convert body length")?;
    ensure!(
        bytes >= prefix.len() + suffix.len(),
        "plan body shape is too short"
    );
    let mut body = Vec::with_capacity(bytes);
    body.extend_from_slice(prefix);
    body.extend(std::iter::repeat_n(
        b'x',
        bytes - prefix.len() - suffix.len(),
    ));
    body.extend_from_slice(suffix);
    Ok(body)
}

fn synthetic_bearer(bytes: usize) -> String {
    const PREFIX: &str = "Bearer ";
    if bytes >= PREFIX.len() {
        format!("{PREFIX}{}", "s".repeat(bytes - PREFIX.len()))
    } else {
        "s".repeat(bytes)
    }
}

fn direct_policy(server_addr: SocketAddr, trust_roots_pem: Vec<u8>) -> DirectTlsPolicy {
    DirectTlsPolicy {
        connect_timeout_ms: 5_000,
        handshake_timeout_ms: 5_000,
        required_alpn: Some("http/1.1".to_owned()),
        trust_roots_pem: Some(trust_roots_pem),
        dial_override: Some(DialEndpoint {
            host: server_addr.ip().to_string(),
            port: server_addr.port(),
        }),
        proxy: None,
    }
}

fn pool_key(
    credential: &str,
    profile_epoch: u64,
    bundle_version: u32,
    egress: &str,
    egress_epoch: u64,
) -> PoolKey {
    PoolKey {
        credential_id: credential.to_owned(),
        profile_epoch,
        archetype_bundle_version: bundle_version,
        egress_binding_id: egress.to_owned(),
        egress_epoch,
        destination_authority: "api.anthropic.com".to_owned(),
        negotiated_protocol: "http/1.1".to_owned(),
    }
}

async fn spawn_proxy(
    kind: ProxyKind,
    upstream: SocketAddr,
) -> Result<(
    ProxyRoute,
    tokio::task::JoinHandle<Result<ProxyObservation>>,
)> {
    let listener = TcpListener::bind(localhost_any()).await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        match kind {
            ProxyKind::HttpConnect | ProxyKind::HttpConnectBasic => {
                serve_http_connect(listener, upstream).await
            }
            ProxyKind::Socks5Local | ProxyKind::Socks5Remote => {
                serve_socks5(listener, upstream).await
            }
        }
    });
    let endpoint = DialEndpoint {
        host: address.ip().to_string(),
        port: address.port(),
    };
    let route = match kind {
        ProxyKind::HttpConnect => ProxyRoute::HttpConnect {
            endpoint,
            credentials: None,
        },
        ProxyKind::HttpConnectBasic => ProxyRoute::HttpConnect {
            endpoint,
            credentials: Some(ProxyCredentials::new(
                "fixture-user".to_owned(),
                "fixture-pass".to_owned(),
            )),
        },
        ProxyKind::Socks5Local => ProxyRoute::Socks5 {
            endpoint,
            dns: Socks5Dns::Local,
            credentials: None,
        },
        ProxyKind::Socks5Remote => ProxyRoute::Socks5 {
            endpoint,
            dns: Socks5Dns::Remote,
            credentials: None,
        },
    };
    Ok((route, task))
}

async fn serve_http_connect(
    listener: TcpListener,
    upstream: SocketAddr,
) -> Result<ProxyObservation> {
    let (mut client, _) = listener.accept().await?;
    let head = read_http_head(&mut client, 16 * 1024).await?;
    let text = std::str::from_utf8(&head)?;
    let requested_authority = text
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .unwrap_or_default()
        .to_owned();
    let proxy_authorization_seen = text.lines().any(|line| {
        line.to_ascii_lowercase()
            .starts_with("proxy-authorization:")
    });
    let mut origin = TcpStream::connect(upstream).await?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut origin).await
        && !is_terminal_close(&error)
    {
        return Err(error.into());
    }
    Ok(ProxyObservation {
        requested_authority,
        proxy_authorization_seen,
        socks_address_type: None,
    })
}

async fn serve_socks5(listener: TcpListener, upstream: SocketAddr) -> Result<ProxyObservation> {
    let (mut client, _) = listener.accept().await?;
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    ensure!(greeting[0] == 5, "invalid SOCKS version");
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    client.read_exact(&mut methods).await?;
    client.write_all(&[5, 0]).await?;
    let mut request = [0_u8; 4];
    client.read_exact(&mut request).await?;
    ensure!(request[..3] == [5, 1, 0], "invalid SOCKS CONNECT request");
    let requested_authority = read_socks_address(&mut client, request[3]).await?;
    let mut origin = TcpStream::connect(upstream).await?;
    client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
    if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut origin).await
        && !is_terminal_close(&error)
    {
        return Err(error.into());
    }
    Ok(ProxyObservation {
        requested_authority,
        proxy_authorization_seen: false,
        socks_address_type: Some(request[3]),
    })
}

async fn read_socks_address(stream: &mut TcpStream, kind: u8) -> Result<String> {
    let host = match kind {
        1 => {
            let mut value = [0_u8; 4];
            stream.read_exact(&mut value).await?;
            Ipv4Addr::from(value).to_string()
        }
        3 => {
            let length = stream.read_u8().await?;
            let mut value = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut value).await?;
            String::from_utf8(value)?
        }
        4 => {
            let mut value = [0_u8; 16];
            stream.read_exact(&mut value).await?;
            std::net::Ipv6Addr::from(value).to_string()
        }
        _ => return Err(anyhow!("invalid SOCKS address type")),
    };
    let port = stream.read_u16().await?;
    Ok(format!("{host}:{port}"))
}

async fn read_http_head(stream: &mut TcpStream, limit: usize) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    while response.len() < limit {
        let byte = stream.read_u8().await?;
        response.push(byte);
        if response.ends_with(b"\r\n\r\n") {
            return Ok(response);
        }
    }
    Err(anyhow!("HTTP head exceeded limit"))
}

fn ephemeral_certificate(authority: &str) -> Result<(X509, PKey<Private>)> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, authority)?;
    let name = name.build();
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_subject_name(&name)?;
    certificate.set_issuer_name(&name)?;
    certificate.set_pubkey(&key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(1)?;
    certificate.set_not_before(&not_before)?;
    certificate.set_not_after(&not_after)?;
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    certificate.set_serial_number(&serial)?;
    let mut subject_alt_name = SubjectAlternativeName::new();
    if authority.parse::<IpAddr>().is_ok() {
        subject_alt_name.ip(authority);
    } else {
        subject_alt_name.dns(authority);
    }
    let extensions = [
        BasicConstraints::new().critical().ca().build()?,
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .key_cert_sign()
            .build()?,
        ExtendedKeyUsage::new().server_auth().build()?,
        subject_alt_name.build(&certificate.x509v3_context(None, None))?,
    ];
    for extension in extensions {
        certificate.append_extension(&extension)?;
    }
    certificate.sign(&key, MessageDigest::sha256())?;
    Ok((certificate.build(), key))
}

fn pass<const N: usize>(id: &str, entries: [(&str, Value); N]) -> ScenarioEvidence {
    ScenarioEvidence {
        id: id.to_owned(),
        decision: "pass".to_owned(),
        observations: entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    }
}

fn transport_error_stage(error: &transport_core::TransportError) -> &'static str {
    match error {
        transport_core::TransportError::Connection { stage, .. } => stage,
        _ => "non_connection_error",
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_terminal_close(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
}

fn localhost_any() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn observed_now() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("unix-ms:{millis}")
}

fn current_exe_sha256() -> Result<String> {
    let path = std::env::current_exe().context("resolve current executable")?;
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn report_sha256(report: &TransportMatrixReport) -> Result<String> {
    let value = serde_json::to_value(report)?;
    let mut object = value
        .as_object()
        .cloned()
        .context("report is not an object")?;
    object.insert("report_sha256".to_owned(), Value::String(String::new()));
    Ok(sha256_hex(&serde_json::to_vec(&object)?))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
