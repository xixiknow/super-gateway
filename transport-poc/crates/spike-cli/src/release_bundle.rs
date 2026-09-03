use std::{
    collections::BTreeSet,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use archetype_bundle::{ApplicationProfileSpec, CandidateArchetypeBundle, HeaderValueMode, verify_bundle};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use capture_schema::{CaptureManifest, CaptureManifestState};
use clap::ValueEnum;
use ed25519_dalek::SigningKey;
use gateway_domain::{FinalUpstreamRequest, UpstreamHeader};
use gateway_transport::{
    ApplicationProfile, BoringTlsConnector, BundleConnectionPolicy, BundleEvidenceGate, BundleLifecycle,
    BundleLoadContext, BundleRuntimeState, BundleTrustStore, CompiledTransportEngine, EngineBuild, HeaderTemplate,
    Http1Profile, SignedBundleEnvelope, TlsProfile, TransportBundlePayload, TrustKey, TrustKeyStatus,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tls_tap::{TlsTapConfig, TlsTapListener, parse_client_hello};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

const FORMAL_BACKEND_ID: &str = "gateway-transport-boringssl-h1-v1";
const ENGINE_ABI: &str = "1.0";
const ENGINE_BUILD: &str = "0.1.0";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum PublishLifecycle {
    Verified,
    Active,
}

#[derive(Debug)]
pub(crate) struct PromoteRequest {
    pub candidate: PathBuf,
    pub manifest: PathBuf,
    pub audit: PathBuf,
    pub stability_report: PathBuf,
    pub signing_key: PathBuf,
    pub key_id: String,
    pub target: String,
    pub source_archetype_version_id: String,
    pub engine_artifact: PathBuf,
    pub lifecycle: PublishLifecycle,
    pub output: PathBuf,
    pub trust_store_output: PathBuf,
    pub replay_report_output: PathBuf,
}

#[derive(Debug, Serialize)]
struct FormalReplayReport {
    schema_version: u32,
    decision: &'static str,
    target: String,
    source_candidate_sha256: String,
    production_verifier_sha256: String,
    production_engine_artifact_sha256: String,
    tls_client_hello_exact: bool,
    cipher_order_exact: bool,
    extension_order_exact: bool,
    alpn_order_exact: bool,
    client_hello_length_exact: bool,
    record_framing_exact: bool,
    http1_header_order_exact: bool,
    http1_body_bytes_exact: bool,
}

pub(crate) async fn promote(request: PromoteRequest) -> Result<()> {
    ensure!(
        request.target == "x86_64-pc-windows-msvc",
        "formal release currently targets Windows x86_64"
    );
    let candidate: CandidateArchetypeBundle = read_json(&request.candidate)?;
    verify_bundle(&candidate).context("verify POC schema v2 Bundle candidate")?;
    let manifest: CaptureManifest = read_json(&request.manifest)?;
    manifest.validate().context("verify capture Manifest")?;
    ensure!(
        manifest.state == CaptureManifestState::Verified,
        "capture Manifest is not verified"
    );
    ensure!(
        candidate.evidence.manifest_id == manifest.manifest_id,
        "candidate and Manifest are not bound"
    );
    ensure!(
        candidate.evidence.capture_run_id == manifest.capture_run_id,
        "candidate and Manifest use different capture runs"
    );
    verify_audit(&request.audit, &candidate.bundle_sha256)?;
    verify_stability(&request.stability_report)?;
    let tls = formal_tls_profile(&candidate)?;
    let headers = formal_headers(&candidate)?;
    let replay = run_formal_replay(&request, &candidate, &tls, &headers).await?;
    write_json(&request.replay_report_output, &replay)?;
    let replay_hash = file_sha256(&request.replay_report_output)?;
    let engine_hash = file_sha256(&request.engine_artifact)?;
    let client_version = parse_client_version(&manifest.environment.claude_code_version)?;
    let artifact_version = encode_artifact_version(&client_version)?;
    let claude_binary_hash = manifest
        .environment
        .binary_sha256
        .as_deref()
        .context("capture Manifest has no Claude executable SHA-256")?;
    ensure!(
        claude_binary_hash.len() == 64,
        "capture Manifest Claude executable SHA-256 is invalid"
    );
    let capture_cohort = format!(
        "windows-x86_64-claude-code-native-{client_version}-{}",
        &claude_binary_hash[..16]
    );
    let mut evidence_hashes = vec![
        candidate.evidence.passive_tls.normalized_sha256.clone(),
        candidate.evidence.controlled_http2.normalized_sha256.clone(),
        file_sha256(&request.candidate)?,
        file_sha256(&request.manifest)?,
        file_sha256(&request.audit)?,
        file_sha256(&request.stability_report)?,
        replay_hash,
    ];
    evidence_hashes.sort();
    evidence_hashes.dedup();
    let lifecycle = match request.lifecycle {
        PublishLifecycle::Verified => BundleLifecycle::Verified,
        PublishLifecycle::Active => BundleLifecycle::Active,
    };
    let payload = TransportBundlePayload {
        schema_version: "1.0.0".into(),
        engine_abi_version: ENGINE_ABI.into(),
        bundle_id: format!("claude_code_windows_x64_{}_h1", client_version.replace('.', "_")).into_boxed_str(),
        artifact_version,
        lifecycle,
        evidence_gate: BundleEvidenceGate::Passed,
        runtime_state: BundleRuntimeState::Loadable,
        backend_id: FORMAL_BACKEND_ID.into(),
        required_capabilities: vec!["tls_client_hello".into(), "ordered_http1".into()],
        source_archetype_version_id: request.source_archetype_version_id.clone().into_boxed_str(),
        capture_cohort: capture_cohort.into_boxed_str(),
        application: ApplicationProfile::H1 {
            authority: "api.anthropic.com".into(),
            tls,
            http1: Http1Profile {
                request_line_form: "origin".into(),
                header_order: headers,
                framing: "content-length".into(),
            },
            connection: connection_policy(),
        },
        min_engine_build: ENGINE_BUILD.into(),
        max_engine_build: None,
        engine_builds: vec![EngineBuild {
            target: request.target.clone().into_boxed_str(),
            artifact_digest: engine_hash.into_boxed_str(),
            boringssl_revision: "cloudflare-boring-5.2".into(),
            compiler: "rustc 1.95.0 msvc".into(),
        }],
        supported_targets: vec![request.target.clone().into_boxed_str()],
        evidence_hashes: evidence_hashes.into_iter().map(String::into_boxed_str).collect(),
        created_at: manifest.created_at.clone().into_boxed_str(),
    };
    let signing_key = load_or_create_signing_key(&request.signing_key)?;
    let envelope = SignedBundleEnvelope::sign(payload, request.key_id.clone(), &signing_key)
        .context("sign formal Bundle envelope")?;
    let trust_store = BundleTrustStore {
        format_version: "1.0.0".into(),
        domain: "transport_bundle_v1".into(),
        keys: vec![TrustKey {
            key_id: request.key_id.into_boxed_str(),
            status: TrustKeyStatus::Current,
            public_key_base64: STANDARD.encode(signing_key.verifying_key().to_bytes()).into_boxed_str(),
            valid_from_unix_seconds: None,
            valid_until_unix_seconds: None,
        }],
    };
    verify_formal_envelope(&envelope, &trust_store, &request.target)?;
    write_json(&request.output, &envelope)?;
    write_json(&request.trust_store_output, &trust_store)?;
    println!(
        "formal signed Bundle: version={client_version}, target={}, sha256={}, output={}",
        request.target,
        envelope.canonicalization.canonical_hash,
        request.output.display()
    );
    Ok(())
}

fn formal_tls_profile(candidate: &CandidateArchetypeBundle) -> Result<TlsProfile> {
    let groups = extension_attribute(candidate, 10, "groups")?;
    let key_shares = extension_attribute(candidate, 51, "key_share_shape")?;
    Ok(TlsProfile {
        client_hello_profile: format!("claude-code-{}", candidate.archetype_id).into_boxed_str(),
        alpn: candidate
            .tls
            .alpn_order
            .iter()
            .cloned()
            .map(String::into_boxed_str)
            .collect(),
        cipher_suite_ids: candidate.tls.cipher_suites.clone(),
        supported_group_ids: parse_hex_list(&groups)?,
        key_share_group_ids: key_shares
            .split(',')
            .map(|value| value.split(':').next().unwrap_or(value))
            .map(parse_hex_u16)
            .collect::<Result<Vec<_>>>()?,
        extension_order: candidate
            .tls
            .extensions
            .iter()
            .map(|item| item.extension_type)
            .collect(),
        grease_enabled: candidate.tls.cipher_suites.iter().any(|value| value & 0x0f0f == 0x0a0a),
        permute_extensions: false,
        session_resumption: false,
    })
}

fn extension_attribute(candidate: &CandidateArchetypeBundle, extension_type: u16, name: &str) -> Result<String> {
    candidate
        .tls
        .extensions
        .iter()
        .find(|extension| extension.extension_type == extension_type)
        .and_then(|extension| extension.attributes.iter().find(|attribute| attribute.name == name))
        .and_then(|attribute| attribute.value.clone())
        .with_context(|| format!("TLS extension {extension_type} attribute {name} is missing"))
}

fn parse_hex_list(value: &str) -> Result<Vec<u16>> {
    value.split(',').map(parse_hex_u16).collect()
}

fn parse_hex_u16(value: &str) -> Result<u16> {
    let value = value
        .trim()
        .strip_prefix("0x")
        .context("TLS identifier lacks 0x prefix")?;
    u16::from_str_radix(value, 16).context("TLS identifier is invalid")
}

fn formal_headers(candidate: &CandidateArchetypeBundle) -> Result<Vec<HeaderTemplate>> {
    let mut headers = Vec::with_capacity(candidate.headers.ordered_names.len());
    for name in &candidate.headers.ordered_names {
        let rule = candidate
            .headers
            .value_rules
            .iter()
            .find(|rule| rule.wire_name == *name)
            .with_context(|| format!("Header rule is missing for {name}"))?;
        let template = match (&rule.mode, rule.canonical_name.as_str()) {
            (HeaderValueMode::Exact, _) => rule.exact_value.clone().context("exact Header has no value")?,
            (HeaderValueMode::CredentialDerivedSecret, "authorization" | "x-api-key") => "{authorization}".to_owned(),
            (HeaderValueMode::CredentialDerivedSecret, "x-claude-code-session-id") => "{session_id}".to_owned(),
            (HeaderValueMode::Shape, "anthropic-dangerous-direct-browser-access") => "true".to_owned(),
            (HeaderValueMode::Shape, "connection") => "keep-alive".to_owned(),
            (HeaderValueMode::Shape, "host") => "{authority}".to_owned(),
            (HeaderValueMode::Shape, "content-length") => "{content_length}".to_owned(),
            _ => bail!("Header {} has no safe formal runtime template", rule.wire_name),
        };
        headers.push(HeaderTemplate {
            name: rule.wire_name.clone().into_boxed_str(),
            value_template: template.into_boxed_str(),
            sensitive: rule.mode == HeaderValueMode::CredentialDerivedSecret,
        });
    }
    Ok(headers)
}

async fn run_formal_replay(
    request: &PromoteRequest,
    candidate: &CandidateArchetypeBundle,
    tls: &TlsProfile,
    headers: &[HeaderTemplate],
) -> Result<FormalReplayReport> {
    let application = match &candidate.application {
        ApplicationProfileSpec::Http1(profile) => profile,
        ApplicationProfileSpec::Http2(_) => bail!("formal Windows release requires HTTP/1.1 evidence"),
    };
    let tap = TlsTapListener::bind(TlsTapConfig {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        upstream_host: "api.anthropic.com".to_owned(),
        upstream_port: 443,
        max_capture_bytes: 256 * 1024,
        session_timeout: Duration::from_secs(30),
    })
    .await
    .context("bind formal production TLS replay tap")?;
    let tap_addr = tap.local_addr().context("read formal replay tap address")?;
    let capture_task = tokio::spawn(tap.capture_client_hello());
    let stream = TcpStream::connect(tap_addr)
        .await
        .context("connect formal replay tap")?;
    let connection = BoringTlsConnector
        .connect(
            Box::new(stream),
            "api.anthropic.com",
            tls,
            Duration::from_secs(20),
            &CancellationToken::new(),
            false,
        )
        .await
        .context("run formal gateway-transport TLS replay")?;
    let captured = capture_task.await.context("join formal replay tap")??;
    drop(connection);
    let hello = parse_client_hello(&captured).context("parse formal replay ClientHello")?;
    let expected_extensions = candidate
        .tls
        .extensions
        .iter()
        .map(|extension| extension.extension_type)
        .collect::<Vec<_>>();
    let actual_extensions = hello
        .extensions
        .iter()
        .map(|extension| extension.extension_type)
        .collect::<Vec<_>>();
    let cipher_order_exact = hello.cipher_suites == candidate.tls.cipher_suites;
    let extension_order_exact = actual_extensions == expected_extensions;
    let alpn_order_exact = hello.alpn == candidate.tls.alpn_order;
    let client_hello_length_exact = hello.client_hello_len == candidate.tls.client_hello_len;
    let record_framing_exact = hello.record_lengths == candidate.tls.record_lengths;
    let (http1_header_order_exact, http1_body_bytes_exact) = replay_http1(headers, application.body_bytes)?;
    ensure!(
        cipher_order_exact
            && extension_order_exact
            && alpn_order_exact
            && client_hello_length_exact
            && record_framing_exact
            && http1_header_order_exact
            && http1_body_bytes_exact,
        "formal production Transport replay does not match the verified reference"
    );
    Ok(FormalReplayReport {
        schema_version: 1,
        decision: "passed",
        target: request.target.clone(),
        source_candidate_sha256: file_sha256(&request.candidate)?,
        production_verifier_sha256: file_sha256(
            &std::env::current_exe().context("locate production replay executable")?,
        )?,
        production_engine_artifact_sha256: file_sha256(&request.engine_artifact)?,
        tls_client_hello_exact: true,
        cipher_order_exact,
        extension_order_exact,
        alpn_order_exact,
        client_hello_length_exact,
        record_framing_exact,
        http1_header_order_exact,
        http1_body_bytes_exact,
    })
}

fn replay_http1(headers: &[HeaderTemplate], body_bytes: u32) -> Result<(bool, bool)> {
    let body_len = usize::try_from(body_bytes).context("captured Body length is invalid")?;
    let body = vec![b'x'; body_len];
    let rendered_headers = headers
        .iter()
        .map(|header| {
            let value = header
                .value_template
                .replace("{authorization}", &format!("Bearer {}", "x".repeat(54)))
                .replace("{session_id}", "00000000-0000-4000-8000-000000000000")
                .replace("{authority}", "api.anthropic.com")
                .replace("{content_length}", &body_len.to_string());
            ensure!(
                !value.contains(['{', '}']),
                "unresolved Header template in formal replay"
            );
            Ok(UpstreamHeader {
                name: header.name.clone(),
                value: Arc::from(value.into_bytes()),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let request = FinalUpstreamRequest {
        method: "POST".into(),
        scheme: "https".into(),
        authority: "api.anthropic.com".into(),
        path_and_query: "/v1/messages?beta=true".into(),
        headers: rendered_headers.into(),
        body: Arc::from(body),
        stream: true,
    };
    let wire = gateway_transport::encode_request(&request).context("encode formal HTTP/1 replay")?;
    let header_end = wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("formal HTTP/1 replay lacks Header terminator")?;
    let head = std::str::from_utf8(&wire[..header_end]).context("formal HTTP/1 Header is not ASCII")?;
    let actual_names = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name))
        .collect::<Vec<_>>();
    let expected_names = headers.iter().map(|header| header.name.as_ref()).collect::<Vec<_>>();
    Ok((actual_names == expected_names, wire.len() - header_end - 4 == body_len))
}

fn connection_policy() -> BundleConnectionPolicy {
    BundleConnectionPolicy {
        pool_key_fields: [
            "credential_id",
            "profile_epoch",
            "bundle_id",
            "bundle_version",
            "egress_binding_id",
            "egress_epoch",
            "authority",
            "sni",
            "protocol",
        ]
        .into_iter()
        .map(Into::into)
        .collect(),
        reuse_policy: "exact_pool_key".into(),
        resumption_cache_scope: "disabled".into(),
    }
}

fn verify_audit(path: &Path, candidate_hash: &str) -> Result<()> {
    let audit: Value = read_json(path)?;
    ensure!(
        audit.get("bundle_sha256").and_then(Value::as_str) == Some(candidate_hash),
        "Canary Audit is not bound to the candidate"
    );
    ensure!(
        audit.get("decision").and_then(Value::as_str) == Some("ready_for_canary"),
        "Canary Audit did not pass"
    );
    ensure!(
        audit.get("blocker_count").and_then(Value::as_u64) == Some(0),
        "Canary Audit has blockers"
    );
    Ok(())
}

fn verify_stability(path: &Path) -> Result<()> {
    let report: Value = read_json(path)?;
    let iterations = report
        .get("iterations")
        .and_then(Value::as_u64)
        .context("stability report has no iteration count")?;
    let passed = report
        .get("passed_runs")
        .and_then(Value::as_u64)
        .context("stability report has no passed run count")?;
    let decision = report.get("decision").and_then(Value::as_str).unwrap_or_default();
    ensure!(
        iterations >= 20 && passed == iterations && decision.eq_ignore_ascii_case("pass"),
        "20-round stability gate did not pass"
    );
    Ok(())
}

fn verify_formal_envelope(envelope: &SignedBundleEnvelope, trust_store: &BundleTrustStore, target: &str) -> Result<()> {
    let verified = envelope
        .clone()
        .verify(
            trust_store,
            &BundleLoadContext {
                engine_abi_version: ENGINE_ABI.into(),
                engine_build: ENGINE_BUILD.into(),
                target: target.into(),
                supported_capabilities: BTreeSet::from(["tls_client_hello".into(), "ordered_http1".into()]),
                now_unix_seconds: 1_800_000_000,
                for_new_activation: true,
            },
        )
        .context("verify formal signed Bundle")?;
    CompiledTransportEngine::compile(verified).context("compile formal signed Bundle")?;
    Ok(())
}

fn load_or_create_signing_key(path: &Path) -> Result<SigningKey> {
    let value = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("read signing key {}", path.display()))?
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create signing key directory {}", parent.display()))?;
        }
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("generate Ed25519 signing key: {error}"))?;
        let encoded = hex::encode(bytes);
        fs::write(path, encoded.as_bytes()).with_context(|| format!("write signing key {}", path.display()))?;
        encoded
    };
    let bytes = hex::decode(value.trim()).context("signing key is not hexadecimal")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must contain 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn parse_client_version(value: &str) -> Result<String> {
    let version = value
        .split_whitespace()
        .next()
        .context("Claude Code version is missing")?;
    let parts = version.split('.').collect::<Vec<_>>();
    ensure!(
        parts.len() == 3 && parts.iter().all(|part| part.parse::<u64>().is_ok()),
        "Claude Code version is invalid"
    );
    Ok(version.to_owned())
}

fn encode_artifact_version(version: &str) -> Result<u64> {
    let parts = version
        .split('.')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse Claude Code version")?;
    ensure!(
        parts.len() == 3 && parts[1] < 1_000 && parts[2] < 1_000,
        "Claude Code version cannot be encoded"
    );
    Ok(parts[0] * 1_000_000 + parts[1] * 1_000 + parts[2])
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create output directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).context("serialize release JSON")?;
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn file_sha256(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {} for SHA-256", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
