#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail, ensure};
#[cfg(feature = "boring-backend")]
use archetype_bundle::HeaderValueMode;
use archetype_bundle::{
    BundleCompilerOptions, CandidateArchetypeBundle, compile_bundle, verify_bundle,
};
use capture_schema::{
    CAPTURE_MANIFEST_SCHEMA_VERSION, CAPTURE_SCHEMA_VERSION, CaptureBatch, CaptureEvent,
    CaptureEvidenceRef, CaptureLane, CaptureManifest, CaptureManifestState, ConnectionPhase,
    Direction, DnsMode, EnvironmentDescriptor, HeaderObservation, Http2FrameDetail, Http2FrameType,
    Http2Setting, ManifestEnvironmentDescriptor, ManifestScenarioDescriptor, ManifestVerification,
    NetworkDescriptor, NetworkPath, ScenarioDescriptor, TargetDescriptor, TlsAttributeObservation,
    TlsExtensionObservation,
};
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(feature = "boring-backend")]
use controlled_h2_capture::{CapturedH2Frame, ControlledH2Server, Http1RequestObservation};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
#[cfg(feature = "boring-backend")]
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(feature = "boring-backend")]
use tls_tap::{ConnectTlsTapConfig, ConnectTlsTapListener, parse_client_hello};
#[cfg(feature = "boring-backend")]
use transport_core::boring_backend::{
    DialEndpoint, DirectTlsPolicy, H1ProbePolicy, H1ProbeRequest, H2ProbePolicy, H2ProbeRequest,
    ProxyRoute, connect_direct, probe_h1_cancellation_with_request, probe_h1_with_request,
    probe_h2, probe_h2_with_request,
};
use transport_core::{
    ApplicationReplayPlan, AuditMode, BackendDescriptor, CanaryCancellationEvidence,
    CanaryTlsEvidence, ReplayPlan, TargetKind, TransportTarget, audit_bundle,
    audit_bundle_with_canary_evidence, build_replay_plan, h2_backend, load_bundle,
    verify_replay_plan,
};
#[cfg(feature = "boring-backend")]
use transport_core::{build_canary_cancellation_evidence, build_canary_tls_evidence};
use uuid::Uuid;
use wire_diff::{AllowedDifference, DiffDecision, DiffPolicy, WireDiffReport, compare_captures};
use wire_normalizer::{
    NormalizedCapture, normalize_capture, recompute_normalized_sha256, verify_normalized_capture,
};

const FRESH_STABILITY_MATRIX_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Parser)]
#[command(about = "Transport spike capture fixture and normalization utility")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Validate {
        #[arg(long)]
        input: PathBuf,
    },
    Normalize {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Sample {
        #[arg(long)]
        output: PathBuf,
    },
    SampleSet {
        #[arg(long)]
        directory: PathBuf,
    },
    Manifest {
        #[arg(long)]
        passive_tls: PathBuf,
        #[arg(long)]
        controlled_http2: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Diff {
        #[arg(long)]
        reference: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    Bundle {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        passive_tls: PathBuf,
        #[arg(long)]
        controlled_http2: PathBuf,
        #[arg(long)]
        archetype_id: Option<String>,
        #[arg(long, default_value_t = 1)]
        bundle_version: u32,
        #[arg(long)]
        output: PathBuf,
    },
    VerifyBundle {
        #[arg(long)]
        input: PathBuf,
    },
    AuditBundle {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = AuditModeArg::Probe)]
        mode: AuditModeArg,
        #[arg(long)]
        probe_plan: Vec<PathBuf>,
        #[arg(long = "tls-evidence", requires = "probe_plan")]
        tls_evidence: Vec<PathBuf>,
        #[arg(long = "cancellation-evidence", requires = "probe_plan")]
        cancellation_evidence: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    Plan {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long, value_enum, default_value_t = TargetKindArg::ControlledCapture)]
        target_kind: TargetKindArg,
        #[arg(long)]
        authority: String,
        #[arg(long, default_value_t = 443)]
        port: u16,
        #[arg(long, value_enum, default_value_t = AuditModeArg::Probe)]
        mode: AuditModeArg,
        #[arg(long)]
        output: PathBuf,
    },
    #[cfg(feature = "boring-backend")]
    ProbeTls {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long, default_value_t = 5_000)]
        connect_timeout_ms: u64,
        #[arg(long, default_value_t = 10_000)]
        handshake_timeout_ms: u64,
        #[arg(long, default_value = "h2")]
        required_alpn: String,
        #[arg(long)]
        ca_bundle: Option<PathBuf>,
        #[arg(long, requires = "dial_port")]
        dial_host: Option<String>,
        #[arg(long, requires = "dial_host")]
        dial_port: Option<u16>,
        #[arg(long)]
        output: PathBuf,
    },
    #[cfg(feature = "boring-backend")]
    ProbeH2 {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long, default_value_t = 5_000)]
        connect_timeout_ms: u64,
        #[arg(long, default_value_t = 10_000)]
        tls_handshake_timeout_ms: u64,
        #[arg(long, default_value_t = 10_000)]
        h2_handshake_timeout_ms: u64,
        #[arg(long)]
        ca_bundle: Option<PathBuf>,
        #[arg(long, requires = "dial_port")]
        dial_host: Option<String>,
        #[arg(long, requires = "dial_host")]
        dial_port: Option<u16>,
        #[arg(long)]
        output: PathBuf,
    },
    #[cfg(feature = "boring-backend")]
    CaptureTlsDiff {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        reference: PathBuf,
        #[arg(long)]
        ca_bundle: Option<PathBuf>,
        #[arg(long, default_value_t = 10_000)]
        connect_timeout_ms: u64,
        #[arg(long, default_value_t = 15_000)]
        handshake_timeout_ms: u64,
        #[arg(long)]
        output_capture: PathBuf,
        #[arg(long)]
        output_diff: PathBuf,
        #[arg(long)]
        output_evidence: PathBuf,
        #[arg(long)]
        output_canary_evidence: PathBuf,
    },
    #[cfg(feature = "boring-backend")]
    CaptureH2Diff {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        reference: PathBuf,
        #[arg(long, default_value_t = 15_000)]
        timeout_ms: u64,
        #[arg(long)]
        output_capture: PathBuf,
        #[arg(long)]
        output_diff: PathBuf,
        #[arg(long)]
        output_evidence: PathBuf,
    },
    #[cfg(feature = "boring-backend")]
    CaptureH1Diff {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        reference: PathBuf,
        #[arg(long, default_value_t = 15_000)]
        timeout_ms: u64,
        #[arg(long)]
        output_capture: PathBuf,
        #[arg(long)]
        output_diff: PathBuf,
        #[arg(long)]
        output_evidence: PathBuf,
    },
    #[cfg(feature = "boring-backend")]
    CaptureH1Cancellation {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long, default_value_t = 15_000)]
        timeout_ms: u64,
        #[arg(long)]
        output_evidence: PathBuf,
    },
    #[cfg(feature = "boring-backend")]
    FreshStabilityMatrix {
        #[arg(long)]
        official_plan: PathBuf,
        #[arg(long)]
        controlled_plan: PathBuf,
        #[arg(long)]
        reference_directory: PathBuf,
        #[arg(long, default_value_t = 20)]
        iterations: usize,
        #[arg(long)]
        reference_collection_attempts: Option<usize>,
        #[arg(long)]
        ca_bundle: Option<PathBuf>,
        #[arg(long, default_value_t = 10_000)]
        connect_timeout_ms: u64,
        #[arg(long, default_value_t = 15_000)]
        handshake_timeout_ms: u64,
        #[arg(long, default_value_t = 15_000)]
        h1_timeout_ms: u64,
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long)]
        output_report: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AuditModeArg {
    Probe,
    Canary,
}

impl From<AuditModeArg> for AuditMode {
    fn from(value: AuditModeArg) -> Self {
        match value {
            AuditModeArg::Probe => Self::Probe,
            AuditModeArg::Canary => Self::Canary,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TargetKindArg {
    AnthropicOfficial,
    ControlledCapture,
}

impl From<TargetKindArg> for TargetKind {
    fn from(value: TargetKindArg) -> Self {
        match value {
            TargetKindArg::AnthropicOfficial => Self::AnthropicOfficial,
            TargetKindArg::ControlledCapture => Self::ControlledCapture,
        }
    }
}

// Keeping command dispatch together makes the CLI's artifact flow visible in
// one place; protocol and validation logic remain in dedicated crates.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Validate { input } => {
            let batch = read_batch(&input)?;
            batch.validate().context("validate capture batch")?;
            println!(
                "valid capture: artifact_id={}, run_id={}, events={}",
                batch.capture_artifact_id,
                batch.capture_run_id,
                batch.events.len()
            );
        }
        Command::Normalize { input, output } => {
            let batch = read_batch(&input)?;
            let normalized = normalize_capture(&batch).context("normalize capture batch")?;
            write_json(&output, &normalized)?;
            println!(
                "normalized capture: artifact_id={}, run_id={}, sha256={}, events={}",
                normalized.capture_artifact_id,
                normalized.capture_run_id,
                normalized.normalized_sha256,
                normalized.event_count()
            );
        }
        Command::Sample { output } => {
            let batch = sample_batch(CaptureLane::ReferenceControlledEndpoint, Uuid::new_v4());
            write_json(&output, &batch)?;
            println!(
                "synthetic sample created: artifact_id={}, run_id={}, events={}",
                batch.capture_artifact_id,
                batch.capture_run_id,
                batch.events.len()
            );
        }
        Command::SampleSet { directory } => {
            write_sample_set(&directory)?;
            println!(
                "synthetic reference/replay sample set created: {}",
                directory.display()
            );
        }
        Command::Manifest {
            passive_tls,
            controlled_http2,
            output,
        } => {
            let passive = read_json::<NormalizedCapture>(&passive_tls)?;
            let controlled = read_json::<NormalizedCapture>(&controlled_http2)?;
            let manifest = build_manifest(&passive, &controlled)?;
            write_json(&output, &manifest)?;
            println!(
                "verified manifest: manifest_id={}, run_id={}",
                manifest.manifest_id, manifest.capture_run_id
            );
        }
        Command::Diff {
            reference,
            candidate,
            policy,
            output,
        } => {
            let reference = read_json::<NormalizedCapture>(&reference)?;
            let candidate = read_json::<NormalizedCapture>(&candidate)?;
            let policy = policy
                .as_ref()
                .map(read_json::<DiffPolicy>)
                .transpose()?
                .unwrap_or_default();
            let report = compare_captures(&reference, &candidate, &policy)
                .context("compare normalized captures")?;
            write_json(&output, &report)?;
            println!(
                "wire diff: decision={:?}, match={:?}, differences={}, report_id={}",
                report.decision,
                report.match_level,
                report.summary.total_differences,
                report.report_id
            );
            if report.decision != DiffDecision::Pass {
                bail!(
                    "wire diff gate ended with {:?}; inspect {}",
                    report.decision,
                    output.display()
                );
            }
        }
        Command::Bundle {
            manifest,
            passive_tls,
            controlled_http2,
            archetype_id,
            bundle_version,
            output,
        } => {
            let manifest = read_json::<CaptureManifest>(&manifest)?;
            let passive = read_json::<NormalizedCapture>(&passive_tls)?;
            let controlled = read_json::<NormalizedCapture>(&controlled_http2)?;
            let archetype_id =
                archetype_id.unwrap_or_else(|| default_archetype_id(&manifest.environment));
            let options = BundleCompilerOptions::production_defaults(archetype_id, bundle_version);
            let bundle = compile_bundle(&manifest, &passive, &controlled, &options)
                .context("compile Archetype Bundle candidate")?;
            write_json(&output, &bundle)?;
            println!(
                "bundle candidate: archetype_id={}, version={}, sha256={}",
                bundle.archetype_id, bundle.bundle_version, bundle.bundle_sha256
            );
        }
        Command::VerifyBundle { input } => {
            let bundle = read_transport_bundle(&input)?;
            verify_bundle(&bundle).context("verify Archetype Bundle candidate")?;
            println!(
                "valid bundle: archetype_id={}, version={}, sha256={}",
                bundle.archetype_id, bundle.bundle_version, bundle.bundle_sha256
            );
        }
        Command::AuditBundle {
            input,
            mode,
            probe_plan,
            tls_evidence,
            cancellation_evidence,
            output,
        } => {
            let bundle = read_transport_bundle(&input)?;
            let backend = BackendDescriptor::upstream_boring_h2();
            let mode = AuditMode::from(mode);
            let audit = if tls_evidence.is_empty() && cancellation_evidence.is_empty() {
                audit_bundle(&bundle, &backend, mode)
            } else {
                ensure!(
                    mode == AuditMode::Canary,
                    "TLS evidence is consumed only by Canary audits"
                );
                let probe_plans = probe_plan
                    .iter()
                    .map(read_replay_plan)
                    .collect::<Result<Vec<_>>>()?;
                let tls_evidence = tls_evidence
                    .iter()
                    .map(read_json::<CanaryTlsEvidence>)
                    .collect::<Result<Vec<_>>>()?;
                let cancellation_evidence = cancellation_evidence
                    .iter()
                    .map(read_json::<CanaryCancellationEvidence>)
                    .collect::<Result<Vec<_>>>()?;
                audit_bundle_with_canary_evidence(
                    &bundle,
                    &backend,
                    mode,
                    &probe_plans,
                    &engine_build_id()?,
                    &tls_evidence,
                    &cancellation_evidence,
                )
            }
            .context("audit transport backend capabilities")?;
            write_json(&output, &audit)?;
            println!(
                "transport capability audit: decision={:?}, blockers={}, backend={}",
                audit.decision, audit.blocker_count, audit.backend.backend_id
            );
        }
        Command::Plan {
            bundle,
            target_kind,
            authority,
            port,
            mode,
            output,
        } => {
            let bundle = read_transport_bundle(&bundle)?;
            let plan = build_replay_plan(
                &bundle,
                &BackendDescriptor::upstream_boring_h2(),
                TransportTarget {
                    kind: target_kind.into(),
                    authority,
                    port,
                },
                mode.into(),
            )
            .context("build fail-closed transport replay plan")?;
            if matches!(plan.application, ApplicationReplayPlan::Http2(_)) {
                h2_backend::build_client(&plan).context("configure h2 replay backend")?;
            }
            write_json(&output, &plan)?;
            println!(
                "transport replay plan: target={}:{}, decision={:?}, sha256={}",
                plan.target.authority, plan.target.port, plan.audit.decision, plan.plan_sha256
            );
        }
        #[cfg(feature = "boring-backend")]
        Command::ProbeTls {
            plan,
            connect_timeout_ms,
            handshake_timeout_ms,
            required_alpn,
            ca_bundle,
            dial_host,
            dial_port,
            output,
        } => {
            let plan = read_replay_plan(&plan)?;
            let trust_roots_pem = ca_bundle
                .as_ref()
                .map(|path| {
                    fs::read(path).with_context(|| format!("read CA bundle {}", path.display()))
                })
                .transpose()?;
            let connection = connect_direct(
                &plan,
                &DirectTlsPolicy {
                    connect_timeout_ms,
                    handshake_timeout_ms,
                    required_alpn: Some(required_alpn),
                    trust_roots_pem,
                    dial_override: dial_endpoint(dial_host, dial_port)?,
                    proxy: None,
                },
            )
            .await
            .context("run certificate-verified direct TLS probe")?;
            let observation = connection.observation.clone();
            drop(connection);
            write_json(&output, &observation)?;
            println!(
                "TLS probe: target={}:{}, version={}, alpn={}, cipher={}, certificate_sha256={}",
                observation.authority,
                observation.port,
                observation.tls_version,
                observation.negotiated_alpn,
                observation.cipher,
                observation.certificate_sha256
            );
        }
        #[cfg(feature = "boring-backend")]
        Command::ProbeH2 {
            plan,
            connect_timeout_ms,
            tls_handshake_timeout_ms,
            h2_handshake_timeout_ms,
            ca_bundle,
            dial_host,
            dial_port,
            output,
        } => {
            let plan = read_replay_plan(&plan)?;
            let trust_roots_pem = read_optional_file(ca_bundle.as_ref(), "CA bundle")?;
            let observation = probe_h2(
                &plan,
                &H2ProbePolicy {
                    tls: DirectTlsPolicy {
                        connect_timeout_ms,
                        handshake_timeout_ms: tls_handshake_timeout_ms,
                        required_alpn: Some("h2".to_owned()),
                        trust_roots_pem,
                        dial_override: dial_endpoint(dial_host, dial_port)?,
                        proxy: None,
                    },
                    handshake_timeout_ms: h2_handshake_timeout_ms,
                },
            )
            .await
            .context("run certificate-verified H2 preface probe")?;
            write_json(&output, &observation)?;
            println!(
                "H2 probe: target={}:{}, TLS={}, cipher={}, SETTINGS={}, h2_handshake_us={}",
                observation.tls.authority,
                observation.tls.port,
                observation.tls.tls_version,
                observation.tls.cipher,
                observation.configured_settings.len(),
                observation.handshake_elapsed_micros
            );
        }
        #[cfg(feature = "boring-backend")]
        Command::CaptureTlsDiff {
            plan,
            reference,
            ca_bundle,
            connect_timeout_ms,
            handshake_timeout_ms,
            output_capture,
            output_diff,
            output_evidence,
            output_canary_evidence,
        } => {
            let plan = read_replay_plan(&plan)?;
            ensure!(
                plan.target.kind == TargetKind::AnthropicOfficial,
                "TLS official diff requires an Anthropic official Replay Plan"
            );
            let reference = read_json::<NormalizedCapture>(&reference)?;
            ensure!(
                reference.lane == CaptureLane::ReferenceOfficialTls,
                "TLS official diff requires reference_official_tls evidence"
            );
            let trust_roots_pem = read_optional_file(ca_bundle.as_ref(), "CA bundle")?;
            let (candidate, observation) = capture_tls_candidate(
                &plan,
                &reference,
                trust_roots_pem,
                connect_timeout_ms,
                handshake_timeout_ms,
            )
            .await?;
            write_json(&output_capture, &candidate)?;
            write_json(&output_evidence, &observation)?;
            let policy = DiffPolicy {
                allowed_differences: vec![AllowedDifference {
                    path: "/events/1/timing_bucket".to_owned(),
                    rationale: "same-target TLS byte replay excludes local CONNECT setup latency"
                        .to_owned(),
                    evidence_ref: "capture-method:connect-tls-tap".to_owned(),
                }],
                ..DiffPolicy::default()
            };
            let report = compare_captures(&reference, &candidate, &policy)
                .context("compare real TLS tap with reference evidence")?;
            write_json(&output_diff, &report)?;
            println!(
                "TLS tap diff: decision={:?}, match={:?}, findings={}, TLS={}, cipher={}",
                report.decision,
                report.match_level,
                report.summary.total_differences,
                observation.tls_version,
                observation.cipher
            );
            if report.decision != DiffDecision::Pass {
                bail!(
                    "TLS tap diff ended with {:?}; inspect {}",
                    report.decision,
                    output_diff.display()
                );
            }
            let canary_evidence = build_canary_tls_evidence(
                &plan,
                &engine_build_id()?,
                &reference,
                &candidate,
                &report,
            )
            .context("build integrity-bound Canary TLS evidence")?;
            write_json(&output_canary_evidence, &canary_evidence)?;
            println!(
                "Canary TLS evidence: sha256={}, controls={}",
                canary_evidence.evidence_sha256,
                canary_evidence.verified_controls.len()
            );
        }
        #[cfg(feature = "boring-backend")]
        Command::CaptureH2Diff {
            plan,
            reference,
            timeout_ms,
            output_capture,
            output_diff,
            output_evidence,
        } => {
            let plan = read_replay_plan(&plan)?;
            ensure!(
                plan.target.kind == TargetKind::ControlledCapture,
                "controlled H2 diff requires a controlled-capture Replay Plan"
            );
            let reference = read_json::<NormalizedCapture>(&reference)?;
            ensure!(
                reference.lane == CaptureLane::ReferenceControlledEndpoint,
                "controlled H2 diff requires reference_controlled_endpoint evidence"
            );
            let (candidate, evidence) = capture_h2_candidate(&plan, &reference, timeout_ms).await?;
            write_json(&output_capture, &candidate)?;
            write_json(&output_evidence, &evidence)?;
            let report = compare_captures(&reference, &candidate, &DiffPolicy::default())
                .context("compare controlled H2 capture with reference evidence")?;
            write_json(&output_diff, &report)?;
            println!(
                "controlled H2 diff: decision={:?}, findings={}, settings_exact={}, frames={}",
                report.decision,
                report.summary.total_differences,
                evidence.settings_exact,
                evidence.frame_count
            );
            if report.decision != DiffDecision::Pass {
                bail!(
                    "controlled H2 diff ended with {:?}; inspect {}",
                    report.decision,
                    output_diff.display()
                );
            }
        }
        #[cfg(feature = "boring-backend")]
        Command::CaptureH1Diff {
            plan,
            reference,
            timeout_ms,
            output_capture,
            output_diff,
            output_evidence,
        } => {
            let plan = read_replay_plan(&plan)?;
            ensure!(
                plan.target.kind == TargetKind::ControlledCapture,
                "controlled H1 diff requires a controlled-capture Replay Plan"
            );
            let reference = read_json::<NormalizedCapture>(&reference)?;
            ensure!(
                reference.lane == CaptureLane::ReferenceControlledEndpoint,
                "controlled H1 diff requires reference_controlled_endpoint evidence"
            );
            let (candidate, evidence) = capture_h1_candidate(&plan, &reference, timeout_ms).await?;
            ensure!(
                evidence.header_order_exact && evidence.body_bytes_exact,
                "controlled H1 replay violated Bundle Header order or body length"
            );
            write_json(&output_capture, &candidate)?;
            write_json(&output_evidence, &evidence)?;
            let report = compare_captures(&reference, &candidate, &h1_diff_policy(&reference))
                .context("compare controlled H1 capture with reference evidence")?;
            write_json(&output_diff, &report)?;
            println!(
                "controlled H1 diff: decision={:?}, findings={}, headers_exact={}, body_exact={}",
                report.decision,
                report.summary.total_differences,
                evidence.header_order_exact,
                evidence.body_bytes_exact
            );
            if report.decision != DiffDecision::Pass {
                bail!(
                    "controlled H1 diff ended with {:?}; inspect {}",
                    report.decision,
                    output_diff.display()
                );
            }
        }
        #[cfg(feature = "boring-backend")]
        Command::CaptureH1Cancellation {
            plan,
            timeout_ms,
            output_evidence,
        } => {
            let plan = read_replay_plan(&plan)?;
            ensure!(
                plan.target.kind == TargetKind::ControlledCapture,
                "H1 cancellation capture requires a controlled-capture Replay Plan"
            );
            let evidence = capture_h1_cancellation_evidence(&plan, timeout_ms).await?;
            write_json(&output_evidence, &evidence)?;
            println!(
                "controlled H1 cancellation: action={:?}, peer_close={}, sha256={}",
                evidence.protocol_action, evidence.peer_close_observed, evidence.evidence_sha256
            );
        }
        #[cfg(feature = "boring-backend")]
        Command::FreshStabilityMatrix {
            official_plan,
            controlled_plan,
            reference_directory,
            iterations,
            reference_collection_attempts,
            ca_bundle,
            connect_timeout_ms,
            handshake_timeout_ms,
            h1_timeout_ms,
            output_directory,
            output_report,
        } => {
            let official_plan = read_replay_plan(&official_plan)?;
            let controlled_plan = read_replay_plan(&controlled_plan)?;
            let trust_roots_pem = read_optional_file(ca_bundle.as_ref(), "CA bundle")?;
            let report = run_fresh_stability_matrix(
                &official_plan,
                &controlled_plan,
                FreshStabilityOptions {
                    reference_directory: &reference_directory,
                    iterations,
                    reference_collection_attempts: reference_collection_attempts
                        .unwrap_or(iterations),
                    trust_roots_pem,
                    connect_timeout_ms,
                    handshake_timeout_ms,
                    h1_timeout_ms,
                    output_directory: &output_directory,
                },
            )
            .await?;
            write_json(&output_report, &report)?;
            println!(
                "fresh stability matrix: decision={:?}, runs={}, passed={}, sha256={}",
                report.decision, report.iterations, report.passed_runs, report.report_sha256
            );
            if report.decision != DiffDecision::Pass {
                bail!(
                    "fresh stability matrix ended with {:?}; inspect {}",
                    report.decision,
                    output_report.display()
                );
            }
        }
    }
    Ok(())
}

#[cfg(feature = "boring-backend")]
struct FreshStabilityOptions<'a> {
    reference_directory: &'a Path,
    iterations: usize,
    reference_collection_attempts: usize,
    trust_roots_pem: Option<Vec<u8>>,
    connect_timeout_ms: u64,
    handshake_timeout_ms: u64,
    h1_timeout_ms: u64,
    output_directory: &'a Path,
}

#[cfg(feature = "boring-backend")]
#[derive(Debug, serde::Serialize)]
struct FreshStabilityMatrixReport {
    schema_version: u32,
    matrix_id: Uuid,
    bundle_sha256: String,
    official_plan_sha256: String,
    controlled_plan_sha256: String,
    engine_build_id: String,
    reference_directory: String,
    output_directory: String,
    iterations: usize,
    reference_collection_attempts: usize,
    reference_collection_failures: usize,
    passed_runs: usize,
    decision: DiffDecision,
    runs: Vec<FreshStabilityRun>,
    report_sha256: String,
}

#[cfg(feature = "boring-backend")]
#[derive(Debug, serde::Serialize)]
struct FreshStabilityRun {
    iteration: usize,
    capture_run_id: Uuid,
    manifest_id: Uuid,
    official_reference_sha256: String,
    controlled_reference_sha256: String,
    official_reference_stability: WireDiffReport,
    controlled_reference_stability: WireDiffReport,
    official_replay: WireDiffReport,
    controlled_h1_replay: WireDiffReport,
    h1_header_order_exact: bool,
    h1_body_bytes_exact: bool,
    decision: DiffDecision,
    official_replay_capture: String,
    official_replay_diff: String,
    official_handshake_evidence: String,
    controlled_replay_capture: String,
    controlled_replay_diff: String,
    controlled_h1_evidence: String,
}

#[cfg(feature = "boring-backend")]
#[allow(clippy::too_many_lines)]
async fn run_fresh_stability_matrix(
    official_plan: &ReplayPlan,
    controlled_plan: &ReplayPlan,
    options: FreshStabilityOptions<'_>,
) -> Result<FreshStabilityMatrixReport> {
    ensure!(
        options.iterations >= 20,
        "fresh stability matrix requires at least 20 iterations"
    );
    ensure!(
        options.reference_collection_attempts >= options.iterations,
        "reference collection attempts must cover every successful iteration"
    );
    ensure!(
        official_plan.target.kind == TargetKind::AnthropicOfficial,
        "fresh stability matrix official plan must target Anthropic"
    );
    ensure!(
        controlled_plan.target.kind == TargetKind::ControlledCapture,
        "fresh stability matrix controlled plan must target the capture endpoint"
    );
    ensure!(
        matches!(controlled_plan.application, ApplicationReplayPlan::Http1(_)),
        "fresh stability matrix controlled plan must use HTTP/1.1"
    );
    ensure!(
        official_plan.bundle_sha256 == controlled_plan.bundle_sha256,
        "fresh stability matrix plans must bind the same Bundle"
    );
    ensure!(
        official_plan.backend_id == controlled_plan.backend_id,
        "fresh stability matrix plans must bind the same backend"
    );
    ensure!(
        options.connect_timeout_ms > 0
            && options.handshake_timeout_ms > 0
            && options.h1_timeout_ms > 0,
        "fresh stability matrix timeouts must be positive"
    );
    ensure!(
        !options.output_directory.exists(),
        "fresh stability output directory already exists: {}",
        options.output_directory.display()
    );
    fs::create_dir_all(options.output_directory).with_context(|| {
        format!(
            "create fresh stability output directory {}",
            options.output_directory.display()
        )
    })?;

    let official_baseline = read_matrix_reference(
        options.reference_directory,
        1,
        "official",
        &CaptureLane::ReferenceOfficialTls,
    )?;
    let controlled_baseline = read_matrix_reference(
        options.reference_directory,
        1,
        "controlled",
        &CaptureLane::ReferenceControlledEndpoint,
    )?;
    let engine_build_id = engine_build_id()?;
    let mut runs = Vec::with_capacity(options.iterations);

    for iteration in 1..=options.iterations {
        let official = read_matrix_reference(
            options.reference_directory,
            iteration,
            "official",
            &CaptureLane::ReferenceOfficialTls,
        )?;
        let controlled = read_matrix_reference(
            options.reference_directory,
            iteration,
            "controlled",
            &CaptureLane::ReferenceControlledEndpoint,
        )?;
        let manifest = build_manifest(&official, &controlled)
            .with_context(|| format!("verify paired references for iteration {iteration}"))?;

        let official_reference_stability = compare_reference_stability(
            &official_baseline,
            &official,
            &reference_stability_policy(&official_baseline),
        )
        .with_context(|| {
            format!("compare official reference stability at iteration {iteration}")
        })?;
        let controlled_reference_stability = compare_reference_stability(
            &controlled_baseline,
            &controlled,
            &reference_stability_policy(&controlled_baseline),
        )
        .with_context(|| {
            format!("compare controlled reference stability at iteration {iteration}")
        })?;

        let prefix = format!("{iteration:02}");
        let official_replay_capture = options
            .output_directory
            .join(format!("{prefix}-tls-replay.normalized.json"));
        let official_replay_diff = options
            .output_directory
            .join(format!("{prefix}-tls-diff.json"));
        let official_handshake_evidence = options
            .output_directory
            .join(format!("{prefix}-tls-handshake.json"));
        let controlled_replay_capture = options
            .output_directory
            .join(format!("{prefix}-h1-replay.normalized.json"));
        let controlled_replay_diff = options
            .output_directory
            .join(format!("{prefix}-h1-diff.json"));
        let controlled_h1_evidence = options
            .output_directory
            .join(format!("{prefix}-h1-control.json"));

        let (tls_candidate, tls_observation) = capture_tls_candidate(
            official_plan,
            &official,
            options.trust_roots_pem.clone(),
            options.connect_timeout_ms,
            options.handshake_timeout_ms,
        )
        .await
        .with_context(|| format!("capture official TLS replay at iteration {iteration}"))?;
        let official_replay = compare_captures(&official, &tls_candidate, &tls_diff_policy())
            .with_context(|| format!("compare official TLS replay at iteration {iteration}"))?;
        write_json(&official_replay_capture, &tls_candidate)?;
        write_json(&official_replay_diff, &official_replay)?;
        write_json(&official_handshake_evidence, &tls_observation)?;

        let (h1_candidate, h1_evidence) =
            capture_h1_candidate(controlled_plan, &controlled, options.h1_timeout_ms)
                .await
                .with_context(|| {
                    format!("capture controlled H1 replay at iteration {iteration}")
                })?;
        let controlled_h1_replay =
            compare_captures(&controlled, &h1_candidate, &h1_diff_policy(&controlled))
                .with_context(|| {
                    format!("compare controlled H1 replay at iteration {iteration}")
                })?;
        write_json(&controlled_replay_capture, &h1_candidate)?;
        write_json(&controlled_replay_diff, &controlled_h1_replay)?;
        write_json(&controlled_h1_evidence, &h1_evidence)?;

        let decisions = [
            official_reference_stability.decision,
            controlled_reference_stability.decision,
            official_replay.decision,
            controlled_h1_replay.decision,
        ];
        let decision = combined_decision(
            &decisions,
            h1_evidence.header_order_exact && h1_evidence.body_bytes_exact,
        );
        runs.push(FreshStabilityRun {
            iteration,
            capture_run_id: official.capture_run_id,
            manifest_id: manifest.manifest_id,
            official_reference_sha256: official.normalized_sha256,
            controlled_reference_sha256: controlled.normalized_sha256,
            official_reference_stability,
            controlled_reference_stability,
            official_replay,
            controlled_h1_replay,
            h1_header_order_exact: h1_evidence.header_order_exact,
            h1_body_bytes_exact: h1_evidence.body_bytes_exact,
            decision,
            official_replay_capture: official_replay_capture.display().to_string(),
            official_replay_diff: official_replay_diff.display().to_string(),
            official_handshake_evidence: official_handshake_evidence.display().to_string(),
            controlled_replay_capture: controlled_replay_capture.display().to_string(),
            controlled_replay_diff: controlled_replay_diff.display().to_string(),
            controlled_h1_evidence: controlled_h1_evidence.display().to_string(),
        });
        println!("fresh stability iteration {iteration}: decision={decision:?}");
    }

    let passed_runs = runs
        .iter()
        .filter(|run| run.decision == DiffDecision::Pass)
        .count();
    let decisions = runs.iter().map(|run| run.decision).collect::<Vec<_>>();
    let decision = combined_decision(&decisions, true);
    let mut report = FreshStabilityMatrixReport {
        schema_version: FRESH_STABILITY_MATRIX_SCHEMA_VERSION,
        matrix_id: Uuid::new_v4(),
        bundle_sha256: official_plan.bundle_sha256.clone(),
        official_plan_sha256: official_plan.plan_sha256.clone(),
        controlled_plan_sha256: controlled_plan.plan_sha256.clone(),
        engine_build_id,
        reference_directory: options.reference_directory.display().to_string(),
        output_directory: options.output_directory.display().to_string(),
        iterations: options.iterations,
        reference_collection_attempts: options.reference_collection_attempts,
        reference_collection_failures: options
            .reference_collection_attempts
            .saturating_sub(options.iterations),
        passed_runs,
        decision,
        runs,
        report_sha256: String::new(),
    };
    report.report_sha256 = matrix_report_sha256(&report)?;
    Ok(report)
}

#[cfg(feature = "boring-backend")]
fn read_matrix_reference(
    directory: &Path,
    iteration: usize,
    kind: &str,
    expected_lane: &CaptureLane,
) -> Result<NormalizedCapture> {
    let path = directory.join(format!("{iteration:02}-{kind}.normalized.json"));
    let reference = read_json::<NormalizedCapture>(&path)?;
    verify_normalized_capture(&reference)
        .with_context(|| format!("verify matrix reference {}", path.display()))?;
    ensure!(
        &reference.lane == expected_lane,
        "matrix reference {} has the wrong lane",
        path.display()
    );
    Ok(reference)
}

#[cfg(feature = "boring-backend")]
fn compare_reference_stability(
    baseline: &NormalizedCapture,
    current: &NormalizedCapture,
    policy: &DiffPolicy,
) -> Result<WireDiffReport> {
    let mut candidate = current.clone();
    candidate.lane = match baseline.lane {
        CaptureLane::ReferenceOfficialTls => CaptureLane::ReplayOfficialTls,
        CaptureLane::ReferenceControlledEndpoint => CaptureLane::ReplayControlledEndpoint,
        _ => bail!("reference stability baseline must use a reference lane"),
    };
    candidate.normalized_sha256 = recompute_normalized_sha256(&candidate)
        .context("recompute reference stability candidate digest")?;
    compare_captures(baseline, &candidate, policy).context("compare reference stability")
}

#[cfg(feature = "boring-backend")]
fn reference_stability_policy(reference: &NormalizedCapture) -> DiffPolicy {
    let allowed_differences = reference
        .events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| match event {
            wire_normalizer::NormalizedEvent::ConnectionLifecycle { .. } => {
                Some(AllowedDifference {
                    path: format!("/events/{index}/timing_bucket"),
                    rationale: "fresh connections may cross timing buckets".to_owned(),
                    evidence_ref: "matrix-policy:fresh-reference-timing".to_owned(),
                })
            }
            wire_normalizer::NormalizedEvent::SseChunk { .. } => Some(AllowedDifference {
                path: format!("/events/{index}/byte_len"),
                rationale:
                    "response Body/SSE remains transparent and is outside outbound request drift"
                        .to_owned(),
                evidence_ref: "product-decision:transparent-response-body-sse".to_owned(),
            }),
            _ => None,
        })
        .collect();
    DiffPolicy {
        timing_bucket_tolerance: 7,
        max_findings: 2_000,
        allowed_differences,
    }
}

#[cfg(feature = "boring-backend")]
fn tls_diff_policy() -> DiffPolicy {
    DiffPolicy {
        allowed_differences: vec![AllowedDifference {
            path: "/events/1/timing_bucket".to_owned(),
            rationale: "same-target TLS byte replay excludes local CONNECT setup latency"
                .to_owned(),
            evidence_ref: "capture-method:connect-tls-tap".to_owned(),
        }],
        ..DiffPolicy::default()
    }
}

#[cfg(feature = "boring-backend")]
fn combined_decision(decisions: &[DiffDecision], controls_exact: bool) -> DiffDecision {
    if !controls_exact || decisions.contains(&DiffDecision::Fail) {
        DiffDecision::Fail
    } else if decisions
        .iter()
        .all(|decision| *decision == DiffDecision::Pass)
    {
        DiffDecision::Pass
    } else {
        DiffDecision::Inconclusive
    }
}

#[cfg(feature = "boring-backend")]
fn matrix_report_sha256(report: &FreshStabilityMatrixReport) -> Result<String> {
    let bytes =
        serde_json::to_vec(report).context("serialize fresh stability report for digest")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(feature = "boring-backend")]
fn h1_diff_policy(reference: &NormalizedCapture) -> DiffPolicy {
    let allowed_differences = reference
        .events
        .iter()
        .enumerate()
        .filter(|(_, event)| matches!(event, wire_normalizer::NormalizedEvent::SseChunk { .. }))
        .map(|(index, _)| AllowedDifference {
            path: format!("/events/{index}/byte_len"),
            rationale: "response Body/SSE is transparent; this gate targets the outbound HTTP/1.1 request wire shape".to_owned(),
            evidence_ref: "product-decision:transparent-response-body-sse".to_owned(),
        })
        .collect();
    DiffPolicy {
        timing_bucket_tolerance: 7,
        max_findings: 2_000,
        allowed_differences,
    }
}

fn read_batch(path: &PathBuf) -> Result<CaptureBatch> {
    read_json(path)
}

fn read_transport_bundle(path: &PathBuf) -> Result<CandidateArchetypeBundle> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    load_bundle(&bytes).with_context(|| format!("load verified Bundle {}", path.display()))
}

fn read_replay_plan(path: &PathBuf) -> Result<ReplayPlan> {
    let plan = read_json::<ReplayPlan>(path)?;
    verify_replay_plan(&plan).with_context(|| format!("verify Replay Plan {}", path.display()))?;
    Ok(plan)
}

fn engine_build_id() -> Result<String> {
    let executable = std::env::current_exe().context("resolve current Transport Engine binary")?;
    let bytes = fs::read(&executable)
        .with_context(|| format!("read Transport Engine binary {}", executable.display()))?;
    Ok(format!(
        "spike-cli/{}+sha256:{}",
        env!("CARGO_PKG_VERSION"),
        hex::encode(Sha256::digest(bytes))
    ))
}

#[cfg(feature = "boring-backend")]
fn read_optional_file(path: Option<&PathBuf>, label: &str) -> Result<Option<Vec<u8>>> {
    path.map(|path| fs::read(path).with_context(|| format!("read {label} {}", path.display())))
        .transpose()
}

#[cfg(feature = "boring-backend")]
fn dial_endpoint(host: Option<String>, port: Option<u16>) -> Result<Option<DialEndpoint>> {
    match (host, port) {
        (None, None) => Ok(None),
        (Some(host), Some(port)) => Ok(Some(DialEndpoint { host, port })),
        _ => bail!("dial host and port must be provided together"),
    }
}

#[cfg(feature = "boring-backend")]
async fn capture_tls_candidate(
    plan: &ReplayPlan,
    reference: &NormalizedCapture,
    trust_roots_pem: Option<Vec<u8>>,
    connect_timeout_ms: u64,
    handshake_timeout_ms: u64,
) -> Result<(
    NormalizedCapture,
    transport_core::boring_backend::TlsHandshakeObservation,
)> {
    let tap = ConnectTlsTapListener::bind(ConnectTlsTapConfig {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        allowed_host: plan.target.authority.clone(),
        allowed_port: plan.target.port,
        max_connect_header_bytes: 16 * 1024,
        max_capture_bytes: 256 * 1024,
        session_timeout: Duration::from_millis(
            connect_timeout_ms
                .saturating_add(handshake_timeout_ms)
                .saturating_add(5_000),
        ),
        upstream_http_proxy: None,
    })
    .await
    .context("bind one-shot TLS CONNECT pass-through tap")?;
    let tap_addr = tap.local_addr().context("read TLS tap address")?;
    let tap_task = tokio::spawn(tap.capture_one());
    let connection = connect_direct(
        plan,
        &DirectTlsPolicy {
            connect_timeout_ms,
            handshake_timeout_ms,
            required_alpn: required_alpn_for_tls_replay(&plan.tls.alpn_wire)?,
            trust_roots_pem,
            dial_override: None,
            proxy: Some(ProxyRoute::HttpConnect {
                endpoint: DialEndpoint {
                    host: tap_addr.ip().to_string(),
                    port: tap_addr.port(),
                },
                credentials: None,
            }),
        },
    )
    .await
    .context("connect BoringSSL probe through TLS tap")?;
    let observation = connection.observation.clone();
    drop(connection);
    let captured = tap_task
        .await
        .context("join TLS tap task")?
        .context("capture TLS pass-through bytes")?;
    let hello = parse_client_hello(&captured).context("parse captured ClientHello")?;
    let batch = raw_tls_candidate(reference, plan, &hello, &observation)?;
    let normalized = normalize_capture(&batch).context("normalize TLS tap candidate")?;
    Ok((normalized, observation))
}

#[cfg(feature = "boring-backend")]
fn required_alpn_for_tls_replay(alpn_wire: &[u8]) -> Result<Option<String>> {
    if alpn_wire.is_empty() {
        return Ok(None);
    }

    let mut protocols = vec![];
    let mut offset = 0;
    while offset < alpn_wire.len() {
        let length = usize::from(alpn_wire[offset]);
        offset += 1;
        ensure!(length > 0, "Replay Plan contains an empty ALPN protocol");
        let end = offset
            .checked_add(length)
            .context("Replay Plan ALPN length overflow")?;
        ensure!(
            end <= alpn_wire.len(),
            "Replay Plan contains a truncated ALPN protocol"
        );
        protocols.push(
            std::str::from_utf8(&alpn_wire[offset..end])
                .context("Replay Plan ALPN protocol is not UTF-8")?
                .to_owned(),
        );
        offset = end;
    }

    Ok(protocols.into_iter().next())
}

#[cfg(feature = "boring-backend")]
fn raw_tls_candidate(
    reference: &NormalizedCapture,
    plan: &ReplayPlan,
    hello: &tls_tap::ParsedClientHello,
    observation: &transport_core::boring_backend::TlsHandshakeObservation,
) -> Result<CaptureBatch> {
    let connection_id = "tls-tap-connection".to_owned();
    let batch = CaptureBatch {
        schema_version: CAPTURE_SCHEMA_VERSION,
        capture_artifact_id: Uuid::new_v4(),
        capture_run_id: Uuid::new_v4(),
        lane: CaptureLane::ReplayOfficialTls,
        observed_at: observed_now(),
        environment: EnvironmentDescriptor {
            os_name: reference.environment.os_name.clone(),
            os_version: reference.environment.os_version.clone(),
            os_build: reference.environment.os_build.clone(),
            arch: reference.environment.arch.clone(),
            kernel: reference.environment.kernel.clone(),
            claude_code_version: reference.environment.claude_code_version.clone(),
            runtime_name: reference.environment.runtime_name.clone(),
            runtime_version: reference.environment.runtime_version.clone(),
            binary_sha256: reference.environment.binary_sha256.clone(),
            labels: BTreeMap::new(),
        },
        target: TargetDescriptor {
            authority: format!("{}:{}", plan.target.authority, plan.target.port),
            official_anthropic: true,
        },
        network: NetworkDescriptor {
            path: NetworkPath::HttpConnect,
            dns_mode: DnsMode::Local,
            proxy_software: Some("spike-cli-connect-tls-tap".to_owned()),
            proxy_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        },
        scenario: ScenarioDescriptor {
            id: reference.scenario.id.clone(),
            fresh_connection: reference.scenario.fresh_connection,
            expected_protocol: reference.scenario.expected_protocol.clone(),
            concurrent_streams: reference.scenario.concurrent_streams,
            request_shape: reference.scenario.request_shape.clone(),
        },
        events: vec![
            CaptureEvent::ConnectionLifecycle {
                connection_id: connection_id.clone(),
                phase: ConnectionPhase::ProxyTunnelEstablished,
                offset_micros: 0,
                negotiated_protocol: None,
                resumed: None,
            },
            CaptureEvent::ConnectionLifecycle {
                connection_id: connection_id.clone(),
                phase: ConnectionPhase::TlsStarted,
                offset_micros: observation.connect_elapsed_micros,
                negotiated_protocol: None,
                resumed: None,
            },
            CaptureEvent::TlsClientHello {
                connection_id,
                record_version: hello.record_version,
                legacy_version: hello.legacy_version,
                cipher_suites: hello.cipher_suites.clone(),
                extensions: hello.extensions.clone(),
                alpn: hello.alpn.clone(),
                client_hello_len: hello.client_hello_len,
                record_lengths: hello.record_lengths.clone(),
            },
        ],
    };
    batch.validate().context("validate TLS tap CaptureBatch")?;
    Ok(batch)
}

#[cfg(feature = "boring-backend")]
fn observed_now() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("unix-ms:{millis}")
}

#[cfg(feature = "boring-backend")]
#[derive(Debug, serde::Serialize)]
struct H1ControlEvidence {
    expected_header_order: Vec<String>,
    observed_header_order: Vec<String>,
    header_order_exact: bool,
    expected_body_bytes: u32,
    observed_body_bytes: u32,
    body_bytes_exact: bool,
    response_status: u16,
    application_protocol: String,
    tls_negotiated_alpn: String,
    decrypted_client_bytes: usize,
}

#[cfg(feature = "boring-backend")]
async fn capture_h1_cancellation_evidence(
    plan: &ReplayPlan,
    timeout_ms: u64,
) -> Result<CanaryCancellationEvidence> {
    ensure!(
        timeout_ms > 0,
        "controlled H1 cancellation timeout must be positive"
    );
    let profile = plan.http1().context("require HTTP/1.1 Replay Plan")?;
    let path = synthetic_messages_path(profile.path_bytes)?;
    let body = synthetic_h1_body(profile.body_bytes)?;
    let headers = synthetic_h1_headers(plan, body.len())?;
    let authorization = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.clone())
        .context("HTTP/1.1 profile has no synthetic authorization Header")?;
    let timeout = Duration::from_millis(timeout_ms);
    let server = ControlledH2Server::bind_claude_messages_cancellation(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &plan.target.authority,
        timeout,
        4 * 1024 * 1024,
        authorization,
        4 * 1024 * 1024,
        timeout,
    )
    .await
    .context("bind controlled H1 cancellation endpoint")?;
    let server_addr = server
        .local_addr()
        .context("read controlled H1 cancellation address")?;
    let trust_roots_pem = server.ca_pem().to_vec();
    let capture_task = tokio::spawn(server.capture_one());
    let observation = probe_h1_cancellation_with_request(
        plan,
        &H1ProbePolicy {
            tls: DirectTlsPolicy {
                connect_timeout_ms: timeout_ms,
                handshake_timeout_ms: timeout_ms,
                required_alpn: (!plan.tls.alpn_wire.is_empty()).then(|| "http/1.1".to_owned()),
                trust_roots_pem: Some(trust_roots_pem),
                dial_override: Some(DialEndpoint {
                    host: server_addr.ip().to_string(),
                    port: server_addr.port(),
                }),
                proxy: None,
            },
            io_timeout_ms: timeout_ms,
            max_response_bytes: 4 * 1024 * 1024,
        },
        &H1ProbeRequest {
            path,
            headers,
            body,
        },
    )
    .await
    .context("run controlled H1 streaming cancellation")?;
    let captured = capture_task
        .await
        .context("join controlled H1 cancellation task")?
        .context("observe controlled H1 peer close")?;
    let peer = captured
        .cancellation
        .as_ref()
        .context("controlled endpoint produced no cancellation observation")?;
    ensure!(
        peer.stage == observation.stage
            && peer.protocol_action == observation.protocol_action
            && peer.peer_close_observed
            && !peer.other_streams_affected
            && peer.response_bytes_sent > 0,
        "controlled peer cancellation observation differs from Transport Engine action"
    );
    build_canary_cancellation_evidence(
        plan,
        &engine_build_id()?,
        &observation,
        peer.peer_close_observed,
    )
    .context("build integrity-bound Canary cancellation evidence")
}

#[cfg(feature = "boring-backend")]
async fn capture_h1_candidate(
    plan: &ReplayPlan,
    reference: &NormalizedCapture,
    timeout_ms: u64,
) -> Result<(NormalizedCapture, H1ControlEvidence)> {
    ensure!(timeout_ms > 0, "controlled H1 timeout must be positive");
    let profile = plan.http1().context("require HTTP/1.1 Replay Plan")?;
    let path = synthetic_messages_path(profile.path_bytes)?;
    let body = synthetic_h1_body(profile.body_bytes)?;
    let headers = synthetic_h1_headers(plan, body.len())?;
    let authorization = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.clone())
        .context("HTTP/1.1 profile has no synthetic authorization Header")?;
    let timeout = Duration::from_millis(timeout_ms);
    let server = ControlledH2Server::bind_claude_messages(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &plan.target.authority,
        timeout,
        4 * 1024 * 1024,
        authorization,
        4 * 1024 * 1024,
    )
    .await
    .context("bind controlled TLS/HTTP1 Capture Endpoint")?;
    let server_addr = server.local_addr().context("read controlled H1 address")?;
    let trust_roots_pem = server.ca_pem().to_vec();
    let capture_task = tokio::spawn(server.capture_one());
    let observation = probe_h1_with_request(
        plan,
        &H1ProbePolicy {
            tls: DirectTlsPolicy {
                connect_timeout_ms: timeout_ms,
                handshake_timeout_ms: timeout_ms,
                required_alpn: (!plan.tls.alpn_wire.is_empty()).then(|| "http/1.1".to_owned()),
                trust_roots_pem: Some(trust_roots_pem),
                dial_override: Some(DialEndpoint {
                    host: server_addr.ip().to_string(),
                    port: server_addr.port(),
                }),
                proxy: None,
            },
            io_timeout_ms: timeout_ms,
            max_response_bytes: 4 * 1024 * 1024,
        },
        &H1ProbeRequest {
            path,
            headers,
            body,
        },
    )
    .await
    .context("probe controlled TLS/HTTP1 Capture Endpoint")?;
    let captured = capture_task
        .await
        .context("join controlled H1 capture task")?
        .context("capture controlled H1 request")?;
    let request = captured
        .http1_request
        .as_ref()
        .context("controlled endpoint negotiated no HTTP/1.1 request")?;
    let expected_header_order = plan
        .headers
        .iter()
        .map(|rule| rule.wire_name.clone())
        .collect::<Vec<_>>();
    let observed_header_order = request
        .headers
        .iter()
        .map(|header| header.name.clone())
        .collect::<Vec<_>>();
    let evidence = H1ControlEvidence {
        header_order_exact: observed_header_order == expected_header_order,
        body_bytes_exact: request.body_bytes == profile.body_bytes,
        expected_header_order,
        observed_header_order,
        expected_body_bytes: profile.body_bytes,
        observed_body_bytes: request.body_bytes,
        response_status: observation.response_status,
        application_protocol: captured.negotiated_alpn.clone(),
        tls_negotiated_alpn: observation.tls.negotiated_alpn.clone(),
        decrypted_client_bytes: captured.decrypted_client_bytes,
    };
    let batch = raw_h1_candidate(
        reference,
        plan,
        request,
        &captured.response_sse_chunk_lengths,
        observation.tls.handshake_elapsed_micros,
    )?;
    let normalized = normalize_capture(&batch).context("normalize controlled H1 candidate")?;
    Ok((normalized, evidence))
}

#[cfg(feature = "boring-backend")]
fn synthetic_messages_path(path_bytes: usize) -> Result<String> {
    const BASE: &str = "/v1/messages";
    const BETA: &str = "/v1/messages?beta=true";
    if path_bytes == BASE.len() {
        return Ok(BASE.to_owned());
    }
    if path_bytes == BETA.len() {
        return Ok(BETA.to_owned());
    }
    ensure!(
        path_bytes >= BASE.len() + 3,
        "observed HTTP/1.1 path shape is too short"
    );
    let mut path = format!("{BASE}?x=");
    path.push_str(&"x".repeat(path_bytes - path.len()));
    Ok(path)
}

#[cfg(feature = "boring-backend")]
fn synthetic_h1_body(body_bytes: u32) -> Result<Vec<u8>> {
    let prefix = br#"{"model":"capture-model","max_tokens":1,"stream":true,"messages":[{"role":"user","content":"probe"}],"padding":""#;
    let suffix = br#""}"#;
    let body_bytes = usize::try_from(body_bytes).context("convert HTTP/1.1 body length")?;
    ensure!(
        body_bytes >= prefix.len() + suffix.len(),
        "observed HTTP/1.1 body is too short for synthetic Messages JSON"
    );
    let mut body = Vec::with_capacity(body_bytes);
    body.extend_from_slice(prefix);
    body.extend(std::iter::repeat_n(
        b'x',
        body_bytes - prefix.len() - suffix.len(),
    ));
    body.extend_from_slice(suffix);
    Ok(body)
}

#[cfg(feature = "boring-backend")]
fn synthetic_h1_headers(plan: &ReplayPlan, body_bytes: usize) -> Result<Vec<(String, String)>> {
    plan.headers
        .iter()
        .map(|rule| {
            let value = match rule.canonical_name.as_str() {
                "host" => plan.target.authority.clone(),
                "content-length" => body_bytes.to_string(),
                "connection" if rule.value_bytes == 10 => "keep-alive".to_owned(),
                "authorization" => synthetic_bearer(rule.value_bytes),
                "x-claude-code-session-id" if rule.value_bytes == 36 => {
                    "00000000-0000-4000-8000-000000000000".to_owned()
                }
                _ => match rule.mode {
                    HeaderValueMode::Exact => rule.exact_value.clone().with_context(|| {
                        format!(
                            "exact controlled header {} has no value",
                            rule.canonical_name
                        )
                    })?,
                    HeaderValueMode::Shape | HeaderValueMode::CredentialDerivedSecret => {
                        "x".repeat(rule.value_bytes)
                    }
                },
            };
            ensure!(
                value.len() == rule.value_bytes,
                "synthetic Header {} does not preserve observed value shape",
                rule.canonical_name
            );
            Ok((rule.wire_name.clone(), value))
        })
        .collect()
}

#[cfg(feature = "boring-backend")]
fn synthetic_bearer(bytes: usize) -> String {
    const PREFIX: &str = "Bearer ";
    if bytes >= PREFIX.len() {
        format!("{PREFIX}{}", "s".repeat(bytes - PREFIX.len()))
    } else {
        "s".repeat(bytes)
    }
}

#[cfg(feature = "boring-backend")]
fn raw_h1_candidate(
    reference: &NormalizedCapture,
    plan: &ReplayPlan,
    request: &Http1RequestObservation,
    response_sse_chunk_lengths: &[u32],
    tls_elapsed_micros: u64,
) -> Result<CaptureBatch> {
    let connection_id = "controlled-h1-connection".to_owned();
    let mut events = vec![
        CaptureEvent::ConnectionLifecycle {
            connection_id: connection_id.clone(),
            phase: ConnectionPhase::TlsEstablished,
            offset_micros: tls_elapsed_micros,
            negotiated_protocol: Some("http/1.1".to_owned()),
            resumed: None,
        },
        CaptureEvent::ConnectionLifecycle {
            connection_id: connection_id.clone(),
            phase: ConnectionPhase::Ready,
            offset_micros: tls_elapsed_micros,
            negotiated_protocol: Some("http/1.1".to_owned()),
            resumed: None,
        },
        CaptureEvent::Http1Request {
            connection_id: connection_id.clone(),
            method: request.method.clone(),
            path: request.path.clone(),
            version: request.version.clone(),
            headers: request.headers.clone(),
            body_bytes: request.body_bytes,
        },
    ];
    events.extend(
        response_sse_chunk_lengths
            .iter()
            .enumerate()
            .map(|(index, byte_len)| CaptureEvent::SseChunk {
                connection_id: connection_id.clone(),
                stream_id: 0,
                sequence: u64::try_from(index + 1).unwrap_or(u64::MAX),
                byte_len: *byte_len,
                content_sha256: None,
                event_type: Some("synthetic_claude_event_sequence".to_owned()),
            }),
    );
    let batch = CaptureBatch {
        schema_version: CAPTURE_SCHEMA_VERSION,
        capture_artifact_id: Uuid::new_v4(),
        capture_run_id: Uuid::new_v4(),
        lane: CaptureLane::ReplayControlledEndpoint,
        observed_at: observed_now(),
        environment: EnvironmentDescriptor {
            os_name: reference.environment.os_name.clone(),
            os_version: reference.environment.os_version.clone(),
            os_build: reference.environment.os_build.clone(),
            arch: reference.environment.arch.clone(),
            kernel: reference.environment.kernel.clone(),
            claude_code_version: reference.environment.claude_code_version.clone(),
            runtime_name: reference.environment.runtime_name.clone(),
            runtime_version: reference.environment.runtime_version.clone(),
            binary_sha256: reference.environment.binary_sha256.clone(),
            labels: BTreeMap::new(),
        },
        target: TargetDescriptor {
            authority: format!("{}:{}", plan.target.authority, plan.target.port),
            official_anthropic: false,
        },
        network: NetworkDescriptor {
            path: reference.network.path.clone(),
            dns_mode: reference.network.dns_mode.clone(),
            proxy_software: None,
            proxy_version: None,
        },
        scenario: ScenarioDescriptor {
            id: reference.scenario.id.clone(),
            fresh_connection: reference.scenario.fresh_connection,
            expected_protocol: "http/1.1".to_owned(),
            concurrent_streams: reference.scenario.concurrent_streams,
            request_shape: reference.scenario.request_shape.clone(),
        },
        events,
    };
    batch
        .validate()
        .context("validate controlled H1 CaptureBatch")?;
    Ok(batch)
}

#[cfg(feature = "boring-backend")]
#[derive(Debug, serde::Serialize)]
struct H2ControlEvidence {
    expected_settings: Vec<Http2Setting>,
    observed_settings: Vec<Http2Setting>,
    expected_settings_order: Vec<u16>,
    observed_settings_order: Vec<u16>,
    settings_exact: bool,
    frame_count: usize,
    decrypted_client_bytes: usize,
    negotiated_alpn: String,
}

#[cfg(feature = "boring-backend")]
async fn capture_h2_candidate(
    plan: &ReplayPlan,
    reference: &NormalizedCapture,
    timeout_ms: u64,
) -> Result<(NormalizedCapture, H2ControlEvidence)> {
    ensure!(timeout_ms > 0, "controlled H2 timeout must be positive");
    let timeout = Duration::from_millis(timeout_ms);
    let server = ControlledH2Server::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &plan.target.authority,
        timeout,
        4 * 1024 * 1024,
    )
    .await
    .context("bind controlled TLS/H2 Capture Endpoint")?;
    let server_addr = server.local_addr().context("read controlled H2 address")?;
    let trust_roots_pem = server.ca_pem().to_vec();
    let capture_task = tokio::spawn(server.capture_one());
    let request = synthetic_h2_request(plan)?;
    let probe = probe_h2_with_request(
        plan,
        &H2ProbePolicy {
            tls: DirectTlsPolicy {
                connect_timeout_ms: timeout_ms,
                handshake_timeout_ms: timeout_ms,
                required_alpn: Some("h2".to_owned()),
                trust_roots_pem: Some(trust_roots_pem),
                dial_override: Some(DialEndpoint {
                    host: server_addr.ip().to_string(),
                    port: server_addr.port(),
                }),
                proxy: None,
            },
            handshake_timeout_ms: timeout_ms,
        },
        &request,
    )
    .await
    .context("probe controlled TLS/H2 Capture Endpoint")?;
    let captured = capture_task
        .await
        .context("join controlled H2 capture task")?
        .context("capture controlled H2 frames")?;
    let observed_settings = captured
        .frames
        .iter()
        .find_map(|frame| match &frame.detail {
            Http2FrameDetail::Settings { entries } => Some(entries.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let observed_settings_order = observed_settings
        .iter()
        .map(|setting| setting.id)
        .collect::<Vec<_>>();
    let http2 = plan.http2().context("require HTTP/2 Replay Plan")?;
    let evidence = H2ControlEvidence {
        expected_settings: http2.settings.clone(),
        observed_settings: observed_settings.clone(),
        expected_settings_order: http2.settings_order.clone(),
        observed_settings_order: observed_settings_order.clone(),
        settings_exact: observed_settings == http2.settings
            && observed_settings_order == http2.settings_order,
        frame_count: captured.frames.len(),
        decrypted_client_bytes: captured.decrypted_client_bytes,
        negotiated_alpn: captured.negotiated_alpn,
    };
    let batch = raw_h2_candidate(
        reference,
        plan,
        &captured.frames,
        probe.tls.handshake_elapsed_micros,
    )?;
    let normalized = normalize_capture(&batch).context("normalize controlled H2 candidate")?;
    Ok((normalized, evidence))
}

#[cfg(feature = "boring-backend")]
fn synthetic_h2_request(plan: &ReplayPlan) -> Result<H2ProbeRequest> {
    let method = plan
        .headers
        .iter()
        .find(|rule| rule.canonical_name == ":method")
        .and_then(|rule| rule.exact_value.clone())
        .unwrap_or_else(|| "POST".to_owned());
    let headers = plan
        .headers
        .iter()
        .filter(|rule| !rule.canonical_name.starts_with(':') && rule.canonical_name != "host")
        .map(|rule| {
            let value = match rule.mode {
                HeaderValueMode::Exact => rule.exact_value.clone().with_context(|| {
                    format!(
                        "exact controlled header {} has no value",
                        rule.canonical_name
                    )
                })?,
                HeaderValueMode::Shape => "x".repeat(rule.value_bytes),
                HeaderValueMode::CredentialDerivedSecret => "s".repeat(rule.value_bytes),
            };
            Ok((rule.wire_name.clone(), value))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(H2ProbeRequest {
        method,
        path: "/v1/messages".to_owned(),
        headers,
        end_stream: false,
    })
}

#[cfg(feature = "boring-backend")]
fn raw_h2_candidate(
    reference: &NormalizedCapture,
    plan: &ReplayPlan,
    frames: &[CapturedH2Frame],
    tls_elapsed_micros: u64,
) -> Result<CaptureBatch> {
    let connection_id = "controlled-h2-connection".to_owned();
    let mut events = vec![CaptureEvent::ConnectionLifecycle {
        connection_id: connection_id.clone(),
        phase: ConnectionPhase::TlsStarted,
        offset_micros: tls_elapsed_micros,
        negotiated_protocol: None,
        resumed: None,
    }];
    events.extend(frames.iter().map(|frame| CaptureEvent::Http2Frame {
        connection_id: connection_id.clone(),
        direction: Direction::ClientToServer,
        sequence: frame.sequence,
        stream_id: frame.stream_id,
        frame_type: frame.frame_type.clone(),
        flags: frame.flags.clone(),
        length: frame.length,
        detail: frame.detail.clone(),
    }));
    let batch = CaptureBatch {
        schema_version: CAPTURE_SCHEMA_VERSION,
        capture_artifact_id: Uuid::new_v4(),
        capture_run_id: Uuid::new_v4(),
        lane: CaptureLane::ReplayControlledEndpoint,
        observed_at: observed_now(),
        environment: EnvironmentDescriptor {
            os_name: reference.environment.os_name.clone(),
            os_version: reference.environment.os_version.clone(),
            os_build: reference.environment.os_build.clone(),
            arch: reference.environment.arch.clone(),
            kernel: reference.environment.kernel.clone(),
            claude_code_version: reference.environment.claude_code_version.clone(),
            runtime_name: reference.environment.runtime_name.clone(),
            runtime_version: reference.environment.runtime_version.clone(),
            binary_sha256: reference.environment.binary_sha256.clone(),
            labels: BTreeMap::new(),
        },
        target: TargetDescriptor {
            authority: format!("{}:{}", plan.target.authority, plan.target.port),
            official_anthropic: false,
        },
        network: NetworkDescriptor {
            path: reference.network.path.clone(),
            dns_mode: reference.network.dns_mode.clone(),
            proxy_software: None,
            proxy_version: None,
        },
        scenario: ScenarioDescriptor {
            id: reference.scenario.id.clone(),
            fresh_connection: reference.scenario.fresh_connection,
            expected_protocol: reference.scenario.expected_protocol.clone(),
            concurrent_streams: reference.scenario.concurrent_streams,
            request_shape: reference.scenario.request_shape.clone(),
        },
        events,
    };
    batch
        .validate()
        .context("validate controlled H2 CaptureBatch")?;
    Ok(batch)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn write_json(path: &PathBuf, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).context("serialize JSON")?;
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn write_sample_set(directory: &Path) -> Result<()> {
    let reference_run_id = Uuid::new_v4();
    let samples = [
        (
            "reference-official",
            sample_batch(CaptureLane::ReferenceOfficialTls, reference_run_id),
        ),
        (
            "reference-controlled",
            sample_batch(CaptureLane::ReferenceControlledEndpoint, reference_run_id),
        ),
        (
            "replay-controlled",
            sample_batch(CaptureLane::ReplayControlledEndpoint, Uuid::new_v4()),
        ),
    ];
    for (name, batch) in samples {
        write_json(&directory.join(format!("{name}.raw.json")), &batch)?;
        let normalized = normalize_capture(&batch).context("normalize sample set batch")?;
        write_json(
            &directory.join(format!("{name}.normalized.json")),
            &normalized,
        )?;
    }
    Ok(())
}

fn build_manifest(
    passive: &NormalizedCapture,
    controlled: &NormalizedCapture,
) -> Result<CaptureManifest> {
    verify_normalized_capture(passive).context("verify passive TLS artifact")?;
    verify_normalized_capture(controlled).context("verify controlled H2 artifact")?;
    ensure!(
        passive.capture_run_id == controlled.capture_run_id,
        "manifest evidence must share capture_run_id"
    );
    ensure!(
        passive.lane == CaptureLane::ReferenceOfficialTls,
        "passive evidence must use reference_official_tls lane"
    );
    ensure!(
        controlled.lane == CaptureLane::ReferenceControlledEndpoint,
        "controlled evidence must use reference_controlled_endpoint lane"
    );
    ensure!(
        passive.normalizer_version == controlled.normalizer_version,
        "manifest evidence uses different normalizer versions"
    );
    let passive_environment = manifest_environment(passive);
    let controlled_environment = manifest_environment(controlled);
    ensure!(
        passive_environment == controlled_environment,
        "manifest evidence environment metadata differs"
    );
    let passive_scenario = manifest_scenario(passive);
    let controlled_scenario = manifest_scenario(controlled);
    ensure!(
        passive_scenario == controlled_scenario,
        "manifest evidence scenario metadata differs"
    );

    let manifest = CaptureManifest {
        schema_version: CAPTURE_MANIFEST_SCHEMA_VERSION,
        manifest_id: Uuid::new_v4(),
        capture_run_id: passive.capture_run_id,
        created_at: controlled.observed_at.clone(),
        state: CaptureManifestState::Verified,
        environment: controlled_environment,
        scenario: controlled_scenario,
        passive_tls: evidence_ref(passive),
        controlled_http2: evidence_ref(controlled),
        verification: ManifestVerification {
            normalizer_version: controlled.normalizer_version.clone(),
            paired_fields_verified: true,
            secret_scan_passed: true,
            verified_at: Some(controlled.observed_at.clone()),
            evidence_notes: vec!["generated from integrity-checked normalized evidence".to_owned()],
        },
    };
    manifest.validate().context("validate capture manifest")?;
    Ok(manifest)
}

fn manifest_environment(capture: &NormalizedCapture) -> ManifestEnvironmentDescriptor {
    ManifestEnvironmentDescriptor {
        os_name: capture.environment.os_name.clone(),
        os_version: capture.environment.os_version.clone(),
        os_build: capture.environment.os_build.clone(),
        arch: capture.environment.arch.clone(),
        kernel: capture.environment.kernel.clone(),
        claude_code_version: capture.environment.claude_code_version.clone(),
        runtime_name: capture.environment.runtime_name.clone(),
        runtime_version: capture.environment.runtime_version.clone(),
        binary_sha256: capture.environment.binary_sha256.clone(),
    }
}

fn manifest_scenario(capture: &NormalizedCapture) -> ManifestScenarioDescriptor {
    ManifestScenarioDescriptor {
        id: capture.scenario.id.clone(),
        fresh_connection: capture.scenario.fresh_connection,
        concurrent_streams: capture.scenario.concurrent_streams,
        request_shape: capture.scenario.request_shape.clone(),
    }
}

fn evidence_ref(capture: &NormalizedCapture) -> CaptureEvidenceRef {
    CaptureEvidenceRef {
        capture_artifact_id: capture.capture_artifact_id,
        capture_run_id: capture.capture_run_id,
        lane: capture.lane.clone(),
        normalized_sha256: capture.normalized_sha256.clone(),
        event_count: capture.event_count(),
    }
}

fn default_archetype_id(environment: &ManifestEnvironmentDescriptor) -> String {
    format!(
        "claude-code/{}/{}/{}/{}",
        archetype_segment(&environment.os_name),
        archetype_segment(&environment.arch),
        archetype_segment(&environment.runtime_name),
        archetype_segment(&environment.claude_code_version)
    )
}

fn archetype_segment(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

// This deliberately keeps the entire fixture visible as one auditable wire
// scenario instead of hiding its ordering across helper functions.
#[allow(clippy::too_many_lines)]
fn sample_batch(lane: CaptureLane, capture_run_id: Uuid) -> CaptureBatch {
    let connection_id = "collector-raw-connection-7".to_owned();
    let official = lane.is_official();
    let authority = if official {
        "api.anthropic.com:443"
    } else {
        "capture.internal.example:443"
    };
    let hostname = authority.trim_end_matches(":443");
    let mut events = vec![
        CaptureEvent::ConnectionLifecycle {
            connection_id: connection_id.clone(),
            phase: ConnectionPhase::TlsStarted,
            offset_micros: 3_120,
            negotiated_protocol: None,
            resumed: None,
        },
        CaptureEvent::TlsClientHello {
            connection_id: connection_id.clone(),
            record_version: 0x0301,
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302, 0x1303],
            extensions: vec![
                TlsExtensionObservation {
                    extension_type: 0,
                    name: "server_name".to_owned(),
                    position: 0,
                    encoded_len: 30,
                    attributes: vec![TlsAttributeObservation {
                        name: "hostname".to_owned(),
                        value: hostname.to_owned(),
                        dynamic: true,
                    }],
                },
                TlsExtensionObservation {
                    extension_type: 16,
                    name: "application_layer_protocol_negotiation".to_owned(),
                    position: 1,
                    encoded_len: 5,
                    attributes: vec![],
                },
            ],
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            client_hello_len: 245,
            record_lengths: vec![250],
        },
        CaptureEvent::Http2Frame {
            connection_id: connection_id.clone(),
            direction: Direction::ClientToServer,
            sequence: 1,
            stream_id: 0,
            frame_type: Http2FrameType::Settings,
            flags: vec![],
            length: 18,
            detail: Http2FrameDetail::Settings {
                entries: vec![
                    Http2Setting {
                        id: 1,
                        value: 65_536,
                    },
                    Http2Setting {
                        id: 4,
                        value: 6_291_456,
                    },
                    Http2Setting {
                        id: 6,
                        value: 262_144,
                    },
                ],
            },
        },
        CaptureEvent::Http2Frame {
            connection_id,
            direction: Direction::ClientToServer,
            sequence: 2,
            stream_id: 1,
            frame_type: Http2FrameType::Headers,
            flags: vec!["end_headers".to_owned()],
            length: 180,
            detail: Http2FrameDetail::Headers {
                headers: vec![
                    HeaderObservation {
                        name: ":method".to_owned(),
                        value: "POST".to_owned(),
                    },
                    HeaderObservation {
                        name: ":authority".to_owned(),
                        value: hostname.to_owned(),
                    },
                    HeaderObservation {
                        name: "user-agent".to_owned(),
                        value: "claude-cli/fixture".to_owned(),
                    },
                    HeaderObservation {
                        name: "authorization".to_owned(),
                        value: "Bearer SYNTHETIC_SECRET".to_owned(),
                    },
                    HeaderObservation {
                        name: "x-session-id".to_owned(),
                        value: "synthetic-session-id".to_owned(),
                    },
                ],
            },
        },
    ];
    events.retain(|event| {
        matches!(event, CaptureEvent::ConnectionLifecycle { .. })
            || official == matches!(event, CaptureEvent::TlsClientHello { .. })
    });
    CaptureBatch {
        schema_version: CAPTURE_SCHEMA_VERSION,
        capture_artifact_id: Uuid::new_v4(),
        capture_run_id,
        lane,
        observed_at: "2026-08-22T00:00:00Z".to_owned(),
        environment: EnvironmentDescriptor {
            os_name: "linux".to_owned(),
            os_version: "fixture".to_owned(),
            os_build: None,
            arch: "x86_64".to_owned(),
            kernel: Some("fixture-kernel".to_owned()),
            claude_code_version: "fixture".to_owned(),
            runtime_name: "bun".to_owned(),
            runtime_version: "fixture".to_owned(),
            binary_sha256: None,
            labels: BTreeMap::from([("runner_id".to_owned(), "secret-runner-42".to_owned())]),
        },
        target: TargetDescriptor {
            authority: authority.to_owned(),
            official_anthropic: official,
        },
        network: NetworkDescriptor {
            path: NetworkPath::Direct,
            dns_mode: DnsMode::Local,
            proxy_software: None,
            proxy_version: None,
        },
        scenario: ScenarioDescriptor {
            id: "T01-minimal-message".to_owned(),
            fresh_connection: true,
            expected_protocol: "h2".to_owned(),
            concurrent_streams: 1,
            request_shape: "synthetic-minimal-message".to_owned(),
        },
        events,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "boring-backend")]
    #[test]
    fn tls_replay_accepts_an_empty_alpn_profile() {
        assert_eq!(
            required_alpn_for_tls_replay(&[]).expect("decode empty ALPN profile"),
            None
        );
    }

    #[cfg(feature = "boring-backend")]
    #[test]
    fn tls_replay_requires_the_first_offered_alpn_protocol() {
        assert_eq!(
            required_alpn_for_tls_replay(b"\x02h2\x08http/1.1")
                .expect("decode ordered ALPN profile"),
            Some("h2".to_owned())
        );
    }

    #[cfg(feature = "boring-backend")]
    #[test]
    fn tls_replay_rejects_truncated_alpn_encoding() {
        let error = required_alpn_for_tls_replay(b"\x08http").expect_err("reject bad ALPN");
        assert!(error.to_string().contains("truncated ALPN"));
    }

    #[test]
    fn manifest_pairs_logical_scenario_across_different_lane_protocols() {
        let capture_run_id = Uuid::new_v4();
        let passive = normalize_capture(&sample_batch(
            CaptureLane::ReferenceOfficialTls,
            capture_run_id,
        ))
        .expect("normalize passive fixture");
        let mut controlled_batch =
            sample_batch(CaptureLane::ReferenceControlledEndpoint, capture_run_id);
        controlled_batch.scenario.expected_protocol = "http/1.1".to_owned();
        let controlled =
            normalize_capture(&controlled_batch).expect("normalize controlled fixture");

        let manifest = build_manifest(&passive, &controlled)
            .expect("pair lanes with distinct observed protocols");

        assert_eq!(manifest.scenario.id, passive.scenario.id);
        assert_ne!(
            passive.scenario.expected_protocol,
            controlled.scenario.expected_protocol
        );
    }
}
