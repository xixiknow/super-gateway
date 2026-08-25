#![forbid(unsafe_code)]

use capture_schema::{
    CaptureEvidenceRef, CaptureLane, CaptureManifest, CaptureManifestState, ConnectionPhase,
    Direction, Http2FrameType,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;
use uuid::Uuid;
use wire_normalizer::{
    NormalizedCapture, NormalizedEvent, NormalizedHeader, NormalizedHttp2FrameDetail,
    NormalizedTlsExtension, ValueKind, ValueShape, verify_normalized_capture,
};

pub const ARCHETYPE_BUNDLE_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug)]
pub struct BundleCompilerOptions {
    pub archetype_id: String,
    pub bundle_version: u32,
    pub engine_api: String,
    pub rust_targets: Vec<String>,
}

impl BundleCompilerOptions {
    pub fn production_defaults(archetype_id: String, bundle_version: u32) -> Self {
        Self {
            archetype_id,
            bundle_version,
            engine_api: "v1".to_owned(),
            rust_targets: vec![
                "x86_64-unknown-linux-gnu".to_owned(),
                "aarch64-unknown-linux-gnu".to_owned(),
            ],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateArchetypeBundle {
    pub schema_version: u32,
    pub archetype_id: String,
    pub bundle_version: u32,
    pub state: BundleState,
    pub evidence: BundleEvidence,
    pub compatibility: BundleCompatibility,
    pub tls: TlsProfileSpec,
    pub application: ApplicationProfileSpec,
    pub headers: HeaderProfileSpec,
    pub connection: ConnectionProfileSpec,
    pub verification: BundleVerification,
    pub bundle_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "protocol", content = "profile", rename_all = "snake_case")]
pub enum ApplicationProfileSpec {
    Http1(Http1ProfileSpec),
    Http2(Http2ProfileSpec),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http1ProfileSpec {
    pub method: String,
    pub path_shape: ValueShape,
    pub version: String,
    pub body_bytes: u32,
    pub content_length_framing: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BundleState {
    Candidate,
    Canary,
    Active,
    Retired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleEvidence {
    pub manifest_id: Uuid,
    pub capture_run_id: Uuid,
    pub passive_tls: CaptureEvidenceRef,
    pub controlled_http2: CaptureEvidenceRef,
    pub manifest_verified_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleCompatibility {
    pub engine_api: String,
    pub rust_targets: Vec<String>,
    pub min_engine_build: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsProfileSpec {
    pub record_version: u16,
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<NormalizedTlsExtension>,
    pub alpn_order: Vec<String>,
    pub client_hello_len: u32,
    pub record_lengths: Vec<u32>,
    pub dynamic_fields: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http2ProfileSpec {
    pub client_frames: Vec<Http2FrameSpec>,
    pub settings_order: Vec<u16>,
    pub connection_window_update: Option<u32>,
    pub pseudo_header_order: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http2FrameSpec {
    pub sequence: u64,
    pub stream_id: u32,
    pub frame_type: Http2FrameType,
    pub flags: Vec<String>,
    pub length: u32,
    pub detail: NormalizedHttp2FrameDetail,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderProfileSpec {
    pub ordered_names: Vec<String>,
    pub casing_policy: HeaderCasingPolicy,
    pub value_rules: Vec<HeaderValueRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeaderCasingPolicy {
    Lowercase,
    PreserveObserved,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderValueRule {
    pub wire_name: String,
    pub canonical_name: String,
    pub mode: HeaderValueMode,
    pub exact_value: Option<String>,
    pub value_kind: ValueKind,
    pub value_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeaderValueMode {
    Exact,
    Shape,
    CredentialDerivedSecret,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionProfileSpec {
    pub lifecycle_phases: Vec<ConnectionPhase>,
    pub negotiated_protocols: Vec<String>,
    pub resumption_observations: Vec<bool>,
    pub fresh_connection_observed: bool,
    pub pooled_connection_observed: bool,
    pub observed_concurrent_streams: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleVerification {
    pub fixture_set: String,
    pub expected_normalized_hashes: Vec<String>,
    pub privacy_invariants_checked: bool,
    pub wire_diff_required: bool,
}

/// Compiles verified two-lane reference evidence into a transport bundle candidate.
///
/// # Errors
///
/// Returns [`BundleError`] when evidence binding, integrity, profile stability,
/// required protocol observations, or bundle privacy checks fail.
pub fn compile_bundle(
    manifest: &CaptureManifest,
    passive_tls: &NormalizedCapture,
    controlled_http2: &NormalizedCapture,
    options: &BundleCompilerOptions,
) -> Result<CandidateArchetypeBundle, BundleError> {
    validate_inputs(manifest, passive_tls, controlled_http2, options)?;
    let tls = extract_stable_tls(passive_tls)?;
    let application = extract_application(controlled_http2)?;
    let headers = extract_headers(controlled_http2)?;
    let connection = extract_connection(passive_tls, controlled_http2);
    let verified_at = manifest
        .verification
        .verified_at
        .clone()
        .ok_or(BundleError::ManifestNotVerified)?;

    let mut bundle = CandidateArchetypeBundle {
        schema_version: ARCHETYPE_BUNDLE_SCHEMA_VERSION,
        archetype_id: options.archetype_id.clone(),
        bundle_version: options.bundle_version,
        state: BundleState::Candidate,
        evidence: BundleEvidence {
            manifest_id: manifest.manifest_id,
            capture_run_id: manifest.capture_run_id,
            passive_tls: manifest.passive_tls.clone(),
            controlled_http2: manifest.controlled_http2.clone(),
            manifest_verified_at: verified_at,
        },
        compatibility: BundleCompatibility {
            engine_api: options.engine_api.clone(),
            rust_targets: options.rust_targets.clone(),
            min_engine_build: None,
        },
        tls,
        application,
        headers,
        connection,
        verification: BundleVerification {
            fixture_set: format!("manifest:{}", manifest.manifest_id),
            expected_normalized_hashes: vec![
                passive_tls.normalized_sha256.clone(),
                controlled_http2.normalized_sha256.clone(),
            ],
            privacy_invariants_checked: true,
            wire_diff_required: true,
        },
        bundle_sha256: String::new(),
    };
    bundle.bundle_sha256 = recompute_bundle_sha256(&bundle)?;
    verify_bundle(&bundle)?;
    Ok(bundle)
}

/// Verifies the candidate digest and secret-free schema invariants.
///
/// # Errors
///
/// Returns [`BundleError`] when the digest, identifiers, evidence, dynamic TLS
/// values, or secret Header rules violate the bundle contract.
pub fn verify_bundle(bundle: &CandidateArchetypeBundle) -> Result<(), BundleError> {
    if bundle.schema_version != ARCHETYPE_BUNDLE_SCHEMA_VERSION {
        return Err(BundleError::UnsupportedSchema(bundle.schema_version));
    }
    validate_archetype_id(&bundle.archetype_id)?;
    if bundle.bundle_version == 0 {
        return Err(BundleError::InvalidBundleVersion);
    }
    if bundle.compatibility.engine_api.trim().is_empty()
        || bundle.compatibility.rust_targets.is_empty()
    {
        return Err(BundleError::MissingCompatibility);
    }
    if bundle.evidence.manifest_id.is_nil()
        || bundle.evidence.capture_run_id.is_nil()
        || bundle.evidence.passive_tls.capture_artifact_id
            == bundle.evidence.controlled_http2.capture_artifact_id
        || bundle.evidence.passive_tls.lane != CaptureLane::ReferenceOfficialTls
        || bundle.evidence.controlled_http2.lane != CaptureLane::ReferenceControlledEndpoint
        || !is_sha256(&bundle.evidence.passive_tls.normalized_sha256)
        || !is_sha256(&bundle.evidence.controlled_http2.normalized_sha256)
    {
        return Err(BundleError::InvalidEvidenceBinding);
    }
    for extension in &bundle.tls.extensions {
        for attribute in &extension.attributes {
            if (attribute.dynamic || is_secret_tls_attribute(&attribute.name))
                && attribute.value.is_some()
            {
                return Err(BundleError::SecretInBundle(format!(
                    "tls.extensions[{}].{}",
                    extension.position, attribute.name
                )));
            }
        }
    }
    for rule in &bundle.headers.value_rules {
        if (rule.mode == HeaderValueMode::CredentialDerivedSecret
            || is_secret_header(&rule.canonical_name))
            && (rule.exact_value.is_some() || rule.mode != HeaderValueMode::CredentialDerivedSecret)
        {
            return Err(BundleError::SecretInBundle(format!(
                "headers.{}",
                rule.canonical_name
            )));
        }
    }
    match &bundle.application {
        ApplicationProfileSpec::Http1(profile) => {
            if profile.method.is_empty()
                || profile.version != "HTTP/1.1"
                || profile.path_shape.bytes == 0
            {
                return Err(BundleError::InvalidApplicationProfile);
            }
        }
        ApplicationProfileSpec::Http2(profile) => {
            if profile.client_frames.is_empty() {
                return Err(BundleError::InvalidApplicationProfile);
            }
            for frame in &profile.client_frames {
                if let NormalizedHttp2FrameDetail::Headers { headers } = &frame.detail {
                    for header in headers {
                        if is_secret_header(&header.canonical_name) && header.value.is_some() {
                            return Err(BundleError::SecretInBundle(format!(
                                "http2.headers.{}",
                                header.canonical_name
                            )));
                        }
                    }
                }
            }
        }
    }
    let actual = recompute_bundle_sha256(bundle)?;
    if actual != bundle.bundle_sha256 {
        return Err(BundleError::IntegrityMismatch {
            expected: bundle.bundle_sha256.clone(),
            actual,
        });
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_secret_tls_attribute(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if name.ends_with("_shape") || name.ends_with("_length") || name.ends_with("_count") {
        return false;
    }
    ["random", "key_share", "psk", "session", "ticket"]
        .iter()
        .any(|marker| name.contains(marker))
}

fn is_secret_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "cookie"
            | "proxy-authorization"
            | "set-cookie"
            | "x-api-key"
            | "x-anthropic-billing-header"
    ) || [
        "session",
        "request-id",
        "device-id",
        "fingerprint",
        "profile-seed",
        "session-hmac",
    ]
    .iter()
    .any(|marker| name.contains(marker))
}

/// Computes the canonical bundle digest with its digest field blanked.
///
/// # Errors
///
/// Returns [`BundleError::Encoding`] when canonical JSON serialization fails.
pub fn recompute_bundle_sha256(bundle: &CandidateArchetypeBundle) -> Result<String, BundleError> {
    let mut unsigned = bundle.clone();
    unsigned.bundle_sha256.clear();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&unsigned)?)))
}

fn validate_inputs(
    manifest: &CaptureManifest,
    passive_tls: &NormalizedCapture,
    controlled_http2: &NormalizedCapture,
    options: &BundleCompilerOptions,
) -> Result<(), BundleError> {
    manifest.validate()?;
    if !matches!(
        manifest.state,
        CaptureManifestState::Verified
            | CaptureManifestState::Canary
            | CaptureManifestState::Active
    ) {
        return Err(BundleError::ManifestNotVerified);
    }
    verify_normalized_capture(passive_tls)?;
    verify_normalized_capture(controlled_http2)?;
    validate_archetype_id(&options.archetype_id)?;
    if options.bundle_version == 0 {
        return Err(BundleError::InvalidBundleVersion);
    }
    if !evidence_matches(&manifest.passive_tls, passive_tls)
        || !evidence_matches(&manifest.controlled_http2, controlled_http2)
        || manifest.verification.normalizer_version != passive_tls.normalizer_version
        || manifest.verification.normalizer_version != controlled_http2.normalizer_version
        || !manifest_environment_matches(manifest, passive_tls)
        || !manifest_environment_matches(manifest, controlled_http2)
        || !manifest_scenario_matches(manifest, passive_tls)
        || !manifest_scenario_matches(manifest, controlled_http2)
    {
        return Err(BundleError::EvidenceMismatch);
    }
    if passive_tls.lane != CaptureLane::ReferenceOfficialTls
        || controlled_http2.lane != CaptureLane::ReferenceControlledEndpoint
    {
        return Err(BundleError::EvidenceMismatch);
    }
    Ok(())
}

fn manifest_environment_matches(manifest: &CaptureManifest, capture: &NormalizedCapture) -> bool {
    manifest.environment.os_name == capture.environment.os_name
        && manifest.environment.os_version == capture.environment.os_version
        && manifest.environment.os_build == capture.environment.os_build
        && manifest.environment.arch == capture.environment.arch
        && manifest.environment.kernel == capture.environment.kernel
        && manifest.environment.claude_code_version == capture.environment.claude_code_version
        && manifest.environment.runtime_name == capture.environment.runtime_name
        && manifest.environment.runtime_version == capture.environment.runtime_version
        && manifest.environment.binary_sha256 == capture.environment.binary_sha256
}

fn manifest_scenario_matches(manifest: &CaptureManifest, capture: &NormalizedCapture) -> bool {
    manifest.scenario.id == capture.scenario.id
        && manifest.scenario.fresh_connection == capture.scenario.fresh_connection
        && manifest.scenario.concurrent_streams == capture.scenario.concurrent_streams
        && manifest.scenario.request_shape == capture.scenario.request_shape
}

fn evidence_matches(reference: &CaptureEvidenceRef, capture: &NormalizedCapture) -> bool {
    reference.capture_artifact_id == capture.capture_artifact_id
        && reference.capture_run_id == capture.capture_run_id
        && reference.lane == capture.lane
        && reference.normalized_sha256 == capture.normalized_sha256
        && reference.event_count == capture.event_count()
}

fn validate_archetype_id(value: &str) -> Result<(), BundleError> {
    if value.is_empty()
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
    {
        return Err(BundleError::InvalidArchetypeId);
    }
    Ok(())
}

fn extract_stable_tls(capture: &NormalizedCapture) -> Result<TlsProfileSpec, BundleError> {
    let mut candidates = capture.events.iter().filter_map(|event| {
        let NormalizedEvent::TlsClientHello {
            record_version,
            legacy_version,
            cipher_suites,
            extensions,
            alpn,
            client_hello_len,
            record_lengths,
            ..
        } = event
        else {
            return None;
        };
        Some(TlsProfileSpec {
            record_version: *record_version,
            legacy_version: *legacy_version,
            cipher_suites: cipher_suites.clone(),
            extensions: extensions.clone(),
            alpn_order: alpn.clone(),
            client_hello_len: *client_hello_len,
            record_lengths: record_lengths.clone(),
            dynamic_fields: extensions
                .iter()
                .flat_map(|extension| {
                    extension
                        .attributes
                        .iter()
                        .filter(|attribute| attribute.dynamic)
                        .map(|attribute| {
                            format!("tls.extensions[{}].{}", extension.position, attribute.name)
                        })
                })
                .collect(),
        })
    });
    let first = candidates.next().ok_or(BundleError::MissingTlsEvidence)?;
    if candidates.any(|candidate| candidate != first) {
        return Err(BundleError::UnstableTlsEvidence);
    }
    Ok(first)
}

fn extract_application(capture: &NormalizedCapture) -> Result<ApplicationProfileSpec, BundleError> {
    if let Some(profile) = extract_http1(capture) {
        return Ok(ApplicationProfileSpec::Http1(profile));
    }
    extract_http2(capture).map(ApplicationProfileSpec::Http2)
}

fn extract_http1(capture: &NormalizedCapture) -> Option<Http1ProfileSpec> {
    capture.events.iter().find_map(|event| {
        let NormalizedEvent::Http1Request {
            method,
            path,
            version,
            headers,
            body_bytes,
            ..
        } = event
        else {
            return None;
        };
        Some(Http1ProfileSpec {
            method: method.clone(),
            path_shape: path.clone(),
            version: version.clone(),
            body_bytes: *body_bytes,
            content_length_framing: headers
                .iter()
                .any(|header| header.canonical_name == "content-length"),
        })
    })
}

fn extract_http2(capture: &NormalizedCapture) -> Result<Http2ProfileSpec, BundleError> {
    let client_frames = capture
        .events
        .iter()
        .filter_map(|event| {
            let NormalizedEvent::Http2Frame {
                direction: Direction::ClientToServer,
                sequence,
                stream_id,
                frame_type,
                flags,
                length,
                detail,
                ..
            } = event
            else {
                return None;
            };
            Some(Http2FrameSpec {
                sequence: *sequence,
                stream_id: *stream_id,
                frame_type: frame_type.clone(),
                flags: flags.clone(),
                length: *length,
                detail: detail.clone(),
            })
        })
        .collect::<Vec<_>>();
    if client_frames.is_empty() {
        return Err(BundleError::MissingHttp2Evidence);
    }
    let settings_order = client_frames
        .iter()
        .find_map(|frame| match &frame.detail {
            NormalizedHttp2FrameDetail::Settings { entries } => {
                Some(entries.iter().map(|entry| entry.id).collect())
            }
            _ => None,
        })
        .unwrap_or_default();
    let connection_window_update = client_frames.iter().find_map(|frame| {
        if frame.stream_id == 0
            && let NormalizedHttp2FrameDetail::WindowUpdate { increment } = &frame.detail
        {
            return Some(*increment);
        }
        None
    });
    let pseudo_header_order = first_headers(capture)
        .iter()
        .filter(|header| header.canonical_name.starts_with(':'))
        .map(|header| header.wire_name.clone())
        .collect();
    Ok(Http2ProfileSpec {
        client_frames,
        settings_order,
        connection_window_update,
        pseudo_header_order,
    })
}

fn extract_headers(capture: &NormalizedCapture) -> Result<HeaderProfileSpec, BundleError> {
    let headers = first_headers(capture);
    if headers.is_empty() {
        return Err(BundleError::MissingHeaderEvidence);
    }
    let casing_policy = if headers
        .iter()
        .all(|header| header.wire_name == header.canonical_name)
    {
        HeaderCasingPolicy::Lowercase
    } else {
        HeaderCasingPolicy::PreserveObserved
    };
    let value_rules = headers
        .iter()
        .map(|header| HeaderValueRule {
            wire_name: header.wire_name.clone(),
            canonical_name: header.canonical_name.clone(),
            mode: if header.value_shape.kind == ValueKind::Secret {
                HeaderValueMode::CredentialDerivedSecret
            } else if header.value.is_some() {
                HeaderValueMode::Exact
            } else {
                HeaderValueMode::Shape
            },
            exact_value: header.value.clone(),
            value_kind: header.value_shape.kind.clone(),
            value_bytes: header.value_shape.bytes,
        })
        .collect();
    Ok(HeaderProfileSpec {
        ordered_names: headers
            .iter()
            .map(|header| header.wire_name.clone())
            .collect(),
        casing_policy,
        value_rules,
    })
}

fn first_headers(capture: &NormalizedCapture) -> &[NormalizedHeader] {
    capture
        .events
        .iter()
        .find_map(|event| match event {
            NormalizedEvent::Http2Frame {
                detail: NormalizedHttp2FrameDetail::Headers { headers },
                direction: Direction::ClientToServer,
                ..
            }
            | NormalizedEvent::Http1Request { headers, .. } => Some(headers.as_slice()),
            _ => None,
        })
        .unwrap_or_default()
}

fn extract_connection(
    passive_tls: &NormalizedCapture,
    controlled_http2: &NormalizedCapture,
) -> ConnectionProfileSpec {
    let mut lifecycle_phases = vec![];
    let mut negotiated_protocols = BTreeSet::new();
    let mut resumption_observations = BTreeSet::new();
    for event in passive_tls.events.iter().chain(&controlled_http2.events) {
        if let NormalizedEvent::ConnectionLifecycle {
            phase,
            negotiated_protocol,
            resumed,
            ..
        } = event
        {
            if !lifecycle_phases.contains(phase) {
                lifecycle_phases.push(phase.clone());
            }
            negotiated_protocols.extend(negotiated_protocol.clone());
            resumption_observations.extend(*resumed);
        }
    }
    ConnectionProfileSpec {
        lifecycle_phases,
        negotiated_protocols: negotiated_protocols.into_iter().collect(),
        resumption_observations: resumption_observations.into_iter().collect(),
        fresh_connection_observed: controlled_http2.scenario.fresh_connection,
        pooled_connection_observed: !controlled_http2.scenario.fresh_connection,
        observed_concurrent_streams: controlled_http2.scenario.concurrent_streams,
    }
}

#[derive(Debug, Error)]
pub enum BundleError {
    #[error(transparent)]
    Manifest(#[from] capture_schema::ValidationError),
    #[error(transparent)]
    NormalizedEvidence(#[from] wire_normalizer::NormalizationError),
    #[error("manifest is not verified")]
    ManifestNotVerified,
    #[error("manifest evidence does not match supplied normalized artifacts")]
    EvidenceMismatch,
    #[error("bundle evidence binding is invalid")]
    InvalidEvidenceBinding,
    #[error("archetype_id is invalid")]
    InvalidArchetypeId,
    #[error("bundle_version must be greater than zero")]
    InvalidBundleVersion,
    #[error("bundle compatibility is incomplete")]
    MissingCompatibility,
    #[error("passive evidence contains no TLS ClientHello")]
    MissingTlsEvidence,
    #[error("passive evidence contains multiple stable TLS profiles")]
    UnstableTlsEvidence,
    #[error("controlled evidence contains neither an HTTP/1.1 request nor client HTTP/2 frames")]
    MissingHttp2Evidence,
    #[error("bundle application protocol profile is invalid")]
    InvalidApplicationProfile,
    #[error("controlled evidence contains no request Header observation")]
    MissingHeaderEvidence,
    #[error("bundle contains a credential-specific value at {0}")]
    SecretInBundle(String),
    #[error("unsupported bundle schema version {0}")]
    UnsupportedSchema(u32),
    #[error("bundle integrity mismatch: expected {expected}, actual {actual}")]
    IntegrityMismatch { expected: String, actual: String },
    #[error("failed to encode bundle: {0}")]
    Encoding(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use capture_schema::{
        CAPTURE_MANIFEST_SCHEMA_VERSION, CAPTURE_SCHEMA_VERSION, CaptureBatch, CaptureEvent,
        DnsMode, EnvironmentDescriptor, HeaderObservation, Http2FrameDetail, Http2Setting,
        ManifestEnvironmentDescriptor, ManifestScenarioDescriptor, ManifestVerification,
        NetworkDescriptor, NetworkPath, ScenarioDescriptor, TargetDescriptor,
        TlsAttributeObservation, TlsExtensionObservation,
    };
    use std::collections::BTreeMap;
    use wire_normalizer::{normalize_capture, recompute_normalized_sha256};

    fn environment() -> EnvironmentDescriptor {
        EnvironmentDescriptor {
            os_name: "linux".to_owned(),
            os_version: "fixture".to_owned(),
            os_build: None,
            arch: "x86_64".to_owned(),
            kernel: None,
            claude_code_version: "fixture".to_owned(),
            runtime_name: "bun".to_owned(),
            runtime_version: "fixture".to_owned(),
            binary_sha256: None,
            labels: BTreeMap::new(),
        }
    }

    fn scenario() -> ScenarioDescriptor {
        ScenarioDescriptor {
            id: "T01".to_owned(),
            fresh_connection: true,
            expected_protocol: "h2".to_owned(),
            concurrent_streams: 1,
            request_shape: "fixture".to_owned(),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn normalized_pair_with_protocol(http1: bool) -> (NormalizedCapture, NormalizedCapture) {
        let run_id = Uuid::new_v4();
        let passive = normalize_capture(&CaptureBatch {
            schema_version: CAPTURE_SCHEMA_VERSION,
            capture_artifact_id: Uuid::new_v4(),
            capture_run_id: run_id,
            lane: CaptureLane::ReferenceOfficialTls,
            observed_at: "2026-08-22T00:00:00Z".to_owned(),
            environment: environment(),
            target: TargetDescriptor {
                authority: "api.anthropic.com:443".to_owned(),
                official_anthropic: true,
            },
            network: NetworkDescriptor {
                path: NetworkPath::Direct,
                dns_mode: DnsMode::Local,
                proxy_software: None,
                proxy_version: None,
            },
            scenario: scenario(),
            events: vec![CaptureEvent::TlsClientHello {
                connection_id: "raw-official".to_owned(),
                record_version: 0x0301,
                legacy_version: 0x0303,
                cipher_suites: vec![0x1301, 0x1302],
                extensions: vec![TlsExtensionObservation {
                    extension_type: 51,
                    name: "key_share".to_owned(),
                    position: 0,
                    encoded_len: 36,
                    attributes: vec![TlsAttributeObservation {
                        name: "key_share_bytes".to_owned(),
                        value: "TOP_SECRET_KEY_SHARE".to_owned(),
                        dynamic: true,
                    }],
                }],
                alpn: vec!["h2".to_owned()],
                client_hello_len: 220,
                record_lengths: vec![225],
            }],
        })
        .expect("normalize passive fixture");
        let mut controlled_scenario = scenario();
        controlled_scenario.expected_protocol = if http1 { "http/1.1" } else { "h2" }.to_owned();
        let controlled_events = if http1 {
            vec![CaptureEvent::Http1Request {
                connection_id: "raw-controlled".to_owned(),
                method: "POST".to_owned(),
                path: "/v1/messages?beta=true".to_owned(),
                version: "HTTP/1.1".to_owned(),
                headers: vec![
                    HeaderObservation {
                        name: "Content-Type".to_owned(),
                        value: "application/json".to_owned(),
                    },
                    HeaderObservation {
                        name: "Authorization".to_owned(),
                        value: "Bearer TOP_SECRET".to_owned(),
                    },
                    HeaderObservation {
                        name: "Content-Length".to_owned(),
                        value: "128".to_owned(),
                    },
                ],
                body_bytes: 128,
            }]
        } else {
            vec![
                CaptureEvent::Http2Frame {
                    connection_id: "raw-controlled".to_owned(),
                    direction: Direction::ClientToServer,
                    sequence: 1,
                    stream_id: 0,
                    frame_type: Http2FrameType::Settings,
                    flags: vec![],
                    length: 6,
                    detail: Http2FrameDetail::Settings {
                        entries: vec![Http2Setting { id: 1, value: 4096 }],
                    },
                },
                CaptureEvent::Http2Frame {
                    connection_id: "raw-controlled".to_owned(),
                    direction: Direction::ClientToServer,
                    sequence: 2,
                    stream_id: 1,
                    frame_type: Http2FrameType::Headers,
                    flags: vec!["end_headers".to_owned()],
                    length: 80,
                    detail: Http2FrameDetail::Headers {
                        headers: vec![
                            HeaderObservation {
                                name: ":method".to_owned(),
                                value: "POST".to_owned(),
                            },
                            HeaderObservation {
                                name: "authorization".to_owned(),
                                value: "Bearer TOP_SECRET".to_owned(),
                            },
                        ],
                    },
                },
            ]
        };
        let controlled = normalize_capture(&CaptureBatch {
            schema_version: CAPTURE_SCHEMA_VERSION,
            capture_artifact_id: Uuid::new_v4(),
            capture_run_id: run_id,
            lane: CaptureLane::ReferenceControlledEndpoint,
            observed_at: "2026-08-22T00:00:00Z".to_owned(),
            environment: environment(),
            target: TargetDescriptor {
                authority: "capture.invalid:443".to_owned(),
                official_anthropic: false,
            },
            network: NetworkDescriptor {
                path: NetworkPath::Direct,
                dns_mode: DnsMode::Local,
                proxy_software: None,
                proxy_version: None,
            },
            scenario: controlled_scenario,
            events: controlled_events,
        })
        .expect("normalize controlled fixture");
        (passive, controlled)
    }

    fn normalized_pair() -> (NormalizedCapture, NormalizedCapture) {
        normalized_pair_with_protocol(true)
    }

    fn manifest(passive: &NormalizedCapture, controlled: &NormalizedCapture) -> CaptureManifest {
        CaptureManifest {
            schema_version: CAPTURE_MANIFEST_SCHEMA_VERSION,
            manifest_id: Uuid::new_v4(),
            capture_run_id: passive.capture_run_id,
            created_at: "2026-08-22T00:00:00Z".to_owned(),
            state: CaptureManifestState::Verified,
            environment: ManifestEnvironmentDescriptor {
                os_name: "linux".to_owned(),
                os_version: "fixture".to_owned(),
                os_build: None,
                arch: "x86_64".to_owned(),
                kernel: None,
                claude_code_version: "fixture".to_owned(),
                runtime_name: "bun".to_owned(),
                runtime_version: "fixture".to_owned(),
                binary_sha256: None,
            },
            scenario: ManifestScenarioDescriptor {
                id: passive.scenario.id.clone(),
                fresh_connection: passive.scenario.fresh_connection,
                concurrent_streams: passive.scenario.concurrent_streams,
                request_shape: passive.scenario.request_shape.clone(),
            },
            passive_tls: CaptureEvidenceRef {
                capture_artifact_id: passive.capture_artifact_id,
                capture_run_id: passive.capture_run_id,
                lane: passive.lane.clone(),
                normalized_sha256: passive.normalized_sha256.clone(),
                event_count: passive.event_count(),
            },
            controlled_http2: CaptureEvidenceRef {
                capture_artifact_id: controlled.capture_artifact_id,
                capture_run_id: controlled.capture_run_id,
                lane: controlled.lane.clone(),
                normalized_sha256: controlled.normalized_sha256.clone(),
                event_count: controlled.event_count(),
            },
            verification: ManifestVerification {
                normalizer_version: "1".to_owned(),
                paired_fields_verified: true,
                secret_scan_passed: true,
                verified_at: Some("2026-08-22T00:00:00Z".to_owned()),
                evidence_notes: vec![],
            },
        }
    }

    fn options() -> BundleCompilerOptions {
        BundleCompilerOptions::production_defaults(
            "claude-code/linux/x86_64/bun/fixture".to_owned(),
            1,
        )
    }

    #[test]
    fn compiles_verified_bundle_without_secrets() {
        let (passive, controlled) = normalized_pair();
        assert_ne!(
            passive.scenario.expected_protocol,
            controlled.scenario.expected_protocol
        );
        let bundle = compile_bundle(
            &manifest(&passive, &controlled),
            &passive,
            &controlled,
            &options(),
        )
        .expect("compile bundle");
        verify_bundle(&bundle).expect("verify bundle");
        let encoded = serde_json::to_string(&bundle).expect("serialize bundle");
        assert!(!encoded.contains("TOP_SECRET"));
        assert_eq!(bundle.tls.dynamic_fields.len(), 1);
        let ApplicationProfileSpec::Http1(http1) = &bundle.application else {
            panic!("expected HTTP/1.1 profile");
        };
        assert_eq!(http1.version, "HTTP/1.1");
        assert_eq!(http1.body_bytes, 128);
        assert!(http1.content_length_framing);
        assert_eq!(
            bundle.headers.value_rules[1].mode,
            HeaderValueMode::CredentialDerivedSecret
        );
    }

    #[test]
    fn rejects_manifest_artifact_mismatch() {
        let (passive, controlled) = normalized_pair();
        let mut manifest = manifest(&passive, &controlled);
        manifest.passive_tls.capture_artifact_id = Uuid::new_v4();
        assert!(matches!(
            compile_bundle(&manifest, &passive, &controlled, &options()),
            Err(BundleError::EvidenceMismatch)
        ));
    }

    #[test]
    fn detects_bundle_tampering() {
        let (passive, controlled) = normalized_pair();
        let mut bundle = compile_bundle(
            &manifest(&passive, &controlled),
            &passive,
            &controlled,
            &options(),
        )
        .expect("compile bundle");
        let ApplicationProfileSpec::Http1(http1) = &mut bundle.application else {
            panic!("expected HTTP/1.1 profile");
        };
        http1.body_bytes += 1;
        assert!(matches!(
            verify_bundle(&bundle),
            Err(BundleError::IntegrityMismatch { .. })
        ));
    }

    #[test]
    fn rejects_rehashed_secret_value() {
        let (passive, controlled) = normalized_pair();
        let mut bundle = compile_bundle(
            &manifest(&passive, &controlled),
            &passive,
            &controlled,
            &options(),
        )
        .expect("compile bundle");
        bundle.headers.value_rules[1].exact_value = Some("TOP_SECRET".to_owned());
        bundle.bundle_sha256 = recompute_bundle_sha256(&bundle).expect("recompute bundle hash");
        assert!(matches!(
            verify_bundle(&bundle),
            Err(BundleError::SecretInBundle(_))
        ));
    }

    #[test]
    fn keeps_http2_bundle_path_available() {
        let (passive, controlled) = normalized_pair_with_protocol(false);
        let bundle = compile_bundle(
            &manifest(&passive, &controlled),
            &passive,
            &controlled,
            &options(),
        )
        .expect("compile HTTP/2 bundle");
        let ApplicationProfileSpec::Http2(http2) = &bundle.application else {
            panic!("expected HTTP/2 profile");
        };
        assert_eq!(http2.settings_order, vec![1]);
    }

    #[test]
    fn rejects_modified_normalized_evidence() {
        let (passive, mut controlled) = normalized_pair();
        controlled.scenario.id = "tampered".to_owned();
        controlled.normalized_sha256 =
            recompute_normalized_sha256(&controlled).expect("refresh fixture hash");
        assert!(matches!(
            compile_bundle(
                &manifest(&passive, &controlled),
                &passive,
                &controlled,
                &options()
            ),
            Err(BundleError::Manifest(_) | BundleError::EvidenceMismatch)
        ));
    }
}
