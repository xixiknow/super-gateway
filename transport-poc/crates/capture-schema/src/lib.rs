#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const CAPTURE_SCHEMA_VERSION: u32 = 2;
pub const CAPTURE_MANIFEST_SCHEMA_VERSION: u32 = 2;
pub const MAX_CAPTURE_EVENTS: usize = 100_000;
pub const MAX_HEADER_VALUE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureBatch {
    pub schema_version: u32,
    pub capture_artifact_id: Uuid,
    pub capture_run_id: Uuid,
    pub lane: CaptureLane,
    pub observed_at: String,
    pub environment: EnvironmentDescriptor,
    pub target: TargetDescriptor,
    pub network: NetworkDescriptor,
    pub scenario: ScenarioDescriptor,
    pub events: Vec<CaptureEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEnvironmentDescriptor {
    pub os_name: String,
    pub os_version: String,
    pub os_build: Option<String>,
    pub arch: String,
    pub kernel: Option<String>,
    pub claude_code_version: String,
    pub runtime_name: String,
    pub runtime_version: String,
    pub binary_sha256: Option<String>,
}

impl CaptureBatch {
    /// Validates structural invariants before a batch enters normalization.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when the schema version, required fields,
    /// event limits, header syntax, or per-connection sequence invariants fail.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != CAPTURE_SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchema(self.schema_version));
        }
        if self.capture_run_id.is_nil() {
            return Err(ValidationError::NilCaptureRunId);
        }
        if self.capture_artifact_id.is_nil() {
            return Err(ValidationError::NilCaptureArtifactId);
        }
        require_non_empty("observed_at", &self.observed_at)?;
        require_non_empty("environment.os_name", &self.environment.os_name)?;
        require_non_empty("environment.os_version", &self.environment.os_version)?;
        require_non_empty("environment.arch", &self.environment.arch)?;
        require_non_empty(
            "environment.claude_code_version",
            &self.environment.claude_code_version,
        )?;
        require_non_empty("target.authority", &self.target.authority)?;
        require_non_empty("scenario.id", &self.scenario.id)?;
        if self.lane.is_official() != self.target.official_anthropic {
            return Err(ValidationError::LaneTargetMismatch);
        }

        if self.events.len() > MAX_CAPTURE_EVENTS {
            return Err(ValidationError::TooManyEvents(self.events.len()));
        }

        let mut h2_sequences = BTreeSet::new();
        for event in &self.events {
            event.validate(&mut h2_sequences)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CaptureLane {
    ReferenceOfficialTls,
    ReferenceControlledEndpoint,
    ReplayOfficialTls,
    ReplayControlledEndpoint,
}

impl CaptureLane {
    pub fn is_official(&self) -> bool {
        matches!(self, Self::ReferenceOfficialTls | Self::ReplayOfficialTls)
    }

    pub fn is_reference(&self) -> bool {
        matches!(
            self,
            Self::ReferenceOfficialTls | Self::ReferenceControlledEndpoint
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureManifest {
    pub schema_version: u32,
    pub manifest_id: Uuid,
    pub capture_run_id: Uuid,
    pub created_at: String,
    pub state: CaptureManifestState,
    pub environment: ManifestEnvironmentDescriptor,
    pub scenario: ManifestScenarioDescriptor,
    pub passive_tls: CaptureEvidenceRef,
    pub controlled_http2: CaptureEvidenceRef,
    pub verification: ManifestVerification,
}

impl CaptureManifest {
    /// Validates two-lane evidence pairing and verified-state requirements.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when identifiers, lane roles, hashes,
    /// environment metadata, or verification state are inconsistent.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != CAPTURE_MANIFEST_SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedManifestSchema(
                self.schema_version,
            ));
        }
        if self.manifest_id.is_nil() {
            return Err(ValidationError::NilManifestId);
        }
        if self.capture_run_id.is_nil() {
            return Err(ValidationError::NilCaptureRunId);
        }
        require_non_empty("manifest.created_at", &self.created_at)?;
        require_non_empty("manifest.environment.os_name", &self.environment.os_name)?;
        require_non_empty(
            "manifest.environment.claude_code_version",
            &self.environment.claude_code_version,
        )?;
        require_non_empty("manifest.scenario.id", &self.scenario.id)?;
        require_non_empty(
            "manifest.scenario.request_shape",
            &self.scenario.request_shape,
        )?;
        self.passive_tls.validate()?;
        self.controlled_http2.validate()?;
        if self.passive_tls.capture_run_id != self.capture_run_id
            || self.controlled_http2.capture_run_id != self.capture_run_id
        {
            return Err(ValidationError::ManifestRunMismatch);
        }
        if self.passive_tls.capture_artifact_id == self.controlled_http2.capture_artifact_id {
            return Err(ValidationError::DuplicateManifestArtifact);
        }
        if !matches!(self.passive_tls.lane, CaptureLane::ReferenceOfficialTls)
            || !matches!(
                self.controlled_http2.lane,
                CaptureLane::ReferenceControlledEndpoint
            )
        {
            return Err(ValidationError::ManifestLaneMismatch);
        }
        if matches!(
            self.state,
            CaptureManifestState::Verified
                | CaptureManifestState::Canary
                | CaptureManifestState::Active
        ) && (!self.verification.paired_fields_verified
            || !self.verification.secret_scan_passed
            || self.verification.verified_at.is_none())
        {
            return Err(ValidationError::IncompleteManifestVerification);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureManifestState {
    Draft,
    Verified,
    Canary,
    Active,
    Retired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureEvidenceRef {
    pub capture_artifact_id: Uuid,
    pub capture_run_id: Uuid,
    pub lane: CaptureLane,
    pub normalized_sha256: String,
    pub event_count: usize,
}

impl CaptureEvidenceRef {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.capture_artifact_id.is_nil() {
            return Err(ValidationError::NilCaptureArtifactId);
        }
        if self.capture_run_id.is_nil() {
            return Err(ValidationError::NilCaptureRunId);
        }
        if !is_lower_hex_sha256(&self.normalized_sha256) {
            return Err(ValidationError::InvalidEvidenceHash);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestVerification {
    pub normalizer_version: String,
    pub paired_fields_verified: bool,
    pub secret_scan_passed: bool,
    pub verified_at: Option<String>,
    #[serde(default)]
    pub evidence_notes: Vec<String>,
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentDescriptor {
    pub os_name: String,
    pub os_version: String,
    pub os_build: Option<String>,
    pub arch: String,
    pub kernel: Option<String>,
    pub claude_code_version: String,
    pub runtime_name: String,
    pub runtime_version: String,
    pub binary_sha256: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetDescriptor {
    pub authority: String,
    pub official_anthropic: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkDescriptor {
    pub path: NetworkPath,
    pub dns_mode: DnsMode,
    pub proxy_software: Option<String>,
    pub proxy_version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPath {
    Direct,
    HttpConnect,
    Socks5,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    Local,
    Remote,
    NotApplicable,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioDescriptor {
    pub id: String,
    pub fresh_connection: bool,
    pub expected_protocol: String,
    pub concurrent_streams: u32,
    pub request_shape: String,
}

/// Logical scenario fields that must match across both evidence lanes.
///
/// Negotiated protocol remains lane-local on [`ScenarioDescriptor`], because
/// official passive TLS and the controlled endpoint may legitimately negotiate
/// different protocols while exercising the same logical request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestScenarioDescriptor {
    pub id: String,
    pub fresh_connection: bool,
    pub concurrent_streams: u32,
    pub request_shape: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaptureEvent {
    TlsClientHello {
        connection_id: String,
        record_version: u16,
        legacy_version: u16,
        cipher_suites: Vec<u16>,
        extensions: Vec<TlsExtensionObservation>,
        alpn: Vec<String>,
        client_hello_len: u32,
        record_lengths: Vec<u32>,
    },
    Http2Frame {
        connection_id: String,
        direction: Direction,
        sequence: u64,
        stream_id: u32,
        frame_type: Http2FrameType,
        flags: Vec<String>,
        length: u32,
        detail: Http2FrameDetail,
    },
    Http1Request {
        connection_id: String,
        method: String,
        path: String,
        version: String,
        headers: Vec<HeaderObservation>,
        body_bytes: u32,
    },
    ConnectionLifecycle {
        connection_id: String,
        phase: ConnectionPhase,
        offset_micros: u64,
        negotiated_protocol: Option<String>,
        resumed: Option<bool>,
    },
    SseChunk {
        connection_id: String,
        stream_id: u32,
        sequence: u64,
        byte_len: u32,
        content_sha256: Option<String>,
        event_type: Option<String>,
    },
    Cancellation {
        connection_id: String,
        stream_id: Option<u32>,
        stage: CancellationStage,
        protocol_action: ProtocolAction,
        other_streams_affected: bool,
    },
}

impl CaptureEvent {
    fn validate(&self, h2_sequences: &mut BTreeSet<(String, u64)>) -> Result<(), ValidationError> {
        match self {
            Self::TlsClientHello {
                connection_id,
                extensions,
                alpn,
                ..
            } => {
                require_non_empty("event.connection_id", connection_id)?;
                let mut positions = BTreeSet::new();
                for extension in extensions {
                    if !positions.insert(extension.position) {
                        return Err(ValidationError::DuplicateTlsExtensionPosition(
                            extension.position,
                        ));
                    }
                    require_non_empty("tls_extension.name", &extension.name)?;
                    for attribute in &extension.attributes {
                        require_non_empty("tls_attribute.name", &attribute.name)?;
                        if attribute.value.len() > MAX_HEADER_VALUE_BYTES {
                            return Err(ValidationError::FieldTooLarge {
                                field: format!("tls_attribute.{}", attribute.name),
                                bytes: attribute.value.len(),
                            });
                        }
                    }
                }
                for protocol in alpn {
                    require_non_empty("tls.alpn", protocol)?;
                }
            }
            Self::Http2Frame {
                connection_id,
                sequence,
                detail,
                ..
            } => {
                require_non_empty("event.connection_id", connection_id)?;
                if !h2_sequences.insert((connection_id.clone(), *sequence)) {
                    return Err(ValidationError::DuplicateHttp2Sequence {
                        connection_id: connection_id.clone(),
                        sequence: *sequence,
                    });
                }
                detail.validate()?;
            }
            Self::Http1Request {
                connection_id,
                method,
                path,
                version,
                headers,
                ..
            } => {
                require_non_empty("event.connection_id", connection_id)?;
                require_non_empty("http1.method", method)?;
                require_non_empty("http1.path", path)?;
                require_non_empty("http1.version", version)?;
                for header in headers {
                    validate_header(header)?;
                }
            }
            Self::ConnectionLifecycle { connection_id, .. }
            | Self::SseChunk { connection_id, .. }
            | Self::Cancellation { connection_id, .. } => {
                require_non_empty("event.connection_id", connection_id)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsExtensionObservation {
    pub extension_type: u16,
    pub name: String,
    pub position: u16,
    pub encoded_len: u32,
    #[serde(default)]
    pub attributes: Vec<TlsAttributeObservation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsAttributeObservation {
    pub name: String,
    pub value: String,
    pub dynamic: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Http2FrameType {
    Settings,
    WindowUpdate,
    Headers,
    Continuation,
    Data,
    Priority,
    PriorityUpdate,
    Ping,
    RstStream,
    GoAway,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Http2FrameDetail {
    Settings {
        entries: Vec<Http2Setting>,
    },
    WindowUpdate {
        increment: u32,
    },
    Headers {
        headers: Vec<HeaderObservation>,
    },
    Data {
        content_sha256: Option<String>,
    },
    Priority {
        exclusive: bool,
        dependency: u32,
        weight: u16,
    },
    Ping {
        ack: bool,
        opaque_sha256: Option<String>,
    },
    RstStream {
        error_code: u32,
    },
    GoAway {
        last_stream_id: u32,
        error_code: u32,
    },
    Empty,
    Other {
        summary: String,
    },
}

impl Http2FrameDetail {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Headers { headers } => {
                for header in headers {
                    validate_header(header)?;
                }
            }
            Self::Other { summary } => require_non_empty("h2.other.summary", summary)?,
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http2Setting {
    pub id: u16,
    pub value: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderObservation {
    pub name: String,
    pub value: String,
}

fn validate_header(header: &HeaderObservation) -> Result<(), ValidationError> {
    if header.name.is_empty()
        || !header.name.is_ascii()
        || header
            .name
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(ValidationError::InvalidHeaderName(header.name.clone()));
    }
    if header.value.len() > MAX_HEADER_VALUE_BYTES {
        return Err(ValidationError::HeaderValueTooLarge {
            name: header.name.clone(),
            bytes: header.value.len(),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPhase {
    DnsStart,
    DnsComplete,
    TcpConnected,
    ProxyTunnelEstablished,
    TlsStarted,
    TlsEstablished,
    Http2PrefaceSent,
    Ready,
    Idle,
    Closed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CancellationStage {
    BeforeConnect,
    RequestUpload,
    AwaitingResponse,
    ResponseStreaming,
    ResponseDelivery,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolAction {
    None,
    RstStream,
    CloseConnection,
    GoAway,
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::EmptyField(field));
    }
    Ok(())
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("unsupported capture schema version {0}")]
    UnsupportedSchema(u32),
    #[error("capture_run_id must not be nil")]
    NilCaptureRunId,
    #[error("capture_artifact_id must not be nil")]
    NilCaptureArtifactId,
    #[error("capture lane does not match target class")]
    LaneTargetMismatch,
    #[error("unsupported capture manifest schema version {0}")]
    UnsupportedManifestSchema(u32),
    #[error("manifest_id must not be nil")]
    NilManifestId,
    #[error("manifest evidence does not share the manifest capture_run_id")]
    ManifestRunMismatch,
    #[error("manifest evidence must use distinct capture artifacts")]
    DuplicateManifestArtifact,
    #[error("manifest evidence lanes are not a reference official/controlled pair")]
    ManifestLaneMismatch,
    #[error("verified manifest is missing verification evidence")]
    IncompleteManifestVerification,
    #[error("evidence hash must be a lowercase SHA-256 hex digest")]
    InvalidEvidenceHash,
    #[error("required field {0} is empty")]
    EmptyField(&'static str),
    #[error("capture contains too many events: {0}")]
    TooManyEvents(usize),
    #[error("invalid header name: {0}")]
    InvalidHeaderName(String),
    #[error("header {name} is too large: {bytes} bytes")]
    HeaderValueTooLarge { name: String, bytes: usize },
    #[error("field {field} is too large: {bytes} bytes")]
    FieldTooLarge { field: String, bytes: usize },
    #[error("duplicate TLS extension position {0}")]
    DuplicateTlsExtensionPosition(u16),
    #[error("duplicate HTTP/2 sequence {sequence} for connection {connection_id}")]
    DuplicateHttp2Sequence {
        connection_id: String,
        sequence: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_batch() -> CaptureBatch {
        CaptureBatch {
            schema_version: CAPTURE_SCHEMA_VERSION,
            capture_artifact_id: Uuid::new_v4(),
            capture_run_id: Uuid::new_v4(),
            lane: CaptureLane::ReferenceControlledEndpoint,
            observed_at: "2026-08-22T00:00:00Z".to_owned(),
            environment: EnvironmentDescriptor {
                os_name: "linux".to_owned(),
                os_version: "test".to_owned(),
                os_build: None,
                arch: "x86_64".to_owned(),
                kernel: None,
                claude_code_version: "test".to_owned(),
                runtime_name: "bun".to_owned(),
                runtime_version: "test".to_owned(),
                binary_sha256: None,
                labels: BTreeMap::new(),
            },
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
            scenario: ScenarioDescriptor {
                id: "T01".to_owned(),
                fresh_connection: true,
                expected_protocol: "h2".to_owned(),
                concurrent_streams: 1,
                request_shape: "synthetic".to_owned(),
            },
            events: vec![],
        }
    }

    #[test]
    fn validates_minimal_batch() {
        minimal_batch().validate().expect("minimal batch is valid");
    }

    #[test]
    fn rejects_duplicate_h2_sequences() {
        let mut batch = minimal_batch();
        let event = CaptureEvent::Http2Frame {
            connection_id: "c1".to_owned(),
            direction: Direction::ClientToServer,
            sequence: 1,
            stream_id: 0,
            frame_type: Http2FrameType::Settings,
            flags: vec![],
            length: 0,
            detail: Http2FrameDetail::Settings { entries: vec![] },
        };
        batch.events = vec![event.clone(), event];

        assert!(matches!(
            batch.validate(),
            Err(ValidationError::DuplicateHttp2Sequence { .. })
        ));
    }

    #[test]
    fn rejects_header_control_characters() {
        let mut batch = minimal_batch();
        batch.events.push(CaptureEvent::Http2Frame {
            connection_id: "c1".to_owned(),
            direction: Direction::ClientToServer,
            sequence: 1,
            stream_id: 1,
            frame_type: Http2FrameType::Headers,
            flags: vec!["end_headers".to_owned()],
            length: 10,
            detail: Http2FrameDetail::Headers {
                headers: vec![HeaderObservation {
                    name: "bad\nname".to_owned(),
                    value: "value".to_owned(),
                }],
            },
        });

        assert!(matches!(
            batch.validate(),
            Err(ValidationError::InvalidHeaderName(_))
        ));
    }

    fn minimal_manifest() -> CaptureManifest {
        let run_id = Uuid::new_v4();
        CaptureManifest {
            schema_version: CAPTURE_MANIFEST_SCHEMA_VERSION,
            manifest_id: Uuid::new_v4(),
            capture_run_id: run_id,
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
                id: "T01".to_owned(),
                fresh_connection: true,
                concurrent_streams: 1,
                request_shape: "fixture".to_owned(),
            },
            passive_tls: CaptureEvidenceRef {
                capture_artifact_id: Uuid::new_v4(),
                capture_run_id: run_id,
                lane: CaptureLane::ReferenceOfficialTls,
                normalized_sha256: "a".repeat(64),
                event_count: 2,
            },
            controlled_http2: CaptureEvidenceRef {
                capture_artifact_id: Uuid::new_v4(),
                capture_run_id: run_id,
                lane: CaptureLane::ReferenceControlledEndpoint,
                normalized_sha256: "b".repeat(64),
                event_count: 3,
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

    #[test]
    fn validates_verified_two_lane_manifest() {
        minimal_manifest().validate().expect("manifest is valid");
    }

    #[test]
    fn rejects_manifest_with_mixed_run_ids() {
        let mut manifest = minimal_manifest();
        manifest.controlled_http2.capture_run_id = Uuid::new_v4();
        assert_eq!(
            manifest.validate(),
            Err(ValidationError::ManifestRunMismatch)
        );
    }

    #[test]
    fn rejects_lane_target_mismatch() {
        let mut batch = minimal_batch();
        batch.lane = CaptureLane::ReferenceOfficialTls;
        assert_eq!(batch.validate(), Err(ValidationError::LaneTargetMismatch));
    }
}
