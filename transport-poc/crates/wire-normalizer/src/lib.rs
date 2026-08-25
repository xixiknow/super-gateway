#![forbid(unsafe_code)]

use capture_schema::{
    CancellationStage, CaptureBatch, CaptureEvent, CaptureLane, ConnectionPhase, Direction,
    DnsMode, Http2FrameDetail, Http2FrameType, Http2Setting, NetworkPath, ProtocolAction,
    ValidationError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

pub const NORMALIZER_VERSION: &str = "1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedCapture {
    pub schema_version: u32,
    pub normalizer_version: String,
    pub capture_artifact_id: Uuid,
    pub capture_run_id: Uuid,
    pub lane: CaptureLane,
    pub observed_at: String,
    pub environment: NormalizedEnvironment,
    pub target: NormalizedTarget,
    pub network: NormalizedNetwork,
    pub scenario: NormalizedScenario,
    pub events: Vec<NormalizedEvent>,
    pub normalized_sha256: String,
}

impl NormalizedCapture {
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedEnvironment {
    pub os_name: String,
    pub os_version: String,
    pub os_build: Option<String>,
    pub arch: String,
    pub kernel: Option<String>,
    pub claude_code_version: String,
    pub runtime_name: String,
    pub runtime_version: String,
    pub binary_sha256: Option<String>,
    pub labels: BTreeMap<String, ValueShape>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedTarget {
    pub target_class: String,
    pub official_anthropic: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedNetwork {
    pub path: NetworkPath,
    pub dns_mode: DnsMode,
    pub proxy_software: Option<String>,
    pub proxy_version: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedScenario {
    pub id: String,
    pub fresh_connection: bool,
    pub expected_protocol: String,
    pub concurrent_streams: u32,
    pub request_shape: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NormalizedEvent {
    TlsClientHello {
        connection_id: String,
        record_version: u16,
        legacy_version: u16,
        cipher_suites: Vec<u16>,
        extensions: Vec<NormalizedTlsExtension>,
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
        detail: NormalizedHttp2FrameDetail,
    },
    Http1Request {
        connection_id: String,
        method: String,
        path: ValueShape,
        version: String,
        headers: Vec<NormalizedHeader>,
        body_bytes: u32,
    },
    ConnectionLifecycle {
        connection_id: String,
        phase: ConnectionPhase,
        timing_bucket: TimingBucket,
        negotiated_protocol: Option<String>,
        resumed: Option<bool>,
    },
    SseChunk {
        connection_id: String,
        stream_id: u32,
        sequence: u64,
        byte_len: u32,
        content_hash_present: bool,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedTlsExtension {
    pub extension_type: u16,
    pub name: String,
    pub position: u16,
    pub encoded_len: u32,
    pub attributes: Vec<NormalizedTlsAttribute>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedTlsAttribute {
    pub name: String,
    pub dynamic: bool,
    pub value: Option<String>,
    pub value_shape: ValueShape,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NormalizedHttp2FrameDetail {
    Settings {
        entries: Vec<Http2Setting>,
    },
    WindowUpdate {
        increment: u32,
    },
    Headers {
        headers: Vec<NormalizedHeader>,
    },
    Data {
        content_hash_present: bool,
    },
    Priority {
        exclusive: bool,
        dependency: u32,
        weight: u16,
    },
    Ping {
        ack: bool,
        opaque_hash_present: bool,
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
        summary_shape: ValueShape,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedHeader {
    pub wire_name: String,
    pub canonical_name: String,
    pub value: Option<String>,
    pub value_shape: ValueShape,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValueShape {
    pub kind: ValueKind,
    pub bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValueKind {
    Empty,
    Secret,
    Uuid,
    Hex,
    Integer,
    Base64Like,
    Ascii,
    Utf8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimingBucket {
    UnderOneMillisecond,
    OneToFiveMilliseconds,
    FiveToTwentyMilliseconds,
    TwentyToOneHundredMilliseconds,
    OneHundredMillisecondsToOneSecond,
    OneToFiveSeconds,
    OverFiveSeconds,
}

/// Validates and converts a raw collector batch into its persistence-safe form.
///
/// # Errors
///
/// Returns [`NormalizationError`] when source validation fails or the
/// normalized representation cannot be serialized for integrity hashing.
pub fn normalize_capture(batch: &CaptureBatch) -> Result<NormalizedCapture, NormalizationError> {
    batch.validate()?;

    let mut connection_ids = BTreeMap::<String, String>::new();
    let mut next_connection = 1_u64;
    let events = batch
        .events
        .iter()
        .map(|event| normalize_event(event, &mut connection_ids, &mut next_connection))
        .collect::<Vec<_>>();

    let environment = NormalizedEnvironment {
        os_name: batch.environment.os_name.clone(),
        os_version: batch.environment.os_version.clone(),
        os_build: batch.environment.os_build.clone(),
        arch: batch.environment.arch.clone(),
        kernel: batch.environment.kernel.clone(),
        claude_code_version: batch.environment.claude_code_version.clone(),
        runtime_name: batch.environment.runtime_name.clone(),
        runtime_version: batch.environment.runtime_version.clone(),
        binary_sha256: batch.environment.binary_sha256.clone(),
        labels: batch
            .environment
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value_shape(value, false)))
            .collect(),
    };
    let target = NormalizedTarget {
        target_class: if batch.target.official_anthropic {
            "anthropic_official".to_owned()
        } else {
            "capture_endpoint".to_owned()
        },
        official_anthropic: batch.target.official_anthropic,
    };
    let network = NormalizedNetwork {
        path: batch.network.path.clone(),
        dns_mode: batch.network.dns_mode.clone(),
        proxy_software: batch.network.proxy_software.clone(),
        proxy_version: batch.network.proxy_version.clone(),
    };
    let scenario = NormalizedScenario {
        id: batch.scenario.id.clone(),
        fresh_connection: batch.scenario.fresh_connection,
        expected_protocol: batch.scenario.expected_protocol.clone(),
        concurrent_streams: batch.scenario.concurrent_streams,
        request_shape: batch.scenario.request_shape.clone(),
    };

    let unsigned = UnsignedNormalizedCapture {
        schema_version: batch.schema_version,
        normalizer_version: NORMALIZER_VERSION,
        capture_artifact_id: batch.capture_artifact_id,
        capture_run_id: batch.capture_run_id,
        lane: &batch.lane,
        observed_at: &batch.observed_at,
        environment: &environment,
        target: &target,
        network: &network,
        scenario: &scenario,
        events: &events,
    };
    let normalized_sha256 = hash_unsigned(&unsigned)?;

    Ok(NormalizedCapture {
        schema_version: batch.schema_version,
        normalizer_version: NORMALIZER_VERSION.to_owned(),
        capture_artifact_id: batch.capture_artifact_id,
        capture_run_id: batch.capture_run_id,
        lane: batch.lane.clone(),
        observed_at: batch.observed_at.clone(),
        environment,
        target,
        network,
        scenario,
        events,
        normalized_sha256,
    })
}

/// Recomputes the persistence integrity digest without trusting the embedded hash.
///
/// # Errors
///
/// Returns [`NormalizationError`] if the normalized structure cannot be encoded.
pub fn recompute_normalized_sha256(
    capture: &NormalizedCapture,
) -> Result<String, NormalizationError> {
    hash_unsigned(&UnsignedNormalizedCapture {
        schema_version: capture.schema_version,
        normalizer_version: &capture.normalizer_version,
        capture_artifact_id: capture.capture_artifact_id,
        capture_run_id: capture.capture_run_id,
        lane: &capture.lane,
        observed_at: &capture.observed_at,
        environment: &capture.environment,
        target: &capture.target,
        network: &capture.network,
        scenario: &capture.scenario,
        events: &capture.events,
    })
}

/// Verifies that a persisted normalized capture still matches its embedded digest.
///
/// # Errors
///
/// Returns [`NormalizationError::IntegrityMismatch`] when content has changed and
/// propagates encoding failures from digest recomputation.
pub fn verify_normalized_capture(capture: &NormalizedCapture) -> Result<(), NormalizationError> {
    verify_privacy_invariants(capture)?;
    let actual = recompute_normalized_sha256(capture)?;
    if actual == capture.normalized_sha256 {
        Ok(())
    } else {
        Err(NormalizationError::IntegrityMismatch {
            expected: capture.normalized_sha256.clone(),
            actual,
        })
    }
}

/// Checks that a normalized artifact contains only persistence-safe forms.
///
/// # Errors
///
/// Returns [`NormalizationError::PrivacyInvariant`] when a dynamic TLS value,
/// secret header, raw connection identifier, or target identity survives.
pub fn verify_privacy_invariants(capture: &NormalizedCapture) -> Result<(), NormalizationError> {
    let expected_target = if capture.target.official_anthropic {
        "anthropic_official"
    } else {
        "capture_endpoint"
    };
    if capture.target.target_class != expected_target
        || capture.lane.is_official() != capture.target.official_anthropic
    {
        return Err(NormalizationError::PrivacyInvariant(
            "target class and capture lane are inconsistent".to_owned(),
        ));
    }
    for (event_index, event) in capture.events.iter().enumerate() {
        let connection_id = normalized_event_connection_id(event);
        if !is_normalized_connection_id(connection_id) {
            return Err(NormalizationError::PrivacyInvariant(format!(
                "event {event_index} contains a raw connection identifier"
            )));
        }
        match event {
            NormalizedEvent::TlsClientHello { extensions, .. } => {
                for extension in extensions {
                    for attribute in &extension.attributes {
                        if (attribute.dynamic || is_tls_secret_attribute(&attribute.name))
                            && attribute.value.is_some()
                        {
                            return Err(NormalizationError::PrivacyInvariant(format!(
                                "event {event_index} contains a dynamic TLS value"
                            )));
                        }
                    }
                }
            }
            NormalizedEvent::Http2Frame {
                detail: NormalizedHttp2FrameDetail::Headers { headers },
                ..
            }
            | NormalizedEvent::Http1Request { headers, .. } => {
                for header in headers {
                    if is_secret_header(&header.canonical_name)
                        && (header.value.is_some() || header.value_shape.kind != ValueKind::Secret)
                    {
                        return Err(NormalizationError::PrivacyInvariant(format!(
                            "event {event_index} contains a secret header value"
                        )));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn normalized_event_connection_id(event: &NormalizedEvent) -> &str {
    match event {
        NormalizedEvent::TlsClientHello { connection_id, .. }
        | NormalizedEvent::Http2Frame { connection_id, .. }
        | NormalizedEvent::Http1Request { connection_id, .. }
        | NormalizedEvent::ConnectionLifecycle { connection_id, .. }
        | NormalizedEvent::SseChunk { connection_id, .. }
        | NormalizedEvent::Cancellation { connection_id, .. } => connection_id,
    }
}

fn is_normalized_connection_id(value: &str) -> bool {
    value.strip_prefix("conn-").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn hash_unsigned(unsigned: &UnsignedNormalizedCapture<'_>) -> Result<String, NormalizationError> {
    let encoded = serde_json::to_vec(unsigned)?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

#[derive(Serialize)]
struct UnsignedNormalizedCapture<'a> {
    schema_version: u32,
    normalizer_version: &'a str,
    capture_artifact_id: Uuid,
    capture_run_id: Uuid,
    lane: &'a CaptureLane,
    observed_at: &'a str,
    environment: &'a NormalizedEnvironment,
    target: &'a NormalizedTarget,
    network: &'a NormalizedNetwork,
    scenario: &'a NormalizedScenario,
    events: &'a [NormalizedEvent],
}

// Keeping all variants together makes the raw-to-normalized exhaustiveness
// boundary auditable when a new wire event is introduced.
#[allow(clippy::too_many_lines)]
fn normalize_event(
    event: &CaptureEvent,
    connection_ids: &mut BTreeMap<String, String>,
    next_connection: &mut u64,
) -> NormalizedEvent {
    match event {
        CaptureEvent::TlsClientHello {
            connection_id,
            record_version,
            legacy_version,
            cipher_suites,
            extensions,
            alpn,
            client_hello_len,
            record_lengths,
        } => NormalizedEvent::TlsClientHello {
            connection_id: normalize_connection_id(connection_id, connection_ids, next_connection),
            record_version: *record_version,
            legacy_version: *legacy_version,
            cipher_suites: cipher_suites.clone(),
            extensions: extensions
                .iter()
                .map(|extension| NormalizedTlsExtension {
                    extension_type: extension.extension_type,
                    name: extension.name.clone(),
                    position: extension.position,
                    encoded_len: extension.encoded_len,
                    attributes: extension
                        .attributes
                        .iter()
                        .map(|attribute| {
                            let forced_dynamic = is_tls_secret_attribute(&attribute.name);
                            let dynamic = attribute.dynamic || forced_dynamic;
                            NormalizedTlsAttribute {
                                name: attribute.name.clone(),
                                dynamic,
                                value: (!dynamic).then(|| attribute.value.clone()),
                                value_shape: value_shape(&attribute.value, forced_dynamic),
                            }
                        })
                        .collect(),
                })
                .collect(),
            alpn: alpn.clone(),
            client_hello_len: *client_hello_len,
            record_lengths: record_lengths.clone(),
        },
        CaptureEvent::Http2Frame {
            connection_id,
            direction,
            sequence,
            stream_id,
            frame_type,
            flags,
            length,
            detail,
        } => NormalizedEvent::Http2Frame {
            connection_id: normalize_connection_id(connection_id, connection_ids, next_connection),
            direction: direction.clone(),
            sequence: *sequence,
            stream_id: *stream_id,
            frame_type: frame_type.clone(),
            flags: flags.clone(),
            length: *length,
            detail: normalize_h2_detail(detail),
        },
        CaptureEvent::Http1Request {
            connection_id,
            method,
            path,
            version,
            headers,
            body_bytes,
        } => NormalizedEvent::Http1Request {
            connection_id: normalize_connection_id(connection_id, connection_ids, next_connection),
            method: method.clone(),
            path: value_shape(path, false),
            version: version.clone(),
            headers: normalize_headers(headers),
            body_bytes: *body_bytes,
        },
        CaptureEvent::ConnectionLifecycle {
            connection_id,
            phase,
            offset_micros,
            negotiated_protocol,
            resumed,
        } => NormalizedEvent::ConnectionLifecycle {
            connection_id: normalize_connection_id(connection_id, connection_ids, next_connection),
            phase: phase.clone(),
            timing_bucket: timing_bucket(*offset_micros),
            negotiated_protocol: negotiated_protocol.clone(),
            resumed: *resumed,
        },
        CaptureEvent::SseChunk {
            connection_id,
            stream_id,
            sequence,
            byte_len,
            content_sha256,
            event_type,
        } => NormalizedEvent::SseChunk {
            connection_id: normalize_connection_id(connection_id, connection_ids, next_connection),
            stream_id: *stream_id,
            sequence: *sequence,
            byte_len: *byte_len,
            content_hash_present: content_sha256.is_some(),
            event_type: event_type.clone(),
        },
        CaptureEvent::Cancellation {
            connection_id,
            stream_id,
            stage,
            protocol_action,
            other_streams_affected,
        } => NormalizedEvent::Cancellation {
            connection_id: normalize_connection_id(connection_id, connection_ids, next_connection),
            stream_id: *stream_id,
            stage: stage.clone(),
            protocol_action: protocol_action.clone(),
            other_streams_affected: *other_streams_affected,
        },
    }
}

fn normalize_h2_detail(detail: &Http2FrameDetail) -> NormalizedHttp2FrameDetail {
    match detail {
        Http2FrameDetail::Settings { entries } => NormalizedHttp2FrameDetail::Settings {
            entries: entries.clone(),
        },
        Http2FrameDetail::WindowUpdate { increment } => NormalizedHttp2FrameDetail::WindowUpdate {
            increment: *increment,
        },
        Http2FrameDetail::Headers { headers } => NormalizedHttp2FrameDetail::Headers {
            headers: normalize_headers(headers),
        },
        Http2FrameDetail::Data { content_sha256 } => NormalizedHttp2FrameDetail::Data {
            content_hash_present: content_sha256.is_some(),
        },
        Http2FrameDetail::Priority {
            exclusive,
            dependency,
            weight,
        } => NormalizedHttp2FrameDetail::Priority {
            exclusive: *exclusive,
            dependency: *dependency,
            weight: *weight,
        },
        Http2FrameDetail::Ping { ack, opaque_sha256 } => NormalizedHttp2FrameDetail::Ping {
            ack: *ack,
            opaque_hash_present: opaque_sha256.is_some(),
        },
        Http2FrameDetail::RstStream { error_code } => NormalizedHttp2FrameDetail::RstStream {
            error_code: *error_code,
        },
        Http2FrameDetail::GoAway {
            last_stream_id,
            error_code,
        } => NormalizedHttp2FrameDetail::GoAway {
            last_stream_id: *last_stream_id,
            error_code: *error_code,
        },
        Http2FrameDetail::Empty => NormalizedHttp2FrameDetail::Empty,
        Http2FrameDetail::Other { summary } => NormalizedHttp2FrameDetail::Other {
            summary_shape: value_shape(summary, false),
        },
    }
}

fn normalize_headers(headers: &[capture_schema::HeaderObservation]) -> Vec<NormalizedHeader> {
    headers
        .iter()
        .map(|header| {
            let canonical_name = header.name.to_ascii_lowercase();
            let preserve = is_safe_exact_header(&canonical_name);
            let secret = is_secret_header(&canonical_name);
            NormalizedHeader {
                wire_name: header.name.clone(),
                canonical_name,
                value: (preserve && !secret).then(|| header.value.clone()),
                value_shape: value_shape(&header.value, secret),
            }
        })
        .collect()
}

fn normalize_connection_id(
    raw: &str,
    connection_ids: &mut BTreeMap<String, String>,
    next_connection: &mut u64,
) -> String {
    if let Some(existing) = connection_ids.get(raw) {
        return existing.clone();
    }
    let normalized = format!("conn-{next_connection}");
    *next_connection += 1;
    connection_ids.insert(raw.to_owned(), normalized.clone());
    normalized
}

fn is_tls_secret_attribute(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    [
        "client_random",
        "key_share_bytes",
        "psk_identity",
        "session_id",
        "session_ticket",
        "ticket",
    ]
    .iter()
    .any(|candidate| normalized.contains(candidate))
}

fn is_secret_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "cookie"
            | "proxy-authorization"
            | "set-cookie"
            | "x-api-key"
            | "x-client-request-id"
            | "x-claude-code-session-id"
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

fn is_safe_exact_header(name: &str) -> bool {
    matches!(
        name,
        ":method"
            | ":scheme"
            | "accept"
            | "accept-encoding"
            | "anthropic-beta"
            | "anthropic-version"
            | "content-type"
            | "user-agent"
            | "x-app"
            | "x-stainless-arch"
            | "x-stainless-lang"
            | "x-stainless-os"
            | "x-stainless-package-version"
            | "x-stainless-retry-count"
            | "x-stainless-runtime"
            | "x-stainless-runtime-version"
            | "x-stainless-timeout"
    )
}

fn value_shape(value: &str, secret: bool) -> ValueShape {
    let kind = if secret {
        ValueKind::Secret
    } else if value.is_empty() {
        ValueKind::Empty
    } else if Uuid::parse_str(value).is_ok() {
        ValueKind::Uuid
    } else if value.len() >= 8
        && value.len().is_multiple_of(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        ValueKind::Hex
    } else if value.bytes().all(|byte| byte.is_ascii_digit()) {
        ValueKind::Integer
    } else if value.len() >= 16
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-' | b'=')
        })
    {
        ValueKind::Base64Like
    } else if value.is_ascii() {
        ValueKind::Ascii
    } else {
        ValueKind::Utf8
    };
    ValueShape {
        kind,
        bytes: value.len(),
    }
}

fn timing_bucket(offset_micros: u64) -> TimingBucket {
    match offset_micros {
        0..1_000 => TimingBucket::UnderOneMillisecond,
        1_000..5_000 => TimingBucket::OneToFiveMilliseconds,
        5_000..20_000 => TimingBucket::FiveToTwentyMilliseconds,
        20_000..100_000 => TimingBucket::TwentyToOneHundredMilliseconds,
        100_000..1_000_000 => TimingBucket::OneHundredMillisecondsToOneSecond,
        1_000_000..5_000_000 => TimingBucket::OneToFiveSeconds,
        _ => TimingBucket::OverFiveSeconds,
    }
}

#[derive(Debug, Error)]
pub enum NormalizationError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("failed to encode normalized capture: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("normalized capture integrity mismatch: expected {expected}, actual {actual}")]
    IntegrityMismatch { expected: String, actual: String },
    #[error("normalized capture privacy invariant failed: {0}")]
    PrivacyInvariant(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use capture_schema::{
        CAPTURE_SCHEMA_VERSION, DnsMode, EnvironmentDescriptor, HeaderObservation,
        NetworkDescriptor, NetworkPath, ScenarioDescriptor, TargetDescriptor,
    };

    fn batch_with_headers(headers: Vec<HeaderObservation>) -> CaptureBatch {
        CaptureBatch {
            schema_version: CAPTURE_SCHEMA_VERSION,
            capture_artifact_id: Uuid::new_v4(),
            capture_run_id: Uuid::new_v4(),
            lane: capture_schema::CaptureLane::ReferenceControlledEndpoint,
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
                authority: "internal.capture.invalid:443".to_owned(),
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
            events: vec![CaptureEvent::Http2Frame {
                connection_id: "secret-connection-id".to_owned(),
                direction: Direction::ClientToServer,
                sequence: 1,
                stream_id: 1,
                frame_type: Http2FrameType::Headers,
                flags: vec!["end_headers".to_owned()],
                length: 10,
                detail: Http2FrameDetail::Headers { headers },
            }],
        }
    }

    #[test]
    fn strips_secret_headers_and_internal_target() {
        let batch = batch_with_headers(vec![
            HeaderObservation {
                name: "authorization".to_owned(),
                value: "Bearer TOP_SECRET".to_owned(),
            },
            HeaderObservation {
                name: "user-agent".to_owned(),
                value: "claude-cli/test".to_owned(),
            },
        ]);

        let normalized = normalize_capture(&batch).expect("normalization succeeds");
        let serialized = serde_json::to_string(&normalized).expect("serialization succeeds");
        assert!(!serialized.contains("TOP_SECRET"));
        assert!(!serialized.contains("internal.capture.invalid"));
        assert!(!serialized.contains("secret-connection-id"));
        assert!(serialized.contains("claude-cli/test"));
        assert!(serialized.contains("capture_endpoint"));
    }

    #[test]
    fn preserves_header_order() {
        let batch = batch_with_headers(vec![
            HeaderObservation {
                name: ":method".to_owned(),
                value: "POST".to_owned(),
            },
            HeaderObservation {
                name: "user-agent".to_owned(),
                value: "claude-cli/test".to_owned(),
            },
            HeaderObservation {
                name: "authorization".to_owned(),
                value: "Bearer secret".to_owned(),
            },
        ]);

        let normalized = normalize_capture(&batch).expect("normalization succeeds");
        let NormalizedEvent::Http2Frame {
            detail: NormalizedHttp2FrameDetail::Headers { headers },
            ..
        } = &normalized.events[0]
        else {
            panic!("expected normalized headers event");
        };
        assert_eq!(headers[0].canonical_name, ":method");
        assert_eq!(headers[1].canonical_name, "user-agent");
        assert_eq!(headers[2].canonical_name, "authorization");
        assert_eq!(headers[2].value, None);
        assert_eq!(headers[2].value_shape.kind, ValueKind::Secret);
    }

    #[test]
    fn normalizes_http1_path_and_secrets_without_losing_header_order() {
        let mut batch = batch_with_headers(vec![]);
        batch.scenario.expected_protocol = "http/1.1".to_owned();
        batch.events = vec![CaptureEvent::Http1Request {
            connection_id: "raw-http1-connection".to_owned(),
            method: "POST".to_owned(),
            path: "/v1/messages?private=value".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: vec![
                HeaderObservation {
                    name: "User-Agent".to_owned(),
                    value: "claude-cli/test".to_owned(),
                },
                HeaderObservation {
                    name: "Authorization".to_owned(),
                    value: "Bearer TOP_SECRET".to_owned(),
                },
            ],
            body_bytes: 2048,
        }];

        let normalized = normalize_capture(&batch).expect("normalization succeeds");
        let serialized = serde_json::to_string(&normalized).expect("serialization succeeds");
        assert!(!serialized.contains("private=value"));
        assert!(!serialized.contains("TOP_SECRET"));
        assert!(!serialized.contains("raw-http1-connection"));
        let NormalizedEvent::Http1Request { headers, path, .. } = &normalized.events[0] else {
            panic!("expected normalized HTTP/1.1 request");
        };
        assert_eq!(headers[0].canonical_name, "user-agent");
        assert_eq!(headers[1].canonical_name, "authorization");
        assert_eq!(headers[1].value_shape.kind, ValueKind::Secret);
        assert_eq!(path.bytes, "/v1/messages?private=value".len());
    }

    #[test]
    fn detects_persisted_capture_tampering() {
        let batch = batch_with_headers(vec![HeaderObservation {
            name: "user-agent".to_owned(),
            value: "claude-cli/test".to_owned(),
        }]);
        let mut normalized = normalize_capture(&batch).expect("normalization succeeds");
        verify_normalized_capture(&normalized).expect("original digest is valid");
        normalized.scenario.id = "tampered".to_owned();
        assert!(matches!(
            verify_normalized_capture(&normalized),
            Err(NormalizationError::IntegrityMismatch { .. })
        ));
    }

    #[test]
    fn rejects_rehashed_secret_header_value() {
        let batch = batch_with_headers(vec![HeaderObservation {
            name: "x-session-id".to_owned(),
            value: "secret-session".to_owned(),
        }]);
        let mut normalized = normalize_capture(&batch).expect("normalization succeeds");
        let NormalizedEvent::Http2Frame {
            detail: NormalizedHttp2FrameDetail::Headers { headers },
            ..
        } = &mut normalized.events[0]
        else {
            panic!("expected header event");
        };
        assert_eq!(headers[0].value_shape.kind, ValueKind::Secret);
        headers[0].value = Some("secret-session".to_owned());
        normalized.normalized_sha256 =
            recompute_normalized_sha256(&normalized).expect("recompute hash");
        assert!(matches!(
            verify_normalized_capture(&normalized),
            Err(NormalizationError::PrivacyInvariant(_))
        ));
    }
}
