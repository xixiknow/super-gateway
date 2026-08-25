#![forbid(unsafe_code)]

use capture_schema::CaptureLane;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;
use wire_normalizer::{
    NormalizationError, NormalizedCapture, NormalizedEvent, verify_normalized_capture,
};

pub const WIRE_DIFF_REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffPolicy {
    pub timing_bucket_tolerance: u8,
    pub max_findings: usize,
    #[serde(default)]
    pub allowed_differences: Vec<AllowedDifference>,
}

impl Default for DiffPolicy {
    fn default() -> Self {
        Self {
            timing_bucket_tolerance: 1,
            max_findings: 2_000,
            allowed_differences: vec![],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowedDifference {
    pub path: String,
    pub rationale: String,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireDiffReport {
    pub schema_version: u32,
    pub report_id: Uuid,
    pub reference: CaptureSummary,
    pub candidate: CaptureSummary,
    pub reference_comparison_sha256: String,
    pub candidate_comparison_sha256: String,
    pub match_level: DiffClassification,
    pub decision: DiffDecision,
    pub findings: Vec<DiffFinding>,
    pub summary: DiffSummary,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureSummary {
    pub capture_artifact_id: Uuid,
    pub capture_run_id: Uuid,
    pub lane: CaptureLane,
    pub normalized_sha256: String,
    pub os_name: String,
    pub arch: String,
    pub claude_code_version: String,
    pub runtime_name: String,
    pub runtime_version: String,
    pub target_class: String,
    pub scenario_id: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiffClassification {
    Exact,
    NormalizedExact,
    BehavioralMatch,
    UnclassifiedDrift,
    HardMismatch,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiffDecision {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffLayer {
    Input,
    Tls,
    Http2,
    Headers,
    Connection,
    Sse,
    Cancellation,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffFinding {
    pub path: String,
    pub layer: DiffLayer,
    pub classification: DiffClassification,
    pub reference: Value,
    pub candidate: Value,
    pub message: String,
    pub allowed_by: Option<AllowedDifference>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffSummary {
    pub total_differences: usize,
    pub emitted_findings: usize,
    pub truncated: bool,
    pub counts: BTreeMap<DiffClassification, usize>,
}

/// Compares two integrity-checked normalized captures and emits a gate decision.
///
/// # Errors
///
/// Returns [`ComparisonError`] if either normalized artifact fails integrity
/// verification or if the comparison projection cannot be encoded.
pub fn compare_captures(
    reference: &NormalizedCapture,
    candidate: &NormalizedCapture,
    policy: &DiffPolicy,
) -> Result<WireDiffReport, ComparisonError> {
    verify_normalized_capture(reference)?;
    verify_normalized_capture(candidate)?;

    let reference_value = comparison_value(reference);
    let candidate_value = comparison_value(candidate);
    let reference_comparison_sha256 = hash_value(&reference_value)?;
    let candidate_comparison_sha256 = hash_value(&candidate_value)?;

    let mut accumulator = DiffAccumulator::new(reference, candidate, policy);
    add_input_findings(reference, candidate, &mut accumulator);
    if accumulator.total_differences == 0 {
        compare_values(&reference_value, &candidate_value, "", &mut accumulator);
    }

    let (match_level, decision) = accumulator.outcome();
    let counts = accumulator
        .findings
        .iter()
        .fold(BTreeMap::new(), |mut counts, finding| {
            *counts.entry(finding.classification).or_default() += 1;
            counts
        });
    let summary = DiffSummary {
        total_differences: accumulator.total_differences,
        emitted_findings: accumulator.findings.len(),
        truncated: accumulator.total_differences > accumulator.findings.len(),
        counts,
    };

    Ok(WireDiffReport {
        schema_version: WIRE_DIFF_REPORT_SCHEMA_VERSION,
        report_id: Uuid::new_v4(),
        reference: CaptureSummary::from(reference),
        candidate: CaptureSummary::from(candidate),
        reference_comparison_sha256,
        candidate_comparison_sha256,
        match_level,
        decision,
        findings: accumulator.findings,
        summary,
    })
}

impl From<&NormalizedCapture> for CaptureSummary {
    fn from(capture: &NormalizedCapture) -> Self {
        Self {
            capture_artifact_id: capture.capture_artifact_id,
            capture_run_id: capture.capture_run_id,
            lane: capture.lane.clone(),
            normalized_sha256: capture.normalized_sha256.clone(),
            os_name: capture.environment.os_name.clone(),
            arch: capture.environment.arch.clone(),
            claude_code_version: capture.environment.claude_code_version.clone(),
            runtime_name: capture.environment.runtime_name.clone(),
            runtime_version: capture.environment.runtime_version.clone(),
            target_class: capture.target.target_class.clone(),
            scenario_id: capture.scenario.id.clone(),
        }
    }
}

fn comparison_value(capture: &NormalizedCapture) -> Value {
    json!({
        "target": capture.target,
        "network": {
            "path": capture.network.path,
            "dns_mode": capture.network.dns_mode,
        },
        "scenario": capture.scenario,
        "events": capture.events,
    })
}

fn hash_value(value: &Value) -> Result<String, ComparisonError> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn add_input_findings(
    reference: &NormalizedCapture,
    candidate: &NormalizedCapture,
    accumulator: &mut DiffAccumulator<'_>,
) {
    input_difference(
        accumulator,
        "/schema_version",
        &reference.schema_version,
        &candidate.schema_version,
        "capture schema versions differ",
    );
    input_difference(
        accumulator,
        "/normalizer_version",
        &reference.normalizer_version,
        &candidate.normalizer_version,
        "normalizer versions differ",
    );
    if !valid_lane_pair(&reference.lane, &candidate.lane) {
        accumulator.push(DiffFinding {
            path: "/lane".to_owned(),
            layer: DiffLayer::Input,
            classification: DiffClassification::UnclassifiedDrift,
            reference: json!(reference.lane),
            candidate: json!(candidate.lane),
            message: "captures are not a reference/replay pair for the same target lane".to_owned(),
            allowed_by: None,
        });
    }
    input_difference(
        accumulator,
        "/target",
        &reference.target,
        &candidate.target,
        "capture targets are not comparable",
    );
    input_difference(
        accumulator,
        "/network/path",
        &reference.network.path,
        &candidate.network.path,
        "network paths differ",
    );
    input_difference(
        accumulator,
        "/network/dns_mode",
        &reference.network.dns_mode,
        &candidate.network.dns_mode,
        "DNS modes differ",
    );
    input_difference(
        accumulator,
        "/scenario",
        &reference.scenario,
        &candidate.scenario,
        "capture scenarios differ",
    );
}

fn input_difference<T: Serialize + PartialEq>(
    accumulator: &mut DiffAccumulator<'_>,
    path: &str,
    reference: &T,
    candidate: &T,
    message: &str,
) {
    if reference != candidate {
        accumulator.push(DiffFinding {
            path: path.to_owned(),
            layer: DiffLayer::Input,
            classification: DiffClassification::UnclassifiedDrift,
            reference: serde_json::to_value(reference).unwrap_or(Value::Null),
            candidate: serde_json::to_value(candidate).unwrap_or(Value::Null),
            message: message.to_owned(),
            allowed_by: None,
        });
    }
}

fn valid_lane_pair(reference: &CaptureLane, candidate: &CaptureLane) -> bool {
    matches!(
        (reference, candidate),
        (
            CaptureLane::ReferenceOfficialTls,
            CaptureLane::ReplayOfficialTls
        ) | (
            CaptureLane::ReferenceControlledEndpoint,
            CaptureLane::ReplayControlledEndpoint
        )
    )
}

fn compare_values(
    reference: &Value,
    candidate: &Value,
    path: &str,
    accumulator: &mut DiffAccumulator<'_>,
) {
    match (reference, candidate) {
        (Value::Object(reference), Value::Object(candidate)) => {
            let mut keys = reference.keys().chain(candidate.keys()).collect::<Vec<_>>();
            keys.sort_unstable();
            keys.dedup();
            for key in keys {
                let child_path = format!("{path}/{}", escape_pointer(key));
                match (reference.get(key), candidate.get(key)) {
                    (Some(reference), Some(candidate)) => {
                        compare_values(reference, candidate, &child_path, accumulator);
                    }
                    (reference, candidate) => accumulator.record_value_difference(
                        child_path,
                        reference.cloned().unwrap_or(Value::Null),
                        candidate.cloned().unwrap_or(Value::Null),
                    ),
                }
            }
        }
        (Value::Array(reference), Value::Array(candidate)) => {
            if reference.len() != candidate.len() {
                accumulator.record_value_difference(
                    format!("{path}/length"),
                    json!(reference.len()),
                    json!(candidate.len()),
                );
            }
            for index in 0..reference.len().min(candidate.len()) {
                compare_values(
                    &reference[index],
                    &candidate[index],
                    &format!("{path}/{index}"),
                    accumulator,
                );
            }
        }
        _ if reference != candidate => accumulator.record_value_difference(
            path.to_owned(),
            reference.clone(),
            candidate.clone(),
        ),
        _ => {}
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

struct DiffAccumulator<'a> {
    reference: &'a NormalizedCapture,
    candidate: &'a NormalizedCapture,
    policy: &'a DiffPolicy,
    findings: Vec<DiffFinding>,
    total_differences: usize,
    saw_hard_mismatch: bool,
    saw_unclassified_drift: bool,
}

impl<'a> DiffAccumulator<'a> {
    fn new(
        reference: &'a NormalizedCapture,
        candidate: &'a NormalizedCapture,
        policy: &'a DiffPolicy,
    ) -> Self {
        Self {
            reference,
            candidate,
            policy,
            findings: vec![],
            total_differences: 0,
            saw_hard_mismatch: false,
            saw_unclassified_drift: false,
        }
    }

    fn record_value_difference(&mut self, path: String, reference: Value, candidate: Value) {
        let (mut classification, message) = classify_difference(
            &path,
            &reference,
            &candidate,
            self.policy.timing_bucket_tolerance,
        );
        let declared_allowance = self
            .policy
            .allowed_differences
            .iter()
            .find(|allowed| allowed.path == path)
            .cloned();
        let allowed_by = if classification == DiffClassification::UnclassifiedDrift {
            declared_allowance
        } else {
            None
        };
        if allowed_by.is_some() {
            classification = DiffClassification::BehavioralMatch;
        }
        self.push(DiffFinding {
            layer: layer_for_path(&path, self.reference, self.candidate),
            path,
            classification,
            reference,
            candidate,
            message,
            allowed_by,
        });
    }

    fn push(&mut self, finding: DiffFinding) {
        self.total_differences += 1;
        self.saw_hard_mismatch |= finding.classification == DiffClassification::HardMismatch;
        self.saw_unclassified_drift |=
            finding.classification == DiffClassification::UnclassifiedDrift;
        if self.findings.len() < self.policy.max_findings {
            self.findings.push(finding);
        }
    }

    fn outcome(&self) -> (DiffClassification, DiffDecision) {
        if self.saw_hard_mismatch {
            (DiffClassification::HardMismatch, DiffDecision::Fail)
        } else if self.saw_unclassified_drift || self.total_differences > self.findings.len() {
            (
                DiffClassification::UnclassifiedDrift,
                DiffDecision::Inconclusive,
            )
        } else if self.total_differences > 0 {
            (DiffClassification::BehavioralMatch, DiffDecision::Pass)
        } else {
            (DiffClassification::NormalizedExact, DiffDecision::Pass)
        }
    }
}

fn classify_difference(
    path: &str,
    reference: &Value,
    candidate: &Value,
    timing_tolerance: u8,
) -> (DiffClassification, String) {
    if path.ends_with("/timing_bucket") {
        let distance = timing_distance(reference, candidate);
        return if distance.is_some_and(|distance| distance <= timing_tolerance) {
            (
                DiffClassification::BehavioralMatch,
                "connection timing remains inside the configured bucket tolerance".to_owned(),
            )
        } else {
            (
                DiffClassification::UnclassifiedDrift,
                "connection timing is outside the configured bucket tolerance".to_owned(),
            )
        };
    }
    if path.contains("/summary_shape/")
        || (path.contains("/events/")
            && (path.ends_with("/byte_len")
                || path.ends_with("/content_hash_present")
                || path.ends_with("/event_type")))
    {
        return (
            DiffClassification::UnclassifiedDrift,
            "difference requires explicit evidence classification".to_owned(),
        );
    }
    (
        DiffClassification::HardMismatch,
        "fixed wire field, ordering, size, or protocol behavior differs".to_owned(),
    )
}

fn timing_distance(reference: &Value, candidate: &Value) -> Option<u8> {
    let reference = timing_rank(reference.as_str()?)?;
    let candidate = timing_rank(candidate.as_str()?)?;
    Some(reference.abs_diff(candidate))
}

fn timing_rank(value: &str) -> Option<u8> {
    match value {
        "under_one_millisecond" => Some(0),
        "one_to_five_milliseconds" => Some(1),
        "five_to_twenty_milliseconds" => Some(2),
        "twenty_to_one_hundred_milliseconds" => Some(3),
        "one_hundred_milliseconds_to_one_second" => Some(4),
        "one_to_five_seconds" => Some(5),
        "over_five_seconds" => Some(6),
        _ => None,
    }
}

fn layer_for_path(
    path: &str,
    reference: &NormalizedCapture,
    candidate: &NormalizedCapture,
) -> DiffLayer {
    if path.starts_with("/target") || path.starts_with("/network") || path.starts_with("/scenario")
    {
        return DiffLayer::Input;
    }
    let Some(index) = path
        .strip_prefix("/events/")
        .and_then(|rest| rest.split('/').next())
        .and_then(|index| index.parse::<usize>().ok())
    else {
        return DiffLayer::Unknown;
    };
    let event = reference.events.get(index).or(candidate.events.get(index));
    match event {
        Some(NormalizedEvent::TlsClientHello { .. }) => DiffLayer::Tls,
        Some(NormalizedEvent::Http2Frame { .. }) if path.contains("/headers/") => {
            DiffLayer::Headers
        }
        Some(NormalizedEvent::Http2Frame { .. }) => DiffLayer::Http2,
        Some(NormalizedEvent::Http1Request { .. }) => DiffLayer::Headers,
        Some(NormalizedEvent::ConnectionLifecycle { .. }) => DiffLayer::Connection,
        Some(NormalizedEvent::SseChunk { .. }) => DiffLayer::Sse,
        Some(NormalizedEvent::Cancellation { .. }) => DiffLayer::Cancellation,
        None => DiffLayer::Unknown,
    }
}

#[derive(Debug, Error)]
pub enum ComparisonError {
    #[error(transparent)]
    Integrity(#[from] NormalizationError),
    #[error("failed to encode comparison projection: {0}")]
    Encoding(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use capture_schema::{
        CAPTURE_SCHEMA_VERSION, CaptureBatch, CaptureEvent, ConnectionPhase, Direction, DnsMode,
        EnvironmentDescriptor, Http2FrameDetail, Http2FrameType, NetworkDescriptor, NetworkPath,
        ScenarioDescriptor, TargetDescriptor,
    };
    use std::collections::BTreeMap;
    use wire_normalizer::{normalize_capture, recompute_normalized_sha256};

    fn capture(lane: CaptureLane, offset_micros: u64) -> NormalizedCapture {
        normalize_capture(&CaptureBatch {
            schema_version: CAPTURE_SCHEMA_VERSION,
            capture_artifact_id: Uuid::new_v4(),
            capture_run_id: Uuid::new_v4(),
            lane,
            observed_at: "2026-08-22T00:00:00Z".to_owned(),
            environment: EnvironmentDescriptor {
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
                request_shape: "fixture".to_owned(),
            },
            events: vec![
                CaptureEvent::ConnectionLifecycle {
                    connection_id: "raw-c1".to_owned(),
                    phase: ConnectionPhase::TlsEstablished,
                    offset_micros,
                    negotiated_protocol: Some("h2".to_owned()),
                    resumed: Some(false),
                },
                CaptureEvent::Http2Frame {
                    connection_id: "raw-c1".to_owned(),
                    direction: Direction::ClientToServer,
                    sequence: 1,
                    stream_id: 0,
                    frame_type: Http2FrameType::Settings,
                    flags: vec![],
                    length: 6,
                    detail: Http2FrameDetail::Settings { entries: vec![] },
                },
            ],
        })
        .expect("normalize fixture")
    }

    fn refresh_hash(capture: &mut NormalizedCapture) {
        capture.normalized_sha256 =
            recompute_normalized_sha256(capture).expect("recompute fixture hash");
    }

    #[test]
    fn identical_wire_projection_is_normalized_exact() {
        let reference = capture(CaptureLane::ReferenceControlledEndpoint, 2_000);
        let candidate = capture(CaptureLane::ReplayControlledEndpoint, 2_000);
        let report = compare_captures(&reference, &candidate, &DiffPolicy::default())
            .expect("comparison succeeds");
        assert_eq!(report.match_level, DiffClassification::NormalizedExact);
        assert_eq!(report.decision, DiffDecision::Pass);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn adjacent_timing_bucket_is_behavioral_match() {
        let reference = capture(CaptureLane::ReferenceControlledEndpoint, 2_000);
        let candidate = capture(CaptureLane::ReplayControlledEndpoint, 7_000);
        let report = compare_captures(&reference, &candidate, &DiffPolicy::default())
            .expect("comparison succeeds");
        assert_eq!(report.match_level, DiffClassification::BehavioralMatch);
        assert_eq!(report.decision, DiffDecision::Pass);
    }

    #[test]
    fn fixed_h2_setting_difference_fails() {
        let reference = capture(CaptureLane::ReferenceControlledEndpoint, 2_000);
        let mut candidate = capture(CaptureLane::ReplayControlledEndpoint, 2_000);
        let NormalizedEvent::Http2Frame { length, .. } = &mut candidate.events[1] else {
            panic!("expected H2 frame");
        };
        *length = 12;
        refresh_hash(&mut candidate);
        let report = compare_captures(&reference, &candidate, &DiffPolicy::default())
            .expect("comparison succeeds");
        assert_eq!(report.match_level, DiffClassification::HardMismatch);
        assert_eq!(report.decision, DiffDecision::Fail);
    }

    #[test]
    fn invalid_lane_pair_is_inconclusive() {
        let reference = capture(CaptureLane::ReferenceControlledEndpoint, 2_000);
        let candidate = capture(CaptureLane::ReferenceControlledEndpoint, 2_000);
        let report = compare_captures(&reference, &candidate, &DiffPolicy::default())
            .expect("comparison succeeds");
        assert_eq!(report.match_level, DiffClassification::UnclassifiedDrift);
        assert_eq!(report.decision, DiffDecision::Inconclusive);
    }

    #[test]
    fn evidence_allowance_can_classify_timing_drift() {
        let reference = capture(CaptureLane::ReferenceControlledEndpoint, 2_000);
        let candidate = capture(CaptureLane::ReplayControlledEndpoint, 2_000_000);
        let policy = DiffPolicy {
            timing_bucket_tolerance: 1,
            max_findings: 100,
            allowed_differences: vec![AllowedDifference {
                path: "/events/0/timing_bucket".to_owned(),
                rationale: "verified slow-path timing cluster".to_owned(),
                evidence_ref: "manifest:test-cluster".to_owned(),
            }],
        };
        let report =
            compare_captures(&reference, &candidate, &policy).expect("comparison succeeds");
        assert_eq!(report.match_level, DiffClassification::BehavioralMatch);
        assert_eq!(report.decision, DiffDecision::Pass);
        assert!(report.findings[0].allowed_by.is_some());
    }

    #[test]
    fn allowance_does_not_downgrade_hard_field() {
        let reference = capture(CaptureLane::ReferenceControlledEndpoint, 2_000);
        let mut candidate = capture(CaptureLane::ReplayControlledEndpoint, 2_000);
        let NormalizedEvent::Http2Frame { length, .. } = &mut candidate.events[1] else {
            panic!("expected H2 frame");
        };
        *length = 12;
        refresh_hash(&mut candidate);
        let policy = DiffPolicy {
            timing_bucket_tolerance: 1,
            max_findings: 100,
            allowed_differences: vec![AllowedDifference {
                path: "/events/1/length".to_owned(),
                rationale: "attempted hard-field allowance".to_owned(),
                evidence_ref: "manifest:not-applicable".to_owned(),
            }],
        };
        let report =
            compare_captures(&reference, &candidate, &policy).expect("comparison succeeds");
        assert_eq!(report.decision, DiffDecision::Fail);
        assert!(report.findings[0].allowed_by.is_none());
    }
}
