#![forbid(unsafe_code)]

#[cfg(feature = "boring-backend")]
mod egress;

use archetype_bundle::{
    ApplicationProfileSpec, CandidateArchetypeBundle, HeaderValueRule, Http1ProfileSpec,
    Http2FrameSpec, verify_bundle,
};
use capture_schema::{CancellationStage, Http2Setting, ProtocolAction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;
use wire_diff::{
    AllowedDifference, DiffDecision, DiffLayer, DiffPolicy, WireDiffReport, compare_captures,
};
use wire_normalizer::{
    NormalizedCapture, NormalizedEvent, NormalizedHttp2FrameDetail, NormalizedTlsExtension,
    verify_normalized_capture,
};

pub const TRANSPORT_PLAN_SCHEMA_VERSION: u32 = 4;
pub const CANARY_TLS_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const CANARY_CANCELLATION_EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// Decodes and verifies an Archetype Bundle before it enters Transport Core.
///
/// # Errors
///
/// Returns [`TransportError`] when JSON decoding, evidence binding, integrity,
/// or privacy invariants fail.
pub fn load_bundle(input: &[u8]) -> Result<CandidateArchetypeBundle, TransportError> {
    let bundle = serde_json::from_slice(input)?;
    verify_bundle(&bundle)?;
    Ok(bundle)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    Probe,
    Canary,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    ReadyForProbe,
    ReadyForCanary,
    Blocked,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ControlPoint {
    TlsProtocolVersions,
    TlsCipherOrder,
    TlsExtensionOrder,
    TlsAlpnOrder,
    TlsClientHelloLength,
    TlsRecordFraming,
    TlsDynamicFields,
    TlsSessionResumption,
    Http1RequestLine,
    Http1HeaderOrder,
    Http1HeaderCasing,
    Http1BodyFraming,
    Http2SettingsValues,
    Http2SettingsOrder,
    Http2ConnectionWindow,
    Http2FrameSequence,
    Http2PseudoHeaderOrder,
    Http2HeaderOrder,
    Http2HeaderCasing,
    Http2HpackEncoding,
    CancellationBehavior,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Native,
    WireVerificationRequired,
    PatchRequired,
    EvidenceMissing,
    Unsupported,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendDescriptor {
    pub backend_id: String,
    pub tls: String,
    pub http1: String,
    pub http2: String,
    pub capabilities: BTreeMap<ControlPoint, CapabilitySupport>,
}

impl BackendDescriptor {
    pub fn upstream_boring_h2() -> Self {
        let capabilities = [
            (ControlPoint::TlsProtocolVersions, CapabilitySupport::Native),
            (
                ControlPoint::TlsCipherOrder,
                CapabilitySupport::WireVerificationRequired,
            ),
            (
                ControlPoint::TlsExtensionOrder,
                CapabilitySupport::WireVerificationRequired,
            ),
            (ControlPoint::TlsAlpnOrder, CapabilitySupport::Native),
            (
                ControlPoint::TlsClientHelloLength,
                CapabilitySupport::WireVerificationRequired,
            ),
            (
                ControlPoint::TlsRecordFraming,
                CapabilitySupport::WireVerificationRequired,
            ),
            (ControlPoint::TlsDynamicFields, CapabilitySupport::Native),
            (
                ControlPoint::TlsSessionResumption,
                CapabilitySupport::Native,
            ),
            (ControlPoint::Http1RequestLine, CapabilitySupport::Native),
            (ControlPoint::Http1HeaderOrder, CapabilitySupport::Native),
            (ControlPoint::Http1HeaderCasing, CapabilitySupport::Native),
            (ControlPoint::Http1BodyFraming, CapabilitySupport::Native),
            (ControlPoint::Http2SettingsValues, CapabilitySupport::Native),
            (
                ControlPoint::Http2SettingsOrder,
                CapabilitySupport::WireVerificationRequired,
            ),
            (
                ControlPoint::Http2ConnectionWindow,
                CapabilitySupport::Native,
            ),
            (
                ControlPoint::Http2FrameSequence,
                CapabilitySupport::WireVerificationRequired,
            ),
            (
                ControlPoint::Http2PseudoHeaderOrder,
                CapabilitySupport::WireVerificationRequired,
            ),
            (
                ControlPoint::Http2HeaderOrder,
                CapabilitySupport::WireVerificationRequired,
            ),
            (ControlPoint::Http2HeaderCasing, CapabilitySupport::Native),
            (
                ControlPoint::Http2HpackEncoding,
                CapabilitySupport::EvidenceMissing,
            ),
            (
                ControlPoint::CancellationBehavior,
                CapabilitySupport::EvidenceMissing,
            ),
        ]
        .into_iter()
        .collect();
        Self {
            backend_id: "cloudflare-boring-5.2+h2-0.4".to_owned(),
            tls: "cloudflare/boring 5.2".to_owned(),
            http1: "ordered byte writer".to_owned(),
            http2: "hyperium/h2 0.4".to_owned(),
            capabilities,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityAudit {
    pub mode: AuditMode,
    pub decision: AuditDecision,
    pub bundle_sha256: String,
    pub backend: BackendDescriptor,
    pub items: Vec<CapabilityAuditItem>,
    pub blocker_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityAuditItem {
    pub control: ControlPoint,
    pub support: CapabilitySupport,
    pub required_by: Vec<String>,
    pub blocking: bool,
    pub note: String,
    #[serde(default)]
    pub verification_evidence: Vec<String>,
}

/// Integrity-bound proof that one Transport Engine build reproduced the official TLS lane.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryTlsEvidence {
    pub schema_version: u32,
    pub evidence_id: Uuid,
    pub bundle_sha256: String,
    pub probe_plan_sha256: String,
    pub backend_id: String,
    pub target: TransportTarget,
    pub engine_build_id: String,
    pub report_sha256: String,
    pub report: WireDiffReport,
    pub verified_controls: Vec<ControlPoint>,
    pub evidence_sha256: String,
}

/// Integrity-bound proof that one Transport Engine build closes an HTTP/1.1
/// upstream connection when a streaming request is cancelled after response
/// commitment, while preserving bytes already delivered.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryCancellationEvidence {
    pub schema_version: u32,
    pub evidence_id: Uuid,
    pub bundle_sha256: String,
    pub probe_plan_sha256: String,
    pub backend_id: String,
    pub target: TransportTarget,
    pub engine_build_id: String,
    pub protocol: String,
    pub stage: CancellationStage,
    pub protocol_action: ProtocolAction,
    pub response_status: u16,
    pub connection_reusable: bool,
    pub response_bytes_preserved: bool,
    pub response_bytes_observed: u64,
    pub peer_close_observed: bool,
    pub evidence_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct H1CancellationObservation {
    pub response_status: u16,
    pub response_bytes_before_cancel: u64,
    pub stage: CancellationStage,
    pub protocol_action: ProtocolAction,
    pub connection_reusable: bool,
    pub response_bytes_preserved: bool,
}

/// Audits every Bundle control point against an explicit backend capability matrix.
///
/// # Errors
///
/// Returns [`TransportError`] if the Bundle fails integrity or privacy verification.
pub fn audit_bundle(
    bundle: &CandidateArchetypeBundle,
    backend: &BackendDescriptor,
    mode: AuditMode,
) -> Result<CapabilityAudit, TransportError> {
    audit_bundle_internal(bundle, backend, mode, &BTreeMap::new())
}

/// Audits a Bundle while consuming verified TLS wire evidence bound to the exact
/// Bundle, backend, target, engine build and probe plan.
///
/// # Errors
///
/// Returns [`TransportError`] when evidence integrity or any binding differs.
pub fn audit_bundle_with_tls_evidence(
    bundle: &CandidateArchetypeBundle,
    backend: &BackendDescriptor,
    mode: AuditMode,
    probe_plan: &ReplayPlan,
    engine_build_id: &str,
    evidence: &[CanaryTlsEvidence],
) -> Result<CapabilityAudit, TransportError> {
    audit_bundle_with_canary_evidence(
        bundle,
        backend,
        mode,
        std::slice::from_ref(probe_plan),
        engine_build_id,
        evidence,
        &[],
    )
}

/// Audits a Bundle while consuming all supported integrity-bound Canary evidence.
/// Each evidence envelope must match one supplied, verified Probe Replay Plan.
///
/// # Errors
///
/// Returns [`TransportError`] when a plan, evidence envelope, or binding differs.
pub fn audit_bundle_with_canary_evidence(
    bundle: &CandidateArchetypeBundle,
    backend: &BackendDescriptor,
    mode: AuditMode,
    probe_plans: &[ReplayPlan],
    engine_build_id: &str,
    tls_evidence: &[CanaryTlsEvidence],
    cancellation_evidence: &[CanaryCancellationEvidence],
) -> Result<CapabilityAudit, TransportError> {
    verify_bundle(bundle)?;
    if engine_build_id.trim().is_empty() {
        return Err(TransportError::InvalidCanaryTlsEvidence);
    }

    let mut plans_by_sha256 = BTreeMap::<String, &ReplayPlan>::new();
    for plan in probe_plans {
        verify_replay_plan(plan)?;
        if plan.audit.mode != AuditMode::Probe
            || plan.audit.decision != AuditDecision::ReadyForProbe
            || plan.bundle_sha256 != bundle.bundle_sha256
            || plan.backend_id != backend.backend_id
            || plans_by_sha256
                .insert(plan.plan_sha256.clone(), plan)
                .is_some()
        {
            return Err(TransportError::CanaryEvidenceBindingMismatch);
        }
    }

    let mut verification_by_control = BTreeMap::<ControlPoint, Vec<String>>::new();
    for item in tls_evidence {
        verify_canary_tls_evidence(item)?;
        let probe_plan = plans_by_sha256
            .get(&item.probe_plan_sha256)
            .ok_or(TransportError::CanaryEvidenceBindingMismatch)?;
        if item.bundle_sha256 != bundle.bundle_sha256
            || item.backend_id != backend.backend_id
            || item.target != probe_plan.target
            || item.probe_plan_sha256 != probe_plan.plan_sha256
            || item.engine_build_id != engine_build_id
        {
            return Err(TransportError::CanaryEvidenceBindingMismatch);
        }
        for control in &item.verified_controls {
            verification_by_control
                .entry(*control)
                .or_default()
                .push(item.evidence_sha256.clone());
        }
    }
    for item in cancellation_evidence {
        verify_canary_cancellation_evidence(item)?;
        let probe_plan = plans_by_sha256
            .get(&item.probe_plan_sha256)
            .ok_or(TransportError::CanaryEvidenceBindingMismatch)?;
        if item.bundle_sha256 != bundle.bundle_sha256
            || item.backend_id != backend.backend_id
            || item.target != probe_plan.target
            || item.engine_build_id != engine_build_id
            || probe_plan.http1().is_err()
        {
            return Err(TransportError::CanaryEvidenceBindingMismatch);
        }
        verification_by_control
            .entry(ControlPoint::CancellationBehavior)
            .or_default()
            .push(item.evidence_sha256.clone());
    }
    for hashes in verification_by_control.values_mut() {
        hashes.sort();
        hashes.dedup();
    }
    audit_bundle_internal(bundle, backend, mode, &verification_by_control)
}

fn audit_bundle_internal(
    bundle: &CandidateArchetypeBundle,
    backend: &BackendDescriptor,
    mode: AuditMode,
    verification_by_control: &BTreeMap<ControlPoint, Vec<String>>,
) -> Result<CapabilityAudit, TransportError> {
    verify_bundle(bundle)?;
    let requirements = bundle_requirements(bundle);
    let items = requirements
        .into_iter()
        .map(|(control, required_by)| {
            let support = backend
                .capabilities
                .get(&control)
                .copied()
                .unwrap_or(CapabilitySupport::Unsupported);
            let evidence_can_satisfy = support == CapabilitySupport::WireVerificationRequired
                || (support == CapabilitySupport::EvidenceMissing
                    && control == ControlPoint::CancellationBehavior);
            let verification_evidence = if mode == AuditMode::Canary && evidence_can_satisfy {
                verification_by_control
                    .get(&control)
                    .cloned()
                    .unwrap_or_default()
            } else {
                vec![]
            };
            let blocking = is_blocking(support, mode) && verification_evidence.is_empty();
            let mut note = capability_note(control, support);
            if !verification_evidence.is_empty() {
                note.push_str("; verified by integrity-bound Canary TLS evidence");
            }
            CapabilityAuditItem {
                control,
                support,
                required_by,
                blocking,
                note,
                verification_evidence,
            }
        })
        .collect::<Vec<_>>();
    let blocker_count = items.iter().filter(|item| item.blocking).count();
    let decision = if blocker_count > 0 {
        AuditDecision::Blocked
    } else if mode == AuditMode::Probe {
        AuditDecision::ReadyForProbe
    } else {
        AuditDecision::ReadyForCanary
    };
    Ok(CapabilityAudit {
        mode,
        decision,
        bundle_sha256: bundle.bundle_sha256.clone(),
        backend: backend.clone(),
        items,
        blocker_count,
    })
}

fn bundle_requirements(bundle: &CandidateArchetypeBundle) -> BTreeMap<ControlPoint, Vec<String>> {
    let mut requirements = BTreeMap::new();
    requirements.insert(
        ControlPoint::TlsProtocolVersions,
        vec!["/tls/legacy_version".to_owned()],
    );
    requirements.insert(
        ControlPoint::TlsCipherOrder,
        vec!["/tls/cipher_suites".to_owned()],
    );
    requirements.insert(
        ControlPoint::TlsExtensionOrder,
        vec!["/tls/extensions".to_owned()],
    );
    requirements.insert(
        ControlPoint::TlsAlpnOrder,
        vec!["/tls/alpn_order".to_owned()],
    );
    requirements.insert(
        ControlPoint::TlsClientHelloLength,
        vec!["/tls/client_hello_len".to_owned()],
    );
    requirements.insert(
        ControlPoint::TlsRecordFraming,
        vec!["/tls/record_lengths".to_owned()],
    );
    if !bundle.tls.dynamic_fields.is_empty() {
        requirements.insert(
            ControlPoint::TlsDynamicFields,
            vec!["/tls/dynamic_fields".to_owned()],
        );
    }
    requirements.insert(
        ControlPoint::TlsSessionResumption,
        vec!["/connection/resumption_observations".to_owned()],
    );
    match &bundle.application {
        ApplicationProfileSpec::Http1(_) => {
            requirements.insert(
                ControlPoint::Http1RequestLine,
                vec![
                    "/application/profile/method".to_owned(),
                    "/application/profile/version".to_owned(),
                ],
            );
            requirements.insert(
                ControlPoint::Http1HeaderOrder,
                vec!["/headers/ordered_names".to_owned()],
            );
            requirements.insert(
                ControlPoint::Http1HeaderCasing,
                vec!["/headers/casing_policy".to_owned()],
            );
            requirements.insert(
                ControlPoint::Http1BodyFraming,
                vec!["/application/profile/content_length_framing".to_owned()],
            );
        }
        ApplicationProfileSpec::Http2(http2) => {
            requirements.insert(
                ControlPoint::Http2SettingsValues,
                vec!["/application/profile/client_frames/settings".to_owned()],
            );
            requirements.insert(
                ControlPoint::Http2SettingsOrder,
                vec!["/application/profile/settings_order".to_owned()],
            );
            if http2.connection_window_update.is_some() {
                requirements.insert(
                    ControlPoint::Http2ConnectionWindow,
                    vec!["/application/profile/connection_window_update".to_owned()],
                );
            }
            requirements.insert(
                ControlPoint::Http2FrameSequence,
                vec!["/application/profile/client_frames".to_owned()],
            );
            requirements.insert(
                ControlPoint::Http2PseudoHeaderOrder,
                vec!["/application/profile/pseudo_header_order".to_owned()],
            );
            requirements.insert(
                ControlPoint::Http2HeaderOrder,
                vec!["/headers/ordered_names".to_owned()],
            );
            requirements.insert(
                ControlPoint::Http2HeaderCasing,
                vec!["/headers/casing_policy".to_owned()],
            );
            requirements.insert(
                ControlPoint::Http2HpackEncoding,
                vec!["capture_manifest:hpack_policy".to_owned()],
            );
        }
    }
    requirements.insert(
        ControlPoint::CancellationBehavior,
        vec!["capture_manifest:cancellation_matrix".to_owned()],
    );
    requirements
}

fn is_blocking(support: CapabilitySupport, mode: AuditMode) -> bool {
    match (mode, support) {
        (_, CapabilitySupport::Unsupported)
        | (
            AuditMode::Canary,
            CapabilitySupport::WireVerificationRequired
            | CapabilitySupport::PatchRequired
            | CapabilitySupport::EvidenceMissing,
        ) => true,
        (AuditMode::Probe, _) | (AuditMode::Canary, CapabilitySupport::Native) => false,
    }
}

fn capability_note(control: ControlPoint, support: CapabilitySupport) -> String {
    match (control, support) {
        (ControlPoint::TlsCipherOrder, CapabilitySupport::WireVerificationRequired) => {
            "BoringSSL exposes pre-TLS1.3 cipher configuration; TLS1.3 suites remain library-defined"
                .to_owned()
        }
        (ControlPoint::TlsExtensionOrder, CapabilitySupport::WireVerificationRequired) => {
            "BoringSSL exposes GREASE and permutation toggles, not an arbitrary extension-order API"
                .to_owned()
        }
        (ControlPoint::Http2SettingsOrder, CapabilitySupport::WireVerificationRequired) => {
            "h2 exposes SETTINGS values while encoding order remains implementation-defined"
                .to_owned()
        }
        (ControlPoint::Http2HpackEncoding, CapabilitySupport::EvidenceMissing) => {
            "current Bundle records decoded Header shape; HPACK byte evidence must be added"
                .to_owned()
        }
        (ControlPoint::CancellationBehavior, CapabilitySupport::EvidenceMissing) => {
            "current fixture does not yet carry a verified cancellation scenario matrix".to_owned()
        }
        (_, CapabilitySupport::Native) => "backend exposes a direct configuration API".to_owned(),
        (_, CapabilitySupport::WireVerificationRequired) => {
            "backend output must pass capture-and-diff before Canary".to_owned()
        }
        (_, CapabilitySupport::PatchRequired) => {
            "upstream API needs a maintained patch or thin transport layer".to_owned()
        }
        (_, CapabilitySupport::EvidenceMissing) => {
            "reference evidence must be extended before Canary".to_owned()
        }
        (_, CapabilitySupport::Unsupported) => "backend has no declared implementation".to_owned(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportTarget {
    pub kind: TargetKind,
    pub authority: String,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    AnthropicOfficial,
    ControlledCapture,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayPlan {
    pub schema_version: u32,
    pub bundle_sha256: String,
    pub backend_id: String,
    pub target: TransportTarget,
    pub tls: TlsReplayPlan,
    pub application: ApplicationReplayPlan,
    pub headers: Vec<HeaderValueRule>,
    pub audit: CapabilityAudit,
    pub plan_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "protocol", content = "plan", rename_all = "snake_case")]
pub enum ApplicationReplayPlan {
    Http1(Http1ReplayPlan),
    Http2(Http2ReplayPlan),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http1ReplayPlan {
    pub method: String,
    pub path_bytes: usize,
    pub version: String,
    pub body_bytes: u32,
    pub content_length_framing: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsReplayPlan {
    pub server_name: String,
    pub alpn_wire: Vec<u8>,
    pub cipher_suite_ids: Vec<u16>,
    pub supported_group_ids: Vec<u16>,
    pub key_share_group_ids: Vec<u16>,
    pub extension_order: Vec<u16>,
    pub grease_enabled: bool,
    pub permute_extensions: bool,
    pub expected_client_hello_len: u32,
    pub expected_record_lengths: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Http2ReplayPlan {
    pub settings: Vec<Http2Setting>,
    pub settings_order: Vec<u16>,
    pub connection_window_update: Option<u32>,
    pub frames: Vec<Http2FrameSpec>,
    pub pseudo_header_order: Vec<String>,
}

impl ReplayPlan {
    /// Returns the HTTP/1.1 section of a protocol-discriminated Replay Plan.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolMismatch`] for an HTTP/2 plan.
    pub fn http1(&self) -> Result<&Http1ReplayPlan, TransportError> {
        match &self.application {
            ApplicationReplayPlan::Http1(plan) => Ok(plan),
            ApplicationReplayPlan::Http2(_) => Err(TransportError::ProtocolMismatch),
        }
    }

    /// Returns the HTTP/2 section of a protocol-discriminated Replay Plan.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolMismatch`] for an HTTP/1.1 plan.
    pub fn http2(&self) -> Result<&Http2ReplayPlan, TransportError> {
        match &self.application {
            ApplicationReplayPlan::Http2(plan) => Ok(plan),
            ApplicationReplayPlan::Http1(_) => Err(TransportError::ProtocolMismatch),
        }
    }
}

/// Builds a secret-free replay plan after fail-closed capability auditing.
///
/// # Errors
///
/// Returns [`TransportError`] for invalid targets, ALPN encoding, Bundle
/// verification failures, or a capability gate that blocks the requested mode.
pub fn build_replay_plan(
    bundle: &CandidateArchetypeBundle,
    backend: &BackendDescriptor,
    target: TransportTarget,
    mode: AuditMode,
) -> Result<ReplayPlan, TransportError> {
    validate_target(&target)?;
    let audit = audit_bundle(bundle, backend, mode)?;
    build_replay_plan_from_audit(bundle, backend, target, audit)
}

/// Builds a replay plan using TLS evidence-aware Canary auditing.
///
/// # Errors
///
/// Returns [`TransportError`] for invalid evidence bindings or any remaining
/// capability blocker.
pub fn build_replay_plan_with_tls_evidence(
    bundle: &CandidateArchetypeBundle,
    backend: &BackendDescriptor,
    target: TransportTarget,
    mode: AuditMode,
    probe_plan: &ReplayPlan,
    engine_build_id: &str,
    evidence: &[CanaryTlsEvidence],
) -> Result<ReplayPlan, TransportError> {
    validate_target(&target)?;
    if target != probe_plan.target {
        return Err(TransportError::CanaryEvidenceBindingMismatch);
    }
    let audit = audit_bundle_with_tls_evidence(
        bundle,
        backend,
        mode,
        probe_plan,
        engine_build_id,
        evidence,
    )?;
    build_replay_plan_from_audit(bundle, backend, target, audit)
}

fn build_replay_plan_from_audit(
    bundle: &CandidateArchetypeBundle,
    backend: &BackendDescriptor,
    target: TransportTarget,
    audit: CapabilityAudit,
) -> Result<ReplayPlan, TransportError> {
    if audit.decision == AuditDecision::Blocked {
        return Err(TransportError::CapabilityBlocked(Box::new(audit)));
    }
    let application = match &bundle.application {
        ApplicationProfileSpec::Http1(profile) => {
            ApplicationReplayPlan::Http1(http1_replay_plan(profile))
        }
        ApplicationProfileSpec::Http2(profile) => {
            let settings = profile
                .client_frames
                .iter()
                .find_map(|frame| match &frame.detail {
                    NormalizedHttp2FrameDetail::Settings { entries } => Some(entries.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            ApplicationReplayPlan::Http2(Http2ReplayPlan {
                settings,
                settings_order: profile.settings_order.clone(),
                connection_window_update: profile.connection_window_update,
                frames: profile.client_frames.clone(),
                pseudo_header_order: profile.pseudo_header_order.clone(),
            })
        }
    };
    let tls = TlsReplayPlan {
        server_name: target.authority.clone(),
        alpn_wire: encode_alpn(&bundle.tls.alpn_order)?,
        cipher_suite_ids: bundle.tls.cipher_suites.clone(),
        supported_group_ids: tls_group_ids(&bundle.tls.extensions, 10, "groups")?,
        key_share_group_ids: tls_group_ids(&bundle.tls.extensions, 51, "key_share_shape")?,
        extension_order: bundle
            .tls
            .extensions
            .iter()
            .map(|extension| extension.extension_type)
            .collect(),
        grease_enabled: bundle
            .tls
            .extensions
            .iter()
            .any(|extension| is_grease(extension.extension_type)),
        permute_extensions: false,
        expected_client_hello_len: bundle.tls.client_hello_len,
        expected_record_lengths: bundle.tls.record_lengths.clone(),
    };
    let mut plan = ReplayPlan {
        schema_version: TRANSPORT_PLAN_SCHEMA_VERSION,
        bundle_sha256: bundle.bundle_sha256.clone(),
        backend_id: backend.backend_id.clone(),
        target,
        tls,
        application,
        headers: bundle.headers.value_rules.clone(),
        audit,
        plan_sha256: String::new(),
    };
    plan.plan_sha256 = hash_plan(&plan)?;
    Ok(plan)
}

fn http1_replay_plan(profile: &Http1ProfileSpec) -> Http1ReplayPlan {
    Http1ReplayPlan {
        method: profile.method.clone(),
        path_bytes: profile.path_shape.bytes,
        version: profile.version.clone(),
        body_bytes: profile.body_bytes,
        content_length_framing: profile.content_length_framing,
    }
}

/// Revalidates a serialized Replay Plan before any network operation.
///
/// # Errors
///
/// Returns [`TransportError::InvalidPlan`] when schema, target, audit binding,
/// decision, or the canonical plan digest has changed.
pub fn verify_replay_plan(plan: &ReplayPlan) -> Result<(), TransportError> {
    validate_target(&plan.target)?;
    if plan.schema_version != TRANSPORT_PLAN_SCHEMA_VERSION
        || plan.bundle_sha256 != plan.audit.bundle_sha256
        || plan.backend_id != plan.audit.backend.backend_id
        || plan.audit.decision == AuditDecision::Blocked
        || plan.plan_sha256 != hash_plan(plan)?
    {
        return Err(TransportError::InvalidPlan);
    }
    Ok(())
}

/// Builds a Canary TLS proof from a successful, complete official/reference
/// versus replay/candidate capture comparison.
///
/// # Errors
///
/// Returns [`TransportError`] when the probe plan, captures, diff policy, or
/// report does not satisfy the fail-closed TLS evidence contract.
pub fn build_canary_tls_evidence(
    probe_plan: &ReplayPlan,
    engine_build_id: &str,
    reference: &NormalizedCapture,
    candidate: &NormalizedCapture,
    report: &WireDiffReport,
) -> Result<CanaryTlsEvidence, TransportError> {
    verify_replay_plan(probe_plan)?;
    if probe_plan.audit.mode != AuditMode::Probe
        || probe_plan.audit.decision != AuditDecision::ReadyForProbe
        || probe_plan.target.kind != TargetKind::AnthropicOfficial
        || engine_build_id.trim().is_empty()
    {
        return Err(TransportError::InvalidCanaryTlsEvidence);
    }
    verify_normalized_capture(reference).map_err(|_| TransportError::InvalidCanaryTlsEvidence)?;
    verify_normalized_capture(candidate).map_err(|_| TransportError::InvalidCanaryTlsEvidence)?;
    validate_tls_evidence_report(reference, candidate, report)?;
    if !tls_capture_matches_plan(candidate, probe_plan)? {
        return Err(TransportError::InvalidCanaryTlsEvidence);
    }

    let report_sha256 = hash_serializable(report)?;
    let mut evidence = CanaryTlsEvidence {
        schema_version: CANARY_TLS_EVIDENCE_SCHEMA_VERSION,
        evidence_id: Uuid::new_v4(),
        bundle_sha256: probe_plan.bundle_sha256.clone(),
        probe_plan_sha256: probe_plan.plan_sha256.clone(),
        backend_id: probe_plan.backend_id.clone(),
        target: probe_plan.target.clone(),
        engine_build_id: engine_build_id.to_owned(),
        report_sha256,
        report: report.clone(),
        verified_controls: tls_verified_controls(),
        evidence_sha256: String::new(),
    };
    evidence.evidence_sha256 = hash_canary_tls_evidence(&evidence)?;
    Ok(evidence)
}

/// Revalidates a serialized Canary TLS evidence envelope.
///
/// # Errors
///
/// Returns [`TransportError::InvalidCanaryTlsEvidence`] for an invalid schema,
/// target, report, control set, or integrity digest.
pub fn verify_canary_tls_evidence(evidence: &CanaryTlsEvidence) -> Result<(), TransportError> {
    validate_target(&evidence.target)?;
    if evidence.schema_version != CANARY_TLS_EVIDENCE_SCHEMA_VERSION
        || evidence.target.kind != TargetKind::AnthropicOfficial
        || evidence.engine_build_id.trim().is_empty()
        || evidence.bundle_sha256.len() != 64
        || evidence.probe_plan_sha256.len() != 64
        || evidence.report_sha256 != hash_serializable(&evidence.report)?
        || evidence.verified_controls != tls_verified_controls()
        || evidence.evidence_sha256 != hash_canary_tls_evidence(evidence)?
        || evidence.report.decision != DiffDecision::Pass
        || evidence.report.summary.truncated
        || !is_official_tls_lane_pair(&evidence.report)
        || !only_supported_tls_allowances(&evidence.report)
    {
        return Err(TransportError::InvalidCanaryTlsEvidence);
    }
    Ok(())
}

fn validate_tls_evidence_report(
    reference: &NormalizedCapture,
    candidate: &NormalizedCapture,
    report: &WireDiffReport,
) -> Result<(), TransportError> {
    if reference.lane != capture_schema::CaptureLane::ReferenceOfficialTls
        || candidate.lane != capture_schema::CaptureLane::ReplayOfficialTls
        || report.decision != DiffDecision::Pass
        || report.summary.truncated
        || !only_supported_tls_allowances(report)
    {
        return Err(TransportError::InvalidCanaryTlsEvidence);
    }

    let policy = DiffPolicy {
        allowed_differences: report
            .findings
            .iter()
            .filter_map(|finding| finding.allowed_by.clone())
            .fold(Vec::<AllowedDifference>::new(), |mut allowed, item| {
                if !allowed.contains(&item) {
                    allowed.push(item);
                }
                allowed
            }),
        ..DiffPolicy::default()
    };
    let recomputed = compare_captures(reference, candidate, &policy)
        .map_err(|_| TransportError::InvalidCanaryTlsEvidence)?;
    if !same_report_except_id(report, &recomputed)
        || tls_client_hello(reference) != tls_client_hello(candidate)
    {
        return Err(TransportError::InvalidCanaryTlsEvidence);
    }
    Ok(())
}

fn tls_client_hello(capture: &NormalizedCapture) -> Option<&NormalizedEvent> {
    let mut events = capture
        .events
        .iter()
        .filter(|event| matches!(event, NormalizedEvent::TlsClientHello { .. }));
    let first = events.next();
    if first.is_some() && events.next().is_none() {
        first
    } else {
        None
    }
}

fn tls_capture_matches_plan(
    capture: &NormalizedCapture,
    plan: &ReplayPlan,
) -> Result<bool, TransportError> {
    let Some(NormalizedEvent::TlsClientHello {
        cipher_suites,
        extensions,
        alpn,
        client_hello_len,
        record_lengths,
        ..
    }) = tls_client_hello(capture)
    else {
        return Ok(false);
    };
    Ok(cipher_suites == &plan.tls.cipher_suite_ids
        && extensions
            .iter()
            .map(|extension| extension.extension_type)
            .eq(plan.tls.extension_order.iter().copied())
        && encode_alpn(alpn)? == plan.tls.alpn_wire
        && *client_hello_len == plan.tls.expected_client_hello_len
        && record_lengths == &plan.tls.expected_record_lengths
        && tls_group_ids(extensions, 10, "groups")? == plan.tls.supported_group_ids
        && tls_group_ids(extensions, 51, "key_share_shape")? == plan.tls.key_share_group_ids)
}

fn only_supported_tls_allowances(report: &WireDiffReport) -> bool {
    report.findings.iter().all(|finding| {
        finding.allowed_by.as_ref().is_none_or(|allowed| {
            finding.layer == DiffLayer::Connection
                && finding.path.ends_with("/timing_bucket")
                && allowed.path == finding.path
                && !allowed.rationale.trim().is_empty()
                && !allowed.evidence_ref.trim().is_empty()
        })
    })
}

fn is_official_tls_lane_pair(report: &WireDiffReport) -> bool {
    report.reference.lane == capture_schema::CaptureLane::ReferenceOfficialTls
        && report.candidate.lane == capture_schema::CaptureLane::ReplayOfficialTls
}

fn same_report_except_id(left: &WireDiffReport, right: &WireDiffReport) -> bool {
    left.schema_version == right.schema_version
        && left.reference == right.reference
        && left.candidate == right.candidate
        && left.reference_comparison_sha256 == right.reference_comparison_sha256
        && left.candidate_comparison_sha256 == right.candidate_comparison_sha256
        && left.match_level == right.match_level
        && left.decision == right.decision
        && left.findings == right.findings
        && left.summary == right.summary
}

fn tls_verified_controls() -> Vec<ControlPoint> {
    vec![
        ControlPoint::TlsProtocolVersions,
        ControlPoint::TlsCipherOrder,
        ControlPoint::TlsExtensionOrder,
        ControlPoint::TlsAlpnOrder,
        ControlPoint::TlsClientHelloLength,
        ControlPoint::TlsRecordFraming,
    ]
}

fn hash_canary_tls_evidence(evidence: &CanaryTlsEvidence) -> Result<String, TransportError> {
    let mut canonical = evidence.clone();
    canonical.evidence_sha256.clear();
    hash_serializable(&canonical)
}

/// Builds a Canary cancellation proof from a live HTTP/1.1 streaming probe and
/// the controlled peer's independent close observation.
///
/// # Errors
///
/// Returns [`TransportError::InvalidCanaryCancellationEvidence`] when the plan
/// or observation does not demonstrate the required fail-closed semantics.
pub fn build_canary_cancellation_evidence(
    probe_plan: &ReplayPlan,
    engine_build_id: &str,
    observation: &H1CancellationObservation,
    peer_close_observed: bool,
) -> Result<CanaryCancellationEvidence, TransportError> {
    verify_replay_plan(probe_plan)?;
    if probe_plan.audit.mode != AuditMode::Probe
        || probe_plan.audit.decision != AuditDecision::ReadyForProbe
        || probe_plan.target.kind != TargetKind::ControlledCapture
        || probe_plan.http1().is_err()
        || engine_build_id.trim().is_empty()
        || !valid_h1_cancellation_observation(observation, peer_close_observed)
    {
        return Err(TransportError::InvalidCanaryCancellationEvidence);
    }
    let mut evidence = CanaryCancellationEvidence {
        schema_version: CANARY_CANCELLATION_EVIDENCE_SCHEMA_VERSION,
        evidence_id: Uuid::new_v4(),
        bundle_sha256: probe_plan.bundle_sha256.clone(),
        probe_plan_sha256: probe_plan.plan_sha256.clone(),
        backend_id: probe_plan.backend_id.clone(),
        target: probe_plan.target.clone(),
        engine_build_id: engine_build_id.to_owned(),
        protocol: "http1".to_owned(),
        stage: observation.stage.clone(),
        protocol_action: observation.protocol_action.clone(),
        response_status: observation.response_status,
        connection_reusable: observation.connection_reusable,
        response_bytes_preserved: observation.response_bytes_preserved,
        response_bytes_observed: observation.response_bytes_before_cancel,
        peer_close_observed,
        evidence_sha256: String::new(),
    };
    evidence.evidence_sha256 = hash_canary_cancellation_evidence(&evidence)?;
    Ok(evidence)
}

/// Revalidates a serialized Canary cancellation evidence envelope.
///
/// # Errors
///
/// Returns [`TransportError::InvalidCanaryCancellationEvidence`] for an invalid
/// schema, target, observation, or integrity digest.
pub fn verify_canary_cancellation_evidence(
    evidence: &CanaryCancellationEvidence,
) -> Result<(), TransportError> {
    validate_target(&evidence.target)?;
    let observation = H1CancellationObservation {
        response_status: evidence.response_status,
        response_bytes_before_cancel: evidence.response_bytes_observed,
        stage: evidence.stage.clone(),
        protocol_action: evidence.protocol_action.clone(),
        connection_reusable: evidence.connection_reusable,
        response_bytes_preserved: evidence.response_bytes_preserved,
    };
    if evidence.schema_version != CANARY_CANCELLATION_EVIDENCE_SCHEMA_VERSION
        || evidence.target.kind != TargetKind::ControlledCapture
        || evidence.bundle_sha256.len() != 64
        || evidence.probe_plan_sha256.len() != 64
        || evidence.engine_build_id.trim().is_empty()
        || evidence.protocol != "http1"
        || !valid_h1_cancellation_observation(&observation, evidence.peer_close_observed)
        || evidence.evidence_sha256 != hash_canary_cancellation_evidence(evidence)?
    {
        return Err(TransportError::InvalidCanaryCancellationEvidence);
    }
    Ok(())
}

fn valid_h1_cancellation_observation(
    observation: &H1CancellationObservation,
    peer_close_observed: bool,
) -> bool {
    (200..300).contains(&observation.response_status)
        && observation.response_bytes_before_cancel > 0
        && observation.stage == CancellationStage::ResponseStreaming
        && observation.protocol_action == ProtocolAction::CloseConnection
        && !observation.connection_reusable
        && observation.response_bytes_preserved
        && peer_close_observed
}

fn hash_canary_cancellation_evidence(
    evidence: &CanaryCancellationEvidence,
) -> Result<String, TransportError> {
    let mut canonical = evidence.clone();
    canonical.evidence_sha256.clear();
    hash_serializable(&canonical)
}

fn hash_serializable<T: Serialize>(value: &T) -> Result<String, TransportError> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn validate_target(target: &TransportTarget) -> Result<(), TransportError> {
    if target.port == 0
        || target.authority.is_empty()
        || target.authority.contains(|character: char| {
            character.is_whitespace() || matches!(character, '/' | '\\' | ':' | '@')
        })
    {
        return Err(TransportError::InvalidTarget);
    }
    if target.kind == TargetKind::AnthropicOfficial && target.authority != "api.anthropic.com" {
        return Err(TransportError::InvalidTarget);
    }
    Ok(())
}

fn encode_alpn(protocols: &[String]) -> Result<Vec<u8>, TransportError> {
    let mut encoded = vec![];
    for protocol in protocols {
        let length = u8::try_from(protocol.len()).map_err(|_| TransportError::InvalidAlpn)?;
        if length == 0 {
            return Err(TransportError::InvalidAlpn);
        }
        encoded.push(length);
        encoded.extend_from_slice(protocol.as_bytes());
    }
    Ok(encoded)
}

fn tls_group_ids(
    extensions: &[NormalizedTlsExtension],
    extension_type: u16,
    attribute_name: &str,
) -> Result<Vec<u16>, TransportError> {
    let Some(extension) = extensions
        .iter()
        .find(|extension| extension.extension_type == extension_type)
    else {
        return Ok(vec![]);
    };
    let attribute = extension
        .attributes
        .iter()
        .find(|attribute| attribute.name == attribute_name)
        .ok_or(TransportError::InvalidTlsProfile)?;
    if attribute.dynamic {
        return Err(TransportError::InvalidTlsProfile);
    }
    let value = attribute
        .value
        .as_deref()
        .ok_or(TransportError::InvalidTlsProfile)?;
    value
        .split(',')
        .map(|entry| {
            let group = entry
                .split_once(':')
                .map_or(entry, |(group, _)| group)
                .strip_prefix("0x")
                .ok_or(TransportError::InvalidTlsProfile)?;
            u16::from_str_radix(group, 16).map_err(|_| TransportError::InvalidTlsProfile)
        })
        .collect()
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0x00ff
}

fn hash_plan(plan: &ReplayPlan) -> Result<String, TransportError> {
    let mut unsigned = plan.clone();
    unsigned.plan_sha256.clear();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&unsigned)?)))
}

pub mod h2_backend {
    use super::{ReplayPlan, TransportError};
    use std::collections::BTreeSet;

    const DEFAULT_CONNECTION_WINDOW: u32 = 65_535;
    const MIN_FRAME_SIZE: u32 = 16_384;
    const MAX_FRAME_SIZE: u32 = 16_777_215;

    /// Applies all standard HTTP/2 SETTINGS values exposed by `h2`.
    ///
    /// SETTINGS order, frame sequence and HPACK byte layout remain guarded by
    /// the plan's wire-verification audit; this adapter does not claim to set
    /// them through value-only builder APIs.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::BackendConfiguration`] for duplicate or
    /// unknown SETTINGS, invalid `ENABLE_PUSH`/`MAX_FRAME_SIZE` values, or a
    /// connection-window increment that overflows the protocol range.
    pub fn build_client(plan: &ReplayPlan) -> Result<h2::client::Builder, TransportError> {
        let http2 = plan.http2()?;
        let mut builder = h2::client::Builder::new();
        let mut seen = BTreeSet::new();
        for setting in &http2.settings {
            if !seen.insert(setting.id) {
                return Err(configuration_error(format!(
                    "duplicate HTTP/2 setting id {}",
                    setting.id
                )));
            }
            match setting.id {
                1 => {
                    builder.header_table_size(setting.value);
                }
                2 if setting.value <= 1 => {
                    builder.enable_push(setting.value == 1);
                }
                2 => {
                    return Err(configuration_error("ENABLE_PUSH must be 0 or 1"));
                }
                3 => {
                    builder.max_concurrent_streams(setting.value);
                }
                4 => {
                    builder.initial_window_size(setting.value);
                }
                5 if (MIN_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&setting.value) => {
                    builder.max_frame_size(setting.value);
                }
                5 => {
                    return Err(configuration_error(format!(
                        "MAX_FRAME_SIZE must be in {MIN_FRAME_SIZE}..={MAX_FRAME_SIZE}"
                    )));
                }
                6 => {
                    builder.max_header_list_size(setting.value);
                }
                id => {
                    return Err(configuration_error(format!(
                        "HTTP/2 setting id {id} has no declared h2 builder mapping"
                    )));
                }
            }
        }
        if let Some(increment) = http2.connection_window_update {
            let target = DEFAULT_CONNECTION_WINDOW
                .checked_add(increment)
                .ok_or_else(|| configuration_error("connection WINDOW_UPDATE overflows u32"))?;
            builder.initial_connection_window_size(target);
        }
        Ok(builder)
    }

    fn configuration_error(message: impl Into<String>) -> TransportError {
        TransportError::BackendConfiguration(message.into())
    }
}

#[cfg(feature = "boring-backend")]
pub mod boring_backend {
    use super::{
        CancellationStage, H1CancellationObservation, Http2Setting, ProtocolAction, ReplayPlan,
        TransportError, h2_backend, verify_replay_plan,
    };
    use crate::egress::{BoxedIo, open_egress};
    pub use crate::egress::{ProxyCredentials, ProxyRoute, Socks5Dns};
    use archetype_bundle::HeaderValueMode;
    use boring::{
        hash::MessageDigest,
        ssl::{SslConnector, SslMethod},
        x509::{X509, store::X509StoreBuilder},
    };
    use serde::{Deserialize, Serialize};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct DialEndpoint {
        pub host: String,
        pub port: u16,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct DirectTlsPolicy {
        pub connect_timeout_ms: u64,
        pub handshake_timeout_ms: u64,
        pub required_alpn: Option<String>,
        pub trust_roots_pem: Option<Vec<u8>>,
        pub dial_override: Option<DialEndpoint>,
        pub proxy: Option<ProxyRoute>,
    }

    impl Default for DirectTlsPolicy {
        fn default() -> Self {
            Self {
                connect_timeout_ms: 5_000,
                handshake_timeout_ms: 10_000,
                required_alpn: Some("h2".to_owned()),
                trust_roots_pem: None,
                dial_override: None,
                proxy: None,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TlsHandshakeObservation {
        pub authority: String,
        pub port: u16,
        pub network_family: String,
        pub negotiated_alpn: String,
        pub tls_version: String,
        pub cipher: String,
        pub session_reused: bool,
        pub certificate_sha256: String,
        pub certificate_verified: bool,
        pub connect_elapsed_micros: u64,
        pub handshake_elapsed_micros: u64,
    }

    pub struct DirectTlsConnection {
        pub stream: tokio_boring::SslStream<BoxedIo>,
        pub observation: TlsHandshakeObservation,
    }

    impl std::fmt::Debug for DirectTlsConnection {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("DirectTlsConnection")
                .field("observation", &self.observation)
                .finish_non_exhaustive()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct H2ProbePolicy {
        pub tls: DirectTlsPolicy,
        pub handshake_timeout_ms: u64,
    }

    impl Default for H2ProbePolicy {
        fn default() -> Self {
            Self {
                tls: DirectTlsPolicy::default(),
                handshake_timeout_ms: 10_000,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct H2HandshakeObservation {
        pub tls: TlsHandshakeObservation,
        pub configured_settings: Vec<Http2Setting>,
        pub bundle_expected_settings_order: Vec<u16>,
        pub configured_connection_window_update: Option<u32>,
        pub settings_values_applied: bool,
        pub settings_wire_order_verified: bool,
        pub server_settings_observed: bool,
        pub application_requests_sent: u32,
        pub handshake_elapsed_micros: u64,
        pub connection_drive_elapsed_micros: u64,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct H2ProbeRequest {
        pub method: String,
        pub path: String,
        pub headers: Vec<(String, String)>,
        pub end_stream: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct H1ProbePolicy {
        pub tls: DirectTlsPolicy,
        pub io_timeout_ms: u64,
        pub max_response_bytes: usize,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct H1ProbeRequest {
        pub path: String,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct H1ProbeObservation {
        pub tls: TlsHandshakeObservation,
        pub request_head_bytes: usize,
        pub request_body_bytes: usize,
        pub response_bytes: usize,
        pub response_status: u16,
        pub connection_reusable: bool,
    }

    /// Sends one byte-ordered HTTP/1.1 request through the verified `BoringSSL`
    /// connector. It is intentionally a low-level writer so Header order and
    /// casing come from the Replay Plan rather than a map-based HTTP client.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] for protocol/profile mismatch, malformed
    /// request fields, TLS/I/O failure, timeout, or an invalid response line.
    pub async fn probe_h1_with_request(
        plan: &ReplayPlan,
        policy: &H1ProbePolicy,
        request: &H1ProbeRequest,
    ) -> Result<H1ProbeObservation, TransportError> {
        let profile = plan.http1()?;
        if policy.io_timeout_ms == 0
            || policy.max_response_bytes < 1024
            || request.path.is_empty()
            || request.path.len() != profile.path_bytes
            || request.body.len() != usize::try_from(profile.body_bytes).unwrap_or(usize::MAX)
            || request
                .path
                .bytes()
                .any(|byte| byte == b'\r' || byte == b'\n')
            || request.headers.iter().any(|(name, value)| {
                name.is_empty()
                    || name
                        .bytes()
                        .any(|byte| byte == b':' || byte == b'\r' || byte == b'\n')
                    || value.bytes().any(|byte| byte == b'\r' || byte == b'\n')
            })
        {
            return Err(TransportError::InvalidConnectionPolicy);
        }
        validate_h1_headers(plan, profile, request)?;
        let mut connection = connect_direct(plan, &policy.tls).await?;
        let mut wire = Vec::with_capacity(
            request
                .body
                .len()
                .saturating_add(request.headers.len().saturating_mul(48)),
        );
        wire.extend_from_slice(profile.method.as_bytes());
        wire.push(b' ');
        wire.extend_from_slice(request.path.as_bytes());
        wire.push(b' ');
        wire.extend_from_slice(profile.version.as_bytes());
        wire.extend_from_slice(b"\r\n");
        for (name, value) in &request.headers {
            wire.extend_from_slice(name.as_bytes());
            wire.extend_from_slice(b": ");
            wire.extend_from_slice(value.as_bytes());
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"\r\n");
        let request_head_bytes = wire.len();
        wire.extend_from_slice(&request.body);
        let timeout = Duration::from_millis(policy.io_timeout_ms);
        tokio::time::timeout(timeout, connection.stream.write_all(&wire))
            .await
            .map_err(|_| connection_error("http1_write", "deadline exceeded"))?
            .map_err(|error| connection_error("http1_write", error.to_string()))?;
        tokio::time::timeout(timeout, connection.stream.flush())
            .await
            .map_err(|_| connection_error("http1_flush", "deadline exceeded"))?
            .map_err(|error| connection_error("http1_flush", error.to_string()))?;
        let mut response = Vec::new();
        tokio::time::timeout(
            timeout,
            (&mut connection.stream)
                .take(u64::try_from(policy.max_response_bytes).unwrap_or(u64::MAX))
                .read_to_end(&mut response),
        )
        .await
        .map_err(|_| connection_error("http1_read", "deadline exceeded"))?
        .map_err(|error| connection_error("http1_read", error.to_string()))?;
        let response_status = parse_http1_status(&response)?;
        Ok(H1ProbeObservation {
            tls: connection.observation,
            request_head_bytes,
            request_body_bytes: request.body.len(),
            response_bytes: response.len(),
            response_status,
            connection_reusable: false,
        })
    }

    /// Sends one byte-ordered HTTP/1.1 request, waits until response bytes have
    /// been committed, then cancels by dropping and evicting the TLS connection.
    /// The controlled peer must independently confirm the close before this
    /// observation is eligible for Canary evidence.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] for invalid request shape, connection failure,
    /// timeout, response overflow, or cancellation before response commitment.
    pub async fn probe_h1_cancellation_with_request(
        plan: &ReplayPlan,
        policy: &H1ProbePolicy,
        request: &H1ProbeRequest,
    ) -> Result<H1CancellationObservation, TransportError> {
        let profile = plan.http1()?;
        if policy.io_timeout_ms == 0
            || policy.max_response_bytes < 1024
            || request.path.is_empty()
            || request.path.len() != profile.path_bytes
            || request.body.len() != usize::try_from(profile.body_bytes).unwrap_or(usize::MAX)
            || request
                .path
                .bytes()
                .any(|byte| byte == b'\r' || byte == b'\n')
            || request.headers.iter().any(|(name, value)| {
                name.is_empty()
                    || name
                        .bytes()
                        .any(|byte| byte == b':' || byte == b'\r' || byte == b'\n')
                    || value.bytes().any(|byte| byte == b'\r' || byte == b'\n')
            })
        {
            return Err(TransportError::InvalidConnectionPolicy);
        }
        validate_h1_headers(plan, profile, request)?;
        let mut connection = connect_direct(plan, &policy.tls).await?;
        let mut wire = Vec::with_capacity(
            request
                .body
                .len()
                .saturating_add(request.headers.len().saturating_mul(48)),
        );
        wire.extend_from_slice(profile.method.as_bytes());
        wire.push(b' ');
        wire.extend_from_slice(request.path.as_bytes());
        wire.push(b' ');
        wire.extend_from_slice(profile.version.as_bytes());
        wire.extend_from_slice(b"\r\n");
        for (name, value) in &request.headers {
            wire.extend_from_slice(name.as_bytes());
            wire.extend_from_slice(b": ");
            wire.extend_from_slice(value.as_bytes());
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(&request.body);
        let timeout = Duration::from_millis(policy.io_timeout_ms);
        tokio::time::timeout(timeout, connection.stream.write_all(&wire))
            .await
            .map_err(|_| connection_error("http1_write", "deadline exceeded"))?
            .map_err(|error| connection_error("http1_write", error.to_string()))?;
        tokio::time::timeout(timeout, connection.stream.flush())
            .await
            .map_err(|_| connection_error("http1_flush", "deadline exceeded"))?
            .map_err(|error| connection_error("http1_flush", error.to_string()))?;

        let mut response = Vec::new();
        let mut buffer = vec![0_u8; 16 * 1024].into_boxed_slice();
        loop {
            let read = tokio::time::timeout(timeout, connection.stream.read(&mut buffer))
                .await
                .map_err(|_| connection_error("http1_read", "deadline exceeded"))?
                .map_err(|error| connection_error("http1_read", error.to_string()))?;
            if read == 0 {
                return Err(connection_error(
                    "http1_read",
                    "peer closed before a streaming response body was committed",
                ));
            }
            if response.len().saturating_add(read) > policy.max_response_bytes {
                return Err(connection_error(
                    "http1_read",
                    "response byte limit exceeded",
                ));
            }
            response.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = response
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .map(|position| position + 4)
                && response.len() > header_end
            {
                break;
            }
        }
        let response_status = parse_http1_status(&response)?;
        let response_bytes_before_cancel = u64::try_from(response.len()).unwrap_or(u64::MAX);
        drop(connection);
        Ok(H1CancellationObservation {
            response_status,
            response_bytes_before_cancel,
            stage: CancellationStage::ResponseStreaming,
            protocol_action: ProtocolAction::CloseConnection,
            connection_reusable: false,
            response_bytes_preserved: true,
        })
    }

    fn validate_h1_headers(
        plan: &ReplayPlan,
        profile: &super::Http1ReplayPlan,
        request: &H1ProbeRequest,
    ) -> Result<(), TransportError> {
        if request.headers.len() != plan.headers.len() {
            return Err(configuration_error(
                "HTTP/1.1 Header count differs from Replay Plan",
            ));
        }
        for ((name, value), rule) in request.headers.iter().zip(&plan.headers) {
            let fixed_value_differs = rule.mode == HeaderValueMode::Exact
                && rule.exact_value.as_deref() != Some(value.as_str());
            if name != &rule.wire_name || value.len() != rule.value_bytes || fixed_value_differs {
                return Err(configuration_error(format!(
                    "HTTP/1.1 Header {} differs from Replay Plan",
                    rule.canonical_name
                )));
            }
        }
        if profile.content_length_framing {
            let expected = request.body.len().to_string();
            let content_length = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.as_str());
            if content_length != Some(expected.as_str()) {
                return Err(configuration_error(
                    "HTTP/1.1 Content-Length does not match request Body",
                ));
            }
        }
        Ok(())
    }

    fn parse_http1_status(response: &[u8]) -> Result<u16, TransportError> {
        let line_end = response
            .windows(2)
            .position(|part| part == b"\r\n")
            .ok_or_else(|| connection_error("http1_response", "missing status line"))?;
        let line = std::str::from_utf8(&response[..line_end])
            .map_err(|_| connection_error("http1_response", "status line is not UTF-8"))?;
        let mut parts = line.split_ascii_whitespace();
        if parts.next() != Some("HTTP/1.1") {
            return Err(connection_error(
                "http1_response",
                "unexpected HTTP version",
            ));
        }
        parts
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| connection_error("http1_response", "invalid status code"))
    }

    /// Applies the controls exposed directly by upstream `BoringSSL`.
    ///
    /// The remaining fields stay guarded by the plan's wire-verification audit.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::BackendConfiguration`] if `BoringSSL` rejects
    /// the ALPN, GREASE, or extension-permutation configuration.
    pub fn build_connector(plan: &ReplayPlan) -> Result<SslConnector, TransportError> {
        build_connector_with_trust_roots(plan, None)
    }

    /// Builds the same connector with an optional explicit PEM trust bundle.
    /// Explicit roots replace platform defaults, making container deployments
    /// deterministic and allowing capture environments to inject their public
    /// test CA without weakening hostname or peer verification.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::BackendConfiguration`] for an empty/malformed
    /// PEM bundle or a rejected trust-store configuration.
    pub fn build_connector_with_trust_roots(
        plan: &ReplayPlan,
        trust_roots_pem: Option<&[u8]>,
    ) -> Result<SslConnector, TransportError> {
        verify_replay_plan(plan)?;
        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|error| TransportError::BackendConfiguration(error.to_string()))?;
        builder
            .set_alpn_protos(&plan.tls.alpn_wire)
            .map_err(|error| TransportError::BackendConfiguration(error.to_string()))?;
        apply_cipher_order(&mut builder, &plan.tls.cipher_suite_ids)?;
        apply_supported_groups(
            &mut builder,
            &plan.tls.supported_group_ids,
            &plan.tls.key_share_group_ids,
        )?;
        if plan.tls.extension_order.contains(&5) {
            builder.enable_ocsp_stapling();
        }
        if plan.tls.extension_order.contains(&18) {
            builder.enable_signed_cert_timestamps();
        }
        builder.set_grease_enabled(plan.tls.grease_enabled);
        builder.set_permute_extensions(plan.tls.permute_extensions);
        if let Some(pem) = trust_roots_pem {
            let certificates = X509::stack_from_pem(pem)
                .map_err(|error| TransportError::BackendConfiguration(error.to_string()))?;
            if certificates.is_empty() {
                return Err(TransportError::BackendConfiguration(
                    "explicit trust bundle contains no certificates".to_owned(),
                ));
            }
            let mut store = X509StoreBuilder::new()
                .map_err(|error| TransportError::BackendConfiguration(error.to_string()))?;
            for certificate in certificates {
                store
                    .add_cert(certificate)
                    .map_err(|error| TransportError::BackendConfiguration(error.to_string()))?;
            }
            builder
                .set_verify_cert_store(store.build())
                .map_err(|error| TransportError::BackendConfiguration(error.to_string()))?;
        }
        Ok(builder.build())
    }

    fn apply_cipher_order(
        builder: &mut boring::ssl::SslConnectorBuilder,
        cipher_suite_ids: &[u16],
    ) -> Result<(), TransportError> {
        let names = cipher_suite_ids
            .iter()
            .filter(|&&id| !(0x1301..=0x1303).contains(&id))
            .map(|id| {
                pre_tls13_cipher_name(*id).ok_or_else(|| {
                    configuration_error(format!(
                        "Replay Plan cipher suite 0x{id:04x} has no BoringSSL mapping"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !names.is_empty() {
            builder
                .set_strict_cipher_list(&names.join(":"))
                .map_err(|error| TransportError::BackendConfiguration(error.to_string()))?;
        }
        Ok(())
    }

    fn pre_tls13_cipher_name(id: u16) -> Option<&'static str> {
        match id {
            0xc02f => Some("ECDHE-RSA-AES128-GCM-SHA256"),
            0xc02b => Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
            0xc030 => Some("ECDHE-RSA-AES256-GCM-SHA384"),
            0xc02c => Some("ECDHE-ECDSA-AES256-GCM-SHA384"),
            0xc027 => Some("ECDHE-RSA-AES128-SHA256"),
            0xcca9 => Some("ECDHE-ECDSA-CHACHA20-POLY1305"),
            0xcca8 => Some("ECDHE-RSA-CHACHA20-POLY1305"),
            0xc009 => Some("ECDHE-ECDSA-AES128-SHA"),
            0xc013 => Some("ECDHE-RSA-AES128-SHA"),
            0xc00a => Some("ECDHE-ECDSA-AES256-SHA"),
            0xc014 => Some("ECDHE-RSA-AES256-SHA"),
            0x009c => Some("AES128-GCM-SHA256"),
            0x009d => Some("AES256-GCM-SHA384"),
            0x002f => Some("AES128-SHA"),
            0x0035 => Some("AES256-SHA"),
            _ => None,
        }
    }

    fn apply_supported_groups(
        builder: &mut boring::ssl::SslConnectorBuilder,
        supported_group_ids: &[u16],
        key_share_group_ids: &[u16],
    ) -> Result<(), TransportError> {
        if supported_group_ids.is_empty() {
            if key_share_group_ids.is_empty() {
                return Ok(());
            }
            return Err(configuration_error(
                "Replay Plan has KeyShare groups without supported groups",
            ));
        }
        if key_share_group_ids.len() > 1
            || key_share_group_ids
                .first()
                .is_some_and(|group| Some(group) != supported_group_ids.first())
        {
            return Err(configuration_error(
                "Replay Plan KeyShare layout is not representable by BoringSSL curve controls",
            ));
        }
        let names = supported_group_ids
            .iter()
            .map(|id| {
                tls_group_name(*id).ok_or_else(|| {
                    configuration_error(format!(
                        "Replay Plan TLS group 0x{id:04x} has no BoringSSL mapping"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        builder
            .set_curves_list(&names.join(":"))
            .map_err(|error| TransportError::BackendConfiguration(error.to_string()))
    }

    fn tls_group_name(id: u16) -> Option<&'static str> {
        match id {
            0x001d => Some("X25519"),
            0x0017 => Some("P-256"),
            0x0018 => Some("P-384"),
            0x0019 => Some("P-521"),
            _ => None,
        }
    }

    /// Opens a certificate-verified direct TCP/TLS connection from a verified
    /// Replay Plan and records only non-secret negotiated properties.
    ///
    /// Hostname verification and system trust roots are always enabled by the
    /// `SslConnector`; the policy has no insecure bypass switch.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] for invalid plans/policies, TCP or TLS
    /// timeout/failure, certificate failure, missing peer properties, or ALPN
    /// drift.
    pub async fn connect_direct(
        plan: &ReplayPlan,
        policy: &DirectTlsPolicy,
    ) -> Result<DirectTlsConnection, TransportError> {
        validate_policy(plan, policy)?;
        let connector = build_connector_with_trust_roots(plan, policy.trust_roots_pem.as_deref())?;
        let connect_started = Instant::now();
        let (tcp, network_family) = open_egress(
            &plan.target.authority,
            plan.target.port,
            policy.dial_override.as_ref(),
            policy.proxy.as_ref(),
            Duration::from_millis(policy.connect_timeout_ms),
        )
        .await
        .map_err(|error| connection_error(error.stage(), error.to_string()))?;
        let connect_elapsed_micros = elapsed_micros(connect_started);

        let config = connector
            .configure()
            .map_err(|error| TransportError::BackendConfiguration(error.to_string()))?;
        let handshake_stage = if policy.proxy.is_some() {
            "unhealthy_tls_passthrough"
        } else {
            "tls_handshake"
        };
        let handshake_started = Instant::now();
        let stream = tokio::time::timeout(
            Duration::from_millis(policy.handshake_timeout_ms),
            tokio_boring::connect(config, &plan.target.authority, tcp),
        )
        .await
        .map_err(|_| connection_error(handshake_stage, "deadline exceeded"))?
        .map_err(|error| connection_error(handshake_stage, error.to_string()))?;
        let handshake_elapsed_micros = elapsed_micros(handshake_started);
        let ssl = stream.ssl();
        if let Err(verify_error) = ssl.verify_result() {
            return Err(connection_error(
                if policy.proxy.is_some() {
                    "unhealthy_tls_passthrough"
                } else {
                    "certificate_verify"
                },
                verify_error.error_string(),
            ));
        }
        let negotiated_alpn = ssl.selected_alpn_protocol();
        match (policy.required_alpn.as_deref(), negotiated_alpn) {
            (Some(required), Some(observed)) if observed == required.as_bytes() => {}
            (None, None) => {}
            (required, observed) => {
                return Err(connection_error(
                    "alpn_verify",
                    format!(
                        "expected {}, negotiated {}",
                        required.unwrap_or("<none>"),
                        observed
                            .map(String::from_utf8_lossy)
                            .as_deref()
                            .unwrap_or("<none>")
                    ),
                ));
            }
        }
        let certificate = ssl
            .peer_certificate()
            .ok_or_else(|| connection_error("certificate_verify", "peer sent no certificate"))?;
        let certificate_sha256 = certificate
            .digest(MessageDigest::sha256())
            .map_err(|error| connection_error("certificate_digest", error.to_string()))?;
        let cipher = ssl
            .current_cipher()
            .ok_or_else(|| connection_error("tls_observation", "cipher is missing"))?
            .name()
            .to_owned();
        let observation = TlsHandshakeObservation {
            authority: plan.target.authority.clone(),
            port: plan.target.port,
            network_family,
            negotiated_alpn: negotiated_alpn.map_or_else(
                || "none".to_owned(),
                |value| String::from_utf8_lossy(value).into_owned(),
            ),
            tls_version: ssl.version_str().to_owned(),
            cipher,
            session_reused: ssl.session_reused(),
            certificate_sha256: hex::encode(certificate_sha256),
            certificate_verified: true,
            connect_elapsed_micros,
            handshake_elapsed_micros,
        };
        Ok(DirectTlsConnection {
            stream,
            observation,
        })
    }

    /// Completes the `h2` client preface/SETTINGS handshake over a verified TLS
    /// connection without sending an application request.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] when TLS setup, H2 builder configuration, or
    /// the H2 handshake fails or exceeds its deadline.
    pub async fn probe_h2(
        plan: &ReplayPlan,
        policy: &H2ProbePolicy,
    ) -> Result<H2HandshakeObservation, TransportError> {
        probe_h2_inner(plan, policy, None).await
    }

    /// Completes the H2 handshake and submits one caller-supplied synthetic
    /// request. This is intended only for controlled capture endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] when the request is malformed, transport
    /// setup fails, or the request cannot be submitted within the deadline.
    pub async fn probe_h2_with_request(
        plan: &ReplayPlan,
        policy: &H2ProbePolicy,
        request: &H2ProbeRequest,
    ) -> Result<H2HandshakeObservation, TransportError> {
        probe_h2_inner(plan, policy, Some(request)).await
    }

    async fn probe_h2_inner(
        plan: &ReplayPlan,
        policy: &H2ProbePolicy,
        request: Option<&H2ProbeRequest>,
    ) -> Result<H2HandshakeObservation, TransportError> {
        if policy.handshake_timeout_ms == 0 {
            return Err(TransportError::InvalidConnectionPolicy);
        }
        let tls = connect_direct(plan, &policy.tls).await?;
        let builder = h2_backend::build_client(plan)?;
        let started = Instant::now();
        let (mut send_request, connection) = tokio::time::timeout(
            Duration::from_millis(policy.handshake_timeout_ms),
            builder.handshake::<_, bytes::Bytes>(tls.stream),
        )
        .await
        .map_err(|_| connection_error("h2_handshake", "deadline exceeded"))?
        .map_err(|error| connection_error("h2_handshake", error.to_string()))?;
        let handshake_elapsed_micros = elapsed_micros(started);
        let mut response_future = None;
        let mut request_stream = None;
        if let Some(request) = request {
            let method = http::Method::from_bytes(request.method.as_bytes())
                .map_err(|_| configuration_error("controlled H2 request method is invalid"))?;
            let uri = format!("https://{}{}", plan.target.authority, request.path)
                .parse::<http::Uri>()
                .map_err(|_| configuration_error("controlled H2 request URI is invalid"))?;
            let mut http_request = http::Request::builder()
                .method(method)
                .uri(uri)
                .version(http::Version::HTTP_2)
                .body(())
                .map_err(|_| configuration_error("controlled H2 request is invalid"))?;
            for (name, value) in &request.headers {
                let name = http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                    configuration_error("controlled H2 request header name is invalid")
                })?;
                let value = http::header::HeaderValue::from_str(value).map_err(|_| {
                    configuration_error("controlled H2 request header value is invalid")
                })?;
                http_request.headers_mut().append(name, value);
            }
            send_request = tokio::time::timeout(
                Duration::from_millis(policy.handshake_timeout_ms),
                send_request.ready(),
            )
            .await
            .map_err(|_| connection_error("h2_request_ready", "deadline exceeded"))?
            .map_err(|error| connection_error("h2_request_ready", error.to_string()))?;
            let (response, stream) = send_request
                .send_request(http_request, request.end_stream)
                .map_err(|error| connection_error("h2_send_request", error.to_string()))?;
            response_future = Some(response);
            request_stream = Some(stream);
        }
        let drive_started = Instant::now();
        let mut connection = Box::pin(connection);
        if let Ok(result) =
            tokio::time::timeout(Duration::from_millis(25), connection.as_mut()).await
        {
            result.map_err(|error| connection_error("h2_connection", error.to_string()))?;
        }
        let connection_drive_elapsed_micros = elapsed_micros(drive_started);
        drop(response_future);
        drop(request_stream);
        drop(send_request);
        drop(connection);
        let http2 = plan.http2()?;
        Ok(H2HandshakeObservation {
            tls: tls.observation,
            configured_settings: http2.settings.clone(),
            bundle_expected_settings_order: http2.settings_order.clone(),
            configured_connection_window_update: http2.connection_window_update,
            settings_values_applied: true,
            settings_wire_order_verified: false,
            server_settings_observed: false,
            application_requests_sent: u32::from(request.is_some()),
            handshake_elapsed_micros,
            connection_drive_elapsed_micros,
        })
    }

    fn validate_policy(plan: &ReplayPlan, policy: &DirectTlsPolicy) -> Result<(), TransportError> {
        verify_replay_plan(plan)?;
        if policy.connect_timeout_ms == 0
            || policy.handshake_timeout_ms == 0
            || policy.required_alpn.as_ref().is_some_and(|required| {
                required.is_empty() || !offers_alpn(&plan.tls.alpn_wire, required.as_bytes())
            })
            || (policy.required_alpn.is_none() && !plan.tls.alpn_wire.is_empty())
            || policy.dial_override.as_ref().is_some_and(|endpoint| {
                endpoint.host.is_empty()
                    || endpoint.port == 0
                    || endpoint.host.contains(|character: char| {
                        character.is_whitespace() || matches!(character, '/' | '\\' | '@')
                    })
            })
            || policy.proxy.as_ref().is_some_and(|proxy| !proxy.is_valid())
            || (policy.proxy.is_some() && policy.dial_override.is_some())
        {
            return Err(TransportError::InvalidConnectionPolicy);
        }
        Ok(())
    }

    fn offers_alpn(wire: &[u8], required: &[u8]) -> bool {
        let mut offset = 0;
        while let Some(length) = wire.get(offset).copied() {
            offset += 1;
            let end = offset.saturating_add(usize::from(length));
            let Some(protocol) = wire.get(offset..end) else {
                return false;
            };
            if protocol == required {
                return true;
            }
            offset = end;
        }
        false
    }

    fn elapsed_micros(started: Instant) -> u64 {
        u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    fn configuration_error(message: impl Into<String>) -> TransportError {
        TransportError::BackendConfiguration(message.into())
    }

    fn connection_error(stage: &'static str, message: impl Into<String>) -> TransportError {
        TransportError::Connection {
            stage,
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error(transparent)]
    Bundle(#[from] archetype_bundle::BundleError),
    #[error("capability audit blocked replay plan")]
    CapabilityBlocked(Box<CapabilityAudit>),
    #[error("transport target is invalid")]
    InvalidTarget,
    #[error("transport replay plan is invalid or has been modified")]
    InvalidPlan,
    #[error("Canary TLS evidence is invalid or has been modified")]
    InvalidCanaryTlsEvidence,
    #[error(
        "Canary evidence does not match a supplied Probe Plan, Bundle, backend, or engine build"
    )]
    CanaryEvidenceBindingMismatch,
    #[error("Canary cancellation evidence is invalid or has been modified")]
    InvalidCanaryCancellationEvidence,
    #[error("ALPN list is invalid")]
    InvalidAlpn,
    #[error("TLS profile contains an invalid stable field")]
    InvalidTlsProfile,
    #[error("TLS connection policy is invalid")]
    InvalidConnectionPolicy,
    #[error("transport replay plan application protocol does not match the requested backend")]
    ProtocolMismatch,
    #[error("transport JSON processing failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("backend configuration failed: {0}")]
    BackendConfiguration(String),
    #[error("transport connection failed at {stage}: {message}")]
    Connection {
        stage: &'static str,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use archetype_bundle::{
        ARCHETYPE_BUNDLE_SCHEMA_VERSION, ApplicationProfileSpec, BundleCompatibility,
        BundleEvidence, BundleState, BundleVerification, ConnectionProfileSpec, HeaderCasingPolicy,
        HeaderProfileSpec, HeaderValueMode, Http2ProfileSpec, TlsProfileSpec,
        recompute_bundle_sha256,
    };
    use capture_schema::{CaptureEvidenceRef, CaptureLane, DnsMode, Http2FrameType, NetworkPath};
    use uuid::Uuid;
    use wire_normalizer::{
        NORMALIZER_VERSION, NormalizedEnvironment, NormalizedNetwork, NormalizedScenario,
        NormalizedTarget, NormalizedTlsAttribute, NormalizedTlsExtension, ValueKind, ValueShape,
        recompute_normalized_sha256,
    };

    fn bundle() -> CandidateArchetypeBundle {
        let run_id = Uuid::new_v4();
        let evidence = |lane| CaptureEvidenceRef {
            capture_artifact_id: Uuid::new_v4(),
            capture_run_id: run_id,
            lane,
            normalized_sha256: "a".repeat(64),
            event_count: 1,
        };
        let mut bundle = CandidateArchetypeBundle {
            schema_version: ARCHETYPE_BUNDLE_SCHEMA_VERSION,
            archetype_id: "claude-code/linux/x86_64/bun/fixture".to_owned(),
            bundle_version: 1,
            state: BundleState::Candidate,
            evidence: BundleEvidence {
                manifest_id: Uuid::new_v4(),
                capture_run_id: run_id,
                passive_tls: evidence(CaptureLane::ReferenceOfficialTls),
                controlled_http2: evidence(CaptureLane::ReferenceControlledEndpoint),
                manifest_verified_at: "2026-08-22T00:00:00Z".to_owned(),
            },
            compatibility: BundleCompatibility {
                engine_api: "v1".to_owned(),
                rust_targets: vec!["x86_64-unknown-linux-gnu".to_owned()],
                min_engine_build: None,
            },
            tls: TlsProfileSpec {
                record_version: 0x0301,
                legacy_version: 0x0303,
                cipher_suites: vec![0x1301, 0x1302],
                extensions: vec![],
                alpn_order: vec!["h2".to_owned()],
                client_hello_len: 200,
                record_lengths: vec![205],
                dynamic_fields: vec![],
            },
            application: ApplicationProfileSpec::Http2(Http2ProfileSpec {
                client_frames: vec![Http2FrameSpec {
                    sequence: 1,
                    stream_id: 0,
                    frame_type: Http2FrameType::Settings,
                    flags: vec![],
                    length: 6,
                    detail: NormalizedHttp2FrameDetail::Settings {
                        entries: vec![Http2Setting { id: 1, value: 4096 }],
                    },
                }],
                settings_order: vec![1],
                connection_window_update: None,
                pseudo_header_order: vec![":method".to_owned()],
            }),
            headers: HeaderProfileSpec {
                ordered_names: vec![":method".to_owned()],
                casing_policy: HeaderCasingPolicy::Lowercase,
                value_rules: vec![HeaderValueRule {
                    wire_name: ":method".to_owned(),
                    canonical_name: ":method".to_owned(),
                    mode: HeaderValueMode::Exact,
                    exact_value: Some("POST".to_owned()),
                    value_kind: ValueKind::Ascii,
                    value_bytes: 4,
                }],
            },
            connection: ConnectionProfileSpec {
                lifecycle_phases: vec![],
                negotiated_protocols: vec!["h2".to_owned()],
                resumption_observations: vec![false],
                fresh_connection_observed: true,
                pooled_connection_observed: false,
                observed_concurrent_streams: 1,
            },
            verification: BundleVerification {
                fixture_set: "manifest:test".to_owned(),
                expected_normalized_hashes: vec!["a".repeat(64)],
                privacy_invariants_checked: true,
                wire_diff_required: true,
            },
            bundle_sha256: String::new(),
        };
        bundle.bundle_sha256 = recompute_bundle_sha256(&bundle).expect("hash fixture bundle");
        bundle
    }

    fn official_tls_capture(lane: CaptureLane) -> NormalizedCapture {
        let mut capture = NormalizedCapture {
            schema_version: capture_schema::CAPTURE_SCHEMA_VERSION,
            normalizer_version: NORMALIZER_VERSION.to_owned(),
            capture_artifact_id: Uuid::new_v4(),
            capture_run_id: Uuid::new_v4(),
            lane,
            observed_at: "2026-08-24T00:00:00Z".to_owned(),
            environment: NormalizedEnvironment {
                os_name: "windows".to_owned(),
                os_version: "fixture".to_owned(),
                os_build: None,
                arch: "x86_64".to_owned(),
                kernel: None,
                claude_code_version: "2.1.241".to_owned(),
                runtime_name: "bun".to_owned(),
                runtime_version: "fixture".to_owned(),
                binary_sha256: None,
                labels: BTreeMap::new(),
            },
            target: NormalizedTarget {
                target_class: "anthropic_official".to_owned(),
                official_anthropic: true,
            },
            network: NormalizedNetwork {
                path: NetworkPath::Direct,
                dns_mode: DnsMode::Local,
                proxy_software: None,
                proxy_version: None,
            },
            scenario: NormalizedScenario {
                id: "T01-minimal-message".to_owned(),
                fresh_connection: true,
                expected_protocol: "tls".to_owned(),
                concurrent_streams: 1,
                request_shape: "tls-client-hello-only".to_owned(),
            },
            events: vec![NormalizedEvent::TlsClientHello {
                connection_id: "conn-1".to_owned(),
                record_version: 0x0301,
                legacy_version: 0x0303,
                cipher_suites: vec![0x1301, 0x1302],
                extensions: vec![],
                alpn: vec!["h2".to_owned()],
                client_hello_len: 200,
                record_lengths: vec![205],
            }],
            normalized_sha256: String::new(),
        };
        capture.normalized_sha256 =
            recompute_normalized_sha256(&capture).expect("hash TLS fixture");
        capture
    }

    fn http1_bundle() -> CandidateArchetypeBundle {
        let mut fixture = bundle();
        fixture.application = ApplicationProfileSpec::Http1(Http1ProfileSpec {
            method: "POST".to_owned(),
            path_shape: ValueShape {
                kind: ValueKind::Ascii,
                bytes: 12,
            },
            version: "HTTP/1.1".to_owned(),
            body_bytes: 1024,
            content_length_framing: true,
        });
        fixture.headers = HeaderProfileSpec {
            ordered_names: vec![
                "host".to_owned(),
                "content-length".to_owned(),
                "authorization".to_owned(),
            ],
            casing_policy: HeaderCasingPolicy::Lowercase,
            value_rules: vec![
                HeaderValueRule {
                    wire_name: "host".to_owned(),
                    canonical_name: "host".to_owned(),
                    mode: HeaderValueMode::Exact,
                    exact_value: Some("capture.invalid".to_owned()),
                    value_kind: ValueKind::Ascii,
                    value_bytes: 15,
                },
                HeaderValueRule {
                    wire_name: "content-length".to_owned(),
                    canonical_name: "content-length".to_owned(),
                    mode: HeaderValueMode::Exact,
                    exact_value: Some("1024".to_owned()),
                    value_kind: ValueKind::Integer,
                    value_bytes: 4,
                },
                HeaderValueRule {
                    wire_name: "authorization".to_owned(),
                    canonical_name: "authorization".to_owned(),
                    mode: HeaderValueMode::CredentialDerivedSecret,
                    exact_value: None,
                    value_kind: ValueKind::Secret,
                    value_bytes: 24,
                },
            ],
        };
        fixture.connection.negotiated_protocols = vec!["http/1.1".to_owned()];
        fixture.bundle_sha256 = recompute_bundle_sha256(&fixture).expect("rehash H1 fixture");
        fixture
    }

    #[test]
    fn upstream_backend_is_ready_for_probe() {
        let audit = audit_bundle(
            &bundle(),
            &BackendDescriptor::upstream_boring_h2(),
            AuditMode::Probe,
        )
        .expect("audit bundle");
        assert_eq!(audit.decision, AuditDecision::ReadyForProbe);
        assert_eq!(audit.blocker_count, 0);
    }

    #[test]
    fn bundle_loader_rejects_tampered_artifact() {
        let fixture = bundle();
        let encoded = serde_json::to_vec(&fixture).expect("encode fixture");
        let loaded = load_bundle(&encoded).expect("load verified fixture");
        assert_eq!(loaded.bundle_sha256, fixture.bundle_sha256);

        let mut tampered = fixture;
        tampered.tls.client_hello_len += 1;
        let encoded = serde_json::to_vec(&tampered).expect("encode tampered fixture");
        assert!(matches!(
            load_bundle(&encoded),
            Err(TransportError::Bundle(_))
        ));
    }

    #[test]
    fn replay_plan_extracts_supported_and_key_share_groups() {
        let attribute = |name: &str, value: &str| NormalizedTlsAttribute {
            name: name.to_owned(),
            dynamic: false,
            value: Some(value.to_owned()),
            value_shape: ValueShape {
                kind: ValueKind::Ascii,
                bytes: value.len(),
            },
        };
        let mut fixture = bundle();
        fixture.tls.extensions = vec![
            NormalizedTlsExtension {
                extension_type: 10,
                name: "supported_groups".to_owned(),
                position: 0,
                encoded_len: 8,
                attributes: vec![attribute("groups", "0x001d,0x0017,0x0018")],
            },
            NormalizedTlsExtension {
                extension_type: 51,
                name: "key_share".to_owned(),
                position: 1,
                encoded_len: 38,
                attributes: vec![attribute("key_share_shape", "0x001d:32")],
            },
        ];
        fixture.bundle_sha256 = recompute_bundle_sha256(&fixture).expect("rehash fixture");

        let plan = build_replay_plan(
            &fixture,
            &BackendDescriptor::upstream_boring_h2(),
            TransportTarget {
                kind: TargetKind::ControlledCapture,
                authority: "capture.invalid".to_owned(),
                port: 9443,
            },
            AuditMode::Probe,
        )
        .expect("build replay plan");

        assert_eq!(plan.tls.supported_group_ids, vec![0x001d, 0x0017, 0x0018]);
        assert_eq!(plan.tls.key_share_group_ids, vec![0x001d]);
        assert_eq!(plan.schema_version, TRANSPORT_PLAN_SCHEMA_VERSION);
    }

    #[test]
    fn upstream_backend_blocks_canary_until_wire_evidence_exists() {
        let audit = audit_bundle(
            &bundle(),
            &BackendDescriptor::upstream_boring_h2(),
            AuditMode::Canary,
        )
        .expect("audit bundle");
        assert_eq!(audit.decision, AuditDecision::Blocked);
        assert!(audit.blocker_count > 0);
    }

    #[test]
    fn canary_tls_evidence_releases_only_bound_wire_controls() {
        let fixture = bundle();
        let backend = BackendDescriptor::upstream_boring_h2();
        let probe_plan = build_replay_plan(
            &fixture,
            &backend,
            TransportTarget {
                kind: TargetKind::AnthropicOfficial,
                authority: "api.anthropic.com".to_owned(),
                port: 443,
            },
            AuditMode::Probe,
        )
        .expect("build official probe plan");
        let reference = official_tls_capture(CaptureLane::ReferenceOfficialTls);
        let candidate = official_tls_capture(CaptureLane::ReplayOfficialTls);
        let report = compare_captures(&reference, &candidate, &DiffPolicy::default())
            .expect("compare exact TLS captures");
        let evidence = build_canary_tls_evidence(
            &probe_plan,
            "spike-cli/fixture+sha256:fixture",
            &reference,
            &candidate,
            &report,
        )
        .expect("build Canary TLS evidence");
        verify_canary_tls_evidence(&evidence).expect("verify Canary TLS evidence");

        let audit = audit_bundle_with_tls_evidence(
            &fixture,
            &backend,
            AuditMode::Canary,
            &probe_plan,
            "spike-cli/fixture+sha256:fixture",
            std::slice::from_ref(&evidence),
        )
        .expect("consume Canary TLS evidence");
        for control in [
            ControlPoint::TlsCipherOrder,
            ControlPoint::TlsExtensionOrder,
            ControlPoint::TlsClientHelloLength,
            ControlPoint::TlsRecordFraming,
        ] {
            let item = audit
                .items
                .iter()
                .find(|item| item.control == control)
                .expect("TLS control is present");
            assert!(!item.blocking);
            assert_eq!(
                item.verification_evidence,
                vec![evidence.evidence_sha256.clone()]
            );
        }
        assert!(
            audit
                .items
                .iter()
                .find(|item| item.control == ControlPoint::CancellationBehavior)
                .expect("cancellation control is present")
                .blocking
        );
    }

    #[test]
    fn canary_tls_evidence_rejects_tampering_and_engine_drift() {
        let fixture = bundle();
        let backend = BackendDescriptor::upstream_boring_h2();
        let probe_plan = build_replay_plan(
            &fixture,
            &backend,
            TransportTarget {
                kind: TargetKind::AnthropicOfficial,
                authority: "api.anthropic.com".to_owned(),
                port: 443,
            },
            AuditMode::Probe,
        )
        .expect("build official probe plan");
        let reference = official_tls_capture(CaptureLane::ReferenceOfficialTls);
        let candidate = official_tls_capture(CaptureLane::ReplayOfficialTls);
        let report = compare_captures(&reference, &candidate, &DiffPolicy::default())
            .expect("compare exact TLS captures");
        let evidence =
            build_canary_tls_evidence(&probe_plan, "engine-a", &reference, &candidate, &report)
                .expect("build Canary TLS evidence");

        let mut tampered = evidence.clone();
        tampered.verified_controls.pop();
        assert!(matches!(
            verify_canary_tls_evidence(&tampered),
            Err(TransportError::InvalidCanaryTlsEvidence)
        ));
        assert!(matches!(
            audit_bundle_with_tls_evidence(
                &fixture,
                &backend,
                AuditMode::Canary,
                &probe_plan,
                "engine-b",
                &[evidence],
            ),
            Err(TransportError::CanaryEvidenceBindingMismatch)
        ));
    }

    #[test]
    fn combined_tls_and_cancellation_evidence_unlocks_http1_canary() {
        let fixture = http1_bundle();
        let backend = BackendDescriptor::upstream_boring_h2();
        let official_plan = build_replay_plan(
            &fixture,
            &backend,
            TransportTarget {
                kind: TargetKind::AnthropicOfficial,
                authority: "api.anthropic.com".to_owned(),
                port: 443,
            },
            AuditMode::Probe,
        )
        .expect("build official H1 probe plan");
        let controlled_plan = build_replay_plan(
            &fixture,
            &backend,
            TransportTarget {
                kind: TargetKind::ControlledCapture,
                authority: "capture.invalid".to_owned(),
                port: 9443,
            },
            AuditMode::Probe,
        )
        .expect("build controlled H1 probe plan");
        let reference = official_tls_capture(CaptureLane::ReferenceOfficialTls);
        let candidate = official_tls_capture(CaptureLane::ReplayOfficialTls);
        let report = compare_captures(&reference, &candidate, &DiffPolicy::default())
            .expect("compare exact TLS captures");
        let tls_evidence =
            build_canary_tls_evidence(&official_plan, "engine-a", &reference, &candidate, &report)
                .expect("build TLS evidence");
        let cancellation_evidence = build_canary_cancellation_evidence(
            &controlled_plan,
            "engine-a",
            &H1CancellationObservation {
                response_status: 200,
                response_bytes_before_cancel: 256,
                stage: CancellationStage::ResponseStreaming,
                protocol_action: ProtocolAction::CloseConnection,
                connection_reusable: false,
                response_bytes_preserved: true,
            },
            true,
        )
        .expect("build cancellation evidence");

        let audit = audit_bundle_with_canary_evidence(
            &fixture,
            &backend,
            AuditMode::Canary,
            &[official_plan, controlled_plan],
            "engine-a",
            &[tls_evidence],
            &[cancellation_evidence],
        )
        .expect("consume combined Canary evidence");
        assert_eq!(audit.decision, AuditDecision::ReadyForCanary);
        assert_eq!(audit.blocker_count, 0);
    }

    #[test]
    fn builds_secret_free_probe_plan() {
        let plan = build_replay_plan(
            &bundle(),
            &BackendDescriptor::upstream_boring_h2(),
            TransportTarget {
                kind: TargetKind::AnthropicOfficial,
                authority: "api.anthropic.com".to_owned(),
                port: 443,
            },
            AuditMode::Probe,
        )
        .expect("build replay plan");
        assert_eq!(plan.audit.decision, AuditDecision::ReadyForProbe);
        assert_eq!(plan.tls.alpn_wire, b"\x02h2");
        assert_eq!(plan.http2().expect("HTTP/2 plan").settings_order, vec![1]);
        assert_eq!(plan.plan_sha256.len(), 64);
        h2_backend::build_client(&plan).expect("configure h2 builder");
        verify_replay_plan(&plan).expect("verify replay plan");
    }

    #[test]
    fn replay_plan_verifier_detects_tampering() {
        let mut plan = build_replay_plan(
            &bundle(),
            &BackendDescriptor::upstream_boring_h2(),
            TransportTarget {
                kind: TargetKind::ControlledCapture,
                authority: "capture.invalid".to_owned(),
                port: 9443,
            },
            AuditMode::Probe,
        )
        .expect("build replay plan");
        plan.target.port = 443;
        assert!(matches!(
            verify_replay_plan(&plan),
            Err(TransportError::InvalidPlan)
        ));
    }

    #[cfg(feature = "boring-backend")]
    #[test]
    fn boring_backend_rejects_malformed_explicit_trust_roots() {
        let plan = build_replay_plan(
            &bundle(),
            &BackendDescriptor::upstream_boring_h2(),
            TransportTarget {
                kind: TargetKind::ControlledCapture,
                authority: "capture.invalid".to_owned(),
                port: 9443,
            },
            AuditMode::Probe,
        )
        .expect("build replay plan");
        assert!(matches!(
            boring_backend::build_connector_with_trust_roots(&plan, Some(b"not a PEM certificate")),
            Err(TransportError::BackendConfiguration(_))
        ));
    }

    #[test]
    fn h2_backend_rejects_unknown_setting_without_fallback() {
        let mut fixture = bundle();
        let ApplicationProfileSpec::Http2(http2) = &mut fixture.application else {
            panic!("expected HTTP/2 fixture");
        };
        if let NormalizedHttp2FrameDetail::Settings { entries } = &mut http2.client_frames[0].detail
        {
            entries.push(Http2Setting {
                id: 65_000,
                value: 1,
            });
        }
        fixture.bundle_sha256 = recompute_bundle_sha256(&fixture).expect("rehash fixture");
        let plan = build_replay_plan(
            &fixture,
            &BackendDescriptor::upstream_boring_h2(),
            TransportTarget {
                kind: TargetKind::ControlledCapture,
                authority: "capture.invalid".to_owned(),
                port: 9443,
            },
            AuditMode::Probe,
        )
        .expect("build probe plan");
        assert!(matches!(
            h2_backend::build_client(&plan),
            Err(TransportError::BackendConfiguration(_))
        ));
    }

    #[test]
    fn rejects_non_anthropic_official_target() {
        assert!(matches!(
            build_replay_plan(
                &bundle(),
                &BackendDescriptor::upstream_boring_h2(),
                TransportTarget {
                    kind: TargetKind::AnthropicOfficial,
                    authority: "example.com".to_owned(),
                    port: 443,
                },
                AuditMode::Probe,
            ),
            Err(TransportError::InvalidTarget)
        ));
    }

    #[test]
    fn canary_plan_fails_closed() {
        assert!(matches!(
            build_replay_plan(
                &bundle(),
                &BackendDescriptor::upstream_boring_h2(),
                TransportTarget {
                    kind: TargetKind::ControlledCapture,
                    authority: "capture.invalid".to_owned(),
                    port: 9443,
                },
                AuditMode::Canary,
            ),
            Err(TransportError::CapabilityBlocked(_))
        ));
    }
}
