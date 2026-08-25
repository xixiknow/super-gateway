//! Strict signed Transport Bundle ABI, trust store and loader.

use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const ENVELOPE_VERSION: &str = "1.0.0";
const SCHEMA_VERSION: &str = "1.0.0";
const SIGNATURE_DOMAIN: &str = "transport_bundle_v1";
const POOL_FIELDS: [&str; 9] = [
    "credential_id",
    "profile_epoch",
    "bundle_id",
    "bundle_version",
    "egress_binding_id",
    "egress_epoch",
    "authority",
    "sni",
    "protocol",
];

/// Publication lifecycle, orthogonal to runtime quarantine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleLifecycle {
    /// Authored but not evidence-verified.
    Draft,
    /// Offline evidence and construction checks passed.
    Verified,
    /// Explicit Credential cohort may use it.
    Canary,
    /// New compatible Credentials may receive it.
    Active,
    /// No new assignment.
    Retired,
}

/// Offline evidence decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleEvidenceGate {
    /// Evidence is incomplete.
    Pending,
    /// Evidence gates passed.
    Passed,
    /// At least one evidence gate failed.
    Failed,
}

/// Orthogonal runtime state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleRuntimeState {
    /// Artifact may be compiled when all other gates pass.
    Loadable,
    /// Artifact is excluded from new attempts.
    Quarantined,
}

/// One ordered, non-secret application header template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderTemplate {
    /// Exact wire name/casing.
    pub name: Box<str>,
    /// Template expression, never populated production secret material.
    pub value_template: Box<str>,
    /// Whether the rendered value must be redacted in all observers.
    pub sensitive: bool,
}

/// TLS controls whose availability and wire evidence are checked separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsProfile {
    /// Stable profile identifier tied to capture evidence.
    pub client_hello_profile: Box<str>,
    /// Exact ALPN offer order.
    pub alpn: Vec<Box<str>>,
    /// Ordered TLS cipher suite IDs observed for the cohort.
    pub cipher_suite_ids: Vec<u16>,
    /// Ordered supported group IDs.
    pub supported_group_ids: Vec<u16>,
    /// Ordered offered key-share group IDs.
    pub key_share_group_ids: Vec<u16>,
    /// Expected `ClientHello` extension IDs used for control/evidence auditing.
    pub extension_order: Vec<u16>,
    /// Whether `BoringSSL` GREASE is enabled.
    pub grease_enabled: bool,
    /// Whether `BoringSSL` extension permutation is enabled.
    pub permute_extensions: bool,
    /// Resumption remains false until its own evidence gate passes.
    pub session_resumption: bool,
}

/// HTTP/1.1 wire profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http1Profile {
    /// Request target form, currently `origin`.
    pub request_line_form: Box<str>,
    /// Bundle-provided ordered header templates.
    pub header_order: Vec<HeaderTemplate>,
    /// Request framing, currently `content-length`.
    pub framing: Box<str>,
}

/// HTTP/2 wire profile kept activation-gated until real cohort evidence exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http2Profile {
    /// Ordered SETTINGS names.
    pub settings_order: Vec<Box<str>>,
    /// Initial stream window.
    pub initial_window_size: u32,
    /// Ordered pseudo headers.
    pub pseudo_header_order: Vec<Box<str>>,
    /// Ordered ordinary header templates.
    pub header_order: Vec<HeaderTemplate>,
}

/// Connection isolation and reuse contract embedded in every Bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleConnectionPolicy {
    /// Exact nine semantic fields used by the runtime `PoolKey`.
    pub pool_key_fields: Vec<Box<str>>,
    /// Expected `exact_pool_key`.
    pub reuse_policy: Box<str>,
    /// `disabled` until resumption evidence exists.
    pub resumption_cache_scope: Box<str>,
}

/// Protocol-discriminated application profile. H1 and H2 fields cannot coexist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApplicationProfile {
    /// HTTP/1.1 Bundle.
    H1 {
        /// Fixed Anthropic authority.
        authority: Box<str>,
        /// TLS controls.
        tls: TlsProfile,
        /// H1 controls.
        http1: Http1Profile,
        /// Connection isolation.
        connection: BundleConnectionPolicy,
    },
    /// HTTP/2 Bundle.
    H2 {
        /// Fixed Anthropic authority.
        authority: Box<str>,
        /// TLS controls.
        tls: TlsProfile,
        /// H2 controls.
        http2: Http2Profile,
        /// Connection isolation.
        connection: BundleConnectionPolicy,
    },
}

impl ApplicationProfile {
    fn tls(&self) -> &TlsProfile {
        match self {
            Self::H1 { tls, .. } | Self::H2 { tls, .. } => tls,
        }
    }

    fn connection(&self) -> &BundleConnectionPolicy {
        match self {
            Self::H1 { connection, .. } | Self::H2 { connection, .. } => connection,
        }
    }

    fn authority(&self) -> &str {
        match self {
            Self::H1 { authority, .. } | Self::H2 { authority, .. } => authority,
        }
    }
}

/// One engine artifact bound to a supported native target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineBuild {
    /// Rust target triple.
    pub target: Box<str>,
    /// Release artifact SHA-256.
    pub artifact_digest: Box<str>,
    /// Pinned `BoringSSL` revision.
    pub boringssl_revision: Box<str>,
    /// Compiler/toolchain description.
    pub compiler: Box<str>,
}

/// Canonical, secret-free signed payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportBundlePayload {
    /// Payload schema.
    pub schema_version: Box<str>,
    /// Runtime semantic ABI.
    pub engine_abi_version: Box<str>,
    /// Stable artifact family identity.
    pub bundle_id: Box<str>,
    /// Monotonic artifact version.
    pub artifact_version: u64,
    /// Publication lifecycle.
    pub lifecycle: BundleLifecycle,
    /// Evidence decision.
    pub evidence_gate: BundleEvidenceGate,
    /// Runtime quarantine state.
    pub runtime_state: BundleRuntimeState,
    /// Required transport backend.
    pub backend_id: Box<str>,
    /// Fail-closed capability names.
    pub required_capabilities: Vec<Box<str>>,
    /// Source Archetype version.
    pub source_archetype_version_id: Box<str>,
    /// Stable capture cohort.
    pub capture_cohort: Box<str>,
    /// Exactly one protocol profile.
    pub application: ApplicationProfile,
    /// Minimum compatible release build.
    pub min_engine_build: Box<str>,
    /// Optional maximum compatible release build.
    pub max_engine_build: Option<Box<str>>,
    /// Native release evidence.
    pub engine_builds: Vec<EngineBuild>,
    /// Targets for which this Bundle may be compiled.
    pub supported_targets: Vec<Box<str>>,
    /// Referenced evidence SHA-256 digests.
    pub evidence_hashes: Vec<Box<str>>,
    /// Artifact creation time.
    pub created_at: Box<str>,
}

/// Canonicalization and detached payload hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleCanonicalization {
    /// Must be `jcs_rfc8785`.
    pub algorithm: Box<str>,
    /// Must be `sha256`.
    pub hash_algorithm: Box<str>,
    /// SHA-256 of the JCS payload only; it is outside its own preimage.
    pub canonical_hash: Box<str>,
}

/// Detached signature metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSignature {
    /// Domain-separated signature namespace.
    pub domain: Box<str>,
    /// Must be `ed25519`.
    pub algorithm: Box<str>,
    /// Public key identity in the `TrustStore`.
    pub key_id: Box<str>,
    /// Detached 64-byte Ed25519 signature.
    pub detached_signature_base64: Box<str>,
}

/// Signed Bundle envelope. Hash/signature fields never enter payload canonicalization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBundleEnvelope {
    /// Envelope schema.
    pub envelope_version: Box<str>,
    /// Canonical signed payload.
    pub payload: TransportBundlePayload,
    /// Canonicalization metadata.
    pub canonicalization: BundleCanonicalization,
    /// Detached signature.
    pub signature: BundleSignature,
}

/// Trust key state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustKeyStatus {
    /// May approve a new activation and verify an existing artifact.
    Current,
    /// May only verify an already-approved historical artifact.
    Historical,
    /// Reject every artifact signed by this key.
    Revoked,
}

/// One Ed25519 Bundle verification key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustKey {
    /// Stable key ID.
    pub key_id: Box<str>,
    /// Key state.
    pub status: TrustKeyStatus,
    /// Raw 32-byte Ed25519 public key.
    pub public_key_base64: Box<str>,
    /// Optional inclusive Unix-second lower bound.
    pub valid_from_unix_seconds: Option<u64>,
    /// Optional exclusive Unix-second upper bound.
    pub valid_until_unix_seconds: Option<u64>,
}

/// Public-key-only production Bundle `TrustStore`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleTrustStore {
    /// `TrustStore` schema.
    pub format_version: Box<str>,
    /// Must match the Bundle signature domain.
    pub domain: Box<str>,
    /// Approved public keys.
    pub keys: Vec<TrustKey>,
}

/// Runtime facts used by the strict Bundle loader.
#[derive(Clone, Debug)]
pub struct BundleLoadContext {
    /// Supported semantic ABI.
    pub engine_abi_version: Box<str>,
    /// Running release build version.
    pub engine_build: Box<str>,
    /// Native Rust target.
    pub target: Box<str>,
    /// Backend capabilities implemented and enabled in this build.
    pub supported_capabilities: BTreeSet<Box<str>>,
    /// Current Unix time for `TrustStore` validity windows.
    pub now_unix_seconds: u64,
    /// True when approving a new canary/active pointer; historical keys then fail closed.
    pub for_new_activation: bool,
}

/// Fully verified payload plus its canonical bytes/hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    /// Verified payload.
    pub payload: TransportBundlePayload,
    /// Exact RFC 8785 bytes used for hash/signature verification.
    pub canonical_payload: Vec<u8>,
    /// Lowercase payload SHA-256.
    pub canonical_hash: Box<str>,
    /// Key that verified the signature.
    pub signer_key_id: Box<str>,
}

/// Bundle loader rejection.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BundleLoadError {
    /// Strict JSON decoding failed, including unknown fields.
    #[error("bundle envelope schema rejected")]
    Schema,
    /// Envelope, signature domain or canonicalization algorithm is unsupported.
    #[error("bundle envelope algorithm rejected")]
    Algorithm,
    /// Canonical payload hash differs from the envelope.
    #[error("bundle payload hash mismatch")]
    HashMismatch,
    /// Signing key is absent, revoked, invalid, expired or unauthorized for activation.
    #[error("bundle trust key rejected")]
    Trust,
    /// Ed25519 verification failed.
    #[error("bundle signature rejected")]
    Signature,
    /// ABI, target or engine build range does not match.
    #[error("bundle engine compatibility rejected")]
    Compatibility,
    /// Required capability is not implemented/enabled.
    #[error("bundle required capability unavailable")]
    Capability,
    /// Lifecycle/evidence/runtime state is not loadable.
    #[error("bundle lifecycle or evidence gate rejected")]
    Lifecycle,
    /// Pool, authority, protocol or resumption contract is inconsistent.
    #[error("bundle wire contract rejected")]
    WireContract,
    /// Payload appears to contain literal secret material.
    #[error("bundle privacy scan rejected")]
    Privacy,
}

impl SignedBundleEnvelope {
    /// Decode a strict JSON envelope and verify all cryptographic/runtime gates.
    ///
    /// # Errors
    ///
    /// Returns a stable fail-closed [`BundleLoadError`] for any invalid or unknown input.
    pub fn verify_json(
        bytes: &[u8],
        trust_store: &BundleTrustStore,
        context: &BundleLoadContext,
    ) -> Result<VerifiedBundle, BundleLoadError> {
        let envelope: Self = serde_json::from_slice(bytes).map_err(|_| BundleLoadError::Schema)?;
        envelope.verify(trust_store, context)
    }

    /// Verify a decoded strict envelope.
    ///
    /// # Errors
    ///
    /// Returns a stable fail-closed [`BundleLoadError`] for any failed gate.
    pub fn verify(
        self,
        trust_store: &BundleTrustStore,
        context: &BundleLoadContext,
    ) -> Result<VerifiedBundle, BundleLoadError> {
        validate_algorithms(&self, trust_store)?;
        validate_payload(&self.payload, context)?;
        let canonical_payload = serde_jcs::to_vec(&self.payload).map_err(|_| BundleLoadError::Schema)?;
        if contains_literal_secret(&canonical_payload) {
            return Err(BundleLoadError::Privacy);
        }
        let canonical_hash = sha256_hex(&canonical_payload);
        if canonical_hash != self.canonicalization.canonical_hash.as_ref() {
            return Err(BundleLoadError::HashMismatch);
        }
        let key = select_key(trust_store, &self.signature.key_id, context)?;
        verify_signature(key, &self.signature, &canonical_hash, &canonical_payload)?;
        Ok(VerifiedBundle {
            payload: self.payload,
            canonical_payload,
            canonical_hash: canonical_hash.into_boxed_str(),
            signer_key_id: key.key_id.clone(),
        })
    }
}

fn validate_algorithms(envelope: &SignedBundleEnvelope, trust_store: &BundleTrustStore) -> Result<(), BundleLoadError> {
    if envelope.envelope_version.as_ref() != ENVELOPE_VERSION
        || envelope.payload.schema_version.as_ref() != SCHEMA_VERSION
        || envelope.canonicalization.algorithm.as_ref() != "jcs_rfc8785"
        || envelope.canonicalization.hash_algorithm.as_ref() != "sha256"
        || envelope.signature.domain.as_ref() != SIGNATURE_DOMAIN
        || envelope.signature.algorithm.as_ref() != "ed25519"
        || trust_store.domain.as_ref() != SIGNATURE_DOMAIN
        || trust_store.format_version.as_ref() != ENVELOPE_VERSION
    {
        return Err(BundleLoadError::Algorithm);
    }
    Ok(())
}

fn validate_payload(payload: &TransportBundlePayload, context: &BundleLoadContext) -> Result<(), BundleLoadError> {
    if payload.engine_abi_version != context.engine_abi_version
        || payload.bundle_id.is_empty()
        || payload.artifact_version == 0
        || payload.evidence_hashes.is_empty()
        || !payload.supported_targets.contains(&context.target)
        || !payload.engine_builds.iter().any(|build| build.target == context.target)
    {
        return Err(BundleLoadError::Compatibility);
    }
    let current = Version::parse(&context.engine_build).map_err(|_| BundleLoadError::Compatibility)?;
    let minimum = Version::parse(&payload.min_engine_build).map_err(|_| BundleLoadError::Compatibility)?;
    let maximum = payload
        .max_engine_build
        .as_deref()
        .map(Version::parse)
        .transpose()
        .map_err(|_| BundleLoadError::Compatibility)?;
    if current < minimum || maximum.is_some_and(|maximum| current > maximum) {
        return Err(BundleLoadError::Compatibility);
    }
    if payload
        .required_capabilities
        .iter()
        .any(|capability| !context.supported_capabilities.contains(capability))
    {
        return Err(BundleLoadError::Capability);
    }
    if payload.evidence_gate != BundleEvidenceGate::Passed
        || payload.runtime_state != BundleRuntimeState::Loadable
        || matches!(payload.lifecycle, BundleLifecycle::Draft | BundleLifecycle::Retired)
    {
        return Err(BundleLoadError::Lifecycle);
    }
    let application = &payload.application;
    if application.authority() != "api.anthropic.com"
        || application
            .connection()
            .pool_key_fields
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            != POOL_FIELDS
        || application.connection().reuse_policy.as_ref() != "exact_pool_key"
        || application.tls().session_resumption
        || application.connection().resumption_cache_scope.as_ref() != "disabled"
    {
        return Err(BundleLoadError::WireContract);
    }
    match application {
        ApplicationProfile::H1 { tls, http1, .. } => {
            if !tls.alpn.iter().any(|value| value.as_ref() == "http/1.1")
                || tls.alpn.iter().any(|value| value.as_ref() == "h2")
                || http1.request_line_form.as_ref() != "origin"
                || http1.framing.as_ref() != "content-length"
            {
                return Err(BundleLoadError::WireContract);
            }
        }
        ApplicationProfile::H2 { tls, .. } => {
            if tls.alpn.first().map(AsRef::as_ref) != Some("h2") {
                return Err(BundleLoadError::WireContract);
            }
        }
    }
    Ok(())
}

fn select_key<'a>(
    trust_store: &'a BundleTrustStore,
    key_id: &str,
    context: &BundleLoadContext,
) -> Result<&'a TrustKey, BundleLoadError> {
    let mut matches = trust_store.keys.iter().filter(|key| key.key_id.as_ref() == key_id);
    let key = matches.next().ok_or(BundleLoadError::Trust)?;
    if matches.next().is_some()
        || key.status == TrustKeyStatus::Revoked
        || (context.for_new_activation && key.status != TrustKeyStatus::Current)
        || key
            .valid_from_unix_seconds
            .is_some_and(|start| context.now_unix_seconds < start)
        || key
            .valid_until_unix_seconds
            .is_some_and(|end| context.now_unix_seconds >= end)
    {
        return Err(BundleLoadError::Trust);
    }
    Ok(key)
}

fn verify_signature(
    key: &TrustKey,
    signature: &BundleSignature,
    canonical_hash: &str,
    canonical_payload: &[u8],
) -> Result<(), BundleLoadError> {
    let public_bytes = STANDARD
        .decode(key.public_key_base64.as_bytes())
        .map_err(|_| BundleLoadError::Trust)?;
    let public_array: [u8; 32] = public_bytes.try_into().map_err(|_| BundleLoadError::Trust)?;
    let verifying_key = VerifyingKey::from_bytes(&public_array).map_err(|_| BundleLoadError::Trust)?;
    let signature_bytes = STANDARD
        .decode(signature.detached_signature_base64.as_bytes())
        .map_err(|_| BundleLoadError::Signature)?;
    let parsed_signature = Signature::from_slice(&signature_bytes).map_err(|_| BundleLoadError::Signature)?;
    verifying_key
        .verify_strict(
            &signature_preimage(canonical_hash, canonical_payload),
            &parsed_signature,
        )
        .map_err(|_| BundleLoadError::Signature)
}

fn signature_preimage(canonical_hash: &str, canonical_payload: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical_hash.len() + canonical_payload.len() + 2);
    preimage.extend_from_slice(SIGNATURE_DOMAIN.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(canonical_hash.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(canonical_payload);
    preimage
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut rendered = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(rendered, "{byte:02x}");
    }
    rendered
}

fn contains_literal_secret(canonical_payload: &[u8]) -> bool {
    let lowered = String::from_utf8_lossy(canonical_payload).to_ascii_lowercase();
    ["bearer ", "sk-ant-", "setup-token-", "refresh_token\":\""]
        .iter()
        .any(|marker| lowered.contains(marker))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::{
        ApplicationProfile, BundleCanonicalization, BundleConnectionPolicy, BundleEvidenceGate, BundleLifecycle,
        BundleLoadContext, BundleLoadError, BundleRuntimeState, BundleSignature, BundleTrustStore, EngineBuild,
        HeaderTemplate, Http1Profile, SignedBundleEnvelope, TlsProfile, TransportBundlePayload, TrustKey,
        TrustKeyStatus, sha256_hex, signature_preimage,
    };

    fn signed_fixture() -> (Vec<u8>, BundleTrustStore, BundleLoadContext) {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let connection = BundleConnectionPolicy {
            pool_key_fields: super::POOL_FIELDS.into_iter().map(Into::into).collect(),
            reuse_policy: "exact_pool_key".into(),
            resumption_cache_scope: "disabled".into(),
        };
        let payload = TransportBundlePayload {
            schema_version: "1.0.0".into(),
            engine_abi_version: "1.0".into(),
            bundle_id: "bundle_test".into(),
            artifact_version: 1,
            lifecycle: BundleLifecycle::Verified,
            evidence_gate: BundleEvidenceGate::Passed,
            runtime_state: BundleRuntimeState::Loadable,
            backend_id: "boringssl-h1-v1".into(),
            required_capabilities: vec!["tls_client_hello".into(), "ordered_http1".into()],
            source_archetype_version_id: "arch_test".into(),
            capture_cohort: "windows-test".into(),
            application: ApplicationProfile::H1 {
                authority: "api.anthropic.com".into(),
                tls: TlsProfile {
                    client_hello_profile: "test".into(),
                    alpn: vec!["http/1.1".into()],
                    cipher_suite_ids: vec![0x1301, 0x1302, 0x1303, 0xc02f],
                    supported_group_ids: vec![0x001d, 0x0017],
                    key_share_group_ids: vec![0x001d],
                    extension_order: vec![0, 11, 10, 16, 5, 18],
                    grease_enabled: true,
                    permute_extensions: false,
                    session_resumption: false,
                },
                http1: Http1Profile {
                    request_line_form: "origin".into(),
                    header_order: vec![HeaderTemplate {
                        name: "host".into(),
                        value_template: "{authority}".into(),
                        sensitive: false,
                    }],
                    framing: "content-length".into(),
                },
                connection,
            },
            min_engine_build: "0.1.0".into(),
            max_engine_build: None,
            engine_builds: vec![EngineBuild {
                target: "x86_64-pc-windows-msvc".into(),
                artifact_digest: "a".repeat(64).into_boxed_str(),
                boringssl_revision: "test".into(),
                compiler: "rustc".into(),
            }],
            supported_targets: vec!["x86_64-pc-windows-msvc".into()],
            evidence_hashes: vec!["b".repeat(64).into_boxed_str()],
            created_at: "2026-08-24T00:00:00Z".into(),
        };
        let canonical = serde_jcs::to_vec(&payload).unwrap_or_default();
        let hash = sha256_hex(&canonical);
        let signature = signing_key.sign(&signature_preimage(&hash, &canonical));
        let envelope = SignedBundleEnvelope {
            envelope_version: "1.0.0".into(),
            payload,
            canonicalization: BundleCanonicalization {
                algorithm: "jcs_rfc8785".into(),
                hash_algorithm: "sha256".into(),
                canonical_hash: hash.into_boxed_str(),
            },
            signature: BundleSignature {
                domain: "transport_bundle_v1".into(),
                algorithm: "ed25519".into(),
                key_id: "test-key".into(),
                detached_signature_base64: STANDARD.encode(signature.to_bytes()).into_boxed_str(),
            },
        };
        let store = BundleTrustStore {
            format_version: "1.0.0".into(),
            domain: "transport_bundle_v1".into(),
            keys: vec![TrustKey {
                key_id: "test-key".into(),
                status: TrustKeyStatus::Current,
                public_key_base64: STANDARD.encode(signing_key.verifying_key().to_bytes()).into_boxed_str(),
                valid_from_unix_seconds: None,
                valid_until_unix_seconds: None,
            }],
        };
        let context = BundleLoadContext {
            engine_abi_version: "1.0".into(),
            engine_build: "0.1.0".into(),
            target: "x86_64-pc-windows-msvc".into(),
            supported_capabilities: BTreeSet::from(["tls_client_hello".into(), "ordered_http1".into()]),
            now_unix_seconds: 1_777_161_600,
            for_new_activation: true,
        };
        (serde_json::to_vec(&envelope).unwrap_or_default(), store, context)
    }

    #[test]
    fn verifies_jcs_hash_and_ed25519_signature() {
        let (bytes, store, context) = signed_fixture();
        let verified = SignedBundleEnvelope::verify_json(&bytes, &store, &context);
        assert!(verified.is_ok());
    }

    #[test]
    fn rejects_unknown_fields_and_payload_mutation() {
        let (bytes, store, context) = signed_fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        value["payload"]["unknown"] = serde_json::json!(true);
        let unknown = serde_json::to_vec(&value).unwrap_or_default();
        assert_eq!(
            SignedBundleEnvelope::verify_json(&unknown, &store, &context),
            Err(BundleLoadError::Schema)
        );

        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        value["payload"]["capture_cohort"] = serde_json::json!("mutated");
        let mutated = serde_json::to_vec(&value).unwrap_or_default();
        assert_eq!(
            SignedBundleEnvelope::verify_json(&mutated, &store, &context),
            Err(BundleLoadError::HashMismatch)
        );
    }

    #[test]
    fn historical_key_cannot_approve_new_activation() {
        let (bytes, mut store, context) = signed_fixture();
        store.keys[0].status = TrustKeyStatus::Historical;
        assert_eq!(
            SignedBundleEnvelope::verify_json(&bytes, &store, &context),
            Err(BundleLoadError::Trust)
        );
    }

    #[test]
    fn missing_capability_fails_closed() {
        let (bytes, store, mut context) = signed_fixture();
        context.supported_capabilities.remove("ordered_http1");
        assert_eq!(
            SignedBundleEnvelope::verify_json(&bytes, &store, &context),
            Err(BundleLoadError::Capability)
        );
    }
}
