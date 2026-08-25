//! Data-plane ports and immutable access/catalog snapshots.
#![allow(missing_docs, clippy::doc_markdown)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use gateway_domain::{
    AgentId, ClientClass, GenericAdjustedRequest, GroupId, PlatformKeyId, RequestId, SecretBytes, SecretValue,
    SessionId, TrafficClass, UserId,
};
use gateway_policy::RequestPolicy;
use gateway_services::security::lookup_digest;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// Endpoint permission attached to a Platform Key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointPermission {
    Messages,
    Models,
}

/// Token-bucket configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    pub requests_per_minute: u32,
    pub burst: u32,
}

impl RateLimit {
    /// Default Messages rate. It exists even when no administrator override is present.
    pub const DEFAULT_MESSAGES: Self = Self {
        requests_per_minute: 60,
        burst: 10,
    };

    /// Independent `/v1/models` default.
    pub const DEFAULT_MODELS: Self = Self {
        requests_per_minute: 60,
        burst: 10,
    };
}

/// Explicit-probe action configured at Group scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeAction {
    #[default]
    Observe,
    Throttle,
    Reject,
}

/// One strong, deterministic Background Catalog signal. All signals in an
/// entry must match before the request can be classified as explicit
/// background traffic.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackgroundSignal {
    HeaderEquals { name: Box<str>, value: Box<str> },
    HeaderContains { name: Box<str>, value: Box<str> },
    BodyEquals { pointer: Box<str>, value: Value },
    BodyPresent { pointer: Box<str> },
}

/// A published, deterministic Background Catalog entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundCatalogEntry {
    pub id: Box<str>,
    pub action: ProbeAction,
    #[serde(default)]
    pub client_classes: BTreeSet<ClientClass>,
    pub match_all: Vec<BackgroundSignal>,
}

/// Versioned Background Catalog payload stored inside the generic Artifact
/// envelope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundCatalogDocument {
    pub entries: Vec<BackgroundCatalogEntry>,
}

/// Immutable, validated Background Catalog shared by every AccessGrant in one
/// management-runtime generation.
#[derive(Clone, Debug, Default)]
pub struct BackgroundCatalog {
    entries: Arc<[BackgroundCatalogEntry]>,
    action_by_id: Arc<BTreeMap<Box<str>, ProbeAction>>,
}

impl BackgroundCatalog {
    /// Compile a catalog and reject ambiguous duplicate match definitions.
    ///
    /// # Errors
    ///
    /// Returns [`BackgroundCatalogError`] when the catalog is empty, exceeds
    /// its bounds, contains an invalid signal, or has ambiguous identities or
    /// match definitions.
    pub fn compile(mut document: BackgroundCatalogDocument) -> Result<Self, BackgroundCatalogError> {
        if document.entries.is_empty() || document.entries.len() > 10_000 {
            return Err(BackgroundCatalogError::EntryCount);
        }
        let mut ids = BTreeSet::new();
        let mut signatures = BTreeSet::new();
        for entry in &document.entries {
            if entry.id.is_empty()
                || entry.id.len() > 128
                || !entry
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
            {
                return Err(BackgroundCatalogError::EntryId);
            }
            if !ids.insert(entry.id.clone()) {
                return Err(BackgroundCatalogError::DuplicateEntryId);
            }
            if entry.match_all.is_empty() || entry.match_all.len() > 16 {
                return Err(BackgroundCatalogError::SignalCount);
            }
            for signal in &entry.match_all {
                validate_background_signal(signal)?;
            }
            let signature = serde_json::to_vec(&(entry.client_classes.clone(), entry.match_all.clone()))
                .map_err(|_| BackgroundCatalogError::InvalidSignal)?;
            if !signatures.insert(signature) {
                return Err(BackgroundCatalogError::DuplicateMatch);
            }
        }
        // More-specific templates win, while ID supplies a deterministic tie
        // breaker that is independent from JSON array order.
        document.entries.sort_by(|left, right| {
            right
                .match_all
                .len()
                .cmp(&left.match_all.len())
                .then_with(|| left.id.cmp(&right.id))
        });
        let action_by_id = document
            .entries
            .iter()
            .map(|entry| (entry.id.clone(), entry.action))
            .collect();
        Ok(Self {
            entries: document.entries.into(),
            action_by_id: Arc::new(action_by_id),
        })
    }

    #[must_use]
    pub fn classify(&self, headers: &http::HeaderMap, body: &Value, client_class: ClientClass) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| {
                (entry.client_classes.is_empty() || entry.client_classes.contains(&client_class))
                    && entry
                        .match_all
                        .iter()
                        .all(|signal| background_signal_matches(signal, headers, body))
            })
            .map(|entry| entry.id.as_ref())
    }

    #[must_use]
    pub fn action(&self, entry_id: &str) -> ProbeAction {
        self.action_by_id.get(entry_id).copied().unwrap_or(ProbeAction::Observe)
    }

    #[must_use]
    pub fn entries(&self) -> &[BackgroundCatalogEntry] {
        &self.entries
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackgroundCatalogError {
    #[error("Background Catalog must contain between 1 and 10000 entries")]
    EntryCount,
    #[error("Background Catalog entry id is invalid")]
    EntryId,
    #[error("Background Catalog entry id is duplicated")]
    DuplicateEntryId,
    #[error("Background Catalog entry must contain between 1 and 16 strong signals")]
    SignalCount,
    #[error("Background Catalog signal is invalid")]
    InvalidSignal,
    #[error("Background Catalog contains an ambiguous duplicate match")]
    DuplicateMatch,
}

fn validate_background_signal(signal: &BackgroundSignal) -> Result<(), BackgroundCatalogError> {
    match signal {
        BackgroundSignal::HeaderEquals { name, value } | BackgroundSignal::HeaderContains { name, value } => {
            if name.len() > 128
                || http::header::HeaderName::from_bytes(name.as_bytes()).is_err()
                || value.is_empty()
                || value.len() > 1_024
                || value.contains(['\r', '\n'])
            {
                return Err(BackgroundCatalogError::InvalidSignal);
            }
        }
        BackgroundSignal::BodyEquals { pointer, value } => {
            if !valid_catalog_pointer(pointer)
                || matches!(value, Value::Array(_) | Value::Object(_))
                || value.to_string().len() > 1_024
            {
                return Err(BackgroundCatalogError::InvalidSignal);
            }
        }
        BackgroundSignal::BodyPresent { pointer } => {
            if !valid_catalog_pointer(pointer) {
                return Err(BackgroundCatalogError::InvalidSignal);
            }
        }
    }
    Ok(())
}

fn valid_catalog_pointer(pointer: &str) -> bool {
    pointer.starts_with('/') && pointer.len() <= 256 && !pointer.contains("//") && !pointer.contains(['\r', '\n'])
}

fn background_signal_matches(signal: &BackgroundSignal, headers: &http::HeaderMap, body: &Value) -> bool {
    match signal {
        BackgroundSignal::HeaderEquals { name, value } => {
            unique_catalog_header(headers, name).is_some_and(|candidate| candidate == value.as_ref())
        }
        BackgroundSignal::HeaderContains { name, value } => unique_catalog_header(headers, name)
            .is_some_and(|candidate| candidate.to_ascii_lowercase().contains(&value.to_ascii_lowercase())),
        BackgroundSignal::BodyEquals { pointer, value } => {
            body.pointer(pointer).is_some_and(|candidate| candidate == value)
        }
        BackgroundSignal::BodyPresent { pointer } => body.pointer(pointer).is_some(),
    }
}

fn unique_catalog_header<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(first)
}

/// Effective request-frozen Content Audit decision. Group policy and a valid
/// two-person Key grant are resolved before the request can enter a queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ContentAuditMode {
    /// Metadata is retained, but request/response bodies are not captured.
    #[default]
    MetadataOnly,
    /// Original/final request and upstream response are encrypted for the
    /// frozen retention period.
    FullEncrypted { retention_days: u16 },
}

/// Fully resolved, request-frozen Platform Key/User/Group access projection.
#[derive(Clone, Debug)]
pub struct AccessGrant {
    pub owner_user_id: UserId,
    pub platform_key_id: PlatformKeyId,
    pub group_id: GroupId,
    pub permissions: BTreeSet<EndpointPermission>,
    /// Empty means all published models allowed.
    pub key_model_scope: BTreeSet<Box<str>>,
    /// Empty means all published models allowed.
    pub group_model_scope: BTreeSet<Box<str>>,
    /// Effective Body cap, still bounded by the platform hard cap.
    pub body_limit_bytes: usize,
    pub messages_rate: RateLimit,
    pub models_rate: RateLimit,
    /// Per-Key hard upper bound; defaults to five when created.
    pub concurrency_limit: u32,
    /// Empty means no source-IP restriction.
    pub ip_allowlist: Vec<IpNet>,
    pub accepted_client_classes: BTreeSet<ClientClass>,
    /// Compiled global Background Catalog frozen with this access generation.
    pub background_catalog: Arc<BackgroundCatalog>,
    pub probe_action: ProbeAction,
    /// Whether the special explicit-probe marker is authorized for this key/group.
    pub allow_explicit_probe_marker: bool,
    pub content_audit: ContentAuditMode,
    /// Key-scoped approval expiry. Group-required full audit has no expiry.
    pub content_audit_expires_at_unix_seconds: Option<u64>,
    /// Frozen policy/catalog artifact set.
    pub policy: Arc<RequestPolicy>,
}

/// Secret lookup boundary. Implementations return only active, unexpired, enabled grants.
pub trait AccessResolver: Send + Sync {
    /// Resolve by plaintext at the shortest possible boundary.
    fn resolve(&self, secret: &SecretValue) -> Option<Arc<AccessGrant>>;
}

/// Production-safe empty resolver used until an active access snapshot is published.
#[derive(Debug, Default)]
pub struct DenyAllAccessResolver;

impl AccessResolver for DenyAllAccessResolver {
    fn resolve(&self, _secret: &SecretValue) -> Option<Arc<AccessGrant>> {
        None
    }
}

/// Test/bootstrap resolver storing only SHA-256 lookup digests and comparing in constant time.
#[derive(Clone, Default)]
pub struct InMemoryAccessResolver {
    entries: Arc<[AccessDigestEntry]>,
}

type AccessDigestEntry = (Box<[u8; 32]>, Arc<AccessGrant>);

impl std::fmt::Debug for InMemoryAccessResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InMemoryAccessResolver")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl InMemoryAccessResolver {
    /// Build from plaintext fixtures, retaining no plaintext after construction.
    #[must_use]
    pub fn new(entries: Vec<(SecretValue, Arc<AccessGrant>)>) -> Self {
        let entries = entries
            .into_iter()
            .map(|(secret, grant)| {
                let digest: [u8; 32] = Sha256::digest(secret.expose().as_bytes()).into();
                (Box::new(digest), grant)
            })
            .collect::<Vec<_>>()
            .into();
        Self { entries }
    }
}

impl AccessResolver for InMemoryAccessResolver {
    fn resolve(&self, secret: &SecretValue) -> Option<Arc<AccessGrant>> {
        let candidate: [u8; 32] = Sha256::digest(secret.expose().as_bytes()).into();
        let mut found = None;
        for (digest, grant) in self.entries.iter() {
            if bool::from(digest.as_ref().ct_eq(&candidate)) {
                found = Some(freeze_content_audit(grant));
            }
        }
        found
    }
}

/// Production access snapshot backed by versioned keyed digests and immutable grants.
#[derive(Clone)]
pub struct VersionedDigestAccessResolver {
    digest_key: Arc<SecretBytes>,
    entries: Arc<[AccessDigestEntry]>,
}

impl std::fmt::Debug for VersionedDigestAccessResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VersionedDigestAccessResolver")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl VersionedDigestAccessResolver {
    /// Build an immutable active-key projection without retaining any plaintext key.
    #[must_use]
    pub fn new(digest_key: SecretBytes, entries: Vec<([u8; 32], Arc<AccessGrant>)>) -> Self {
        Self {
            digest_key: Arc::new(digest_key),
            entries: entries
                .into_iter()
                .map(|(digest, grant)| (Box::new(digest), grant))
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl AccessResolver for VersionedDigestAccessResolver {
    fn resolve(&self, secret: &SecretValue) -> Option<Arc<AccessGrant>> {
        let mut framed = b"platform-key:v1:".to_vec();
        framed.extend_from_slice(secret.expose().as_bytes());
        let candidate = lookup_digest(&self.digest_key, &SecretBytes::new(framed)).ok()?;
        let mut found = None;
        for (digest, grant) in self.entries.iter() {
            if bool::from(digest.as_ref().ct_eq(&candidate)) {
                found = Some(freeze_content_audit(grant));
            }
        }
        found
    }
}

fn freeze_content_audit(grant: &Arc<AccessGrant>) -> Arc<AccessGrant> {
    let expired = grant.content_audit_expires_at_unix_seconds.is_some_and(|expires| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(true, |now| now.as_secs() >= expires)
    });
    if !expired {
        return grant.clone();
    }
    let mut frozen = grant.as_ref().clone();
    frozen.content_audit = ContentAuditMode::MetadataOnly;
    Arc::new(frozen)
}

/// Published model projection used by `/v1/models`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRecord {
    pub id: Box<str>,
    pub display_name: Box<str>,
    pub created_at: Box<str>,
}

/// Stable model catalog port, independent of instantaneous Credential health.
pub trait ModelCatalog: Send + Sync {
    fn published(&self) -> Arc<[ModelRecord]>;
}

/// Immutable in-memory published catalog.
#[derive(Clone, Debug, Default)]
pub struct StaticModelCatalog {
    models: Arc<[ModelRecord]>,
}

impl StaticModelCatalog {
    /// Sort exact model IDs and reject neither aliases nor runtime health state.
    #[must_use]
    pub fn new(mut models: Vec<ModelRecord>) -> Self {
        models.sort_by(|left, right| left.id.cmp(&right.id));
        models.dedup_by(|left, right| left.id == right.id);
        Self { models: models.into() }
    }
}

impl ModelCatalog for StaticModelCatalog {
    fn published(&self) -> Arc<[ModelRecord]> {
        self.models.clone()
    }
}

/// One internally consistent access, policy and model generation.
pub struct ManagementRuntimeSnapshot {
    pub access: Arc<dyn AccessResolver>,
    pub models: Arc<dyn ModelCatalog>,
}

impl std::fmt::Debug for ManagementRuntimeSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagementRuntimeSnapshot")
            .finish_non_exhaustive()
    }
}

/// Process-local, atomically replaceable management projection. A request loads
/// exactly one snapshot before authentication and keeps it for its full Edge path.
#[derive(Clone)]
pub struct ManagementRuntimeBridge {
    current: Arc<ArcSwap<ManagementRuntimeSnapshot>>,
}

impl ManagementRuntimeBridge {
    #[must_use]
    pub fn new(access: Arc<dyn AccessResolver>, models: Arc<dyn ModelCatalog>) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(ManagementRuntimeSnapshot { access, models })),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<ManagementRuntimeSnapshot> {
        self.current.load_full()
    }

    /// Publish a fully compiled generation in one non-failing pointer swap.
    pub fn publish(&self, access: Arc<dyn AccessResolver>, models: Arc<dyn ModelCatalog>) {
        self.current
            .store(Arc::new(ManagementRuntimeSnapshot { access, models }));
    }
}

impl std::fmt::Debug for ManagementRuntimeBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagementRuntimeBridge")
            .finish_non_exhaustive()
    }
}

/// Credential-neutral dispatch input. Original identity headers have no representation here.
#[derive(Clone, Debug)]
pub struct DispatchRequest {
    pub request_id: RequestId,
    pub owner_user_id: UserId,
    pub platform_key_id: PlatformKeyId,
    pub group_id: GroupId,
    pub base_session_id: SessionId,
    pub agent_id: AgentId,
    pub client_class: ClientClass,
    pub traffic_class: TrafficClass,
    pub identity_conflict: bool,
    pub accepted_at: Duration,
    pub pre_upstream_deadline: Duration,
    /// Effective audit policy frozen at authentication time.
    pub content_audit: ContentAuditMode,
    /// Exact authenticated client body before policy adjustment. It is retained
    /// only for the optional encrypted Content Audit latch.
    pub original_body: Arc<[u8]>,
    pub generic: Arc<GenericAdjustedRequest>,
    pub anthropic_version: Option<Box<str>>,
    pub anthropic_beta: Option<Box<str>>,
}

/// R7 response prepared by the bounded response pipeline.
pub type UpstreamResponse = gateway_services::response::PreparedClientResponse;

/// Message scheduling/transport port. R3 tests inject a capturing implementation.
#[async_trait]
pub trait MessageDispatcher: Send + Sync {
    async fn dispatch(&self, request: DispatchRequest) -> Result<UpstreamResponse, DispatchError>;
}

/// Stable pre-commit dispatch error class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchError {
    Unavailable,
    /// Request-frozen full Content Audit could not durably latch before the
    /// first upstream byte. The client may retry after the advertised delay.
    AuditUnavailable {
        retry_after_seconds: u64,
    },
    Overloaded {
        retry_after_seconds: u64,
    },
    GroupRateLimited {
        retry_after_seconds: u64,
    },
    CredentialCooldown {
        retry_after_seconds: u64,
    },
    QueueFull {
        retry_after_seconds: u64,
    },
    /// A pre-upstream capacity wait exhausted the shared Group deadline. No
    /// Anthropic request byte has been written.
    PreUpstreamTimeout {
        retry_after_seconds: u64,
    },
    DeterministicUnavailable,
    DeadlineExceeded,
    Cancelled,
}

/// Fail-closed dispatcher used before R4–R7 components publish readiness.
#[derive(Debug, Default)]
pub struct UnavailableDispatcher;

#[async_trait]
impl MessageDispatcher for UnavailableDispatcher {
    async fn dispatch(&self, _request: DispatchRequest) -> Result<UpstreamResponse, DispatchError> {
        Err(DispatchError::Unavailable)
    }
}

/// Complete Edge dependencies.
#[derive(Clone)]
pub struct DataPlaneState {
    pub probe: crate::ProbeState,
    pub runtime: ManagementRuntimeBridge,
    pub dispatcher: Arc<dyn MessageDispatcher>,
    pub observability: gateway_services::observability::DataPlaneObservability,
    pub business_rates: crate::BusinessRateLimiter,
    pub concurrency: crate::KeyConcurrencyLimiter,
    pub trusted_proxies: crate::TrustedProxyConfig,
    pub platform_body_limit_bytes: usize,
}

impl std::fmt::Debug for DataPlaneState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DataPlaneState")
            .field("platform_body_limit_bytes", &self.platform_body_limit_bytes)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod runtime_tests {
    use std::{collections::BTreeSet, sync::Arc};

    use gateway_domain::ClientClass;
    use http::{HeaderMap, HeaderValue};
    use serde_json::json;

    use super::{
        BackgroundCatalog, BackgroundCatalogDocument, BackgroundCatalogEntry, BackgroundCatalogError, BackgroundSignal,
        DenyAllAccessResolver, ManagementRuntimeBridge, ModelRecord, ProbeAction, StaticModelCatalog,
    };

    #[test]
    fn runtime_publish_is_atomic_and_existing_request_snapshot_stays_frozen() {
        let bridge = ManagementRuntimeBridge::new(
            Arc::new(DenyAllAccessResolver),
            Arc::new(StaticModelCatalog::new(vec![model("old")])),
        );
        let frozen = bridge.snapshot();
        bridge.publish(
            Arc::new(DenyAllAccessResolver),
            Arc::new(StaticModelCatalog::new(vec![model("new")])),
        );
        let current = bridge.snapshot();
        assert!(!Arc::ptr_eq(&frozen, &current));
        assert_eq!(frozen.models.published()[0].id.as_ref(), "old");
        assert_eq!(current.models.published()[0].id.as_ref(), "new");
    }

    #[test]
    fn background_catalog_uses_strong_all_match_signals_and_owns_the_action() -> Result<(), BackgroundCatalogError> {
        let catalog = BackgroundCatalog::compile(BackgroundCatalogDocument {
            entries: vec![BackgroundCatalogEntry {
                id: "claude-code-heartbeat-v1".into(),
                action: ProbeAction::Reject,
                client_classes: BTreeSet::from([ClientClass::ClaudeCodeCli]),
                match_all: vec![
                    BackgroundSignal::HeaderContains {
                        name: "user-agent".into(),
                        value: "claude-code".into(),
                    },
                    BackgroundSignal::BodyEquals {
                        pointer: "/max_tokens".into(),
                        value: json!(1),
                    },
                ],
            }],
        })?;
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("Claude-Code/2.1.220"));
        let request = json!({"max_tokens":1,"messages":[]});
        assert_eq!(
            catalog.classify(&headers, &request, ClientClass::ClaudeCodeCli),
            Some("claude-code-heartbeat-v1")
        );
        assert_eq!(catalog.action("claude-code-heartbeat-v1"), ProbeAction::Reject);
        assert_eq!(
            catalog.classify(&headers, &request, ClientClass::NonClaudeCodeCli),
            None
        );
        assert_eq!(
            catalog.classify(&headers, &json!({"max_tokens":8}), ClientClass::ClaudeCodeCli),
            None
        );
        headers.append("user-agent", HeaderValue::from_static("claude-code/duplicate"));
        assert_eq!(catalog.classify(&headers, &request, ClientClass::ClaudeCodeCli), None);
        Ok(())
    }

    #[test]
    fn background_catalog_rejects_ambiguous_duplicate_matches() {
        let entry = BackgroundCatalogEntry {
            id: "one".into(),
            action: ProbeAction::Observe,
            client_classes: BTreeSet::new(),
            match_all: vec![BackgroundSignal::BodyPresent {
                pointer: "/metadata".into(),
            }],
        };
        let mut duplicate = entry.clone();
        duplicate.id = "two".into();
        duplicate.action = ProbeAction::Throttle;
        assert!(matches!(
            BackgroundCatalog::compile(BackgroundCatalogDocument {
                entries: vec![entry, duplicate]
            }),
            Err(BackgroundCatalogError::DuplicateMatch)
        ));
    }

    fn model(id: &str) -> ModelRecord {
        ModelRecord {
            id: id.into(),
            display_name: id.into(),
            created_at: "0".into(),
        }
    }
}
