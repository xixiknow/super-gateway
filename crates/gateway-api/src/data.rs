//! Data-plane ports and immutable access/catalog snapshots.
#![allow(missing_docs, clippy::doc_markdown)]

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use gateway_domain::{
    AgentId, ClientClass, ClientOs, GenericAdjustedRequest, GroupId, OsResolution, PlatformKeyId, RequestId,
    SecretBytes, SecretValue, SessionId, SystemClock, UserId,
};
use gateway_policy::RequestPolicy;
use gateway_services::security::lookup_digest;
use ipnet::IpNet;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// Endpoint permission attached to a Platform Key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointPermission {
    Messages,
    Models,
}

/// Northbound business endpoint carried through dispatch so transport can
/// select the matching upstream path and telemetry label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchEndpoint {
    Messages,
    CountTokens,
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

    /// Independent `/v1/messages/count_tokens` default.
    pub const DEFAULT_COUNT_TOKENS: Self = Self {
        requests_per_minute: 120,
        burst: 20,
    };
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
    /// Independent Count Tokens RPM bucket.
    pub count_tokens_rate: RateLimit,
    pub models_rate: RateLimit,
    /// Per-Key hard upper bound; defaults to five when created.
    pub concurrency_limit: u32,
    /// Empty means no source-IP restriction.
    pub ip_allowlist: Vec<IpNet>,
    pub accepted_client_classes: BTreeSet<ClientClass>,
    pub default_os_family: ClientOs,
    /// Frozen policy/catalog artifact set.
    pub policy: Arc<RequestPolicy>,
}

/// Secret lookup boundary. Implementations return only active, unexpired, enabled grants.
pub trait AccessResolver: Send + Sync {
    /// Resolve by plaintext at the shortest possible boundary.
    fn resolve(&self, secret: &SecretValue) -> Option<Arc<AccessGrant>>;
}

/// Result of the durable user/key spend-cap admission check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendDecision {
    Allowed,
    Limited,
    Unavailable,
}

/// Durable spend admission boundary evaluated before a message enters scheduling.
#[async_trait]
pub trait SpendAuthorizer: Send + Sync {
    async fn authorize(&self, owner_user_id: &UserId, platform_key_id: &PlatformKeyId) -> SpendDecision;
}

/// Development/test default when no durable spend caps are configured.
#[derive(Debug, Default)]
pub struct AllowAllSpendAuthorizer;

#[async_trait]
impl SpendAuthorizer for AllowAllSpendAuthorizer {
    async fn authorize(&self, _owner_user_id: &UserId, _platform_key_id: &PlatformKeyId) -> SpendDecision {
        SpendDecision::Allowed
    }
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
                found = Some(grant.clone());
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
                found = Some(grant.clone());
            }
        }
        found
    }
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
    pub endpoint: DispatchEndpoint,
    pub request_id: RequestId,
    pub owner_user_id: UserId,
    pub platform_key_id: PlatformKeyId,
    pub group_id: GroupId,
    pub base_session_id: SessionId,
    pub agent_id: AgentId,
    pub client_class: ClientClass,
    /// Client application hint used only for the controlled Claude Code x-app header.
    pub client_app: Option<Box<str>>,
    pub client_os: ClientOs,
    pub os_resolution: OsResolution,
    pub os_mismatch: bool,
    pub identity_conflict: bool,
    pub accepted_at: Duration,
    pub pre_upstream_deadline: Duration,
    /// Exact authenticated client body before policy adjustment, retained for
    /// the optional plaintext body capture.
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
    BundleUnavailable,
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
    pub client_os_sessions: ClientOsSessionCache,
    pub concurrency: crate::KeyConcurrencyLimiter,
    pub spend_authorizer: Arc<dyn SpendAuthorizer>,
    pub trusted_proxies: crate::TrustedProxyConfig,
    pub platform_body_limit_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct ClientOsSessionEntry {
    os: ClientOs,
    last_seen: Duration,
}

/// Bounded, process-local OS affinity keyed by a digest of the client base session.
#[derive(Clone)]
pub struct ClientOsSessionCache {
    clock: Arc<dyn gateway_domain::Clock>,
    entries: Arc<Mutex<HashMap<Box<str>, ClientOsSessionEntry>>>,
    ttl: Duration,
    capacity: usize,
}

impl std::fmt::Debug for ClientOsSessionCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientOsSessionCache")
            .field("ttl", &self.ttl)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl Default for ClientOsSessionCache {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock::new()), Duration::from_hours(24), 32_768)
    }
}

impl ClientOsSessionCache {
    #[must_use]
    pub fn new(clock: Arc<dyn gateway_domain::Clock>, ttl: Duration, capacity: usize) -> Self {
        Self {
            clock,
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            capacity: capacity.max(1),
        }
    }

    pub(crate) fn remember(&self, session_digest: &str, os: ClientOs) {
        let now = self.clock.now().monotonic;
        let mut entries = lock_os_sessions(&self.entries);
        prune_os_sessions(&mut entries, now, self.ttl);
        if entries.len() >= self.capacity
            && !entries.contains_key(session_digest)
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(session_digest.into(), ClientOsSessionEntry { os, last_seen: now });
    }

    pub(crate) fn resolve(&self, session_digest: &str) -> Option<ClientOs> {
        let now = self.clock.now().monotonic;
        let mut entries = lock_os_sessions(&self.entries);
        prune_os_sessions(&mut entries, now, self.ttl);
        let entry = entries.get_mut(session_digest)?;
        entry.last_seen = now;
        Some(entry.os)
    }
}

fn lock_os_sessions(
    entries: &Mutex<HashMap<Box<str>, ClientOsSessionEntry>>,
) -> MutexGuard<'_, HashMap<Box<str>, ClientOsSessionEntry>> {
    entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn prune_os_sessions(entries: &mut HashMap<Box<str>, ClientOsSessionEntry>, now: Duration, ttl: Duration) {
    let stale_before = now.saturating_sub(ttl);
    entries.retain(|_, entry| entry.last_seen >= stale_before);
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
    use std::sync::Arc;

    use super::{DenyAllAccessResolver, ManagementRuntimeBridge, ModelRecord, StaticModelCatalog};

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

    fn model(id: &str) -> ModelRecord {
        ModelRecord {
            id: id.into(),
            display_name: id.into(),
            created_at: "0".into(),
        }
    }
}
