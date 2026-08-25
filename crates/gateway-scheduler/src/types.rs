//! Scheduler value objects and externally observable decisions.
#![allow(missing_docs, clippy::doc_markdown, clippy::struct_excessive_bools)]

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use gateway_domain::{
    AgentId, ArchetypeVersionId, CredentialId, CredentialProfileId, DeviceIdentityId, Digest, EgressBindingId,
    GenericAdjustedRequest, GroupId, LeaseId, PlatformKeyId, Portability, RequestId, SessionId, SnapshotVersion,
    TicketId, TransportBundleId, UserId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::BucketConfig;

/// Owner generation fences every state-changing callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OwnerGeneration(u64);

impl OwnerGeneration {
    /// Construct a non-zero generation.
    ///
    /// # Errors
    ///
    /// Generation zero is reserved for absence of an owner.
    pub fn new(value: u64) -> Result<Self, SchedulerError> {
        if value == 0 {
            return Err(SchedulerError::InvalidGeneration);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorIdentity {
    pub group_id: GroupId,
    pub owner_partition: Box<str>,
    pub executor_id: Box<str>,
    pub generation: OwnerGeneration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeLifecycle {
    Loading,
    Serving,
    Draining,
    OwnerUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCapacityConfig {
    pub enabled: bool,
    pub max_active_sessions: u32,
    pub idle_ttl: Duration,
    pub new_session_wait: Duration,
}

impl Default for SessionCapacityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_active_sessions: u32::MAX,
            idle_ttl: Duration::from_mins(30),
            new_session_wait: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupConfig {
    /// Exact Group Config artifact version expected on newly admitted requests.
    pub snapshot_version: SnapshotVersion,
    /// `None` means no product-level Group concurrency cap.
    pub concurrency_limit: Option<u32>,
    /// `None` means Group RPM is unlimited.
    pub rate_limit: Option<BucketConfig>,
    /// `None` uses exactly twice the effective concurrency.
    pub queue_capacity: Option<usize>,
    pub pre_upstream_wait: Duration,
    pub preferred_capacity_wait: Duration,
    /// Grace between cancellation and forced Credential Lease release.
    pub cancel_grace: Duration,
    pub affinity_ttl: Duration,
    pub affinity_migration_successes: u32,
    pub quota_guard_basis_points: u16,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            snapshot_version: SnapshotVersion::new("v1"),
            concurrency_limit: None,
            rate_limit: None,
            queue_capacity: None,
            pre_upstream_wait: Duration::from_secs(30),
            preferred_capacity_wait: Duration::from_secs(2),
            cancel_grace: Duration::from_secs(2),
            affinity_ttl: Duration::from_hours(24),
            affinity_migration_successes: 3,
            quota_guard_basis_points: 9_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EligibilityClass {
    Eligible,
    TemporarilyBlocked,
    DeterministicallyIneligible,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialState {
    pub lifecycle_active: bool,
    pub auth_healthy: bool,
    pub profile_ready: bool,
    pub egress_ready: bool,
    pub transport_ready: bool,
    pub cooldown_until: Option<Duration>,
    pub quota_used_basis_points: Option<u16>,
    pub quota_reset_at: Option<Duration>,
    pub half_open_inflight: bool,
}

/// Durable Credential cooldown projected into the owning scheduler actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialCooldownUpdate {
    pub credential_id: CredentialId,
    /// `Some` fences new grants until the deadline; `None` clears a proven-recovered cooldown.
    pub cooldown_until: Option<Duration>,
}

/// Durable authentication generation projected into the owning scheduler actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialAuthUpdate {
    pub credential_id: CredentialId,
    pub token_version: u64,
    pub auth_healthy: bool,
}

/// Durable subscription quota projection applied to the owning actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialQuotaUpdate {
    pub credential_id: CredentialId,
    /// UUIDv7 observation order encoded as an integer for stale-write fencing.
    pub observation_version: u128,
    pub used_basis_points: u16,
    pub reset_at: Duration,
}

/// Result of applying an administrator-owned, process-local scheduling fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialFenceResult {
    Applied { inflight: u32 },
    Missing,
    StaleIgnored,
}

/// Result of removing a fenced Credential from one Group owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialRemoveResult {
    Removed,
    Busy { inflight: u32 },
    NotFenced,
    Missing,
    StaleIgnored,
}

impl Default for CredentialState {
    fn default() -> Self {
        Self {
            lifecycle_active: true,
            auth_healthy: true,
            profile_ready: true,
            egress_ready: true,
            transport_ready: true,
            cooldown_until: None,
            quota_used_basis_points: None,
            quota_reset_at: None,
            half_open_inflight: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialConfig {
    pub id: CredentialId,
    /// Monotonic Credential aggregate revision covering auth/profile/device/
    /// egress continuity and lifecycle projection.
    pub credential_projection_revision: u64,
    /// Monotonic active-pointer revision used to reject stale scheduling
    /// projections without replacing auth/profile runtime state.
    pub scheduling_projection_revision: u64,
    pub concurrency_limit: u32,
    pub rate_limit: BucketConfig,
    pub priority: u16,
    pub weight: u32,
    /// Empty means all models.
    pub model_scope: BTreeSet<Box<str>>,
    pub attribution_optional: bool,
    pub session_capacity: SessionCapacityConfig,
    pub token_version: u64,
    pub profile_id: CredentialProfileId,
    pub profile_epoch: u64,
    pub device_identity_id: DeviceIdentityId,
    pub device_epoch: u64,
    pub archetype_version_id: ArchetypeVersionId,
    pub bundle_id: TransportBundleId,
    pub bundle_version: u64,
    pub bundle_hash: Digest,
    pub egress_binding_id: EgressBindingId,
    pub egress_epoch: u64,
    pub bundle_epoch: u64,
    pub quota_observation_version: Option<u128>,
    pub state: CredentialState,
}

#[derive(Clone, Debug)]
pub struct ScheduleEntry {
    pub request_id: RequestId,
    pub owner_user_id: UserId,
    pub platform_key_id: PlatformKeyId,
    pub group_id: GroupId,
    pub base_session_id: SessionId,
    pub agent_id: AgentId,
    pub generic: Arc<GenericAdjustedRequest>,
    pub accepted_at: Duration,
    pub pre_upstream_deadline: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AffinityKey {
    pub platform_key_id: PlatformKeyId,
    pub base_session_id: SessionId,
    pub agent_id: AgentId,
    pub model_id: Box<str>,
}

impl From<&ScheduleEntry> for AffinityKey {
    fn from(entry: &ScheduleEntry) -> Self {
        Self {
            platform_key_id: entry.platform_key_id.clone(),
            base_session_id: entry.base_session_id.clone(),
            agent_id: entry.agent_id.clone(),
            model_id: entry.generic.model_id.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketState {
    Queued,
    Granted,
    Cancelled,
    TimedOut,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueTicket {
    pub id: TicketId,
    pub request_id: RequestId,
    pub deadline: Duration,
    pub state: TicketState,
    pub generation: OwnerGeneration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionKind {
    GroupUnavailable,
    QueueFull,
    GroupRateDeadline,
    CooldownBeyondDeadline,
    TimedOut,
    Cancelled,
    /// An identifier was already admitted in this generation.
    DuplicateRequest,
    /// Optional Session capacity wait reached its bounded deadline.
    SessionCapacityDeadline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub kind: RejectionKind,
    pub retry_after: Option<Duration>,
}

#[derive(Clone, Debug)]
pub enum AdmissionDecision {
    Granted(CredentialLease),
    Queued(QueueTicket),
    Rejected(Rejection),
    StaleIgnored,
}

#[derive(Clone, Debug)]
pub struct QueueResolution {
    pub request_id: RequestId,
    pub decision: AdmissionDecision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialLease {
    pub id: LeaseId,
    pub request_id: RequestId,
    pub credential_id: CredentialId,
    pub owner_generation: OwnerGeneration,
    pub token_version: u64,
    pub profile_id: CredentialProfileId,
    pub profile_epoch: u64,
    pub device_identity_id: DeviceIdentityId,
    pub device_epoch: u64,
    pub archetype_version_id: ArchetypeVersionId,
    pub bundle_id: TransportBundleId,
    pub bundle_version: u64,
    pub bundle_hash: Digest,
    pub egress_binding_id: EgressBindingId,
    pub egress_epoch: u64,
    pub bundle_epoch: u64,
    pub half_open: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryCredentialTarget {
    Same(CredentialId),
    Alternate { exclude: CredentialId },
}

#[derive(Clone, Debug)]
pub struct RetryLeaseRequest {
    pub current_lease_id: LeaseId,
    pub entry: ScheduleEntry,
    pub target: RetryCredentialTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryLeaseDecision {
    Granted(Box<CredentialLease>),
    NoCandidate,
    StaleIgnored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseRelease {
    Released,
    StaleIgnored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    GroupPermit,
    QueueTicket,
    SessionClaim,
    CredentialLease,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceAction {
    Acquire,
    Release,
    ForcedRelease,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceEvent {
    pub sequence: u64,
    pub request_id: RequestId,
    pub resource_kind: ResourceKind,
    pub resource_id: Box<str>,
    pub action: ResourceAction,
    pub portability: Portability,
    pub generation: OwnerGeneration,
    pub observed_at: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerSnapshot {
    pub generation: OwnerGeneration,
    pub lifecycle: RuntimeLifecycle,
    pub group_config_version: SnapshotVersion,
    pub configured_concurrency: Option<u32>,
    pub effective_concurrency: usize,
    pub total_credential_capacity: u32,
    pub queue_capacity: usize,
    pub active_leases: usize,
    pub active_group_permits: usize,
    pub queued_tickets: usize,
    pub credential_inflight: Vec<(CredentialId, u32)>,
    pub fenced_credentials: Vec<CredentialId>,
    pub session_claims: usize,
    pub resource_balance: isize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchedulerError {
    #[error("owner generation must be non-zero")]
    InvalidGeneration,
    #[error("resource released more than once or is unknown")]
    DuplicateRelease,
    #[error("request, ticket, or credential identifier already exists")]
    DuplicateIdentifier,
    #[error("entry belongs to another group")]
    WrongGroup,
    #[error("invalid scheduler configuration")]
    InvalidConfiguration,
}
