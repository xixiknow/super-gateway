//! Deterministic single-owner Group scheduler state machine.
#![allow(clippy::missing_errors_doc)]

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use gateway_domain::{CredentialId, LeaseId, PlatformKeyId, Portability, RequestId, SessionId, TicketId};
use uuid::Uuid;

use crate::fair_queue::FairQueue;
use crate::{
    AdmissionDecision, AffinityKey, CredentialAuthUpdate, CredentialConfig, CredentialCooldownUpdate,
    CredentialFenceResult, CredentialLease, CredentialQuotaUpdate, CredentialRemoveResult, EligibilityClass,
    ExecutorIdentity, GroupConfig, LeaseRelease, OwnerGeneration, QueueResolution, QueueTicket, Rejection,
    RejectionKind, ResourceAction, ResourceEvent, ResourceKind, RetryCredentialTarget, RetryLeaseDecision,
    RetryLeaseRequest, RuntimeLifecycle, ScheduleEntry, SchedulerError, SchedulerSnapshot, TicketState, TokenBucket,
};

#[derive(Debug)]
struct CredentialRuntime {
    config: CredentialConfig,
    bucket: TokenBucket,
    inflight: u32,
    half_open_consumed: bool,
    quota_observation_version: Option<u128>,
    admin_fenced: bool,
}

#[derive(Clone, Debug)]
struct AffinityEntry {
    credential_id: CredentialId,
    expires_at: Duration,
    migration_candidate: Option<CredentialId>,
    migration_successes: u32,
}

#[derive(Clone, Debug)]
struct SessionClaim {
    active_requests: u32,
    idle_since: Option<Duration>,
    last_request_id: RequestId,
    resource_id: Box<str>,
}

type SessionClaimKey = (CredentialId, PlatformKeyId, SessionId);

#[derive(Clone, Debug)]
struct LeaseRecord {
    lease: CredentialLease,
    session_claim_key: Option<SessionClaimKey>,
}

#[derive(Clone, Debug)]
struct WaitingRecord {
    ticket: QueueTicket,
    session_slot_deadline: Option<Duration>,
}

#[derive(Clone, Debug)]
enum PoolEvaluation {
    Candidate(CredentialId),
    Wait,
    SessionCapacity(Duration),
    Cooldown(Duration),
    DeterministicUnavailable,
}

/// Single-threaded scheduler. The actor wrapper serializes all production calls.
#[derive(Debug)]
pub struct SchedulerEngine {
    identity: ExecutorIdentity,
    lifecycle: RuntimeLifecycle,
    config: GroupConfig,
    group_bucket: Option<TokenBucket>,
    credentials: BTreeMap<CredentialId, CredentialRuntime>,
    queue: FairQueue,
    waiting: BTreeMap<RequestId, WaitingRecord>,
    leases: BTreeMap<LeaseId, LeaseRecord>,
    request_leases: BTreeMap<RequestId, LeaseId>,
    pending_cancels: BTreeMap<LeaseId, Duration>,
    group_permits: BTreeSet<RequestId>,
    seen_requests: BTreeSet<RequestId>,
    request_portability: BTreeMap<RequestId, Portability>,
    group_rate_admitted: BTreeSet<RequestId>,
    affinities: BTreeMap<AffinityKey, AffinityEntry>,
    session_claims: BTreeMap<SessionClaimKey, SessionClaim>,
    events: Vec<ResourceEvent>,
    event_sequence: u64,
    resource_balance: isize,
}

impl SchedulerEngine {
    /// Build a Serving Group runtime from a frozen config and Credential projection.
    ///
    /// # Errors
    ///
    /// Rejects duplicate Credential IDs, zero limits, invalid queue bounds, or a quota guard
    /// outside 1..=10000 basis points. An empty Group is a valid runtime projection so that a
    /// drained Credential can be attached without recreating the owner actor.
    pub fn new(
        identity: ExecutorIdentity,
        config: GroupConfig,
        credentials: impl IntoIterator<Item = CredentialConfig>,
        now: Duration,
    ) -> Result<Self, SchedulerError> {
        let mut runtimes = BTreeMap::new();
        for credential in credentials {
            if credential.concurrency_limit == 0
                || credential.rate_limit.requests_per_minute == 0
                || credential.rate_limit.burst == 0
                || credential.weight == 0
            {
                return Err(SchedulerError::InvalidConfiguration);
            }
            let id = credential.id.clone();
            let bucket = TokenBucket::full(credential.rate_limit, now);
            if runtimes
                .insert(
                    id,
                    CredentialRuntime {
                        quota_observation_version: credential.quota_observation_version,
                        config: credential,
                        bucket,
                        inflight: 0,
                        half_open_consumed: false,
                        admin_fenced: false,
                    },
                )
                .is_some()
            {
                return Err(SchedulerError::DuplicateIdentifier);
            }
        }
        if config.quota_guard_basis_points == 0
            || config.quota_guard_basis_points > 10_000
            || config.affinity_migration_successes == 0
            || config.cancel_grace.is_zero()
        {
            return Err(SchedulerError::InvalidConfiguration);
        }
        let healthy_capacity = capacity_sum(&runtimes);
        let effective = config
            .concurrency_limit
            .map_or(healthy_capacity, |limit| limit.min(healthy_capacity));
        let maximum_queue = usize::try_from(effective).unwrap_or(usize::MAX).saturating_mul(2);
        if healthy_capacity > 0 && config.queue_capacity.is_some_and(|capacity| capacity > maximum_queue) {
            return Err(SchedulerError::InvalidConfiguration);
        }
        let group_bucket = config.rate_limit.map(|rate| TokenBucket::full(rate, now));
        Ok(Self {
            identity,
            lifecycle: RuntimeLifecycle::Serving,
            config,
            group_bucket,
            credentials: runtimes,
            queue: FairQueue::default(),
            waiting: BTreeMap::new(),
            leases: BTreeMap::new(),
            request_leases: BTreeMap::new(),
            pending_cancels: BTreeMap::new(),
            group_permits: BTreeSet::new(),
            seen_requests: BTreeSet::new(),
            request_portability: BTreeMap::new(),
            group_rate_admitted: BTreeSet::new(),
            affinities: BTreeMap::new(),
            session_claims: BTreeMap::new(),
            events: Vec::new(),
            event_sequence: 0,
            resource_balance: 0,
        })
    }

    /// Admit or enqueue a request using the caller's absolute monotonic deadline.
    pub fn admit(
        &mut self,
        generation: OwnerGeneration,
        entry: ScheduleEntry,
        now: Duration,
    ) -> Result<AdmissionDecision, SchedulerError> {
        if generation != self.identity.generation {
            return Ok(AdmissionDecision::StaleIgnored);
        }
        if entry.group_id != self.identity.group_id {
            return Err(SchedulerError::WrongGroup);
        }
        if entry.generic.snapshot_set.group_config != self.config.snapshot_version {
            return Ok(rejected(RejectionKind::GroupUnavailable, Some(Duration::from_secs(1))));
        }
        if self.seen_requests.contains(&entry.request_id) {
            return Ok(AdmissionDecision::Rejected(Rejection {
                kind: RejectionKind::DuplicateRequest,
                retry_after: None,
            }));
        }
        if self.lifecycle != RuntimeLifecycle::Serving {
            return Ok(rejected(RejectionKind::GroupUnavailable, None));
        }
        if now >= entry.pre_upstream_deadline {
            return Ok(rejected(RejectionKind::TimedOut, Some(Duration::from_secs(5))));
        }
        self.seen_requests.insert(entry.request_id.clone());
        self.request_portability
            .insert(entry.request_id.clone(), entry.generic.portability.clone());
        self.prune(now);

        if let Some(bucket) = &mut self.group_bucket {
            if !bucket.try_consume(now) {
                let retry = bucket.retry_after(now);
                if now.saturating_add(retry) >= entry.pre_upstream_deadline {
                    return Ok(rejected(RejectionKind::GroupRateDeadline, Some(Duration::from_secs(5))));
                }
                return self.enqueue(entry, now, None);
            }
            self.group_rate_admitted.insert(entry.request_id.clone());
        }

        let evaluation = self.evaluate_pool(&entry, now);
        if self.group_permits.len() < self.effective_concurrency() && self.queue.len() == 0 {
            match &evaluation {
                PoolEvaluation::Candidate(credential_id) => {
                    return self
                        .grant(entry, credential_id, now, true)
                        .map(AdmissionDecision::Granted);
                }
                PoolEvaluation::Cooldown(retry) if now.saturating_add(*retry) >= entry.pre_upstream_deadline => {
                    self.group_rate_admitted.remove(&entry.request_id);
                    return Ok(rejected(RejectionKind::CooldownBeyondDeadline, Some(*retry)));
                }
                PoolEvaluation::DeterministicUnavailable => {
                    self.group_rate_admitted.remove(&entry.request_id);
                    return Ok(rejected(RejectionKind::GroupUnavailable, None));
                }
                PoolEvaluation::Wait | PoolEvaluation::Cooldown(_) | PoolEvaluation::SessionCapacity(_) => {}
            }
        } else if matches!(&evaluation, PoolEvaluation::DeterministicUnavailable) {
            self.group_rate_admitted.remove(&entry.request_id);
            return Ok(rejected(RejectionKind::GroupUnavailable, None));
        }
        let slot_deadline = match &evaluation {
            PoolEvaluation::SessionCapacity(wait) => Some(now.saturating_add(*wait)),
            _ => None,
        };
        self.enqueue(entry, now, slot_deadline)
    }

    /// Atomically replace the Group scheduling generation. Queued work frozen
    /// under another Group Config version is rejected so the caller can retry
    /// through a consistent policy + scheduler snapshot.
    pub fn reconfigure(
        &mut self,
        generation: OwnerGeneration,
        config: GroupConfig,
        now: Duration,
    ) -> Result<Vec<QueueResolution>, SchedulerError> {
        if generation != self.identity.generation {
            return Ok(Vec::new());
        }
        if config.quota_guard_basis_points == 0
            || config.quota_guard_basis_points > 10_000
            || config.affinity_migration_successes == 0
            || config.cancel_grace.is_zero()
        {
            return Err(SchedulerError::InvalidConfiguration);
        }
        let capacity = capacity_sum(&self.credentials);
        let effective = config.concurrency_limit.map_or(capacity, |limit| limit.min(capacity));
        let maximum_queue = usize::try_from(effective).unwrap_or(usize::MAX).saturating_mul(2);
        if capacity != 0
            && config
                .queue_capacity
                .is_some_and(|configured| configured > maximum_queue)
        {
            return Err(SchedulerError::InvalidConfiguration);
        }
        let queued = self.queue.drain();
        let mut resolutions = Vec::new();
        for entry in queued {
            if entry.generic.snapshot_set.group_config == config.snapshot_version {
                self.queue.push(entry);
                continue;
            }
            let request_id = entry.request_id;
            if let Some(waiting) = self.waiting.remove(&request_id) {
                self.record_event(
                    request_id.clone(),
                    ResourceKind::QueueTicket,
                    waiting.ticket.id.as_str().into(),
                    ResourceAction::ForcedRelease,
                    now,
                );
            }
            self.group_rate_admitted.remove(&request_id);
            resolutions.push(QueueResolution {
                request_id,
                decision: rejected(RejectionKind::GroupUnavailable, Some(Duration::from_secs(1))),
            });
        }
        self.group_bucket = config.rate_limit.map(|rate| TokenBucket::full(rate, now));
        self.config = config;
        self.prune(now);
        Ok(resolutions)
    }

    /// Upsert one durable Credential scheduling projection. Existing leases,
    /// affinity and session claims remain intact; a concurrency downscale only
    /// prevents future grants until in-flight work falls below the new limit.
    pub fn reconfigure_credential(
        &mut self,
        generation: OwnerGeneration,
        config: CredentialConfig,
        now: Duration,
    ) -> Result<bool, SchedulerError> {
        if generation != self.identity.generation {
            return Ok(false);
        }
        if config.concurrency_limit == 0
            || config.rate_limit.requests_per_minute == 0
            || config.rate_limit.burst == 0
            || config.weight == 0
            || config.scheduling_projection_revision == 0
        {
            return Err(SchedulerError::InvalidConfiguration);
        }
        if let Some(runtime) = self.credentials.get_mut(&config.id) {
            if config.credential_projection_revision < runtime.config.credential_projection_revision
                || (config.credential_projection_revision == runtime.config.credential_projection_revision
                    && config.scheduling_projection_revision <= runtime.config.scheduling_projection_revision)
            {
                return Ok(false);
            }
            runtime.bucket.reconfigure(config.rate_limit, now);
            let device_changed = config.device_epoch != runtime.config.device_epoch;
            if config.credential_projection_revision > runtime.config.credential_projection_revision {
                runtime.quota_observation_version = config.quota_observation_version;
                runtime.config = config;
                if device_changed {
                    let credential_id = runtime.config.id.clone();
                    self.affinities
                        .retain(|_, affinity| affinity.credential_id != credential_id);
                    self.session_claims
                        .retain(|(candidate, _, _), claim| candidate != &credential_id || claim.active_requests != 0);
                }
            } else {
                runtime.config.scheduling_projection_revision = config.scheduling_projection_revision;
                runtime.config.concurrency_limit = config.concurrency_limit;
                runtime.config.rate_limit = config.rate_limit;
                runtime.config.priority = config.priority;
                runtime.config.weight = config.weight;
                runtime.config.model_scope = config.model_scope;
                runtime.config.attribution_optional = config.attribution_optional;
                runtime.config.session_capacity = config.session_capacity;
            }
            return Ok(true);
        }
        let id = config.id.clone();
        let bucket = TokenBucket::full(config.rate_limit, now);
        self.credentials.insert(
            id,
            CredentialRuntime {
                quota_observation_version: config.quota_observation_version,
                config,
                bucket,
                inflight: 0,
                half_open_consumed: false,
                admin_fenced: false,
            },
        );
        Ok(true)
    }

    /// Release one Lease exactly once. Old-owner callbacks have no business-state effect.
    pub fn release_lease(
        &mut self,
        generation: OwnerGeneration,
        lease_id: &LeaseId,
        now: Duration,
    ) -> Result<LeaseRelease, SchedulerError> {
        if generation != self.identity.generation {
            return Ok(LeaseRelease::StaleIgnored);
        }
        let record = self.leases.remove(lease_id).ok_or(SchedulerError::DuplicateRelease)?;
        self.request_leases.remove(&record.lease.request_id);
        self.pending_cancels.remove(lease_id);
        if let Some(runtime) = self.credentials.get_mut(&record.lease.credential_id) {
            runtime.inflight = runtime
                .inflight
                .checked_sub(1)
                .ok_or(SchedulerError::DuplicateRelease)?;
            if record.lease.half_open {
                runtime.config.state.half_open_inflight = false;
            }
        }
        if let Some(claim_key) = record.session_claim_key
            && let Some(claim) = self.session_claims.get_mut(&claim_key)
        {
            claim.active_requests = claim
                .active_requests
                .checked_sub(1)
                .ok_or(SchedulerError::DuplicateRelease)?;
            if claim.active_requests == 0 {
                claim.idle_since = Some(now);
            }
        }
        self.record_event(
            record.lease.request_id,
            ResourceKind::CredentialLease,
            lease_id.as_str().into(),
            ResourceAction::Release,
            now,
        );
        Ok(LeaseRelease::Released)
    }

    /// Replace a request's exact Lease in one actor mutation while retaining
    /// its Group permit, fairness position, and one-time Group RPM charge.
    pub fn replace_lease(
        &mut self,
        generation: OwnerGeneration,
        request: RetryLeaseRequest,
        now: Duration,
    ) -> Result<RetryLeaseDecision, SchedulerError> {
        if generation != self.identity.generation {
            return Ok(RetryLeaseDecision::StaleIgnored);
        }
        if request.entry.group_id != self.identity.group_id {
            return Err(SchedulerError::WrongGroup);
        }
        let current = self
            .leases
            .get(&request.current_lease_id)
            .ok_or(SchedulerError::DuplicateRelease)?;
        if current.lease.request_id != request.entry.request_id
            || self.request_leases.get(&request.entry.request_id) != Some(&request.current_lease_id)
            || !self.group_permits.contains(&request.entry.request_id)
        {
            return Err(SchedulerError::DuplicateIdentifier);
        }
        let current_credential = current.lease.credential_id.clone();
        let Some(target) = self.retry_candidate(&request.entry, &request.target, &current_credential, now) else {
            return Ok(RetryLeaseDecision::NoCandidate);
        };
        self.release_lease(generation, &request.current_lease_id, now)?;
        let lease = self.grant(request.entry, &target, now, false)?;
        Ok(RetryLeaseDecision::Granted(Box::new(lease)))
    }

    /// Cancel a queued or leased request. A Lease cancellation is an explicit release in actor order.
    pub fn cancel(
        &mut self,
        generation: OwnerGeneration,
        request_id: &RequestId,
        now: Duration,
    ) -> Result<AdmissionDecision, SchedulerError> {
        if generation != self.identity.generation {
            return Ok(AdmissionDecision::StaleIgnored);
        }
        if let Some(waiting) = self.waiting.remove(request_id) {
            let _ = self.queue.remove(request_id);
            self.group_rate_admitted.remove(request_id);
            self.record_event(
                request_id.clone(),
                ResourceKind::QueueTicket,
                waiting.ticket.id.as_str().into(),
                ResourceAction::Release,
                now,
            );
            return Ok(rejected(RejectionKind::Cancelled, None));
        }
        if let Some(lease_id) = self.request_leases.get(request_id).cloned() {
            if self.group_permits.contains(request_id) {
                self.release_group_permit(request_id, ResourceAction::Release, now)?;
            }
            self.pending_cancels
                .entry(lease_id)
                .or_insert_with(|| now.saturating_add(self.config.cancel_grace));
            return Ok(rejected(RejectionKind::Cancelled, None));
        }
        if self.group_permits.contains(request_id) {
            self.release_group_permit(request_id, ResourceAction::Release, now)?;
        }
        Ok(rejected(RejectionKind::Cancelled, None))
    }

    /// Confirm that transport no longer uses a cancelled Lease, then release its capacity and request permit.
    pub fn confirm_transport_cancel(
        &mut self,
        generation: OwnerGeneration,
        request_id: &RequestId,
        now: Duration,
    ) -> Result<LeaseRelease, SchedulerError> {
        if generation != self.identity.generation {
            return Ok(LeaseRelease::StaleIgnored);
        }
        let lease_id = self
            .request_leases
            .get(request_id)
            .cloned()
            .ok_or(SchedulerError::DuplicateRelease)?;
        self.pending_cancels.remove(&lease_id);
        self.release_lease(generation, &lease_id, now)
    }

    /// Release the Group request permit after client delivery or terminal cleanup, then pump old queue work.
    pub fn complete_request(
        &mut self,
        generation: OwnerGeneration,
        request_id: &RequestId,
        now: Duration,
    ) -> Result<Vec<QueueResolution>, SchedulerError> {
        if generation != self.identity.generation {
            return Ok(Vec::new());
        }
        if self.request_leases.contains_key(request_id) {
            return Err(SchedulerError::InvalidConfiguration);
        }
        self.release_group_permit(request_id, ResourceAction::Release, now)?;
        Ok(self.pump(generation, now))
    }

    /// Grant every currently runnable queue head until capacity is exhausted.
    pub fn pump(&mut self, generation: OwnerGeneration, now: Duration) -> Vec<QueueResolution> {
        if generation != self.identity.generation || self.lifecycle != RuntimeLifecycle::Serving {
            return Vec::new();
        }
        self.expire_cancel_grace(now);
        self.prune(now);
        let mut resolutions = self.expire_waiters(now);
        loop {
            if self.group_permits.len() >= self.effective_concurrency() {
                break;
            }
            let group_bucket = &mut self.group_bucket;
            let group_rate_admitted = &mut self.group_rate_admitted;
            let credentials = &mut self.credentials;
            let affinities = &self.affinities;
            let session_claims = &self.session_claims;
            let config = &self.config;
            let entry = self.queue.pop_runnable(|candidate| {
                if candidate.pre_upstream_deadline <= now {
                    return true;
                }
                let rate_ready = if group_rate_admitted.contains(&candidate.request_id) {
                    true
                } else if let Some(bucket) = group_bucket.as_mut() {
                    if bucket.try_consume(now) {
                        group_rate_admitted.insert(candidate.request_id.clone());
                        true
                    } else {
                        false
                    }
                } else {
                    true
                };
                rate_ready
                    && matches!(
                        evaluate_pool_fields(credentials, affinities, session_claims, config, candidate, now),
                        PoolEvaluation::Candidate(_)
                    )
            });
            let Some(entry) = entry else {
                break;
            };
            let Some(waiting) = self.waiting.remove(&entry.request_id) else {
                continue;
            };
            self.record_event(
                entry.request_id.clone(),
                ResourceKind::QueueTicket,
                waiting.ticket.id.as_str().into(),
                ResourceAction::Release,
                now,
            );
            if now >= entry.pre_upstream_deadline {
                self.group_rate_admitted.remove(&entry.request_id);
                resolutions.push(QueueResolution {
                    request_id: entry.request_id,
                    decision: rejected(RejectionKind::TimedOut, Some(Duration::from_secs(5))),
                });
                continue;
            }
            let PoolEvaluation::Candidate(credential_id) = self.evaluate_pool(&entry, now) else {
                // State changed only through this actor; a candidate observed in the same turn remains valid.
                self.queue.push(entry);
                self.waiting.insert(waiting.ticket.request_id.clone(), waiting);
                break;
            };
            let request_id = entry.request_id.clone();
            let decision = self.grant(entry, &credential_id, now, true).map_or_else(
                |_| rejected(RejectionKind::GroupUnavailable, None),
                AdmissionDecision::Granted,
            );
            resolutions.push(QueueResolution { request_id, decision });
        }
        resolutions
    }

    /// Stop new grants, cancel all pre-Lease work, and let existing Leases drain.
    pub fn disable(&mut self, generation: OwnerGeneration, now: Duration) -> Vec<QueueResolution> {
        if generation != self.identity.generation {
            return Vec::new();
        }
        self.lifecycle = RuntimeLifecycle::Draining;
        let entries = self.queue.drain();
        let mut resolutions = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(waiting) = self.waiting.remove(&entry.request_id) {
                self.record_event(
                    entry.request_id.clone(),
                    ResourceKind::QueueTicket,
                    waiting.ticket.id.as_str().into(),
                    ResourceAction::ForcedRelease,
                    now,
                );
            }
            self.group_rate_admitted.remove(&entry.request_id);
            resolutions.push(QueueResolution {
                request_id: entry.request_id,
                decision: rejected(RejectionKind::GroupUnavailable, None),
            });
        }
        resolutions
    }

    /// Observe a successful spillover. Migration requires the configured stable-success threshold.
    pub fn record_success(&mut self, affinity_key: &AffinityKey, credential_id: &CredentialId, now: Duration) {
        let Some(entry) = self.affinities.get_mut(affinity_key) else {
            self.affinities.insert(
                affinity_key.clone(),
                AffinityEntry {
                    credential_id: credential_id.clone(),
                    expires_at: now.saturating_add(self.config.affinity_ttl),
                    migration_candidate: None,
                    migration_successes: 0,
                },
            );
            return;
        };
        if &entry.credential_id == credential_id {
            entry.migration_candidate = None;
            entry.migration_successes = 0;
            entry.expires_at = now.saturating_add(self.config.affinity_ttl);
            return;
        }
        if entry.migration_candidate.as_ref() == Some(credential_id) {
            entry.migration_successes = entry.migration_successes.saturating_add(1);
        } else {
            entry.migration_candidate = Some(credential_id.clone());
            entry.migration_successes = 1;
        }
        if entry.migration_successes >= self.config.affinity_migration_successes {
            entry.credential_id = credential_id.clone();
            entry.migration_candidate = None;
            entry.migration_successes = 0;
            entry.expires_at = now.saturating_add(self.config.affinity_ttl);
        }
    }

    /// Close the one-shot quota half-open probe and update the Credential projection.
    pub fn record_half_open_result(
        &mut self,
        generation: OwnerGeneration,
        credential_id: &CredentialId,
        succeeded: bool,
        now: Duration,
    ) {
        if generation != self.identity.generation {
            return;
        }
        let Some(runtime) = self.credentials.get_mut(credential_id) else {
            return;
        };
        runtime.config.state.half_open_inflight = false;
        if succeeded {
            runtime.config.state.quota_used_basis_points = None;
            runtime.config.state.quota_reset_at = None;
            runtime.half_open_consumed = false;
        } else {
            let retry = now.saturating_add(Duration::from_mins(1));
            runtime.config.state.cooldown_until = Some(retry);
            runtime.config.state.quota_reset_at = Some(retry);
            runtime.half_open_consumed = false;
        }
    }

    /// Apply a generation-fenced durable cooldown observation.
    pub fn observe_credential_cooldown(
        &mut self,
        generation: OwnerGeneration,
        update: &CredentialCooldownUpdate,
    ) -> bool {
        if generation != self.identity.generation {
            return false;
        }
        let Some(runtime) = self.credentials.get_mut(&update.credential_id) else {
            return false;
        };
        runtime.config.state.cooldown_until = update.cooldown_until;
        true
    }

    /// Apply a generation-fenced durable authentication/token observation.
    pub fn observe_credential_auth(&mut self, generation: OwnerGeneration, update: &CredentialAuthUpdate) -> bool {
        if generation != self.identity.generation || update.token_version == 0 {
            return false;
        }
        let Some(runtime) = self.credentials.get_mut(&update.credential_id) else {
            return false;
        };
        if update.token_version < runtime.config.token_version {
            return false;
        }
        runtime.config.token_version = update.token_version;
        runtime.config.state.auth_healthy = update.auth_healthy;
        true
    }

    /// Apply a generation- and observation-fenced durable quota projection.
    pub fn observe_credential_quota(&mut self, generation: OwnerGeneration, update: &CredentialQuotaUpdate) -> bool {
        if generation != self.identity.generation || update.used_basis_points > 10_000 {
            return false;
        }
        let Some(runtime) = self.credentials.get_mut(&update.credential_id) else {
            return false;
        };
        if runtime
            .quota_observation_version
            .is_some_and(|current| update.observation_version <= current)
        {
            return false;
        }
        runtime.quota_observation_version = Some(update.observation_version);
        runtime.config.quota_observation_version = Some(update.observation_version);
        runtime.config.state.quota_used_basis_points = Some(update.used_basis_points);
        runtime.config.state.quota_reset_at = Some(update.reset_at);
        runtime.config.state.half_open_inflight = false;
        runtime.half_open_consumed = false;
        true
    }

    /// Normalized state used by invariants and model tests.
    #[must_use]
    pub fn snapshot(&self) -> SchedulerSnapshot {
        SchedulerSnapshot {
            generation: self.identity.generation,
            lifecycle: self.lifecycle,
            group_config_version: self.config.snapshot_version.clone(),
            configured_concurrency: self.config.concurrency_limit,
            effective_concurrency: self.effective_concurrency(),
            total_credential_capacity: capacity_sum(&self.credentials),
            queue_capacity: self.queue_capacity(),
            active_leases: self.leases.len(),
            active_group_permits: self.group_permits.len(),
            queued_tickets: self.queue.len(),
            credential_inflight: self
                .credentials
                .iter()
                .map(|(id, runtime)| (id.clone(), runtime.inflight))
                .collect(),
            fenced_credentials: self
                .credentials
                .iter()
                .filter(|(_, runtime)| runtime.admin_fenced)
                .map(|(id, _)| id.clone())
                .collect(),
            session_claims: self.session_claims.len(),
            resource_balance: self.resource_balance,
        }
    }

    /// Fence or unfence one Credential without changing existing Leases.
    pub fn set_credential_fence(
        &mut self,
        generation: OwnerGeneration,
        credential_id: &CredentialId,
        fenced: bool,
    ) -> CredentialFenceResult {
        if generation != self.identity.generation {
            return CredentialFenceResult::StaleIgnored;
        }
        let Some(runtime) = self.credentials.get_mut(credential_id) else {
            return CredentialFenceResult::Missing;
        };
        runtime.admin_fenced = fenced;
        CredentialFenceResult::Applied {
            inflight: runtime.inflight,
        }
    }

    /// Remove a fenced Credential only after every exact Lease has drained.
    pub fn remove_fenced_credential(
        &mut self,
        generation: OwnerGeneration,
        credential_id: &CredentialId,
    ) -> CredentialRemoveResult {
        if generation != self.identity.generation {
            return CredentialRemoveResult::StaleIgnored;
        }
        let Some(runtime) = self.credentials.get(credential_id) else {
            return CredentialRemoveResult::Missing;
        };
        if !runtime.admin_fenced {
            return CredentialRemoveResult::NotFenced;
        }
        if runtime.inflight != 0 {
            return CredentialRemoveResult::Busy {
                inflight: runtime.inflight,
            };
        }
        self.credentials.remove(credential_id);
        self.affinities
            .retain(|_, affinity| &affinity.credential_id != credential_id);
        self.session_claims
            .retain(|(candidate, _, _), claim| candidate != credential_id || claim.active_requests != 0);
        CredentialRemoveResult::Removed
    }

    /// Append-only in-memory resource ledger for persistence adapters.
    #[must_use]
    pub fn resource_events(&self) -> &[ResourceEvent] {
        &self.events
    }

    /// Drain persisted/forwarded events so the long-running owner does not retain an unbounded history.
    pub fn take_resource_events(&mut self) -> Vec<ResourceEvent> {
        std::mem::take(&mut self.events)
    }

    /// Acknowledge the durable prefix of the append-only resource ledger.
    pub fn acknowledge_resource_events(&mut self, through_sequence: u64) {
        self.events.retain(|event| event.sequence > through_sequence);
    }

    pub(crate) fn abandon_admission(&mut self, decision: AdmissionDecision, now: Duration) {
        match decision {
            AdmissionDecision::Granted(lease) => {
                let request_id = lease.request_id.clone();
                let _ = self.release_lease(self.identity.generation, &lease.id, now);
                let _ = self.release_group_permit(&request_id, ResourceAction::ForcedRelease, now);
            }
            AdmissionDecision::Queued(ticket) => {
                let _ = self.cancel(self.identity.generation, &ticket.request_id, now);
            }
            AdmissionDecision::Rejected(_) | AdmissionDecision::StaleIgnored => {}
        }
    }

    fn enqueue(
        &mut self,
        entry: ScheduleEntry,
        now: Duration,
        session_slot_deadline: Option<Duration>,
    ) -> Result<AdmissionDecision, SchedulerError> {
        if self.queue.len() >= self.queue_capacity() {
            self.group_rate_admitted.remove(&entry.request_id);
            return Ok(rejected(RejectionKind::QueueFull, Some(Duration::from_secs(2))));
        }
        let ticket_id = TicketId::new(format!("ticket_{}", Uuid::new_v4().simple()))
            .map_err(|_| SchedulerError::InvalidConfiguration)?;
        let ticket = QueueTicket {
            id: ticket_id,
            request_id: entry.request_id.clone(),
            deadline: entry.pre_upstream_deadline,
            state: TicketState::Queued,
            generation: self.identity.generation,
        };
        self.queue.push(entry.clone());
        self.waiting.insert(
            entry.request_id.clone(),
            WaitingRecord {
                ticket: ticket.clone(),
                session_slot_deadline,
            },
        );
        self.record_event(
            entry.request_id,
            ResourceKind::QueueTicket,
            ticket.id.as_str().into(),
            ResourceAction::Acquire,
            now,
        );
        Ok(AdmissionDecision::Queued(ticket))
    }

    fn acquire_session_claim(
        &mut self,
        entry: &ScheduleEntry,
        credential_id: &CredentialId,
    ) -> (Option<SessionClaimKey>, Option<Box<str>>) {
        if !self
            .credentials
            .get(credential_id)
            .is_some_and(|runtime| runtime.config.session_capacity.enabled)
        {
            return (None, None);
        }
        let key = (
            credential_id.clone(),
            entry.platform_key_id.clone(),
            entry.base_session_id.clone(),
        );
        let resource_id: Box<str> = format!("{}:{}:{}", key.0, key.1, key.2).into_boxed_str();
        let mut new_resource = None;
        let claim = self.session_claims.entry(key.clone()).or_insert_with(|| {
            new_resource = Some(resource_id.clone());
            SessionClaim {
                active_requests: 0,
                idle_since: None,
                last_request_id: entry.request_id.clone(),
                resource_id,
            }
        });
        claim.active_requests = claim.active_requests.saturating_add(1);
        claim.idle_since = None;
        claim.last_request_id = entry.request_id.clone();
        (Some(key), new_resource)
    }

    fn grant(
        &mut self,
        entry: ScheduleEntry,
        credential_id: &CredentialId,
        now: Duration,
        acquire_group_permit: bool,
    ) -> Result<CredentialLease, SchedulerError> {
        let runtime = self
            .credentials
            .get_mut(credential_id)
            .ok_or(SchedulerError::InvalidConfiguration)?;
        if !runtime.bucket.try_consume(now) || runtime.inflight >= runtime.config.concurrency_limit {
            return Err(SchedulerError::InvalidConfiguration);
        }
        let half_open = quota_requires_half_open(runtime, self.config.quota_guard_basis_points, now);
        if half_open {
            if runtime.config.state.half_open_inflight
                || runtime.half_open_consumed
                || !matches!(entry.generic.portability, Portability::Portable)
            {
                return Err(SchedulerError::InvalidConfiguration);
            }
            runtime.config.state.half_open_inflight = true;
            runtime.half_open_consumed = true;
        }
        runtime.inflight = runtime.inflight.saturating_add(1);
        let lease_id = LeaseId::new(format!("lease_{}", Uuid::new_v4().simple()))
            .map_err(|_| SchedulerError::InvalidConfiguration)?;
        let lease = CredentialLease {
            id: lease_id.clone(),
            request_id: entry.request_id.clone(),
            credential_id: credential_id.clone(),
            owner_generation: self.identity.generation,
            token_version: runtime.config.token_version,
            profile_id: runtime.config.profile_id.clone(),
            profile_epoch: runtime.config.profile_epoch,
            device_identity_id: runtime.config.device_identity_id.clone(),
            device_epoch: runtime.config.device_epoch,
            archetype_version_id: runtime.config.archetype_version_id.clone(),
            bundle_id: runtime.config.bundle_id.clone(),
            bundle_version: runtime.config.bundle_version,
            bundle_hash: runtime.config.bundle_hash.clone(),
            egress_binding_id: runtime.config.egress_binding_id.clone(),
            egress_epoch: runtime.config.egress_epoch,
            bundle_epoch: runtime.config.bundle_epoch,
            half_open,
        };
        let (session_claim_key, new_session_claim) = self.acquire_session_claim(&entry, credential_id);
        self.leases.insert(
            lease_id.clone(),
            LeaseRecord {
                lease: lease.clone(),
                session_claim_key,
            },
        );
        self.request_leases.insert(entry.request_id.clone(), lease_id.clone());
        if acquire_group_permit {
            self.group_permits.insert(entry.request_id.clone());
        }
        self.group_rate_admitted.remove(&entry.request_id);
        if acquire_group_permit {
            self.record_event(
                entry.request_id.clone(),
                ResourceKind::GroupPermit,
                Box::from("group-permit"),
                ResourceAction::Acquire,
                now,
            );
        }
        if let Some(resource_id) = new_session_claim {
            self.record_event(
                entry.request_id.clone(),
                ResourceKind::SessionClaim,
                resource_id,
                ResourceAction::Acquire,
                now,
            );
        }
        self.record_event(
            entry.request_id,
            ResourceKind::CredentialLease,
            lease_id.as_str().into(),
            ResourceAction::Acquire,
            now,
        );
        Ok(lease)
    }

    fn retry_candidate(
        &mut self,
        entry: &ScheduleEntry,
        target: &RetryCredentialTarget,
        current_credential: &CredentialId,
        now: Duration,
    ) -> Option<CredentialId> {
        if matches!(
            &entry.generic.portability,
            Portability::Pinned {
                credential_id: Some(pinned),
                ..
            } if !matches!(target, RetryCredentialTarget::Same(id) if id == pinned)
        ) {
            return None;
        }
        let mut candidates = Vec::new();
        let ids = self.credentials.keys().cloned().collect::<Vec<_>>();
        for id in ids {
            let selected = match target {
                RetryCredentialTarget::Same(expected) => &id == expected,
                RetryCredentialTarget::Alternate { exclude } => &id != exclude,
            };
            if !selected || session_capacity_blocked(&self.credentials[&id].config, &self.session_claims, entry) {
                continue;
            }
            let released_current = &id == current_credential;
            if released_current {
                let runtime = self.credentials.get_mut(&id)?;
                runtime.inflight = runtime.inflight.checked_sub(1)?;
            }
            let (class, _) = {
                let runtime = self.credentials.get_mut(&id)?;
                eligibility(runtime, &self.config, entry, now)
            };
            if released_current {
                let runtime = self.credentials.get_mut(&id)?;
                runtime.inflight = runtime.inflight.saturating_add(1);
            }
            if class == EligibilityClass::Eligible {
                candidates.push(id);
            }
        }
        let best_priority = candidates
            .iter()
            .filter_map(|id| self.credentials.get(id).map(|runtime| runtime.config.priority))
            .min()?;
        candidates.retain(|id| {
            self.credentials
                .get(id)
                .is_some_and(|runtime| runtime.config.priority == best_priority)
        });
        candidates.sort_by(|left, right| compare_candidates(&self.credentials, left, right));
        candidates.into_iter().next()
    }

    fn evaluate_pool(&mut self, entry: &ScheduleEntry, now: Duration) -> PoolEvaluation {
        evaluate_pool_fields(
            &mut self.credentials,
            &self.affinities,
            &self.session_claims,
            &self.config,
            entry,
            now,
        )
    }

    fn effective_concurrency(&self) -> usize {
        let healthy = capacity_sum(&self.credentials);
        let configured = self.config.concurrency_limit.unwrap_or(healthy);
        usize::try_from(configured.min(healthy)).unwrap_or(usize::MAX)
    }

    fn queue_capacity(&self) -> usize {
        self.config
            .queue_capacity
            .unwrap_or_else(|| self.effective_concurrency().saturating_mul(2))
    }

    fn expire_waiters(&mut self, now: Duration) -> Vec<QueueResolution> {
        let expired = self
            .waiting
            .iter()
            .filter(|(_, waiting)| {
                waiting.ticket.deadline <= now || waiting.session_slot_deadline.is_some_and(|deadline| deadline <= now)
            })
            .map(|(request_id, waiting)| {
                let kind = if waiting.session_slot_deadline.is_some_and(|deadline| deadline <= now) {
                    RejectionKind::SessionCapacityDeadline
                } else {
                    RejectionKind::TimedOut
                };
                (request_id.clone(), kind)
            })
            .collect::<Vec<_>>();
        let mut resolutions = Vec::with_capacity(expired.len());
        for (request_id, kind) in expired {
            let _ = self.queue.remove(&request_id);
            if let Some(waiting) = self.waiting.remove(&request_id) {
                self.record_event(
                    request_id.clone(),
                    ResourceKind::QueueTicket,
                    waiting.ticket.id.as_str().into(),
                    ResourceAction::Release,
                    now,
                );
            }
            self.group_rate_admitted.remove(&request_id);
            resolutions.push(QueueResolution {
                request_id,
                decision: rejected(kind, Some(Duration::from_secs(5))),
            });
        }
        resolutions
    }

    fn expire_cancel_grace(&mut self, now: Duration) {
        let expired = self
            .pending_cancels
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(lease_id, _)| lease_id.clone())
            .collect::<Vec<_>>();
        for lease_id in expired {
            // The request permit was released at cancellation time. Only the
            // upstream Lease remains fenced through the grace period.
            let _ = self.release_lease(self.identity.generation, &lease_id, now);
        }
    }

    fn prune(&mut self, now: Duration) {
        self.affinities.retain(|_, entry| entry.expires_at > now);
        let idle_ttl_by_credential = self
            .credentials
            .iter()
            .map(|(id, runtime)| (id.clone(), runtime.config.session_capacity.idle_ttl))
            .collect::<BTreeMap<_, _>>();
        let expired_claims = self
            .session_claims
            .iter()
            .filter(|((credential_id, _, _), claim)| {
                claim.active_requests == 0
                    && claim.idle_since.is_none_or(|idle| {
                        now.saturating_sub(idle)
                            >= idle_ttl_by_credential
                                .get(credential_id)
                                .copied()
                                .unwrap_or(Duration::ZERO)
                    })
            })
            .map(|(key, claim)| (key.clone(), claim.last_request_id.clone(), claim.resource_id.clone()))
            .collect::<Vec<_>>();
        for (key, request_id, resource_id) in expired_claims {
            self.session_claims.remove(&key);
            self.record_event(
                request_id,
                ResourceKind::SessionClaim,
                resource_id,
                ResourceAction::Release,
                now,
            );
        }
        for runtime in self.credentials.values_mut() {
            if runtime
                .config
                .state
                .quota_used_basis_points
                .is_none_or(|used| used < self.config.quota_guard_basis_points)
            {
                runtime.half_open_consumed = false;
            }
        }
    }

    fn record_event(
        &mut self,
        request_id: RequestId,
        kind: ResourceKind,
        resource_id: Box<str>,
        action: ResourceAction,
        now: Duration,
    ) {
        self.event_sequence = self.event_sequence.saturating_add(1);
        match action {
            ResourceAction::Acquire => self.resource_balance = self.resource_balance.saturating_add(1),
            ResourceAction::Release | ResourceAction::ForcedRelease => {
                self.resource_balance = self.resource_balance.saturating_sub(1);
            }
        }
        let portability = self
            .request_portability
            .get(&request_id)
            .cloned()
            .unwrap_or(Portability::Pinned {
                credential_id: None,
                reasons: Vec::new(),
            });
        self.events.push(ResourceEvent {
            sequence: self.event_sequence,
            request_id,
            resource_kind: kind,
            resource_id,
            action,
            portability,
            generation: self.identity.generation,
            observed_at: now,
        });
    }

    fn release_group_permit(
        &mut self,
        request_id: &RequestId,
        action: ResourceAction,
        now: Duration,
    ) -> Result<(), SchedulerError> {
        if !self.group_permits.remove(request_id) {
            return Err(SchedulerError::DuplicateRelease);
        }
        self.record_event(
            request_id.clone(),
            ResourceKind::GroupPermit,
            Box::from("group-permit"),
            action,
            now,
        );
        Ok(())
    }
}

fn capacity_sum(credentials: &BTreeMap<CredentialId, CredentialRuntime>) -> u32 {
    credentials
        .values()
        .filter(|runtime| runtime.config.state.lifecycle_active)
        .map(|runtime| runtime.config.concurrency_limit)
        .fold(0_u32, u32::saturating_add)
}

fn evaluate_pool_fields(
    credentials: &mut BTreeMap<CredentialId, CredentialRuntime>,
    affinities: &BTreeMap<AffinityKey, AffinityEntry>,
    session_claims: &BTreeMap<SessionClaimKey, SessionClaim>,
    config: &GroupConfig,
    entry: &ScheduleEntry,
    now: Duration,
) -> PoolEvaluation {
    let affinity_key = AffinityKey::from(entry);
    let preferred = affinities.get(&affinity_key).map(|value| &value.credential_id);
    let pinned = match &entry.generic.portability {
        Portability::Pinned {
            credential_id: Some(id),
            ..
        } => Some(id),
        Portability::Portable
        | Portability::Pinned {
            credential_id: None, ..
        } => None,
    };
    let mut candidates = Vec::new();
    let mut saw_temporary = false;
    let mut earliest_recovery: Option<Duration> = None;
    let mut preferred_capacity_only = false;
    let mut session_wait: Option<Duration> = None;

    for (id, runtime) in credentials.iter_mut() {
        if pinned.is_some_and(|target| target != id) {
            continue;
        }
        if session_capacity_blocked(&runtime.config, session_claims, entry) {
            saw_temporary = true;
            let wait = runtime.config.session_capacity.new_session_wait;
            session_wait = Some(session_wait.map_or(wait, |known| known.min(wait)));
            continue;
        }
        let (class, recovery) = eligibility(runtime, config, entry, now);
        match class {
            EligibilityClass::Eligible => candidates.push(id.clone()),
            EligibilityClass::TemporarilyBlocked => {
                saw_temporary = true;
                if preferred == Some(id) && runtime.inflight >= runtime.config.concurrency_limit {
                    preferred_capacity_only = true;
                }
                if let Some(recovery) = recovery {
                    earliest_recovery = Some(earliest_recovery.map_or(recovery, |known| known.min(recovery)));
                }
            }
            EligibilityClass::DeterministicallyIneligible => {}
        }
    }

    if candidates.is_empty() {
        if let Some(wait) = session_wait {
            return PoolEvaluation::SessionCapacity(wait);
        }
        return earliest_recovery.map_or_else(
            || {
                if saw_temporary {
                    PoolEvaluation::Wait
                } else {
                    PoolEvaluation::DeterministicUnavailable
                }
            },
            |recovery| PoolEvaluation::Cooldown(recovery.saturating_sub(now)),
        );
    }
    let best_priority = candidates
        .iter()
        .filter_map(|id| credentials.get(id).map(|runtime| runtime.config.priority))
        .min();
    if let Some(priority) = best_priority {
        candidates.retain(|id| {
            credentials
                .get(id)
                .is_some_and(|runtime| runtime.config.priority == priority)
        });
    }
    if let Some(preferred) = preferred {
        if candidates.iter().any(|id| id == preferred) {
            return PoolEvaluation::Candidate(preferred.clone());
        }
        if preferred_capacity_only && now < entry.accepted_at.saturating_add(config.preferred_capacity_wait) {
            return PoolEvaluation::Wait;
        }
    }
    candidates.sort_by(|left, right| compare_candidates(credentials, left, right));
    candidates
        .into_iter()
        .next()
        .map_or(PoolEvaluation::DeterministicUnavailable, PoolEvaluation::Candidate)
}

fn eligibility(
    runtime: &mut CredentialRuntime,
    config: &GroupConfig,
    entry: &ScheduleEntry,
    now: Duration,
) -> (EligibilityClass, Option<Duration>) {
    let half_open = quota_requires_half_open(runtime, config.quota_guard_basis_points, now);
    let credential = &runtime.config;
    if runtime.admin_fenced
        || !credential.state.lifecycle_active
        || !credential.state.profile_ready
        || !credential.state.egress_ready
        || !credential.state.transport_ready
        || (!credential.model_scope.is_empty() && !credential.model_scope.contains(entry.generic.model_id.as_ref()))
        || (entry.generic.attribution_suppressed && !credential.attribution_optional)
    {
        return (EligibilityClass::DeterministicallyIneligible, None);
    }
    if !credential.state.auth_healthy || runtime.inflight >= credential.concurrency_limit {
        return (EligibilityClass::TemporarilyBlocked, None);
    }
    if let Some(cooldown_until) = credential.state.cooldown_until
        && cooldown_until > now
    {
        return (EligibilityClass::TemporarilyBlocked, Some(cooldown_until));
    }
    if half_open {
        if credential.state.half_open_inflight
            || runtime.half_open_consumed
            || !matches!(entry.generic.portability, Portability::Portable)
        {
            return (EligibilityClass::TemporarilyBlocked, credential.state.quota_reset_at);
        }
    } else if credential
        .state
        .quota_used_basis_points
        .is_some_and(|used| used >= config.quota_guard_basis_points)
    {
        return (EligibilityClass::TemporarilyBlocked, credential.state.quota_reset_at);
    }
    if !runtime.bucket.try_consume_preview(now) {
        return (
            EligibilityClass::TemporarilyBlocked,
            Some(now.saturating_add(runtime.bucket.retry_after(now))),
        );
    }
    (EligibilityClass::Eligible, None)
}

fn session_capacity_blocked(
    credential: &CredentialConfig,
    session_claims: &BTreeMap<SessionClaimKey, SessionClaim>,
    entry: &ScheduleEntry,
) -> bool {
    if !credential.session_capacity.enabled {
        return false;
    }
    let claim_key = (
        credential.id.clone(),
        entry.platform_key_id.clone(),
        entry.base_session_id.clone(),
    );
    if session_claims.contains_key(&claim_key) {
        return false;
    }
    let active_sessions = session_claims
        .keys()
        .filter(|(credential_id, _, _)| credential_id == &credential.id)
        .count();
    active_sessions >= usize::try_from(credential.session_capacity.max_active_sessions).unwrap_or(usize::MAX)
}

fn quota_requires_half_open(runtime: &CredentialRuntime, guard: u16, now: Duration) -> bool {
    runtime
        .config
        .state
        .quota_used_basis_points
        .is_some_and(|used| used >= guard)
        && runtime.config.state.quota_reset_at.is_some_and(|reset| reset <= now)
}

fn compare_candidates(
    credentials: &BTreeMap<CredentialId, CredentialRuntime>,
    left: &CredentialId,
    right: &CredentialId,
) -> Ordering {
    let Some(left_runtime) = credentials.get(left) else {
        return Ordering::Greater;
    };
    let Some(right_runtime) = credentials.get(right) else {
        return Ordering::Less;
    };
    let left_pressure = u64::from(left_runtime.inflight) * u64::from(right_runtime.config.concurrency_limit);
    let right_pressure = u64::from(right_runtime.inflight) * u64::from(left_runtime.config.concurrency_limit);
    let left_quota = left_runtime.config.state.quota_used_basis_points.unwrap_or(10_000);
    let right_quota = right_runtime.config.state.quota_used_basis_points.unwrap_or(10_000);
    left_quota
        .cmp(&right_quota)
        .then_with(|| left_pressure.cmp(&right_pressure))
        .then_with(|| right_runtime.config.weight.cmp(&left_runtime.config.weight))
        .then_with(|| left.cmp(right))
}

fn rejected(kind: RejectionKind, retry_after: Option<Duration>) -> AdmissionDecision {
    AdmissionDecision::Rejected(Rejection { kind, retry_after })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::field_reassign_with_default)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc, time::Duration};

    use gateway_domain::{
        AgentId, ArchetypeVersionId, CredentialId, CredentialProfileId, DeviceIdentityId, Digest, EgressBindingId,
        GenericAdjustedRequest, GroupId, PlatformKeyId, Portability, RequestId, RequestReplayBody, RequestSnapshotSet,
        SessionId, SnapshotVersion, TransportBundleId, UserId,
    };
    use serde_json::json;

    use crate::{
        AdmissionDecision, AffinityKey, BucketConfig, CredentialAuthUpdate, CredentialConfig, CredentialCooldownUpdate,
        CredentialFenceResult, CredentialQuotaUpdate, CredentialRemoveResult, CredentialState, ExecutorIdentity,
        GroupConfig, OwnerGeneration, RejectionKind, ResourceAction, ResourceKind, RetryCredentialTarget,
        RetryLeaseDecision, RetryLeaseRequest, ScheduleEntry, SchedulerEngine, SessionCapacityConfig,
    };

    fn typed<T>(result: Result<T, gateway_domain::DomainError>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => std::panic::panic_any(error),
        }
    }

    fn generation() -> OwnerGeneration {
        match OwnerGeneration::new(7) {
            Ok(value) => value,
            Err(error) => std::panic::panic_any(error),
        }
    }

    fn generic(portability: Portability) -> Arc<GenericAdjustedRequest> {
        let bytes = Arc::<[u8]>::from(br#"{"model":"claude-test","messages":[]}"#.as_slice());
        let body = Arc::new(RequestReplayBody::new(
            bytes.clone(),
            Arc::new(json!({"model":"claude-test","messages":[]})),
            true,
        ));
        let version = || SnapshotVersion::new("v1");
        Arc::new(GenericAdjustedRequest {
            replay_body: body,
            body_digest: Digest::of(&bytes),
            model_id: "claude-test".into(),
            stream: false,
            portability,
            attribution_suppressed: false,
            change_set: Arc::from([]),
            snapshot_set: Arc::new(RequestSnapshotSet {
                access_policy: version(),
                group_config: version(),
                enforcement: version(),
                ruleset: None,
                capability: version(),
                background_catalog: version(),
                client_profile_catalog: version(),
                price: version(),
                serializer: version(),
            }),
        })
    }

    fn credential(index: u8, concurrency: u32) -> CredentialConfig {
        CredentialConfig {
            id: typed(CredentialId::new(format!("credential_{index}"))),
            credential_projection_revision: 1,
            scheduling_projection_revision: 1,
            concurrency_limit: concurrency,
            rate_limit: BucketConfig {
                requests_per_minute: 600,
                burst: 100,
            },
            priority: 0,
            weight: 1,
            model_scope: BTreeSet::new(),
            attribution_optional: true,
            session_capacity: SessionCapacityConfig::default(),
            token_version: 1,
            profile_id: typed(CredentialProfileId::new(format!("profile_{index}"))),
            profile_epoch: 2,
            device_identity_id: typed(DeviceIdentityId::new(format!("device_{index}"))),
            device_epoch: 1,
            archetype_version_id: typed(ArchetypeVersionId::new(format!("archetype_{index}"))),
            bundle_id: typed(TransportBundleId::new(format!("bundle_{index}"))),
            bundle_version: 1,
            bundle_hash: Digest::of(format!("bundle-{index}").as_bytes()),
            egress_binding_id: typed(EgressBindingId::new(format!("egress_{index}"))),
            egress_epoch: 3,
            bundle_epoch: 4,
            quota_observation_version: None,
            state: CredentialState::default(),
        }
    }

    fn entry(index: u16, key: u8, session: u8, agent: u8, portability: Portability) -> ScheduleEntry {
        ScheduleEntry {
            request_id: typed(RequestId::new(format!("request_{index}"))),
            owner_user_id: typed(UserId::new(format!("user_{key}"))),
            platform_key_id: typed(PlatformKeyId::new(format!("key_{key}"))),
            group_id: typed(GroupId::new("group_1")),
            base_session_id: typed(SessionId::new(format!("session_{session}"))),
            agent_id: typed(AgentId::new(format!("agent_{agent}"))),
            generic: generic(portability),
            accepted_at: Duration::ZERO,
            pre_upstream_deadline: Duration::from_secs(30),
        }
    }

    fn engine(credentials: Vec<CredentialConfig>) -> SchedulerEngine {
        engine_with_config(credentials, GroupConfig::default())
    }

    fn engine_with_config(credentials: Vec<CredentialConfig>, config: GroupConfig) -> SchedulerEngine {
        let result = SchedulerEngine::new(
            ExecutorIdentity {
                group_id: typed(GroupId::new("group_1")),
                owner_partition: "partition_1".into(),
                executor_id: "executor_1".into(),
                generation: generation(),
            },
            config,
            credentials,
            Duration::ZERO,
        );
        match result {
            Ok(value) => value,
            Err(error) => std::panic::panic_any(error),
        }
    }

    #[test]
    fn empty_group_runtime_is_ready_for_later_credential_attachment() {
        let mut engine = engine(Vec::new());
        let decision = engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO);
        assert!(matches!(decision, Ok(AdmissionDecision::Rejected(_))));
        assert_eq!(engine.snapshot().active_leases, 0);
        assert_eq!(engine.snapshot().total_credential_capacity, 0);
    }

    #[test]
    fn forty_requests_use_fifteen_leases_and_twenty_five_queue_positions() {
        let mut engine = engine(vec![credential(1, 5), credential(2, 5), credential(3, 5)]);
        for index in 0..40_u16 {
            let decision = engine.admit(
                generation(),
                entry(index, u8::try_from(index / 4).unwrap_or(0), 1, 1, Portability::Portable),
                Duration::ZERO,
            );
            assert!(decision.is_ok());
        }
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.active_leases, 15);
        assert_eq!(snapshot.queued_tickets, 25);
        assert_eq!(
            snapshot.credential_inflight.iter().map(|(_, count)| count).sum::<u32>(),
            15
        );
    }

    #[test]
    fn queue_cap_rejects_forty_sixth_request() {
        let mut engine = engine(vec![credential(1, 5), credential(2, 5), credential(3, 5)]);
        let mut last = None;
        for index in 0..46_u16 {
            last = engine
                .admit(
                    generation(),
                    entry(index, u8::try_from(index).unwrap_or(0), 1, 1, Portability::Portable),
                    Duration::ZERO,
                )
                .ok();
        }
        assert!(matches!(
            last,
            Some(AdmissionDecision::Rejected(ref rejection)) if rejection.kind == RejectionKind::QueueFull
        ));
    }

    #[test]
    fn main_and_nine_subagents_have_no_session_cap() {
        let mut engine = engine(vec![credential(1, 5), credential(2, 5), credential(3, 5)]);
        for agent in 0..10_u8 {
            let result = engine.admit(
                generation(),
                entry(u16::from(agent), 1, 1, agent, Portability::Portable),
                Duration::ZERO,
            );
            assert!(matches!(result, Ok(AdmissionDecision::Granted(_))));
        }
        assert_eq!(engine.snapshot().active_leases, 10);
    }

    #[test]
    fn retry_replaces_only_the_credential_lease_and_keeps_one_group_permit() {
        let mut engine = engine(vec![credential(1, 5), credential(2, 5)]);
        let scheduled = entry(1, 1, 1, 1, Portability::Portable);
        let first = match engine.admit(generation(), scheduled.clone(), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        let replacement = engine
            .replace_lease(
                generation(),
                RetryLeaseRequest {
                    current_lease_id: first.id.clone(),
                    entry: scheduled,
                    target: RetryCredentialTarget::Alternate {
                        exclude: first.credential_id.clone(),
                    },
                },
                Duration::from_secs(1),
            )
            .unwrap_or_else(|error| std::panic::panic_any(error));
        let second = match replacement {
            RetryLeaseDecision::Granted(lease) => lease,
            other => std::panic::panic_any(format!("unexpected retry decision: {other:?}")),
        };
        assert_ne!(first.credential_id, second.credential_id);
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.active_leases, 1);
        assert_eq!(snapshot.active_group_permits, 1);
        assert_eq!(snapshot.resource_balance, 2);
        let permit_acquires = engine
            .resource_events()
            .iter()
            .filter(|event| event.resource_kind == ResourceKind::GroupPermit && event.action == ResourceAction::Acquire)
            .count();
        assert_eq!(permit_acquires, 1);
        assert!(
            engine
                .release_lease(generation(), &first.id, Duration::from_secs(2))
                .is_err()
        );
        assert!(
            engine
                .release_lease(generation(), &second.id, Duration::from_secs(2))
                .is_ok()
        );
    }

    #[test]
    fn stale_release_has_zero_state_effect_and_exact_release_is_enforced() {
        let mut engine = engine(vec![credential(1, 5)]);
        let lease = match engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        let before = engine.snapshot();
        let stale = match OwnerGeneration::new(6) {
            Ok(value) => value,
            Err(error) => std::panic::panic_any(error),
        };
        assert!(engine.release_lease(stale, &lease.id, Duration::ZERO).is_ok());
        assert_eq!(engine.snapshot(), before);
        assert!(engine.release_lease(generation(), &lease.id, Duration::ZERO).is_ok());
        assert!(engine.release_lease(generation(), &lease.id, Duration::ZERO).is_err());
    }

    #[test]
    fn pinned_request_does_not_spill_to_another_credential() {
        let mut credentials = vec![credential(1, 1), credential(2, 5)];
        credentials[0].state.transport_ready = false;
        let pinned_id = credentials[0].id.clone();
        let mut engine = engine(credentials);
        let decision = engine.admit(
            generation(),
            entry(
                1,
                1,
                1,
                1,
                Portability::Pinned {
                    credential_id: Some(pinned_id),
                    reasons: Vec::new(),
                },
            ),
            Duration::ZERO,
        );
        assert!(matches!(
            decision,
            Ok(AdmissionDecision::Rejected(ref rejection)) if rejection.kind == RejectionKind::GroupUnavailable
        ));
    }

    #[test]
    fn affinity_migrates_only_after_stable_success_threshold() {
        let mut engine = engine(vec![credential(1, 1), credential(2, 1)]);
        let scheduled = entry(1, 1, 1, 1, Portability::Portable);
        let key = AffinityKey::from(&scheduled);
        let first = match engine.admit(generation(), scheduled, Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        let alternate = typed(CredentialId::new("credential_2"));
        engine.record_success(&key, &first.credential_id, Duration::ZERO);
        engine.record_success(&key, &alternate, Duration::from_secs(1));
        engine.record_success(&key, &alternate, Duration::from_secs(2));
        engine.record_success(&key, &alternate, Duration::from_secs(3));
        assert!(
            engine
                .release_lease(generation(), &first.id, Duration::from_secs(4))
                .is_ok()
        );
        let next = match engine.admit(
            generation(),
            entry(2, 1, 1, 1, Portability::Portable),
            Duration::from_secs(4),
        ) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert_eq!(next.credential_id, alternate);
    }

    #[test]
    fn queued_request_cannot_be_overtaken_after_lease_release() {
        let mut engine = engine(vec![credential(1, 1)]);
        let first = match engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert!(matches!(
            engine.admit(generation(), entry(2, 2, 2, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Queued(_))
        ));
        assert!(
            engine
                .release_lease(generation(), &first.id, Duration::from_secs(1))
                .is_ok()
        );
        assert!(matches!(
            engine.admit(
                generation(),
                entry(3, 3, 3, 1, Portability::Portable),
                Duration::from_secs(1)
            ),
            Ok(AdmissionDecision::Queued(_))
        ));
        let resolutions = engine.complete_request(generation(), &first.request_id, Duration::from_secs(1));
        assert!(matches!(
            resolutions,
            Ok(ref values) if values.len() == 1 && values[0].request_id == typed(RequestId::new("request_2"))
        ));
    }

    #[test]
    fn cancellation_holds_capacity_until_transport_confirmation_or_grace() {
        let mut engine = engine(vec![credential(1, 1)]);
        let first = match engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert!(engine.cancel(generation(), &first.request_id, Duration::ZERO).is_ok());
        assert_eq!(engine.snapshot().active_group_permits, 0);
        assert_eq!(engine.snapshot().active_leases, 1);
        assert!(matches!(
            engine.admit(generation(), entry(2, 2, 2, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Queued(_))
        ));
        assert!(engine.pump(generation(), Duration::from_millis(1_999)).is_empty());
        let resolutions = engine.pump(generation(), Duration::from_secs(2));
        assert_eq!(resolutions.len(), 1);
        assert_eq!(engine.snapshot().active_leases, 1);
    }

    #[test]
    fn all_deterministic_blockers_reject_without_queueing() {
        let mut blocked = credential(1, 5);
        blocked.state.profile_ready = false;
        let mut engine = engine(vec![blocked]);
        let decision = engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO);
        assert!(matches!(
            decision,
            Ok(AdmissionDecision::Rejected(ref rejection))
                if rejection.kind == RejectionKind::GroupUnavailable && rejection.retry_after.is_none()
        ));
        assert_eq!(engine.snapshot().queued_tickets, 0);
    }

    #[test]
    fn cooldown_inside_deadline_queues_and_beyond_deadline_returns_429_class() {
        let mut short = credential(1, 5);
        short.state.cooldown_until = Some(Duration::from_secs(12));
        let mut short_engine = engine(vec![short]);
        assert!(matches!(
            short_engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Queued(_))
        ));

        let mut long = credential(1, 5);
        long.state.cooldown_until = Some(Duration::from_secs(45));
        let mut engine = engine(vec![long]);
        let decision = engine.admit(generation(), entry(2, 1, 1, 1, Portability::Portable), Duration::ZERO);
        assert!(matches!(
            decision,
            Ok(AdmissionDecision::Rejected(ref rejection))
                if rejection.kind == RejectionKind::CooldownBeyondDeadline
                    && rejection.retry_after == Some(Duration::from_secs(45))
        ));
    }

    #[test]
    fn optional_session_capacity_has_a_fixed_five_second_wait() {
        let mut configured = credential(1, 2);
        configured.session_capacity = SessionCapacityConfig {
            enabled: true,
            max_active_sessions: 1,
            idle_ttl: Duration::from_mins(30),
            new_session_wait: Duration::from_secs(5),
        };
        let mut engine = engine(vec![configured]);
        let first = match engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert!(engine.release_lease(generation(), &first.id, Duration::ZERO).is_ok());
        assert!(
            engine
                .complete_request(generation(), &first.request_id, Duration::ZERO)
                .is_ok()
        );
        assert!(matches!(
            engine.admit(generation(), entry(2, 1, 2, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Queued(_))
        ));
        let resolutions = engine.pump(generation(), Duration::from_secs(5));
        assert!(matches!(
            resolutions.as_slice(),
            [resolution]
                if matches!(
                    resolution.decision,
                    AdmissionDecision::Rejected(ref rejection)
                        if rejection.kind == RejectionKind::SessionCapacityDeadline
                )
        ));
    }

    #[test]
    fn quota_reset_allows_exactly_one_half_open_until_result() {
        let mut pressured = credential(1, 2);
        pressured.state.quota_used_basis_points = Some(9_500);
        pressured.state.quota_reset_at = Some(Duration::ZERO);
        let credential_id = pressured.id.clone();
        let mut engine = engine(vec![pressured]);
        let first = match engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert!(first.half_open);
        assert!(matches!(
            engine.admit(generation(), entry(2, 2, 2, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Queued(_))
        ));
        assert!(engine.release_lease(generation(), &first.id, Duration::ZERO).is_ok());
        assert!(
            engine
                .complete_request(generation(), &first.request_id, Duration::ZERO)
                .is_ok()
        );
        assert!(engine.pump(generation(), Duration::from_secs(1)).is_empty());
        engine.record_half_open_result(generation(), &credential_id, true, Duration::from_secs(1));
        let resolutions = engine.pump(generation(), Duration::from_secs(1));
        assert!(
            matches!(resolutions.as_slice(), [resolution] if matches!(resolution.decision, AdmissionDecision::Granted(_)))
        );
    }

    #[test]
    fn request_identifier_is_tombstoned_for_the_owner_generation() {
        let mut engine = engine(vec![credential(1, 1)]);
        let first_entry = entry(1, 1, 1, 1, Portability::Portable);
        let lease = match engine.admit(generation(), first_entry.clone(), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert!(engine.release_lease(generation(), &lease.id, Duration::ZERO).is_ok());
        assert!(
            engine
                .complete_request(generation(), &lease.request_id, Duration::ZERO)
                .is_ok()
        );
        assert!(matches!(
            engine.admit(generation(), first_entry, Duration::from_secs(1)),
            Ok(AdmissionDecision::Rejected(ref rejection)) if rejection.kind == RejectionKind::DuplicateRequest
        ));
    }

    #[test]
    fn group_permit_outlives_upstream_lease_until_delivery_completion() {
        let mut config = GroupConfig::default();
        config.concurrency_limit = Some(1);
        let mut engine = engine_with_config(vec![credential(1, 2)], config);
        let lease = match engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert!(engine.release_lease(generation(), &lease.id, Duration::ZERO).is_ok());
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.active_leases, 0);
        assert_eq!(snapshot.active_group_permits, 1);
        assert!(matches!(
            engine.admit(generation(), entry(2, 2, 2, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Queued(_))
        ));
    }

    #[test]
    fn group_disable_cancels_queue_but_keeps_active_lease() {
        let mut engine = engine(vec![credential(1, 1)]);
        let active = engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO);
        assert!(matches!(active, Ok(AdmissionDecision::Granted(_))));
        assert!(matches!(
            engine.admit(generation(), entry(2, 2, 2, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Queued(_))
        ));
        let rejected = engine.disable(generation(), Duration::from_secs(1));
        assert_eq!(rejected.len(), 1);
        assert_eq!(engine.snapshot().active_leases, 1);
        assert_eq!(engine.snapshot().queued_tickets, 0);
    }

    #[test]
    fn group_rpm_wait_reuses_the_original_absolute_deadline() {
        let mut config = GroupConfig::default();
        config.rate_limit = Some(BucketConfig {
            requests_per_minute: 60,
            burst: 1,
        });
        let mut engine = engine_with_config(vec![credential(1, 2)], config);
        let first = match engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert!(matches!(
            engine.admit(generation(), entry(2, 2, 2, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Queued(_))
        ));
        assert!(engine.release_lease(generation(), &first.id, Duration::ZERO).is_ok());
        let immediate = engine.complete_request(generation(), &first.request_id, Duration::ZERO);
        assert!(matches!(immediate, Ok(ref resolutions) if resolutions.is_empty()));
        let resolutions = engine.pump(generation(), Duration::from_secs(1));
        assert!(
            matches!(resolutions.as_slice(), [resolution] if matches!(resolution.decision, AdmissionDecision::Granted(_)))
        );
    }

    #[test]
    fn preferred_capacity_waits_exactly_two_seconds_then_spills() {
        let mut engine = engine(vec![credential(1, 1), credential(2, 1)]);
        let first_entry = entry(1, 1, 1, 1, Portability::Portable);
        let affinity_key = AffinityKey::from(&first_entry);
        let first = match engine.admit(generation(), first_entry, Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        engine.record_success(&affinity_key, &first.credential_id, Duration::ZERO);
        assert!(matches!(
            engine.admit(generation(), entry(2, 1, 1, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Queued(_))
        ));
        assert!(engine.pump(generation(), Duration::from_millis(1_999)).is_empty());
        let resolutions = engine.pump(generation(), Duration::from_secs(2));
        assert!(matches!(
            resolutions.as_slice(),
            [resolution]
                if matches!(
                    resolution.decision,
                    AdmissionDecision::Granted(ref lease) if lease.credential_id != first.credential_id
                )
        ));
    }

    #[test]
    fn group_rpm_recovery_beyond_deadline_is_a_rate_rejection_without_lease() {
        let config = GroupConfig {
            rate_limit: Some(BucketConfig {
                requests_per_minute: 1,
                burst: 1,
            }),
            ..GroupConfig::default()
        };
        let mut engine = engine_with_config(vec![credential(1, 2)], config);
        assert!(matches!(
            engine.admit(generation(), entry(1, 1, 1, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Granted(_))
        ));
        let decision = engine.admit(generation(), entry(2, 2, 2, 1, Portability::Portable), Duration::ZERO);
        assert!(matches!(
            decision,
            Ok(AdmissionDecision::Rejected(ref rejection))
                if rejection.kind == RejectionKind::GroupRateDeadline
                    && rejection.retry_after == Some(Duration::from_secs(5))
        ));
        assert_eq!(engine.snapshot().active_leases, 1);
    }

    #[test]
    fn credential_cooldown_observation_is_generation_fenced_and_changes_eligibility() {
        let mut engine = engine(vec![credential(1, 2)]);
        let credential_id = typed(CredentialId::new("credential_1"));
        let update = CredentialCooldownUpdate {
            credential_id,
            cooldown_until: Some(Duration::from_mins(1)),
        };
        let stale = match OwnerGeneration::new(2) {
            Ok(value) => value,
            Err(error) => std::panic::panic_any(error),
        };
        assert!(!engine.observe_credential_cooldown(stale, &update));
        assert!(engine.observe_credential_cooldown(generation(), &update));
        assert!(matches!(
            engine.admit(generation(), entry(9, 9, 9, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Rejected(ref rejection)) if rejection.kind == RejectionKind::CooldownBeyondDeadline
        ));
    }

    #[test]
    fn administrator_fence_blocks_new_grants_and_remove_waits_for_exact_lease_drain() {
        let mut engine = engine(vec![credential(1, 1), credential(2, 1)]);
        let credential_id = typed(CredentialId::new("credential_1"));
        let first = match engine.admit(generation(), entry(90, 1, 1, 1, Portability::Portable), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert_eq!(first.credential_id, credential_id);
        assert_eq!(
            engine.set_credential_fence(generation(), &credential_id, true),
            CredentialFenceResult::Applied { inflight: 1 }
        );
        assert_eq!(engine.snapshot().fenced_credentials, vec![credential_id.clone()]);
        let second = match engine.admit(generation(), entry(91, 2, 2, 1, Portability::Portable), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert_ne!(second.credential_id, credential_id);
        assert_eq!(
            engine.remove_fenced_credential(generation(), &credential_id),
            CredentialRemoveResult::Busy { inflight: 1 }
        );
        assert!(
            engine
                .release_lease(generation(), &first.id, Duration::from_secs(1))
                .is_ok()
        );
        assert!(
            engine
                .complete_request(generation(), &first.request_id, Duration::from_secs(1))
                .is_ok()
        );
        assert_eq!(
            engine.remove_fenced_credential(generation(), &credential_id),
            CredentialRemoveResult::Removed
        );
        assert!(
            engine
                .snapshot()
                .credential_inflight
                .iter()
                .all(|(id, _)| id != &credential_id)
        );
    }

    #[test]
    fn group_reconfigure_rejects_old_queued_generation_and_fences_mixed_snapshots() {
        let mut engine = engine(vec![credential(1, 1)]);
        assert!(matches!(
            engine.admit(generation(), entry(92, 1, 1, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Granted(_))
        ));
        assert!(matches!(
            engine.admit(generation(), entry(93, 2, 2, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Queued(_))
        ));
        let mut next_config = GroupConfig::default();
        next_config.snapshot_version = SnapshotVersion::new("v2");
        let rejected = engine
            .reconfigure(generation(), next_config, Duration::from_secs(1))
            .unwrap_or_else(|error| std::panic::panic_any(error));
        assert!(matches!(
            rejected.as_slice(),
            [resolution]
                if matches!(
                    resolution.decision,
                    AdmissionDecision::Rejected(ref rejection)
                        if rejection.kind == RejectionKind::GroupUnavailable
                )
        ));
        assert!(matches!(
            engine.admit(generation(), entry(94, 3, 3, 1, Portability::Portable), Duration::from_secs(1)),
            Ok(AdmissionDecision::Rejected(ref rejection)) if rejection.kind == RejectionKind::GroupUnavailable
        ));
        let mut current = entry(95, 4, 4, 1, Portability::Portable);
        let mut adjusted = (*current.generic).clone();
        let mut snapshots = (*adjusted.snapshot_set).clone();
        snapshots.group_config = SnapshotVersion::new("v2");
        adjusted.snapshot_set = Arc::new(snapshots);
        current.generic = Arc::new(adjusted);
        assert!(matches!(
            engine.admit(generation(), current, Duration::from_secs(1)),
            Ok(AdmissionDecision::Queued(_))
        ));
    }

    #[test]
    fn credential_reconfigure_downscales_without_revoking_existing_leases() {
        let mut engine = engine(vec![credential(1, 2)]);
        for index in 200_u8..202 {
            assert!(matches!(
                engine.admit(
                    generation(),
                    entry(u16::from(index), 1, index, 1, Portability::Portable,),
                    Duration::ZERO
                ),
                Ok(AdmissionDecision::Granted(_))
            ));
        }
        let mut updated = credential(1, 1);
        updated.credential_projection_revision = 2;
        updated.scheduling_projection_revision = 2;
        assert_eq!(
            engine.reconfigure_credential(generation(), updated.clone(), Duration::from_secs(1)),
            Ok(true)
        );
        assert_eq!(engine.snapshot().active_leases, 2);
        assert!(matches!(
            engine.admit(
                generation(),
                entry(202, 2, 3, 1, Portability::Portable),
                Duration::from_secs(1)
            ),
            Ok(AdmissionDecision::Queued(_))
        ));
        assert_eq!(
            engine.reconfigure_credential(generation(), updated, Duration::from_secs(2)),
            Ok(false)
        );
    }

    #[test]
    fn credential_continuity_replace_preserves_old_lease_and_updates_new_lease() {
        let mut engine = engine(vec![credential(1, 1)]);
        let first = match engine.admit(generation(), entry(203, 1, 1, 1, Portability::Portable), Duration::ZERO) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert_eq!(first.profile_epoch, 2);
        let mut updated = credential(1, 1);
        updated.credential_projection_revision = 2;
        updated.profile_epoch = 3;
        updated.archetype_version_id = typed(ArchetypeVersionId::new("archetype_migrated"));
        assert_eq!(
            engine.reconfigure_credential(generation(), updated, Duration::from_secs(1)),
            Ok(true)
        );
        assert_eq!(first.profile_epoch, 2);
        assert!(
            engine
                .release_lease(generation(), &first.id, Duration::from_secs(2))
                .is_ok()
        );
        assert!(
            engine
                .complete_request(generation(), &first.request_id, Duration::from_secs(2))
                .is_ok()
        );
        let second = match engine.admit(
            generation(),
            entry(204, 1, 1, 1, Portability::Portable),
            Duration::from_secs(2),
        ) {
            Ok(AdmissionDecision::Granted(lease)) => lease,
            other => std::panic::panic_any(format!("unexpected decision: {other:?}")),
        };
        assert_eq!(second.profile_epoch, 3);
        let mut stale = credential(1, 1);
        stale.credential_projection_revision = 1;
        stale.scheduling_projection_revision = 99;
        assert_eq!(
            engine.reconfigure_credential(generation(), stale, Duration::from_secs(3)),
            Ok(false)
        );
    }

    #[test]
    fn credential_auth_observation_advances_token_generation_and_rejects_stale_updates() {
        let mut engine = engine(vec![credential(1, 2)]);
        let credential_id = typed(CredentialId::new("credential_1"));
        let update = CredentialAuthUpdate {
            credential_id: credential_id.clone(),
            token_version: 2,
            auth_healthy: true,
        };
        assert!(engine.observe_credential_auth(generation(), &update));
        assert!(!engine.observe_credential_auth(
            generation(),
            &CredentialAuthUpdate {
                credential_id,
                token_version: 1,
                auth_healthy: true,
            },
        ));
        assert!(matches!(
            engine.admit(generation(), entry(10, 1, 1, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Granted(ref lease)) if lease.token_version == 2
        ));
    }

    #[test]
    fn credential_quota_observation_is_generation_and_version_fenced() {
        let mut engine = engine(vec![credential(1, 2)]);
        let credential_id = typed(CredentialId::new("credential_1"));
        let update = CredentialQuotaUpdate {
            credential_id: credential_id.clone(),
            observation_version: 20,
            used_basis_points: 9_500,
            reset_at: Duration::from_mins(5),
        };
        assert!(engine.observe_credential_quota(generation(), &update));
        assert!(!engine.observe_credential_quota(
            generation(),
            &CredentialQuotaUpdate {
                credential_id: credential_id.clone(),
                observation_version: 19,
                used_basis_points: 100,
                reset_at: Duration::ZERO,
            },
        ));
        assert!(matches!(
            engine.admit(generation(), entry(11, 1, 1, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Rejected(ref rejection))
                if rejection.kind == RejectionKind::CooldownBeyondDeadline
        ));
        let stale_generation = OwnerGeneration::new(6).unwrap_or_else(|error| std::panic::panic_any(error));
        assert!(!engine.observe_credential_quota(
            stale_generation,
            &CredentialQuotaUpdate {
                credential_id,
                observation_version: 21,
                used_basis_points: 0,
                reset_at: Duration::ZERO,
            },
        ));
    }

    #[test]
    fn resource_ledger_is_peeked_then_acknowledged_by_sequence() {
        let mut engine = engine(vec![credential(1, 2)]);
        assert!(matches!(
            engine.admit(generation(), entry(12, 1, 1, 1, Portability::Portable), Duration::ZERO),
            Ok(AdmissionDecision::Granted(_))
        ));
        let events = engine.resource_events();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.portability == Portability::Portable));
        let first_sequence = events[0].sequence;
        let last_sequence = events[1].sequence;
        engine.acknowledge_resource_events(first_sequence);
        assert_eq!(engine.resource_events().len(), 1);
        assert_eq!(engine.resource_events()[0].sequence, last_sequence);
        engine.acknowledge_resource_events(last_sequence);
        assert!(engine.resource_events().is_empty());
    }
}
