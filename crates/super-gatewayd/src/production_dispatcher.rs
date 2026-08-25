//! Production composition of Group scheduling, Credential/Profile material,
//! exact Transport Bundle selection, Content Audit latching and transparent
//! response delivery.

#![allow(clippy::similar_names, clippy::too_many_lines)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use gateway_api::{ContentAuditMode, DispatchError, DispatchRequest, MessageDispatcher, UpstreamResponse};
use gateway_domain::{
    ArchetypeVersionId, AttemptDeadlines, AttemptIdentitySnapshot, AttemptPlanId, Clock, ConnectionAttemptId,
    CredentialId, CredentialProfileId, DeviceIdentityId, Digest, EgressBindingId, EgressRouteSnapshot,
    FinalUpstreamRequest, GroupId, MaintenanceTrigger, PinReason, Portability, ProxyCredentials, ProxyEndpointId,
    SecretBytes, SecretValue, Socks5DnsMode, TransportAttemptSnapshot, TransportBundleId, UpstreamHeader,
};
use gateway_scheduler::{
    AdmissionDecision, BucketConfig, ConnectionAttemptBudget, CredentialAuthUpdate, CredentialConfig,
    CredentialCooldownUpdate, CredentialFenceResult, CredentialLease, CredentialQuotaUpdate, CredentialRemoveResult,
    CredentialState, ExecutorIdentity, GroupConfig, GroupExecutorHandle, OwnerGeneration, QueueResolution, Rejection,
    RejectionKind, ResourceAction, ResourceEvent, ResourceKind, RetryContext, RetryCredentialTarget, RetryErrorClass,
    RetryLeaseDecision, RetryLeaseRequest, RetryStrategy, ScheduleEntry, SchedulerEngine, SessionCapacityConfig,
    decide_retry,
};
use gateway_services::{
    content_audit::{AuditCaptureKind, AuditObjectContext, AuditObjectManifest, ContentAuditLatch, ContentAuditStore},
    credential::{CredentialMaintainer, CredentialServiceError},
    quota::{SUBSCRIPTION_QUOTA_PARSER_VERSION, parse_subscription_quota_headers},
    response::{
        DeliveryCompletion, DeliveryCompletionError, DeliveryReport, ResponseConfig, ResponseError, ResponsePipeline,
        ResponseSideWriter,
    },
    scheduler::SchedulerSupervisor,
    security::{EnvelopeAad, EnvelopeService, LocalAesKeyProvider, SecretEnvelope},
    usage::{ObservedResponseUsage, calculate_cost},
};
use gateway_storage::{
    AuditOutboxRecord, CancelEstimateEvidencePersist, CostPersist, DeliveryComplete, DeliveryStart, PgStorage,
    QuotaObservationPersist, RequestCreate, RequestLifecycleComplete, SchedulerResourceEventRecord,
    SubmissionIntentArm, UsagePersist,
};
use gateway_transport::{
    EngineCatalogHandle, HealthEffect, MonotonicEventSink, RawResponseBody, RawUpstreamResponse, RetrySafety,
    TransportAttempt, TransportCore, TransportError, TransportErrorCode, TransportEvent, TransportEventKind,
    TransportEventSink,
};
use hmac::{Hmac, Mac as _};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use tokio::sync::{Mutex, Notify, RwLock, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const ACTIVE_GROUP_RUNTIME_SQL: &str = "SELECT g.id,gc.config_version,gc.default_rpm,gc.default_rpm_burst,gc.max_concurrency,gc.queue_capacity, \
            gc.pre_upstream_wait_ms,gc.preferred_capacity_wait_ms,gc.affinity_ttl_ms, \
            gc.affinity_migration_successes,gc.quota_guard_basis_points, \
            gc.upstream_connect_ms,gc.upstream_non_stream_total_ms,gc.upstream_stream_idle_ms, \
            gc.min_retry_budget_ms,gc.cancel_grace_ms,gc.queue_full_retry_after_ms, \
            gc.queue_wait_retry_after_ms \
     FROM gateway.credential_group g \
     JOIN gateway.group_active_config active ON active.group_id=g.id \
     JOIN gateway.group_config gc ON gc.id=active.config_id \
     WHERE g.status_code='active' AND ($1::uuid IS NULL OR g.id=$1) ORDER BY g.id";

/// Complete production dispatcher. All mutable scheduling state remains inside
/// one actor per Group; this adapter owns only immutable runtime projections.
pub(crate) struct ProductionDispatcher {
    storage: Arc<PgStorage>,
    groups: Arc<ArcSwap<BTreeMap<GroupId, Arc<RuntimeGroup>>>>,
    group_registry_lock: Mutex<()>,
    scheduler_supervisor: SchedulerSupervisor,
    executor_id: Box<str>,
    engines: Arc<EngineCatalogHandle>,
    transport: Arc<dyn TransportCore>,
    response: ResponsePipeline,
    clock: Arc<dyn Clock>,
    content_audit: Option<Arc<ContentAuditStore>>,
    credential_maintainer: Option<Arc<dyn CredentialMaintainer>>,
    request_cancellation: CancellationToken,
    audit_tasks: Arc<Mutex<Vec<ResponseAuditHandle>>>,
}

impl std::fmt::Debug for ProductionDispatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionDispatcher")
            .field("group_count", &self.groups.load().len())
            .field("content_audit_configured", &self.content_audit.is_some())
            .finish_non_exhaustive()
    }
}

impl ProductionDispatcher {
    /// Load and fence active Groups, then start bounded queue expiry ticks.
    pub(crate) async fn load(
        storage: Arc<PgStorage>,
        engines: Arc<EngineCatalogHandle>,
        transport: Arc<dyn TransportCore>,
        response_tmp_dir: std::path::PathBuf,
        clock: Arc<dyn Clock>,
        content_audit: Option<Arc<ContentAuditStore>>,
        credential_maintainer: Option<Arc<dyn CredentialMaintainer>>,
    ) -> anyhow::Result<Self> {
        let mut spill_key = vec![0_u8; 32];
        getrandom::fill(&mut spill_key).map_err(|_| anyhow::anyhow!("response spill key generation failed"))?;
        let response = ResponsePipeline::new(
            ResponseConfig::default(),
            response_tmp_dir,
            Arc::new(SecretBytes::new(spill_key)),
        )?;
        response.sweep_orphans().await?;

        let supervisor = SchedulerSupervisor::default();
        let mut groups = BTreeMap::new();
        let executor_id = format!("executor_{}", Uuid::now_v7().simple());
        let group_rows = sqlx::query(ACTIVE_GROUP_RUNTIME_SQL)
            .bind(Option::<Uuid>::None)
            .fetch_all(&storage.pool())
            .await?;
        let catalog = engines.snapshot();
        for row in group_rows {
            let group_uuid: Uuid = row.try_get("id")?;
            let group_id = GroupId::new(group_uuid.to_string())?;
            let now = clock.now().monotonic;
            let credentials = load_scheduler_credentials(&storage, group_uuid, &catalog, now).await?;
            let claim = match storage.claim_group_owner(group_uuid, &executor_id).await {
                Ok(claim) => claim,
                Err(gateway_storage::StorageError::RevisionConflict) => {
                    tracing::warn!(event = "group_owner_not_started", group_id = %group_id, reason = "owner_lease_held");
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let generation = OwnerGeneration::new(u64::try_from(claim.owner_generation)?)?;
            let request_limits = runtime_request_limits(&row)?;
            let group_config = runtime_group_config(&row, group_uuid, request_limits)?;
            let identity = ExecutorIdentity {
                group_id: group_id.clone(),
                owner_partition: "single_process".into(),
                executor_id: executor_id.clone().into_boxed_str(),
                generation,
            };
            let engine = SchedulerEngine::new(identity, group_config, credentials, clock.now().monotonic)?;
            let handle = supervisor.register(group_id.clone(), engine)?;
            let runtime = Arc::new(RuntimeGroup::new(
                executor_id.clone().into_boxed_str(),
                generation,
                handle,
                clock.clone(),
                storage.clone(),
                group_uuid,
                request_limits,
            ));
            runtime.spawn_ticks();
            groups.insert(group_id, runtime);
        }
        Ok(Self {
            storage,
            groups: Arc::new(ArcSwap::from_pointee(groups)),
            group_registry_lock: Mutex::new(()),
            scheduler_supervisor: supervisor,
            executor_id: executor_id.into_boxed_str(),
            engines,
            transport,
            response,
            clock,
            content_audit,
            credential_maintainer,
            request_cancellation: CancellationToken::new(),
            audit_tasks: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn runtime_group(&self, group_id: &GroupId) -> Option<Arc<RuntimeGroup>> {
        self.groups.load().get(group_id).cloned()
    }

    fn runtime_groups(&self) -> Vec<Arc<RuntimeGroup>> {
        self.groups.load().values().cloned().collect()
    }

    fn publish_runtime_group(&self, group_id: GroupId, runtime: Arc<RuntimeGroup>) {
        let mut next = (*self.groups.load_full()).clone();
        next.insert(group_id, runtime);
        self.groups.store(Arc::new(next));
    }

    fn remove_runtime_group(&self, group_id: &GroupId) {
        let mut next = (*self.groups.load_full()).clone();
        next.remove(group_id);
        self.groups.store(Arc::new(next));
    }

    /// Ensure one active Group has a process-local owner actor. The durable
    /// owner generation remains authoritative and concurrent installers are
    /// serialized so one Group cannot claim two generations in this process.
    pub(crate) async fn ensure_group_projection(&self, group_uuid: Uuid) -> Result<bool, DispatchError> {
        let _registry_guard = self.group_registry_lock.lock().await;
        let row = sqlx::query(ACTIVE_GROUP_RUNTIME_SQL)
            .bind(Some(group_uuid))
            .fetch_optional(&self.storage.pool())
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        let Some(row) = row else {
            return Ok(false);
        };
        self.install_runtime_group(&row).await
    }

    async fn install_runtime_group(&self, row: &sqlx::postgres::PgRow) -> Result<bool, DispatchError> {
        let group_uuid: Uuid = row.try_get("id").map_err(|_| DispatchError::Unavailable)?;
        let group_id = GroupId::new(group_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        if self.runtime_group(&group_id).is_some() {
            return Ok(true);
        }
        let catalog = self.engines.snapshot();
        let now = self.clock.now().monotonic;
        let credentials = load_scheduler_credentials(&self.storage, group_uuid, &catalog, now)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        let claim = match self.storage.claim_group_owner(group_uuid, &self.executor_id).await {
            Ok(claim) => claim,
            Err(gateway_storage::StorageError::RevisionConflict) => return Ok(false),
            Err(_) => return Err(DispatchError::Unavailable),
        };
        let generation =
            OwnerGeneration::new(u64::try_from(claim.owner_generation).map_err(|_| DispatchError::Unavailable)?)
                .map_err(|_| DispatchError::Unavailable)?;
        let request_limits = runtime_request_limits(row).map_err(|_| DispatchError::Unavailable)?;
        let group_config =
            runtime_group_config(row, group_uuid, request_limits).map_err(|_| DispatchError::Unavailable)?;
        let identity = ExecutorIdentity {
            group_id: group_id.clone(),
            owner_partition: "single_process".into(),
            executor_id: self.executor_id.clone(),
            generation,
        };
        let engine = SchedulerEngine::new(identity, group_config, credentials, now)
            .map_err(|_| DispatchError::DeterministicUnavailable)?;
        let Ok(handle) = self.scheduler_supervisor.register(group_id.clone(), engine) else {
            let _ = self
                .storage
                .release_group_owner(group_uuid, &self.executor_id, claim.owner_generation)
                .await;
            return Err(DispatchError::Unavailable);
        };
        let runtime = Arc::new(RuntimeGroup::new(
            self.executor_id.clone(),
            generation,
            handle,
            self.clock.clone(),
            self.storage.clone(),
            group_uuid,
            request_limits,
        ));
        runtime.spawn_ticks();
        self.publish_runtime_group(group_id, runtime);
        Ok(true)
    }

    /// Reconcile the complete active Group registry. New Groups are installed
    /// without restart; disabled or archived Groups are drained, release their
    /// exact durable owner generation, and can later be re-registered.
    pub(crate) async fn reconcile_group_registry(&self) -> Result<(), DispatchError> {
        let _registry_guard = self.group_registry_lock.lock().await;
        let rows = sqlx::query(ACTIVE_GROUP_RUNTIME_SQL)
            .bind(Option::<Uuid>::None)
            .fetch_all(&self.storage.pool())
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        let mut active = BTreeSet::new();
        for row in &rows {
            let group_uuid: Uuid = row.try_get("id").map_err(|_| DispatchError::Unavailable)?;
            active.insert(GroupId::new(group_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?);
            self.install_runtime_group(row).await?;
        }
        for runtime in self.runtime_groups() {
            let group_id =
                GroupId::new(runtime.group_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
            if !active.contains(&group_id) {
                runtime.shutdown_owner().await;
                let _ = self.scheduler_supervisor.unregister(&group_id);
                self.remove_runtime_group(&group_id);
            }
        }
        Ok(())
    }

    /// Fence new admissions while keeping owner heartbeats and existing
    /// response deliveries alive through the configured drain window.
    pub(crate) async fn begin_drain(&self) {
        for group in self.runtime_groups() {
            group.begin_drain().await;
        }
    }

    pub(crate) async fn group_capacity_projection(
        &self,
        group_uuid: Uuid,
    ) -> Result<Option<serde_json::Value>, DispatchError> {
        let group_id = GroupId::new(group_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        let Some(group) = self.runtime_group(&group_id) else {
            return Ok(None);
        };
        let snapshot = group.handle.snapshot().await.map_err(|_| DispatchError::Unavailable)?;
        let lifecycle = match snapshot.lifecycle {
            gateway_scheduler::RuntimeLifecycle::Loading => "loading",
            gateway_scheduler::RuntimeLifecycle::Serving => "serving",
            gateway_scheduler::RuntimeLifecycle::Draining => "draining",
            gateway_scheduler::RuntimeLifecycle::OwnerUnavailable => "owner_unavailable",
        };
        let credentials = snapshot
            .credential_inflight
            .iter()
            .map(|(credential_id, inflight)| json!({"credential_id":credential_id.as_str(),"inflight":inflight}))
            .collect::<Vec<_>>();
        Ok(Some(json!({
            "id":group_uuid,"group_id":group_uuid,"owner_generation":snapshot.generation.get(),
            "owner_valid":group.owner_valid.load(Ordering::Acquire),"lifecycle":lifecycle,
            "group_config_version":snapshot.group_config_version.0.as_ref(),
            "configured_concurrency":snapshot.configured_concurrency,
            "effective_concurrency":snapshot.effective_concurrency,
            "total_credential_capacity":snapshot.total_credential_capacity,
            "active_group_permits":snapshot.active_group_permits,"active_leases":snapshot.active_leases,
            "queue":{"used":snapshot.queued_tickets,"capacity":snapshot.queue_capacity},
            "active_session_claims":snapshot.session_claims,"credential_inflight":credentials,
            "resource_balance":snapshot.resource_balance,"revision":snapshot.generation.get()
        })))
    }

    pub(crate) async fn clear_credential_cooldown_projection(
        &self,
        group_uuid: Uuid,
        credential_uuid: Uuid,
    ) -> Result<bool, DispatchError> {
        let group_id = GroupId::new(group_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        let Some(group) = self.runtime_group(&group_id) else {
            return Ok(false);
        };
        let credential_id =
            CredentialId::new(credential_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        group
            .observe_credential_cooldown(CredentialCooldownUpdate {
                credential_id,
                cooldown_until: None,
            })
            .await?;
        Ok(true)
    }

    pub(crate) async fn refresh_credential_for_admin(
        &self,
        credential_uuid: Uuid,
        expected_token_version: u64,
    ) -> Result<(u64, bool), CredentialServiceError> {
        let row = sqlx::query(
            "SELECT group_id,token_version,lifecycle_state_code,auth_kind_code \
             FROM gateway.anthropic_credential WHERE id=$1",
        )
        .bind(credential_uuid)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| CredentialServiceError::Transient)?
        .ok_or(CredentialServiceError::InvalidAuthentication)?;
        let group_uuid: Uuid = row.try_get("group_id").map_err(|_| CredentialServiceError::Transient)?;
        let current_token_version = u64::try_from(
            row.try_get::<i64, _>("token_version")
                .map_err(|_| CredentialServiceError::Transient)?,
        )
        .map_err(|_| CredentialServiceError::Transient)?;
        let lifecycle: String = row
            .try_get("lifecycle_state_code")
            .map_err(|_| CredentialServiceError::Transient)?;
        let auth_kind: String = row
            .try_get("auth_kind_code")
            .map_err(|_| CredentialServiceError::Transient)?;
        if lifecycle != "active"
            || !matches!(auth_kind.as_str(), "oauth_subscription" | "setup_token_subscription")
            || current_token_version < expected_token_version
        {
            return Err(CredentialServiceError::InvalidAuthentication);
        }
        let credential_id = CredentialId::new(credential_uuid.to_string())
            .map_err(|_| CredentialServiceError::InvalidAuthentication)?;
        let token_version = if current_token_version == expected_token_version {
            let maintainer = self
                .credential_maintainer
                .as_ref()
                .ok_or(CredentialServiceError::EvidencePending)?;
            Arc::clone(maintainer)
                .maintain(credential_id.clone(), MaintenanceTrigger::Admin)
                .await?
                .commit
                .token_version
        } else {
            current_token_version
        };
        let group_id = GroupId::new(group_uuid.to_string()).map_err(|_| CredentialServiceError::Transient)?;
        let Some(group) = self.runtime_group(&group_id) else {
            return Ok((token_version, false));
        };
        group
            .observe_credential_auth(CredentialAuthUpdate {
                credential_id,
                token_version,
                auth_healthy: true,
            })
            .await
            .map_err(|_| CredentialServiceError::Transient)?;
        Ok((token_version, true))
    }

    pub(crate) async fn fence_credential_for_admin(
        &self,
        group_uuid: Uuid,
        credential_uuid: Uuid,
    ) -> Result<Option<u32>, DispatchError> {
        let group_id = GroupId::new(group_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        let Some(group) = self.runtime_group(&group_id) else {
            return Ok(None);
        };
        let credential_id =
            CredentialId::new(credential_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        group.set_credential_fence(credential_id, true).await.map(Some)
    }

    pub(crate) async fn unfence_credential_for_admin(
        &self,
        group_uuid: Uuid,
        credential_uuid: Uuid,
    ) -> Result<bool, DispatchError> {
        let group_id = GroupId::new(group_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        let Some(group) = self.runtime_group(&group_id) else {
            return Ok(false);
        };
        let credential_id =
            CredentialId::new(credential_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        group.set_credential_fence(credential_id, false).await?;
        Ok(true)
    }

    async fn project_transport_health(
        &self,
        lease: &CredentialLease,
        proxy_endpoint_id: Option<&ProxyEndpointId>,
        error: &TransportError,
    ) -> Result<(), DispatchError> {
        if matches!(error.health_effect, HealthEffect::None | HealthEffect::SuccessfulProbe) {
            return Ok(());
        }
        let credential_id = parse_uuid(lease.credential_id.as_str())?;
        let bundle_id = parse_uuid(lease.bundle_id.as_str())?;
        let archetype_version_id = parse_uuid(lease.archetype_version_id.as_str())?;
        let proxy_id = proxy_endpoint_id.map(|id| parse_uuid(id.as_str())).transpose()?;
        let diagnostic_code = transport_error_code(error.code);
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| DispatchError::Unavailable)?;

        let (targets, blocker_code, aggregate_type, aggregate_id, aggregate_revision, action) = match error
            .health_effect
        {
            HealthEffect::QuarantineBundle => {
                let revision: Option<i64> = sqlx::query_scalar(
                    "UPDATE catalog.transport_bundle SET lifecycle_code='quarantined',runtime_state_code='quarantined' \
                         WHERE id=$1 AND runtime_state_code<>'quarantined' RETURNING artifact_version",
                )
                .bind(bundle_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| DispatchError::Unavailable)?;
                let Some(revision) = revision else {
                    transaction.rollback().await.map_err(|_| DispatchError::Unavailable)?;
                    return Ok(());
                };
                sqlx::query(
                        "INSERT INTO catalog.bundle_runtime_incident \
                         (id,transport_bundle_id,archetype_version_id,severity_code,state_code,reason_code,detail,opened_at) \
                         SELECT $1,$2,$3,'critical','open',$4,$5,clock_timestamp() \
                         WHERE NOT EXISTS(SELECT 1 FROM catalog.bundle_runtime_incident \
                           WHERE transport_bundle_id=$2 AND state_code='open')",
                    )
                    .bind(Uuid::now_v7())
                    .bind(bundle_id)
                    .bind(archetype_version_id)
                    .bind(diagnostic_code)
                    .bind(json!({"phase":format!("{:?}",error.phase),"failure_scope":format!("{:?}",error.failure_scope)}))
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| DispatchError::Unavailable)?;
                let targets = sqlx::query_as::<_, (Uuid, Uuid)>(
                    "SELECT credential.id,credential.group_id FROM gateway.anthropic_credential credential \
                         JOIN gateway.credential_profile profile ON profile.credential_id=credential.id \
                           AND profile.lifecycle_code='active' \
                         WHERE profile.archetype_version_id=$1 AND credential.lifecycle_state_code='active' \
                         ORDER BY credential.id FOR UPDATE OF credential",
                )
                .bind(archetype_version_id)
                .fetch_all(&mut *transaction)
                .await
                .map_err(|_| DispatchError::Unavailable)?;
                (
                    targets,
                    "bundle_unavailable",
                    "transport_bundle",
                    bundle_id,
                    revision,
                    "transport_bundle_quarantined",
                )
            }
            HealthEffect::QuarantineEgress | HealthEffect::TransientFailure if proxy_id.is_some() => {
                let proxy_id = proxy_id.ok_or(DispatchError::DeterministicUnavailable)?;
                let row = sqlx::query(
                        "SELECT consecutive_failures, \
                                COALESCE(failure_window_started_at>=clock_timestamp()-interval '60 seconds',false) AS window_fresh \
                         FROM gateway.proxy_endpoint WHERE id=$1 AND lifecycle_code='active' FOR UPDATE",
                    )
                    .bind(proxy_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(|_| DispatchError::Unavailable)?
                    .ok_or(DispatchError::DeterministicUnavailable)?;
                let current = row
                    .try_get::<i32, _>("consecutive_failures")
                    .map_err(|_| DispatchError::Unavailable)?;
                let window_fresh = row
                    .try_get::<bool, _>("window_fresh")
                    .map_err(|_| DispatchError::Unavailable)?;
                let failures = if window_fresh { current.saturating_add(1) } else { 1 };
                let quarantine = error.health_effect == HealthEffect::QuarantineEgress || failures >= 3;
                let health = if quarantine {
                    match error.code {
                        TransportErrorCode::ProxyAuthentication => "auth_failed",
                        TransportErrorCode::TlsCertificate => "tls_intercepted",
                        _ => "unhealthy",
                    }
                } else {
                    "unknown"
                };
                let revision: i64 = sqlx::query_scalar(
                        "UPDATE gateway.proxy_endpoint SET consecutive_failures=$2,consecutive_successes=0, \
                           failure_window_started_at=CASE WHEN $3 THEN failure_window_started_at ELSE clock_timestamp() END, \
                           health_code=CASE WHEN $4 THEN $5 ELSE health_code END, \
                           circuit_open_until=CASE WHEN $4 THEN clock_timestamp()+interval '60 seconds' ELSE circuit_open_until END, \
                           last_error_code=$6,last_probed_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp() \
                         WHERE id=$1 RETURNING revision",
                    )
                    .bind(proxy_id)
                    .bind(failures)
                    .bind(window_fresh)
                    .bind(quarantine)
                    .bind(health)
                    .bind(diagnostic_code)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(|_| DispatchError::Unavailable)?;
                if !quarantine {
                    transaction.commit().await.map_err(|_| DispatchError::Unavailable)?;
                    return Ok(());
                }
                let targets = sqlx::query_as::<_, (Uuid, Uuid)>(
                        "SELECT credential.id,credential.group_id FROM gateway.anthropic_credential credential \
                         JOIN gateway.credential_egress_binding binding ON binding.credential_id=credential.id \
                         WHERE binding.proxy_id=$1 AND binding.lifecycle_code='active' \
                           AND credential.lifecycle_state_code='active' ORDER BY credential.id FOR UPDATE OF credential",
                    )
                    .bind(proxy_id)
                    .fetch_all(&mut *transaction)
                    .await
                    .map_err(|_| DispatchError::Unavailable)?;
                (
                    targets,
                    "proxy_unhealthy",
                    "proxy_endpoint",
                    proxy_id,
                    revision,
                    "transport_egress_quarantined",
                )
            }
            HealthEffect::QuarantineEgress => {
                let targets = sqlx::query_as::<_, (Uuid, Uuid)>(
                    "SELECT id,group_id FROM gateway.anthropic_credential \
                         WHERE id=$1 AND lifecycle_state_code='active' FOR UPDATE",
                )
                .bind(credential_id)
                .fetch_all(&mut *transaction)
                .await
                .map_err(|_| DispatchError::Unavailable)?;
                (
                    targets,
                    "transport_unavailable",
                    "credential",
                    credential_id,
                    1,
                    "transport_egress_quarantined",
                )
            }
            HealthEffect::TransientFailure | HealthEffect::None | HealthEffect::SuccessfulProbe => {
                transaction.rollback().await.map_err(|_| DispatchError::Unavailable)?;
                return Ok(());
            }
        };

        let mut effective_revision = aggregate_revision;
        for (affected_credential_id, _) in &targets {
            let revision: i64 = sqlx::query_scalar(
                "UPDATE gateway.anthropic_credential SET transport_state_code='transport_unavailable', \
                   scheduling_state_code='transport_unavailable',revision=revision+1,updated_at=clock_timestamp() \
                 WHERE id=$1 RETURNING revision",
            )
            .bind(affected_credential_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
            if *affected_credential_id == aggregate_id {
                effective_revision = revision;
            }
            sqlx::query(
                "INSERT INTO gateway.credential_transport_blocker \
                 (id,credential_id,blocker_code,state_code,detail,observed_at) \
                 VALUES ($1,$2,$3,'active',$4,clock_timestamp()) \
                 ON CONFLICT (credential_id,blocker_code) WHERE state_code='active' \
                 DO UPDATE SET detail=EXCLUDED.detail,observed_at=EXCLUDED.observed_at",
            )
            .bind(Uuid::now_v7())
            .bind(affected_credential_id)
            .bind(blocker_code)
            .bind(json!({"diagnostic_code":diagnostic_code,"bundle_id":bundle_id,"proxy_id":proxy_id}))
            .execute(&mut *transaction)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        }
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &AuditOutboxRecord {
                    actor_type: "system".to_owned(),
                    actor_id: None,
                    action: action.to_owned(),
                    object_type: aggregate_type.to_owned(),
                    object_id: Some(aggregate_id.to_string()),
                    outcome: "success".to_owned(),
                    redacted_detail: json!({
                        "diagnostic_code":diagnostic_code,"affected_credentials":targets.len(),
                        "bundle_id":bundle_id,"proxy_id":proxy_id
                    }),
                    topic: "transport.health.quarantined".to_owned(),
                    aggregate_id,
                    aggregate_revision: effective_revision,
                    payload: json!({
                        "diagnostic_code":diagnostic_code,"affected_credentials":targets.len(),
                        "bundle_id":bundle_id,"proxy_id":proxy_id
                    }),
                },
            )
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        transaction.commit().await.map_err(|_| DispatchError::Unavailable)?;
        for (affected_credential_id, affected_group_id) in targets {
            let _ = self
                .fence_credential_for_admin(affected_group_id, affected_credential_id)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn remove_archived_credential_projection(
        &self,
        group_uuid: Uuid,
        credential_uuid: Uuid,
    ) -> Result<bool, DispatchError> {
        let group_id = GroupId::new(group_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        let Some(group) = self.runtime_group(&group_id) else {
            return Ok(false);
        };
        let credential_id =
            CredentialId::new(credential_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        group.remove_fenced_credential(credential_id).await?;
        Ok(true)
    }

    pub(crate) async fn reconfigure_group_projection(&self, group_uuid: Uuid) -> Result<bool, DispatchError> {
        let group_id = GroupId::new(group_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        let Some(group) = self.runtime_group(&group_id) else {
            return Ok(false);
        };
        let row = sqlx::query(
            "SELECT gc.config_version,gc.default_rpm,gc.default_rpm_burst,gc.max_concurrency,gc.queue_capacity, \
                    gc.pre_upstream_wait_ms,gc.preferred_capacity_wait_ms,gc.affinity_ttl_ms, \
                    gc.affinity_migration_successes,gc.quota_guard_basis_points,gc.upstream_connect_ms, \
                    gc.upstream_non_stream_total_ms,gc.upstream_stream_idle_ms,gc.min_retry_budget_ms, \
                    gc.cancel_grace_ms,gc.queue_full_retry_after_ms,gc.queue_wait_retry_after_ms \
             FROM gateway.credential_group g JOIN gateway.group_active_config active ON active.group_id=g.id \
             JOIN gateway.group_config gc ON gc.id=active.config_id WHERE g.id=$1 AND g.status_code='active'",
        )
        .bind(group_uuid)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| DispatchError::Unavailable)?
        .ok_or(DispatchError::DeterministicUnavailable)?;
        let limits = RuntimeRequestLimits {
            pre_upstream_wait: millis(&row, "pre_upstream_wait_ms").map_err(|_| DispatchError::Unavailable)?,
            upstream_connect: millis(&row, "upstream_connect_ms").map_err(|_| DispatchError::Unavailable)?,
            upstream_non_stream_total: millis(&row, "upstream_non_stream_total_ms")
                .map_err(|_| DispatchError::Unavailable)?,
            upstream_stream_idle: millis(&row, "upstream_stream_idle_ms").map_err(|_| DispatchError::Unavailable)?,
            min_retry_budget: millis(&row, "min_retry_budget_ms").map_err(|_| DispatchError::Unavailable)?,
            cancel_grace: millis(&row, "cancel_grace_ms").map_err(|_| DispatchError::Unavailable)?,
            queue_full_retry_after: millis(&row, "queue_full_retry_after_ms")
                .map_err(|_| DispatchError::Unavailable)?,
            queue_wait_retry_after: millis(&row, "queue_wait_retry_after_ms")
                .map_err(|_| DispatchError::Unavailable)?,
        };
        let config = GroupConfig {
            snapshot_version: gateway_domain::SnapshotVersion::new(format!(
                "group:{group_uuid}:config:{}",
                row.try_get::<i64, _>("config_version")
                    .map_err(|_| DispatchError::Unavailable)?
            )),
            concurrency_limit: optional_u32(&row, "max_concurrency").map_err(|_| DispatchError::Unavailable)?,
            rate_limit: match (
                optional_u32(&row, "default_rpm").map_err(|_| DispatchError::Unavailable)?,
                optional_u32(&row, "default_rpm_burst").map_err(|_| DispatchError::Unavailable)?,
            ) {
                (Some(requests_per_minute), Some(burst)) => Some(BucketConfig {
                    requests_per_minute,
                    burst,
                }),
                (None, None) => None,
                _ => return Err(DispatchError::DeterministicUnavailable),
            },
            queue_capacity: optional_usize(&row, "queue_capacity").map_err(|_| DispatchError::Unavailable)?,
            pre_upstream_wait: limits.pre_upstream_wait,
            preferred_capacity_wait: millis(&row, "preferred_capacity_wait_ms")
                .map_err(|_| DispatchError::Unavailable)?,
            cancel_grace: limits.cancel_grace,
            affinity_ttl: millis(&row, "affinity_ttl_ms").map_err(|_| DispatchError::Unavailable)?,
            affinity_migration_successes: u32::try_from(
                row.try_get::<i32, _>("affinity_migration_successes")
                    .map_err(|_| DispatchError::Unavailable)?,
            )
            .map_err(|_| DispatchError::Unavailable)?,
            quota_guard_basis_points: u16::try_from(
                row.try_get::<i32, _>("quota_guard_basis_points")
                    .map_err(|_| DispatchError::Unavailable)?,
            )
            .map_err(|_| DispatchError::Unavailable)?,
        };
        if group
            .handle
            .snapshot()
            .await
            .map_err(|_| DispatchError::Unavailable)?
            .group_config_version
            == config.snapshot_version
        {
            return Ok(true);
        }
        group.reconfigure(config, limits).await?;
        Ok(true)
    }

    pub(crate) async fn reconfigure_credential_projection(
        &self,
        group_uuid: Uuid,
        credential_uuid: Uuid,
    ) -> Result<bool, DispatchError> {
        let group_id = GroupId::new(group_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        let credential_id =
            CredentialId::new(credential_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        let Some(group) = self.runtime_group(&group_id) else {
            return Ok(false);
        };
        let catalog = self.engines.snapshot();
        let credentials = load_scheduler_credentials(&self.storage, group_uuid, &catalog, group.clock.now().monotonic)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        let Some(config) = credentials.into_iter().find(|candidate| candidate.id == credential_id) else {
            return Ok(false);
        };
        group.reconfigure_credential(config).await?;
        Ok(true)
    }

    pub(crate) fn advance_credential_profile_epoch(
        &self,
        credential_uuid: Uuid,
        minimum_profile_epoch: u64,
    ) -> Result<usize, DispatchError> {
        let credential_id =
            CredentialId::new(credential_uuid.to_string()).map_err(|_| DispatchError::DeterministicUnavailable)?;
        Ok(self
            .transport
            .advance_credential_profile_epoch(&credential_id, minimum_profile_epoch))
    }

    pub(crate) fn drain_transport_generation(&self, generation: gateway_transport::ActivationGeneration) -> usize {
        self.transport.drain_generation(generation)
    }

    pub(crate) fn spawn_group_config_reconciliation(
        self: &Arc<Self>,
        cancellation: &CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let dispatcher = self.clone();
        let cancellation = cancellation.child_token();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    () = cancellation.cancelled() => return,
                    _ = interval.tick() => {
                        if let Err(error) = dispatcher.reconcile_group_registry().await {
                            tracing::warn!(event="group_registry_reconcile_failed", error=?error);
                        }
                        for group in dispatcher.runtime_groups() {
                            if let Err(error) = dispatcher.reconfigure_group_projection(group.group_uuid).await {
                                tracing::warn!(event="group_config_projection_reconcile_failed", group_id=%group.group_uuid, error=?error);
                            }
                            let catalog = dispatcher.engines.snapshot();
                            match load_scheduler_credentials(
                                &dispatcher.storage,
                                group.group_uuid,
                                &catalog,
                                group.clock.now().monotonic,
                            )
                            .await
                            {
                                Ok(credentials) => {
                                    for config in credentials {
                                        if let Err(error) = group.reconfigure_credential(config).await {
                                            tracing::warn!(event="credential_config_projection_reconcile_failed", group_id=%group.group_uuid, error=?error);
                                        }
                                    }
                                }
                                Err(error) => tracing::warn!(event="credential_config_projection_load_failed", group_id=%group.group_uuid, error=%error),
                            }
                        }
                    }
                }
            }
        })
    }

    pub(crate) fn spawn_scheduled_credential_maintenance(
        self: &Arc<Self>,
        cancellation: &CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let dispatcher = self.clone();
        let cancellation = cancellation.child_token();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = cancellation.cancelled() => return,
                    _ = interval.tick() => {
                        if let Err(error) = dispatcher.maintain_due_credentials().await {
                            tracing::warn!(event="scheduled_credential_maintenance_failed", error=%error);
                        }
                    }
                }
            }
        })
    }

    /// Force-close active upstream relays after the graceful drain deadline.
    pub(crate) fn force_cancel_requests(&self) {
        self.request_cancellation.cancel();
    }

    /// Release exact owner generations after all HTTP servers have drained.
    pub(crate) async fn shutdown_owners(&self) {
        self.await_response_audits().await;
        for group in self.runtime_groups() {
            group.shutdown_owner().await;
        }
    }

    async fn await_response_audits(&self) {
        let mut tasks = std::mem::take(&mut *self.audit_tasks.lock().await);
        for task in &mut tasks {
            if tokio::time::timeout(Duration::from_secs(30), &mut task.handle)
                .await
                .is_err()
            {
                task.handle.abort();
                if let Some(latch) = &task.latch {
                    record_response_audit_gap(&self.storage, task.request_id, latch).await;
                }
            }
        }
    }

    async fn maintain_due_credentials(&self) -> anyhow::Result<usize> {
        let Some(maintainer) = self.credential_maintainer.as_ref() else {
            return Ok(0);
        };
        let rows = sqlx::query(
            "SELECT c.id,c.group_id,c.token_version FROM gateway.anthropic_credential c \
             JOIN gateway.credential_auth_version av ON av.id=c.active_auth_version_id AND av.credential_id=c.id \
             WHERE c.lifecycle_state_code='active' AND c.auth_state_code IN ('healthy','expiring') \
               AND c.scheduling_state_code IN ('eligible','cooldown') \
               AND c.auth_kind_code IN ('oauth_subscription','setup_token_subscription') \
               AND av.refresh_secret_id IS NOT NULL AND av.expires_at IS NOT NULL \
               AND clock_timestamp() >= av.expires_at - LEAST( \
                 av.expires_at-av.issued_at, \
                 LEAST(interval '4 hours',GREATEST(interval '5 minutes',(av.expires_at-av.issued_at)*0.1)) \
               ) + (((hashtextextended(c.id::text,0) & 2147483647) % 31) * interval '1 second') \
             ORDER BY av.expires_at,c.id LIMIT 32",
        )
        .fetch_all(&self.storage.pool())
        .await?;
        let mut tasks = tokio::task::JoinSet::new();
        for row in rows {
            let credential_uuid: Uuid = row.try_get("id")?;
            let group_uuid: Uuid = row.try_get("group_id")?;
            let token_version = u64::try_from(row.try_get::<i64, _>("token_version")?)?;
            let credential_id = CredentialId::new(credential_uuid.to_string())?;
            let group_id = GroupId::new(group_uuid.to_string())?;
            let Some(group) = self.runtime_group(&group_id) else {
                continue;
            };
            let maintainer = maintainer.clone();
            tasks.spawn(async move {
                let result = maintainer
                    .maintain(credential_id.clone(), MaintenanceTrigger::Scheduled)
                    .await;
                match result {
                    Ok(outcome) => group
                        .observe_credential_auth(CredentialAuthUpdate {
                            credential_id,
                            token_version: outcome.commit.token_version,
                            auth_healthy: true,
                        })
                        .await
                        .is_ok(),
                    Err(error) => {
                        if matches!(
                            error,
                            CredentialServiceError::InvalidAuthentication
                                | CredentialServiceError::AccountMismatch
                                | CredentialServiceError::ManualRecoveryRequired(_)
                        ) {
                            let _ = group
                                .observe_credential_auth(CredentialAuthUpdate {
                                    credential_id,
                                    token_version,
                                    auth_healthy: false,
                                })
                                .await;
                        }
                        false
                    }
                }
            });
        }
        let mut maintained = 0_usize;
        while let Some(result) = tasks.join_next().await {
            if result? {
                maintained = maintained.saturating_add(1);
            }
        }
        Ok(maintained)
    }
}

#[async_trait]
impl MessageDispatcher for ProductionDispatcher {
    async fn dispatch(&self, request: DispatchRequest) -> Result<UpstreamResponse, DispatchError> {
        let group = self
            .runtime_group(&request.group_id)
            .ok_or(DispatchError::DeterministicUnavailable)?;
        let request_limits = *group.request_limits.read().await;
        let request_uuid = request_uuid(&request)?;
        let model_id = self
            .storage
            .resolve_model_id(&request.generic.model_id)
            .await
            .map_err(|_| DispatchError::Unavailable)?
            .ok_or(DispatchError::DeterministicUnavailable)?;
        self.storage
            .create_request_after_auth(&RequestCreate {
                request_id: request_uuid,
                platform_key_id: parse_uuid(request.platform_key_id.as_str())?,
                group_id: parse_uuid(request.group_id.as_str())?,
                owner_executor_id: group.executor_id.clone(),
                owner_generation: i64::try_from(group.generation.get()).map_err(|_| DispatchError::Unavailable)?,
                endpoint_code: "messages".into(),
                client_class_code: match request.client_class {
                    gateway_domain::ClientClass::ClaudeCodeCli => "claude_code_cli".into(),
                    gateway_domain::ClientClass::NonClaudeCodeCli => "non_claude_code_cli".into(),
                },
                model_id: Some(model_id),
                request_body_bytes: i64::try_from(request.original_body.len())
                    .map_err(|_| DispatchError::Unavailable)?,
                response_mode: if request.generic.stream {
                    gateway_domain::ResponseMode::Streaming
                } else {
                    gateway_domain::ResponseMode::NonStreaming
                },
            })
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        let mut request_guard = RequestTerminalGuard::new(self.storage.clone(), request_uuid);

        let mut content_latch = None;
        if let ContentAuditMode::FullEncrypted { retention_days } = request.content_audit {
            let store = self
                .content_audit
                .as_ref()
                .ok_or(DispatchError::AuditUnavailable { retry_after_seconds: 5 })?;
            let mut latch = ContentAuditLatch::default();
            capture_content(
                &self.storage,
                store,
                request_uuid,
                parse_uuid(request.owner_user_id.as_str())?,
                AuditCaptureKind::OriginalRequest,
                &request.original_body,
                request.generic.snapshot_set.access_policy.0.as_ref(),
                retention_days,
            )
            .await?;
            latch
                .original_durable()
                .map_err(|_| DispatchError::AuditUnavailable { retry_after_seconds: 5 })?;
            content_latch = Some((Arc::new(Mutex::new(latch)), retention_days));
        }

        let cancellation = self.request_cancellation.child_token();
        let pre_upstream_deadline = request.accepted_at.saturating_add(request_limits.pre_upstream_wait);
        let response_reservation = if request.generic.stream {
            None
        } else {
            let remaining = pre_upstream_deadline.saturating_sub(self.clock.now().monotonic);
            Some(
                match self.response.reserve_non_stream_for(&cancellation, remaining).await {
                    Ok(reservation) => reservation,
                    Err(ResponseError::ReservationQueueFull) => {
                        return Err(DispatchError::QueueFull {
                            retry_after_seconds: retry_after_seconds(request_limits.queue_full_retry_after),
                        });
                    }
                    Err(ResponseError::ReservationTimeout) => {
                        return Err(DispatchError::PreUpstreamTimeout {
                            retry_after_seconds: retry_after_seconds(request_limits.queue_wait_retry_after),
                        });
                    }
                    Err(ResponseError::Cancelled) => return Err(DispatchError::Cancelled),
                    Err(_) => return Err(DispatchError::Unavailable),
                },
            )
        };
        let entry = ScheduleEntry {
            request_id: request.request_id.clone(),
            owner_user_id: request.owner_user_id.clone(),
            platform_key_id: request.platform_key_id.clone(),
            group_id: request.group_id.clone(),
            base_session_id: request.base_session_id.clone(),
            agent_id: request.agent_id.clone(),
            generic: request.generic.clone(),
            accepted_at: request.accepted_at,
            pre_upstream_deadline,
        };
        let decision = group.admit(entry.clone()).await?;
        let (mut lease, current_phase) = match decision {
            RuntimeAdmission::Granted(lease) => (lease, "accepted"),
            RuntimeAdmission::Queued { receiver, mut guard } => {
                self.storage
                    .advance_request_phase(request_uuid, "accepted", "queued")
                    .await
                    .map_err(|_| DispatchError::Unavailable)?;
                (
                    group
                        .wait_for_resolution(
                            &request.request_id,
                            pre_upstream_deadline,
                            receiver,
                            &mut guard,
                            request_limits,
                        )
                        .await?,
                    "queued",
                )
            }
            RuntimeAdmission::Rejected(rejection) => {
                return Err(map_rejection(&rejection, request_limits));
            }
        };
        let mut lease_guard = LeaseGuard::new(group.clone(), lease.clone());
        self.storage
            .advance_request_phase(request_uuid, current_phase, "submitting")
            .await
            .map_err(|_| DispatchError::Unavailable)?;

        if let Some((latch, retention_days)) = content_latch.as_mut() {
            let store = self
                .content_audit
                .as_ref()
                .ok_or(DispatchError::AuditUnavailable { retry_after_seconds: 5 })?;
            capture_content(
                &self.storage,
                store,
                request_uuid,
                parse_uuid(request.owner_user_id.as_str())?,
                AuditCaptureKind::FinalRequest,
                request.generic.replay_body.bytes(),
                request.generic.snapshot_set.access_policy.0.as_ref(),
                *retention_days,
            )
            .await?;
            let mut latch = latch.lock().await;
            latch
                .first_final_durable()
                .map_err(|_| DispatchError::AuditUnavailable { retry_after_seconds: 5 })?;
            latch
                .start_upstream()
                .map_err(|_| DispatchError::AuditUnavailable { retry_after_seconds: 5 })?;
        }

        let mut connection_budget = ConnectionAttemptBudget::default();
        let mut messages_attempts = 0_u8;
        let mut refresh_attempted = false;
        let mut next_attempt_reason = "initial";
        let mut upstream_total_deadline: Option<Instant> = None;
        let (raw, attempt_telemetry, transport_terminal) = loop {
            if !connection_budget.begin() {
                return Err(DispatchError::Unavailable);
            }
            let remaining_upstream =
                upstream_total_deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
            if !request.generic.stream
                && remaining_upstream.is_some_and(|remaining| remaining < request_limits.min_retry_budget)
            {
                return Err(DispatchError::DeadlineExceeded);
            }
            let attempt_upstream_total = remaining_upstream.unwrap_or(request_limits.upstream_non_stream_total);
            let attempt_connect = remaining_upstream.map_or(request_limits.upstream_connect, |remaining| {
                request_limits.upstream_connect.min(remaining)
            });
            let connection_ordinal = connection_budget.attempts();
            let messages_ordinal = messages_attempts.saturating_add(1);
            let selected = load_selected_credential(&self.storage, &lease).await?;
            let catalog = self.engines.snapshot();
            let engine = catalog
                .find_exact(
                    lease.archetype_version_id.as_str(),
                    lease.bundle_id.as_str(),
                    lease.bundle_version,
                    lease.bundle_hash.as_str(),
                )
                .ok_or(DispatchError::DeterministicUnavailable)?;
            let derived_session = derive_session_id(
                &selected.session_hmac,
                request.base_session_id.as_str(),
                request.agent_id.as_str(),
            )?;
            let final_request = Arc::new(build_final_request(&request, &selected, &engine, &derived_session)?);
            let health_proxy_endpoint_id = selected.proxy_endpoint_id.clone();
            let reason = next_attempt_reason;
            let attempt_telemetry = create_attempt_telemetry(
                &self.storage,
                request_uuid,
                &request,
                &lease,
                &selected,
                &engine,
                catalog.generation().get(),
                connection_ordinal,
                messages_ordinal,
                reason,
            )
            .await?;
            let attempt_plan_id = AttemptPlanId::new(format!("plan_{}", Uuid::now_v7().simple()))
                .map_err(|_| DispatchError::Unavailable)?;
            let connection_attempt_id =
                ConnectionAttemptId::new(format!("conn_{}", attempt_telemetry.connection_attempt_id.simple()))
                    .map_err(|_| DispatchError::Unavailable)?;
            let attempt_cancellation = cancellation.child_token();
            let attempt = TransportAttempt {
                connection_attempt_id,
                ordinal: connection_ordinal,
                snapshot: TransportAttemptSnapshot {
                    request_id: request.request_id.clone(),
                    attempt_plan_id,
                    identity: AttemptIdentitySnapshot {
                        credential_id: lease.credential_id.clone(),
                        token_version: lease.token_version,
                        profile_id: lease.profile_id.clone(),
                        profile_epoch: lease.profile_epoch,
                        device_identity_id: lease.device_identity_id.clone(),
                        device_epoch: lease.device_epoch,
                        archetype_version_id: lease.archetype_version_id.clone(),
                        bundle_id: lease.bundle_id.clone(),
                        bundle_version: lease.bundle_version,
                        bundle_hash: lease.bundle_hash.clone(),
                        egress_binding_id: lease.egress_binding_id.clone(),
                        proxy_endpoint_id: selected.proxy_endpoint_id.clone(),
                        egress_epoch: lease.egress_epoch,
                        session_derivation_version: 1,
                    },
                    egress: selected.egress,
                    request: final_request,
                    deadlines: AttemptDeadlines {
                        connect: attempt_connect,
                        upstream_total: attempt_upstream_total,
                        stream_idle: request_limits.upstream_stream_idle,
                        cancel_grace: request_limits.cancel_grace,
                    },
                },
                engine,
                activation_generation: catalog.generation(),
                cancellation: attempt_cancellation.clone(),
            };
            let first_byte = Arc::new(FirstByteEventSink::default());
            let sink = Arc::new(MonotonicEventSink::new(first_byte.clone()));
            let mut execution = Box::pin(self.transport.execute(attempt, sink));
            let mut attempt_promoted = false;
            let execution = loop {
                tokio::select! {
                    biased;
                    request_bytes = first_byte.wait_for_first_byte(), if !attempt_promoted => {
                        promote_attempt_telemetry(
                            &self.storage,
                            &attempt_telemetry,
                            request_bytes,
                            None,
                        ).await?;
                        attempt_promoted = true;
                        messages_attempts = messages_attempts.saturating_add(1);
                        if !request.generic.stream
                            && upstream_total_deadline.is_none()
                            && let Some(first_byte_at) = first_byte.first_byte_at()
                        {
                            upstream_total_deadline =
                                first_byte_at.checked_add(request_limits.upstream_non_stream_total);
                        }
                    }
                    result = &mut execution => break result,
                }
            };
            if !request.generic.stream
                && upstream_total_deadline.is_none()
                && let Some(first_byte_at) = first_byte.first_byte_at()
            {
                upstream_total_deadline = first_byte_at.checked_add(request_limits.upstream_non_stream_total);
            }
            match execution {
                Ok(raw) => {
                    let request_bytes = first_byte.request_bytes();
                    if request_bytes == 0 {
                        fail_attempt_telemetry(&self.storage, &attempt_telemetry, 0, false).await?;
                        return Err(DispatchError::Unavailable);
                    }
                    if attempt_promoted {
                        update_attempt_http_status(&self.storage, &attempt_telemetry, raw.status).await?;
                    } else {
                        promote_attempt_telemetry(&self.storage, &attempt_telemetry, request_bytes, Some(raw.status))
                            .await?;
                        messages_attempts = messages_attempts.saturating_add(1);
                    }
                    observe_subscription_quota_headers(
                        &self.storage,
                        &group,
                        &lease.credential_id,
                        &raw.headers,
                        self.clock.now().monotonic,
                    )
                    .await;
                    let retry_after = if raw.status == 429 {
                        let cooldown =
                            persist_rate_limit_cooldown(&self.storage, &attempt_telemetry, trusted_retry_after(&raw))
                                .await?;
                        group
                            .observe_credential_cooldown(CredentialCooldownUpdate {
                                credential_id: lease.credential_id.clone(),
                                cooldown_until: Some(self.clock.now().monotonic.saturating_add(cooldown)),
                            })
                            .await?;
                        cooldown
                    } else {
                        trusted_retry_after(&raw).unwrap_or(Duration::ZERO)
                    };
                    if raw.status != 429
                        && clear_rate_limit_cooldown(&self.storage, attempt_telemetry.credential_id)
                            .await
                            .unwrap_or(false)
                    {
                        group
                            .observe_credential_cooldown(CredentialCooldownUpdate {
                                credential_id: lease.credential_id.clone(),
                                cooldown_until: None,
                            })
                            .await?;
                    }
                    if raw.status == 401 && !refresh_attempted && messages_attempts < 3 {
                        let Some(maintainer) = self.credential_maintainer.as_ref() else {
                            break (raw, attempt_telemetry, first_byte.transport_terminal());
                        };
                        refresh_attempted = true;
                        let maintenance = Arc::clone(maintainer)
                            .maintain(lease.credential_id.clone(), MaintenanceTrigger::Upstream401);
                        let maintenance_outcome = if let Some(deadline) = upstream_total_deadline {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if let Ok(outcome) = tokio::time::timeout(remaining, maintenance).await {
                                outcome
                            } else {
                                let _ = discard_raw_response(raw, &attempt_cancellation).await;
                                mark_attempt_final(&self.storage, &attempt_telemetry).await?;
                                return Err(DispatchError::DeadlineExceeded);
                            }
                        } else {
                            maintenance.await
                        };
                        match maintenance_outcome {
                            Ok(outcome) => {
                                group
                                    .observe_credential_auth(CredentialAuthUpdate {
                                        credential_id: lease.credential_id.clone(),
                                        token_version: outcome.commit.token_version,
                                        auth_healthy: true,
                                    })
                                    .await?;
                                if !discard_raw_response(raw, &attempt_cancellation).await {
                                    mark_attempt_final(&self.storage, &attempt_telemetry).await?;
                                    return Err(DispatchError::Unavailable);
                                }
                                let replacement = group
                                    .replace_lease(
                                        entry.clone(),
                                        &lease,
                                        RetryCredentialTarget::Same(lease.credential_id.clone()),
                                    )
                                    .await?;
                                if let Some(replacement) = replacement {
                                    lease_guard.replace(replacement.clone());
                                    complete_attempt_for_retry(
                                        &self.storage,
                                        &attempt_telemetry,
                                        Duration::ZERO,
                                        "refresh_same_credential",
                                    )
                                    .await?;
                                    lease = replacement;
                                    next_attempt_reason = "oauth_refresh_replay";
                                    continue;
                                }
                                mark_attempt_final(&self.storage, &attempt_telemetry).await?;
                                return Err(DispatchError::Unavailable);
                            }
                            Err(error) => {
                                if matches!(
                                    error,
                                    CredentialServiceError::InvalidAuthentication
                                        | CredentialServiceError::AccountMismatch
                                        | CredentialServiceError::ManualRecoveryRequired(_)
                                ) {
                                    group
                                        .observe_credential_auth(CredentialAuthUpdate {
                                            credential_id: lease.credential_id.clone(),
                                            token_version: lease.token_version,
                                            auth_healthy: false,
                                        })
                                        .await?;
                                }
                            }
                        }
                    }
                    if let Some(error_class) = retry_error_class_for_status(raw.status) {
                        let status = raw.status;
                        let remaining_deadline = upstream_total_deadline.map_or(Duration::MAX, |deadline| {
                            deadline.saturating_duration_since(Instant::now())
                        });
                        let proposed_backoff = retry_backoff(status, messages_attempts, request_uuid, retry_after);
                        let context = |alternate_credential_available| RetryContext {
                            error: error_class,
                            portability: &request.generic.portability,
                            response_committed: false,
                            body_replayable: request.generic.digest_is_valid(),
                            messages_attempts,
                            refresh_already_attempted: refresh_attempted,
                            same_credential_available: true,
                            alternate_credential_available,
                            remaining_deadline,
                            min_retry_budget: request_limits.min_retry_budget,
                            proposed_backoff,
                        };
                        let mut decision = decide_retry(&context(true));
                        if !decision.allowed {
                            break (raw, attempt_telemetry, first_byte.transport_terminal());
                        }
                        if !discard_raw_response(raw, &attempt_cancellation).await {
                            mark_attempt_final(&self.storage, &attempt_telemetry).await?;
                            return Err(DispatchError::Unavailable);
                        }
                        let mut replacement = match decision.strategy {
                            Some(RetryStrategy::SwitchCredential) => {
                                group
                                    .replace_lease(
                                        entry.clone(),
                                        &lease,
                                        RetryCredentialTarget::Alternate {
                                            exclude: lease.credential_id.clone(),
                                        },
                                    )
                                    .await?
                            }
                            Some(RetryStrategy::SameCredential | RetryStrategy::RefreshSameCredential) | None => None,
                        };
                        if replacement.is_none() && decision.strategy == Some(RetryStrategy::SwitchCredential) {
                            decision = decide_retry(&context(false));
                        }
                        if replacement.is_none() && decision.strategy == Some(RetryStrategy::SameCredential) {
                            if !decision.backoff.is_zero() {
                                tokio::select! {
                                    () = cancellation.cancelled() => return Err(DispatchError::Cancelled),
                                    () = tokio::time::sleep(decision.backoff) => {}
                                }
                            }
                            replacement = group
                                .replace_lease(
                                    entry.clone(),
                                    &lease,
                                    RetryCredentialTarget::Same(lease.credential_id.clone()),
                                )
                                .await?;
                        }
                        if let Some(replacement) = replacement {
                            lease_guard.replace(replacement.clone());
                            let retry_decision = match decision.strategy {
                                Some(RetryStrategy::SwitchCredential) => "switch_credential",
                                Some(RetryStrategy::SameCredential) => "same_credential",
                                Some(RetryStrategy::RefreshSameCredential) => "refresh_same_credential",
                                None => "none",
                            };
                            complete_attempt_for_retry(
                                &self.storage,
                                &attempt_telemetry,
                                decision.backoff,
                                retry_decision,
                            )
                            .await?;
                            next_attempt_reason = if replacement.credential_id == lease.credential_id {
                                match error_class {
                                    RetryErrorClass::RateLimited429 => "rate_limit_retry",
                                    RetryErrorClass::Overloaded529 | RetryErrorClass::Upstream5xx => "overload_retry",
                                    _ => "credential_switch",
                                }
                            } else {
                                "credential_switch"
                            };
                            lease = replacement;
                            continue;
                        }
                        mark_attempt_final(&self.storage, &attempt_telemetry).await?;
                        return Err(map_retry_status(status, retry_after));
                    }
                    break (raw, attempt_telemetry, first_byte.transport_terminal());
                }
                Err(error) => {
                    self.project_transport_health(&lease, health_proxy_endpoint_id.as_ref(), &error)
                        .await?;
                    let request_bytes = first_byte.request_bytes().max(error.upstream_request_bytes_written);
                    if request_bytes > 0 {
                        if !attempt_promoted {
                            promote_attempt_telemetry(&self.storage, &attempt_telemetry, request_bytes, None).await?;
                            messages_attempts = messages_attempts.saturating_add(1);
                        }
                        if error.retry_safety == RetrySafety::CommitUnknown {
                            let remaining_deadline = upstream_total_deadline.map_or(Duration::MAX, |deadline| {
                                deadline.saturating_duration_since(Instant::now())
                            });
                            let proposed_backoff = retry_backoff(503, messages_attempts, request_uuid, Duration::ZERO);
                            let context = |alternate_credential_available| RetryContext {
                                error: RetryErrorClass::NetworkBeforeCommit,
                                portability: &request.generic.portability,
                                response_committed: false,
                                body_replayable: request.generic.digest_is_valid(),
                                messages_attempts,
                                refresh_already_attempted: false,
                                same_credential_available: true,
                                alternate_credential_available,
                                remaining_deadline,
                                min_retry_budget: request_limits.min_retry_budget,
                                proposed_backoff,
                            };
                            let mut decision = decide_retry(&context(true));
                            let mut replacement = match decision.strategy {
                                Some(RetryStrategy::SwitchCredential) => {
                                    group
                                        .replace_lease(
                                            entry.clone(),
                                            &lease,
                                            RetryCredentialTarget::Alternate {
                                                exclude: lease.credential_id.clone(),
                                            },
                                        )
                                        .await?
                                }
                                _ => None,
                            };
                            if replacement.is_none() && decision.strategy == Some(RetryStrategy::SwitchCredential) {
                                decision = decide_retry(&context(false));
                            }
                            if replacement.is_none() && decision.strategy == Some(RetryStrategy::SameCredential) {
                                if !decision.backoff.is_zero() {
                                    tokio::select! {
                                        () = cancellation.cancelled() => {
                                            fail_attempt_telemetry(
                                                &self.storage,
                                                &attempt_telemetry,
                                                request_bytes,
                                                true,
                                            ).await?;
                                            return Err(DispatchError::Cancelled);
                                        },
                                        () = tokio::time::sleep(decision.backoff) => {}
                                    }
                                }
                                replacement = group
                                    .replace_lease(
                                        entry.clone(),
                                        &lease,
                                        RetryCredentialTarget::Same(lease.credential_id.clone()),
                                    )
                                    .await?;
                            }
                            if let Some(replacement) = replacement {
                                lease_guard.replace(replacement.clone());
                                fail_attempt_telemetry(&self.storage, &attempt_telemetry, request_bytes, false).await?;
                                next_attempt_reason = if replacement.credential_id == lease.credential_id {
                                    "network_retry"
                                } else {
                                    "credential_switch"
                                };
                                lease = replacement;
                                continue;
                            }
                        }
                        fail_attempt_telemetry(&self.storage, &attempt_telemetry, request_bytes, true).await?;
                        return Err(map_transport_error(&error));
                    }
                    fail_attempt_telemetry(&self.storage, &attempt_telemetry, 0, false).await?;
                    if error.retry_safety != RetrySafety::SafeBeforeSubmission || connection_ordinal >= 3 {
                        return Err(map_transport_error(&error));
                    }
                    let same = group
                        .replace_lease(
                            entry.clone(),
                            &lease,
                            RetryCredentialTarget::Same(lease.credential_id.clone()),
                        )
                        .await?;
                    let replacement = if same.is_some() {
                        same
                    } else if matches!(request.generic.portability, gateway_domain::Portability::Portable) {
                        group
                            .replace_lease(
                                entry.clone(),
                                &lease,
                                RetryCredentialTarget::Alternate {
                                    exclude: lease.credential_id.clone(),
                                },
                            )
                            .await?
                    } else {
                        None
                    };
                    let Some(replacement) = replacement else {
                        return Err(map_transport_error(&error));
                    };
                    next_attempt_reason = if replacement.credential_id == lease.credential_id {
                        "network_retry"
                    } else {
                        "credential_switch"
                    };
                    lease = replacement.clone();
                    lease_guard.replace(replacement);
                }
            }
        };
        lease_guard.defer_release(request_limits.cancel_grace);
        let response_side_writer: Option<Box<dyn ResponseSideWriter>> =
            if let Some((latch, retention_days)) = content_latch.as_ref() {
                let (tap, receiver, gap, truncated) = response_audit_channel(64 * 1024 * 1024);
                let audit_handle = spawn_response_content_audit(ResponseAuditTask {
                    storage: self.storage.clone(),
                    store: self
                        .content_audit
                        .clone()
                        .ok_or(DispatchError::AuditUnavailable { retry_after_seconds: 5 })?,
                    request_id: request_uuid,
                    owner_user_id: parse_uuid(request.owner_user_id.as_str())?,
                    policy_version: request
                        .generic
                        .snapshot_set
                        .access_policy
                        .0
                        .to_string()
                        .into_boxed_str(),
                    retention_days: *retention_days,
                    latch: latch.clone(),
                    receiver,
                    gap,
                    truncated,
                });
                let mut tasks = self.audit_tasks.lock().await;
                tasks.retain(|task| !task.handle.is_finished());
                tasks.push(audit_handle);
                Some(Box::new(tap))
            } else {
                None
            };
        let mut response = self
            .response
            .prepare_with_side_writer_and_reservation(
                raw,
                cancellation.clone(),
                response_side_writer,
                response_reservation,
            )
            .await
            .map_err(|error| {
                cancellation.cancel();
                map_response_error(&error)
            })?;
        let delivery_id = Uuid::now_v7();
        if self
            .storage
            .start_response_delivery(&DeliveryStart {
                delivery_id,
                request_id: request_uuid,
                attempt_id: Some(attempt_telemetry.attempt_id),
                streaming: matches!(response.mode, gateway_domain::ResponseMode::Streaming),
                buffer_tier_code: response.buffer_tier.map(|tier| match tier {
                    gateway_domain::BufferTier::Memory => Box::from("memory"),
                    gateway_domain::BufferTier::EncryptedSpill => Box::from("encrypted_spill"),
                }),
                client_write_idle_ms: 120_000,
            })
            .await
            .is_err()
        {
            cancellation.cancel();
            return Err(DispatchError::Unavailable);
        }
        let completion_lease = if matches!(response.mode, gateway_domain::ResponseMode::NonStreaming) {
            if !group.release_lease_only(lease.clone()).await {
                cancellation.cancel();
                return Err(DispatchError::Unavailable);
            }
            None
        } else {
            Some(lease.clone())
        };
        let completion = Arc::new(RequestCompletion {
            storage: self.storage.clone(),
            group: group.clone(),
            lease: completion_lease,
            request_id: request.request_id,
            request_uuid,
            delivery_id,
            attempt_id: attempt_telemetry.attempt_id,
            model_id,
            clock: self.clock.clone(),
            committed: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            content_latch: content_latch.map(|(latch, _)| latch),
            transport_terminal,
            cancel_grace: request_limits.cancel_grace,
            cancel_input_tokens: estimate_cancel_input_tokens(request.generic.replay_body.bytes()),
            cancel_input_basis_digest: Sha256::digest(request.generic.replay_body.bytes()).into(),
            usage_terminal: Mutex::new(UsageTerminalLatch::default()),
        });
        let (_unused_usage_sender, empty_usage_receiver) = oneshot::channel();
        let usage_receiver = std::mem::replace(&mut response.usage, empty_usage_receiver);
        let usage_completion = completion.clone();
        tokio::spawn(async move {
            if let Ok(usage) = usage_receiver.await {
                usage_completion.usage_observed(usage).await;
            }
        });
        response.completion = Some(completion);
        lease_guard.disarm();
        request_guard.disarm();
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug)]
struct RuntimeRequestLimits {
    pre_upstream_wait: Duration,
    upstream_connect: Duration,
    upstream_non_stream_total: Duration,
    upstream_stream_idle: Duration,
    min_retry_budget: Duration,
    cancel_grace: Duration,
    queue_full_retry_after: Duration,
    queue_wait_retry_after: Duration,
}

struct RuntimeGroup {
    executor_id: Box<str>,
    generation: OwnerGeneration,
    handle: GroupExecutorHandle,
    clock: Arc<dyn Clock>,
    storage: Arc<PgStorage>,
    group_uuid: Uuid,
    request_limits: RwLock<RuntimeRequestLimits>,
    owner_valid: AtomicBool,
    local_lease_deadline_ms: AtomicU64,
    coordination: Mutex<()>,
    pending: Mutex<BTreeMap<gateway_domain::RequestId, oneshot::Sender<AdmissionDecision>>>,
}

impl RuntimeGroup {
    fn new(
        executor_id: Box<str>,
        generation: OwnerGeneration,
        handle: GroupExecutorHandle,
        clock: Arc<dyn Clock>,
        storage: Arc<PgStorage>,
        group_uuid: Uuid,
        request_limits: RuntimeRequestLimits,
    ) -> Self {
        let lease_deadline = clock.now().monotonic.saturating_add(Duration::from_secs(20));
        Self {
            executor_id,
            generation,
            handle,
            clock,
            storage,
            group_uuid,
            request_limits: RwLock::new(request_limits),
            owner_valid: AtomicBool::new(true),
            local_lease_deadline_ms: AtomicU64::new(duration_millis(lease_deadline)),
            coordination: Mutex::new(()),
            pending: Mutex::new(BTreeMap::new()),
        }
    }

    fn spawn_ticks(self: &Arc<Self>) {
        let runtime = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(25));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            while runtime.owner_valid.load(Ordering::Acquire) {
                tokio::select! {
                    _ = tick.tick() => {
                        if let Ok(resolutions) = runtime.handle.tick(runtime.generation, runtime.clock.now().monotonic).await {
                            if runtime.flush_resource_events().await.is_err() {
                                runtime.fence_lost_owner().await;
                                break;
                            }
                            runtime.route(resolutions).await;
                        } else {
                            runtime.fence_lost_owner().await;
                            break;
                        }
                    }
                    _ = heartbeat.tick() => {
                        let generation = i64::try_from(runtime.generation.get());
                        let renewed = match generation {
                            Ok(value) => tokio::time::timeout(
                                Duration::from_secs(10),
                                runtime.storage.heartbeat_group_owner(
                                    runtime.group_uuid,
                                    &runtime.executor_id,
                                    value,
                                ),
                            ).await.is_ok_and(|result| result.is_ok()),
                            Err(_) => false,
                        };
                        if renewed {
                            let deadline = runtime.clock.now().monotonic.saturating_add(Duration::from_secs(20));
                            runtime.local_lease_deadline_ms.store(duration_millis(deadline), Ordering::Release);
                        } else {
                            runtime.fence_lost_owner().await;
                            break;
                        }
                    }
                }
            }
        });
    }

    async fn flush_resource_events(&self) -> Result<(), DispatchError> {
        let events = self
            .handle
            .resource_events()
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        let Some(last_sequence) = events.last().map(|event| event.sequence) else {
            return Ok(());
        };
        let records = events
            .iter()
            .map(|event| scheduler_resource_record(self.group_uuid, event))
            .collect::<Result<Vec<_>, _>>()?;
        self.storage
            .append_scheduler_resource_events(&records)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        self.handle
            .acknowledge_resource_events(last_sequence)
            .await
            .map_err(|_| DispatchError::Unavailable)
    }

    async fn admit(self: &Arc<Self>, entry: ScheduleEntry) -> Result<RuntimeAdmission, DispatchError> {
        if !self.owner_valid.load(Ordering::Acquire)
            || duration_millis(self.clock.now().monotonic) >= self.local_lease_deadline_ms.load(Ordering::Acquire)
        {
            self.fence_lost_owner().await;
            return Err(DispatchError::Unavailable);
        }
        let _coordination_guard = self.coordination.lock().await;
        let request_id = entry.request_id.clone();
        let decision = self
            .handle
            .admit(self.generation, entry, self.clock.now().monotonic)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        self.flush_resource_events().await?;
        match decision {
            AdmissionDecision::Granted(lease) => Ok(RuntimeAdmission::Granted(lease)),
            AdmissionDecision::Queued(_) => {
                let (sender, receiver) = oneshot::channel();
                if self.pending.lock().await.insert(request_id.clone(), sender).is_some() {
                    return Err(DispatchError::DeterministicUnavailable);
                }
                Ok(RuntimeAdmission::Queued {
                    receiver,
                    guard: QueueGuard::new(self.clone(), request_id),
                })
            }
            AdmissionDecision::Rejected(rejection) => Ok(RuntimeAdmission::Rejected(rejection)),
            AdmissionDecision::StaleIgnored => Err(DispatchError::Unavailable),
        }
    }

    async fn wait_for_resolution(
        &self,
        request_id: &gateway_domain::RequestId,
        pre_upstream_deadline: Duration,
        receiver: oneshot::Receiver<AdmissionDecision>,
        guard: &mut QueueGuard,
        request_limits: RuntimeRequestLimits,
    ) -> Result<CredentialLease, DispatchError> {
        let remaining = pre_upstream_deadline.saturating_sub(self.clock.now().monotonic);
        let decision = match tokio::time::timeout(remaining, receiver).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(_)) => return Err(DispatchError::Unavailable),
            Err(_) => {
                self.cancel_queued(request_id.clone()).await;
                guard.disarm();
                return Err(DispatchError::PreUpstreamTimeout {
                    retry_after_seconds: retry_after_seconds(request_limits.queue_wait_retry_after),
                });
            }
        };
        guard.disarm();
        match decision {
            AdmissionDecision::Granted(lease) => Ok(lease),
            AdmissionDecision::Rejected(rejection) => Err(map_rejection(&rejection, request_limits)),
            AdmissionDecision::Queued(_) | AdmissionDecision::StaleIgnored => Err(DispatchError::Unavailable),
        }
    }

    async fn replace_lease(
        &self,
        entry: ScheduleEntry,
        current_lease: &CredentialLease,
        target: RetryCredentialTarget,
    ) -> Result<Option<CredentialLease>, DispatchError> {
        if !self.owner_valid.load(Ordering::Acquire) {
            return Err(DispatchError::Unavailable);
        }
        let coordination_guard = self.coordination.lock().await;
        let decision = self
            .handle
            .replace_lease(
                self.generation,
                RetryLeaseRequest {
                    current_lease_id: current_lease.id.clone(),
                    entry,
                    target,
                },
                self.clock.now().monotonic,
            )
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        if self.flush_resource_events().await.is_err() {
            self.owner_valid.store(false, Ordering::Release);
            let now = self.clock.now().monotonic;
            let mut resolutions = self.handle.begin_drain(self.generation, now).await.unwrap_or_default();
            if let RetryLeaseDecision::Granted(lease) = &decision {
                if let Ok((_, mut released)) = self.handle.release_lease(self.generation, lease.id.clone(), now).await {
                    resolutions.append(&mut released);
                }
                if let Ok(mut completed) = self
                    .handle
                    .complete_request(self.generation, lease.request_id.clone(), now)
                    .await
                {
                    resolutions.append(&mut completed);
                }
            }
            let _ = self.flush_resource_events().await;
            drop(coordination_guard);
            self.route(resolutions).await;
            return Err(DispatchError::Unavailable);
        }
        drop(coordination_guard);
        match decision {
            RetryLeaseDecision::Granted(lease) => Ok(Some(*lease)),
            RetryLeaseDecision::NoCandidate => Ok(None),
            RetryLeaseDecision::StaleIgnored => Err(DispatchError::Unavailable),
        }
    }

    async fn observe_credential_cooldown(&self, update: CredentialCooldownUpdate) -> Result<(), DispatchError> {
        if !self.owner_valid.load(Ordering::Acquire) {
            return Err(DispatchError::Unavailable);
        }
        let coordination_guard = self.coordination.lock().await;
        let (applied, resolutions) = self
            .handle
            .observe_credential_cooldown(self.generation, update, self.clock.now().monotonic)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        self.flush_resource_events().await?;
        drop(coordination_guard);
        if !applied {
            return Err(DispatchError::Unavailable);
        }
        self.route(resolutions).await;
        Ok(())
    }

    async fn set_credential_fence(&self, credential_id: CredentialId, fenced: bool) -> Result<u32, DispatchError> {
        if !self.owner_valid.load(Ordering::Acquire) {
            return Err(DispatchError::Unavailable);
        }
        let coordination_guard = self.coordination.lock().await;
        let (result, resolutions) = self
            .handle
            .set_credential_fence(self.generation, credential_id, fenced, self.clock.now().monotonic)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        self.flush_resource_events().await?;
        drop(coordination_guard);
        self.route(resolutions).await;
        match result {
            CredentialFenceResult::Applied { inflight } => Ok(inflight),
            CredentialFenceResult::Missing => Ok(0),
            CredentialFenceResult::StaleIgnored => Err(DispatchError::Unavailable),
        }
    }

    async fn remove_fenced_credential(&self, credential_id: CredentialId) -> Result<(), DispatchError> {
        if !self.owner_valid.load(Ordering::Acquire) {
            return Err(DispatchError::Unavailable);
        }
        let coordination_guard = self.coordination.lock().await;
        let (result, resolutions) = self
            .handle
            .remove_fenced_credential(self.generation, credential_id, self.clock.now().monotonic)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        self.flush_resource_events().await?;
        drop(coordination_guard);
        self.route(resolutions).await;
        match result {
            CredentialRemoveResult::Removed | CredentialRemoveResult::Missing => Ok(()),
            CredentialRemoveResult::Busy { .. }
            | CredentialRemoveResult::NotFenced
            | CredentialRemoveResult::StaleIgnored => Err(DispatchError::Unavailable),
        }
    }

    async fn reconfigure(
        &self,
        config: GroupConfig,
        request_limits: RuntimeRequestLimits,
    ) -> Result<(), DispatchError> {
        if !self.owner_valid.load(Ordering::Acquire) {
            return Err(DispatchError::Unavailable);
        }
        let coordination_guard = self.coordination.lock().await;
        let resolutions = self
            .handle
            .reconfigure_group(self.generation, config, self.clock.now().monotonic)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        *self.request_limits.write().await = request_limits;
        self.flush_resource_events().await?;
        drop(coordination_guard);
        self.route(resolutions).await;
        Ok(())
    }

    async fn reconfigure_credential(&self, config: CredentialConfig) -> Result<bool, DispatchError> {
        if !self.owner_valid.load(Ordering::Acquire) {
            return Err(DispatchError::Unavailable);
        }
        let coordination_guard = self.coordination.lock().await;
        let (applied, resolutions) = self
            .handle
            .reconfigure_credential(self.generation, config, self.clock.now().monotonic)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        self.flush_resource_events().await?;
        drop(coordination_guard);
        self.route(resolutions).await;
        Ok(applied)
    }

    async fn observe_credential_auth(&self, update: CredentialAuthUpdate) -> Result<(), DispatchError> {
        if !self.owner_valid.load(Ordering::Acquire) {
            return Err(DispatchError::Unavailable);
        }
        let coordination_guard = self.coordination.lock().await;
        let (applied, resolutions) = self
            .handle
            .observe_credential_auth(self.generation, update, self.clock.now().monotonic)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        self.flush_resource_events().await?;
        drop(coordination_guard);
        if !applied {
            return Err(DispatchError::Unavailable);
        }
        self.route(resolutions).await;
        Ok(())
    }

    async fn observe_credential_quota(&self, update: CredentialQuotaUpdate) -> Result<(), DispatchError> {
        if !self.owner_valid.load(Ordering::Acquire) {
            return Err(DispatchError::Unavailable);
        }
        let coordination_guard = self.coordination.lock().await;
        let (applied, resolutions) = self
            .handle
            .observe_credential_quota(self.generation, update, self.clock.now().monotonic)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        self.flush_resource_events().await?;
        drop(coordination_guard);
        if !applied {
            return Ok(());
        }
        self.route(resolutions).await;
        Ok(())
    }

    async fn cancel_queued(&self, request_id: gateway_domain::RequestId) {
        let coordination_guard = self.coordination.lock().await;
        self.pending.lock().await.remove(&request_id);
        let decision = self
            .handle
            .cancel(self.generation, request_id, self.clock.now().monotonic)
            .await;
        if self.flush_resource_events().await.is_err() {
            tracing::error!(event="scheduler_resource_ledger_persist_failed", group_id=%self.group_uuid);
        }
        drop(coordination_guard);
        if let Ok(AdmissionDecision::Granted(lease)) = decision {
            self.release_and_complete(lease).await;
        }
    }

    async fn release_and_complete(&self, lease: CredentialLease) {
        let request_id = lease.request_id.clone();
        let _ = self.release_lease_only(lease).await;
        self.complete_request_only(request_id).await;
    }

    async fn release_lease_only(&self, lease: CredentialLease) -> bool {
        if let Ok((_, resolutions)) = self
            .handle
            .release_lease(self.generation, lease.id, self.clock.now().monotonic)
            .await
        {
            if self.flush_resource_events().await.is_err() {
                return false;
            }
            self.route(resolutions).await;
            true
        } else {
            false
        }
    }

    async fn complete_request_only(&self, request_id: gateway_domain::RequestId) {
        if let Ok(resolutions) = self
            .handle
            .complete_request(self.generation, request_id, self.clock.now().monotonic)
            .await
        {
            if self.flush_resource_events().await.is_err() {
                return;
            }
            self.route(resolutions).await;
        }
    }

    async fn cancel_active(&self, request_id: gateway_domain::RequestId) {
        let coordination_guard = self.coordination.lock().await;
        let cancelled = self
            .handle
            .cancel(self.generation, request_id, self.clock.now().monotonic)
            .await
            .is_ok();
        let ledger_persisted = self.flush_resource_events().await.is_ok();
        drop(coordination_guard);
        if cancelled
            && ledger_persisted
            && let Ok(resolutions) = self.handle.tick(self.generation, self.clock.now().monotonic).await
        {
            self.route(resolutions).await;
        }
    }

    async fn confirm_transport_cancel(&self, request_id: gateway_domain::RequestId) {
        let coordination_guard = self.coordination.lock().await;
        let confirmed = self
            .handle
            .confirm_transport_cancel(self.generation, request_id, self.clock.now().monotonic)
            .await
            .is_ok();
        let ledger_persisted = self.flush_resource_events().await.is_ok();
        drop(coordination_guard);
        if confirmed
            && ledger_persisted
            && let Ok(resolutions) = self.handle.tick(self.generation, self.clock.now().monotonic).await
        {
            self.route(resolutions).await;
        }
    }

    async fn route(&self, mut resolutions: Vec<QueueResolution>) {
        while !resolutions.is_empty() {
            let coordination_guard = self.coordination.lock().await;
            let mut orphaned = Vec::new();
            let mut pending = self.pending.lock().await;
            for resolution in std::mem::take(&mut resolutions) {
                if let Some(sender) = pending.remove(&resolution.request_id) {
                    if let Err(decision) = sender.send(resolution.decision)
                        && let AdmissionDecision::Granted(lease) = decision
                    {
                        orphaned.push(lease);
                    }
                } else if let AdmissionDecision::Granted(lease) = resolution.decision {
                    orphaned.push(lease);
                }
            }
            drop(pending);
            drop(coordination_guard);
            for lease in orphaned {
                let now = self.clock.now().monotonic;
                if let Ok((_, mut released)) = self.handle.release_lease(self.generation, lease.id, now).await {
                    resolutions.append(&mut released);
                }
                if let Ok(mut completed) = self
                    .handle
                    .complete_request(self.generation, lease.request_id, now)
                    .await
                {
                    resolutions.append(&mut completed);
                }
            }
        }
        if self.flush_resource_events().await.is_err() {
            tracing::error!(event="scheduler_resource_ledger_persist_failed", group_id=%self.group_uuid);
        }
    }

    async fn begin_drain(&self) {
        let resolutions = self
            .handle
            .begin_drain(self.generation, self.clock.now().monotonic)
            .await
            .unwrap_or_default();
        if self.flush_resource_events().await.is_err() {
            tracing::error!(event="scheduler_resource_ledger_persist_failed", group_id=%self.group_uuid);
        }
        self.route(resolutions).await;
    }

    async fn fence_lost_owner(&self) {
        if self.owner_valid.swap(false, Ordering::AcqRel) {
            tracing::error!(event = "group_owner_fenced", group_id = %self.group_uuid, generation = self.generation.get());
            self.begin_drain().await;
        }
    }

    async fn shutdown_owner(&self) {
        self.begin_drain().await;
        self.owner_valid.store(false, Ordering::Release);
        if let Ok(generation) = i64::try_from(self.generation.get()) {
            let _ = self
                .storage
                .release_group_owner(self.group_uuid, &self.executor_id, generation)
                .await;
        }
    }
}

enum RuntimeAdmission {
    Granted(CredentialLease),
    Queued {
        receiver: oneshot::Receiver<AdmissionDecision>,
        guard: QueueGuard,
    },
    Rejected(Rejection),
}

struct RequestTerminalGuard {
    storage: Arc<PgStorage>,
    request_id: Option<Uuid>,
}

impl RequestTerminalGuard {
    fn new(storage: Arc<PgStorage>, request_id: Uuid) -> Self {
        Self {
            storage,
            request_id: Some(request_id),
        }
    }

    fn disarm(&mut self) {
        self.request_id.take();
    }
}

impl Drop for RequestTerminalGuard {
    fn drop(&mut self) {
        if let Some(request_id) = self.request_id.take() {
            let storage = self.storage.clone();
            tokio::spawn(async move {
                let _ = storage
                    .terminalize_uncommitted_request(request_id, "failed_before_commit")
                    .await;
            });
        }
    }
}

struct QueueGuard {
    group: Arc<RuntimeGroup>,
    request_id: Option<gateway_domain::RequestId>,
}

impl QueueGuard {
    fn new(group: Arc<RuntimeGroup>, request_id: gateway_domain::RequestId) -> Self {
        Self {
            group,
            request_id: Some(request_id),
        }
    }

    fn disarm(&mut self) {
        self.request_id.take();
    }
}

impl Drop for QueueGuard {
    fn drop(&mut self) {
        if let Some(request_id) = self.request_id.take() {
            let group = self.group.clone();
            tokio::spawn(async move { group.cancel_queued(request_id).await });
        }
    }
}

struct LeaseGuard {
    group: Arc<RuntimeGroup>,
    lease: Option<CredentialLease>,
    release_delay: Duration,
}

impl LeaseGuard {
    fn new(group: Arc<RuntimeGroup>, lease: CredentialLease) -> Self {
        Self {
            group,
            lease: Some(lease),
            release_delay: Duration::ZERO,
        }
    }

    fn disarm(&mut self) {
        self.lease.take();
    }

    fn defer_release(&mut self, delay: Duration) {
        self.release_delay = delay;
    }

    fn replace(&mut self, lease: CredentialLease) {
        self.lease = Some(lease);
        self.release_delay = Duration::ZERO;
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            let group = self.group.clone();
            let delay = self.release_delay;
            tokio::spawn(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                group.release_and_complete(lease).await;
            });
        }
    }
}

struct RequestCompletion {
    storage: Arc<PgStorage>,
    group: Arc<RuntimeGroup>,
    lease: Option<CredentialLease>,
    request_id: gateway_domain::RequestId,
    request_uuid: Uuid,
    delivery_id: Uuid,
    attempt_id: Uuid,
    model_id: Uuid,
    clock: Arc<dyn Clock>,
    committed: AtomicBool,
    finished: AtomicBool,
    content_latch: Option<Arc<Mutex<ContentAuditLatch>>>,
    transport_terminal: CancellationToken,
    cancel_grace: Duration,
    cancel_input_tokens: u64,
    cancel_input_basis_digest: [u8; 32],
    usage_terminal: Mutex<UsageTerminalLatch>,
}

#[derive(Default)]
struct UsageTerminalLatch {
    outcome: Option<gateway_domain::DeliveryOutcome>,
    observed: Option<ObservedResponseUsage>,
    cancel_persist_started: bool,
}

async fn finish_scheduler_resources(
    group: Arc<RuntimeGroup>,
    lease: Option<CredentialLease>,
    request_id: gateway_domain::RequestId,
    outcome: gateway_domain::DeliveryOutcome,
    transport_terminal: CancellationToken,
    cancel_grace: Duration,
) {
    let cancelled = matches!(
        outcome,
        gateway_domain::DeliveryOutcome::ClientDisconnected
            | gateway_domain::DeliveryOutcome::ClientWriteTimeout
            | gateway_domain::DeliveryOutcome::CancelledBeforeCommit
    );
    match (lease, cancelled) {
        (Some(_lease), true) => {
            group.cancel_active(request_id.clone()).await;
            if tokio::time::timeout(cancel_grace, transport_terminal.cancelled())
                .await
                .is_ok()
            {
                group.confirm_transport_cancel(request_id).await;
            }
        }
        (Some(lease), false) => group.release_and_complete(lease).await,
        (None, _) => group.complete_request_only(request_id).await,
    }
}

impl RequestCompletion {
    async fn persist_usage_observation(
        &self,
        usage: gateway_domain::UsageObservation,
        cancel_evidence: Option<CancelEstimateEvidencePersist>,
    ) -> bool {
        let observation_id = Uuid::now_v7();
        let cost = match self
            .storage
            .price_basis_for_request(self.request_uuid, self.model_id)
            .await
        {
            Ok(Some(price)) => calculate_cost(&usage, price.snapshot, "estimated-api-value-v1")
                .ok()
                .and_then(|estimate| {
                    let amount_pico_usd = match estimate.amount_usd.as_deref() {
                        Some(amount) => Some(decimal_usd_to_pico_text(amount)?),
                        None => None,
                    };
                    Some(CostPersist {
                        cost_id: Uuid::now_v7(),
                        usage_observation_id: observation_id,
                        price_entry_id: Some(price.price_entry_id),
                        price_snapshot: price.snapshot,
                        estimate,
                        amount_pico_usd,
                        known_field_mask: known_usage_field_mask(&usage),
                    })
                }),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(event="usage_price_snapshot_load_failed", request_id=%self.request_uuid, ?error);
                None
            }
        };
        let selection_reason_code = Some(
            match (usage.source, usage.completeness) {
                (gateway_domain::UsageSource::Official, gateway_domain::UsageCompleteness::Complete) => {
                    "official_complete"
                }
                (gateway_domain::UsageSource::Official, gateway_domain::UsageCompleteness::Partial) => {
                    "official_partial"
                }
                (gateway_domain::UsageSource::ConsoleCount, _) => "console_count",
                (gateway_domain::UsageSource::LocalEstimate, _) => "local_estimate",
                (gateway_domain::UsageSource::CancelEstimate, _) => "cancel_estimate",
                _ => "unknown",
            }
            .into(),
        );
        let record = UsagePersist {
            observation_id,
            request_id: self.request_uuid,
            attempt_id: Some(self.attempt_id),
            model_id: Some(self.model_id),
            select_as_final: true,
            selection_reason_code,
            cancel_evidence,
            observation: usage,
        };
        for retry in 0_u64..4 {
            match self.storage.append_usage(&record, cost.as_ref()).await {
                Ok(()) => return true,
                Err(error) if retry < 3 => {
                    tracing::warn!(
                        event = "usage_persist_retry",
                        request_id = %self.request_uuid,
                        retry = retry + 1,
                        ?error,
                    );
                    tokio::time::sleep(Duration::from_millis(100_u64 << retry)).await;
                }
                Err(error) => {
                    tracing::error!(event="usage_persist_failed", request_id=%self.request_uuid, ?error);
                    return false;
                }
            }
        }
        false
    }

    async fn maybe_persist_cancel_estimate(&self) {
        let observed = {
            let mut state = self.usage_terminal.lock().await;
            let cancelled = state.outcome.is_some_and(|outcome| {
                matches!(
                    outcome,
                    gateway_domain::DeliveryOutcome::ClientDisconnected
                        | gateway_domain::DeliveryOutcome::ClientWriteTimeout
                )
            });
            let Some(observed) = state.observed.clone() else {
                return;
            };
            if !cancelled
                || state.cancel_persist_started
                || observed.official.completeness == gateway_domain::UsageCompleteness::Complete
            {
                return;
            }
            state.cancel_persist_started = true;
            observed
        };
        let output_tokens = observed
            .sse
            .as_ref()
            .filter(|evidence| !evidence.gap)
            .and_then(|evidence| evidence.output_tokens_estimate);
        let usage = gateway_domain::UsageObservation::new(
            gateway_domain::UsageSource::CancelEstimate,
            gateway_domain::UsageCompleteness::Partial,
            gateway_domain::TokenCounts {
                input_tokens: Some(self.cancel_input_tokens),
                output_tokens,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            Some("cancel-boundary-v1".into()),
        )
        .unwrap_or_else(|_| unreachable!("cancel estimate always has a known input field"));
        let cancel_evidence = observed.sse.as_ref().map_or(
            CancelEstimateEvidencePersist {
                input_basis_digest: self.cancel_input_basis_digest,
                sse_complete_event_ordinal: None,
                sse_content_event_ordinal: None,
                sse_decoded_end_offset: None,
                sse_last_event_type: None,
                sse_gap: None,
            },
            |evidence| CancelEstimateEvidencePersist {
                input_basis_digest: self.cancel_input_basis_digest,
                sse_complete_event_ordinal: i64::try_from(evidence.complete_event_ordinal).ok(),
                sse_content_event_ordinal: i64::try_from(evidence.content_event_ordinal).ok(),
                sse_decoded_end_offset: i64::try_from(evidence.decoded_end_offset).ok(),
                sse_last_event_type: evidence.last_event_type.clone(),
                sse_gap: Some(evidence.gap),
            },
        );
        if !self.persist_usage_observation(usage, Some(cancel_evidence)).await {
            self.usage_terminal.lock().await.cancel_persist_started = false;
        }
    }
}

#[async_trait]
impl DeliveryCompletion for RequestCompletion {
    async fn committed(&self) -> Result<(), DeliveryCompletionError> {
        self.storage
            .commit_client_response(self.request_uuid, self.delivery_id)
            .await
            .map_err(|_| DeliveryCompletionError)?;
        self.committed.store(true, Ordering::Release);
        Ok(())
    }

    async fn usage_observed(&self, observed: ObservedResponseUsage) {
        if self
            .storage
            .observe_delivery_upstream_bytes(
                self.request_uuid,
                self.delivery_id,
                i64::try_from(observed.upstream_bytes_received).unwrap_or(i64::MAX),
            )
            .await
            .is_err()
        {
            tracing::warn!(event="upstream_response_bytes_persist_failed", request_id=%self.request_uuid);
        }
        let _ = self.persist_usage_observation(observed.official.clone(), None).await;
        self.usage_terminal.lock().await.observed = Some(observed);
        self.maybe_persist_cancel_estimate().await;
    }

    async fn completed(&self, report: DeliveryReport) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        self.usage_terminal.lock().await.outcome = Some(report.outcome);
        self.maybe_persist_cancel_estimate().await;
        let committed = self.committed.load(Ordering::Acquire);
        if self
            .storage
            .complete_request_lifecycle(&RequestLifecycleComplete {
                request_id: self.request_uuid,
                attempt_id: self.attempt_id,
                delivery: DeliveryComplete {
                    delivery_id: self.delivery_id,
                    outcome: report.outcome,
                    response_committed: committed,
                    upstream_bytes_received: i64::try_from(report.bytes_delivered).unwrap_or(i64::MAX),
                    bytes_delivered: i64::try_from(report.bytes_delivered).unwrap_or(i64::MAX),
                    peak_backpressure_bytes: 0,
                    spill_bytes: 0,
                },
            })
            .await
            .is_err()
        {
            tracing::error!(event="request_terminal_persist_failed", request_id=%self.request_uuid);
        }
        let _ = self.clock.now();
        let _ = &self.request_id;
        let _ = &self.content_latch;
        finish_scheduler_resources(
            self.group.clone(),
            self.lease.clone(),
            self.request_id.clone(),
            report.outcome,
            self.transport_terminal.clone(),
            self.cancel_grace,
        )
        .await;
    }
}

impl Drop for RequestCompletion {
    fn drop(&mut self) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        let storage = self.storage.clone();
        let group = self.group.clone();
        let lease = self.lease.clone();
        let request_id = self.request_id.clone();
        let transport_terminal = self.transport_terminal.clone();
        let cancel_grace = self.cancel_grace;
        let request_uuid = self.request_uuid;
        let delivery_id = self.delivery_id;
        let attempt_id = self.attempt_id;
        let committed = self.committed.load(Ordering::Acquire);
        tokio::spawn(async move {
            if storage
                .complete_request_lifecycle(&RequestLifecycleComplete {
                    request_id: request_uuid,
                    attempt_id,
                    delivery: DeliveryComplete {
                        delivery_id,
                        outcome: gateway_domain::DeliveryOutcome::ClientDisconnected,
                        response_committed: committed,
                        upstream_bytes_received: 0,
                        bytes_delivered: 0,
                        peak_backpressure_bytes: 0,
                        spill_bytes: 0,
                    },
                })
                .await
                .is_err()
            {
                tracing::error!(event="request_terminal_persist_failed", request_id=%request_uuid);
            }
            finish_scheduler_resources(
                group,
                lease,
                request_id,
                gateway_domain::DeliveryOutcome::ClientDisconnected,
                transport_terminal,
                cancel_grace,
            )
            .await;
        });
    }
}

struct SelectedCredential {
    auth_kind: Box<str>,
    auth_secret: SecretBytes,
    session_hmac: SecretBytes,
    egress: EgressRouteSnapshot,
    proxy_endpoint_id: Option<ProxyEndpointId>,
    transport_bundle_id: Uuid,
}

#[allow(clippy::struct_field_names)]
struct AttemptTelemetry {
    intent_id: Uuid,
    connection_attempt_id: Uuid,
    attempt_id: Uuid,
    request_id: Uuid,
    credential_id: Uuid,
    token_version: i64,
    profile_epoch: i64,
    egress_epoch: i64,
    transport_bundle_id: Uuid,
    connection_ordinal: u8,
    messages_ordinal: u8,
    reason_code: &'static str,
}

#[derive(Debug, Default)]
struct FirstByteEventSink {
    request_bytes: AtomicU64,
    first_byte_at: OnceLock<Instant>,
    first_byte_notify: Notify,
    transport_terminal: CancellationToken,
}

impl FirstByteEventSink {
    fn request_bytes(&self) -> u64 {
        self.request_bytes.load(Ordering::Acquire)
    }

    fn first_byte_at(&self) -> Option<Instant> {
        self.first_byte_at.get().copied()
    }

    fn transport_terminal(&self) -> CancellationToken {
        self.transport_terminal.clone()
    }

    async fn wait_for_first_byte(&self) -> u64 {
        loop {
            let request_bytes = self.request_bytes();
            if request_bytes > 0 {
                return request_bytes;
            }
            self.first_byte_notify.notified().await;
        }
    }
}

impl TransportEventSink for FirstByteEventSink {
    fn emit(&self, event: TransportEvent) -> Result<(), gateway_transport::TransportError> {
        if event.kind == TransportEventKind::FirstUpstreamRequestByte {
            let _ = self.first_byte_at.set(Instant::now());
            self.request_bytes
                .store(event.request_bytes_written.max(1), Ordering::Release);
            self.first_byte_notify.notify_one();
        }
        if matches!(
            event.kind,
            TransportEventKind::ResponseComplete | TransportEventKind::CancelConfirmed
        ) {
            self.transport_terminal.cancel();
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_attempt_telemetry(
    storage: &PgStorage,
    request_id: Uuid,
    request: &DispatchRequest,
    lease: &CredentialLease,
    selected: &SelectedCredential,
    engine: &gateway_transport::CompiledTransportEngine,
    activation_generation: u64,
    connection_ordinal: u8,
    messages_ordinal: u8,
    reason_code: &'static str,
) -> Result<AttemptTelemetry, DispatchError> {
    let intent_id = Uuid::now_v7();
    let connection_attempt_id = Uuid::now_v7();
    let attempt_id = Uuid::now_v7();
    let generic_hash: [u8; 32] = Sha256::digest(request.generic.replay_body.bytes()).into();
    storage
        .arm_submission_intent(&SubmissionIntentArm {
            intent_id,
            request_id,
            ordinal: i16::from(messages_ordinal),
            credential_id: parse_uuid(lease.credential_id.as_str())?,
            token_version: i64::try_from(lease.token_version).map_err(|_| DispatchError::Unavailable)?,
            profile_epoch: i64::try_from(lease.profile_epoch).map_err(|_| DispatchError::Unavailable)?,
            egress_epoch: i64::try_from(lease.egress_epoch).map_err(|_| DispatchError::Unavailable)?,
            transport_bundle_id: selected.transport_bundle_id,
            generic_adjusted_request_hash: generic_hash.to_vec(),
        })
        .await
        .map_err(|_| DispatchError::Unavailable)?;
    let protocol = match engine.key.protocol {
        gateway_domain::HttpProtocol::H1 => "h1",
        gateway_domain::HttpProtocol::H2 => "h2",
    };
    let bundle_hash = decode_sha256(lease.bundle_hash.as_str())?;
    let proxy_endpoint_id = selected
        .proxy_endpoint_id
        .as_ref()
        .map(|value| parse_uuid(value.as_str()))
        .transpose()?;
    let mut transaction = storage.pool().begin().await.map_err(|_| DispatchError::Unavailable)?;
    sqlx::query(
        "INSERT INTO telemetry.connection_attempt_record \
         (id,request_month,request_id,ordinal,submission_intent_id,credential_id,profile_epoch,egress_epoch, \
          transport_bundle_id,state_code,pool_reused,request_bytes_written,retry_safe,started_at,bundle_version, \
          bundle_hash,authority,sni,protocol_code,proxy_endpoint_id,activation_generation) \
         SELECT $1,request_month,request_id,$14,$3,$4,$5,$6,$7,'planned',false,0,true,clock_timestamp(),$8,$9,$10,$10,$11,$12,$13 \
         FROM telemetry.request_record WHERE request_id=$2",
    )
    .bind(connection_attempt_id)
    .bind(request_id)
    .bind(intent_id)
    .bind(parse_uuid(lease.credential_id.as_str())?)
    .bind(i64::try_from(lease.profile_epoch).map_err(|_| DispatchError::Unavailable)?)
    .bind(i64::try_from(lease.egress_epoch).map_err(|_| DispatchError::Unavailable)?)
    .bind(selected.transport_bundle_id)
    .bind(i64::try_from(lease.bundle_version).map_err(|_| DispatchError::Unavailable)?)
    .bind(bundle_hash)
    .bind(engine.authority.as_ref())
    .bind(protocol)
    .bind(proxy_endpoint_id)
    .bind(i64::try_from(activation_generation).map_err(|_| DispatchError::Unavailable)?)
    .bind(i16::from(connection_ordinal))
    .execute(&mut *transaction)
    .await
    .map_err(|_| DispatchError::Unavailable)?;
    transaction.commit().await.map_err(|_| DispatchError::Unavailable)?;
    Ok(AttemptTelemetry {
        intent_id,
        connection_attempt_id,
        attempt_id,
        request_id,
        credential_id: parse_uuid(lease.credential_id.as_str())?,
        token_version: i64::try_from(lease.token_version).map_err(|_| DispatchError::Unavailable)?,
        profile_epoch: i64::try_from(lease.profile_epoch).map_err(|_| DispatchError::Unavailable)?,
        egress_epoch: i64::try_from(lease.egress_epoch).map_err(|_| DispatchError::Unavailable)?,
        transport_bundle_id: selected.transport_bundle_id,
        connection_ordinal,
        messages_ordinal,
        reason_code,
    })
}

async fn promote_attempt_telemetry(
    storage: &PgStorage,
    telemetry: &AttemptTelemetry,
    request_bytes: u64,
    status: Option<u16>,
) -> Result<(), DispatchError> {
    let request_bytes = i64::try_from(request_bytes).map_err(|_| DispatchError::Unavailable)?;
    if request_bytes <= 0 {
        return Err(DispatchError::Unavailable);
    }
    let mut transaction = storage.pool().begin().await.map_err(|_| DispatchError::Unavailable)?;
    let promoted = sqlx::query(
        "UPDATE telemetry.attempt_submission_intent \
         SET state_code='promoted',promoted_at=clock_timestamp(),request_bytes_written=$2 \
         WHERE id=$1 AND state_code='armed'",
    )
    .bind(telemetry.intent_id)
    .bind(request_bytes)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DispatchError::Unavailable)?;
    if promoted.rows_affected() != 1 {
        return Err(DispatchError::Unavailable);
    }
    sqlx::query(
        "UPDATE telemetry.connection_attempt_record SET state_code='promoted_on_first_byte', \
           request_bytes_written=$2,completed_at=clock_timestamp() WHERE id=$1 AND state_code='planned'",
    )
    .bind(telemetry.connection_attempt_id)
    .bind(request_bytes)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DispatchError::Unavailable)?;
    sqlx::query(
        "INSERT INTO telemetry.attempt_record \
         (id,request_month,request_id,ordinal,submission_intent_id,connection_attempt_id,credential_id,token_version, \
          profile_epoch,egress_epoch,transport_bundle_id,reason_code,state_code,is_final,submitted_at,http_status) \
         SELECT $1,request_month,request_id,$11,$3,$4,$5,$6,$7,$8,$9,$12,'receiving',false,clock_timestamp(),$10 \
         FROM telemetry.request_record WHERE request_id=$2",
    )
    .bind(telemetry.attempt_id)
    .bind(telemetry.request_id)
    .bind(telemetry.intent_id)
    .bind(telemetry.connection_attempt_id)
    .bind(telemetry.credential_id)
    .bind(telemetry.token_version)
    .bind(telemetry.profile_epoch)
    .bind(telemetry.egress_epoch)
    .bind(telemetry.transport_bundle_id)
    .bind(status.map(i32::from))
    .bind(i16::from(telemetry.messages_ordinal))
    .bind(telemetry.reason_code)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DispatchError::Unavailable)?;
    transaction.commit().await.map_err(|_| DispatchError::Unavailable)
}

async fn update_attempt_http_status(
    storage: &PgStorage,
    telemetry: &AttemptTelemetry,
    status: u16,
) -> Result<(), DispatchError> {
    let updated = sqlx::query(
        "UPDATE telemetry.attempt_record SET http_status=$2 \
         WHERE id=$1 AND request_id=$3 AND completed_at IS NULL",
    )
    .bind(telemetry.attempt_id)
    .bind(i32::from(status))
    .bind(telemetry.request_id)
    .execute(&storage.pool())
    .await
    .map_err(|_| DispatchError::Unavailable)?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(DispatchError::Unavailable)
    }
}

async fn fail_attempt_telemetry(
    storage: &PgStorage,
    telemetry: &AttemptTelemetry,
    request_bytes: u64,
    is_final: bool,
) -> Result<(), DispatchError> {
    let mut transaction = storage.pool().begin().await.map_err(|_| DispatchError::Unavailable)?;
    if request_bytes == 0 {
        let intent = sqlx::query(
            "UPDATE telemetry.attempt_submission_intent SET state_code='aborted',aborted_at=clock_timestamp() \
             WHERE id=$1 AND state_code='armed'",
        )
        .bind(telemetry.intent_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DispatchError::Unavailable)?;
        let connection = sqlx::query(
            "UPDATE telemetry.connection_attempt_record SET state_code='failed_before_first_byte', \
             retry_safe=true,request_bytes_written=0,completed_at=clock_timestamp() \
             WHERE id=$1 AND state_code='planned'",
        )
        .bind(telemetry.connection_attempt_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DispatchError::Unavailable)?;
        if intent.rows_affected() != 1 || connection.rows_affected() != 1 {
            return Err(DispatchError::Unavailable);
        }
    } else {
        let attempt = sqlx::query(
            "UPDATE telemetry.attempt_record SET state_code='failed',is_final=$2,completed_at=clock_timestamp() \
             WHERE id=$1 AND completed_at IS NULL",
        )
        .bind(telemetry.attempt_id)
        .bind(is_final)
        .execute(&mut *transaction)
        .await
        .map_err(|_| DispatchError::Unavailable)?;
        if attempt.rows_affected() != 1 {
            return Err(DispatchError::Unavailable);
        }
    }
    transaction.commit().await.map_err(|_| DispatchError::Unavailable)
}

async fn complete_attempt_for_retry(
    storage: &PgStorage,
    telemetry: &AttemptTelemetry,
    backoff: Duration,
    retry_decision_code: &'static str,
) -> Result<(), DispatchError> {
    let updated = sqlx::query(
        "UPDATE telemetry.attempt_record SET state_code='completed',retry_decision_code=$2, \
           is_final=false,completed_at=clock_timestamp() WHERE id=$1 AND completed_at IS NULL",
    )
    .bind(telemetry.attempt_id)
    .bind(retry_decision_code)
    .execute(&storage.pool())
    .await
    .map_err(|_| DispatchError::Unavailable)?;
    if updated.rows_affected() != 1 {
        return Err(DispatchError::Unavailable);
    }
    tracing::info!(
        event = "messages_attempt_retry",
        request_id = %telemetry.request_id,
        connection_ordinal = telemetry.connection_ordinal,
        messages_ordinal = telemetry.messages_ordinal,
        backoff_ms = backoff.as_millis()
    );
    Ok(())
}

async fn mark_attempt_final(storage: &PgStorage, telemetry: &AttemptTelemetry) -> Result<(), DispatchError> {
    let updated = sqlx::query(
        "UPDATE telemetry.attempt_record SET state_code='failed',retry_decision_code='no_candidate', \
           is_final=true,completed_at=clock_timestamp() WHERE id=$1 AND completed_at IS NULL",
    )
    .bind(telemetry.attempt_id)
    .execute(&storage.pool())
    .await
    .map_err(|_| DispatchError::Unavailable)?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(DispatchError::Unavailable)
    }
}

fn decode_sha256(value: &str) -> Result<Vec<u8>, DispatchError> {
    if value.len() != 64 {
        return Err(DispatchError::DeterministicUnavailable);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, DispatchError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(DispatchError::DeterministicUnavailable),
    }
}

fn runtime_request_limits(row: &sqlx::postgres::PgRow) -> anyhow::Result<RuntimeRequestLimits> {
    Ok(RuntimeRequestLimits {
        pre_upstream_wait: millis(row, "pre_upstream_wait_ms")?,
        upstream_connect: millis(row, "upstream_connect_ms")?,
        upstream_non_stream_total: millis(row, "upstream_non_stream_total_ms")?,
        upstream_stream_idle: millis(row, "upstream_stream_idle_ms")?,
        min_retry_budget: millis(row, "min_retry_budget_ms")?,
        cancel_grace: millis(row, "cancel_grace_ms")?,
        queue_full_retry_after: millis(row, "queue_full_retry_after_ms")?,
        queue_wait_retry_after: millis(row, "queue_wait_retry_after_ms")?,
    })
}

fn runtime_group_config(
    row: &sqlx::postgres::PgRow,
    group_uuid: Uuid,
    request_limits: RuntimeRequestLimits,
) -> anyhow::Result<GroupConfig> {
    let rate_limit = match (
        optional_u32(row, "default_rpm")?,
        optional_u32(row, "default_rpm_burst")?,
    ) {
        (Some(requests_per_minute), Some(burst)) => Some(BucketConfig {
            requests_per_minute,
            burst,
        }),
        (None, None) => None,
        _ => anyhow::bail!("Group RPM configuration is incomplete"),
    };
    Ok(GroupConfig {
        snapshot_version: gateway_domain::SnapshotVersion::new(format!(
            "group:{group_uuid}:config:{}",
            row.try_get::<i64, _>("config_version")?
        )),
        concurrency_limit: optional_u32(row, "max_concurrency")?,
        rate_limit,
        queue_capacity: optional_usize(row, "queue_capacity")?,
        pre_upstream_wait: request_limits.pre_upstream_wait,
        preferred_capacity_wait: millis(row, "preferred_capacity_wait_ms")?,
        cancel_grace: request_limits.cancel_grace,
        affinity_ttl: millis(row, "affinity_ttl_ms")?,
        affinity_migration_successes: u32::try_from(row.try_get::<i32, _>("affinity_migration_successes")?)?,
        quota_guard_basis_points: u16::try_from(row.try_get::<i32, _>("quota_guard_basis_points")?)?,
    })
}

async fn load_scheduler_credentials(
    storage: &PgStorage,
    group_id: Uuid,
    catalog: &gateway_transport::EngineCatalog,
    now: Duration,
) -> anyhow::Result<Vec<CredentialConfig>> {
    let rows = sqlx::query(
        "SELECT c.id,c.revision AS credential_projection_revision,c.token_version,c.lifecycle_state_code,c.auth_state_code,c.scheduling_state_code, \
                c.transport_state_code,c.capacity_state_code, \
                EXTRACT(EPOCH FROM GREATEST(c.cooldown_until-clock_timestamp(),interval '0'))*1000 AS cooldown_ms, \
                active_sc.revision AS scheduling_projection_revision,sc.max_concurrency,sc.rpm_limit,sc.rpm_burst,sc.priority_layer, \
                GREATEST(1,ROUND(sc.weight*1000))::bigint AS weight_scaled, \
                sc.session_capacity_enabled,sc.max_active_sessions,sc.session_idle_ttl_ms,sc.new_session_wait_ms, \
                p.id AS profile_id,p.profile_epoch,p.archetype_version_id,d.id AS device_identity_id,d.device_epoch, \
                e.id AS egress_binding_id,e.egress_epoch,t.artifact_version, \
                COALESCE(t.manifest #>> '{payload,bundle_id}',t.manifest ->> 'bundle_id') AS bundle_id, \
                t.manifest #>> '{canonicalization,canonical_hash}' AS canonical_hash, \
                quota.used_basis_points,quota.reset_after_seconds,quota_version.observation_id AS quota_observation_id \
         FROM gateway.anthropic_credential c \
         JOIN gateway.credential_active_scheduling_config active_sc ON active_sc.credential_id=c.id \
         JOIN gateway.credential_scheduling_config sc ON sc.id=active_sc.config_id AND sc.enabled \
         JOIN gateway.credential_profile p ON p.credential_id=c.id AND p.lifecycle_code='active' \
         JOIN gateway.device_identity d ON d.id=p.device_identity_id \
         JOIN gateway.credential_egress_binding e ON e.id=p.egress_binding_id \
              AND e.lifecycle_code='active' AND e.stability_code='stable' \
         JOIN catalog.archetype_bundle_binding binding ON binding.archetype_version_id=p.archetype_version_id \
              AND binding.state_code='active' \
         JOIN catalog.transport_bundle t ON t.id=binding.transport_bundle_id \
              AND t.lifecycle_code IN ('canary','active') AND t.evidence_gate_code='passed' \
              AND t.runtime_state_code='loadable' \
         LEFT JOIN LATERAL ( \
           SELECT LEAST(10000,CEIL(q.utilization*10000))::integer AS used_basis_points, \
                  CEIL(EXTRACT(EPOCH FROM GREATEST( \
                    COALESCE(q.rate_limited_until,q.resets_at)-clock_timestamp(),interval '0')))::bigint AS reset_after_seconds \
           FROM telemetry.credential_quota_current q \
           WHERE q.credential_id=c.id AND q.model_id IS NULL AND q.confidence_code='observed' \
             AND q.utilization IS NOT NULL AND q.window_kind_code IN ('five_hour','seven_day') \
           ORDER BY q.utilization DESC,q.observation_id DESC LIMIT 1 \
         ) quota ON true \
         LEFT JOIN LATERAL ( \
           SELECT q.observation_id FROM telemetry.credential_quota_current q \
           WHERE q.credential_id=c.id AND q.model_id IS NULL AND q.confidence_code='observed' \
             AND q.window_kind_code IN ('five_hour','seven_day') \
           ORDER BY q.observation_id DESC LIMIT 1 \
         ) quota_version ON true \
         WHERE c.group_id=$1 AND c.attachment_state_code='attached' \
           AND c.lifecycle_state_code='active' AND c.auth_state_code IN ('healthy','expiring') \
           AND c.scheduling_state_code IN ('eligible','cooldown') AND c.transport_state_code='ready' \
         ORDER BY c.id",
    )
    .bind(group_id)
    .fetch_all(&storage.pool())
    .await?;
    let mut credentials = Vec::new();
    for row in rows {
        let archetype_uuid: Uuid = row.try_get("archetype_version_id")?;
        let bundle_id: String = row.try_get("bundle_id")?;
        let bundle_version = u64::try_from(row.try_get::<i64, _>("artifact_version")?)?;
        let canonical_hash: Option<String> = row.try_get("canonical_hash")?;
        let Some(canonical_hash) = canonical_hash else {
            continue;
        };
        let Some(engine) = catalog.find_exact(&archetype_uuid.to_string(), &bundle_id, bundle_version, &canonical_hash)
        else {
            continue;
        };
        let cooldown_ms = row.try_get::<Option<f64>, _>("cooldown_ms")?.unwrap_or_default();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let cooldown = (cooldown_ms > 0.0).then(|| Duration::from_millis(cooldown_ms.ceil() as u64));
        let lifecycle_active = row.try_get::<String, _>("lifecycle_state_code")? == "active";
        let auth_healthy = matches!(
            row.try_get::<String, _>("auth_state_code")?.as_str(),
            "healthy" | "expiring"
        );
        let transport_ready = row.try_get::<String, _>("transport_state_code")? == "ready";
        let quota_used_basis_points = row
            .try_get::<Option<i32>, _>("used_basis_points")?
            .map(u16::try_from)
            .transpose()?;
        let quota_reset_at = row
            .try_get::<Option<i64>, _>("reset_after_seconds")?
            .map(u64::try_from)
            .transpose()?
            .map(|seconds| now.saturating_add(Duration::from_secs(seconds)));
        let quota_observation_version = row
            .try_get::<Option<Uuid>, _>("quota_observation_id")?
            .map(|value| value.as_u128());
        credentials.push(CredentialConfig {
            id: CredentialId::new(row.try_get::<Uuid, _>("id")?.to_string())?,
            credential_projection_revision: u64::try_from(row.try_get::<i64, _>("credential_projection_revision")?)?,
            scheduling_projection_revision: u64::try_from(row.try_get::<i64, _>("scheduling_projection_revision")?)?,
            concurrency_limit: u32::try_from(row.try_get::<i32, _>("max_concurrency")?)?,
            rate_limit: BucketConfig {
                requests_per_minute: u32::try_from(row.try_get::<i32, _>("rpm_limit")?)?,
                burst: u32::try_from(row.try_get::<i32, _>("rpm_burst")?)?,
            },
            priority: u16::try_from(row.try_get::<i32, _>("priority_layer")?)?,
            weight: u32::try_from(row.try_get::<i64, _>("weight_scaled")?)?,
            model_scope: BTreeSet::new(),
            attribution_optional: true,
            session_capacity: SessionCapacityConfig {
                enabled: row.try_get("session_capacity_enabled")?,
                max_active_sessions: optional_u32(&row, "max_active_sessions")?.unwrap_or(u32::MAX),
                idle_ttl: millis(&row, "session_idle_ttl_ms")?,
                new_session_wait: millis(&row, "new_session_wait_ms")?,
            },
            token_version: u64::try_from(row.try_get::<i64, _>("token_version")?)?,
            profile_id: CredentialProfileId::new(row.try_get::<Uuid, _>("profile_id")?.to_string())?,
            profile_epoch: u64::try_from(row.try_get::<i64, _>("profile_epoch")?)?,
            device_identity_id: DeviceIdentityId::new(row.try_get::<Uuid, _>("device_identity_id")?.to_string())?,
            device_epoch: u64::try_from(row.try_get::<i64, _>("device_epoch")?)?,
            archetype_version_id: ArchetypeVersionId::new(archetype_uuid.to_string())?,
            bundle_id: TransportBundleId::new(bundle_id)?,
            bundle_version,
            bundle_hash: Digest::parse_sha256_hex(engine.key.bundle_hash.clone())?,
            egress_binding_id: EgressBindingId::new(row.try_get::<Uuid, _>("egress_binding_id")?.to_string())?,
            egress_epoch: u64::try_from(row.try_get::<i64, _>("egress_epoch")?)?,
            bundle_epoch: bundle_version,
            quota_observation_version,
            state: CredentialState {
                lifecycle_active,
                auth_healthy,
                profile_ready: true,
                egress_ready: true,
                transport_ready,
                cooldown_until: cooldown.map(|wait| now.saturating_add(wait)),
                quota_used_basis_points,
                quota_reset_at,
                half_open_inflight: false,
            },
        });
    }
    Ok(credentials)
}

async fn load_selected_credential(
    storage: &PgStorage,
    lease: &CredentialLease,
) -> Result<SelectedCredential, DispatchError> {
    let credential_id = parse_uuid(lease.credential_id.as_str())?;
    let row = sqlx::query(
        "SELECT c.auth_kind_code,c.token_version,av.access_secret_id,av.setup_secret_id,av.console_secret_id, \
                d.session_hmac_secret_id,e.mode_code,e.id AS binding_id,e.egress_epoch, \
                pxy.id AS proxy_id,pxy.proxy_type_code,pxy.host,pxy.port,pxy.auth_secret_id, \
                bundle.id AS transport_bundle_id \
         FROM gateway.anthropic_credential c \
         JOIN gateway.credential_auth_version av ON av.id=c.active_auth_version_id \
              AND av.credential_id=c.id AND av.token_version=c.token_version AND av.material_state_code='active' \
              AND av.auth_kind_code=c.auth_kind_code \
         JOIN gateway.credential_profile profile ON profile.credential_id=c.id AND profile.lifecycle_code='active' \
         JOIN gateway.device_identity d ON d.id=profile.device_identity_id \
         JOIN gateway.credential_egress_binding e ON e.id=profile.egress_binding_id \
              AND e.lifecycle_code='active' AND e.stability_code='stable' \
         JOIN catalog.archetype_bundle_binding binding ON binding.archetype_version_id=profile.archetype_version_id \
              AND binding.state_code='active' \
         JOIN catalog.transport_bundle bundle ON bundle.id=binding.transport_bundle_id \
              AND bundle.artifact_version=$10 \
              AND COALESCE(bundle.manifest #>> '{payload,bundle_id}',bundle.manifest ->> 'bundle_id')=$11 \
              AND bundle.manifest #>> '{canonicalization,canonical_hash}'=$12 \
              AND bundle.lifecycle_code IN ('canary','active') AND bundle.evidence_gate_code='passed' \
              AND bundle.runtime_state_code='loadable' \
         LEFT JOIN gateway.proxy_endpoint pxy ON pxy.id=e.proxy_id AND pxy.lifecycle_code='active' \
              AND pxy.health_code='healthy' AND pxy.stability_code='static' \
         WHERE c.id=$1 AND c.token_version=$2 AND profile.id=$3 AND profile.profile_epoch=$4 \
           AND d.id=$5 AND d.device_epoch=$6 AND e.id=$7 AND e.egress_epoch=$8 \
           AND profile.archetype_version_id=$9 \
           AND c.lifecycle_state_code='active' AND c.auth_state_code IN ('healthy','expiring') \
           AND (c.scheduling_state_code='eligible' OR (c.scheduling_state_code='cooldown' \
                AND c.cooldown_until IS NOT NULL AND c.cooldown_until<=clock_timestamp())) \
           AND c.transport_state_code='ready'",
    )
    .bind(credential_id)
    .bind(i64::try_from(lease.token_version).map_err(|_| DispatchError::Unavailable)?)
    .bind(parse_uuid(lease.profile_id.as_str())?)
    .bind(i64::try_from(lease.profile_epoch).map_err(|_| DispatchError::Unavailable)?)
    .bind(parse_uuid(lease.device_identity_id.as_str())?)
    .bind(i64::try_from(lease.device_epoch).map_err(|_| DispatchError::Unavailable)?)
    .bind(parse_uuid(lease.egress_binding_id.as_str())?)
    .bind(i64::try_from(lease.egress_epoch).map_err(|_| DispatchError::Unavailable)?)
    .bind(parse_uuid(lease.archetype_version_id.as_str())?)
    .bind(i64::try_from(lease.bundle_version).map_err(|_| DispatchError::Unavailable)?)
    .bind(lease.bundle_id.as_str())
    .bind(lease.bundle_hash.as_str())
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| DispatchError::Unavailable)?
    .ok_or(DispatchError::DeterministicUnavailable)?;
    let auth_kind: String = row.try_get("auth_kind_code").map_err(|_| DispatchError::Unavailable)?;
    let auth_secret_id = match auth_kind.as_str() {
        "oauth_subscription" => row.try_get::<Option<Uuid>, _>("access_secret_id"),
        "setup_token_subscription" => row.try_get::<Option<Uuid>, _>("access_secret_id").and_then(|access| {
            if access.is_some() {
                Ok(access)
            } else {
                row.try_get::<Option<Uuid>, _>("setup_secret_id")
            }
        }),
        "console_api_key" => row.try_get::<Option<Uuid>, _>("console_secret_id"),
        _ => return Err(DispatchError::DeterministicUnavailable),
    }
    .map_err(|_| DispatchError::Unavailable)?
    .ok_or(DispatchError::DeterministicUnavailable)?;
    let auth_secret = decrypt_secret(storage, auth_secret_id).await?;
    let session_hmac = decrypt_secret(
        storage,
        row.try_get("session_hmac_secret_id")
            .map_err(|_| DispatchError::Unavailable)?,
    )
    .await?;
    let mode: String = row.try_get("mode_code").map_err(|_| DispatchError::Unavailable)?;
    let (egress, proxy_endpoint_id) = if mode == "direct" {
        (EgressRouteSnapshot::Direct, None)
    } else {
        let proxy_id: Uuid = row
            .try_get::<Option<Uuid>, _>("proxy_id")
            .map_err(|_| DispatchError::Unavailable)?
            .ok_or(DispatchError::DeterministicUnavailable)?;
        let credentials = match row
            .try_get::<Option<Uuid>, _>("auth_secret_id")
            .map_err(|_| DispatchError::Unavailable)?
        {
            Some(secret_id) => {
                let secret = decrypt_secret(storage, secret_id).await?;
                Some(Arc::new(parse_proxy_credentials(&secret)?))
            }
            None => None,
        };
        let host: String = row.try_get("host").map_err(|_| DispatchError::Unavailable)?;
        let port = u16::try_from(row.try_get::<i32, _>("port").map_err(|_| DispatchError::Unavailable)?)
            .map_err(|_| DispatchError::DeterministicUnavailable)?;
        let route = match row
            .try_get::<String, _>("proxy_type_code")
            .map_err(|_| DispatchError::Unavailable)?
            .as_str()
        {
            "http_connect" | "connect" => EgressRouteSnapshot::HttpConnect {
                host: host.into_boxed_str(),
                port,
                credentials,
            },
            "socks5" => EgressRouteSnapshot::Socks5 {
                host: host.into_boxed_str(),
                port,
                dns: Socks5DnsMode::Remote,
                credentials,
            },
            _ => return Err(DispatchError::DeterministicUnavailable),
        };
        (
            route,
            Some(ProxyEndpointId::new(proxy_id.to_string()).map_err(|_| DispatchError::Unavailable)?),
        )
    };
    Ok(SelectedCredential {
        auth_kind: auth_kind.into_boxed_str(),
        auth_secret,
        session_hmac,
        egress,
        proxy_endpoint_id,
        transport_bundle_id: row
            .try_get("transport_bundle_id")
            .map_err(|_| DispatchError::Unavailable)?,
    })
}

async fn decrypt_secret(storage: &PgStorage, secret_id: Uuid) -> Result<SecretBytes, DispatchError> {
    let row = sqlx::query(
        "SELECT secret_kind_code,provider_role_code,ciphertext,nonce,wrapped_dek,key_version,aad_schema_version, \
                owner_type_code,owner_id,purpose_code \
         FROM security.encrypted_secret WHERE id=$1 AND destroyed_at IS NULL",
    )
    .bind(secret_id)
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| DispatchError::Unavailable)?
    .ok_or(DispatchError::DeterministicUnavailable)?;
    let key_version: i64 = row.try_get("key_version").map_err(|_| DispatchError::Unavailable)?;
    let key = storage
        .load_database_business_key(key_version)
        .await
        .map_err(|_| DispatchError::Unavailable)?;
    let provider = LocalAesKeyProvider::new(
        "business",
        u64::try_from(key_version).map_err(|_| DispatchError::Unavailable)?,
        key.expose().to_vec(),
    )
    .map_err(|_| DispatchError::Unavailable)?;
    let schema_version = u32::try_from(
        row.try_get::<i32, _>("aad_schema_version")
            .map_err(|_| DispatchError::Unavailable)?,
    )
    .map_err(|_| DispatchError::Unavailable)?;
    let aad = EnvelopeAad {
        schema_version,
        secret_id,
        secret_kind: row
            .try_get("secret_kind_code")
            .map_err(|_| DispatchError::Unavailable)?,
        provider_role: row
            .try_get("provider_role_code")
            .map_err(|_| DispatchError::Unavailable)?,
        owner_type: row.try_get("owner_type_code").map_err(|_| DispatchError::Unavailable)?,
        owner_id: row.try_get("owner_id").map_err(|_| DispatchError::Unavailable)?,
        purpose: row.try_get("purpose_code").map_err(|_| DispatchError::Unavailable)?,
        key_version: u64::try_from(key_version).map_err(|_| DispatchError::Unavailable)?,
    };
    let envelope = SecretEnvelope {
        schema_version,
        cipher_suite: "aes_256_gcm".to_owned(),
        provider_role: "business".to_owned(),
        key_version: aad.key_version,
        ciphertext_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("ciphertext")
                .map_err(|_| DispatchError::Unavailable)?,
        ),
        nonce_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("nonce")
                .map_err(|_| DispatchError::Unavailable)?,
        ),
        wrapped_dek_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("wrapped_dek")
                .map_err(|_| DispatchError::Unavailable)?,
        ),
    };
    EnvelopeService::new(provider)
        .decrypt(&envelope, &aad)
        .map_err(|_| DispatchError::Unavailable)
}

fn build_final_request(
    request: &DispatchRequest,
    selected: &SelectedCredential,
    engine: &gateway_transport::CompiledTransportEngine,
    session_id: &str,
) -> Result<FinalUpstreamRequest, DispatchError> {
    let auth =
        std::str::from_utf8(selected.auth_secret.expose()).map_err(|_| DispatchError::DeterministicUnavailable)?;
    if auth.is_empty() || auth.contains(['\r', '\n']) {
        return Err(DispatchError::DeterministicUnavailable);
    }
    let authorization = if selected.auth_kind.as_ref() == "console_api_key" {
        auth.to_owned()
    } else {
        format!("Bearer {auth}")
    };
    let anthropic_version = request.anthropic_version.as_deref().unwrap_or("2023-06-01");
    let anthropic_beta = request.anthropic_beta.as_deref().unwrap_or("");
    let mut headers = Vec::with_capacity(engine.headers.len());
    let mut auth_seen = false;
    for template in engine.headers.iter() {
        let canonical = template.name.to_ascii_lowercase();
        if matches!(
            canonical.as_str(),
            "connection"
                | "proxy-connection"
                | "proxy-authorization"
                | "forwarded"
                | "host-forwarded"
                | "x-forwarded-host"
        ) {
            return Err(DispatchError::DeterministicUnavailable);
        }
        let value = render_template(
            &template.value_template,
            &engine.authority,
            &authorization,
            session_id,
            anthropic_version,
            anthropic_beta,
        )?;
        if canonical == "authorization" || canonical == "x-api-key" {
            let expected = if selected.auth_kind.as_ref() == "console_api_key" {
                "x-api-key"
            } else {
                "authorization"
            };
            if canonical != expected || auth_seen {
                return Err(DispatchError::DeterministicUnavailable);
            }
            auth_seen = true;
        }
        headers.push(UpstreamHeader {
            name: template.name.clone(),
            value: Arc::from(value.into_bytes()),
        });
    }
    if !auth_seen {
        return Err(DispatchError::DeterministicUnavailable);
    }
    Ok(FinalUpstreamRequest {
        method: "POST".into(),
        scheme: "https".into(),
        authority: engine.authority.clone(),
        path_and_query: if selected.auth_kind.as_ref() == "console_api_key" {
            "/v1/messages".into()
        } else {
            "/v1/messages?beta=true".into()
        },
        headers: headers.into(),
        body: Arc::from(request.generic.replay_body.bytes()),
        stream: request.generic.stream,
    })
}

fn render_template(
    template: &str,
    authority: &str,
    authorization: &str,
    session_id: &str,
    anthropic_version: &str,
    anthropic_beta: &str,
) -> Result<String, DispatchError> {
    let mut rendered = template.to_owned();
    for (token, value) in [
        ("{authority}", authority),
        ("{authorization}", authorization),
        ("{session_id}", session_id),
        ("{anthropic_version}", anthropic_version),
        ("{anthropic_beta}", anthropic_beta),
        ("{content_type}", "application/json"),
    ] {
        rendered = rendered.replace(token, value);
    }
    if rendered.contains(['{', '}', '\r', '\n']) {
        return Err(DispatchError::DeterministicUnavailable);
    }
    Ok(rendered)
}

fn derive_session_id(secret: &SecretBytes, base_session: &str, agent: &str) -> Result<String, DispatchError> {
    let mut hmac = HmacSha256::new_from_slice(secret.expose()).map_err(|_| DispatchError::DeterministicUnavailable)?;
    hmac.update(b"gateway-credential-session-v1\0");
    hmac.update(base_session.as_bytes());
    hmac.update(b"\0");
    hmac.update(agent.as_bytes());
    let digest = hmac.finalize().into_bytes();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes).to_string())
}

enum ResponseAuditEvent {
    Body(Bytes),
    Finished(bool),
}

struct ResponseAuditTap {
    sender: Option<mpsc::Sender<ResponseAuditEvent>>,
    gap: Arc<AtomicBool>,
    truncated: Arc<AtomicBool>,
    observed: usize,
    limit: usize,
    finished: bool,
}

impl ResponseSideWriter for ResponseAuditTap {
    fn observe(&mut self, bytes: &Bytes) {
        if self.finished || self.gap.load(Ordering::Acquire) {
            return;
        }
        let remaining = self.limit.saturating_sub(self.observed);
        if bytes.len() > remaining {
            self.truncated.store(true, Ordering::Release);
        }
        let mut captured = bytes.slice(..bytes.len().min(remaining));
        self.observed = self.observed.saturating_add(captured.len());
        while !captured.is_empty() {
            let chunk = captured.split_to(captured.len().min(64 * 1024));
            let Some(sender) = &self.sender else {
                self.gap.store(true, Ordering::Release);
                return;
            };
            if sender.try_send(ResponseAuditEvent::Body(chunk)).is_err() {
                self.gap.store(true, Ordering::Release);
                self.sender.take();
                return;
            }
        }
    }

    fn finish(&mut self, complete: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(sender) = self.sender.take()
            && sender.try_send(ResponseAuditEvent::Finished(complete)).is_err()
        {
            self.gap.store(true, Ordering::Release);
        }
    }
}

impl Drop for ResponseAuditTap {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(false);
        }
    }
}

fn response_audit_channel(
    limit: usize,
) -> (
    ResponseAuditTap,
    mpsc::Receiver<ResponseAuditEvent>,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
) {
    let (sender, receiver) = mpsc::channel(16);
    let gap = Arc::new(AtomicBool::new(false));
    let truncated = Arc::new(AtomicBool::new(false));
    (
        ResponseAuditTap {
            sender: Some(sender),
            gap: gap.clone(),
            truncated: truncated.clone(),
            observed: 0,
            limit,
            finished: false,
        },
        receiver,
        gap,
        truncated,
    )
}

struct ResponseAuditTask {
    storage: Arc<PgStorage>,
    store: Arc<ContentAuditStore>,
    request_id: Uuid,
    owner_user_id: Uuid,
    policy_version: Box<str>,
    retention_days: u16,
    latch: Arc<Mutex<ContentAuditLatch>>,
    receiver: mpsc::Receiver<ResponseAuditEvent>,
    gap: Arc<AtomicBool>,
    truncated: Arc<AtomicBool>,
}

struct ResponseAuditHandle {
    request_id: Uuid,
    latch: Option<Arc<Mutex<ContentAuditLatch>>>,
    handle: tokio::task::JoinHandle<()>,
}

fn spawn_response_content_audit(mut task: ResponseAuditTask) -> ResponseAuditHandle {
    let request_id = task.request_id;
    let latch = task.latch.clone();
    let handle = tokio::spawn(async move {
        let mut captured = Vec::new();
        let mut complete = false;
        while let Some(event) = task.receiver.recv().await {
            match event {
                ResponseAuditEvent::Body(bytes) => captured.extend_from_slice(&bytes),
                ResponseAuditEvent::Finished(value) => {
                    complete = value;
                    break;
                }
            }
        }
        let context = AuditObjectContext {
            object_id: Uuid::now_v7(),
            request_id: task.request_id,
            attempt_id: None,
            kind: AuditCaptureKind::Response,
            policy_version: task.policy_version.clone(),
        };
        let truncated = task.truncated.load(Ordering::Acquire);
        if truncated {
            captured.push(0);
        }
        let store_result = task.store.put(&context, &captured).await;
        if truncated {
            captured.pop();
        }
        let persisted = match store_result {
            Ok(manifest) => {
                let result = persist_content_manifest(
                    &task.storage,
                    task.request_id,
                    task.owner_user_id,
                    AuditCaptureKind::Response,
                    &task.policy_version,
                    &captured,
                    &manifest,
                    task.retention_days,
                    complete && !truncated && !task.gap.load(Ordering::Acquire),
                )
                .await;
                if result.is_err() {
                    let _ = task.store.remove_finalized(&manifest).await;
                }
                result.is_ok()
            }
            Err(_) => false,
        };
        if !persisted || !complete || truncated || task.gap.load(Ordering::Acquire) {
            record_response_audit_gap(&task.storage, task.request_id, &task.latch).await;
        }
    });
    ResponseAuditHandle {
        request_id,
        latch: Some(latch),
        handle,
    }
}

async fn record_response_audit_gap(storage: &PgStorage, request_id: Uuid, latch: &Arc<Mutex<ContentAuditLatch>>) {
    let _ = latch.lock().await.side_writer_failed();
    tracing::error!(
        event = "audit_gap",
        severity = "critical",
        capture_kind = "upstream_response",
        request_id = %request_id,
        reason_code = "response_side_writer_failed"
    );
    let _ = sqlx::query(
        "INSERT INTO ops.alert \
         (id,fingerprint,severity_code,type_code,state_code,object_type_code,object_id,summary,detail,first_seen_at,last_seen_at,revision) \
         VALUES ($1,$2,'critical','audit_gap','open','request',$3,'Encrypted response audit has a capture gap', \
                 jsonb_build_object('reason_code','response_side_writer_failed'),clock_timestamp(),clock_timestamp(),1) \
         ON CONFLICT (fingerprint) WHERE state_code IN ('open','acknowledged','silenced') \
         DO UPDATE SET last_seen_at=clock_timestamp(),revision=ops.alert.revision+1",
    )
    .bind(Uuid::now_v7())
    .bind(format!("audit_gap:{request_id}"))
    .bind(request_id.to_string())
    .execute(&storage.pool())
    .await;
}

#[derive(Deserialize)]
struct ProxySecretDocument {
    username: String,
    password: String,
}

fn parse_proxy_credentials(secret: &SecretBytes) -> Result<ProxyCredentials, DispatchError> {
    let text = std::str::from_utf8(secret.expose()).map_err(|_| DispatchError::DeterministicUnavailable)?;
    let (username, password) = if let Ok(document) = serde_json::from_str::<ProxySecretDocument>(text) {
        (document.username, document.password)
    } else {
        let (username, password) = text.split_once(':').ok_or(DispatchError::DeterministicUnavailable)?;
        (username.to_owned(), password.to_owned())
    };
    if username.is_empty() || username.contains(['\r', '\n']) || password.contains(['\r', '\n']) {
        return Err(DispatchError::DeterministicUnavailable);
    }
    Ok(ProxyCredentials {
        username: SecretValue::new(username),
        password: SecretValue::new(password),
    })
}

#[allow(clippy::too_many_arguments)]
async fn capture_content(
    storage: &PgStorage,
    store: &ContentAuditStore,
    request_id: Uuid,
    owner_user_id: Uuid,
    kind: AuditCaptureKind,
    body: &[u8],
    policy_version: &str,
    retention_days: u16,
) -> Result<(), DispatchError> {
    let context = AuditObjectContext {
        object_id: Uuid::now_v7(),
        request_id,
        attempt_id: None,
        kind,
        policy_version: policy_version.to_owned().into_boxed_str(),
    };
    let manifest = store
        .put(&context, body)
        .await
        .map_err(|_| DispatchError::AuditUnavailable { retry_after_seconds: 5 })?;
    let result = persist_content_manifest(
        storage,
        request_id,
        owner_user_id,
        kind,
        policy_version,
        body,
        &manifest,
        retention_days,
        true,
    )
    .await;
    if result.is_err() {
        let _ = store.remove_finalized(&manifest).await;
    }
    result.map_err(|_| DispatchError::AuditUnavailable { retry_after_seconds: 5 })
}

#[allow(clippy::too_many_arguments)]
async fn persist_content_manifest(
    storage: &PgStorage,
    request_id: Uuid,
    owner_user_id: Uuid,
    kind: AuditCaptureKind,
    policy_version: &str,
    body: &[u8],
    manifest: &AuditObjectManifest,
    retention_days: u16,
    capture_complete: bool,
) -> Result<(), DispatchError> {
    let wrapped_dek = STANDARD
        .decode(manifest.wrapped_dek_base64.as_bytes())
        .map_err(|_| DispatchError::Unavailable)?;
    let persisted_length = usize::try_from(manifest.plaintext_length).map_err(|_| DispatchError::Unavailable)?;
    let persisted = body.get(..persisted_length).ok_or(DispatchError::Unavailable)?;
    let content_hash: [u8; 32] = Sha256::digest(persisted).into();
    let object_kind = match kind {
        AuditCaptureKind::OriginalRequest => "original_request",
        AuditCaptureKind::FinalRequest => "final_upstream_request",
        AuditCaptureKind::Response => "upstream_response",
    };
    sqlx::query(
        "INSERT INTO security.content_audit_object \
          (id,request_month,request_id,owner_user_id,scope_code,object_uri,encrypted_dek,key_version,content_sha256, \
           content_length,state_code,expires_at,created_at,storage_state_code,cipher_suite_code,frame_manifest,finalized_at, \
           platform_key_id,group_id,object_kind_code) \
          VALUES ($1,date_trunc('month',clock_timestamp())::date,$2,$3,'full_encrypted',$4,$5,1,$6,$7, \
                  'active',clock_timestamp()+make_interval(days=>$8),clock_timestamp(),'finalized','aes_256_gcm_framed',$9,clock_timestamp(), \
                  (SELECT platform_key_id FROM telemetry.request_record WHERE request_month=date_trunc('month',clock_timestamp())::date AND request_id=$2), \
                  (SELECT group_id FROM telemetry.request_record WHERE request_month=date_trunc('month',clock_timestamp())::date AND request_id=$2),$10)",
    )
    .bind(manifest.object_id)
    .bind(request_id)
    .bind(owner_user_id)
    .bind(manifest.object_uri.as_ref())
    .bind(wrapped_dek)
    .bind(content_hash.as_slice())
    .bind(i64::try_from(persisted.len()).map_err(|_| DispatchError::Unavailable)?)
    .bind(i32::from(retention_days))
    .bind(json!({
        "capture_kind": kind.as_code(),
        "policy_version": policy_version,
        "capture_complete": capture_complete,
        "manifest": manifest
    }))
    .bind(object_kind)
    .execute(&storage.pool())
    .await
    .map_err(|_| DispatchError::Unavailable)?;
    Ok(())
}

fn map_rejection(rejection: &Rejection, limits: RuntimeRequestLimits) -> DispatchError {
    let scheduler_retry_seconds = rejection.retry_after.map_or(1, |value| value.as_secs().max(1));
    match rejection.kind {
        RejectionKind::QueueFull => DispatchError::QueueFull {
            retry_after_seconds: rejection.retry_after.map_or_else(
                || retry_after_seconds(limits.queue_full_retry_after),
                |value| value.as_secs().max(1),
            ),
        },
        RejectionKind::GroupRateDeadline => DispatchError::GroupRateLimited {
            retry_after_seconds: scheduler_retry_seconds,
        },
        RejectionKind::CooldownBeyondDeadline => DispatchError::CredentialCooldown {
            retry_after_seconds: scheduler_retry_seconds,
        },
        RejectionKind::TimedOut | RejectionKind::SessionCapacityDeadline => DispatchError::PreUpstreamTimeout {
            retry_after_seconds: retry_after_seconds(limits.queue_wait_retry_after),
        },
        RejectionKind::Cancelled => DispatchError::Cancelled,
        RejectionKind::GroupUnavailable | RejectionKind::DuplicateRequest => DispatchError::DeterministicUnavailable,
    }
}

fn map_transport_error(error: &gateway_transport::TransportError) -> DispatchError {
    match error.code {
        TransportErrorCode::Timeout => DispatchError::DeadlineExceeded,
        TransportErrorCode::Cancelled | TransportErrorCode::CancelGraceExpired => DispatchError::Cancelled,
        TransportErrorCode::EngineUnavailable
        | TransportErrorCode::BundleRejected
        | TransportErrorCode::AlpnMismatch
        | TransportErrorCode::InternalInvariant => DispatchError::DeterministicUnavailable,
        _ => DispatchError::Unavailable,
    }
}

fn transport_error_code(code: TransportErrorCode) -> &'static str {
    match code {
        TransportErrorCode::EngineUnavailable => "engine_unavailable",
        TransportErrorCode::BundleRejected => "bundle_rejected",
        TransportErrorCode::ResolverFailure => "resolver_failure",
        TransportErrorCode::TcpConnectFailure => "tcp_connect_failure",
        TransportErrorCode::ProxyAuthentication => "proxy_authentication",
        TransportErrorCode::ProxyProtocol => "proxy_protocol",
        TransportErrorCode::TlsCertificate => "tls_certificate",
        TransportErrorCode::TlsHandshake => "tls_handshake",
        TransportErrorCode::AlpnMismatch => "alpn_mismatch",
        TransportErrorCode::H1Framing => "h1_framing",
        TransportErrorCode::H2Protocol => "h2_protocol",
        TransportErrorCode::Timeout => "timeout",
        TransportErrorCode::Cancelled => "cancelled",
        TransportErrorCode::CancelGraceExpired => "cancel_grace_expired",
        TransportErrorCode::InternalInvariant => "internal_invariant",
    }
}

fn map_response_error(error: &ResponseError) -> DispatchError {
    match error {
        ResponseError::ResponseTotalTimeout => DispatchError::DeadlineExceeded,
        ResponseError::Transport(error) => map_transport_error(error),
        ResponseError::Cancelled | ResponseError::ClientDisconnected => DispatchError::Cancelled,
        _ => DispatchError::Unavailable,
    }
}

fn retry_error_class_for_status(status: u16) -> Option<RetryErrorClass> {
    match status {
        401 => Some(RetryErrorClass::Authentication401),
        429 => Some(RetryErrorClass::RateLimited429),
        529 => Some(RetryErrorClass::Overloaded529),
        500 | 502 | 503 | 504 => Some(RetryErrorClass::Upstream5xx),
        _ => None,
    }
}

fn retry_backoff(status: u16, messages_attempts: u8, request_id: Uuid, retry_after: Duration) -> Duration {
    if status == 429 {
        return retry_after;
    }
    if !matches!(status, 500 | 502 | 503 | 504 | 529) {
        return Duration::ZERO;
    }
    let exponent = u32::from(messages_attempts.saturating_sub(1).min(3));
    let base_ms = 100_u64.saturating_mul(1_u64 << exponent);
    let jitter_percent = 50_u64.saturating_add(u64::from(request_id.as_bytes()[15]) % 101);
    Duration::from_millis(base_ms.saturating_mul(jitter_percent) / 100)
}

fn trusted_retry_after(response: &RawUpstreamResponse) -> Option<Duration> {
    trusted_retry_after_headers(&response.headers)
}

fn trusted_retry_after_headers(headers: &[(Box<str>, Bytes)]) -> Option<Duration> {
    let values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return None;
    }
    let text = std::str::from_utf8(&values[0].1).ok()?.trim();
    let seconds = text.parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds.clamp(1, 900)))
}

async fn observe_subscription_quota_headers(
    storage: &PgStorage,
    group: &RuntimeGroup,
    credential_id: &CredentialId,
    headers: &[(Box<str>, Bytes)],
    now: Duration,
) {
    let parsed = parse_subscription_quota_headers(headers);
    if parsed.rejected_windows > 0 {
        tracing::warn!(
            event = "subscription_quota_header_rejected",
            credential_id = %credential_id,
            parser_version = SUBSCRIPTION_QUOTA_PARSER_VERSION,
            rejected_windows = parsed.rejected_windows
        );
    }
    if parsed.observations.is_empty() {
        return;
    }
    let Ok(credential_uuid) = parse_uuid(credential_id.as_str()) else {
        return;
    };
    let observations = parsed
        .observations
        .into_iter()
        .map(|observation| QuotaObservationPersist {
            observation_id: Uuid::now_v7(),
            window_kind_code: observation.window.code().into(),
            utilization_nanos: observation.utilization_nanos,
            reset_epoch_seconds: observation.reset_epoch_seconds,
            header_digest: observation.header_digest.to_vec(),
            parser_version: SUBSCRIPTION_QUOTA_PARSER_VERSION.into(),
        })
        .collect::<Vec<_>>();
    match storage
        .persist_credential_quota_observations(credential_uuid, &observations)
        .await
    {
        Ok(Some(projection)) => {
            let _ = group
                .observe_credential_quota(CredentialQuotaUpdate {
                    credential_id: credential_id.clone(),
                    observation_version: projection.observation_version.as_u128(),
                    used_basis_points: projection.used_basis_points,
                    reset_at: now.saturating_add(projection.reset_after),
                })
                .await;
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(
            event = "subscription_quota_persist_failed",
            credential_id = %credential_id,
            ?error
        ),
    }
}

async fn persist_rate_limit_cooldown(
    storage: &PgStorage,
    telemetry: &AttemptTelemetry,
    trusted_retry_after: Option<Duration>,
) -> Result<Duration, DispatchError> {
    let explicit_seconds = trusted_retry_after
        .map(|duration| i64::try_from(duration.as_secs()))
        .transpose()
        .map_err(|_| DispatchError::Unavailable)?;
    let mut transaction = storage.pool().begin().await.map_err(|_| DispatchError::Unavailable)?;
    let row = sqlx::query(
        "UPDATE gateway.anthropic_credential \
         SET consecutive_cooldown_count=LEAST(consecutive_cooldown_count+1,4), \
             cooldown_until=clock_timestamp() + \
               (COALESCE($2::bigint,CASE consecutive_cooldown_count WHEN 0 THEN 60 WHEN 1 THEN 120 \
                 WHEN 2 THEN 300 ELSE 900 END) * interval '1 second'), \
             scheduling_state_code='cooldown',capacity_state_code='cooldown', \
             revision=revision+1,updated_at=clock_timestamp() \
         WHERE id=$1 AND lifecycle_state_code='active' \
         RETURNING CEIL(EXTRACT(EPOCH FROM (cooldown_until-clock_timestamp())))::bigint AS cooldown_seconds",
    )
    .bind(telemetry.credential_id)
    .bind(explicit_seconds)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| DispatchError::Unavailable)?
    .ok_or(DispatchError::Unavailable)?;
    let seconds = row
        .try_get::<i64, _>("cooldown_seconds")
        .map_err(|_| DispatchError::Unavailable)?
        .clamp(1, 900);
    sqlx::query(
        "INSERT INTO telemetry.credential_cooldown_event \
         (id,credential_id,reason_code,started_at,cooldown_until,source_attempt_id) \
         VALUES ($1,$2,'rate_limit',clock_timestamp(),clock_timestamp()+($3::bigint*interval '1 second'),$4)",
    )
    .bind(Uuid::now_v7())
    .bind(telemetry.credential_id)
    .bind(seconds)
    .bind(telemetry.attempt_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| DispatchError::Unavailable)?;
    transaction.commit().await.map_err(|_| DispatchError::Unavailable)?;
    Ok(Duration::from_secs(
        u64::try_from(seconds).map_err(|_| DispatchError::Unavailable)?,
    ))
}

async fn clear_rate_limit_cooldown(storage: &PgStorage, credential_id: Uuid) -> Result<bool, sqlx::Error> {
    let mut transaction = storage.pool().begin().await?;
    let updated = sqlx::query(
        "UPDATE gateway.anthropic_credential \
         SET consecutive_cooldown_count=0,cooldown_until=NULL, \
             scheduling_state_code=CASE WHEN scheduling_state_code='cooldown' THEN 'eligible' ELSE scheduling_state_code END, \
             capacity_state_code=CASE WHEN capacity_state_code='cooldown' THEN 'available' ELSE capacity_state_code END, \
             revision=revision+1,updated_at=clock_timestamp() \
         WHERE id=$1 AND (consecutive_cooldown_count>0 OR cooldown_until IS NOT NULL)",
    )
    .bind(credential_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        > 0;
    if updated {
        sqlx::query(
            "UPDATE telemetry.credential_cooldown_event SET cleared_at=clock_timestamp() \
             WHERE credential_id=$1 AND cleared_at IS NULL",
        )
        .bind(credential_id)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(updated)
}

async fn discard_raw_response(response: RawUpstreamResponse, cancellation: &CancellationToken) -> bool {
    cancellation.cancel();
    let mut receiver = match response.body {
        RawResponseBody::Sse(receiver) | RawResponseBody::NonStream(receiver) => receiver,
    };
    let drained = tokio::time::timeout(Duration::from_secs(2), async {
        while receiver.recv().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!(event = "retry_response_drain_timeout");
        false
    } else {
        true
    }
}

fn map_retry_status(status: u16, retry_after: Duration) -> DispatchError {
    match status {
        429 => DispatchError::CredentialCooldown {
            retry_after_seconds: if retry_after.is_zero() {
                60
            } else {
                retry_after.as_secs().max(1)
            },
        },
        500 | 502 | 503 | 504 | 529 => DispatchError::Overloaded {
            retry_after_seconds: retry_after.as_secs().max(1),
        },
        _ => DispatchError::Unavailable,
    }
}

fn known_usage_field_mask(usage: &gateway_domain::UsageObservation) -> i32 {
    i32::from(usage.counts.input_tokens.is_some())
        | (i32::from(usage.counts.output_tokens.is_some()) << 1)
        | (i32::from(usage.counts.cache_creation_input_tokens.is_some()) << 2)
        | (i32::from(usage.counts.cache_read_input_tokens.is_some()) << 3)
}

fn estimate_cancel_input_tokens(generic_request_bytes: &[u8]) -> u64 {
    u64::try_from(generic_request_bytes.len())
        .unwrap_or(u64::MAX)
        .saturating_add(3)
        / 4
}

fn decimal_usd_to_pico_text(value: &str) -> Option<Box<str>> {
    const SCALE: u128 = 1_000_000_000_000;
    let (whole, fractional) = value.split_once('.').map_or((value, ""), |parts| parts);
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.len() > 12
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let whole = whole.parse::<u128>().ok()?.checked_mul(SCALE)?;
    let fractional = if fractional.is_empty() {
        0
    } else {
        fractional
            .parse::<u128>()
            .ok()?
            .checked_mul(10_u128.pow(u32::try_from(12 - fractional.len()).ok()?))?
    };
    whole
        .checked_add(fractional)
        .map(|value| value.to_string().into_boxed_str())
}

fn request_uuid(request: &DispatchRequest) -> Result<Uuid, DispatchError> {
    parse_uuid(
        request
            .request_id
            .as_str()
            .strip_prefix("req_")
            .unwrap_or(request.request_id.as_str()),
    )
}

fn scheduler_resource_record(
    group_id: Uuid,
    event: &ResourceEvent,
) -> Result<SchedulerResourceEventRecord, DispatchError> {
    let request_id = Uuid::parse_str(
        event
            .request_id
            .as_str()
            .strip_prefix("req_")
            .unwrap_or(event.request_id.as_str()),
    )
    .map_err(|_| DispatchError::Unavailable)?;
    let mut digest = Sha256::new();
    digest.update(b"gateway-scheduler-resource-event-v1\0");
    digest.update(group_id.as_bytes());
    digest.update(event.generation.get().to_be_bytes());
    digest.update(event.sequence.to_be_bytes());
    let digest = digest.finalize();
    let mut event_bytes = [0_u8; 16];
    event_bytes.copy_from_slice(&digest[..16]);
    event_bytes[6] = (event_bytes[6] & 0x0f) | 0x80;
    event_bytes[8] = (event_bytes[8] & 0x3f) | 0x80;
    Ok(SchedulerResourceEventRecord {
        event_id: Uuid::from_bytes(event_bytes),
        request_id,
        resource_kind_code: match event.resource_kind {
            ResourceKind::GroupPermit => "group_permit",
            ResourceKind::QueueTicket => "queue_ticket",
            ResourceKind::SessionClaim => "session_claim",
            ResourceKind::CredentialLease => "credential_lease",
        }
        .into(),
        resource_token_id: Some(event.resource_id.to_string()),
        action_code: match event.action {
            ResourceAction::Acquire => "acquire",
            ResourceAction::Release => "release",
            ResourceAction::ForcedRelease => "forced_release",
        }
        .into(),
        portability_code: match &event.portability {
            Portability::Portable => "portable",
            Portability::Pinned { reasons, .. }
                if reasons
                    .iter()
                    .any(|reason| matches!(reason, PinReason::UnknownExtension)) =>
            {
                "unknown"
            }
            Portability::Pinned { .. } => "account_bound",
        }
        .into(),
        owner_generation: i64::try_from(event.generation.get()).map_err(|_| DispatchError::Unavailable)?,
        event_sequence: i64::try_from(event.sequence).map_err(|_| DispatchError::Unavailable)?,
        release_reason_code: (event.action == ResourceAction::ForcedRelease).then(|| "forced_release".into()),
    })
}

fn parse_uuid(value: &str) -> Result<Uuid, DispatchError> {
    Uuid::parse_str(value).map_err(|_| DispatchError::Unavailable)
}

fn optional_u32(row: &sqlx::postgres::PgRow, column: &str) -> anyhow::Result<Option<u32>> {
    row.try_get::<Option<i32>, _>(column)?
        .map(u32::try_from)
        .transpose()
        .map_err(Into::into)
}

fn optional_usize(row: &sqlx::postgres::PgRow, column: &str) -> anyhow::Result<Option<usize>> {
    row.try_get::<Option<i32>, _>(column)?
        .map(usize::try_from)
        .transpose()
        .map_err(Into::into)
}

fn millis(row: &sqlx::postgres::PgRow, column: &str) -> anyhow::Result<Duration> {
    Ok(Duration::from_millis(u64::try_from(row.try_get::<i64, _>(column)?)?))
}

fn duration_millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

fn retry_after_seconds(value: Duration) -> u64 {
    u64::try_from(value.as_millis().div_ceil(1000))
        .unwrap_or(u64::MAX)
        .max(1)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use gateway_domain::{Clock, HttpProtocol, SecretBytes, SecretValue, SystemClock, TransportBundleId};
    use gateway_storage::{PgStorage, RuntimeRolePolicy, embedded_migration_count};
    use gateway_transport::{
        ActivationGeneration, CompiledApplicationProfile, CompiledTransportEngine, EngineCatalog, EngineCatalogHandle,
        EngineKey, Http1Profile, NoopTransportCore, TlsProfile,
    };
    use sqlx::Row as _;
    use uuid::Uuid;

    use super::{
        ProductionDispatcher, decimal_usd_to_pico_text, derive_session_id, render_template, retry_backoff,
        trusted_retry_after_headers,
    };

    fn test_engine_catalog() -> Result<Arc<EngineCatalogHandle>, Box<dyn std::error::Error>> {
        let engine = CompiledTransportEngine {
            key: EngineKey {
                bundle_id: TransportBundleId::new("bundle_dynamic_group")?,
                bundle_version: 1,
                bundle_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
                engine_abi: "1.0".into(),
                backend_id: "test".into(),
                protocol: HttpProtocol::H1,
            },
            source_archetype_version_id: "archetype_dynamic_group".into(),
            capture_cohort: "test".into(),
            authority: "api.anthropic.com".into(),
            tls: TlsProfile {
                client_hello_profile: "test".into(),
                alpn: vec!["http/1.1".into()],
                cipher_suite_ids: Vec::new(),
                supported_group_ids: Vec::new(),
                key_share_group_ids: Vec::new(),
                extension_order: Vec::new(),
                grease_enabled: false,
                permute_extensions: false,
                session_resumption: false,
            },
            application: CompiledApplicationProfile::H1(Http1Profile {
                request_line_form: "origin".into(),
                header_order: Vec::new(),
                framing: "content-length".into(),
            }),
            headers: Arc::from([]),
            evidence_hashes: Arc::from([]),
        };
        Ok(Arc::new(EngineCatalogHandle::new(EngineCatalog::build(
            ActivationGeneration::INITIAL,
            [engine],
        )?)))
    }

    #[test]
    fn session_derivation_is_stable_per_base_session_and_agent() -> Result<(), Box<dyn std::error::Error>> {
        let secret = SecretBytes::new(vec![7; 32]);
        let first = derive_session_id(&secret, "session-a", "main").map_err(|_| "derive")?;
        let same = derive_session_id(&secret, "session-a", "main").map_err(|_| "derive")?;
        let subagent = derive_session_id(&secret, "session-a", "subagent-1").map_err(|_| "derive")?;
        assert_eq!(first, same);
        assert_ne!(first, subagent);
        assert_eq!(first.len(), 36);
        Ok(())
    }

    #[test]
    fn unknown_header_template_fails_closed() {
        assert!(render_template("{unknown}", "a", "b", "c", "d", "e").is_err());
    }

    #[test]
    fn retry_after_accepts_one_numeric_value_and_caps_it_at_fifteen_minutes() {
        let one = vec![(Box::from("Retry-After"), Bytes::from_static(b"1200"))];
        assert_eq!(
            trusted_retry_after_headers(&one),
            Some(std::time::Duration::from_mins(15))
        );

        let ambiguous = vec![
            (Box::from("retry-after"), Bytes::from_static(b"60")),
            (Box::from("Retry-After"), Bytes::from_static(b"120")),
        ];
        assert_eq!(trusted_retry_after_headers(&ambiguous), None);
    }

    #[test]
    fn overload_retry_backoff_is_short_bounded_and_rate_limit_uses_cooldown() {
        let request_id = uuid::Uuid::from_u128(7);
        let overload = retry_backoff(529, 2, request_id, std::time::Duration::from_secs(99));
        assert!(overload >= std::time::Duration::from_millis(100));
        assert!(overload <= std::time::Duration::from_millis(300));
        assert_eq!(
            retry_backoff(429, 1, request_id, std::time::Duration::from_mins(1)),
            std::time::Duration::from_mins(1)
        );
    }

    #[test]
    fn decimal_cost_is_converted_without_floating_point() {
        assert_eq!(decimal_usd_to_pico_text("3").as_deref(), Some("3000000000000"));
        assert_eq!(decimal_usd_to_pico_text("0.000300000000").as_deref(), Some("300000000"));
        assert_eq!(decimal_usd_to_pico_text("0.000000000001").as_deref(), Some("1"));
        assert!(decimal_usd_to_pico_text("0.0000000000001").is_none());
    }

    #[tokio::test]
    async fn active_group_is_installed_disabled_and_reactivated_without_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let Ok(database_url) = std::env::var("TEST_R4_RUNTIME_DATABASE_ADMIN_URL") else {
            return Ok(());
        };
        let database_url = SecretValue::new(database_url);
        let migration = PgStorage::migrate(&database_url).await?;
        assert_eq!(migration.applied_count, embedded_migration_count());
        let storage = Arc::new(PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let dispatcher = Arc::new(
            ProductionDispatcher::load(
                storage.clone(),
                test_engine_catalog()?,
                Arc::new(NoopTransportCore),
                std::env::temp_dir().join(format!("super-gateway-r4-runtime-{}", Uuid::now_v7())),
                clock,
                None,
                None,
            )
            .await?,
        );
        let group_id = Uuid::now_v7();
        let config_id = Uuid::now_v7();
        let mut transaction = storage.pool().begin().await?;
        sqlx::query(
            "INSERT INTO gateway.credential_group \
             (id,name,status_code,owner_generation,revision,created_at,updated_at) \
             VALUES ($1,$2,'active',1,1,clock_timestamp(),clock_timestamp())",
        )
        .bind(group_id)
        .bind(format!("dynamic-group-{group_id}"))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO gateway.group_config \
             (id,group_id,config_version,content_hash,default_rpm,queue_timeout_ms,system_prompt_mode_code,proxy_policy_code, \
              model_scope_code,created_at,default_rpm_burst,pre_upstream_wait_ms,preferred_capacity_wait_ms, \
              affinity_ttl_ms,affinity_migration_successes,quota_guard_basis_points,lifecycle_code,validation_report, \
              validated_at,published_at) \
             VALUES ($1,$2,1,$3,60,30000,'preserve','auto','all_published',clock_timestamp(),10,30000,2000, \
                     86400000,3,9500,'active','{\"valid\":true}'::jsonb,clock_timestamp(),clock_timestamp())",
        )
        .bind(config_id)
        .bind(group_id)
        .bind(vec![7_u8; 32])
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO gateway.group_active_config (group_id,config_id,revision,activated_at) \
             VALUES ($1,$2,1,clock_timestamp())",
        )
        .bind(group_id)
        .bind(config_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

        assert!(
            dispatcher
                .ensure_group_projection(group_id)
                .await
                .map_err(|_| "ensure group projection")?
        );
        assert!(
            dispatcher
                .group_capacity_projection(group_id)
                .await
                .map_err(|_| "load group capacity")?
                .is_some()
        );
        let installed = sqlx::query(
            "SELECT owner_generation,revision,owner_executor_id IS NOT NULL AS owned \
             FROM gateway.credential_group WHERE id=$1",
        )
        .bind(group_id)
        .fetch_one(&storage.pool())
        .await?;
        assert_eq!(installed.try_get::<i64, _>("owner_generation")?, 2);
        assert_eq!(installed.try_get::<i64, _>("revision")?, 1);
        assert!(installed.try_get::<bool, _>("owned")?);

        sqlx::query(
            "UPDATE gateway.credential_group SET status_code='disabled',revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1",
        )
        .bind(group_id)
        .execute(&storage.pool())
        .await?;
        dispatcher
            .reconcile_group_registry()
            .await
            .map_err(|_| "disable group runtime")?;
        assert!(
            dispatcher
                .group_capacity_projection(group_id)
                .await
                .map_err(|_| "load disabled capacity")?
                .is_none()
        );
        let disabled_owner: Option<String> =
            sqlx::query_scalar("SELECT owner_executor_id FROM gateway.credential_group WHERE id=$1")
                .bind(group_id)
                .fetch_one(&storage.pool())
                .await?;
        assert!(disabled_owner.is_none());

        sqlx::query(
            "UPDATE gateway.credential_group SET status_code='active',revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1",
        )
        .bind(group_id)
        .execute(&storage.pool())
        .await?;
        dispatcher
            .reconcile_group_registry()
            .await
            .map_err(|_| "reactivate group runtime")?;
        assert!(
            dispatcher
                .group_capacity_projection(group_id)
                .await
                .map_err(|_| "load reactivated capacity")?
                .is_some()
        );
        let reactivated = sqlx::query("SELECT owner_generation,revision FROM gateway.credential_group WHERE id=$1")
            .bind(group_id)
            .fetch_one(&storage.pool())
            .await?;
        assert_eq!(reactivated.try_get::<i64, _>("owner_generation")?, 3);
        assert_eq!(reactivated.try_get::<i64, _>("revision")?, 3);
        dispatcher.shutdown_owners().await;
        Ok(())
    }
}
