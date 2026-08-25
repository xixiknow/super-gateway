//! R9 durable workers and recurring integrity maintenance.
#![allow(
    missing_docs,
    clippy::cast_possible_truncation,
    clippy::duration_suboptimal_units,
    clippy::manual_let_else,
    clippy::manual_unwrap_or_default,
    clippy::single_match_else,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::{
    collections::BTreeSet,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[cfg(target_os = "linux")]
use axum::http::Method;
use base64::Engine as _;
#[cfg(target_os = "linux")]
use base64::engine::general_purpose::STANDARD;
use gateway_domain::SecretValue;
#[cfg(target_os = "linux")]
use gateway_domain::{EgressRouteSnapshot, SecretBytes};
use gateway_services::ReadinessCoordinator;
use gateway_services::content_audit::{AuditCaptureKind, AuditObjectContext, AuditObjectManifest, ContentAuditStore};
use gateway_services::credential::CredentialServiceError;
use gateway_services::export::{
    ExportArtifactContext, ExportArtifactStore, ExportError, ExportFormat, UsageExportRow, encode_usage_export,
    lower_hex,
};
use gateway_services::model_discovery::PgModelCatalogCollector;
use gateway_services::operations::{
    BackupOperationFailure, BackupOperationKind, BackupOperationRequest, BackupOperationResult,
    BackupOperationsExecutor, CredentialEnrollmentJobAttempt, CredentialEnrollmentJobExecutor, DEFAULT_JOB_HEARTBEAT,
    DEFAULT_JOB_LEASE, JobAttemptDecision,
};
use gateway_services::plan::PgPlanCollector;
use gateway_services::security::rewrap_database_business_batch;
#[cfg(target_os = "linux")]
use gateway_services::security::{EnvelopeAad, EnvelopeService, LocalAesKeyProvider, SecretEnvelope};
use gateway_storage::{
    BackupRunCommit, JobLease, OutboxLease, PgStorage, RestoreDrillCommit, RestoreValidationCommit, StorageError,
    UpgradeGateCommit, UpgradePreflightCommit, UsageExportArtifactCommit,
};
#[cfg(target_os = "linux")]
use gateway_storage::{EgressRebindCommit, ProxyProbeCommit};
#[cfg(target_os = "linux")]
use gateway_transport::{ProviderHttpsClient, ProviderHttpsHeader, ProviderHttpsRequest, TransportErrorCode};
#[cfg(target_os = "linux")]
use serde::Deserialize;
use serde_json::json;
use sha2::Digest as _;
use sqlx::Row as _;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::Command,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::production_dispatcher::ProductionDispatcher;
#[cfg(target_os = "linux")]
use crate::provider_http::resolve_proxy_route;
pub(crate) type ManagedBrowserExecutor = crate::managed_browser::CommandManagedBrowserExecutor;

const WORKER_LEASE_SECONDS: i32 = DEFAULT_JOB_LEASE.as_secs() as i32;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct ServerChan3Target {
    host: Box<str>,
    path: SecretValue,
}

pub(crate) fn serverchan3_target(send_key: &str) -> Result<ServerChan3Target, ()> {
    if send_key.len() < 8 || send_key.len() > 512 || !send_key.starts_with("sctp") || !send_key.is_ascii() {
        return Err(());
    }
    let suffix = &send_key[4..];
    let separator = suffix.find('t').ok_or(())?;
    let (uid, token_with_separator) = suffix.split_at(separator);
    let token = token_with_separator.strip_prefix('t').ok_or(())?;
    if uid.is_empty()
        || uid.len() > 20
        || !uid.bytes().all(|value| value.is_ascii_digit())
        || token.len() < 3
        || !token
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
    {
        return Err(());
    }
    Ok(ServerChan3Target {
        host: format!("{uid}.push.ft07.com").into_boxed_str(),
        path: SecretValue::new(format!("/send/{send_key}.send")),
    })
}

#[derive(Clone)]
pub struct CommandBackupOperationsExecutor {
    tool: PathBuf,
    key_file: PathBuf,
    repository: String,
}

impl CommandBackupOperationsExecutor {
    pub fn new(tool: PathBuf, key_file: PathBuf, repository: String) -> Self {
        Self {
            tool,
            key_file,
            repository,
        }
    }
}

#[async_trait::async_trait]
impl BackupOperationsExecutor for CommandBackupOperationsExecutor {
    async fn execute(&self, request: BackupOperationRequest) -> Result<BackupOperationResult, BackupOperationFailure> {
        let operation = match request.kind {
            BackupOperationKind::BackupCreate => "backup",
            BackupOperationKind::ManifestValidation => "verify",
            BackupOperationKind::FullRestoreDrill => "restore-drill",
        };
        let input = serde_json::to_vec(&json!({"schema_version":1,"request":request}))
            .map_err(|_| BackupOperationFailure::Terminal("backup_adapter_input_invalid".to_owned()))?;
        let mut child = Command::new(&self.tool)
            .arg(operation)
            .arg("--json-stdin")
            .arg("--json-stdout")
            .env("GATEWAY_BACKUP_KEY_FILE", &self.key_file)
            .env("GATEWAY_BACKUP_REPOSITORY", &self.repository)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| BackupOperationFailure::Transient("backup_adapter_unavailable".to_owned()))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| BackupOperationFailure::Transient("backup_adapter_unavailable".to_owned()))?;
        stdin
            .write_all(&input)
            .await
            .map_err(|_| BackupOperationFailure::Transient("backup_adapter_io_failed".to_owned()))?;
        drop(stdin);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BackupOperationFailure::Transient("backup_adapter_unavailable".to_owned()))?;
        let mut bounded_stdout = stdout.take(2 * 1024 * 1024 + 1);
        let output = tokio::time::timeout(Duration::from_hours(1), async {
            let mut bytes = Vec::new();
            let (status, _) = tokio::try_join!(child.wait(), bounded_stdout.read_to_end(&mut bytes))?;
            Ok::<_, std::io::Error>((status, bytes))
        })
        .await
        .map_err(|_| BackupOperationFailure::Transient("backup_adapter_timeout".to_owned()))?
        .map_err(|_| BackupOperationFailure::Transient("backup_adapter_io_failed".to_owned()))?;
        if output.1.len() > 2 * 1024 * 1024 {
            return Err(BackupOperationFailure::Terminal(
                "backup_adapter_output_too_large".to_owned(),
            ));
        }
        if !output.0.success() {
            return Err(if output.0.code() == Some(75) {
                BackupOperationFailure::Transient("backup_adapter_transient_failure".to_owned())
            } else {
                BackupOperationFailure::Terminal("backup_adapter_terminal_failure".to_owned())
            });
        }
        serde_json::from_slice(&output.1)
            .map_err(|_| BackupOperationFailure::Terminal("backup_adapter_output_invalid".to_owned()))
    }
}

pub struct EvidenceGatedBackupExecutor;

#[async_trait::async_trait]
impl BackupOperationsExecutor for EvidenceGatedBackupExecutor {
    async fn execute(&self, _request: BackupOperationRequest) -> Result<BackupOperationResult, BackupOperationFailure> {
        Err(BackupOperationFailure::Terminal("backup_not_configured".to_owned()))
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct ProxyProbeTarget {
    pub observer_host: String,
    pub observer_path: String,
}

#[derive(Clone, Debug)]
pub struct IntegrityGuard(Arc<AtomicBool>);

impl IntegrityGuard {
    pub fn new(healthy: bool) -> Self {
        Self(Arc::new(AtomicBool::new(healthy)))
    }

    pub fn healthy(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn set(&self, healthy: bool) {
        self.0.store(healthy, Ordering::Release);
    }
}

pub fn spawn_operations_runtime(
    storage: Arc<PgStorage>,
    audit_integrity_key: SecretValue,
    integrity_guard: IntegrityGuard,
    content_audit_store: Option<Arc<ContentAuditStore>>,
    export_store: Arc<ExportArtifactStore>,
    enrollment_executor: Arc<dyn CredentialEnrollmentJobExecutor>,
    plan_collector: Option<Arc<PgPlanCollector>>,
    model_catalog_collector: Option<Arc<PgModelCatalogCollector>>,
    managed_browser_executor: Option<Arc<ManagedBrowserExecutor>>,
    backup_executor: Arc<dyn BackupOperationsExecutor>,
    credential_runtime: Arc<ProductionDispatcher>,
    readiness: ReadinessCoordinator,
    proxy_probe_target: ProxyProbeTarget,
    cancellation: &CancellationToken,
) -> Vec<JoinHandle<()>> {
    let integrity_storage = storage.clone();
    let integrity_cancel = cancellation.child_token();
    let integrity = tokio::spawn(async move {
        run_integrity_loop(
            integrity_storage,
            audit_integrity_key,
            integrity_guard,
            integrity_cancel,
        )
        .await;
    });
    let job_storage = storage.clone();
    let backup_health_storage = storage.clone();
    let job_cancel = cancellation.child_token();
    let jobs = tokio::spawn(async move {
        run_job_loop(
            job_storage,
            content_audit_store,
            export_store,
            enrollment_executor,
            plan_collector,
            model_catalog_collector,
            managed_browser_executor,
            backup_executor,
            credential_runtime,
            readiness,
            proxy_probe_target,
            job_cancel,
        )
        .await;
    });
    let outbox_cancel = cancellation.child_token();
    let outbox = tokio::spawn(async move { run_outbox_loop(storage, outbox_cancel).await });
    let backup_health_cancel = cancellation.child_token();
    let backup_health =
        tokio::spawn(async move { run_backup_health_loop(backup_health_storage, backup_health_cancel).await });
    vec![integrity, jobs, outbox, backup_health]
}

async fn run_integrity_loop(
    storage: Arc<PgStorage>,
    integrity_key: SecretValue,
    integrity_guard: IntegrityGuard,
    cancellation: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_hours(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return,
            _ = interval.tick() => {
                if let Err(error) = storage.reconcile_stale_request_lifecycles().await {
                    tracing::warn!(event="stale_request_reconciliation_failed", error=%error);
                }
                let run_id = Uuid::now_v7();
                let _ = sqlx::query(
                    "INSERT INTO ops.integrity_check_run (id,state_code,started_at) VALUES ($1,'running',clock_timestamp())",
                )
                .bind(run_id)
                .execute(&storage.pool())
                .await;
                if storage.seal_completed_audit_days(&integrity_key).await.is_ok()
                    && let Ok(report) = storage.verify_audit_integrity(&integrity_key).await {
                        integrity_guard.set(true);
                        let _ = sqlx::query(
                            "UPDATE ops.integrity_check_run SET state_code='succeeded',audit_event_count=$2, \
                             daily_seal_count=$3,deletion_ledger_count=$4,completed_at=clock_timestamp() WHERE id=$1",
                        )
                        .bind(run_id)
                        .bind(i64::try_from(report.audit_event_count).unwrap_or(i64::MAX))
                        .bind(i64::try_from(report.daily_seal_count).unwrap_or(i64::MAX))
                        .bind(i64::try_from(report.deletion_ledger_count).unwrap_or(i64::MAX))
                        .execute(&storage.pool())
                        .await;
                } else {
                        integrity_guard.set(false);
                        let _ = sqlx::query(
                            "UPDATE ops.integrity_check_run SET state_code='failed',error_code='integrity_mismatch', \
                             completed_at=clock_timestamp() WHERE id=$1",
                        )
                        .bind(run_id)
                        .execute(&storage.pool())
                        .await;
                        upsert_critical_alert(&storage, "audit_integrity_mismatch", "Audit integrity verification failed").await;
                }
            }
        }
    }
}

async fn run_backup_health_loop(storage: Arc<PgStorage>, cancellation: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_mins(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return,
            _ = interval.tick() => {
                let freshness: Result<(bool,bool,bool),_> = sqlx::query_as(
                    "SELECT \
                       COALESCE(MAX(completed_at) FILTER (WHERE state_code='succeeded') \
                         > clock_timestamp()-interval '26 hours',false), \
                       COALESCE(MAX(wal_archived_at) FILTER (WHERE state_code='succeeded') \
                         > clock_timestamp()-interval '300 seconds',false), \
                       COALESCE((SELECT MAX(completed_at)>clock_timestamp()-interval '45 days' \
                         FROM ops.restore_drill WHERE kind_code='full_restore_drill' AND state_code='succeeded'),false) \
                     FROM ops.backup_run",
                )
                .fetch_one(&storage.pool())
                .await;
                match freshness {
                    Ok((base_fresh,wal_fresh,drill_fresh)) => {
                        maintain_freshness_alert(&storage,"backup_base_stale",base_fresh,"Latest successful base backup is older than 26 hours").await;
                        maintain_freshness_alert(&storage,"backup_wal_stale",wal_fresh,"Latest successful WAL archive evidence is older than 300 seconds").await;
                        maintain_freshness_alert(&storage,"restore_drill_stale",drill_fresh,"Latest successful isolated restore drill is older than 45 days").await;
                    }
                    Err(error) => tracing::warn!(event="backup_freshness_query_failed", error=%error),
                }
            }
        }
    }
}

async fn maintain_freshness_alert(storage: &PgStorage, fingerprint: &str, fresh: bool, summary: &str) {
    if !fresh {
        upsert_critical_alert(storage, fingerprint, summary).await;
        return;
    }
    let _ = sqlx::query(
        "WITH resolved AS ( \
           UPDATE ops.alert SET state_code='resolved',resolved_at=clock_timestamp(),last_seen_at=clock_timestamp(), \
             detail=detail||jsonb_build_object('resolution','freshness_recovered'),revision=revision+1 \
           WHERE fingerprint=$1 AND state_code IN ('open','acknowledged','silenced') \
           RETURNING id,revision,severity_code,summary \
         ) \
         INSERT INTO ops.outbox_message \
          (id,event_id,topic_code,aggregate_type,aggregate_id,aggregate_revision,payload_schema_version,payload, \
           state_code,lease_generation,attempt_count,available_at,created_at) \
         SELECT $2,$3,'alert.alert_resolved','alert',id,revision,1, \
           jsonb_build_object('severity',severity_code,'summary',summary), \
           'pending',0,0,clock_timestamp(),clock_timestamp() FROM resolved",
    )
    .bind(fingerprint)
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .execute(&storage.pool())
    .await;
}

async fn run_job_loop(
    storage: Arc<PgStorage>,
    content_audit_store: Option<Arc<ContentAuditStore>>,
    export_store: Arc<ExportArtifactStore>,
    enrollment_executor: Arc<dyn CredentialEnrollmentJobExecutor>,
    plan_collector: Option<Arc<PgPlanCollector>>,
    model_catalog_collector: Option<Arc<PgModelCatalogCollector>>,
    managed_browser_executor: Option<Arc<ManagedBrowserExecutor>>,
    backup_executor: Arc<dyn BackupOperationsExecutor>,
    credential_runtime: Arc<ProductionDispatcher>,
    readiness: ReadinessCoordinator,
    proxy_probe_target: ProxyProbeTarget,
    cancellation: CancellationToken,
) {
    let worker_id = format!("super-gatewayd:{}", std::process::id());
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut next_plan_scan = tokio::time::Instant::now();
    let mut next_enrollment_expiry_scan = tokio::time::Instant::now();
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return,
            _ = interval.tick() => {
                if plan_collector.is_some() && tokio::time::Instant::now() >= next_plan_scan {
                    if let Err(error) = schedule_due_plan_collections(&storage).await {
                        tracing::warn!(event="credential_plan_schedule_failed", error=%error);
                    }
                    next_plan_scan = tokio::time::Instant::now() + Duration::from_secs(60);
                }
                if tokio::time::Instant::now() >= next_enrollment_expiry_scan {
                    if let Err(error) = storage.expire_credential_enrollments(100).await {
                        tracing::warn!(event="credential_enrollment_expiry_failed", error=%error);
                    }
                    next_enrollment_expiry_scan = tokio::time::Instant::now() + Duration::from_secs(30);
                }
                if let Ok(expired) = storage.expire_usage_exports(100).await {
                    for object_uri in expired {
                        if let Err(error) = export_store.remove_uri(&object_uri).await {
                            tracing::warn!(event="usage_export_expired_object_cleanup_failed", error=%error);
                        }
                    }
                }
                match storage.claim_jobs(&worker_id, 16, WORKER_LEASE_SECONDS).await {
                    Ok(jobs) => {
                        let mut in_flight = JoinSet::new();
                        for job in jobs {
                            let storage = storage.clone();
                            let content_audit_store = content_audit_store.clone();
                            let export_store = export_store.clone();
                            let enrollment_executor = enrollment_executor.clone();
                            let plan_collector = plan_collector.clone();
                            let model_catalog_collector = model_catalog_collector.clone();
                            let managed_browser_executor = managed_browser_executor.clone();
                            let backup_executor = backup_executor.clone();
                            let credential_runtime = credential_runtime.clone();
                            let readiness = readiness.clone();
                            let proxy_probe_target = proxy_probe_target.clone();
                            let worker_id = worker_id.clone();
                            let job_cancel = cancellation.child_token();
                            in_flight.spawn(async move {
                                process_job_with_heartbeat(
                                    storage,
                                    content_audit_store,
                                    export_store,
                                    enrollment_executor,
                                    plan_collector,
                                    model_catalog_collector,
                                    managed_browser_executor,
                                    backup_executor,
                                    credential_runtime,
                                    readiness,
                                    proxy_probe_target,
                                    job,
                                    worker_id,
                                    job_cancel,
                                )
                                .await;
                            });
                        }
                        while !in_flight.is_empty() {
                            tokio::select! {
                                () = cancellation.cancelled() => {
                                    in_flight.abort_all();
                                    while in_flight.join_next().await.is_some() {}
                                    return;
                                }
                                _ = in_flight.join_next() => {}
                            }
                        }
                    },
                    Err(_) => upsert_critical_alert(&storage, "job_claim_failed", "Durable job claim failed").await,
                }
            }
        }
    }
}

async fn schedule_due_plan_collections(storage: &PgStorage) -> Result<(), sqlx::Error> {
    let mut transaction = storage.pool().begin().await?;
    let owns_planner: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext('credential-plan-planner-v1'))")
            .fetch_one(&mut *transaction)
            .await?;
    if !owns_planner {
        transaction.rollback().await?;
        return Ok(());
    }
    let rows = sqlx::query(
        "SELECT credential.id,credential.group_id,credential.revision,credential.token_version, \
                credential.provider_profile_id,binding.id AS binding_id,binding.egress_epoch, \
                to_char(date_trunc('hour',clock_timestamp()),'YYYYMMDDHH24') AS schedule_bucket \
         FROM gateway.anthropic_credential credential \
         JOIN gateway.credential_auth_version auth ON auth.id=credential.active_auth_version_id \
           AND auth.credential_id=credential.id AND auth.material_state_code='active' \
         JOIN gateway.credential_provider_profile provider ON provider.id=credential.provider_profile_id \
           AND provider.lifecycle_code='active' AND provider.auth_kind_codes ? credential.auth_kind_code \
         JOIN gateway.credential_egress_binding binding ON binding.credential_id=credential.id \
           AND binding.lifecycle_code='active' AND binding.stability_code='stable' \
         LEFT JOIN telemetry.subscription_plan_current current ON current.credential_id=credential.id \
         WHERE credential.lifecycle_state_code NOT IN ('revoked','archived') \
           AND credential.auth_kind_code IN ('oauth_subscription','setup_token_subscription') \
           AND (current.last_attempted_at IS NULL OR current.last_attempted_at<clock_timestamp()-interval '24 hours') \
           AND NOT EXISTS(SELECT 1 FROM ops.durable_job job WHERE job.kind_code='credential_plan_collect_v1' \
             AND job.payload->>'credential_id'=credential.id::text AND job.state_code IN ('scheduled','leased','retry_wait')) \
         ORDER BY COALESCE(current.last_attempted_at,'epoch'::timestamptz),credential.id LIMIT 100 \
         FOR UPDATE OF credential SKIP LOCKED",
    )
    .fetch_all(&mut *transaction)
    .await?;
    for row in rows {
        let credential_id: Uuid = row.try_get("id")?;
        let group_id: Uuid = row.try_get("group_id")?;
        let revision: i64 = row.try_get("revision")?;
        let token_version: i64 = row.try_get("token_version")?;
        let provider_profile_id: Uuid = row.try_get("provider_profile_id")?;
        let binding_id: Uuid = row.try_get("binding_id")?;
        let egress_epoch: i64 = row.try_get("egress_epoch")?;
        let schedule_bucket: String = row.try_get("schedule_bucket")?;
        let job_id = Uuid::now_v7();
        let inserted = sqlx::query(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'credential_plan_collect_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,8,clock_timestamp(),clock_timestamp()) \
             ON CONFLICT (kind_code,idempotency_key) DO NOTHING",
        )
        .bind(job_id)
        .bind(format!("credential-plan-auto:{credential_id}:{schedule_bucket}"))
        .bind(json!({"credential_id":credential_id,"group_id":group_id,"credential_revision":revision,
          "token_version":token_version,"provider_profile_id":provider_profile_id,"binding_id":binding_id,
          "egress_epoch":egress_epoch,"trigger":"scheduled"}))
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() == 1 {
            sqlx::query(
                "INSERT INTO ops.durable_job_history \
                 (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
                 VALUES ($1,$2,NULL,'scheduled',0,'credential_plan_collection_scheduled', \
                   jsonb_build_object('trigger','scheduled'),clock_timestamp())",
            )
            .bind(Uuid::now_v7())
            .bind(job_id)
            .execute(&mut *transaction)
            .await?;
        }
    }
    transaction.commit().await
}

async fn process_job_with_heartbeat(
    storage: Arc<PgStorage>,
    content_audit_store: Option<Arc<ContentAuditStore>>,
    export_store: Arc<ExportArtifactStore>,
    enrollment_executor: Arc<dyn CredentialEnrollmentJobExecutor>,
    plan_collector: Option<Arc<PgPlanCollector>>,
    model_catalog_collector: Option<Arc<PgModelCatalogCollector>>,
    managed_browser_executor: Option<Arc<ManagedBrowserExecutor>>,
    backup_executor: Arc<dyn BackupOperationsExecutor>,
    credential_runtime: Arc<ProductionDispatcher>,
    readiness: ReadinessCoordinator,
    proxy_probe_target: ProxyProbeTarget,
    job: JobLease,
    worker_id: String,
    cancellation: CancellationToken,
) {
    let mut processing = Box::pin(process_job(
        &storage,
        content_audit_store.as_deref(),
        export_store.as_ref(),
        enrollment_executor.as_ref(),
        plan_collector.as_deref(),
        model_catalog_collector.as_deref(),
        managed_browser_executor.as_deref(),
        backup_executor.as_ref(),
        credential_runtime.as_ref(),
        &readiness,
        &proxy_probe_target,
        job.clone(),
        &worker_id,
    ));
    let first_heartbeat = tokio::time::Instant::now() + DEFAULT_JOB_HEARTBEAT;
    let mut heartbeat = tokio::time::interval_at(first_heartbeat, DEFAULT_JOB_HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            () = &mut processing => return,
            _ = heartbeat.tick() => {
                if let Err(error) = storage
                    .heartbeat_job(
                        job.job_id,
                        job.generation,
                        &worker_id,
                        WORKER_LEASE_SECONDS,
                        None,
                    )
                    .await
                {
                    tracing::warn!(
                        event="durable_job_lease_lost",
                        job_id=%job.job_id,
                        generation=job.generation,
                        error=%error,
                    );
                    return;
                }
            }
        }
    }
}

async fn process_job(
    storage: &PgStorage,
    content_audit_store: Option<&ContentAuditStore>,
    export_store: &ExportArtifactStore,
    enrollment_executor: &dyn CredentialEnrollmentJobExecutor,
    plan_collector: Option<&PgPlanCollector>,
    model_catalog_collector: Option<&PgModelCatalogCollector>,
    managed_browser_executor: Option<&ManagedBrowserExecutor>,
    backup_executor: &dyn BackupOperationsExecutor,
    credential_runtime: &ProductionDispatcher,
    readiness: &ReadinessCoordinator,
    proxy_probe_target: &ProxyProbeTarget,
    job: JobLease,
    worker_id: &str,
) {
    #[cfg(not(target_os = "linux"))]
    let _ = proxy_probe_target;

    match job.kind.as_str() {
        "audit_integrity_verify" | "audit_daily_seal" => {
            let _ = storage
                .complete_job(job.job_id, job.generation, "maintenance_loop_owns_execution")
                .await;
        }
        "credential_enrollment_exchange" => {
            let ids = job
                .payload
                .get("enrollment_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
                .zip(
                    job.payload
                        .get("credential_id")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| Uuid::parse_str(value).ok()),
                );
            let Some((enrollment_id, credential_id)) = ids else {
                let _ = storage
                    .dead_letter_job(job.job_id, job.generation, "enrollment_payload_invalid", None)
                    .await;
                return;
            };
            finish_enrollment_job_attempt(
                storage,
                &job,
                enrollment_executor
                    .execute(CredentialEnrollmentJobAttempt {
                        enrollment_id,
                        credential_id,
                        job_id: job.job_id,
                        job_generation: job.generation,
                    })
                    .await,
            )
            .await;
        }
        "credential_plan_collect_v1" => {
            process_credential_plan_collection(storage, plan_collector, &job).await;
        }
        "model_catalog_discovery_v1" => {
            process_model_catalog_discovery(storage, model_catalog_collector, &job).await;
        }
        "plan_mapping_recompute" => {
            let Some(artifact_id) = job
                .payload
                .get("mapping_artifact_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
            else {
                let _ = storage
                    .dead_letter_job(job.job_id, job.generation, "plan_mapping_payload_invalid", None)
                    .await;
                return;
            };
            match storage.recompute_plan_mapping(artifact_id, job.generation).await {
                Ok(_) => {
                    // The recompute transaction also generation-fences and completes
                    // this job, so a second complete_job call would be a false conflict.
                }
                Err(StorageError::InvalidLifecycle | StorageError::RevisionConflict) => {
                    let _ = storage
                        .dead_letter_job(job.job_id, job.generation, "plan_mapping_recompute_rejected", None)
                        .await;
                }
                Err(_) if job.attempt < job.max_attempts => {
                    let _ = storage
                        .retry_job(job.job_id, job.generation, 30, "plan_mapping_recompute_transient", None)
                        .await;
                }
                Err(_) => {
                    let _ = storage
                        .dead_letter_job(job.job_id, job.generation, "plan_mapping_recompute_exhausted", None)
                        .await;
                }
            }
        }
        "credential_admin_refresh" => {
            let credential_id = job
                .payload
                .get("credential_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok());
            let expected_token_version = job
                .payload
                .get("expected_token_version")
                .and_then(serde_json::Value::as_u64);
            let Some((credential_id, expected_token_version)) = credential_id.zip(expected_token_version) else {
                let _ = storage
                    .dead_letter_job(job.job_id, job.generation, "credential_refresh_payload_invalid", None)
                    .await;
                return;
            };
            match credential_runtime
                .refresh_credential_for_admin(credential_id, expected_token_version)
                .await
            {
                Ok((token_version, runtime_projection_applied)) => {
                    let _ = storage
                        .complete_job(
                            job.job_id,
                            job.generation,
                            &format!(
                                "credential_refresh_complete:token_version={token_version}:runtime_projection={runtime_projection_applied}"
                            ),
                        )
                        .await;
                }
                Err(CredentialServiceError::RateLimited(delay)) if job.attempt < job.max_attempts => {
                    let seconds = i32::try_from(delay.as_secs().clamp(1, 900)).unwrap_or(900);
                    let _ = storage
                        .retry_job(
                            job.job_id,
                            job.generation,
                            seconds,
                            "credential_refresh_rate_limited",
                            None,
                        )
                        .await;
                }
                Err(
                    CredentialServiceError::Conflict
                    | CredentialServiceError::WaitingEgress
                    | CredentialServiceError::Transient
                    | CredentialServiceError::WorkerTimeout,
                ) if job.attempt < job.max_attempts => {
                    let _ = storage
                        .retry_job(job.job_id, job.generation, 30, "credential_refresh_transient", None)
                        .await;
                }
                Err(error) => {
                    let code = match error {
                        CredentialServiceError::InvalidAuthentication => "credential_refresh_auth_invalid",
                        CredentialServiceError::AccountMismatch => "credential_refresh_account_mismatch",
                        CredentialServiceError::ManualRecoveryRequired(_) => {
                            "credential_refresh_manual_recovery_required"
                        }
                        CredentialServiceError::EvidencePending => "credential_refresh_evidence_pending",
                        _ => "credential_refresh_exhausted",
                    };
                    let _ = storage.dead_letter_job(job.job_id, job.generation, code, None).await;
                }
            }
        }
        "credential_managed_browser_v1" => {
            let Some(executor) = managed_browser_executor else {
                let _ = storage
                    .dead_letter_job(job.job_id, job.generation, "managed_browser_not_configured", None)
                    .await;
                return;
            };
            match executor.execute(&job).await {
                Ok(commit) => {
                    let projected = credential_runtime
                        .reconfigure_credential_projection(commit.group_id, commit.credential_id)
                        .await;
                    if projected.is_err() {
                        let _ = storage
                            .retry_job(
                                job.job_id,
                                job.generation,
                                5,
                                "managed_browser_runtime_projection_failed",
                                job.checkpoint.as_ref(),
                            )
                            .await;
                        return;
                    }
                    let _ = credential_runtime
                        .unfence_credential_for_admin(commit.group_id, commit.credential_id)
                        .await;
                    let _ = storage
                        .complete_job(
                            job.job_id,
                            job.generation,
                            &format!(
                                "managed_browser_complete:credential_revision={}:token_version={}",
                                commit.credential_revision, commit.token_version
                            ),
                        )
                        .await;
                }
                Err(failure) if failure.retry_after_seconds.is_some() && job.attempt < job.max_attempts => {
                    executor.record_retry(&job, &failure).await;
                    let _ = storage
                        .retry_job(
                            job.job_id,
                            job.generation,
                            i32::try_from(failure.retry_after_seconds.unwrap_or(30)).unwrap_or(30),
                            failure.code,
                            job.checkpoint.as_ref(),
                        )
                        .await;
                }
                Err(failure) => {
                    executor.record_terminal(&job, &failure).await;
                    let _ = storage
                        .dead_letter_job(job.job_id, job.generation, failure.code, None)
                        .await;
                }
            }
        }
        "credential_group_migration_v1" => {
            process_credential_group_migration(storage, credential_runtime, &job).await;
        }
        "credential_egress_rebind_v1" => {
            #[cfg(target_os = "linux")]
            process_credential_egress_rebind(storage, credential_runtime, proxy_probe_target, &job).await;
            #[cfg(not(target_os = "linux"))]
            let _ = storage
                .dead_letter_job(
                    job.job_id,
                    job.generation,
                    "credential_egress_rebind_requires_linux",
                    None,
                )
                .await;
        }
        "content_audit_purge" => {
            let Some(store) = content_audit_store else {
                let _ = storage
                    .retry_job(job.job_id, job.generation, 30, "content_audit_store_unavailable", None)
                    .await;
                return;
            };
            match process_content_audit_purge(storage, store, &job).await {
                Ok(()) => {
                    let _ = storage.complete_job(job.job_id, job.generation, "purge_complete").await;
                }
                Err(error_code) if job.attempt < job.max_attempts => {
                    let _ = storage
                        .retry_job(job.job_id, job.generation, 30, error_code, None)
                        .await;
                }
                Err(error_code) => {
                    let _ = storage
                        .dead_letter_job(job.job_id, job.generation, error_code, None)
                        .await;
                }
            }
        }
        "business_key_rotation" => match process_business_key_rotation(storage, &job, worker_id).await {
            Ok(()) => {
                let _ = storage
                    .complete_job(job.job_id, job.generation, "rewrap_complete_key_decrypt_only")
                    .await;
            }
            Err(RotationJobError::PayloadInvalid) => {
                let _ = storage
                    .dead_letter_job(
                        job.job_id,
                        job.generation,
                        "business_key_rotation_payload_invalid",
                        None,
                    )
                    .await;
            }
            Err(RotationJobError::Transient(error_code)) if job.attempt < job.max_attempts => {
                let _ = storage
                    .retry_job(job.job_id, job.generation, 30, error_code, None)
                    .await;
            }
            Err(RotationJobError::Transient(error_code)) => {
                let _ = storage
                    .dead_letter_job(job.job_id, job.generation, error_code, None)
                    .await;
            }
        },
        "business_key_lifecycle" => {
            let parsed = job
                .payload
                .get("key_version")
                .and_then(serde_json::Value::as_i64)
                .filter(|value| *value >= 1)
                .zip(job.payload.get("target_state").and_then(serde_json::Value::as_str))
                .zip(
                    job.payload
                        .get("rotation_job_id")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| Uuid::parse_str(value).ok()),
                )
                .zip(
                    job.payload
                        .get("backup_run_id")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| Uuid::parse_str(value).ok()),
                )
                .zip(
                    job.payload
                        .get("restore_drill_id")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| Uuid::parse_str(value).ok()),
                );
            let Some(((((key_version, target_state), rotation_job_id), backup_run_id), restore_drill_id)) = parsed
            else {
                let _ = storage
                    .dead_letter_job(
                        job.job_id,
                        job.generation,
                        "business_key_lifecycle_payload_invalid",
                        None,
                    )
                    .await;
                return;
            };
            match storage
                .complete_database_business_key_lifecycle(
                    job.job_id,
                    job.generation,
                    key_version,
                    target_state,
                    rotation_job_id,
                    backup_run_id,
                    restore_drill_id,
                )
                .await
            {
                Ok(()) | Err(StorageError::RevisionConflict) => {}
                Err(StorageError::InvalidLifecycle) => {
                    let _ = storage
                        .dead_letter_job(
                            job.job_id,
                            job.generation,
                            "business_key_lifecycle_evidence_invalid",
                            None,
                        )
                        .await;
                }
                Err(_) if job.attempt < job.max_attempts => {
                    let _ = storage
                        .retry_job(
                            job.job_id,
                            job.generation,
                            30,
                            "business_key_lifecycle_transient",
                            job.checkpoint.as_ref(),
                        )
                        .await;
                }
                Err(_) => {
                    let _ = storage
                        .dead_letter_job(job.job_id, job.generation, "business_key_lifecycle_exhausted", None)
                        .await;
                }
            }
        }
        "notification_channel_test_v1" | "notification_delivery_v1" => {
            #[cfg(target_os = "linux")]
            process_notification_delivery(storage, &job).await;
            #[cfg(not(target_os = "linux"))]
            {
                fail_notification_delivery(storage, &job, "notification_sender_requires_linux").await;
            }
        }
        "usage_export_generate" => {
            process_usage_export(storage, export_store, &job).await;
        }
        "content_audit_export_generate" => {
            let Some(store) = content_audit_store else {
                let _ = storage
                    .retry_job(job.job_id, job.generation, 30, "content_audit_store_unavailable", None)
                    .await;
                return;
            };
            process_content_audit_export(storage, store, export_store, &job).await;
        }
        "upgrade_preflight_v1" => process_upgrade_preflight(storage, readiness, &job).await,
        "backup_create" => process_backup_create(storage, backup_executor, &job).await,
        "restore_manifest_validation" | "restore_full_drill" => {
            process_restore_operation(storage, backup_executor, &job).await;
        }
        "proxy_full_path_probe_v1" => {
            #[cfg(target_os = "linux")]
            process_proxy_probe(storage, proxy_probe_target, &job).await;
            #[cfg(not(target_os = "linux"))]
            let _ = storage
                .dead_letter_job(job.job_id, job.generation, "proxy_probe_requires_linux", None)
                .await;
        }
        _ => {
            let _ = storage
                .dead_letter_job(job.job_id, job.generation, "unsupported_job_kind", None)
                .await;
        }
    }
}

fn notification_job_ids(job: &JobLease) -> Option<(Uuid, Uuid, i64)> {
    let delivery_id = job
        .payload
        .get("delivery_id")?
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())?;
    let destination_id = job
        .payload
        .get("destination_id")?
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())?;
    let destination_revision = job.payload.get("destination_revision")?.as_i64()?;
    Some((delivery_id, destination_id, destination_revision))
}

async fn fail_notification_delivery(storage: &PgStorage, job: &JobLease, error_code: &str) {
    let Some((delivery_id, destination_id, _)) = notification_job_ids(job) else {
        return;
    };
    let _ = storage
        .finish_notification_delivery_attempt(
            delivery_id,
            destination_id,
            job.job_id,
            job.generation,
            job.attempt,
            "failed",
            error_code,
            None,
        )
        .await;
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationSecretMaterial {
    kind: String,
    secret: String,
}

#[cfg(target_os = "linux")]
async fn load_serverchan3_secret(
    storage: &PgStorage,
    destination_id: Uuid,
    expected_revision: i64,
) -> Result<SecretValue, &'static str> {
    let row = sqlx::query(
        "SELECT d.kind_code,d.state_code,d.revision,d.secret_id, \
                s.secret_kind_code,s.provider_role_code,s.cipher_suite_code,s.ciphertext,s.nonce,s.wrapped_dek, \
                s.key_version,s.aad_schema_version,s.owner_type_code,s.owner_id,s.purpose_code \
         FROM ops.notification_destination d \
         JOIN security.encrypted_secret s ON s.id=d.secret_id \
         WHERE d.id=$1 AND s.destroyed_at IS NULL AND s.superseded_at IS NULL",
    )
    .bind(destination_id)
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| "notification_destination_load_failed")?
    .ok_or("notification_destination_missing")?;
    let revision: i64 = row.try_get("revision").map_err(|_| "notification_projection_invalid")?;
    let kind: String = row
        .try_get("kind_code")
        .map_err(|_| "notification_projection_invalid")?;
    let state: String = row
        .try_get("state_code")
        .map_err(|_| "notification_projection_invalid")?;
    let secret_id: Uuid = row
        .try_get("secret_id")
        .map_err(|_| "notification_projection_invalid")?;
    let secret_kind: String = row
        .try_get("secret_kind_code")
        .map_err(|_| "notification_projection_invalid")?;
    let provider_role: String = row
        .try_get("provider_role_code")
        .map_err(|_| "notification_projection_invalid")?;
    let owner_type: String = row
        .try_get("owner_type_code")
        .map_err(|_| "notification_projection_invalid")?;
    let owner_id: String = row.try_get("owner_id").map_err(|_| "notification_projection_invalid")?;
    let purpose: String = row
        .try_get("purpose_code")
        .map_err(|_| "notification_projection_invalid")?;
    if revision != expected_revision
        || kind != "serverchan3"
        || state != "active"
        || secret_kind != "notification_destination"
        || provider_role != "business"
        || owner_type != "notification_destination"
        || owner_id != destination_id.to_string()
        || purpose != "notification_delivery"
    {
        return Err("notification_destination_fence_rejected");
    }
    let key_version_i64: i64 = row
        .try_get("key_version")
        .map_err(|_| "notification_projection_invalid")?;
    let key_version = u64::try_from(key_version_i64).map_err(|_| "notification_projection_invalid")?;
    let schema_version = u32::try_from(
        row.try_get::<i32, _>("aad_schema_version")
            .map_err(|_| "notification_projection_invalid")?,
    )
    .map_err(|_| "notification_projection_invalid")?;
    let root_key = storage
        .load_database_business_key(key_version_i64)
        .await
        .map_err(|_| "notification_key_unavailable")?;
    let aad = EnvelopeAad {
        schema_version,
        secret_id,
        secret_kind,
        provider_role: provider_role.clone(),
        owner_type,
        owner_id,
        purpose,
        key_version,
    };
    let envelope = SecretEnvelope {
        schema_version,
        cipher_suite: row
            .try_get("cipher_suite_code")
            .map_err(|_| "notification_projection_invalid")?,
        provider_role,
        key_version,
        ciphertext_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("ciphertext")
                .map_err(|_| "notification_projection_invalid")?,
        ),
        nonce_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("nonce")
                .map_err(|_| "notification_projection_invalid")?,
        ),
        wrapped_dek_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("wrapped_dek")
                .map_err(|_| "notification_projection_invalid")?,
        ),
    };
    let provider = LocalAesKeyProvider::new("business", key_version, root_key.expose().to_vec())
        .map_err(|_| "notification_key_unavailable")?;
    let plaintext = EnvelopeService::new(provider)
        .decrypt(&envelope, &aad)
        .map_err(|_| "notification_secret_invalid")?;
    let material: NotificationSecretMaterial =
        serde_json::from_slice(plaintext.expose()).map_err(|_| "notification_secret_invalid")?;
    if material.kind != "serverchan3" {
        return Err("notification_secret_invalid");
    }
    Ok(SecretValue::new(material.secret))
}

#[cfg(target_os = "linux")]
async fn process_notification_delivery(storage: &PgStorage, job: &JobLease) {
    let Some((delivery_id, destination_id, destination_revision)) = notification_job_ids(job) else {
        let _ = storage
            .dead_letter_job(job.job_id, job.generation, "notification_payload_invalid", None)
            .await;
        return;
    };
    let payload = match sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM ops.notification_delivery \
         WHERE id=$1 AND destination_id=$2 AND state_code IN ('pending','retry_wait')",
    )
    .bind(delivery_id)
    .bind(destination_id)
    .fetch_optional(&storage.pool())
    .await
    {
        Ok(Some(payload)) => payload,
        Ok(None) => {
            let _ = storage
                .dead_letter_job(job.job_id, job.generation, "notification_delivery_state_invalid", None)
                .await;
            return;
        }
        Err(_) => {
            retry_notification_delivery(storage, job, "notification_delivery_load_failed").await;
            return;
        }
    };
    let send_key = match load_serverchan3_secret(storage, destination_id, destination_revision).await {
        Ok(value) => value,
        Err(error) => {
            fail_notification_delivery(storage, job, error).await;
            return;
        }
    };
    let target = match serverchan3_target(send_key.expose()) {
        Ok(value) => value,
        Err(()) => {
            fail_notification_delivery(storage, job, "serverchan3_send_key_invalid").await;
            return;
        }
    };
    let title = payload
        .get("title")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .unwrap_or("Super Gateway 通知");
    let summary = payload
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.len() <= 4096)
        .unwrap_or("网关产生了一条受控通知。");
    let tags = payload
        .get("tags")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256 && !value.contains(['\r', '\n']))
        .unwrap_or("super-gateway|notification");
    let body = match serde_json::to_vec(&json!({
        "title":title,
        "desp":summary,
        "short":summary.chars().take(120).collect::<String>(),
        "tags":tags
    })) {
        Ok(value) => SecretBytes::new(value),
        Err(_) => {
            fail_notification_delivery(storage, job, "notification_payload_invalid").await;
            return;
        }
    };
    let response = ProviderHttpsClient::default()
        .execute(ProviderHttpsRequest {
            method: Method::POST,
            host: target.host.clone(),
            port: 443,
            host_header: target.host,
            path_and_query: target.path,
            headers: vec![ProviderHttpsHeader {
                name: "content-type",
                value: SecretBytes::new(b"application/json".to_vec()),
            }],
            body,
            response_limit: 64 * 1024,
            egress: EgressRouteSnapshot::Direct,
            cancellation: CancellationToken::new(),
        })
        .await;
    let outcome = match response {
        Ok(response) if (200..300).contains(&response.status) => {
            let provider_code = serde_json::from_slice::<serde_json::Value>(response.body.expose())
                .ok()
                .and_then(|value| value.get("code").and_then(serde_json::Value::as_i64));
            if provider_code == Some(0) {
                Ok(())
            } else {
                Err(("serverchan3_response_invalid", false))
            }
        }
        Ok(response) if response.status == 429 || response.status >= 500 => Err(("serverchan3_transient_status", true)),
        Ok(_) => Err(("serverchan3_request_rejected", false)),
        Err(_) => Err(("serverchan3_transport_failed", true)),
    };
    match outcome {
        Ok(()) => {
            let _ = storage
                .finish_notification_delivery_attempt(
                    delivery_id,
                    destination_id,
                    job.job_id,
                    job.generation,
                    job.attempt,
                    "delivered",
                    "serverchan3_ok",
                    None,
                )
                .await;
        }
        Err((error, true)) if job.attempt < job.max_attempts => {
            retry_notification_delivery(storage, job, error).await;
        }
        Err((error, _)) => {
            fail_notification_delivery(storage, job, error).await;
        }
    }
}

#[cfg(target_os = "linux")]
async fn retry_notification_delivery(storage: &PgStorage, job: &JobLease, error_code: &str) {
    let Some((delivery_id, destination_id, _)) = notification_job_ids(job) else {
        return;
    };
    let delay_seconds = match job.attempt {
        i32::MIN..=1 => 60,
        2 => 300,
        3 => 900,
        _ => 1_800,
    };
    let _ = storage
        .finish_notification_delivery_attempt(
            delivery_id,
            destination_id,
            job.job_id,
            job.generation,
            job.attempt,
            "retry_wait",
            error_code,
            Some(delay_seconds),
        )
        .await;
}

#[cfg(target_os = "linux")]
async fn process_proxy_probe(storage: &PgStorage, target: &ProxyProbeTarget, job: &JobLease) {
    let ids = job
        .payload
        .get("proxy_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .zip(job.payload.get("probe_generation").and_then(serde_json::Value::as_i64));
    let Some((proxy_id, probe_generation)) = ids else {
        let _ = storage
            .dead_letter_job(job.job_id, job.generation, "proxy_probe_payload_invalid", None)
            .await;
        return;
    };
    let started = tokio::time::Instant::now();
    let route = match resolve_proxy_route(storage, proxy_id).await {
        Ok(route) => route,
        Err(_) => {
            finish_proxy_probe(
                storage,
                job,
                proxy_id,
                probe_generation,
                "auth_failed",
                None,
                started,
                json!({"phase":"load_route"}),
            )
            .await;
            return;
        }
    };
    let client = ProviderHttpsClient::default();
    let cancellation = CancellationToken::new();
    let observer = client
        .execute(ProviderHttpsRequest {
            method: Method::GET,
            host: target.observer_host.clone().into_boxed_str(),
            port: 443,
            host_header: target.observer_host.clone().into_boxed_str(),
            path_and_query: SecretValue::new(target.observer_path.clone()),
            headers: Vec::new(),
            body: SecretBytes::new(Vec::new()),
            response_limit: 256,
            egress: route.clone(),
            cancellation: cancellation.clone(),
        })
        .await;
    let observed_exit_ip = match observer {
        Ok(response) if response.status == 200 => std::str::from_utf8(response.body.expose())
            .ok()
            .map(str::trim)
            .filter(|value| value.parse::<std::net::IpAddr>().is_ok())
            .map(str::to_owned),
        Ok(_) => None,
        Err(error) => {
            if transient_probe_error(error.code) && job.attempt < 3 {
                let _ = storage
                    .retry_job(job.job_id, job.generation, 60, "proxy_probe_transient", None)
                    .await;
                return;
            }
            let result = classify_proxy_probe_error(error.code);
            finish_proxy_probe(
                storage,
                job,
                proxy_id,
                probe_generation,
                result,
                None,
                started,
                json!({"phase":"exit_observer"}),
            )
            .await;
            return;
        }
    };
    let Some(observed_exit_ip) = observed_exit_ip else {
        finish_proxy_probe(
            storage,
            job,
            proxy_id,
            probe_generation,
            "tunnel_failed",
            None,
            started,
            json!({"phase":"exit_observer","reason":"invalid_response"}),
        )
        .await;
        return;
    };
    let anthropic = client
        .execute(ProviderHttpsRequest {
            method: Method::GET,
            host: "api.anthropic.com".into(),
            port: 443,
            host_header: "api.anthropic.com".into(),
            path_and_query: SecretValue::new("/".to_owned()),
            headers: Vec::new(),
            body: SecretBytes::new(Vec::new()),
            response_limit: 1024 * 1024,
            egress: route,
            cancellation,
        })
        .await;
    match anthropic {
        Ok(response) => {
            finish_proxy_probe(
                storage,
                job,
                proxy_id,
                probe_generation,
                "healthy",
                Some(observed_exit_ip),
                started,
                json!({"phase":"anthropic_tls","http_status":response.status}),
            )
            .await;
        }
        Err(error) if transient_probe_error(error.code) && job.attempt < 3 => {
            let _ = storage
                .retry_job(job.job_id, job.generation, 60, "proxy_probe_transient", None)
                .await;
        }
        Err(error) => {
            let result = classify_proxy_probe_error(error.code);
            finish_proxy_probe(
                storage,
                job,
                proxy_id,
                probe_generation,
                result,
                Some(observed_exit_ip),
                started,
                json!({"phase":"anthropic_tls"}),
            )
            .await;
        }
    }
}

#[cfg(target_os = "linux")]
fn transient_probe_error(code: TransportErrorCode) -> bool {
    matches!(
        code,
        TransportErrorCode::ResolverFailure | TransportErrorCode::TcpConnectFailure | TransportErrorCode::Timeout
    )
}

#[cfg(target_os = "linux")]
fn classify_proxy_probe_error(code: TransportErrorCode) -> &'static str {
    match code {
        TransportErrorCode::ResolverFailure => "dns_failed",
        TransportErrorCode::ProxyAuthentication => "auth_failed",
        TransportErrorCode::ProxyProtocol => "tunnel_failed",
        TransportErrorCode::TlsCertificate | TransportErrorCode::TlsHandshake | TransportErrorCode::AlpnMismatch => {
            "tls_intercepted"
        }
        TransportErrorCode::Cancelled | TransportErrorCode::CancelGraceExpired => "cancelled",
        _ => "connect_failed",
    }
}

#[cfg(target_os = "linux")]
async fn finish_proxy_probe(
    storage: &PgStorage,
    job: &JobLease,
    proxy_id: Uuid,
    probe_generation: i64,
    result_code: &str,
    observed_exit_ip: Option<String>,
    started: tokio::time::Instant,
    redacted_detail: serde_json::Value,
) {
    let latency_ms = i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX);
    if storage
        .complete_proxy_probe(&ProxyProbeCommit {
            proxy_id,
            job_id: job.job_id,
            job_generation: job.generation,
            probe_generation,
            result_code: result_code.to_owned(),
            observed_exit_ip,
            latency_ms: Some(latency_ms),
            negotiated_alpn: None,
            certificate_sha256: None,
            redacted_detail,
        })
        .await
        .is_err()
    {
        let _ = storage
            .retry_job(job.job_id, job.generation, 30, "proxy_probe_commit_failed", None)
            .await;
    }
}

enum RotationJobError {
    PayloadInvalid,
    Transient(&'static str),
}

async fn process_credential_group_migration(storage: &PgStorage, runtime: &ProductionDispatcher, job: &JobLease) {
    let Some(migration_id) = job
        .payload
        .get("migration_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        let _ = storage
            .dead_letter_job(
                job.job_id,
                job.generation,
                "credential_group_migration_payload_invalid",
                None,
            )
            .await;
        return;
    };
    let mut work = match storage
        .load_credential_group_migration_work(migration_id, job.job_id, job.generation)
        .await
    {
        Ok(work) => work,
        Err(_) => {
            retry_or_dead_letter_migration(storage, job, "credential_group_migration_load_failed", 5).await;
            return;
        }
    };
    if work.state == "draining" {
        let active_leases = match runtime
            .fence_credential_for_admin(work.source_group_id, work.credential_id)
            .await
        {
            Ok(Some(active_leases)) => active_leases,
            _ => {
                retry_or_dead_letter_migration(storage, job, "credential_group_migration_owner_unavailable", 5).await;
                return;
            }
        };
        match storage
            .finish_credential_group_migration_with_job(&work, job.job_id, job.generation, active_leases)
            .await
        {
            Ok(commit) => work.state = commit.state,
            Err(StorageError::CapacityExceeded) => {
                let delay = if work.expired { 1 } else { 2 };
                retry_or_dead_letter_migration(storage, job, "credential_group_migration_draining", delay).await;
                return;
            }
            Err(_) => {
                retry_or_dead_letter_migration(storage, job, "credential_group_migration_commit_failed", 5).await;
                return;
            }
        }
    }
    let projected = if work.state == "committed" {
        let removed = runtime
            .remove_archived_credential_projection(work.source_group_id, work.credential_id)
            .await
            .is_ok();
        let attached = runtime
            .reconfigure_credential_projection(work.target_group_id, work.credential_id)
            .await
            .unwrap_or(false);
        removed && attached
    } else if work.state == "failed" {
        let restored = runtime
            .reconfigure_credential_projection(work.source_group_id, work.credential_id)
            .await
            .unwrap_or(false);
        let unfenced = runtime
            .unfence_credential_for_admin(work.source_group_id, work.credential_id)
            .await
            .unwrap_or(false);
        restored && unfenced
    } else {
        false
    };
    if !projected {
        retry_or_dead_letter_migration(storage, job, "credential_group_migration_projection_failed", 5).await;
        return;
    }
    if storage
        .complete_credential_group_migration_job(migration_id, job.job_id, job.generation)
        .await
        .is_err()
    {
        retry_or_dead_letter_migration(storage, job, "credential_group_migration_finalize_failed", 5).await;
    }
}

async fn retry_or_dead_letter_migration(storage: &PgStorage, job: &JobLease, code: &str, delay_seconds: i32) {
    if job.attempt < job.max_attempts {
        let _ = storage
            .retry_job(job.job_id, job.generation, delay_seconds, code, None)
            .await;
    } else {
        let _ = storage.dead_letter_job(job.job_id, job.generation, code, None).await;
    }
}

async fn process_credential_plan_collection(storage: &PgStorage, collector: Option<&PgPlanCollector>, job: &JobLease) {
    let credential_id = job
        .payload
        .get("credential_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    let expected_revision = job
        .payload
        .get("credential_revision")
        .and_then(serde_json::Value::as_i64);
    let Some((credential_id, expected_revision, collector)) = credential_id
        .zip(expected_revision)
        .and_then(|(credential_id, revision)| collector.map(|collector| (credential_id, revision, collector)))
    else {
        let _ = storage
            .dead_letter_job(
                job.job_id,
                job.generation,
                "credential_plan_collector_unavailable",
                None,
            )
            .await;
        return;
    };
    match collector
        .execute(credential_id, expected_revision, job.job_id, job.generation)
        .await
    {
        Ok(()) => {}
        Err(retry) if job.attempt < job.max_attempts => {
            let _ = storage
                .retry_job(
                    job.job_id,
                    job.generation,
                    i32::try_from(retry.retry_after_seconds).unwrap_or(900),
                    retry.error_code,
                    None,
                )
                .await;
        }
        Err(retry) => {
            if collector
                .finish_failure(
                    credential_id,
                    expected_revision,
                    job.job_id,
                    job.generation,
                    "provider_retry_exhausted",
                )
                .await
                .is_err()
            {
                let _ = storage
                    .dead_letter_job(job.job_id, job.generation, retry.error_code, None)
                    .await;
            }
        }
    }
}

async fn process_model_catalog_discovery(
    storage: &PgStorage,
    collector: Option<&PgModelCatalogCollector>,
    job: &JobLease,
) {
    let uuid = |key: &str| {
        job.payload
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
    };
    let parsed = uuid("source_credential_id")
        .zip(
            job.payload
                .get("credential_revision")
                .and_then(serde_json::Value::as_i64),
        )
        .zip(job.payload.get("token_version").and_then(serde_json::Value::as_i64))
        .zip(uuid("binding_id"))
        .zip(job.payload.get("egress_epoch").and_then(serde_json::Value::as_i64));
    let Some(((((credential_id, revision), token_version), binding_id), egress_epoch)) = parsed else {
        let _ = storage
            .dead_letter_job(job.job_id, job.generation, "model_discovery_payload_invalid", None)
            .await;
        return;
    };
    let Some(collector) = collector else {
        let _ = storage
            .dead_letter_job(
                job.job_id,
                job.generation,
                "model_discovery_collector_unavailable",
                None,
            )
            .await;
        return;
    };
    match collector
        .execute(
            credential_id,
            revision,
            token_version,
            binding_id,
            egress_epoch,
            job.job_id,
            job.generation,
        )
        .await
    {
        Ok(()) => {}
        Err(retry) if job.attempt < job.max_attempts => {
            let _ = storage
                .retry_job(
                    job.job_id,
                    job.generation,
                    i32::try_from(retry.retry_after_seconds).unwrap_or(900),
                    retry.error_code,
                    None,
                )
                .await;
        }
        Err(retry) => {
            let _ = storage
                .dead_letter_job(job.job_id, job.generation, retry.error_code, None)
                .await;
        }
    }
}

#[cfg(target_os = "linux")]
async fn process_credential_egress_rebind(
    storage: &PgStorage,
    runtime: &ProductionDispatcher,
    target: &ProxyProbeTarget,
    job: &JobLease,
) {
    let parsed = parse_egress_rebind_job(job);
    let Some((
        credential_id,
        group_id,
        expected_revision,
        expected_profile_epoch,
        expected_egress_epoch,
        mode,
        proxy_id,
        reason,
    )) = parsed
    else {
        let _ = storage
            .dead_letter_job(
                job.job_id,
                job.generation,
                "credential_egress_rebind_payload_invalid",
                None,
            )
            .await;
        return;
    };
    let committed_profile_epoch = job
        .checkpoint
        .as_ref()
        .filter(|checkpoint| checkpoint.get("phase").and_then(serde_json::Value::as_str) == Some("binding_committed"))
        .and_then(|checkpoint| checkpoint.get("profile_epoch"))
        .and_then(serde_json::Value::as_i64);
    if let Some(profile_epoch) = committed_profile_epoch {
        finish_egress_rebind_projection(storage, runtime, job, group_id, credential_id, profile_epoch).await;
        return;
    }
    let route = match (mode.as_str(), proxy_id) {
        ("direct", None) => EgressRouteSnapshot::Direct,
        ("proxy", Some(proxy_id)) => match resolve_proxy_route(storage, proxy_id).await {
            Ok(route) => route,
            Err(_) => {
                retry_or_dead_letter_migration(storage, job, "credential_egress_rebind_route_unavailable", 30).await;
                return;
            }
        },
        _ => {
            let _ = storage
                .dead_letter_job(
                    job.job_id,
                    job.generation,
                    "credential_egress_rebind_payload_invalid",
                    None,
                )
                .await;
            return;
        }
    };
    let (observed_ip, latency_ms) = match probe_candidate_egress(route, target).await {
        Ok(evidence) => evidence,
        Err(code) => {
            retry_or_dead_letter_migration(storage, job, code, 30).await;
            return;
        }
    };
    let active_leases = match runtime.fence_credential_for_admin(group_id, credential_id).await {
        Ok(Some(value)) => value,
        _ => {
            retry_or_dead_letter_migration(storage, job, "credential_egress_rebind_owner_unavailable", 5).await;
            return;
        }
    };
    if active_leases != 0 {
        retry_or_dead_letter_migration(storage, job, "credential_egress_rebind_draining", 2).await;
        return;
    }
    let commit = storage
        .commit_credential_egress_rebind(&EgressRebindCommit {
            credential_id,
            expected_credential_revision: expected_revision,
            expected_profile_epoch,
            expected_egress_epoch,
            mode,
            proxy_id,
            observed_ip: Some(observed_ip),
            latency_ms,
            reason,
            job_id: job.job_id,
            generation: job.generation,
        })
        .await;
    let commit = match commit {
        Ok(commit) => commit,
        Err(_) => {
            retry_or_dead_letter_migration(storage, job, "credential_egress_rebind_commit_failed", 5).await;
            return;
        }
    };
    finish_egress_rebind_projection(storage, runtime, job, group_id, credential_id, commit.profile_epoch).await;
}

#[cfg(target_os = "linux")]
#[allow(clippy::type_complexity)]
fn parse_egress_rebind_job(job: &JobLease) -> Option<(Uuid, Uuid, i64, i64, i64, String, Option<Uuid>, String)> {
    let uuid = |key: &str| {
        job.payload
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
    };
    let credential_id = uuid("credential_id")?;
    let group_id = uuid("group_id")?;
    let expected_revision = job.payload.get("credential_revision")?.as_i64()?;
    let profile_epoch = job.payload.get("profile_epoch")?.as_i64()?;
    let egress_epoch = job.payload.get("egress_epoch")?.as_i64()?;
    let mode = job.payload.get("mode")?.as_str()?.to_owned();
    let proxy_id = job
        .payload
        .get("proxy_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    let reason = job.payload.get("reason")?.as_str()?.to_owned();
    Some((
        credential_id,
        group_id,
        expected_revision,
        profile_epoch,
        egress_epoch,
        mode,
        proxy_id,
        reason,
    ))
}

#[cfg(target_os = "linux")]
async fn probe_candidate_egress(
    route: EgressRouteSnapshot,
    target: &ProxyProbeTarget,
) -> Result<(String, i32), &'static str> {
    let started = tokio::time::Instant::now();
    let client = ProviderHttpsClient::default();
    let cancellation = CancellationToken::new();
    let observer = client
        .execute(ProviderHttpsRequest {
            method: Method::GET,
            host: target.observer_host.clone().into_boxed_str(),
            port: 443,
            host_header: target.observer_host.clone().into_boxed_str(),
            path_and_query: SecretValue::new(target.observer_path.clone()),
            headers: Vec::new(),
            body: SecretBytes::new(Vec::new()),
            response_limit: 256,
            egress: route.clone(),
            cancellation: cancellation.clone(),
        })
        .await
        .map_err(|error| match classify_proxy_probe_error(error.code) {
            "auth_failed" => "credential_egress_rebind_proxy_auth_failed",
            "tls_intercepted" => "credential_egress_rebind_tls_intercepted",
            _ => "credential_egress_rebind_probe_failed",
        })?;
    if observer.status != 200 {
        return Err("credential_egress_rebind_observer_failed");
    }
    let observed_ip = std::str::from_utf8(observer.body.expose())
        .ok()
        .map(str::trim)
        .filter(|value| value.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_owned)
        .ok_or("credential_egress_rebind_observer_invalid")?;
    client
        .execute(ProviderHttpsRequest {
            method: Method::GET,
            host: "api.anthropic.com".into(),
            port: 443,
            host_header: "api.anthropic.com".into(),
            path_and_query: SecretValue::new("/".to_owned()),
            headers: Vec::new(),
            body: SecretBytes::new(Vec::new()),
            response_limit: 1024 * 1024,
            egress: route,
            cancellation,
        })
        .await
        .map_err(|error| match classify_proxy_probe_error(error.code) {
            "tls_intercepted" => "credential_egress_rebind_tls_intercepted",
            _ => "credential_egress_rebind_anthropic_probe_failed",
        })?;
    Ok((
        observed_ip,
        i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX),
    ))
}

#[cfg(target_os = "linux")]
async fn finish_egress_rebind_projection(
    storage: &PgStorage,
    runtime: &ProductionDispatcher,
    job: &JobLease,
    group_id: Uuid,
    credential_id: Uuid,
    profile_epoch: i64,
) {
    let epoch = match u64::try_from(profile_epoch) {
        Ok(epoch) => epoch,
        Err(_) => {
            let _ = storage
                .dead_letter_job(
                    job.job_id,
                    job.generation,
                    "credential_egress_rebind_epoch_invalid",
                    None,
                )
                .await;
            return;
        }
    };
    let drained = runtime.advance_credential_profile_epoch(credential_id, epoch).is_ok();
    let projected = runtime
        .reconfigure_credential_projection(group_id, credential_id)
        .await
        .unwrap_or(false);
    let unfenced = runtime
        .unfence_credential_for_admin(group_id, credential_id)
        .await
        .unwrap_or(false);
    if !(drained && projected && unfenced) {
        retry_or_dead_letter_migration(storage, job, "credential_egress_rebind_projection_failed", 5).await;
        return;
    }
    if storage
        .complete_job(job.job_id, job.generation, "credential_egress_rebind_complete")
        .await
        .is_err()
    {
        retry_or_dead_letter_migration(storage, job, "credential_egress_rebind_finalize_failed", 5).await;
    }
}

async fn process_upgrade_preflight(storage: &PgStorage, readiness: &ReadinessCoordinator, job: &JobLease) {
    let Some(run_id) = job
        .payload
        .get("upgrade_run_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        let _ = storage
            .dead_letter_job(job.job_id, job.generation, "upgrade_preflight_payload_invalid", None)
            .await;
        return;
    };
    let work = match storage
        .start_upgrade_preflight(run_id, job.job_id, job.generation)
        .await
    {
        Ok(work) => work,
        Err(_) => {
            finish_upgrade_preflight_failure(storage, run_id, job, "upgrade_preflight_start_failed").await;
            return;
        }
    };
    let gates = match collect_upgrade_preflight_gates(storage, readiness, &work.manifest).await {
        Ok(gates) => gates,
        Err(_) => {
            finish_upgrade_preflight_failure(storage, run_id, job, "upgrade_preflight_evidence_unavailable").await;
            return;
        }
    };
    let failed = gates.iter().filter(|gate| gate.state == "failed").count();
    let blocked = gates.iter().filter(|gate| gate.state == "blocked_external").count();
    let state = if failed > 0 {
        "failed"
    } else if blocked > 0 {
        "blocked_external"
    } else {
        "passed"
    };
    let result = json!({
        "schema_version":1,
        "candidate_release":work.release_version,
        "candidate_digest":lower_hex(&work.candidate_digest),
        "gate_count":gates.len(),
        "failed_count":failed,
        "blocked_external_count":blocked,
        "valid_for_seconds":1800
    });
    if storage
        .complete_upgrade_preflight(&UpgradePreflightCommit {
            run_id,
            job_id: job.job_id,
            generation: job.generation,
            state: state.to_owned(),
            result,
            gates,
        })
        .await
        .is_err()
    {
        finish_upgrade_preflight_failure(storage, run_id, job, "upgrade_preflight_commit_failed").await;
    }
}

async fn finish_upgrade_preflight_failure(storage: &PgStorage, run_id: Uuid, job: &JobLease, code: &str) {
    if job.attempt < job.max_attempts {
        let _ = storage.retry_job(job.job_id, job.generation, 30, code, None).await;
    } else {
        let _ = storage
            .fail_upgrade_preflight(run_id, job.job_id, job.generation, code)
            .await;
    }
}

async fn collect_upgrade_preflight_gates(
    storage: &PgStorage,
    readiness: &ReadinessCoordinator,
    manifest: &serde_json::Value,
) -> Result<Vec<UpgradeGateCommit>, StorageError> {
    let mut gates = Vec::with_capacity(11);
    let runtime_abi = manifest.get("runtime_abi_version").and_then(serde_json::Value::as_str);
    gates.push(upgrade_gate(
        "runtime_abi",
        if runtime_abi == Some("r2-v1") {
            "passed"
        } else {
            "failed"
        },
        json!({"required":"r2-v1","candidate":runtime_abi}),
    ));
    let target = manifest.get("target").and_then(serde_json::Value::as_str);
    let runtime_target = crate::app::runtime_target();
    gates.push(upgrade_gate(
        "runtime_target",
        if target == Some(runtime_target) {
            "passed"
        } else {
            "failed"
        },
        json!({"required":runtime_target,"candidate":target}),
    ));

    let report = storage.validate_schema().await?;
    let compatibility = manifest
        .get("schema_compatibility")
        .and_then(serde_json::Value::as_object);
    let minimum = compatibility
        .and_then(|value| value.get("minimum"))
        .and_then(serde_json::Value::as_i64);
    let maximum = compatibility
        .and_then(|value| value.get("maximum"))
        .and_then(serde_json::Value::as_i64);
    let schema_compatible = minimum
        .zip(maximum)
        .is_some_and(|(min, max)| min <= report.current_version && report.current_version <= max);
    gates.push(upgrade_gate(
        "schema_compatibility",
        if schema_compatible { "passed" } else { "failed" },
        json!({"database_version":report.current_version,"minimum":minimum,"maximum":maximum}),
    ));

    let candidate_versions = manifest
        .get("migration_checksums")
        .and_then(serde_json::Value::as_object)
        .map(|checksums| {
            checksums
                .keys()
                .filter_map(|name| name.split('_').next()?.parse::<i64>().ok())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let applied_versions =
        sqlx::query_scalar::<_, i64>("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version")
            .fetch_all(&storage.pool())
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
    let migration_prefix = applied_versions
        .iter()
        .all(|version| candidate_versions.contains(version));
    gates.push(upgrade_gate(
        "migration_prefix",
        if migration_prefix { "passed" } else { "failed" },
        json!({"applied_count":applied_versions.len(),"candidate_count":candidate_versions.len(),"complete_prefix":migration_prefix}),
    ));

    let snapshot = readiness.internal_snapshot();
    let blockers = snapshot.blockers();
    gates.push(upgrade_gate(
        "runtime_readiness",
        if blockers.is_empty() { "passed" } else { "failed" },
        json!({"blockers":blockers}),
    ));
    gates.push(upgrade_gate(
        "audit_deletion_integrity",
        if snapshot.audit_integrity_ready {
            "passed"
        } else {
            "failed"
        },
        json!({"ready":snapshot.audit_integrity_ready}),
    ));

    let unavailable_bundles: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM gateway.anthropic_credential credential \
         JOIN gateway.credential_profile profile ON profile.credential_id=credential.id \
         LEFT JOIN catalog.archetype_bundle_binding binding \
           ON binding.archetype_version_id=profile.archetype_version_id AND binding.state_code='active' \
         LEFT JOIN catalog.transport_bundle bundle ON bundle.id=binding.transport_bundle_id \
         WHERE credential.lifecycle_state_code='active' AND profile.lifecycle_code='active' \
           AND (bundle.id IS NULL OR bundle.lifecycle_code NOT IN ('canary','active') \
             OR bundle.runtime_state_code<>'loadable' OR bundle.evidence_gate_code<>'passed')",
    )
    .fetch_one(&storage.pool())
    .await
    .map_err(|_| StorageError::TransactionFailed)?;
    gates.push(upgrade_gate(
        "active_transport_bundles",
        if unavailable_bundles == 0 { "passed" } else { "failed" },
        json!({"unavailable_count":unavailable_bundles}),
    ));

    let critical_alerts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ops.alert WHERE severity_code='critical' \
         AND state_code IN ('open','acknowledged','silenced')",
    )
    .fetch_one(&storage.pool())
    .await
    .map_err(|_| StorageError::TransactionFailed)?;
    gates.push(upgrade_gate(
        "critical_alerts",
        if critical_alerts == 0 { "passed" } else { "failed" },
        json!({"active_count":critical_alerts,"silence_does_not_bypass":true}),
    ));

    let (base_fresh, wal_fresh, drill_fresh): (bool, bool, bool) = sqlx::query_as(
        "SELECT \
           COALESCE(MAX(completed_at) FILTER (WHERE state_code='succeeded') \
             > clock_timestamp()-interval '26 hours',false), \
           COALESCE(MAX(wal_archived_at) FILTER (WHERE state_code='succeeded') \
             > clock_timestamp()-interval '300 seconds',false), \
           COALESCE((SELECT MAX(completed_at)>clock_timestamp()-interval '45 days' \
             FROM ops.restore_drill WHERE kind_code='full_restore_drill' AND state_code='succeeded'),false) \
         FROM ops.backup_run",
    )
    .fetch_one(&storage.pool())
    .await
    .map_err(|_| StorageError::TransactionFailed)?;
    gates.push(upgrade_gate(
        "backup_recovery_freshness",
        if base_fresh && wal_fresh && drill_fresh {
            "passed"
        } else {
            "failed"
        },
        json!({"base_backup_26h":base_fresh,"wal_300s":wal_fresh,"restore_drill_45d":drill_fresh}),
    ));

    gates.push(upgrade_gate(
        "filesystem_capacity",
        "blocked_external",
        json!({"reason":"filesystem_capacity_provider_not_configured"}),
    ));
    gates.push(upgrade_gate(
        "n_minus_compatibility",
        "blocked_external",
        json!({"reason":"n_minus_1_and_n_minus_2_fixture_evidence_required"}),
    ));
    Ok(gates)
}

fn upgrade_gate(code: &str, state: &str, detail: serde_json::Value) -> UpgradeGateCommit {
    UpgradeGateCommit {
        code: code.to_owned(),
        state: state.to_owned(),
        detail,
    }
}

async fn process_backup_create(storage: &PgStorage, executor: &dyn BackupOperationsExecutor, job: &JobLease) {
    let Some(run_id) = job
        .payload
        .get("backup_run_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        let _ = storage
            .dead_letter_job(job.job_id, job.generation, "backup_payload_invalid", None)
            .await;
        return;
    };
    if storage
        .start_backup_run(run_id, job.job_id, job.generation)
        .await
        .is_err()
    {
        finish_backup_failure(
            storage,
            "backup_run",
            run_id,
            job,
            BackupOperationFailure::Transient("backup_projection_unavailable".to_owned()),
        )
        .await;
        return;
    }
    let result = executor
        .execute(BackupOperationRequest {
            operation_id: run_id,
            kind: BackupOperationKind::BackupCreate,
            backup_run_id: None,
            recovery_point: None,
            manifest: None,
            manifest_sha256_hex: None,
        })
        .await;
    let BackupOperationResult::Backup {
        manifest,
        manifest_sha256_hex,
        database_system_id,
        timeline,
        lsn_start,
        lsn_end,
        wal_archived_at,
        watermarks,
        backup_key_version,
        repository_ref,
        bytes_written,
    } = (match result {
        Ok(result) => result,
        Err(error) => {
            finish_backup_failure(storage, "backup_run", run_id, job, error).await;
            return;
        }
    })
    else {
        finish_backup_failure(
            storage,
            "backup_run",
            run_id,
            job,
            BackupOperationFailure::Terminal("backup_adapter_result_kind_invalid".to_owned()),
        )
        .await;
        return;
    };
    let Some(manifest_sha256) = decode_hex_32(&manifest_sha256_hex) else {
        finish_backup_failure(
            storage,
            "backup_run",
            run_id,
            job,
            BackupOperationFailure::Terminal("backup_manifest_digest_invalid".to_owned()),
        )
        .await;
        return;
    };
    let manifest_bytes = match serde_json::to_vec(&manifest) {
        Ok(bytes) => bytes,
        Err(_) => Vec::new(),
    };
    if sha2::Sha256::digest(&manifest_bytes).as_slice() != manifest_sha256.as_slice()
        || database_system_id.trim().is_empty()
        || timeline < 1
        || backup_key_version < 1
        || bytes_written < 0
        || repository_ref.trim().is_empty()
        || repository_ref.len() > 512
        || repository_ref
            .chars()
            .any(|character| matches!(character, '@' | '?' | '#'))
        || wal_archived_at.trim().is_empty()
        || json_contains_secret_shape(&manifest)
        || json_contains_secret_shape(&watermarks)
    {
        finish_backup_failure(
            storage,
            "backup_run",
            run_id,
            job,
            BackupOperationFailure::Terminal("backup_evidence_invalid".to_owned()),
        )
        .await;
        return;
    }
    let commit = BackupRunCommit {
        run_id,
        job_id: job.job_id,
        generation: job.generation,
        manifest,
        manifest_sha256,
        database_system_id,
        timeline,
        lsn_start,
        lsn_end,
        wal_archived_at,
        watermarks,
        backup_key_version,
        repository_ref,
        bytes_written,
    };
    if storage.complete_backup_run(&commit).await.is_err() {
        finish_backup_failure(
            storage,
            "backup_run",
            run_id,
            job,
            BackupOperationFailure::Transient("backup_commit_failed".to_owned()),
        )
        .await;
    }
}

async fn process_restore_operation(storage: &PgStorage, executor: &dyn BackupOperationsExecutor, job: &JobLease) {
    let Some(drill_id) = job
        .payload
        .get("restore_drill_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        let _ = storage
            .dead_letter_job(job.job_id, job.generation, "restore_payload_invalid", None)
            .await;
        return;
    };
    let work = match storage
        .start_restore_operation(drill_id, job.job_id, job.generation)
        .await
    {
        Ok(work) => work,
        Err(_) => {
            finish_backup_failure(
                storage,
                "restore_drill",
                drill_id,
                job,
                BackupOperationFailure::Transient("restore_projection_unavailable".to_owned()),
            )
            .await;
            return;
        }
    };
    let kind = match work.kind.as_str() {
        "manifest_validation" => BackupOperationKind::ManifestValidation,
        "full_restore_drill" => BackupOperationKind::FullRestoreDrill,
        _ => {
            finish_backup_failure(
                storage,
                "restore_drill",
                drill_id,
                job,
                BackupOperationFailure::Terminal("restore_kind_invalid".to_owned()),
            )
            .await;
            return;
        }
    };
    let result = executor
        .execute(BackupOperationRequest {
            operation_id: drill_id,
            kind,
            backup_run_id: Some(work.backup_run_id),
            recovery_point: work.recovery_point,
            manifest: Some(work.manifest),
            manifest_sha256_hex: Some(lower_hex(&work.manifest_sha256)),
        })
        .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            finish_backup_failure(storage, "restore_drill", drill_id, job, error).await;
            return;
        }
    };
    let completion = match result {
        BackupOperationResult::Validation {
            manifest_sha256_hex,
            checks,
            lineage,
        } if kind == BackupOperationKind::ManifestValidation => {
            let Some(digest) = decode_hex_32(&manifest_sha256_hex) else {
                finish_backup_failure(
                    storage,
                    "restore_drill",
                    drill_id,
                    job,
                    BackupOperationFailure::Terminal("restore_manifest_digest_invalid".to_owned()),
                )
                .await;
                return;
            };
            if digest != work.manifest_sha256 {
                finish_backup_failure(
                    storage,
                    "restore_drill",
                    drill_id,
                    job,
                    BackupOperationFailure::Terminal("restore_manifest_digest_mismatch".to_owned()),
                )
                .await;
                return;
            }
            if json_contains_secret_shape(&checks) || json_contains_secret_shape(&lineage) {
                finish_backup_failure(
                    storage,
                    "restore_drill",
                    drill_id,
                    job,
                    BackupOperationFailure::Terminal("restore_evidence_contains_secret".to_owned()),
                )
                .await;
                return;
            }
            storage
                .complete_restore_validation(&RestoreValidationCommit {
                    drill_id,
                    job_id: job.job_id,
                    generation: job.generation,
                    manifest_sha256: digest,
                    checks,
                    lineage,
                })
                .await
        }
        BackupOperationResult::Drill {
            manifest_sha256_hex,
            isolated_environment_id,
            db_recovered,
            object_replayed,
            ledger_replayed,
            checks,
            lineage,
            rpo_seconds,
            rto_seconds,
            serving_simulated,
            destroyed,
        } if kind == BackupOperationKind::FullRestoreDrill => {
            let Some(digest) = decode_hex_32(&manifest_sha256_hex) else {
                finish_backup_failure(
                    storage,
                    "restore_drill",
                    drill_id,
                    job,
                    BackupOperationFailure::Terminal("restore_manifest_digest_invalid".to_owned()),
                )
                .await;
                return;
            };
            if digest != work.manifest_sha256
                || isolated_environment_id.trim().is_empty()
                || rpo_seconds < 0
                || rto_seconds < 0
                || rpo_seconds > 300
                || rto_seconds > 3_600
                || !db_recovered
                || !object_replayed
                || !ledger_replayed
                || !serving_simulated
                || !destroyed
                || json_contains_secret_shape(&checks)
                || json_contains_secret_shape(&lineage)
            {
                finish_backup_failure(
                    storage,
                    "restore_drill",
                    drill_id,
                    job,
                    BackupOperationFailure::Terminal("restore_evidence_invalid".to_owned()),
                )
                .await;
                return;
            }
            storage
                .complete_restore_drill(&RestoreDrillCommit {
                    drill_id,
                    job_id: job.job_id,
                    generation: job.generation,
                    manifest_sha256: digest,
                    isolated_environment_id,
                    db_recovered,
                    object_replayed,
                    ledger_replayed,
                    checks,
                    lineage,
                    rpo_seconds,
                    rto_seconds,
                    serving_simulated,
                    destroyed,
                })
                .await
        }
        _ => Err(StorageError::InvalidLifecycle),
    };
    if completion.is_err() {
        finish_backup_failure(
            storage,
            "restore_drill",
            drill_id,
            job,
            BackupOperationFailure::Transient("restore_commit_failed".to_owned()),
        )
        .await;
    }
}

async fn finish_backup_failure(
    storage: &PgStorage,
    projection: &str,
    projection_id: Uuid,
    job: &JobLease,
    failure: BackupOperationFailure,
) {
    match failure {
        BackupOperationFailure::Transient(error) if job.attempt < job.max_attempts => {
            let code = sanitized_backup_error(&error, "backup_transient_failure");
            let _ = storage.retry_job(job.job_id, job.generation, 30, code, None).await;
        }
        BackupOperationFailure::Transient(error) | BackupOperationFailure::Terminal(error) => {
            let code = sanitized_backup_error(&error, "backup_terminal_failure");
            if storage
                .fail_backup_operation(projection, projection_id, job.job_id, job.generation, code)
                .await
                .is_ok()
            {
                upsert_critical_alert(
                    storage,
                    &format!("{projection}_failed:{projection_id}"),
                    "Backup or isolated restore operation failed",
                )
                .await;
            }
        }
    }
}

fn sanitized_backup_error<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        value
    } else {
        fallback
    }
}

fn decode_hex_32(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

fn json_contains_secret_shape(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
            let normalized = key.to_ascii_lowercase();
            matches!(
                normalized.as_str(),
                "secret"
                    | "password"
                    | "access_token"
                    | "refresh_token"
                    | "setup_token"
                    | "credential"
                    | "private_key"
                    | "key_file"
                    | "repository_uri"
            ) || json_contains_secret_shape(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(json_contains_secret_shape),
        _ => false,
    }
}

async fn process_usage_export(storage: &PgStorage, store: &ExportArtifactStore, job: &JobLease) {
    let Some(export_id) = job
        .payload
        .get("export_job_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        let _ = storage
            .dead_letter_job(job.job_id, job.generation, "usage_export_payload_invalid", None)
            .await;
        return;
    };
    let work = match storage.start_usage_export(export_id, job.job_id, job.generation).await {
        Ok(work) => work,
        Err(_) if job.attempt < job.max_attempts => {
            let _ = storage
                .retry_job(job.job_id, job.generation, 30, "usage_export_query_failed", None)
                .await;
            return;
        }
        Err(_) => {
            let _ = storage
                .fail_usage_export(export_id, job.job_id, job.generation, "usage_export_query_failed")
                .await;
            return;
        }
    };
    if work.dataset != "usage_requests_v1" || work.query_sha256.len() != 32 {
        let _ = storage
            .fail_usage_export(export_id, job.job_id, job.generation, "usage_export_contract_invalid")
            .await;
        return;
    }
    let format = match work.format.as_str() {
        "jsonl" => ExportFormat::Jsonl,
        "csv" => ExportFormat::Csv,
        _ => {
            let _ = storage
                .fail_usage_export(export_id, job.job_id, job.generation, "usage_export_format_invalid")
                .await;
            return;
        }
    };
    let rows = work
        .rows
        .into_iter()
        .map(|row| UsageExportRow {
            request_id: row.request_id,
            created_at: row.created_at,
            owner_user_id: row.owner_user_id,
            platform_key_id: row.platform_key_id,
            platform_key_name: row.platform_key_name,
            group_id: row.group_id,
            group_name: row.group_name,
            model_id: row.model_id,
            upstream_model_id: row.upstream_model_id,
            endpoint: row.endpoint,
            outcome: row.outcome,
            http_status: row.http_status,
            usage_source: row.usage_source,
            usage_completeness: row.usage_completeness,
            input_tokens: row.input_tokens,
            output_tokens: row.output_tokens,
            cache_creation_input_tokens: row.cache_creation_input_tokens,
            cache_read_input_tokens: row.cache_read_input_tokens,
            amount: row.amount,
            currency: row.currency,
        })
        .collect::<Vec<_>>();
    let plaintext = match encode_usage_export(format, &rows) {
        Ok(plaintext) => plaintext,
        Err(ExportError::TooManyRows | ExportError::TooLarge | ExportError::Encoding) => {
            let _ = storage
                .fail_usage_export(export_id, job.job_id, job.generation, "usage_export_limit_exceeded")
                .await;
            return;
        }
        Err(_) => {
            let _ = storage
                .fail_usage_export(export_id, job.job_id, job.generation, "usage_export_encoding_failed")
                .await;
            return;
        }
    };
    let key_version: i64 = match sqlx::query_scalar(
        "SELECT key_version FROM security.business_key_material \
         WHERE provider_code='database' AND state_code='active'",
    )
    .fetch_optional(&storage.pool())
    .await
    {
        Ok(Some(value)) => value,
        _ => {
            finish_usage_export_transient(storage, export_id, job, "usage_export_key_unavailable").await;
            return;
        }
    };
    let root_key = match storage.load_database_business_key(key_version).await {
        Ok(value) => value,
        Err(_) => {
            finish_usage_export_transient(storage, export_id, job, "usage_export_key_unavailable").await;
            return;
        }
    };
    let context = ExportArtifactContext {
        export_id,
        requested_by: work.requested_by,
        dataset: work.dataset.into_boxed_str(),
        format,
        query_sha256_hex: lower_hex(&work.query_sha256).into_boxed_str(),
    };
    let manifest = match store.put(&context, &plaintext, &root_key, key_version).await {
        Ok(manifest) => manifest,
        Err(_) => {
            finish_usage_export_transient(storage, export_id, job, "usage_export_store_failed").await;
            return;
        }
    };
    let commit = UsageExportArtifactCommit {
        export_id,
        job_id: job.job_id,
        generation: job.generation,
        object_uri: manifest.object_uri.to_string(),
        content_sha256: manifest.content_sha256,
        row_count: i64::try_from(rows.len()).unwrap_or(i64::MAX),
        content_length: manifest.content_length,
        cipher_suite: manifest.cipher_suite.to_string(),
        nonce: manifest.nonce,
        wrapped_dek: manifest.wrapped_dek,
        key_version: manifest.key_version,
    };
    if storage.commit_usage_export(&commit).await.is_err() {
        let _ = store.remove_uri(&commit.object_uri).await;
        finish_usage_export_transient(storage, export_id, job, "usage_export_commit_failed").await;
    }
}

struct ContentAuditExportWork {
    export_id: Uuid,
    requested_by: Uuid,
    query_sha256: Vec<u8>,
    object_id: Uuid,
    request_id: Uuid,
    attempt_id: Option<Uuid>,
    object_kind: String,
    object_uri: String,
    encrypted_dek: Vec<u8>,
    cipher_suite: String,
    content_sha256: Vec<u8>,
    content_length: i64,
    frame_manifest: serde_json::Value,
}

async fn load_content_audit_export_work(
    storage: &PgStorage,
    export_id: Uuid,
    job: &JobLease,
) -> Result<ContentAuditExportWork, StorageError> {
    let mut transaction = storage
        .pool()
        .begin()
        .await
        .map_err(|_| StorageError::ConnectionFailed)?;
    let row = sqlx::query(
        "SELECT export.requested_by,export.dataset_code,export.format_code,export.query_sha256, \
                object.id AS object_id,object.request_id,object.attempt_id,object.object_kind_code,object.object_uri,object.encrypted_dek, \
                object.cipher_suite_code,object.content_sha256,object.content_length,object.frame_manifest \
         FROM ops.export_job export \
         JOIN ops.durable_job job ON job.id=export.durable_job_id \
         JOIN security.content_audit_export_binding binding ON binding.export_job_id=export.id \
         JOIN security.content_audit_search_session session ON session.id=binding.search_session_id \
         JOIN security.content_audit_search_candidate candidate \
           ON candidate.search_session_id=session.id AND candidate.content_audit_object_id=binding.content_audit_object_id \
         JOIN security.content_audit_object object ON object.id=binding.content_audit_object_id \
         WHERE export.id=$1 AND job.id=$2 AND job.state_code='leased' AND job.lease_generation=$3 \
           AND export.state_code IN ('queued','running') AND export.dataset_code='content_audit_record_v1' \
           AND export.format_code='raw' AND session.actor_user_id=export.requested_by \
           AND session.expires_at>clock_timestamp() AND object.scope_code='full_encrypted' \
           AND object.storage_state_code='finalized' AND object.state_code IN ('active','held') \
           AND object.deleted_at IS NULL \
           AND (object.state_code='held' OR object.legal_hold_count>0 OR object.expires_at>clock_timestamp()) \
         FOR UPDATE OF export,job",
    )
    .bind(export_id)
    .bind(job.job_id)
    .bind(job.generation)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| StorageError::ConnectionFailed)?
    .ok_or(StorageError::RevisionConflict)?;
    sqlx::query(
        "UPDATE ops.export_job SET state_code='running',revision=revision+1 WHERE id=$1 AND state_code='queued'",
    )
    .bind(export_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| StorageError::ConnectionFailed)?;
    let work = ContentAuditExportWork {
        export_id,
        requested_by: row
            .try_get("requested_by")
            .map_err(|_| StorageError::IntegrityViolation)?,
        query_sha256: row
            .try_get("query_sha256")
            .map_err(|_| StorageError::IntegrityViolation)?,
        object_id: row.try_get("object_id").map_err(|_| StorageError::IntegrityViolation)?,
        request_id: row
            .try_get("request_id")
            .map_err(|_| StorageError::IntegrityViolation)?,
        attempt_id: row
            .try_get("attempt_id")
            .map_err(|_| StorageError::IntegrityViolation)?,
        object_kind: row
            .try_get("object_kind_code")
            .map_err(|_| StorageError::IntegrityViolation)?,
        object_uri: row
            .try_get("object_uri")
            .map_err(|_| StorageError::IntegrityViolation)?,
        encrypted_dek: row
            .try_get("encrypted_dek")
            .map_err(|_| StorageError::IntegrityViolation)?,
        cipher_suite: row
            .try_get("cipher_suite_code")
            .map_err(|_| StorageError::IntegrityViolation)?,
        content_sha256: row
            .try_get("content_sha256")
            .map_err(|_| StorageError::IntegrityViolation)?,
        content_length: row
            .try_get("content_length")
            .map_err(|_| StorageError::IntegrityViolation)?,
        frame_manifest: row
            .try_get("frame_manifest")
            .map_err(|_| StorageError::IntegrityViolation)?,
    };
    transaction.commit().await.map_err(|_| StorageError::ConnectionFailed)?;
    Ok(work)
}

async fn process_content_audit_export(
    storage: &PgStorage,
    content_store: &ContentAuditStore,
    export_store: &ExportArtifactStore,
    job: &JobLease,
) {
    let Some(export_id) = job
        .payload
        .get("export_job_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        let _ = storage
            .dead_letter_job(job.job_id, job.generation, "content_audit_export_payload_invalid", None)
            .await;
        return;
    };
    let work = match load_content_audit_export_work(storage, export_id, job).await {
        Ok(work) => work,
        Err(_) if job.attempt < job.max_attempts => {
            let _ = storage
                .retry_job(job.job_id, job.generation, 30, "content_audit_export_load_failed", None)
                .await;
            return;
        }
        Err(_) => {
            let _ = storage
                .fail_usage_export(
                    export_id,
                    job.job_id,
                    job.generation,
                    "content_audit_export_load_failed",
                )
                .await;
            return;
        }
    };
    let manifest: AuditObjectManifest = match work
        .frame_manifest
        .get("manifest")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
    {
        Some(manifest) => manifest,
        None => {
            let _ = storage
                .fail_usage_export(export_id, job.job_id, job.generation, "content_audit_source_invalid")
                .await;
            return;
        }
    };
    let internal_kind = work
        .frame_manifest
        .get("capture_kind")
        .and_then(serde_json::Value::as_str);
    let (capture_kind, contract_kind) = match internal_kind {
        Some("original_request") => (AuditCaptureKind::OriginalRequest, "original_request"),
        Some("final_request" | "final_upstream_request") => (AuditCaptureKind::FinalRequest, "final_upstream_request"),
        Some("response" | "upstream_response") => (AuditCaptureKind::Response, "upstream_response"),
        _ => {
            let _ = storage
                .fail_usage_export(export_id, job.job_id, job.generation, "content_audit_source_invalid")
                .await;
            return;
        }
    };
    let policy_version = work
        .frame_manifest
        .get("policy_version")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty());
    let manifest_dek = base64::engine::general_purpose::STANDARD
        .decode(manifest.wrapped_dek_base64.as_bytes())
        .ok();
    if work.query_sha256.len() != 32
        || manifest.object_id != work.object_id
        || manifest.object_uri.as_ref() != work.object_uri
        || manifest_dek.as_deref() != Some(work.encrypted_dek.as_slice())
        || manifest.cipher_suite.as_ref() != work.cipher_suite
        || work.object_kind != contract_kind
        || u64::try_from(work.content_length).ok() != Some(manifest.plaintext_length)
        || policy_version.is_none()
    {
        let _ = storage
            .fail_usage_export(export_id, job.job_id, job.generation, "content_audit_source_invalid")
            .await;
        return;
    }
    let context = AuditObjectContext {
        object_id: work.object_id,
        request_id: work.request_id,
        attempt_id: work.attempt_id,
        kind: capture_kind,
        policy_version: policy_version.unwrap_or_default().to_owned().into_boxed_str(),
    };
    let plaintext = match content_store.read(&context, &manifest).await {
        Ok(plaintext) if sha2::Sha256::digest(&plaintext).as_slice() == work.content_sha256.as_slice() => plaintext,
        _ => {
            let _ = storage
                .fail_usage_export(export_id, job.job_id, job.generation, "content_audit_source_invalid")
                .await;
            return;
        }
    };
    let key_version: i64 = match sqlx::query_scalar(
        "SELECT key_version FROM security.business_key_material \
         WHERE provider_code='database' AND state_code='active'",
    )
    .fetch_optional(&storage.pool())
    .await
    {
        Ok(Some(value)) => value,
        _ => {
            finish_usage_export_transient(storage, export_id, job, "content_audit_export_key_unavailable").await;
            return;
        }
    };
    let root_key = match storage.load_database_business_key(key_version).await {
        Ok(value) => value,
        Err(_) => {
            finish_usage_export_transient(storage, export_id, job, "content_audit_export_key_unavailable").await;
            return;
        }
    };
    let artifact_context = ExportArtifactContext {
        export_id: work.export_id,
        requested_by: work.requested_by,
        dataset: "content_audit_record_v1".into(),
        format: ExportFormat::Raw,
        query_sha256_hex: lower_hex(&work.query_sha256).into_boxed_str(),
    };
    let artifact = match export_store
        .put(&artifact_context, &plaintext, &root_key, key_version)
        .await
    {
        Ok(artifact) => artifact,
        Err(_) => {
            finish_usage_export_transient(storage, export_id, job, "content_audit_export_store_failed").await;
            return;
        }
    };
    let commit = UsageExportArtifactCommit {
        export_id,
        job_id: job.job_id,
        generation: job.generation,
        object_uri: artifact.object_uri.to_string(),
        content_sha256: artifact.content_sha256,
        row_count: 1,
        content_length: artifact.content_length,
        cipher_suite: artifact.cipher_suite.to_string(),
        nonce: artifact.nonce,
        wrapped_dek: artifact.wrapped_dek,
        key_version: artifact.key_version,
    };
    if storage.commit_usage_export(&commit).await.is_err() {
        let _ = export_store.remove_uri(&commit.object_uri).await;
        finish_usage_export_transient(storage, export_id, job, "content_audit_export_commit_failed").await;
    }
}

async fn finish_usage_export_transient(storage: &PgStorage, export_id: Uuid, job: &JobLease, error_code: &'static str) {
    if job.attempt < job.max_attempts {
        let _ = storage
            .retry_job(job.job_id, job.generation, 30, error_code, None)
            .await;
    } else {
        let _ = storage
            .fail_usage_export(export_id, job.job_id, job.generation, error_code)
            .await;
    }
}

async fn process_business_key_rotation(
    storage: &PgStorage,
    job: &JobLease,
    worker_id: &str,
) -> Result<(), RotationJobError> {
    let old_key_version = job
        .payload
        .get("old_key_version")
        .and_then(serde_json::Value::as_i64)
        .filter(|value| *value >= 1)
        .ok_or(RotationJobError::PayloadInvalid)?;
    let new_key_version = job
        .payload
        .get("new_key_version")
        .and_then(serde_json::Value::as_i64)
        .filter(|value| *value > old_key_version)
        .ok_or(RotationJobError::PayloadInvalid)?;
    let batch_size = job
        .payload
        .get("batch_size")
        .and_then(serde_json::Value::as_i64)
        .filter(|value| (1..=1_000).contains(value))
        .ok_or(RotationJobError::PayloadInvalid)?;
    let mut after_secret_id = job
        .checkpoint
        .as_ref()
        .and_then(|value| value.get("after_secret_id"))
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    let mut rewrapped = job
        .checkpoint
        .as_ref()
        .and_then(|value| value.get("rewrapped"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let mut cas_conflicts = job
        .checkpoint
        .as_ref()
        .and_then(|value| value.get("cas_conflicts"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let mut rescans = 0_u8;
    loop {
        let report =
            rewrap_database_business_batch(storage, old_key_version, new_key_version, after_secret_id, batch_size)
                .await
                .map_err(|_| RotationJobError::Transient("business_key_rewrap_failed"))?;
        rewrapped =
            rewrapped.saturating_add(u64::try_from(report.rewrapped).map_err(|_| RotationJobError::PayloadInvalid)?);
        cas_conflicts = cas_conflicts
            .saturating_add(u64::try_from(report.cas_conflicts).map_err(|_| RotationJobError::PayloadInvalid)?);
        after_secret_id = report.next_checkpoint;
        let mut checkpoint = json!({
            "schema_version":1,
            "phase":"rewrapping",
            "after_secret_id":after_secret_id,
            "rewrapped":rewrapped,
            "cas_conflicts":cas_conflicts,
            "remaining_old_references":null
        });
        if report.complete {
            let remaining = storage
                .count_live_business_key_references(old_key_version)
                .await
                .map_err(|_| RotationJobError::Transient("business_key_reference_count_failed"))?;
            checkpoint["remaining_old_references"] = json!(remaining);
            if remaining == 0 {
                checkpoint["phase"] = json!("rewrap_complete_key_decrypt_only");
                storage
                    .heartbeat_job(
                        job.job_id,
                        job.generation,
                        worker_id,
                        WORKER_LEASE_SECONDS,
                        Some(&checkpoint),
                    )
                    .await
                    .map_err(|_| RotationJobError::Transient("business_key_rotation_lease_lost"))?;
                return Ok(());
            }
            rescans = rescans.saturating_add(1);
            if rescans >= 3 {
                return Err(RotationJobError::Transient("business_key_rotation_rescan_pending"));
            }
            after_secret_id = None;
            checkpoint["after_secret_id"] = serde_json::Value::Null;
        }
        storage
            .heartbeat_job(
                job.job_id,
                job.generation,
                worker_id,
                WORKER_LEASE_SECONDS,
                Some(&checkpoint),
            )
            .await
            .map_err(|_| RotationJobError::Transient("business_key_rotation_lease_lost"))?;
    }
}

#[derive(Debug, Default)]
#[cfg(not(target_os = "linux"))]
pub struct EvidenceGatedEnrollmentExecutor;

#[async_trait::async_trait]
#[cfg(not(target_os = "linux"))]
impl CredentialEnrollmentJobExecutor for EvidenceGatedEnrollmentExecutor {
    async fn execute(&self, _attempt: CredentialEnrollmentJobAttempt) -> JobAttemptDecision {
        JobAttemptDecision::Retry {
            error_code: "provider_transport_unavailable".to_owned(),
            retry_after_seconds: 300,
            checkpoint: Some(json!({"stage":"provider_transport"})),
        }
    }
}

async fn finish_enrollment_job_attempt(storage: &PgStorage, job: &JobLease, decision: JobAttemptDecision) {
    match decision {
        JobAttemptDecision::Succeeded { outcome_code } => {
            let _ = storage.complete_job(job.job_id, job.generation, &outcome_code).await;
        }
        JobAttemptDecision::Retry {
            error_code,
            retry_after_seconds,
            checkpoint,
        } if job.attempt < job.max_attempts => {
            let _ = storage
                .retry_job(
                    job.job_id,
                    job.generation,
                    i32::try_from(retry_after_seconds.min(86_400)).unwrap_or(86_400),
                    &error_code,
                    checkpoint.as_ref(),
                )
                .await;
        }
        JobAttemptDecision::Retry {
            error_code, checkpoint, ..
        }
        | JobAttemptDecision::DeadLetter { error_code, checkpoint } => {
            let _ = storage
                .dead_letter_job(job.job_id, job.generation, &error_code, checkpoint.as_ref())
                .await;
        }
    }
}

async fn process_content_audit_purge(
    storage: &PgStorage,
    store: &ContentAuditStore,
    job: &JobLease,
) -> Result<(), &'static str> {
    let object_ids = job
        .payload
        .get("object_ids")
        .and_then(serde_json::Value::as_array)
        .ok_or("purge_payload_invalid")?
        .iter()
        .map(|value| value.as_str().and_then(|value| Uuid::parse_str(value).ok()))
        .collect::<Option<Vec<_>>>()
        .ok_or("purge_payload_invalid")?;
    for object_id in object_ids {
        let mut transaction = storage.pool().begin().await.map_err(|_| "purge_database_unavailable")?;
        let current_job: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM ops.durable_job \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2 FOR SHARE",
        )
        .bind(job.job_id)
        .bind(job.generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| "purge_database_unavailable")?;
        if current_job != Some(job.job_id) {
            return Err("purge_job_lease_lost");
        }
        let row = sqlx::query(
            "SELECT object_uri,content_sha256,state_code,legal_hold_count FROM security.content_audit_object \
             WHERE id=$1 FOR UPDATE",
        )
        .bind(object_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| "purge_database_unavailable")?
        .ok_or("purge_object_missing")?;
        let state: String = sqlx::Row::try_get(&row, "state_code").map_err(|_| "purge_projection_invalid")?;
        let legal_hold_count: i32 =
            sqlx::Row::try_get(&row, "legal_hold_count").map_err(|_| "purge_projection_invalid")?;
        if legal_hold_count != 0 {
            return Err("purge_object_held");
        }
        let digest: Vec<u8> = sqlx::Row::try_get(&row, "content_sha256").map_err(|_| "purge_projection_invalid")?;
        let digest: [u8; 32] = digest.try_into().map_err(|_| "purge_projection_invalid")?;
        if state == "deleted" {
            storage
                .append_deletion_ledger_in(
                    &mut transaction,
                    "content_audit_object",
                    &object_id.to_string(),
                    &digest,
                    "object_deleted",
                    &json!({"job_id":job.job_id,"reconciled":true}),
                )
                .await
                .map_err(|_| "deletion_ledger_unavailable")?;
            transaction.commit().await.map_err(|_| "purge_database_unavailable")?;
            continue;
        }
        if !matches!(state.as_str(), "active" | "deletion_pending") {
            return Err("purge_object_state_conflict");
        }
        let uri: String = sqlx::Row::try_get::<Option<String>, _>(&row, "object_uri")
            .map_err(|_| "purge_projection_invalid")?
            .ok_or("purge_projection_invalid")?;
        storage
            .append_deletion_ledger_in(
                &mut transaction,
                "content_audit_object",
                &object_id.to_string(),
                &digest,
                "scheduled",
                &json!({"job_id":job.job_id}),
            )
            .await
            .map_err(|_| "deletion_ledger_unavailable")?;
        if state == "active" {
            let destroyed = sqlx::query(
                "UPDATE security.content_audit_object SET encrypted_dek=NULL,state_code='deletion_pending' \
                 WHERE id=$1 AND legal_hold_count=0 AND state_code='active'",
            )
            .bind(object_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| "purge_database_unavailable")?;
            if destroyed.rows_affected() != 1 {
                return Err("purge_object_state_conflict");
            }
        }
        storage
            .append_deletion_ledger_in(
                &mut transaction,
                "content_audit_object",
                &object_id.to_string(),
                &digest,
                "key_destroyed",
                &json!({"job_id":job.job_id}),
            )
            .await
            .map_err(|_| "deletion_ledger_unavailable")?;
        transaction.commit().await.map_err(|_| "purge_database_unavailable")?;
        let still_current: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ops.durable_job \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2 AND lease_expires_at>=clock_timestamp())",
        )
        .bind(job.job_id)
        .bind(job.generation)
        .fetch_one(&storage.pool())
        .await
        .map_err(|_| "purge_database_unavailable")?;
        if !still_current {
            return Err("purge_job_lease_lost");
        }
        store.remove_uri(&uri).await.map_err(|_| "purge_object_delete_failed")?;
        let mut finalize = storage.pool().begin().await.map_err(|_| "purge_database_unavailable")?;
        let finalized = sqlx::query(
            "UPDATE security.content_audit_object SET object_uri=NULL,state_code='deleted',storage_state_code='destroyed', \
               deleted_at=clock_timestamp() WHERE id=$1 AND state_code='deletion_pending' AND legal_hold_count=0",
        )
        .bind(object_id)
        .execute(&mut *finalize)
        .await
        .map_err(|_| "purge_database_unavailable")?;
        if finalized.rows_affected() == 0 {
            let state: Option<String> =
                sqlx::query_scalar("SELECT state_code FROM security.content_audit_object WHERE id=$1 FOR UPDATE")
                    .bind(object_id)
                    .fetch_optional(&mut *finalize)
                    .await
                    .map_err(|_| "purge_database_unavailable")?;
            if state.as_deref() != Some("deleted") {
                return Err("purge_object_state_conflict");
            }
        }
        storage
            .append_deletion_ledger_in(
                &mut finalize,
                "content_audit_object",
                &object_id.to_string(),
                &digest,
                "object_deleted",
                &json!({"job_id":job.job_id}),
            )
            .await
            .map_err(|_| "deletion_ledger_unavailable")?;
        finalize.commit().await.map_err(|_| "purge_database_unavailable")?;
    }
    Ok(())
}

async fn run_outbox_loop(storage: Arc<PgStorage>, cancellation: CancellationToken) {
    let worker_id = format!("super-gatewayd-outbox:{}", std::process::id());
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return,
            _ = interval.tick() => {
                if let Ok(messages) = storage.claim_outbox(&worker_id, 32, WORKER_LEASE_SECONDS).await {
                    for message in messages { publish_internal_event(&storage, message).await; }
                }
            }
        }
    }
}

async fn publish_internal_event(storage: &PgStorage, message: OutboxLease) {
    let phase = match message.topic.as_str() {
        "alert.critical" => Some("alert"),
        "alert.alert_resolved" => Some("recovery"),
        _ => None,
    };
    if let Some(phase) = phase {
        if storage.publish_alert_event(&message, phase).await.is_err() {
            let _ = storage
                .retry_outbox(
                    message.message_id,
                    message.generation,
                    30,
                    message.attempt >= 20,
                    "alert_notification_fanout_failed",
                )
                .await;
        }
        return;
    }
    // Non-alert management and lifecycle topics are internal durable events.
    // Their externally observable copy is the immutable audit event that was
    // written in the same transaction; no connector delivery is required.
    // Leaving these leased would manufacture dead letters for every successful
    // management mutation (including export creation and consumption).
    let _ = storage.publish_outbox(message.message_id, message.generation).await;
}

async fn upsert_critical_alert(storage: &PgStorage, fingerprint: &str, summary: &str) {
    let alert_id = Uuid::now_v7();
    let event_id = Uuid::now_v7();
    let payload = json!({"severity":"critical","summary":summary});
    if let Err(error) = sqlx::query(
        "WITH current_alert AS ( \
           INSERT INTO ops.alert \
            (id,fingerprint,severity_code,type_code,state_code,summary,detail,first_seen_at,last_seen_at,revision) \
           VALUES ($1,$2,'critical',$2,'open',$3,'{}'::jsonb,clock_timestamp(),clock_timestamp(),1) \
           ON CONFLICT (fingerprint) WHERE state_code IN ('open','acknowledged','silenced') \
           DO UPDATE SET last_seen_at=clock_timestamp(),summary=EXCLUDED.summary,revision=ops.alert.revision+1 \
           RETURNING id,revision \
         ) \
         INSERT INTO ops.outbox_message \
          (id,event_id,topic_code,aggregate_type,aggregate_id,aggregate_revision,payload_schema_version,payload, \
           state_code,lease_generation,attempt_count,available_at,created_at) \
         SELECT $4,$5,'alert.critical','alert',id,revision,1,$6,'pending',0,0,clock_timestamp(),clock_timestamp() \
         FROM current_alert \
         ON CONFLICT (aggregate_type,aggregate_id,aggregate_revision,topic_code) DO NOTHING",
    )
    .bind(alert_id)
    .bind(fingerprint)
    .bind(summary)
    .bind(Uuid::now_v7())
    .bind(event_id)
    .bind(payload)
    .execute(&storage.pool())
    .await
    {
        tracing::error!(event="critical_alert_outbox_persist_failed", error=%error);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use gateway_domain::SecretValue;
    use gateway_services::operations::{BackupOperationKind, BackupOperationRequest, BackupOperationsExecutor};
    use gateway_storage::{PgStorage, RuntimeRolePolicy, embedded_migration_count};
    use uuid::Uuid;

    use super::{
        DEFAULT_JOB_HEARTBEAT, EvidenceGatedBackupExecutor, WORKER_LEASE_SECONDS, json, sanitized_backup_error,
        serverchan3_target, upsert_critical_alert,
    };

    #[test]
    fn serverchan3_send_key_parser_builds_only_the_fixed_provider_target() {
        let target = serverchan3_target("sctp12345tABC_def-9").expect("fixture key is valid");
        assert_eq!(target.host.as_ref(), "12345.push.ft07.com");
        assert_eq!(target.path.expose(), "/send/sctp12345tABC_def-9.send");
        for invalid in [
            "",
            "sctp",
            "sctpttoken",
            "sctp12t",
            "sctpabcTtoken",
            "sctp12tbad/path",
            "sctp12tbad?query",
            "sctp12tbad\r\nheader",
        ] {
            assert!(serverchan3_target(invalid).is_err(), "accepted invalid fixture");
        }
    }

    #[test]
    fn worker_contract_keeps_secrets_out_of_job_payloads() {
        let payload = json!({"enrollment_id":"fixture","material_count":2});
        let rendered = payload.to_string();
        assert!(!rendered.contains("access_token"));
        assert!(!rendered.contains("refresh_token"));
        assert_eq!(WORKER_LEASE_SECONDS, 60);
        assert_eq!(DEFAULT_JOB_HEARTBEAT.as_secs(), 20);
    }

    #[tokio::test]
    async fn disabled_backup_adapter_is_explicit_and_error_codes_are_bounded() {
        let result = EvidenceGatedBackupExecutor
            .execute(BackupOperationRequest {
                operation_id: Uuid::now_v7(),
                kind: BackupOperationKind::BackupCreate,
                backup_run_id: None,
                recovery_point: None,
                manifest: None,
                manifest_sha256_hex: None,
            })
            .await;
        assert!(matches!(
            result,
            Err(gateway_services::operations::BackupOperationFailure::Terminal(code))
                if code == "backup_not_configured"
        ));
        assert_eq!(sanitized_backup_error("safe_code_9", "fallback"), "safe_code_9");
        assert_eq!(sanitized_backup_error("secret=leak", "fallback"), "fallback");
    }

    #[tokio::test]
    async fn critical_alert_upsert_emits_revisioned_outbox() -> Result<(), Box<dyn std::error::Error>> {
        let Ok(database_url) = std::env::var("TEST_R9_OPERATIONS_DATABASE_ADMIN_URL") else {
            return Ok(());
        };
        let database_url = SecretValue::new(database_url);
        let report = PgStorage::migrate(&database_url).await?;
        assert_eq!(report.applied_count, embedded_migration_count());
        let storage = PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?;
        let fingerprint = format!("r9-critical-fixture-{}", Uuid::now_v7());

        upsert_critical_alert(&storage, &fingerprint, "first fixture").await;
        upsert_critical_alert(&storage, &fingerprint, "second fixture").await;

        let (alert_id, revision, severity, state, summary): (Uuid, i64, String, String, String) =
            sqlx::query_as("SELECT id,revision,severity_code,state_code,summary FROM ops.alert WHERE fingerprint=$1")
                .bind(&fingerprint)
                .fetch_one(&storage.pool())
                .await?;
        assert_eq!(revision, 2);
        assert_eq!(severity, "critical");
        assert_eq!(state, "open");
        assert_eq!(summary, "second fixture");

        let rows: Vec<(i64, serde_json::Value, String)> = sqlx::query_as(
            "SELECT aggregate_revision,payload,state_code FROM ops.outbox_message \
             WHERE topic_code='alert.critical' AND aggregate_type='alert' AND aggregate_id=$1 \
             ORDER BY aggregate_revision",
        )
        .bind(alert_id)
        .fetch_all(&storage.pool())
        .await?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, 1);
        assert_eq!(rows[1].0, 2);
        assert_eq!(rows[0].1["summary"], "first fixture");
        assert_eq!(rows[1].1["summary"], "second fixture");
        assert!(
            rows.iter()
                .all(|row| row.1["severity"] == "critical" && row.2 == "pending")
        );
        Ok(())
    }
}
