//! Runtime assembly and graceful lifecycle.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    str::FromStr as _,
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use gateway_api::{
    AccessGrant, AccessResolver, BackgroundCatalog, BackgroundCatalogDocument, BusinessRateLimiter, ContentAuditMode,
    DataPlaneState, EndpointPermission, KeyConcurrencyLimiter, ManagementRuntimeBridge, ManagementState,
    MessageDispatcher, ModelCatalog, ModelRecord, ProbeAction, ProbeRateLimit, ProbeRateLimiter, ProbeState, RateLimit,
    StaticModelCatalog, TrustedProxyConfig, VersionedDigestAccessResolver, data_plane_router, management_router,
};
use gateway_domain::{
    ClientClass, Clock, Digest, GroupId, InternalReadiness, PlatformKeyId, RequestSnapshotSet, SecretBytes,
    SnapshotVersion, SystemClock, UserId,
};
use gateway_policy::{
    CapabilityCatalog, CapabilityRule, CompiledCapabilitySnapshot, CompiledRuleSet, RequestPolicy, RuleDefinition,
    SystemPolicy,
};
use gateway_services::{ReadinessCoordinator, security::hash_bootstrap_password};
use gateway_storage::{BootstrapAdminRecord, PgStorage, RuntimeRolePolicy};
use gateway_transport::{
    ActivationGeneration, BundleLoadContext, BundleTrustStore, CompiledTransportEngine, EngineCatalog,
    EngineCatalogHandle, SignedBundleEnvelope, TransportCore,
};
use serde::Deserialize;
use serde_json::Value;
use sqlx::Row as _;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    admin_backend::PgManagementBackend,
    config::{BusinessKeyProvider, GatewayConfig, read_secret_file},
    production_dispatcher::ProductionDispatcher,
};

/// Assemble and serve both listeners until a process shutdown signal.
#[allow(
    clippy::too_many_lines,
    reason = "startup keeps readiness transitions in dependency order"
)]
pub async fn run(config: GatewayConfig) -> anyhow::Result<()> {
    std::fs::create_dir_all(&config.response_tmp_dir).context("response temporary directory initialization failed")?;

    let readiness = ReadinessCoordinator::new(InternalReadiness {
        static_configuration_ready: config.invariants_hold(),
        ..InternalReadiness::default()
    });
    let database_url = read_secret_file(&config.database_url_file).context("runtime database reference is invalid")?;
    let storage = Arc::new(
        PgStorage::connect(&database_url, RuntimeRolePolicy::Enforce)
            .await
            .context("runtime database startup check failed")?,
    );
    readiness.update(|state| state.database_schema_ready = true);
    let business_key_provider_ready = match &config.business_key_provider {
        BusinessKeyProvider::Database => storage.ensure_database_business_key().await.is_ok(),
        BusinessKeyProvider::LocalFile(_) | BusinessKeyProvider::ExternalUri(_) => {
            anyhow::bail!("selected business key provider is not wired into the runtime composition root")
        }
    };
    readiness.update(|state| state.business_key_provider_ready = business_key_provider_ready);
    let bootstrap_candidate = config
        .bootstrap_admin
        .as_ref()
        .map(|admin| -> anyhow::Result<BootstrapAdminRecord> {
            let password_phc = hash_bootstrap_password(&admin.password).context("bootstrap password hashing failed")?;
            Ok(BootstrapAdminRecord {
                user_id: uuid::Uuid::now_v7(),
                password_credential_id: uuid::Uuid::now_v7(),
                username: admin.username.trim().to_owned(),
                username_normalized: admin.username.trim().to_lowercase(),
                display_name: admin.display_name.clone(),
                email: admin.email.clone(),
                email_normalized: admin.email.as_ref().map(|value| value.trim().to_lowercase()),
                password_phc,
            })
        })
        .transpose()?;
    storage
        .bootstrap_admin(bootstrap_candidate)
        .await
        .context("database bootstrap failed")?;
    readiness.update(|state| state.bootstrap_ready = true);
    let audit_integrity_key =
        read_secret_file(&config.audit_integrity_key_file).context("audit integrity key is unavailable")?;
    let digest_key = read_secret_file(&config.digest_key_file).context("lookup digest key is unavailable")?;
    let audit_integrity_ready = if storage.seal_completed_audit_days(&audit_integrity_key).await.is_ok() {
        storage.verify_audit_integrity(&audit_integrity_key).await.is_ok()
    } else {
        false
    };
    readiness.update(|state| state.audit_integrity_ready = audit_integrity_ready);
    let full_content_audit_required: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM iam.platform_key_active_config active \
         JOIN iam.platform_key_config config ON config.id=active.config_id \
         JOIN iam.platform_key key ON key.id=active.platform_key_id \
         JOIN gateway.group_active_config ga ON ga.group_id=key.group_id \
         JOIN gateway.group_config gc ON gc.id=ga.config_id \
         LEFT JOIN security.approval_case approval ON approval.id=config.content_audit_approval_case_id \
         WHERE key.status_code='active' AND gc.content_audit_policy_code<>'forbid' \
           AND (gc.content_audit_policy_code='require' OR (gc.content_audit_policy_code='allow' \
                AND config.audit_mode_code='full_encrypted' AND config.content_audit_expires_at>clock_timestamp() \
                AND approval.state_code='consumed' AND approval.consumed_at IS NOT NULL)))",
    )
    .fetch_one(&storage.pool())
    .await
    .context("Content Audit activation projection failed")?;
    let content_audit_store = if let Some(content) = &config.content_audit {
        let key = read_secret_file(&content.key_file).context("Content Audit key is unavailable")?;
        let store = gateway_services::content_audit::ContentAuditStore::new(
            content.directory.clone(),
            SecretBytes::new(key.expose().as_bytes().to_vec()),
        )
        .context("Content Audit store configuration failed")?;
        store
            .preflight()
            .await
            .context("Content Audit store preflight failed")?;
        store
            .sweep_staged()
            .await
            .context("Content Audit orphan sweep failed")?;
        let referenced = sqlx::query_scalar::<_, String>(
            "SELECT object_uri FROM security.content_audit_object \
             WHERE object_uri IS NOT NULL AND storage_state_code='finalized'",
        )
        .fetch_all(&storage.pool())
        .await
        .context("Content Audit manifest projection failed")?
        .into_iter()
        .map(String::into_boxed_str)
        .collect::<BTreeSet<_>>();
        store
            .sweep_unreferenced_finalized(&referenced)
            .await
            .context("Content Audit finalized-object reconciliation failed")?;
        readiness.update(|state| state.content_audit_ready = true);
        Some(Arc::new(store))
    } else {
        readiness.update(|state| state.content_audit_ready = !full_content_audit_required);
        None
    };
    let export_store = Arc::new(gateway_services::export::ExportArtifactStore::new(
        config.response_tmp_dir.join("exports"),
    ));
    export_store
        .preflight()
        .await
        .context("Usage Export store preflight failed")?;
    export_store
        .sweep_staged()
        .await
        .context("Usage Export staged-object sweep failed")?;
    let referenced_exports = sqlx::query_scalar::<_, String>(
        "SELECT object_uri FROM ops.export_job WHERE state_code='succeeded' AND object_uri IS NOT NULL",
    )
    .fetch_all(&storage.pool())
    .await
    .context("Usage Export manifest projection failed")?
    .into_iter()
    .map(String::into_boxed_str)
    .collect::<BTreeSet<_>>();
    export_store
        .sweep_unreferenced_finalized(&referenced_exports)
        .await
        .context("Usage Export finalized-object reconciliation failed")?;
    let (transport_catalog, bundle_trust_store) =
        load_transport_catalog(&config.bundle_trust_store, &config.bundle_dir)
            .context("transport Bundle catalog startup failed")?;
    let active_bundle_ids = storage
        .active_transport_bundle_ids()
        .await
        .context("active Credential Bundle snapshot failed")?;
    let catalog_snapshot = transport_catalog.snapshot();
    let required_bundles_ready = active_bundle_ids
        .iter()
        .all(|bundle_id| catalog_snapshot.contains_bundle_id(bundle_id));
    readiness.update(|state| {
        state.active_configuration_ready = true;
        state.required_bundles_ready = required_bundles_ready;
    });
    #[cfg(target_os = "linux")]
    let transport_core: Arc<dyn TransportCore> = {
        use gateway_transport::{ProductionTransportCore, TransportCore as _, TransportCoreState};

        let core = Arc::new(ProductionTransportCore::new(transport_catalog.clone()));
        readiness.update(|state| state.transport_core_ready = core.state() == TransportCoreState::Ready);
        core
    };
    #[cfg(not(target_os = "linux"))]
    let transport_core: Arc<dyn TransportCore> = {
        readiness.update(|state| state.transport_core_ready = false);
        Arc::new(gateway_transport::NoopTransportCore)
    };
    let (access, models) = load_access_snapshot(&storage, SecretBytes::new(digest_key.expose().as_bytes().to_vec()))
        .await
        .context("active access projection failed")?;
    let management_runtime = ManagementRuntimeBridge::new(access, models);
    let cancellation = CancellationToken::new();
    let transport_management_runtime = Arc::new(crate::admin_backend::TransportManagementRuntime::new(
        bundle_trust_store,
        config.bundle_dir.clone(),
        transport_catalog.clone(),
    )?);
    let runtime_reconcile_storage = storage.clone();
    let runtime_reconcile_bridge = management_runtime.clone();
    let runtime_reconcile_key = SecretBytes::new(digest_key.expose().as_bytes().to_vec());
    let runtime_reconcile_cancel = cancellation.child_token();
    let runtime_reconcile_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                () = runtime_reconcile_cancel.cancelled() => return,
                _ = interval.tick() => match load_access_snapshot(
                    &runtime_reconcile_storage,
                    SecretBytes::new(runtime_reconcile_key.expose().to_vec()),
                ).await {
                    Ok((access,models)) => runtime_reconcile_bridge.publish(access,models),
                    Err(error) => tracing::warn!(event="management_runtime_reconcile_failed", error=%error),
                }
            }
        }
    });
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    #[cfg(target_os = "linux")]
    let provider_http = crate::provider_http::PgProviderHttpPort::new(storage.clone());
    #[cfg(target_os = "linux")]
    let credential_maintainer: Option<Arc<dyn gateway_services::credential::CredentialMaintainer>> = {
        use gateway_services::{
            credential::MaintenanceCoordinator,
            credential_postgres::{PgAuthMaintenanceRepository, PgRefreshMaterialPort},
            credential_provider::SubscriptionOAuthRefreshAdapter,
        };

        let repository = PgAuthMaintenanceRepository::new(storage.clone(), Duration::from_millis(100));
        let material = PgRefreshMaterialPort::new(storage.clone());
        let adapter = SubscriptionOAuthRefreshAdapter::new(provider_http.clone(), material);
        let coordinator = MaintenanceCoordinator::new(repository, adapter, Duration::from_secs(30));
        Some(coordinator)
    };
    #[cfg(not(target_os = "linux"))]
    let credential_maintainer: Option<Arc<dyn gateway_services::credential::CredentialMaintainer>> = None;
    #[cfg(target_os = "linux")]
    let enrollment_executor: Arc<dyn gateway_services::operations::CredentialEnrollmentJobExecutor> =
        gateway_services::credential_enrollment_postgres::PgCredentialEnrollmentExecutor::new(
            storage.clone(),
            provider_http.clone(),
        );
    #[cfg(not(target_os = "linux"))]
    let enrollment_executor: Arc<dyn gateway_services::operations::CredentialEnrollmentJobExecutor> =
        Arc::new(crate::operations::EvidenceGatedEnrollmentExecutor);
    #[cfg(target_os = "linux")]
    let plan_collector = Some(gateway_services::plan::PgPlanCollector::new(
        storage.clone(),
        provider_http.clone(),
    ));
    #[cfg(not(target_os = "linux"))]
    let plan_collector: Option<Arc<gateway_services::plan::PgPlanCollector>> = None;
    #[cfg(target_os = "linux")]
    let model_catalog_collector = Some(gateway_services::model_discovery::PgModelCatalogCollector::new(
        storage.clone(),
        provider_http.clone(),
    ));
    #[cfg(not(target_os = "linux"))]
    let model_catalog_collector: Option<Arc<gateway_services::model_discovery::PgModelCatalogCollector>> = None;
    #[cfg(target_os = "linux")]
    let managed_browser_executor = config.managed_browser.as_ref().map(|browser| {
        crate::managed_browser::CommandManagedBrowserExecutor::new(
            storage.clone(),
            provider_http.clone(),
            provider_http.clone(),
            browser.tool.clone(),
            browser.timeout,
        )
    });
    #[cfg(not(target_os = "linux"))]
    let managed_browser_executor: Option<Arc<crate::operations::ManagedBrowserExecutor>> = None;
    let production_dispatcher = Arc::new(
        ProductionDispatcher::load(
            storage.clone(),
            transport_catalog.clone(),
            transport_core,
            config.response_tmp_dir.clone(),
            clock.clone(),
            content_audit_store.clone(),
            credential_maintainer,
        )
        .await
        .context("production data-plane assembly failed")?,
    );
    let reconciled = storage
        .reconcile_stale_request_lifecycles()
        .await
        .context("stale request lifecycle reconciliation failed")?;
    if reconciled > 0 {
        tracing::warn!(event = "stale_request_lifecycles_reconciled", count = reconciled);
    }
    let dispatcher: Arc<dyn MessageDispatcher> = production_dispatcher.clone();
    let data_metrics = gateway_services::observability::DataPlaneObservability::default();
    let data_state = initial_data_state(
        readiness.clone(),
        data_metrics.clone(),
        management_runtime.clone(),
        dispatcher,
        clock,
    );
    let data_listener = TcpListener::bind(config.data_bind)
        .await
        .context("data listener bind failed")?;
    let admin_listener = TcpListener::bind(config.admin_bind)
        .await
        .context("admin listener bind failed")?;
    readiness.begin_serving();
    let integrity_guard = crate::operations::IntegrityGuard::new(audit_integrity_ready);
    let backup_executor: Arc<dyn gateway_services::operations::BackupOperationsExecutor> =
        config.backup.as_ref().map_or_else(
            || Arc::new(crate::operations::EvidenceGatedBackupExecutor) as Arc<_>,
            |backup| {
                Arc::new(crate::operations::CommandBackupOperationsExecutor::new(
                    backup.tool.clone(),
                    backup.key_file.clone(),
                    backup.repository.clone(),
                )) as Arc<_>
            },
        );
    let mut operation_tasks = crate::operations::spawn_operations_runtime(
        storage.clone(),
        gateway_domain::SecretValue::new(audit_integrity_key.expose().to_owned()),
        integrity_guard.clone(),
        content_audit_store.clone(),
        export_store.clone(),
        enrollment_executor,
        plan_collector,
        model_catalog_collector,
        managed_browser_executor,
        backup_executor,
        production_dispatcher.clone(),
        readiness.clone(),
        crate::operations::ProxyProbeTarget {
            observer_host: config.proxy_probe.observer_host.clone(),
            observer_path: config.proxy_probe.observer_path.clone(),
        },
        &cancellation,
    );
    operation_tasks.push(runtime_reconcile_task);
    operation_tasks.push(production_dispatcher.spawn_scheduled_credential_maintenance(&cancellation));
    operation_tasks.push(production_dispatcher.spawn_group_config_reconciliation(&cancellation));
    let data_cancel = cancellation.child_token();
    let admin_cancel = cancellation.child_token();
    let mut data_task = tokio::spawn(async move {
        axum::serve(
            data_listener,
            data_plane_router(data_state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(data_cancel.cancelled_owned())
        .await
    });
    let management_backend = PgManagementBackend::new(
        storage.clone(),
        SecretBytes::new(digest_key.expose().as_bytes().to_vec()),
        readiness.clone(),
        data_metrics,
        integrity_guard,
        export_store,
        content_audit_store,
        management_runtime.clone(),
        Some(production_dispatcher.clone()),
        Some(transport_management_runtime),
        cfg!(target_os = "linux") && config.managed_browser.is_some(),
    )
    .context("management backend startup failed")?;
    let management_state =
        ManagementState::new(Arc::new(management_backend)).context("embedded management contract failed")?;
    let mut admin_task = tokio::spawn(async move {
        axum::serve(admin_listener, management_router(management_state))
            .with_graceful_shutdown(admin_cancel.cancelled_owned())
            .await
    });

    tracing::info!(
        event = "listeners_started",
        data_bind = %config.data_bind,
        admin_bind = %config.admin_bind,
        readiness = ?readiness.public(),
        "gateway listeners started"
    );

    let serve_result: anyhow::Result<()> = async {
        tokio::select! {
            signal_result = shutdown_signal() => {
                signal_result?;
                tracing::info!(event = "drain_started", deadline_seconds = config.drain_deadline.as_secs());
                readiness.begin_drain();
                production_dispatcher.begin_drain().await;
                cancellation.cancel();
                wait_for_servers(data_task, admin_task, config.drain_deadline).await?;
                readiness.begin_shutdown();
                Ok(())
            }
            data_result = &mut data_task => {
                production_dispatcher.begin_drain().await;
                cancellation.cancel();
                flatten_server_result(data_result, "data")?;
                flatten_server_result(admin_task.await, "admin")?;
                Ok(())
            }
            admin_result = &mut admin_task => {
                production_dispatcher.begin_drain().await;
                cancellation.cancel();
                flatten_server_result(admin_result, "admin")?;
                flatten_server_result(data_task.await, "data")?;
                Ok(())
            }
        }
    }
    .await;
    if serve_result.is_err() {
        production_dispatcher.force_cancel_requests();
    }
    production_dispatcher.shutdown_owners().await;
    wait_for_operations(operation_tasks).await;
    serve_result?;
    tracing::info!(event = "process_stopped", "gateway shutdown complete");
    Ok(())
}

async fn wait_for_operations(tasks: Vec<JoinHandle<()>>) {
    for task in tasks {
        if tokio::time::timeout(Duration::from_secs(5), task).await.is_err() {
            tracing::warn!(event = "operations_worker_shutdown_timeout");
        }
    }
}

fn load_transport_catalog(
    trust_store_path: &Path,
    bundle_dir: &Path,
) -> anyhow::Result<(Arc<EngineCatalogHandle>, Arc<BundleTrustStore>)> {
    let trust_bytes = std::fs::read(trust_store_path).context("Bundle TrustStore is unreadable")?;
    let trust_store: BundleTrustStore =
        serde_json::from_slice(&trust_bytes).context("Bundle TrustStore schema is invalid")?;
    let mut paths = std::fs::read_dir(bundle_dir)
        .context("Bundle directory is unreadable")?
        .collect::<Result<Vec<_>, _>>()
        .context("Bundle directory enumeration failed")?;
    paths.sort_by_key(std::fs::DirEntry::file_name);
    let now_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let context = BundleLoadContext {
        engine_abi_version: "1.0".into(),
        engine_build: env!("CARGO_PKG_VERSION").into(),
        target: runtime_target().into(),
        supported_capabilities: BTreeSet::from(["tls_client_hello".into(), "ordered_http1".into()]),
        now_unix_seconds,
        for_new_activation: false,
    };
    let mut engines = Vec::new();
    for entry in paths {
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path).context("Bundle artifact is unreadable")?;
        let verified = SignedBundleEnvelope::verify_json(&bytes, &trust_store, &context)
            .context("Bundle artifact verification failed")?;
        engines.push(CompiledTransportEngine::compile(verified).context("Bundle engine compilation failed")?);
    }
    let catalog = EngineCatalog::build(ActivationGeneration::INITIAL, engines)
        .context("no verified Transport Bundle is loadable")?;
    Ok((Arc::new(EngineCatalogHandle::new(catalog)), Arc::new(trust_store)))
}

pub(crate) fn runtime_target() -> &'static str {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "windows") => "x86_64-pc-windows-msvc",
        ("aarch64", "windows") => "aarch64-pc-windows-msvc",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("aarch64", "macos") => "aarch64-apple-darwin",
        _ => "unsupported-target",
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "startup compiles one immutable access, model and policy snapshot in dependency order"
)]
pub(crate) async fn load_access_snapshot(
    storage: &PgStorage,
    digest_key: SecretBytes,
) -> anyhow::Result<(Arc<dyn AccessResolver>, Arc<dyn ModelCatalog>)> {
    let model_rows = sqlx::query(
        "SELECT m.upstream_model_id,m.display_name,extract(epoch FROM m.first_seen_at)::bigint AS created_at, \
                c.id AS capability_id,c.capability_version,c.schema_payload,c.content_hash \
         FROM catalog.model_definition m \
         LEFT JOIN catalog.model_capability c ON c.model_id=m.id AND c.lifecycle_code='active' \
         WHERE m.lifecycle_code='published' ORDER BY m.upstream_model_id",
    )
    .fetch_all(&storage.pool())
    .await
    .context("published model projection query failed")?;
    let mut models = Vec::with_capacity(model_rows.len());
    let mut capabilities = Vec::with_capacity(model_rows.len());
    let mut capability_identity = Vec::new();
    for row in &model_rows {
        let model_id = row.try_get::<String, _>("upstream_model_id")?;
        let capability_id = row
            .try_get::<Option<uuid::Uuid>, _>("capability_id")?
            .ok_or_else(|| anyhow::anyhow!("published model {model_id} has no active capability"))?;
        let capability_version = row
            .try_get::<Option<i64>, _>("capability_version")?
            .ok_or_else(|| anyhow::anyhow!("published model {model_id} has no active capability version"))?;
        let payload = row
            .try_get::<Option<Value>, _>("schema_payload")?
            .ok_or_else(|| anyhow::anyhow!("published model {model_id} has no active capability payload"))?;
        let envelope: CapabilityArtifactPayload =
            serde_json::from_value(payload).with_context(|| format!("capability payload for {model_id} is invalid"))?;
        capabilities.push(
            CompiledCapabilitySnapshot::compile(capability_id.to_string(), model_id.clone(), envelope.rules)
                .with_context(|| format!("capability for {model_id} did not compile"))?,
        );
        capability_identity.extend_from_slice(model_id.as_bytes());
        capability_identity.extend_from_slice(&capability_version.to_be_bytes());
        capability_identity.extend_from_slice(&row.try_get::<Vec<u8>, _>("content_hash")?);
        models.push(ModelRecord {
            id: model_id.into_boxed_str(),
            display_name: row.try_get::<String, _>("display_name")?.into_boxed_str(),
            created_at: row.try_get::<i64, _>("created_at")?.to_string().into_boxed_str(),
        });
    }
    let model_ids = models.iter().map(|model| model.id.clone()).collect::<Vec<_>>();
    let capability_catalog = CapabilityCatalog::new(capabilities).context("active capability catalog is invalid")?;
    let capability_snapshot =
        SnapshotVersion::new(format!("capability-set:{}", Digest::of(&capability_identity).as_str()));
    let (background_catalog_snapshot, background_catalog) = load_background_catalog(storage).await?;
    let model_catalog: Arc<dyn ModelCatalog> = Arc::new(StaticModelCatalog::new(models));
    if model_ids.is_empty() {
        return Ok((
            Arc::new(VersionedDigestAccessResolver::new(digest_key, Vec::new())),
            model_catalog,
        ));
    }

    let rows = sqlx::query(
        "SELECT k.id,k.owner_user_id,k.group_id,s.lookup_digest,c.config_version,c.messages_enabled,c.models_enabled, \
                c.max_body_bytes,c.messages_rpm,c.messages_burst,c.models_rpm,c.models_burst,c.max_concurrency, \
                c.ruleset_artifact_id AS key_ruleset_artifact_id, \
                gc.config_version AS group_config_version,gc.ruleset_artifact_id AS group_ruleset_artifact_id, \
                gc.enforcement_artifact_id, \
                gc.system_prompt_mode_code,gc.system_prompt_ref,gc.system_prompt_content, \
                gc.content_audit_retention_days, \
                CASE WHEN gc.content_audit_policy_code='allow' \
                     THEN extract(epoch FROM c.content_audit_expires_at)::bigint ELSE NULL END \
                     AS content_audit_expires_at_unix_seconds, \
                CASE WHEN gc.content_audit_policy_code='require' THEN true \
                     WHEN gc.content_audit_policy_code='allow' AND c.audit_mode_code='full_encrypted' \
                          AND c.content_audit_expires_at>clock_timestamp() AND approval.state_code='consumed' \
                          AND approval.consumed_at IS NOT NULL THEN true ELSE false END AS full_content_audit \
         FROM iam.platform_key k JOIN security.encrypted_secret s ON s.id=k.secret_id \
         JOIN iam.platform_key_active_config ka ON ka.platform_key_id=k.id \
         JOIN iam.platform_key_config c ON c.id=ka.config_id \
         JOIN gateway.credential_group g ON g.id=k.group_id \
         JOIN gateway.group_active_config ga ON ga.group_id=g.id \
         JOIN gateway.group_config gc ON gc.id=ga.config_id \
         LEFT JOIN security.approval_case approval ON approval.id=c.content_audit_approval_case_id \
         JOIN iam.user_account u ON u.id=k.owner_user_id \
         WHERE k.status_code='active' AND (k.expires_at IS NULL OR k.expires_at>clock_timestamp()) \
           AND g.status_code='active' AND u.status_code='active' AND s.destroyed_at IS NULL AND s.lookup_digest IS NOT NULL",
    )
    .fetch_all(&storage.pool())
    .await
    .context("active Platform Key projection query failed")?;
    let mut entries = Vec::with_capacity(rows.len());
    let mut rule_artifacts = BTreeMap::new();
    let mut enforcement_artifacts = BTreeMap::new();
    for row in rows {
        let key_id: uuid::Uuid = row.try_get("id")?;
        let group_id: uuid::Uuid = row.try_get("group_id")?;
        let lookup: Vec<u8> = row.try_get("lookup_digest")?;
        let lookup: [u8; 32] = lookup
            .try_into()
            .map_err(|_| anyhow::anyhow!("Platform Key digest length is invalid"))?;
        let key_models = published_scope(
            storage,
            "iam.platform_key_model_allowlist",
            "platform_key_config_id",
            key_id,
        )
        .await?;
        let group_models =
            published_scope(storage, "gateway.group_model_allowlist", "group_config_id", group_id).await?;
        let client_rows = sqlx::query(
            "SELECT a.client_class_code FROM gateway.group_accepted_client_class a \
             JOIN gateway.group_active_config p ON p.config_id=a.group_config_id WHERE p.group_id=$1",
        )
        .bind(group_id)
        .fetch_all(&storage.pool())
        .await?;
        let accepted_client_classes = client_rows
            .iter()
            .filter_map(
                |client| match client.try_get::<String, _>("client_class_code").ok()?.as_str() {
                    "claude_code_cli" => Some(ClientClass::ClaudeCodeCli),
                    "non_claude_code_cli" => Some(ClientClass::NonClaudeCodeCli),
                    _ => None,
                },
            )
            .collect::<BTreeSet<_>>();
        if accepted_client_classes.is_empty() {
            continue;
        }
        let ip_rows = sqlx::query(
            "SELECT i.network::text AS network FROM iam.platform_key_ip_allowlist i \
             JOIN iam.platform_key_active_config p ON p.config_id=i.platform_key_config_id WHERE p.platform_key_id=$1",
        )
        .bind(key_id)
        .fetch_all(&storage.pool())
        .await?;
        let ip_allowlist = ip_rows
            .iter()
            .map(|ip| ip.try_get::<String, _>("network").map_err(anyhow::Error::from))
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .map(|network| ipnet::IpNet::from_str(&network).map_err(anyhow::Error::from))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let config_version: i64 = row.try_get("config_version")?;
        let group_config_version: i64 = row.try_get("group_config_version")?;
        let group_rules = load_rule_artifact(
            storage,
            &mut rule_artifacts,
            row.try_get("group_ruleset_artifact_id")?,
            "group",
            group_id,
        )
        .await?;
        let key_rules = load_rule_artifact(
            storage,
            &mut rule_artifacts,
            row.try_get("key_ruleset_artifact_id")?,
            "platform_key",
            key_id,
        )
        .await?;
        let effective_ruleset = compile_effective_ruleset(group_id, key_id, group_rules.as_ref(), key_rules.as_ref())?;
        let ruleset_snapshot = ruleset_snapshot(group_rules.as_ref(), key_rules.as_ref());
        let enforcement = load_enforcement_artifact(
            storage,
            &mut enforcement_artifacts,
            row.try_get("enforcement_artifact_id")?,
            group_id,
        )
        .await?;
        let enforcement_snapshot = enforcement.as_ref().map_or_else(
            || SnapshotVersion::new(format!("group:{group_id}:enforcement:{group_config_version}")),
            |artifact| {
                SnapshotVersion::new(format!(
                    "enforcement:{}:{}",
                    artifact.version,
                    Digest::of(&artifact.content_hash).as_str()
                ))
            },
        );
        let snapshots = Arc::new(RequestSnapshotSet {
            access_policy: SnapshotVersion::new(format!("key:{key_id}:config:{config_version}")),
            group_config: SnapshotVersion::new(format!("group:{group_id}:config:{group_config_version}")),
            enforcement: enforcement_snapshot,
            ruleset: ruleset_snapshot,
            capability: capability_snapshot.clone(),
            background_catalog: background_catalog_snapshot.clone(),
            client_profile_catalog: SnapshotVersion::new("client-profile-v1"),
            price: SnapshotVersion::new("price-catalog-current"),
            serializer: SnapshotVersion::new("json-preserve-v1"),
        });
        let mut policy = RequestPolicy::base_for_models(model_ids.clone(), snapshots)?;
        policy.capabilities = capability_catalog.clone();
        policy.ruleset = effective_ruleset;
        policy.enforcement.system =
            enforcement.map_or_else(|| load_system_policy(&row), |artifact| Ok(artifact.system))?;
        let mut permissions = BTreeSet::new();
        if row.try_get::<bool, _>("messages_enabled")? {
            permissions.insert(EndpointPermission::Messages);
        }
        if row.try_get::<bool, _>("models_enabled")? {
            permissions.insert(EndpointPermission::Models);
        }
        let grant = AccessGrant {
            owner_user_id: UserId::new(row.try_get::<uuid::Uuid, _>("owner_user_id")?.to_string())?,
            platform_key_id: PlatformKeyId::new(key_id.to_string())?,
            group_id: GroupId::new(group_id.to_string())?,
            permissions,
            key_model_scope: key_models,
            group_model_scope: group_models,
            body_limit_bytes: usize::try_from(row.try_get::<i64, _>("max_body_bytes")?)?,
            messages_rate: RateLimit {
                requests_per_minute: u32::try_from(row.try_get::<i32, _>("messages_rpm")?)?,
                burst: u32::try_from(row.try_get::<i32, _>("messages_burst")?)?,
            },
            models_rate: RateLimit {
                requests_per_minute: u32::try_from(row.try_get::<i32, _>("models_rpm")?)?,
                burst: u32::try_from(row.try_get::<i32, _>("models_burst")?)?,
            },
            concurrency_limit: u32::try_from(row.try_get::<i32, _>("max_concurrency")?)?,
            ip_allowlist,
            accepted_client_classes,
            background_catalog: background_catalog.clone(),
            probe_action: ProbeAction::Observe,
            allow_explicit_probe_marker: false,
            content_audit: effective_content_audit(&row)?,
            content_audit_expires_at_unix_seconds: row
                .try_get::<Option<i64>, _>("content_audit_expires_at_unix_seconds")?
                .map(u64::try_from)
                .transpose()?,
            policy: Arc::new(policy),
        };
        entries.push((lookup, Arc::new(grant)));
    }
    Ok((
        Arc::new(VersionedDigestAccessResolver::new(digest_key, entries)),
        model_catalog,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityArtifactPayload {
    rules: Vec<CapabilityRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleArtifactPayload {
    #[allow(dead_code)]
    name: Option<String>,
    rules: Vec<RuleDefinition>,
    #[serde(default)]
    #[allow(dead_code)]
    source_refs: Vec<String>,
}

#[derive(Clone)]
struct LoadedRuleArtifact {
    scope_type: Box<str>,
    scope_id: uuid::Uuid,
    version: i64,
    content_hash: Vec<u8>,
    rules: Vec<RuleDefinition>,
}

async fn load_rule_artifact(
    storage: &PgStorage,
    cache: &mut BTreeMap<uuid::Uuid, LoadedRuleArtifact>,
    artifact_id: Option<uuid::Uuid>,
    expected_scope_type: &str,
    expected_scope_id: uuid::Uuid,
) -> anyhow::Result<Option<LoadedRuleArtifact>> {
    let Some(artifact_id) = artifact_id else {
        return Ok(None);
    };
    if let Some(artifact) = cache.get(&artifact_id) {
        validate_rule_artifact_scope(artifact, expected_scope_type, expected_scope_id)?;
        return Ok(Some(artifact.clone()));
    }
    let row = sqlx::query(
        "SELECT artifact_kind_code,scope_type_code,scope_id,artifact_version,lifecycle_code,payload,content_hash,schema_version \
         FROM catalog.versioned_artifact WHERE id=$1",
    )
    .bind(artifact_id)
    .fetch_optional(&storage.pool())
    .await?
    .ok_or_else(|| anyhow::anyhow!("RuleSet artifact {artifact_id} is missing"))?;
    if row.try_get::<String, _>("artifact_kind_code")? != "ruleset"
        || row.try_get::<String, _>("lifecycle_code")? != "active"
        || row.try_get::<i64, _>("schema_version")? != 1
    {
        anyhow::bail!("RuleSet artifact {artifact_id} is not an active schema-v1 ruleset");
    }
    let payload = row
        .try_get::<Option<Value>, _>("payload")?
        .ok_or_else(|| anyhow::anyhow!("RuleSet artifact {artifact_id} must be inline"))?;
    let envelope: RuleArtifactPayload =
        serde_json::from_value(payload).with_context(|| format!("RuleSet artifact {artifact_id} is invalid"))?;
    let artifact = LoadedRuleArtifact {
        scope_type: row
            .try_get::<Option<String>, _>("scope_type_code")?
            .ok_or_else(|| anyhow::anyhow!("RuleSet artifact {artifact_id} has no scope type"))?
            .into_boxed_str(),
        scope_id: row
            .try_get::<Option<uuid::Uuid>, _>("scope_id")?
            .ok_or_else(|| anyhow::anyhow!("RuleSet artifact {artifact_id} has no scope id"))?,
        version: row.try_get("artifact_version")?,
        content_hash: row.try_get("content_hash")?,
        rules: envelope.rules,
    };
    validate_rule_artifact_scope(&artifact, expected_scope_type, expected_scope_id)?;
    cache.insert(artifact_id, artifact.clone());
    Ok(Some(artifact))
}

fn validate_rule_artifact_scope(
    artifact: &LoadedRuleArtifact,
    expected_scope_type: &str,
    expected_scope_id: uuid::Uuid,
) -> anyhow::Result<()> {
    if artifact.scope_type.as_ref() != expected_scope_type || artifact.scope_id != expected_scope_id {
        anyhow::bail!("RuleSet artifact scope does not match its active config");
    }
    Ok(())
}

fn compile_effective_ruleset(
    group_id: uuid::Uuid,
    key_id: uuid::Uuid,
    group: Option<&LoadedRuleArtifact>,
    key: Option<&LoadedRuleArtifact>,
) -> anyhow::Result<Option<CompiledRuleSet>> {
    if group.is_none() && key.is_none() {
        return Ok(None);
    }
    let layers = vec![
        group.map_or_else(Vec::new, |artifact| artifact.rules.clone()),
        key.map_or_else(Vec::new, |artifact| artifact.rules.clone()),
    ];
    Ok(Some(
        CompiledRuleSet::compile_layers(format!("group:{group_id}:key:{key_id}"), layers)
            .context("effective RuleSet did not compile")?,
    ))
}

fn ruleset_snapshot(group: Option<&LoadedRuleArtifact>, key: Option<&LoadedRuleArtifact>) -> Option<SnapshotVersion> {
    if group.is_none() && key.is_none() {
        return None;
    }
    let mut identity = Vec::new();
    for artifact in [group, key].into_iter().flatten() {
        identity.extend_from_slice(artifact.scope_type.as_bytes());
        identity.extend_from_slice(artifact.scope_id.as_bytes());
        identity.extend_from_slice(&artifact.version.to_be_bytes());
        identity.extend_from_slice(&artifact.content_hash);
    }
    Some(SnapshotVersion::new(format!(
        "ruleset-set:{}",
        Digest::of(&identity).as_str()
    )))
}

fn load_system_policy(row: &sqlx::postgres::PgRow) -> anyhow::Result<SystemPolicy> {
    let mode = row.try_get::<String, _>("system_prompt_mode_code")?;
    match mode.as_str() {
        "preserve" => Ok(SystemPolicy::Preserve),
        "strip_client" => Ok(SystemPolicy::StripClient),
        "strip_all" => Ok(SystemPolicy::StripAll),
        "replace" => {
            let platform_system_ref = row
                .try_get::<Option<String>, _>("system_prompt_ref")?
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("replace System policy has no stable reference"))?;
            let content = row
                .try_get::<Option<Value>, _>("system_prompt_content")?
                .ok_or_else(|| anyhow::anyhow!("replace System policy has no content"))?;
            if !content.is_string() && !content.is_array() {
                anyhow::bail!("replace System content must be a string or block array");
            }
            Ok(SystemPolicy::Replace {
                platform_system_ref: platform_system_ref.into_boxed_str(),
                content,
            })
        }
        _ => anyhow::bail!("unsupported System policy mode"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTypedArtifactEnvelope {
    #[allow(dead_code)]
    name: String,
    payload: Value,
    #[serde(default)]
    #[allow(dead_code)]
    source_refs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeEnforcementPayload {
    group_id: String,
    system: SystemPolicy,
}

#[derive(Clone)]
struct LoadedEnforcementArtifact {
    group_id: uuid::Uuid,
    version: i64,
    content_hash: Vec<u8>,
    system: SystemPolicy,
}

async fn load_enforcement_artifact(
    storage: &PgStorage,
    cache: &mut BTreeMap<uuid::Uuid, LoadedEnforcementArtifact>,
    artifact_id: Option<uuid::Uuid>,
    expected_group_id: uuid::Uuid,
) -> anyhow::Result<Option<LoadedEnforcementArtifact>> {
    let Some(artifact_id) = artifact_id else {
        return Ok(None);
    };
    if let Some(artifact) = cache.get(&artifact_id) {
        if artifact.group_id != expected_group_id {
            anyhow::bail!("Enforcement artifact cache scope does not match its Group config");
        }
        return Ok(Some(artifact.clone()));
    }
    let row = sqlx::query(
        "SELECT artifact_kind_code,scope_type_code,scope_id,artifact_version,lifecycle_code,payload,content_hash,schema_version \
         FROM catalog.versioned_artifact WHERE id=$1",
    )
    .bind(artifact_id)
    .fetch_optional(&storage.pool())
    .await?
    .ok_or_else(|| anyhow::anyhow!("Enforcement artifact {artifact_id} is missing"))?;
    if row.try_get::<String, _>("artifact_kind_code")? != "enforcement"
        || row.try_get::<String, _>("lifecycle_code")? != "active"
        || row.try_get::<i64, _>("schema_version")? != 1
        || row.try_get::<Option<String>, _>("scope_type_code")?.as_deref() != Some("group")
        || row.try_get::<Option<uuid::Uuid>, _>("scope_id")? != Some(expected_group_id)
    {
        anyhow::bail!("Enforcement artifact {artifact_id} does not match its active Group config");
    }
    let envelope: StoredTypedArtifactEnvelope = serde_json::from_value(
        row.try_get::<Option<Value>, _>("payload")?
            .ok_or_else(|| anyhow::anyhow!("Enforcement artifact {artifact_id} must be inline"))?,
    )
    .with_context(|| format!("Enforcement artifact {artifact_id} envelope is invalid"))?;
    let payload: RuntimeEnforcementPayload = serde_json::from_value(envelope.payload)
        .with_context(|| format!("Enforcement artifact {artifact_id} payload is invalid"))?;
    if uuid::Uuid::parse_str(&payload.group_id)? != expected_group_id {
        anyhow::bail!("Enforcement artifact payload Group does not match its scope");
    }
    let artifact = LoadedEnforcementArtifact {
        group_id: expected_group_id,
        version: row.try_get("artifact_version")?,
        content_hash: row.try_get("content_hash")?,
        system: payload.system,
    };
    cache.insert(artifact_id, artifact.clone());
    Ok(Some(artifact))
}

async fn load_background_catalog(storage: &PgStorage) -> anyhow::Result<(SnapshotVersion, Arc<BackgroundCatalog>)> {
    let row = sqlx::query(
        "SELECT a.artifact_version,a.content_hash,a.schema_version,a.lifecycle_code,a.payload \
         FROM catalog.active_artifact_pointer p JOIN catalog.versioned_artifact a ON a.id=p.artifact_id \
         WHERE p.artifact_kind_code='background_catalog' AND p.scope_type_code IS NULL AND p.scope_id IS NULL",
    )
    .fetch_optional(&storage.pool())
    .await?;
    let Some(row) = row else {
        return Ok((
            SnapshotVersion::new("background-catalog-disabled"),
            Arc::new(BackgroundCatalog::default()),
        ));
    };
    if row.try_get::<String, _>("lifecycle_code")? != "active" || row.try_get::<i64, _>("schema_version")? != 1 {
        anyhow::bail!("active Background Catalog artifact is invalid");
    }
    let envelope: StoredTypedArtifactEnvelope = serde_json::from_value(
        row.try_get::<Option<Value>, _>("payload")?
            .ok_or_else(|| anyhow::anyhow!("active Background Catalog must be inline"))?,
    )
    .context("active Background Catalog envelope is invalid")?;
    let document: BackgroundCatalogDocument =
        serde_json::from_value(envelope.payload).context("active Background Catalog payload is invalid")?;
    let catalog = BackgroundCatalog::compile(document).context("active Background Catalog did not compile")?;
    let version: i64 = row.try_get("artifact_version")?;
    let hash: Vec<u8> = row.try_get("content_hash")?;
    Ok((
        SnapshotVersion::new(format!("background-catalog:{version}:{}", Digest::of(&hash).as_str())),
        Arc::new(catalog),
    ))
}

fn effective_content_audit(row: &sqlx::postgres::PgRow) -> anyhow::Result<ContentAuditMode> {
    if !row.try_get::<bool, _>("full_content_audit")? {
        return Ok(ContentAuditMode::MetadataOnly);
    }
    let retention_days = u16::try_from(row.try_get::<i32, _>("content_audit_retention_days")?)?;
    Ok(ContentAuditMode::FullEncrypted { retention_days })
}

async fn published_scope(
    storage: &PgStorage,
    table: &'static str,
    parent_column: &'static str,
    parent_id: uuid::Uuid,
) -> anyhow::Result<BTreeSet<Box<str>>> {
    let query = format!(
        "SELECT m.upstream_model_id FROM {table} a JOIN catalog.model_definition m ON m.id=a.model_id \
         WHERE a.{parent_column}=(SELECT config_id FROM {} WHERE {}=$1) AND m.lifecycle_code='published'",
        if table.starts_with("iam.") {
            "iam.platform_key_active_config"
        } else {
            "gateway.group_active_config"
        },
        if table.starts_with("iam.") {
            "platform_key_id"
        } else {
            "group_id"
        }
    );
    let rows = sqlx::query(&query).bind(parent_id).fetch_all(&storage.pool()).await?;
    rows.iter()
        .map(|row| {
            row.try_get::<String, _>("upstream_model_id")
                .map(String::into_boxed_str)
                .map_err(anyhow::Error::from)
        })
        .collect()
}

fn initial_data_state(
    readiness: ReadinessCoordinator,
    observability: gateway_services::observability::DataPlaneObservability,
    runtime: ManagementRuntimeBridge,
    dispatcher: Arc<dyn MessageDispatcher>,
    clock: Arc<dyn Clock>,
) -> DataPlaneState {
    let limiter = Arc::new(ProbeRateLimiter::new(ProbeRateLimit::default(), clock.clone()));
    DataPlaneState {
        probe: ProbeState::new(readiness, limiter),
        runtime,
        dispatcher,
        observability,
        business_rates: BusinessRateLimiter::new(clock),
        concurrency: KeyConcurrencyLimiter::default(),
        trusted_proxies: TrustedProxyConfig::default(),
        platform_body_limit_bytes: 64 * 1024 * 1024,
    }
}

async fn wait_for_servers(
    data_task: JoinHandle<std::io::Result<()>>,
    admin_task: JoinHandle<std::io::Result<()>>,
    deadline: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(deadline, async {
        flatten_server_result(data_task.await, "data")?;
        flatten_server_result(admin_task.await, "admin")?;
        anyhow::Ok(())
    })
    .await
    .context("drain deadline elapsed")??;
    Ok(())
}

fn flatten_server_result(
    result: Result<std::io::Result<()>, tokio::task::JoinError>,
    listener: &'static str,
) -> anyhow::Result<()> {
    result
        .with_context(|| format!("{listener} listener task failed"))?
        .with_context(|| format!("{listener} listener failed"))
}

async fn shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("SIGTERM handler installation failed")?;
        tokio::select! {
            ctrl_c_result = tokio::signal::ctrl_c() => ctrl_c_result.context("Ctrl-C handler failed")?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.context("Ctrl-C handler failed")?;
    Ok(())
}
