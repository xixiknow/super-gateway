#![forbid(unsafe_code)]
//! Real `PostgreSQL` R5 Credential lifecycle and concurrency contract.

use std::sync::Arc;

use gateway_domain::{AuthKind, CredentialPurpose, EnrollmentAuthMethod, EnrollmentMode, ManagementClass, SecretValue};
use gateway_storage::{
    AuthCandidateRecord, AuthCasPrecondition, BootstrapAdminRecord, BootstrapOutcome, BrowserCasPrecondition,
    BrowserMaterialCandidate, CredentialEnrollmentCreate, CredentialGroupMigrationBegin, CredentialLifecycleCommand,
    CredentialProfileProvision, DeviceIdentityRebuild, EgressAllocation, EgressAllocationRequest,
    MaintenanceOperationCreate, ManagedBrowserStrategyCreate, PgStorage, PlanMappingActivation,
    PlanMappingArtifactCreate, PlanObservationCommit, ProfileCohortUpgrade, RuntimeRolePolicy, StorageError,
    embedded_migration_count,
};
use serde_json::json;
use tokio::sync::Barrier;
use uuid::Uuid;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn credential_r5_lifecycle_cas_dedupe_and_plan_contract() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let Ok(database_url) = std::env::var("TEST_DATABASE_ADMIN_URL") else {
        return Ok(());
    };
    let database_url = SecretValue::new(database_url);
    let report = PgStorage::migrate(&database_url).await?;
    assert_eq!(report.applied_count, embedded_migration_count());
    let storage = Arc::new(PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?);
    storage.ensure_database_business_key().await?;
    let admin_id = Uuid::now_v7();
    assert_eq!(
        storage
            .bootstrap_admin(Some(BootstrapAdminRecord {
                user_id: admin_id,
                password_credential_id: Uuid::now_v7(),
                username: format!("r5-admin-{admin_id}"),
                username_normalized: format!("r5-admin-{admin_id}"),
                display_name: Some("R5 Administrator".to_owned()),
                email: None,
                email_normalized: None,
                password_phc: SecretValue::new(
                    "$argon2id$v=19$m=65536,t=3,p=1$cjUtZml4dHVyZS1zYWx0$fixture".to_owned(),
                ),
            }))
            .await?,
        BootstrapOutcome::Created
    );

    let group_id = fixture_group(&storage, "r5-direct", "direct").await?;
    let archetype_id = fixture_archetype(&storage).await?;
    let enrollment_id = Uuid::now_v7();
    let credential_id = Uuid::now_v7();
    storage
        .create_credential_enrollment(&CredentialEnrollmentCreate {
            enrollment_id,
            credential_id,
            group_id,
            created_by: None,
            mode: EnrollmentMode::Create,
            auth_method: EnrollmentAuthMethod::OauthPkce,
            auth_kind: AuthKind::OauthSubscription,
            purpose: CredentialPurpose::Business,
            management_class: ManagementClass::NonManaged,
            recovery_credential_id: None,
            expected_credential_revision: None,
            expires_in_seconds: 1_800,
            callback_window_seconds: 600,
        })
        .await?;
    let scheduling: (i64, i64, i32, i32, i32, i32) = sqlx::query_as(
        "SELECT sc.config_version,active.revision,sc.max_concurrency,sc.rpm_limit,sc.rpm_burst,sc.priority_layer \
         FROM gateway.credential_active_scheduling_config active \
         JOIN gateway.credential_scheduling_config sc ON sc.id=active.config_id \
         WHERE active.credential_id=$1",
    )
    .bind(credential_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(scheduling, (1, 1, 5, 60, 10, 100));
    let binding_id = Uuid::now_v7();
    let allocation = storage
        .allocate_enrollment_egress(&EgressAllocationRequest {
            enrollment_id,
            credential_id,
            binding_id,
            expected_enrollment_revision: 1,
            expected_credential_revision: 1,
        })
        .await?;
    assert_eq!(
        allocation,
        EgressAllocation::Direct {
            binding_id,
            egress_epoch: 1
        }
    );
    let owner = credential_id.to_string();
    let enrollment_owner = enrollment_id.to_string();
    let verifier_secret = fixture_secret(
        &storage,
        "pkce_verifier",
        "credential_enrollment",
        &enrollment_owner,
        "credential_enrollment",
    )
    .await?;
    let callback_material = fixture_secret(
        &storage,
        "oauth_callback_material",
        "credential_enrollment",
        &enrollment_owner,
        "oauth_callback",
    )
    .await?;
    let state_digest = vec![0x11_u8; 32];
    let nonce_digest = vec![0x22_u8; 32];
    assert_eq!(
        storage
            .configure_enrollment_oauth_pkce(
                enrollment_id,
                2,
                "https://fixture.example/authorize",
                "https://gateway.example/callback",
                &state_digest,
                &nonce_digest,
                verifier_secret,
            )
            .await?,
        3
    );
    let stale_callback_material = fixture_secret(
        &storage,
        "oauth_callback_material",
        "credential_enrollment",
        &enrollment_owner,
        "oauth_callback",
    )
    .await?;
    assert!(matches!(
        storage
            .claim_oauth_callback(enrollment_id, 2, &state_digest, &nonce_digest, stale_callback_material,)
            .await,
        Err(StorageError::RevisionConflict)
    ));
    let enrollment_after_stale: (String, i64) =
        sqlx::query_as("SELECT state_code,revision FROM gateway.credential_enrollment WHERE id=$1")
            .bind(enrollment_id)
            .fetch_one(&storage.pool())
            .await?;
    assert_eq!(enrollment_after_stale, ("awaiting_user_action".to_owned(), 3));
    let foreign_callback_material = fixture_secret(
        &storage,
        "oauth_callback_material",
        "credential",
        &owner,
        "oauth_callback",
    )
    .await?;
    assert!(matches!(
        storage
            .claim_oauth_callback(
                enrollment_id,
                3,
                &state_digest,
                &nonce_digest,
                foreign_callback_material,
            )
            .await,
        Err(StorageError::InvalidLifecycle)
    ));
    let foreign_secret_destroyed: Option<String> =
        sqlx::query_scalar("SELECT destroyed_at::text FROM security.encrypted_secret WHERE id=$1")
            .bind(foreign_callback_material)
            .fetch_one(&storage.pool())
            .await?;
    assert!(foreign_secret_destroyed.is_none());
    assert_eq!(
        storage
            .claim_oauth_callback(enrollment_id, 3, &state_digest, &nonce_digest, callback_material,)
            .await?,
        4
    );
    assert!(matches!(
        storage
            .claim_oauth_callback(enrollment_id, 4, &state_digest, &nonce_digest, callback_material,)
            .await,
        Err(StorageError::InvalidLifecycle)
    ));
    assert_eq!(
        storage
            .advance_credential_enrollment(enrollment_id, 4, "exchanging_material", "verifying_account", "retry",)
            .await?,
        5
    );
    let account_uuid = Uuid::now_v7();
    storage
        .claim_verified_account(enrollment_id, credential_id, account_uuid, 5, 2)
        .await?;

    let installation_secret = fixture_secret(&storage, "device_identity", "credential", &owner, "installation").await?;
    let client_secret = fixture_secret(&storage, "device_identity", "credential", &owner, "client").await?;
    let profile_seed = fixture_secret(&storage, "device_identity", "credential", &owner, "profile_seed").await?;
    let session_hmac = fixture_secret(&storage, "session_hmac", "credential", &owner, "session_hmac").await?;
    storage
        .provision_credential_profile(&CredentialProfileProvision {
            enrollment_id,
            credential_id,
            profile_id: Uuid::now_v7(),
            device_identity_id: Uuid::now_v7(),
            archetype_version_id: archetype_id,
            installation_secret_id: installation_secret,
            client_secret_id: client_secret,
            profile_seed_secret_id: profile_seed,
            session_hmac_secret_id: session_hmac,
            installation_digest: Uuid::now_v7().as_bytes().to_vec(),
            client_digest: Uuid::now_v7().as_bytes().to_vec(),
            capture_cohort: "windows-r5".to_owned(),
            allocation_evidence: json!({"allocator": "r5-fixture", "weight": 1}),
            expected_enrollment_revision: 6,
            expected_credential_revision: 3,
            durable_job_fence: None,
        })
        .await?;

    let operation_id = Uuid::now_v7();
    let operation = storage
        .create_or_join_maintenance_operation(&MaintenanceOperationCreate {
            operation_id,
            credential_id,
            kind: "verify".to_owned(),
            trigger: "enrollment".to_owned(),
            conflict_class: "auth_material_write".to_owned(),
            expected_revision: 4,
            expected_token_version: 1,
            egress_binding_id: binding_id,
            egress_epoch: 1,
            adapter_code: Some("oauth_pkce".to_owned()),
            adapter_version: Some("fixture-v1".to_owned()),
            provider_profile_id: None,
        })
        .await?;
    assert!(!operation.joined_existing);
    let access_secret = fixture_secret(&storage, "oauth_access_token", "credential", &owner, "access-v2").await?;
    let refresh_secret = fixture_secret(&storage, "oauth_refresh_token", "credential", &owner, "refresh-v2").await?;
    let commit = storage
        .commit_auth_candidate(
            &AuthCandidateRecord {
                auth_version_id: Uuid::now_v7(),
                credential_id,
                auth_kind: AuthKind::OauthSubscription,
                access_secret_id: Some(access_secret),
                refresh_secret_id: Some(refresh_secret),
                console_secret_id: None,
                verified_account_uuid: Some(account_uuid),
                expires_at_epoch_seconds: Some(2_000_000_000),
                adapter_code: Some("oauth_pkce".to_owned()),
                adapter_version: Some("fixture-v1".to_owned()),
            },
            &AuthCasPrecondition {
                expected_credential_revision: 4,
                expected_token_version: 1,
                expected_account_uuid: Some(account_uuid),
                expected_egress_binding_id: binding_id,
                expected_egress_epoch: 1,
                operation_id,
                operation_generation: 1,
                durable_job_fence: None,
            },
        )
        .await?;
    assert_eq!(commit.token_version, 2);
    assert_eq!(storage.activate_credential(enrollment_id, credential_id, 5).await?, 6);
    let temporary_destroyed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security.encrypted_secret WHERE id=ANY($1) AND destroyed_at IS NOT NULL",
    )
    .bind(vec![verifier_secret, callback_material])
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(temporary_destroyed, 2);
    let snapshot = storage.load_credential_r5_snapshot(credential_id).await?;
    assert_eq!(snapshot.lifecycle, "active");
    assert_eq!(snapshot.account_uuid, Some(account_uuid));
    assert_eq!(snapshot.profile_epoch, Some(1));
    assert_eq!(snapshot.device_epoch, Some(1));
    assert_eq!(snapshot.egress_epoch, Some(1));

    let target_archetype_id = fixture_archetype_upgrade(&storage, archetype_id).await?;
    let cohort_commit = storage
        .upgrade_profile_cohort(&ProfileCohortUpgrade {
            change_id: Uuid::now_v7(),
            credential_id,
            target_archetype_version_id: target_archetype_id,
            target_capture_cohort: "windows-r5-next".to_owned(),
            reason_code: "approved_cohort_upgrade".to_owned(),
            approved_by: admin_id,
            expected_credential_revision: 6,
            expected_profile_epoch: 1,
            allow_explicit_rollback: false,
        })
        .await?;
    assert_eq!(
        (
            cohort_commit.credential_revision,
            cohort_commit.profile_epoch,
            cohort_commit.device_epoch,
            cohort_commit.egress_epoch,
        ),
        (7, 2, 1, 1)
    );
    let rebuilt_installation =
        fixture_secret(&storage, "device_identity", "credential", &owner, "installation-r2").await?;
    let rebuilt_client = fixture_secret(&storage, "device_identity", "credential", &owner, "client-r2").await?;
    let rebuilt_seed = fixture_secret(&storage, "device_identity", "credential", &owner, "profile-seed-r2").await?;
    let rebuilt_session = fixture_secret(&storage, "session_hmac", "credential", &owner, "session-r2").await?;
    let rebuild_commit = storage
        .rebuild_device_identity(&DeviceIdentityRebuild {
            change_id: Uuid::now_v7(),
            credential_id,
            installation_secret_id: rebuilt_installation,
            client_secret_id: rebuilt_client,
            profile_seed_secret_id: rebuilt_seed,
            session_hmac_secret_id: rebuilt_session,
            installation_digest: Uuid::now_v7().as_bytes().to_vec(),
            client_digest: Uuid::now_v7().as_bytes().to_vec(),
            requested_by: Uuid::now_v7(),
            approved_by: admin_id,
            reason_code: "approved_device_rebuild".to_owned(),
            expected_credential_revision: 7,
            expected_profile_epoch: 2,
            expected_device_epoch: 1,
        })
        .await?;
    assert_eq!(
        (
            rebuild_commit.credential_revision,
            rebuild_commit.profile_epoch,
            rebuild_commit.device_epoch,
            rebuild_commit.egress_epoch,
        ),
        (8, 3, 2, 1)
    );
    let destroyed_original_device_secrets: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security.encrypted_secret WHERE id=ANY($1) AND destroyed_at IS NOT NULL \
         AND octet_length(ciphertext)=0 AND octet_length(wrapped_dek)=0",
    )
    .bind(vec![installation_secret, client_secret, profile_seed, session_hmac])
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(destroyed_original_device_secrets, 4);

    let stale_operation_id = Uuid::now_v7();
    storage
        .create_or_join_maintenance_operation(&MaintenanceOperationCreate {
            operation_id: stale_operation_id,
            credential_id,
            kind: "refresh".to_owned(),
            trigger: "admin".to_owned(),
            conflict_class: "auth_material_write".to_owned(),
            expected_revision: 8,
            expected_token_version: 2,
            egress_binding_id: binding_id,
            egress_epoch: 1,
            adapter_code: Some("oauth_refresh".to_owned()),
            adapter_version: Some("fixture-v1".to_owned()),
            provider_profile_id: None,
        })
        .await?;
    let losing_access = fixture_secret(&storage, "oauth_access_token", "credential", &owner, "loser-access").await?;
    let losing_refresh = fixture_secret(&storage, "oauth_refresh_token", "credential", &owner, "loser-refresh").await?;
    let loser = AuthCandidateRecord {
        auth_version_id: Uuid::now_v7(),
        credential_id,
        auth_kind: AuthKind::OauthSubscription,
        access_secret_id: Some(losing_access),
        refresh_secret_id: Some(losing_refresh),
        console_secret_id: None,
        verified_account_uuid: Some(account_uuid),
        expires_at_epoch_seconds: Some(2_000_003_600),
        adapter_code: Some("oauth_refresh".to_owned()),
        adapter_version: Some("fixture-v1".to_owned()),
    };
    sqlx::query(
        "INSERT INTO gateway.credential_auth_secret_stage \
         (operation_id,operation_generation,credential_id,candidate_token_version,access_secret_id,refresh_secret_id) \
         VALUES ($1,1,$2,3,$3,$4)",
    )
    .bind(stale_operation_id)
    .bind(credential_id)
    .bind(losing_access)
    .bind(losing_refresh)
    .execute(&storage.pool())
    .await?;
    assert!(matches!(
        storage
            .commit_auth_candidate(
                &loser,
                &AuthCasPrecondition {
                    expected_credential_revision: 7,
                    expected_token_version: 2,
                    expected_account_uuid: Some(account_uuid),
                    expected_egress_binding_id: binding_id,
                    expected_egress_epoch: 1,
                    operation_id: stale_operation_id,
                    operation_generation: 1,
                    durable_job_fence: None,
                },
            )
            .await,
        Err(StorageError::RevisionConflict)
    ));
    let destroyed_loser_secrets: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security.encrypted_secret WHERE id=ANY($1) AND destroyed_at IS NOT NULL \
         AND octet_length(ciphertext)=0 AND octet_length(wrapped_dek)=0",
    )
    .bind(vec![losing_access, losing_refresh])
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(destroyed_loser_secrets, 2);
    let losing_stage_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM gateway.credential_auth_secret_stage \
         WHERE operation_id=$1 AND operation_generation=1",
    )
    .bind(stale_operation_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(losing_stage_count, 0);

    let strategy_id = Uuid::now_v7();
    assert_eq!(
        storage
            .create_managed_browser_strategy(&ManagedBrowserStrategyCreate {
                strategy_id,
                credential_id,
                expected_credential_revision: 8,
                browser_provider_code: "managed_chromium".to_owned(),
                adapter_version: "fixture-browser-v1".to_owned(),
            })
            .await?,
        9
    );
    let browser_operation_id = Uuid::now_v7();
    storage
        .create_or_join_maintenance_operation(&MaintenanceOperationCreate {
            operation_id: browser_operation_id,
            credential_id,
            kind: "reauthenticate".to_owned(),
            trigger: "strategy_health".to_owned(),
            conflict_class: "auth_material_write".to_owned(),
            expected_revision: 9,
            expected_token_version: 2,
            egress_binding_id: binding_id,
            egress_epoch: 1,
            adapter_code: Some("managed_browser".to_owned()),
            adapter_version: Some("fixture-browser-v1".to_owned()),
            provider_profile_id: None,
        })
        .await?;
    let browser_access = fixture_secret(&storage, "oauth_access_token", "credential", &owner, "browser-access").await?;
    let browser_refresh =
        fixture_secret(&storage, "oauth_refresh_token", "credential", &owner, "browser-refresh").await?;
    let browser_cookie = fixture_secret(&storage, "browser_cookie", "credential", &owner, "browser-cookie").await?;
    let browser_storage = fixture_secret(&storage, "browser_storage", "credential", &owner, "browser-storage").await?;
    let browser_profile = fixture_secret(&storage, "browser_profile", "credential", &owner, "browser-profile").await?;
    let browser_commit = storage
        .commit_browser_reauth_candidate(
            &AuthCandidateRecord {
                auth_version_id: Uuid::now_v7(),
                credential_id,
                auth_kind: AuthKind::OauthSubscription,
                access_secret_id: Some(browser_access),
                refresh_secret_id: Some(browser_refresh),
                console_secret_id: None,
                verified_account_uuid: Some(account_uuid),
                expires_at_epoch_seconds: Some(2_000_007_200),
                adapter_code: Some("managed_browser".to_owned()),
                adapter_version: Some("fixture-browser-v1".to_owned()),
            },
            &BrowserMaterialCandidate {
                material_version_id: Uuid::now_v7(),
                strategy_id,
                credential_id,
                material_version: 1,
                cookie_secret_id: browser_cookie,
                storage_secret_id: Some(browser_storage),
                profile_secret_id: browser_profile,
                verified_account_uuid: account_uuid,
                adapter_version: "fixture-browser-v1".to_owned(),
            },
            &BrowserCasPrecondition {
                strategy_revision: 1,
                durable_job_id: None,
                durable_job_generation: None,
                auth: AuthCasPrecondition {
                    expected_credential_revision: 9,
                    expected_token_version: 2,
                    expected_account_uuid: Some(account_uuid),
                    expected_egress_binding_id: binding_id,
                    expected_egress_epoch: 1,
                    operation_id: browser_operation_id,
                    operation_generation: 1,
                    durable_job_fence: None,
                },
            },
        )
        .await?;
    assert_eq!(browser_commit.auth.token_version, 3);
    assert_eq!(browser_commit.auth.credential_revision, 10);
    assert_eq!(browser_commit.strategy_revision, 2);
    let browser_isolation: (Uuid, Uuid, i64, String) = sqlx::query_as(
        "SELECT strategy.credential_id,material.credential_id,material.egress_epoch,material.state_code \
         FROM gateway.auto_reauth_strategy strategy JOIN gateway.managed_browser_material_version material \
           ON material.id=strategy.active_material_version_id WHERE strategy.id=$1",
    )
    .bind(strategy_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(
        browser_isolation,
        (credential_id, credential_id, 1, "active".to_owned())
    );

    let target_group_id = fixture_group(&storage, "r5-target", "direct").await?;
    let migration_id = Uuid::now_v7();
    assert_eq!(
        storage
            .begin_credential_group_migration(&CredentialGroupMigrationBegin {
                migration_id,
                credential_id,
                source_group_id: group_id,
                target_group_id,
                expected_credential_revision: 10,
                requested_by: admin_id,
                drain_seconds: 300,
            })
            .await?,
        11
    );
    assert_eq!(
        storage.finish_credential_group_migration(migration_id, 11, 0).await?,
        12
    );
    let migrated = storage.load_credential_r5_snapshot(credential_id).await?;
    assert_eq!(migrated.group_id, target_group_id);
    assert_eq!(
        (migrated.profile_epoch, migrated.device_epoch, migrated.egress_epoch),
        (Some(3), Some(2), Some(1))
    );

    let plan_success = Uuid::now_v7();
    storage
        .commit_plan_observation(&PlanObservationCommit {
            observation_id: plan_success,
            credential_id,
            source: "oauth_profile".to_owned(),
            raw_plan_code: Some("max_20x".to_owned()),
            normalized_plan_code: "max".to_owned(),
            raw_redacted: json!({"plan": "max_20x"}),
            raw_digest: Some(vec![9; 32]),
            temporary_display_name: None,
            mapping_version: Some(1),
            mapping_artifact_id: None,
            adapter_version: Some("fixture-v1".to_owned()),
            success: true,
            failure_category: None,
            failure_summary: None,
        })
        .await?;
    storage
        .commit_plan_observation(&PlanObservationCommit {
            observation_id: Uuid::now_v7(),
            credential_id,
            source: "oauth_profile".to_owned(),
            raw_plan_code: None,
            normalized_plan_code: "unknown".to_owned(),
            raw_redacted: json!({}),
            raw_digest: None,
            temporary_display_name: None,
            mapping_version: Some(1),
            mapping_artifact_id: None,
            adapter_version: Some("fixture-v2".to_owned()),
            success: false,
            failure_category: Some("schema_changed".to_owned()),
            failure_summary: Some("redacted".to_owned()),
        })
        .await?;
    let plan: (Uuid, String, bool) = sqlx::query_as(
        "SELECT observation_id,normalized_plan_code,last_refresh_failed \
         FROM telemetry.subscription_plan_current WHERE credential_id=$1",
    )
    .bind(credential_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(plan, (plan_success, "max".to_owned(), true));

    let mapping_artifact_id = Uuid::now_v7();
    storage
        .create_plan_mapping_artifact(&PlanMappingArtifactCreate {
            artifact_id: mapping_artifact_id,
            artifact_version: 1,
            mappings: json!({"max_20x": "max_plus"}),
            content_hash: vec![10; 32],
            created_by: admin_id,
        })
        .await?;
    let recompute_job_id = Uuid::now_v7();
    let mapping_activation = storage
        .activate_plan_mapping(&PlanMappingActivation {
            artifact_id: mapping_artifact_id,
            pointer_id: Uuid::now_v7(),
            recompute_job_id,
            activated_by: admin_id,
            expected_pointer_revision: None,
        })
        .await?;
    assert_eq!(mapping_activation.pointer_revision, 1);
    let mapping_job = storage
        .claim_jobs("r5-plan-worker", 64, 60)
        .await?
        .into_iter()
        .find(|job| job.job_id == recompute_job_id)
        .ok_or(StorageError::InvalidLifecycle)?;
    let recompute = storage
        .recompute_plan_mapping(mapping_artifact_id, mapping_job.generation)
        .await?;
    assert!(recompute.affected_observations >= 1);
    assert_eq!(recompute.affected_credentials, 1);
    let remapped_plan: (String, Uuid) = sqlx::query_as(
        "SELECT normalized_plan_code,mapping_artifact_id \
         FROM telemetry.subscription_plan_current WHERE credential_id=$1",
    )
    .bind(credential_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(remapped_plan, ("max_plus".to_owned(), mapping_artifact_id));
    let recompute_history: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ops.durable_job_history \
         WHERE job_id=$1 AND to_state_code='succeeded' AND outcome_code='plan_mapping_recomputed'",
    )
    .bind(recompute_job_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(recompute_history, 1);

    let lifecycle_actor = Uuid::now_v7();
    let revoked_revision = storage
        .revoke_credential(&CredentialLifecycleCommand {
            credential_id,
            expected_revision: 12,
            actor_id: lifecycle_actor,
            reason_code: "fixture_revoke".to_owned(),
        })
        .await?;
    assert_eq!(revoked_revision, 13);
    storage
        .finalize_revoked_credential(credential_id, revoked_revision, 0)
        .await?;
    let archived_revision = storage
        .archive_credential(
            &CredentialLifecycleCommand {
                credential_id,
                expected_revision: revoked_revision,
                actor_id: lifecycle_actor,
                reason_code: "fixture_archive".to_owned(),
            },
            0,
        )
        .await?;
    assert_eq!(archived_revision, 14);
    let archived = storage.load_credential_r5_snapshot(credential_id).await?;
    assert_eq!(archived.lifecycle, "archived");
    assert_eq!(archived.account_uuid, Some(account_uuid));

    assert_global_account_dedupe(Arc::clone(&storage), group_id).await?;
    Ok(())
}

async fn assert_global_account_dedupe(
    storage: Arc<PgStorage>,
    group_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let account_uuid = Uuid::now_v7();
    let mut fixtures = Vec::new();
    for suffix in 0..2 {
        let enrollment_id = Uuid::now_v7();
        let credential_id = Uuid::now_v7();
        storage
            .create_credential_enrollment(&CredentialEnrollmentCreate {
                enrollment_id,
                credential_id,
                group_id,
                created_by: None,
                mode: EnrollmentMode::Create,
                auth_method: EnrollmentAuthMethod::OauthPkce,
                auth_kind: AuthKind::OauthSubscription,
                purpose: CredentialPurpose::Business,
                management_class: ManagementClass::NonManaged,
                recovery_credential_id: None,
                expected_credential_revision: None,
                expires_in_seconds: 1_800,
                callback_window_seconds: 600,
            })
            .await?;
        storage
            .allocate_enrollment_egress(&EgressAllocationRequest {
                enrollment_id,
                credential_id,
                binding_id: Uuid::now_v7(),
                expected_enrollment_revision: 1,
                expected_credential_revision: 1,
            })
            .await?;
        storage
            .advance_credential_enrollment(enrollment_id, 2, "awaiting_user_action", "exchanging_material", "retry")
            .await?;
        storage
            .advance_credential_enrollment(enrollment_id, 3, "exchanging_material", "verifying_account", "retry")
            .await?;
        fixtures.push((suffix, enrollment_id, credential_id));
    }
    let barrier = Arc::new(Barrier::new(2));
    let mut tasks = Vec::new();
    for (_suffix, enrollment_id, credential_id) in fixtures {
        let storage = Arc::clone(&storage);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            storage
                .claim_verified_account(enrollment_id, credential_id, account_uuid, 4, 2)
                .await
        }));
    }
    let mut winners = 0;
    let mut conflicts = 0;
    for task in tasks {
        match task.await? {
            Ok(()) => winners += 1,
            Err(StorageError::AccountConflict) => conflicts += 1,
            other => return Err(format!("unexpected dedupe result: {other:?}").into()),
        }
    }
    assert_eq!((winners, conflicts), (1, 1));
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM gateway.anthropic_credential WHERE account_uuid=$1")
        .bind(account_uuid)
        .fetch_one(&storage.pool())
        .await?;
    assert_eq!(stored, 1);
    Ok(())
}

async fn fixture_group(
    storage: &PgStorage,
    name: &str,
    egress_policy: &str,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let group_id = Uuid::now_v7();
    let config_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO gateway.credential_group \
         (id,name,status_code,owner_generation,revision,created_at,updated_at) \
         VALUES ($1,$2,'active',1,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(group_id)
    .bind(format!("{name}-{group_id}"))
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO gateway.group_config \
         (id,group_id,config_version,content_hash,default_rpm,queue_capacity,queue_timeout_ms,system_prompt_mode_code, \
          proxy_policy_code,model_scope_code,lifecycle_code,validation_report,validated_at,published_at,created_at) \
         VALUES ($1,$2,1,$3,60,10,30000,'preserve',$4,'all_published','active','{}'::jsonb, \
                 clock_timestamp(),clock_timestamp(),clock_timestamp())",
    )
    .bind(config_id)
    .bind(group_id)
    .bind(Uuid::now_v7().as_bytes().to_vec())
    .bind(egress_policy)
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO gateway.group_active_config (group_id,config_id,revision,activated_at) \
         VALUES ($1,$2,1,clock_timestamp())",
    )
    .bind(group_id)
    .bind(config_id)
    .execute(&storage.pool())
    .await?;
    Ok(group_id)
}

async fn fixture_archetype(storage: &PgStorage) -> Result<Uuid, Box<dyn std::error::Error>> {
    let archetype = Uuid::now_v7();
    let version = Uuid::now_v7();
    let bundle = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO catalog.environment_archetype \
         (id,name,os_family_code,architecture_code,lifecycle_code,created_at,updated_at,revision) \
         VALUES ($1,$2,'windows','x86_64','active',clock_timestamp(),clock_timestamp(),1)",
    )
    .bind(archetype)
    .bind(format!("r5-windows-{archetype}"))
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO catalog.environment_archetype_version \
         (id,archetype_id,version,lifecycle_code,runtime_code,runtime_version,client_version,protocol_profile, \
          content_hash,created_at,activated_at,capture_cohort) \
         VALUES ($1,$2,1,'active','bun','1.2','2.1.220','{}'::jsonb,$3,clock_timestamp(),clock_timestamp(),'windows-r5')",
    )
    .bind(version)
    .bind(archetype)
    .bind(Uuid::now_v7().as_bytes().to_vec())
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO catalog.transport_bundle \
         (id,artifact_version,engine_abi_version,lifecycle_code,manifest,manifest_hash,signature,signing_key_id,object_uri, \
          source_archetype_version_id,capture_cohort,protocol_code,backend_id,evidence_gate_code,min_engine_build, \
          created_at,activated_at) \
         VALUES ($1,1,'r6-v1','active','{}'::jsonb,$2,$3,'fixture','fixture://bundle',$4,'windows-r5','h1', \
                 'boring-h1','passed','0.1.0',clock_timestamp(),clock_timestamp())",
    )
    .bind(bundle)
    .bind(Uuid::now_v7().as_bytes().to_vec())
    .bind(vec![7_u8; 32])
    .bind(version)
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO catalog.archetype_bundle_binding \
         (archetype_version_id,transport_bundle_id,state_code,protocol_code,created_at,activated_at) \
         VALUES ($1,$2,'active','h1',clock_timestamp(),clock_timestamp())",
    )
    .bind(version)
    .bind(bundle)
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO catalog.archetype_capacity_policy \
         (id,archetype_version_id,max_credentials,max_connections,revision,created_at,updated_at) \
         VALUES ($1,$2,100,100,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(Uuid::now_v7())
    .bind(version)
    .execute(&storage.pool())
    .await?;
    Ok(version)
}

async fn fixture_archetype_upgrade(
    storage: &PgStorage,
    source_version: Uuid,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let archetype_id: Uuid =
        sqlx::query_scalar("SELECT archetype_id FROM catalog.environment_archetype_version WHERE id=$1")
            .bind(source_version)
            .fetch_one(&storage.pool())
            .await?;
    let version = Uuid::now_v7();
    let bundle = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO catalog.environment_archetype_version \
         (id,archetype_id,version,lifecycle_code,runtime_code,runtime_version,client_version,protocol_profile, \
          content_hash,created_at,activated_at,capture_cohort) \
         VALUES ($1,$2,2,'active','bun','1.2','2.1.241','{}'::jsonb,$3,clock_timestamp(),clock_timestamp(), \
                 'windows-r5-next')",
    )
    .bind(version)
    .bind(archetype_id)
    .bind(Uuid::now_v7().as_bytes().to_vec())
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO catalog.transport_bundle \
         (id,artifact_version,engine_abi_version,lifecycle_code,manifest,manifest_hash,signature,signing_key_id,object_uri, \
          source_archetype_version_id,capture_cohort,protocol_code,backend_id,evidence_gate_code,min_engine_build, \
          created_at,activated_at) \
         VALUES ($1,2,'r6-v1','active','{}'::jsonb,$2,$3,'fixture','fixture://bundle-v2',$4,'windows-r5-next','h1', \
                 'boring-h1','passed','0.1.0',clock_timestamp(),clock_timestamp())",
    )
    .bind(bundle)
    .bind(Uuid::now_v7().as_bytes().to_vec())
    .bind(vec![8_u8; 32])
    .bind(version)
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO catalog.archetype_bundle_binding \
         (archetype_version_id,transport_bundle_id,state_code,protocol_code,created_at,activated_at) \
         VALUES ($1,$2,'active','h1',clock_timestamp(),clock_timestamp())",
    )
    .bind(version)
    .bind(bundle)
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO catalog.archetype_capacity_policy \
         (id,archetype_version_id,max_credentials,max_connections,revision,created_at,updated_at) \
         VALUES ($1,$2,100,100,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(Uuid::now_v7())
    .bind(version)
    .execute(&storage.pool())
    .await?;
    Ok(version)
}

async fn fixture_secret(
    storage: &PgStorage,
    kind: &str,
    owner_type: &str,
    owner: &str,
    purpose: &str,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO security.encrypted_secret \
         (id,secret_kind_code,provider_role_code,cipher_suite_code,ciphertext,nonce,wrapped_dek,key_version, \
          aad_schema_version,owner_type_code,owner_id,purpose_code,created_at) \
         VALUES ($1,$2,'business','aes_256_gcm',$3,$4,$5,1,1,$6,$7,$8,clock_timestamp())",
    )
    .bind(id)
    .bind(kind)
    .bind(vec![1_u8, 2, 3])
    .bind(vec![0_u8; 12])
    .bind(vec![4_u8, 5, 6])
    .bind(owner_type)
    .bind(owner)
    .bind(purpose)
    .execute(&storage.pool())
    .await?;
    Ok(id)
}
