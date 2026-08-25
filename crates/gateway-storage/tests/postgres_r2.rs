#![forbid(unsafe_code)]
//! Real `PostgreSQL` R2 contract. CI supplies a disposable `PostgreSQL` 16 database.

use std::{collections::BTreeSet, sync::Arc};

use gateway_domain::SecretValue;
use gateway_storage::{
    BootstrapAdminRecord, BootstrapOutcome, PgStorage, RuntimeRolePolicy, StorageError, embedded_migration_count,
};
use tokio::sync::Barrier;
use uuid::Uuid;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one disposable database lifecycle keeps migration, bootstrap, lease, and lock-order assertions deterministic"
)]
async fn postgres_r2_schema_bootstrap_and_role_contract() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let Ok(database_url) = std::env::var("TEST_DATABASE_ADMIN_URL") else {
        return Ok(());
    };
    let database_url = SecretValue::new(database_url);
    let report = PgStorage::migrate(&database_url).await?;
    assert_eq!(report.applied_count, embedded_migration_count());

    let storage = Arc::new(PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?);
    assert!(storage.active_transport_bundle_ids().await?.is_empty());
    let schema_manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/database-schema-manifest.valid.json"
    ))?;
    let expected_tables = schema_manifest["required_tables"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("database schema manifest must contain required_tables"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| std::io::Error::other("required table must be a string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let actual_tables = sqlx::query_as::<_, (String, String)>(
        "SELECT n.nspname, c.relname \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname IN ('iam','gateway','catalog','telemetry','security','ops') \
           AND c.relkind IN ('r','p') AND NOT c.relispartition",
    )
    .fetch_all(&storage.pool())
    .await?
    .into_iter()
    .map(|(schema, table)| format!("{schema}.{table}"))
    .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_tables, expected_tables,
        "real PostgreSQL tables must exactly match the generated schema manifest"
    );

    let policy_release_objects: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ( \
           SELECT 1 FROM information_schema.tables \
             WHERE table_schema='catalog' AND table_name='artifact_rollout_evidence' \
           UNION ALL SELECT 1 FROM information_schema.columns \
             WHERE table_schema='gateway' AND table_name='group_config' AND column_name='enforcement_artifact_id' \
           UNION ALL SELECT 1 FROM pg_indexes \
             WHERE schemaname='catalog' AND indexname='policy_artifact_one_shadow_uq' \
           UNION ALL SELECT 1 FROM pg_indexes \
             WHERE schemaname='catalog' AND indexname='policy_artifact_one_active_uq' \
         ) required",
    )
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(policy_release_objects, 4);

    storage.ensure_database_business_key().await?;
    let candidate = BootstrapAdminRecord {
        user_id: Uuid::now_v7(),
        password_credential_id: Uuid::now_v7(),
        username: "r2-admin".to_owned(),
        username_normalized: "r2-admin".to_owned(),
        display_name: Some("R2 Administrator".to_owned()),
        email: None,
        email_normalized: None,
        password_phc: SecretValue::new("$argon2id$v=19$m=65536,t=3,p=1$cjItZml4dHVyZS1zYWx0$fixture".to_owned()),
    };
    assert_eq!(
        storage.bootstrap_admin(Some(candidate)).await?,
        BootstrapOutcome::Created
    );
    assert_eq!(storage.bootstrap_admin(None).await?, BootstrapOutcome::ExistingUser);

    let group_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO gateway.credential_group \
         (id,name,status_code,owner_generation,revision,created_at,updated_at) \
         VALUES ($1,$2,'active',1,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(group_id)
    .bind(format!("r4-owner-{group_id}"))
    .execute(&storage.pool())
    .await?;
    let first_claim = storage.claim_group_owner(group_id, "executor-a").await?;
    assert_eq!(first_claim.owner_generation, 2);
    assert!(matches!(
        storage.claim_group_owner(group_id, "executor-b").await,
        Err(StorageError::RevisionConflict)
    ));
    storage.heartbeat_group_owner(group_id, "executor-a", 2).await?;
    assert!(
        matches!(
            storage.heartbeat_group_owner(group_id, "executor-a", 1).await,
            Err(StorageError::RevisionConflict)
        ),
        "an old generation must not renew the current owner"
    );
    storage.release_group_owner(group_id, "executor-a", 2).await?;
    let second_claim = storage.claim_group_owner(group_id, "executor-b").await?;
    assert_eq!(second_claim.owner_generation, 3);
    storage.release_group_owner(group_id, "executor-b", 3).await?;
    let group_revision: i64 = sqlx::query_scalar("SELECT revision FROM gateway.credential_group WHERE id=$1")
        .bind(group_id)
        .fetch_one(&storage.pool())
        .await?;
    assert_eq!(
        group_revision, 1,
        "owner lease churn must not invalidate management ETags"
    );

    let scheduler_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE (table_schema,table_name,column_name) IN ( \
           ('gateway','group_config','max_concurrency'), \
           ('gateway','group_config','pre_upstream_wait_ms'), \
           ('gateway','credential_scheduling_config','priority_layer'), \
           ('gateway','credential_scheduling_config','session_capacity_enabled'), \
           ('telemetry','request_stage_timing','stage_ordinal'), \
           ('telemetry','request_resource_event','owner_generation'), \
           ('telemetry','request_resource_event','action_code'))",
    )
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(scheduler_columns, 7);
    let integrity = storage
        .verify_audit_integrity(&SecretValue::new("fixture-audit-integrity-key".to_owned()))
        .await?;
    assert_eq!(integrity.audit_event_count, 1);
    assert_eq!(integrity.deletion_ledger_count, 0);

    assert_eq!(storage.rotate_database_business_key().await?, 2);
    let first_key = storage.load_database_business_key(1).await?;
    let second_key = storage.load_database_business_key(2).await?;
    assert_eq!(first_key.expose().len(), 32);
    assert_eq!(second_key.expose().len(), 32);
    assert_ne!(first_key.expose(), second_key.expose());

    let job_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ops.durable_job \
         (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
         VALUES ($1,'r2_fixture','r2-fixture','scheduled',1,'{}'::jsonb,clock_timestamp(),0,0,3,clock_timestamp(),clock_timestamp())",
    )
    .bind(job_id)
    .execute(&storage.pool())
    .await?;
    let jobs = storage.claim_jobs("r2-worker", 1, 30).await?;
    assert_eq!(jobs.len(), 1);
    assert!(matches!(
        storage.complete_job(job_id, jobs[0].generation + 1, "fixture").await,
        Err(StorageError::RevisionConflict)
    ));
    storage.complete_job(job_id, jobs[0].generation, "fixture").await?;

    let restart_job_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ops.durable_job \
         (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
         VALUES ($1,'r5_restart_fixture',$2,'scheduled',1,'{}'::jsonb,clock_timestamp(),0,0,3,clock_timestamp(),clock_timestamp())",
    )
    .bind(restart_job_id)
    .bind(format!("r5-restart-{restart_job_id}"))
    .execute(&storage.pool())
    .await?;
    let first_lease = storage.claim_jobs("r5-worker-a", 1, 60).await?.remove(0);
    assert_eq!((first_lease.attempt, first_lease.max_attempts), (1, 3));
    assert_eq!(first_lease.checkpoint, None);
    let checkpoint = serde_json::json!({"phase": "account_verified"});
    storage
        .heartbeat_job(
            restart_job_id,
            first_lease.generation,
            "r5-worker-a",
            60,
            Some(&checkpoint),
        )
        .await?;
    storage
        .retry_job(
            restart_job_id,
            first_lease.generation,
            0,
            "transient_fixture",
            Some(&checkpoint),
        )
        .await?;
    let second_lease = storage.claim_jobs("r5-worker-b", 1, 60).await?.remove(0);
    assert_eq!(second_lease.generation, first_lease.generation + 1);
    assert_eq!(second_lease.attempt, 2);
    assert_eq!(second_lease.checkpoint, Some(checkpoint));
    assert!(matches!(
        storage
            .complete_job(restart_job_id, first_lease.generation, "stale-worker")
            .await,
        Err(StorageError::RevisionConflict)
    ));
    storage
        .dead_letter_job(restart_job_id, second_lease.generation, "terminal_fixture", None)
        .await?;
    assert!(storage.claim_jobs("r5-worker-c", 10, 60).await?.is_empty());

    let expired_job_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ops.durable_job \
         (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_owner,lease_generation, \
          lease_expires_at,attempt_count,max_attempts,created_at,updated_at) \
         VALUES ($1,'r5_expired_fixture',$2,'leased',1,'{}'::jsonb,clock_timestamp(),'dead-worker',1, \
                 clock_timestamp()-interval '1 second',1,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(expired_job_id)
    .bind(format!("r5-expired-{expired_job_id}"))
    .execute(&storage.pool())
    .await?;
    assert!(storage.claim_jobs("r5-reaper", 10, 60).await?.is_empty());
    let expired_state: String = sqlx::query_scalar("SELECT state_code FROM ops.durable_job WHERE id=$1")
        .bind(expired_job_id)
        .fetch_one(&storage.pool())
        .await?;
    assert_eq!(expired_state, "dead_letter");

    let outbox = storage.claim_outbox("r2-worker", 1, 30).await?;
    assert_eq!(outbox.len(), 1);
    assert!(matches!(
        storage
            .publish_outbox(outbox[0].message_id, outbox[0].generation + 1)
            .await,
        Err(StorageError::RevisionConflict)
    ));
    storage
        .publish_outbox(outbox[0].message_id, outbox[0].generation)
        .await?;

    let admin_id: Uuid = sqlx::query_scalar("SELECT id FROM iam.user_account LIMIT 1")
        .fetch_one(&storage.pool())
        .await?;
    let group_id = Uuid::now_v7();
    let proxy_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO gateway.credential_group \
         (id,owner_generation,name,status_code,revision,created_by,created_at,updated_at) \
         VALUES ($1,1,'r2-proxy-capacity','active',1,$2,clock_timestamp(),clock_timestamp())",
    )
    .bind(group_id)
    .bind(admin_id)
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO gateway.proxy_endpoint \
         (id,name,proxy_type_code,host,port,lifecycle_code,health_code,stability_code,max_active_bindings,revision,created_at,updated_at) \
         VALUES ($1,'R2 fixture proxy','http_connect','proxy.fixture',8080,'active','healthy','static',5,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(proxy_id)
    .execute(&storage.pool())
    .await?;
    let mut credential_ids = Vec::new();
    for _ in 0..6 {
        let credential_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO gateway.anthropic_credential \
             (id,group_id,purpose_code,auth_kind_code,lifecycle_state_code,auth_state_code,scheduling_state_code,quota_state_code,transport_state_code,management_class_code,token_version,revision,created_at,updated_at) \
             VALUES ($1,$2,'business','oauth_subscription','pending_egress','needs_admin_reauth','blocked','unknown','transport_unavailable','fully_managed',1,1,clock_timestamp(),clock_timestamp())",
        )
        .bind(credential_id)
        .bind(group_id)
        .execute(&storage.pool())
        .await?;
        credential_ids.push(credential_id);
    }
    let barrier = Arc::new(Barrier::new(credential_ids.len()));
    let mut tasks = Vec::new();
    for credential_id in credential_ids {
        let storage = Arc::clone(&storage);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            storage
                .bind_proxy_egress(credential_id, 1, Uuid::now_v7(), proxy_id)
                .await
        }));
    }
    let mut successes = 0;
    let mut capacity_rejections = 0;
    for task in tasks {
        match task.await? {
            Ok(1) => successes += 1,
            Err(StorageError::CapacityExceeded) => capacity_rejections += 1,
            _ => return Err("unexpected proxy binding result".into()),
        }
    }
    assert_eq!(successes, 5);
    assert_eq!(capacity_rejections, 1);

    let atomic_counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM iam.user_account), \
                (SELECT count(*) FROM iam.password_credential), \
                (SELECT count(*) FROM security.audit_event), \
                (SELECT count(*) FROM ops.outbox_message)",
    )
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(atomic_counts, (1, 1, 6, 6));

    let runtime_has_no_schema_create: bool = sqlx::query_scalar(
        "SELECT NOT has_schema_privilege('gateway_runtime','iam','CREATE') \
                AND NOT has_table_privilege('gateway_runtime','security.business_key_material','TRUNCATE')",
    )
    .fetch_one(&storage.pool())
    .await?;
    assert!(runtime_has_no_schema_create);
    let readonly_cannot_read_secret_material: bool = sqlx::query_scalar(
        "SELECT NOT has_table_privilege('gateway_readonly','security.encrypted_secret','SELECT') \
                AND NOT has_table_privilege('gateway_readonly','security.business_key_material','SELECT')",
    )
    .fetch_one(&storage.pool())
    .await?;
    assert!(readonly_cannot_read_secret_material);
    Ok(())
}
