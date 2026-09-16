#![forbid(unsafe_code)]
//! Upgrade proof with historical audit jobs, approvals and exports present.

use std::borrow::Cow;

use gateway_domain::SecretValue;
use gateway_storage::{CURRENT_SCHEMA_VERSION, PgStorage, RuntimeRolePolicy, embedded_migration_count};

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one upgrade lifecycle retains historical rows across the migration"
)]
async fn audit_retirement_preserves_history_and_rejects_new_audit_work() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(url) = std::env::var("TEST_T6_DATABASE_ADMIN_URL") else {
        return Ok(());
    };
    let pool = sqlx::PgPool::connect(&url).await?;
    let mut before = sqlx::migrate!("./migrations");
    before.migrations = Cow::Owned(
        before
            .iter()
            .filter(|migration| migration.version <= 20_260_901_000_100)
            .cloned()
            .collect(),
    );
    before.run(&pool).await?;
    sqlx::raw_sql(
        r"
        INSERT INTO security.business_key_material
          (key_version,provider_code,key_material,state_code,checksum,created_at,activated_at)
        VALUES (1,'database',decode(repeat('01',32),'hex'),'active',decode(repeat('01',32),'hex'),now(),now());
        INSERT INTO iam.user_account
          (id,username,username_normalized,role_code,status_code,created_at,updated_at)
        VALUES ('00000000-0000-0000-0000-000000000001','upgrade-test','upgrade-test',
                'platform_admin','active',now(),now());
        INSERT INTO ops.durable_job
          (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,
           lease_owner,lease_expires_at,max_attempts,created_at,updated_at)
        SELECT gen_random_uuid(),kind,state,state,1,'{}',now(),
               CASE WHEN state='leased' THEN 'fixture' END,
               CASE WHEN state='leased' THEN now()+interval '1 hour' END,3,now(),now()
        FROM unnest(ARRAY['content_audit_purge','content_audit_export_generate','usage_export_generate']) kind,
             unnest(ARRAY['scheduled','leased','retry_wait','succeeded']) state;
        INSERT INTO security.approval_case
          (id,operation_code,object_type_code,object_id,state_code,request_digest,expires_at,created_at)
        VALUES ('00000000-0000-0000-0000-000000000002','content_audit_export','fixture','fixture',
                'pending',decode(repeat('01',32),'hex'),now()+interval '1 day',now());
        INSERT INTO ops.export_job
          (id,requested_by,scope_code,query,state_code,created_at,dataset_code,format_code,query_sha256,content_length)
        VALUES ('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001',
                'all','{}','expired',now(),'content_audit_record_v1','raw',decode(repeat('01',32),'hex'),40000000);
        INSERT INTO ops.export_job
          (id,requested_by,scope_code,query,state_code,created_at,dataset_code,format_code,query_sha256,
           durable_job_id,object_uri,content_sha256,expires_at,row_count,content_length,cipher_suite_code,
           nonce,wrapped_dek,key_version)
        SELECT gen_random_uuid(),'00000000-0000-0000-0000-000000000001','all','{}','succeeded',now(),
               CASE WHEN kind_code='content_audit_export_generate' THEN 'content_audit_record_v1' ELSE 'usage_requests_v1' END,
               CASE WHEN kind_code='content_audit_export_generate' THEN 'raw' ELSE 'jsonl' END,
               decode(repeat('01',32),'hex'),id,kind_code,decode(repeat('01',32),'hex'),now()-interval '1 hour',
               1,100,'aes_256_gcm',decode(repeat('01',12),'hex'),decode('01','hex'),1
        FROM ops.durable_job WHERE state_code='succeeded'
          AND kind_code IN ('content_audit_export_generate','usage_export_generate');
        ",
    )
    .execute(&pool)
    .await?;
    let url = SecretValue::new(url);
    let report = PgStorage::migrate(&url).await?;
    assert_eq!(report.current_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(report.applied_count, embedded_migration_count());
    assert_eq!(PgStorage::migrate(&url).await?, report);
    sqlx::raw_sql(
        r"
        DO $$
        BEGIN
          IF (SELECT count(*) FROM ops.durable_job
              WHERE kind_code LIKE 'content_audit_%' AND state_code='cancelled'
                AND lease_owner IS NULL AND lease_expires_at IS NULL AND completed_at IS NOT NULL) <> 6 THEN
            RAISE EXCEPTION 'pending audit jobs were not cancelled and released';
          END IF;
          IF (SELECT count(*) FROM ops.durable_job
              WHERE kind_code LIKE 'content_audit_%' AND state_code='succeeded') <> 2 THEN
            RAISE EXCEPTION 'completed audit jobs changed';
          END IF;
          IF (SELECT count(*) FROM ops.durable_job
              WHERE kind_code='usage_export_generate' AND state_code<>'cancelled') <> 4 THEN
            RAISE EXCEPTION 'usage jobs changed';
          END IF;
          IF (SELECT count(*) FROM security.approval_case WHERE operation_code='content_audit_export') <> 1
             OR (SELECT count(*) FROM ops.export_job WHERE dataset_code='content_audit_record_v1'
                 AND format_code='raw' AND content_length=40000000) <> 1 THEN
            RAISE EXCEPTION 'historical records not preserved';
          END IF;
          IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='security'
                     AND table_name IN ('content_audit_object','content_audit_export_binding',
                       'content_audit_search_candidate','content_audit_access','content_audit_search_session',
                       'legal_hold','legal_hold_object')) THEN
            RAISE EXCEPTION 'retired tables remain';
          END IF;
          IF EXISTS (SELECT 1 FROM information_schema.columns
                     WHERE (table_schema='iam' AND table_name='platform_key_config'
                       AND column_name IN ('audit_mode_code','content_audit_approval_case_id','content_audit_expires_at'))
                        OR (table_schema='gateway' AND table_name='group_config'
                       AND column_name IN ('content_audit_policy_code','content_audit_retention_days'))) THEN
            RAISE EXCEPTION 'retired columns remain';
          END IF;
          BEGIN
            INSERT INTO security.approval_case
              (id,operation_code,object_type_code,object_id,state_code,request_digest,expires_at,created_at)
            SELECT gen_random_uuid(),operation_code,object_type_code,object_id,state_code,request_digest,expires_at,now()
            FROM security.approval_case WHERE id='00000000-0000-0000-0000-000000000002';
            RAISE EXCEPTION 'new audit approval accepted';
          EXCEPTION WHEN check_violation THEN NULL;
          END;
          BEGIN
            INSERT INTO ops.export_job
              (id,requested_by,scope_code,query,state_code,created_at,dataset_code,format_code,query_sha256)
            SELECT gen_random_uuid(),requested_by,scope_code,query,'queued',now(),dataset_code,format_code,query_sha256
            FROM ops.export_job WHERE id='00000000-0000-0000-0000-000000000003';
            RAISE EXCEPTION 'new audit export accepted';
          EXCEPTION WHEN check_violation THEN NULL;
          END;
          -- NOT VALID preserves history for reading, not for further state transitions.
          BEGIN
            UPDATE security.approval_case SET state_code='expired'
              WHERE id='00000000-0000-0000-0000-000000000002';
            RAISE EXCEPTION 'historical audit approval remained mutable';
          EXCEPTION WHEN check_violation THEN NULL;
          END;
        END $$;
        INSERT INTO security.approval_case
          (id,operation_code,object_type_code,object_id,state_code,request_digest,expires_at,created_at)
        SELECT gen_random_uuid(),operation,'fixture','fixture','pending',decode(repeat('01',32),'hex'),
               now()+interval '1 day',now()
        FROM unnest(ARRAY['device_rebuild','key_provider_change']) operation;
        INSERT INTO ops.export_job
          (id,requested_by,scope_code,query,state_code,created_at,dataset_code,format_code,query_sha256)
        SELECT gen_random_uuid(),'00000000-0000-0000-0000-000000000001','all','{}','queued',now(),
               'usage_requests_v1',format,decode(repeat('01',32),'hex')
        FROM unnest(ARRAY['jsonl','csv']) format;
        ",
    )
    .execute(&pool)
    .await?;
    let storage = PgStorage::connect(&url, RuntimeRolePolicy::AllowPrivilegedTest).await?;
    assert_eq!(storage.expire_usage_exports(100).await?, vec!["usage_export_generate"]);
    let historical: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ops.export_job WHERE dataset_code='content_audit_record_v1' AND state_code='succeeded'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(historical, 1);
    let backup_grants: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('gateway_backup','telemetry.request_body','SELECT') \
         AND has_table_privilege('gateway_backup','ops.system_setting','SELECT')",
    )
    .fetch_one(&pool)
    .await?;
    assert!(backup_grants);
    pool.close().await;
    Ok(())
}
