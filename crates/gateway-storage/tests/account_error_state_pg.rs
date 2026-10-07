#![forbid(unsafe_code)]
//! Real `PostgreSQL` account error-state contract: `last_error` columns on both
//! account tables, the widened cooldown-event reason set (`overload`), and the
//! blocked-state recovery write shared by the dispatcher and the admin clear op.

use gateway_domain::SecretValue;
use gateway_storage::{PgStorage, RuntimeRolePolicy, embedded_migration_count};
use uuid::Uuid;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn account_error_state_columns_and_overload_reason_contract() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let Ok(database_url) = std::env::var("TEST_DATABASE_ADMIN_URL") else {
        return Ok(());
    };
    let database_url = SecretValue::new(database_url);
    let report = PgStorage::migrate(&database_url).await?;
    assert_eq!(report.applied_count, embedded_migration_count());
    let storage = PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?;
    storage.ensure_database_business_key().await?;
    let pool = storage.pool();

    let user_id = Uuid::now_v7();
    let group_id = Uuid::now_v7();
    let credential_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO iam.user_account \
         (id,username,username_normalized,role_code,status_code,revision,created_at,updated_at) \
         VALUES ($1,$2,$2,'platform_admin','active',1,clock_timestamp(),clock_timestamp())",
    )
    .bind(user_id)
    .bind(format!("aes-owner-{user_id}"))
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO gateway.credential_group \
         (id,owner_executor_id,owner_generation,name,status_code,revision,created_by,created_at,updated_at) \
         VALUES ($1,'aes-executor',1,$2,'active',1,$3,clock_timestamp(),clock_timestamp())",
    )
    .bind(group_id)
    .bind(format!("aes-group-{group_id}"))
    .bind(user_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO gateway.anthropic_credential \
         (id,group_id,purpose_code,auth_kind_code,lifecycle_state_code,auth_state_code,scheduling_state_code, \
          quota_state_code,transport_state_code,management_class_code,token_version,revision,created_at,updated_at) \
         VALUES ($1,$2,'business','oauth_subscription','active','healthy','eligible','unknown','ready', \
                 'fully_managed',1,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(credential_id)
    .bind(group_id)
    .execute(&pool)
    .await?;

    // The widened reason set accepts `overload` next to the original five reasons.
    sqlx::query(
        "INSERT INTO telemetry.credential_cooldown_event \
         (id,credential_id,reason_code,started_at,cooldown_until) \
         VALUES ($1,$2,'overload',clock_timestamp(),clock_timestamp()+interval '60 seconds')",
    )
    .bind(Uuid::now_v7())
    .bind(credential_id)
    .execute(&pool)
    .await?;
    assert!(
        sqlx::query(
            "INSERT INTO telemetry.credential_cooldown_event \
             (id,credential_id,reason_code,started_at,cooldown_until) \
             VALUES ($1,$2,'bogus',clock_timestamp(),clock_timestamp()+interval '60 seconds')",
        )
        .bind(Uuid::now_v7())
        .bind(credential_id)
        .execute(&pool)
        .await
        .is_err(),
        "unknown cooldown reason must be rejected"
    );

    // Account-level rejection: blocked + last_error persisted on the account row.
    let updated = sqlx::query(
        "UPDATE gateway.anthropic_credential \
         SET scheduling_state_code='blocked', \
             last_error_code=$2,last_error_message=$3,last_error_at=clock_timestamp(), \
             revision=revision+1,updated_at=clock_timestamp() \
         WHERE id=$1 AND lifecycle_state_code='active' \
           AND (scheduling_state_code<>'blocked' OR last_error_code IS DISTINCT FROM $2) \
         RETURNING group_id",
    )
    .bind(credential_id)
    .bind("account_suspended")
    .bind("account suspended for policy violation")
    .execute(&pool)
    .await?
    .rows_affected();
    assert_eq!(updated, 1, "rejection write must land on an active credential");
    let (state, error_code): (String, String) =
        sqlx::query_as("SELECT scheduling_state_code,last_error_code FROM gateway.anthropic_credential WHERE id=$1")
            .bind(credential_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(state, "blocked");
    assert_eq!(error_code, "account_suspended");

    // Recovery (admin clear-cooldown): blocked reopens and the error clears.
    sqlx::query(
        "UPDATE gateway.anthropic_credential \
         SET consecutive_cooldown_count=0,cooldown_until=NULL, \
             scheduling_state_code=CASE WHEN scheduling_state_code IN ('cooldown','blocked') THEN 'eligible' ELSE scheduling_state_code END, \
             capacity_state_code=CASE WHEN capacity_state_code='cooldown' THEN 'available' ELSE capacity_state_code END, \
             last_error_code=NULL,last_error_message=NULL,last_error_at=NULL, \
             revision=revision+1,updated_at=clock_timestamp() \
         WHERE id=$1",
    )
    .bind(credential_id)
    .execute(&pool)
    .await?;
    let (state, error_code, has_error): (String, Option<String>, bool) = sqlx::query_as(
        "SELECT scheduling_state_code,last_error_code,last_error_at IS NOT NULL \
         FROM gateway.anthropic_credential WHERE id=$1",
    )
    .bind(credential_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(state, "eligible");
    assert_eq!(error_code, None);
    assert!(!has_error);

    // OpenAI accounts carry the same error surface.
    let openai_group = Uuid::now_v7();
    let account_id = Uuid::now_v7();
    let secret_id = Uuid::now_v7();
    let refresh_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO gateway.credential_group (id,name,status_code,provider_code,created_at,updated_at) \
         VALUES ($1,$2,'active','openai',clock_timestamp(),clock_timestamp())",
    )
    .bind(openai_group)
    .bind(format!("aes-openai-{openai_group}"))
    .execute(&pool)
    .await?;
    for secret in [secret_id, refresh_id] {
        sqlx::query(
            "INSERT INTO security.encrypted_secret \
             (id,secret_kind_code,provider_role_code,ciphertext,nonce,wrapped_dek,key_version,aad_schema_version, \
              owner_type_code,owner_id,purpose_code,created_at) \
             SELECT $1,'platform_key','business',$2,$3,$4,key_version,1,'platform_key',$5,'authentication',clock_timestamp() \
             FROM security.business_key_material WHERE state_code='active'",
        )
        .bind(secret)
        .bind(vec![1_u8; 32])
        .bind(vec![2_u8; 12])
        .bind(vec![3_u8; 32])
        .bind(secret.to_string())
        .execute(&pool)
        .await?;
    }
    sqlx::query(
        "INSERT INTO gateway.openai_account \
         (id,group_id,name,auth_kind_code,account_id,access_secret_id,refresh_secret_id,auth_state_code,enabled,verified_at) \
         VALUES ($1,$2,'aes-fixture','oauth',$3,$4,$5,'healthy',true,clock_timestamp())",
    )
    .bind(account_id)
    .bind(openai_group)
    .bind(account_id.to_string())
    .bind(secret_id)
    .bind(refresh_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "UPDATE gateway.openai_account \
         SET last_error_code='account_forbidden',last_error_message='upstream forbidden the account (403)', \
             last_error_at=clock_timestamp() WHERE id=$1",
    )
    .bind(account_id)
    .execute(&pool)
    .await?;
    let openai_error: Option<String> =
        sqlx::query_scalar("SELECT last_error_code FROM gateway.openai_account WHERE id=$1")
            .bind(account_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(openai_error.as_deref(), Some("account_forbidden"));

    Ok(())
}
