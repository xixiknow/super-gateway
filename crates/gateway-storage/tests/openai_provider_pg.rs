//! Disposable-database proof of provider isolation and refresh fencing.

use gateway_domain::SecretValue;
use gateway_storage::{OpenAiRefreshCommit, PgStorage, RuntimeRolePolicy, StorageError};
use uuid::Uuid;

#[tokio::test]
async fn provider_defaults_isolation_and_refresh_cas() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(url) = std::env::var("TEST_OPENAI_DATABASE_URL") else {
        return Ok(());
    };
    let url = SecretValue::new(url);
    PgStorage::migrate(&url).await?;
    let storage = PgStorage::connect(&url, RuntimeRolePolicy::AllowPrivilegedTest).await?;
    storage.ensure_database_business_key().await?;
    let pool = storage.pool();
    let legacy_group = Uuid::now_v7();
    let openai_group = Uuid::now_v7();
    for (id, provider) in [(legacy_group, None), (openai_group, Some("openai"))] {
        sqlx::query("INSERT INTO gateway.credential_group(id,name,status_code,provider_code,created_at,updated_at) VALUES ($1,$2,'active',COALESCE($3,'anthropic'),now(),now())")
            .bind(id).bind(id.to_string()).bind(provider).execute(&pool).await?;
    }
    let provider: String = sqlx::query_scalar("SELECT provider_code FROM gateway.credential_group WHERE id=$1")
        .bind(legacy_group)
        .fetch_one(&pool)
        .await?;
    assert_eq!(provider, "anthropic");
    let enabled: bool = sqlx::query_scalar("SELECT enabled FROM gateway.openai_settings")
        .fetch_one(&pool)
        .await?;
    assert!(!enabled);
    let secret = Uuid::now_v7();
    let refresh = Uuid::now_v7();
    let account = Uuid::now_v7();
    for id in [secret, refresh] {
        sqlx::query("INSERT INTO security.encrypted_secret(id,secret_kind_code,provider_role_code,ciphertext,nonce,wrapped_dek,key_version,aad_schema_version,owner_type_code,owner_id,purpose_code,created_at) SELECT $1,'oauth_access_token','business',decode('01','hex'),decode(repeat('01',12),'hex'),decode('01','hex'),key_version,1,'openai_account',$2,'openai_auth',now() FROM security.business_key_material WHERE state_code='active'")
            .bind(id).bind(account.to_string()).execute(&pool).await?;
    }
    let insert = "INSERT INTO gateway.openai_account(id,group_id,name,auth_kind_code,account_id,access_secret_id,refresh_secret_id,auth_state_code) VALUES ($1,$2,'fixture','oauth',$3,$4,$5,'healthy')";
    assert!(
        sqlx::query(insert)
            .bind(account)
            .bind(legacy_group)
            .bind(account.to_string())
            .bind(secret)
            .bind(refresh)
            .execute(&pool)
            .await
            .is_err()
    );
    sqlx::query(insert)
        .bind(account)
        .bind(openai_group)
        .bind(account.to_string())
        .bind(secret)
        .bind(refresh)
        .execute(&pool)
        .await?;
    assert!(
        sqlx::query("UPDATE gateway.openai_account SET enabled=true WHERE id=$1")
            .bind(account)
            .execute(&pool)
            .await
            .is_err()
    );
    storage.claim_openai_refresh(account, 1).await?;
    assert!(matches!(
        storage.claim_openai_refresh(account, 1).await,
        Err(StorageError::RevisionConflict)
    ));
    let mut tx = pool.begin().await?;
    let mut commit = OpenAiRefreshCommit {
        account_id: account,
        expected_token_version: 1,
        verified_identity: "wrong".into(),
        access_secret_id: secret,
        refresh_secret_id: None,
        id_token_secret_id: None,
        expires_at: Some(2_000_000_000),
    };
    assert!(matches!(
        storage.commit_openai_refresh_in(&mut tx, &commit).await,
        Err(StorageError::AccountMismatch)
    ));
    tx.rollback().await?;
    commit.verified_identity = account.to_string();
    let mut tx = pool.begin().await?;
    storage.commit_openai_refresh_in(&mut tx, &commit).await?;
    tx.commit().await?;
    let (version, stored_refresh): (i64, Uuid) =
        sqlx::query_as("SELECT token_version,refresh_secret_id FROM gateway.openai_account WHERE id=$1")
            .bind(account)
            .fetch_one(&pool)
            .await?;
    assert_eq!(version, 2);
    assert_eq!(stored_refresh, refresh);
    assert!(matches!(
        storage.fail_openai_refresh(account, 1, true).await,
        Err(StorageError::RevisionConflict)
    ));
    Ok(())
}
