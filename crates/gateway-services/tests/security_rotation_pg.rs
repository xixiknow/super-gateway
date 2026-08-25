#![forbid(unsafe_code)]
//! Real `PostgreSQL` proof that DEK rewrap preserves payload ciphertext and plaintext.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use gateway_domain::{SecretBytes, SecretValue};
use gateway_services::security::{
    EnvelopeAad, EnvelopeService, LocalAesKeyProvider, SecretEnvelope, rewrap_database_business_batch,
};
use gateway_storage::{PgStorage, RuntimeRolePolicy};
use sqlx::Row as _;
use uuid::Uuid;

#[tokio::test]
async fn database_key_rotation_rewraps_dek_without_reencrypting_payload() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = std::env::var("TEST_ROTATION_DATABASE_ADMIN_URL") else {
        return Ok(());
    };
    let database_url = SecretValue::new(database_url);
    PgStorage::migrate(&database_url).await?;
    let storage = PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?;
    storage.ensure_database_business_key().await?;
    let old_root = storage.load_database_business_key(1).await?;
    let old_service = EnvelopeService::new(LocalAesKeyProvider::new("business", 1, old_root.expose().to_vec())?);
    let secret_id = Uuid::now_v7();
    let mut aad = EnvelopeAad {
        schema_version: 1,
        secret_id,
        secret_kind: "oauth_refresh_token".to_owned(),
        provider_role: "business".to_owned(),
        owner_type: "credential".to_owned(),
        owner_id: "rotation-fixture".to_owned(),
        purpose: "anthropic_auth".to_owned(),
        key_version: 0,
    };
    let envelope = old_service.encrypt(&SecretBytes::new(b"rotation-secret-canary".to_vec()), aad.clone())?;
    let original_ciphertext = BASE64.decode(&envelope.ciphertext_base64)?;
    sqlx::query(
        "INSERT INTO security.encrypted_secret \
         (id,secret_kind_code,provider_role_code,cipher_suite_code,ciphertext,nonce,wrapped_dek,key_version, \
          aad_schema_version,owner_type_code,owner_id,purpose_code,created_at) \
         VALUES ($1,'oauth_refresh_token','business','aes_256_gcm',$2,$3,$4,1,1,'credential','rotation-fixture','anthropic_auth',clock_timestamp())",
    )
    .bind(secret_id)
    .bind(&original_ciphertext)
    .bind(BASE64.decode(&envelope.nonce_base64)?)
    .bind(BASE64.decode(&envelope.wrapped_dek_base64)?)
    .execute(&storage.pool())
    .await?;

    assert_eq!(storage.rotate_database_business_key().await?, 2);
    let (old_state, old_retired): (String, bool) =
        sqlx::query_as("SELECT state_code,retired_at IS NULL FROM security.business_key_material WHERE key_version=1")
            .fetch_one(&storage.pool())
            .await?;
    assert_eq!(old_state, "decrypt_only");
    assert!(old_retired);
    let report = rewrap_database_business_batch(&storage, 1, 2, None, 100).await?;
    assert_eq!(report.rewrapped, 1);
    assert!(report.complete);
    let row = sqlx::query("SELECT ciphertext,nonce,wrapped_dek,key_version FROM security.encrypted_secret WHERE id=$1")
        .bind(secret_id)
        .fetch_one(&storage.pool())
        .await?;
    let stored_ciphertext: Vec<u8> = row.try_get("ciphertext")?;
    assert_eq!(stored_ciphertext, original_ciphertext);
    let new_root = storage.load_database_business_key(2).await?;
    let new_service = EnvelopeService::new(LocalAesKeyProvider::new("business", 2, new_root.expose().to_vec())?);
    aad.key_version = 2;
    let rotated = SecretEnvelope {
        schema_version: 1,
        cipher_suite: "aes_256_gcm".to_owned(),
        provider_role: "business".to_owned(),
        key_version: 2,
        ciphertext_base64: BASE64.encode(stored_ciphertext),
        nonce_base64: BASE64.encode(row.try_get::<Vec<u8>, _>("nonce")?),
        wrapped_dek_base64: BASE64.encode(row.try_get::<Vec<u8>, _>("wrapped_dek")?),
    };
    assert_eq!(new_service.decrypt(&rotated, &aad)?.expose(), b"rotation-secret-canary");
    assert_eq!(storage.count_live_business_key_references(1).await?, 0);
    Ok(())
}
