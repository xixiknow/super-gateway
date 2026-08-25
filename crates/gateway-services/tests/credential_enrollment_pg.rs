#![forbid(unsafe_code)]
#![allow(clippy::too_many_lines)]
//! Real `PostgreSQL` vertical proof for Existing OAuth enrollment execution.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gateway_domain::{
    AuthKind, CredentialPurpose, EnrollmentAuthMethod, EnrollmentMode, ManagementClass, SecretBytes, SecretValue,
};
use gateway_services::{
    credential::CredentialServiceError,
    credential_enrollment_postgres::PgCredentialEnrollmentExecutor,
    credential_provider::{ProviderHttpPort, ProviderHttpRequest, ProviderHttpResponse},
    operations::{CredentialEnrollmentJobAttempt, CredentialEnrollmentJobExecutor, JobAttemptDecision},
    security::{EnvelopeAad, EnvelopeService, LocalAesKeyProvider},
};
use gateway_storage::{
    CredentialEnrollmentCreate, EgressAllocationRequest, PgStorage, RuntimeRolePolicy, embedded_migration_count,
};
use sqlx::Row as _;
use uuid::Uuid;

struct FakeProviderHttp {
    requests: Mutex<Vec<ProviderHttpRequest>>,
    account_uuid: Uuid,
    organization_uuid: Uuid,
}

struct FakePkceProviderHttp {
    requests: Mutex<Vec<ProviderHttpRequest>>,
    account_uuid: Uuid,
    organization_uuid: Uuid,
}

struct FakeSetupProviderHttp {
    requests: Mutex<Vec<ProviderHttpRequest>>,
    account_uuid: Uuid,
    organization_uuid: Uuid,
}

#[async_trait]
impl ProviderHttpPort for FakeSetupProviderHttp {
    async fn execute(&self, request: ProviderHttpRequest) -> Result<ProviderHttpResponse, CredentialServiceError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request);
        Ok(ProviderHttpResponse {
            status: 200,
            headers: Vec::new(),
            body: SecretBytes::new(
                serde_json::to_vec(&serde_json::json!({
                    "oauth_account": {
                        "account_uuid": self.account_uuid,
                        "organization_uuid": self.organization_uuid
                    },
                    "narrowed": true
                }))
                .map_err(|_| CredentialServiceError::Transient)?,
            ),
        })
    }
}

#[async_trait]
impl ProviderHttpPort for FakePkceProviderHttp {
    async fn execute(&self, request: ProviderHttpRequest) -> Result<ProviderHttpResponse, CredentialServiceError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request);
        Ok(ProviderHttpResponse {
            status: 200,
            headers: Vec::new(),
            body: SecretBytes::new(
                serde_json::to_vec(&serde_json::json!({
                    "access_token":"pkce-access-fixture",
                    "refresh_token":"pkce-refresh-fixture",
                    "token_type":"Bearer",
                    "expires_in":3600,
                    "account":{"uuid":self.account_uuid},
                    "organization":{"uuid":self.organization_uuid}
                }))
                .map_err(|_| CredentialServiceError::Transient)?,
            ),
        })
    }
}

#[async_trait]
impl ProviderHttpPort for FakeProviderHttp {
    async fn execute(&self, request: ProviderHttpRequest) -> Result<ProviderHttpResponse, CredentialServiceError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request);
        Ok(ProviderHttpResponse {
            status: 200,
            headers: Vec::new(),
            body: SecretBytes::new(
                serde_json::to_vec(&serde_json::json!({
                    "account":{"uuid":self.account_uuid,"email":"fixture@example.invalid"},
                    "organization":{"uuid":self.organization_uuid}
                }))
                .map_err(|_| CredentialServiceError::Transient)?,
            ),
        })
    }
}

#[tokio::test]
async fn existing_oauth_job_verifies_deduplicates_provisions_and_activates() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = std::env::var("TEST_R5_ENROLLMENT_DATABASE_ADMIN_URL") else {
        return Ok(());
    };
    let database_url = SecretValue::new(database_url);
    let migration = PgStorage::migrate(&database_url).await?;
    assert_eq!(migration.applied_count, embedded_migration_count());
    let storage = Arc::new(PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?);
    storage.ensure_database_business_key().await?;
    let group_id = fixture_group(&storage).await?;
    fixture_archetype(&storage).await?;

    let enrollment_id = Uuid::now_v7();
    let credential_id = Uuid::now_v7();
    storage
        .create_credential_enrollment(&CredentialEnrollmentCreate {
            enrollment_id,
            credential_id,
            group_id,
            created_by: None,
            mode: EnrollmentMode::Create,
            auth_method: EnrollmentAuthMethod::ExistingOauth,
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
    let access_secret =
        stage_enrollment_secret(&storage, enrollment_id, "oauth_access_token", b"access-fixture").await?;
    let refresh_secret =
        stage_enrollment_secret(&storage, enrollment_id, "oauth_refresh_token", b"refresh-fixture").await?;
    let changed = sqlx::query(
        "UPDATE gateway.credential_enrollment SET material_secret_refs=$2,state_code='exchanging_material', \
         next_action_code='retry',revision=revision+1,updated_at=clock_timestamp() \
         WHERE id=$1 AND revision=2 AND state_code='awaiting_user_action'",
    )
    .bind(enrollment_id)
    .bind(vec![access_secret, refresh_secret])
    .execute(&storage.pool())
    .await?;
    assert_eq!(changed.rows_affected(), 1);

    let provider = Arc::new(FakeProviderHttp {
        requests: Mutex::new(Vec::new()),
        account_uuid: Uuid::now_v7(),
        organization_uuid: Uuid::now_v7(),
    });
    let executor = PgCredentialEnrollmentExecutor::new(storage.clone(), provider.clone());
    let stale_attempt = lease_enrollment_job(&storage, enrollment_id, credential_id).await?;
    sqlx::query(
        "UPDATE ops.durable_job SET lease_generation=lease_generation+1, \
         lease_expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1",
    )
    .bind(stale_attempt.job_id)
    .execute(&storage.pool())
    .await?;
    assert!(matches!(
        executor.execute(stale_attempt).await,
        JobAttemptDecision::Retry { error_code, .. } if error_code == "enrollment_state_retry"
    ));
    assert!(
        provider
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    );
    let attempt = lease_enrollment_job(&storage, enrollment_id, credential_id).await?;
    assert!(matches!(
        executor.execute(attempt.clone()).await,
        JobAttemptDecision::Succeeded { outcome_code } if outcome_code == "credential_activated"
    ));
    assert!(matches!(
        executor.execute(attempt).await,
        JobAttemptDecision::Succeeded { .. }
    ));

    let row = sqlx::query(
        "SELECT c.lifecycle_state_code,c.scheduling_state_code,c.account_uuid,c.token_version, \
                c.active_auth_version_id,c.provider_profile_id,e.state_code,e.material_secret_refs, \
                EXISTS(SELECT 1 FROM gateway.credential_profile p WHERE p.credential_id=c.id) AS profile_exists, \
                EXISTS(SELECT 1 FROM gateway.device_identity d WHERE d.credential_id=c.id) AS device_exists \
         FROM gateway.anthropic_credential c JOIN gateway.credential_enrollment e ON e.id=$2 WHERE c.id=$1",
    )
    .bind(credential_id)
    .bind(enrollment_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(row.try_get::<String, _>("lifecycle_state_code")?, "active");
    assert_eq!(row.try_get::<String, _>("scheduling_state_code")?, "eligible");
    assert_eq!(row.try_get::<Uuid, _>("account_uuid")?, provider.account_uuid);
    assert_eq!(row.try_get::<i64, _>("token_version")?, 2);
    assert!(row.try_get::<Option<Uuid>, _>("active_auth_version_id")?.is_some());
    assert!(row.try_get::<Option<Uuid>, _>("provider_profile_id")?.is_some());
    assert_eq!(row.try_get::<String, _>("state_code")?, "succeeded");
    assert!(row.try_get::<Vec<Uuid>, _>("material_secret_refs")?.is_empty());
    assert!(row.try_get::<bool, _>("profile_exists")?);
    assert!(row.try_get::<bool, _>("device_exists")?);
    let staged_destroyed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security.encrypted_secret WHERE id=ANY($1) AND destroyed_at IS NOT NULL \
         AND octet_length(ciphertext)=0 AND octet_length(wrapped_dek)=0",
    )
    .bind(vec![access_secret, refresh_secret])
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(staged_destroyed, 2);
    {
        let requests = provider
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].endpoint.to_string(),
            "https://api.anthropic.com/api/oauth/profile"
        );
        assert_eq!(requests[0].egress.egress_epoch, 1);
    }

    let before_recovery = sqlx::query(
        "SELECT c.revision,c.active_auth_version_id,p.id AS profile_id,p.device_identity_id,p.egress_binding_id \
         FROM gateway.anthropic_credential c JOIN gateway.credential_profile p ON p.credential_id=c.id \
         WHERE c.id=$1",
    )
    .bind(credential_id)
    .fetch_one(&storage.pool())
    .await?;
    let original_auth_version: Uuid = before_recovery.try_get("active_auth_version_id")?;
    let original_profile: Uuid = before_recovery.try_get("profile_id")?;
    let original_device: Uuid = before_recovery.try_get("device_identity_id")?;
    let original_egress: Uuid = before_recovery.try_get("egress_binding_id")?;
    let recovery_revision: i64 = sqlx::query_scalar(
        "UPDATE gateway.anthropic_credential SET auth_state_code='manual_recovery_required', \
         scheduling_state_code='blocked',revision=revision+1,updated_at=clock_timestamp() \
         WHERE id=$1 RETURNING revision",
    )
    .bind(credential_id)
    .fetch_one(&storage.pool())
    .await?;
    let recovery_enrollment_id = Uuid::now_v7();
    let recovery = storage
        .create_credential_enrollment(&CredentialEnrollmentCreate {
            enrollment_id: recovery_enrollment_id,
            credential_id,
            group_id,
            created_by: None,
            mode: EnrollmentMode::Recover,
            auth_method: EnrollmentAuthMethod::ExistingOauth,
            auth_kind: AuthKind::OauthSubscription,
            purpose: CredentialPurpose::Business,
            management_class: ManagementClass::NonManaged,
            recovery_credential_id: Some(credential_id),
            expected_credential_revision: Some(recovery_revision),
            expires_in_seconds: 1_800,
            callback_window_seconds: 600,
        })
        .await?;
    assert_eq!(recovery.state, "awaiting_user_action");
    let recovery_access = stage_enrollment_secret(
        &storage,
        recovery_enrollment_id,
        "oauth_access_token",
        b"recovered-access",
    )
    .await?;
    let recovery_refresh = stage_enrollment_secret(
        &storage,
        recovery_enrollment_id,
        "oauth_refresh_token",
        b"recovered-refresh",
    )
    .await?;
    let changed = sqlx::query(
        "UPDATE gateway.credential_enrollment SET material_secret_refs=$2,state_code='exchanging_material', \
         next_action_code='retry',revision=revision+1,updated_at=clock_timestamp() \
         WHERE id=$1 AND revision=1 AND state_code='awaiting_user_action'",
    )
    .bind(recovery_enrollment_id)
    .bind(vec![recovery_access, recovery_refresh])
    .execute(&storage.pool())
    .await?;
    assert_eq!(changed.rows_affected(), 1);
    let recovery_provider = Arc::new(FakeProviderHttp {
        requests: Mutex::new(Vec::new()),
        account_uuid: provider.account_uuid,
        organization_uuid: provider.organization_uuid,
    });
    let recovery_executor = PgCredentialEnrollmentExecutor::new(storage.clone(), recovery_provider.clone());
    let recovery_attempt = lease_enrollment_job(&storage, recovery_enrollment_id, credential_id).await?;
    assert!(matches!(
        recovery_executor.execute(recovery_attempt).await,
        JobAttemptDecision::Succeeded { .. }
    ));
    let after_recovery = sqlx::query(
        "SELECT c.active_auth_version_id,c.token_version,c.auth_state_code,c.scheduling_state_code, \
                p.id AS profile_id,p.device_identity_id,p.egress_binding_id,e.state_code \
         FROM gateway.anthropic_credential c JOIN gateway.credential_profile p ON p.credential_id=c.id \
         JOIN gateway.credential_enrollment e ON e.id=$2 WHERE c.id=$1",
    )
    .bind(credential_id)
    .bind(recovery_enrollment_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_ne!(
        after_recovery.try_get::<Uuid, _>("active_auth_version_id")?,
        original_auth_version
    );
    assert_eq!(after_recovery.try_get::<i64, _>("token_version")?, 3);
    assert_eq!(after_recovery.try_get::<String, _>("auth_state_code")?, "healthy");
    assert_eq!(
        after_recovery.try_get::<String, _>("scheduling_state_code")?,
        "eligible"
    );
    assert_eq!(after_recovery.try_get::<Uuid, _>("profile_id")?, original_profile);
    assert_eq!(
        after_recovery.try_get::<Uuid, _>("device_identity_id")?,
        original_device
    );
    assert_eq!(after_recovery.try_get::<Uuid, _>("egress_binding_id")?, original_egress);
    assert_eq!(after_recovery.try_get::<String, _>("state_code")?, "succeeded");
    Ok(())
}

#[tokio::test]
async fn oauth_pkce_callback_is_exchanged_once_and_resumes_from_encrypted_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = std::env::var("TEST_R5_ENROLLMENT_DATABASE_ADMIN_URL") else {
        return Ok(());
    };
    let database_url = SecretValue::new(database_url);
    PgStorage::migrate(&database_url).await?;
    let storage = Arc::new(PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?);
    storage.ensure_database_business_key().await?;
    let group_id = fixture_group(&storage).await?;
    fixture_archetype(&storage).await?;

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
    let verifier = stage_enrollment_secret(&storage, enrollment_id, "pkce_verifier", b"pkce-verifier-fixture").await?;
    let state_digest = vec![0x31; 32];
    let nonce_digest = vec![0x42; 32];
    assert_eq!(
        storage
            .configure_enrollment_oauth_pkce(
                enrollment_id,
                2,
                "https://fixture.example/authorize",
                "https://platform.claude.com/oauth/code/callback",
                &state_digest,
                &nonce_digest,
                verifier,
            )
            .await?,
        3
    );
    let callback_document = serde_json::to_vec(&serde_json::json!({
        "authorization_code":"authorization-code-fixture",
        "state":"state-fixture"
    }))?;
    let callback =
        stage_enrollment_secret(&storage, enrollment_id, "oauth_callback_material", &callback_document).await?;
    assert_eq!(
        storage
            .claim_oauth_callback(enrollment_id, 3, &state_digest, &nonce_digest, callback)
            .await?,
        4
    );

    let provider = Arc::new(FakePkceProviderHttp {
        requests: Mutex::new(Vec::new()),
        account_uuid: Uuid::now_v7(),
        organization_uuid: Uuid::now_v7(),
    });
    let executor = PgCredentialEnrollmentExecutor::new(storage.clone(), provider.clone());
    let attempt = lease_enrollment_job(&storage, enrollment_id, credential_id).await?;
    assert!(matches!(
        executor.execute(attempt.clone()).await,
        JobAttemptDecision::Succeeded { outcome_code } if outcome_code == "credential_activated"
    ));
    assert!(matches!(
        executor.execute(attempt).await,
        JobAttemptDecision::Succeeded { .. }
    ));
    {
        let requests = provider
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, http::Method::POST);
        assert_eq!(
            requests[0].endpoint.to_string(),
            "https://platform.claude.com/v1/oauth/token"
        );
        let request_document: serde_json::Value = serde_json::from_slice(requests[0].body.expose())?;
        assert_eq!(request_document["code"], "authorization-code-fixture");
        assert_eq!(request_document["state"], "state-fixture");
        assert_eq!(request_document["code_verifier"], "pkce-verifier-fixture");
    }

    let result: (String, String, Uuid, i64) = sqlx::query_as(
        "SELECT e.state_code,c.lifecycle_state_code,c.account_uuid,c.token_version \
         FROM gateway.credential_enrollment e \
         JOIN gateway.anthropic_credential c ON c.id=e.pending_credential_id WHERE e.id=$1",
    )
    .bind(enrollment_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(
        result,
        ("succeeded".to_owned(), "active".to_owned(), provider.account_uuid, 2)
    );
    let temporary_secrets_remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security.encrypted_secret WHERE owner_type_code='credential_enrollment' \
         AND owner_id=$1 AND destroyed_at IS NULL",
    )
    .bind(enrollment_id.to_string())
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(temporary_secrets_remaining, 0);
    Ok(())
}

#[tokio::test]
async fn setup_token_bootstrap_activates_without_refresh_material() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = std::env::var("TEST_R5_ENROLLMENT_DATABASE_ADMIN_URL") else {
        return Ok(());
    };
    let database_url = SecretValue::new(database_url);
    PgStorage::migrate(&database_url).await?;
    let storage = Arc::new(PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?);
    storage.ensure_database_business_key().await?;
    let group_id = fixture_group(&storage).await?;
    fixture_archetype(&storage).await?;

    let enrollment_id = Uuid::now_v7();
    let credential_id = Uuid::now_v7();
    storage
        .create_credential_enrollment(&CredentialEnrollmentCreate {
            enrollment_id,
            credential_id,
            group_id,
            created_by: None,
            mode: EnrollmentMode::Create,
            auth_method: EnrollmentAuthMethod::SetupToken,
            auth_kind: AuthKind::SetupTokenSubscription,
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
    let setup_secret = stage_enrollment_secret(&storage, enrollment_id, "setup_token", b"setup-fixture").await?;
    let changed = sqlx::query(
        "UPDATE gateway.credential_enrollment SET material_secret_refs=$2,state_code='exchanging_material', \
         next_action_code='retry',revision=revision+1,updated_at=clock_timestamp() \
         WHERE id=$1 AND revision=2 AND state_code='awaiting_user_action'",
    )
    .bind(enrollment_id)
    .bind(vec![setup_secret])
    .execute(&storage.pool())
    .await?;
    assert_eq!(changed.rows_affected(), 1);

    let provider = Arc::new(FakeSetupProviderHttp {
        requests: Mutex::new(Vec::new()),
        account_uuid: Uuid::now_v7(),
        organization_uuid: Uuid::now_v7(),
    });
    let executor = PgCredentialEnrollmentExecutor::new(storage.clone(), provider.clone());
    let attempt = lease_enrollment_job(&storage, enrollment_id, credential_id).await?;
    assert!(matches!(
        executor.execute(attempt).await,
        JobAttemptDecision::Succeeded { .. }
    ));
    let row = sqlx::query(
        "SELECT c.lifecycle_state_code,c.management_class_code,c.account_uuid,c.token_version, \
                av.auth_kind_code,av.access_secret_id,av.refresh_secret_id,av.expires_at::text AS expires_at, \
                s.secret_kind_code,e.state_code,e.material_secret_refs \
         FROM gateway.anthropic_credential c \
         JOIN gateway.credential_auth_version av ON av.id=c.active_auth_version_id \
         JOIN security.encrypted_secret s ON s.id=av.access_secret_id \
         JOIN gateway.credential_enrollment e ON e.id=$2 WHERE c.id=$1",
    )
    .bind(credential_id)
    .bind(enrollment_id)
    .fetch_one(&storage.pool())
    .await?;
    assert_eq!(row.try_get::<String, _>("lifecycle_state_code")?, "active");
    assert_eq!(row.try_get::<String, _>("management_class_code")?, "non_managed");
    assert_eq!(row.try_get::<Uuid, _>("account_uuid")?, provider.account_uuid);
    assert_eq!(row.try_get::<i64, _>("token_version")?, 2);
    assert_eq!(row.try_get::<String, _>("auth_kind_code")?, "setup_token_subscription");
    assert!(row.try_get::<Option<Uuid>, _>("access_secret_id")?.is_some());
    assert!(row.try_get::<Option<Uuid>, _>("refresh_secret_id")?.is_none());
    assert!(row.try_get::<Option<String>, _>("expires_at")?.is_none());
    assert_eq!(row.try_get::<String, _>("secret_kind_code")?, "setup_token");
    assert_eq!(row.try_get::<String, _>("state_code")?, "succeeded");
    assert!(row.try_get::<Vec<Uuid>, _>("material_secret_refs")?.is_empty());
    let temporary_secret_destroyed: bool = sqlx::query_scalar(
        "SELECT destroyed_at IS NOT NULL AND octet_length(ciphertext)=0 AND octet_length(wrapped_dek)=0 \
         FROM security.encrypted_secret WHERE id=$1",
    )
    .bind(setup_secret)
    .fetch_one(&storage.pool())
    .await?;
    assert!(temporary_secret_destroyed);
    let requests = provider
        .requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, http::Method::GET);
    assert_eq!(requests[0].endpoint.path(), "/api/claude_cli/bootstrap");
    Ok(())
}

async fn fixture_group(storage: &PgStorage) -> Result<Uuid, Box<dyn std::error::Error>> {
    let group_id = Uuid::now_v7();
    let config_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO gateway.credential_group (id,name,status_code,owner_generation,revision,created_at,updated_at) \
         VALUES ($1,$2,'active',1,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(group_id)
    .bind(format!("r5-enrollment-{group_id}"))
    .execute(&storage.pool())
    .await?;
    sqlx::query(
        "INSERT INTO gateway.group_config \
         (id,group_id,config_version,content_hash,default_rpm,queue_capacity,queue_timeout_ms,system_prompt_mode_code, \
          proxy_policy_code,model_scope_code,lifecycle_code,validation_report,validated_at,published_at,created_at) \
         VALUES ($1,$2,1,$3,60,10,30000,'preserve','direct','all_published','active','{}'::jsonb, \
                 clock_timestamp(),clock_timestamp(),clock_timestamp())",
    )
    .bind(config_id)
    .bind(group_id)
    .bind(Uuid::now_v7().as_bytes().to_vec())
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

async fn lease_enrollment_job(
    storage: &PgStorage,
    enrollment_id: Uuid,
    credential_id: Uuid,
) -> Result<CredentialEnrollmentJobAttempt, Box<dyn std::error::Error>> {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM ops.durable_job WHERE kind_code='credential_enrollment_exchange' \
         AND payload->>'enrollment_id'=$1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(enrollment_id.to_string())
    .fetch_optional(&storage.pool())
    .await?;
    let job_id = existing.unwrap_or_else(Uuid::now_v7);
    let generation: i64 = if existing.is_some() {
        sqlx::query_scalar(
            "UPDATE ops.durable_job SET state_code='leased',lease_owner='credential-enrollment-pg-test', \
             lease_generation=CASE WHEN state_code='leased' THEN lease_generation ELSE lease_generation+1 END, \
             lease_expires_at=clock_timestamp()+interval '1 hour',updated_at=clock_timestamp() \
             WHERE id=$1 RETURNING lease_generation",
        )
        .bind(job_id)
        .fetch_one(&storage.pool())
        .await?
    } else {
        sqlx::query(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_owner, \
              lease_generation,lease_expires_at,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'credential_enrollment_exchange',$2,'leased',1,$3,clock_timestamp(), \
              'credential-enrollment-pg-test',1,clock_timestamp()+interval '1 hour',1,10,clock_timestamp(),clock_timestamp())",
        )
        .bind(job_id)
        .bind(format!("credential-enrollment-pg-test:{enrollment_id}"))
        .bind(serde_json::json!({"enrollment_id":enrollment_id,"credential_id":credential_id}))
        .execute(&storage.pool())
        .await?;
        1
    };
    Ok(CredentialEnrollmentJobAttempt {
        enrollment_id,
        credential_id,
        job_id,
        job_generation: generation,
    })
}

async fn fixture_archetype(storage: &PgStorage) -> Result<(), Box<dyn std::error::Error>> {
    let archetype = Uuid::now_v7();
    let version = Uuid::now_v7();
    let bundle = Uuid::now_v7();
    let artifact_version: i64 =
        sqlx::query_scalar("SELECT COALESCE(max(artifact_version),0)+1 FROM catalog.transport_bundle")
            .fetch_one(&storage.pool())
            .await?;
    sqlx::query(
        "INSERT INTO catalog.environment_archetype \
         (id,name,os_family_code,architecture_code,lifecycle_code,created_at,updated_at,revision) \
         VALUES ($1,$2,'windows','x86_64','active',clock_timestamp(),clock_timestamp(),1)",
    )
    .bind(archetype)
    .bind(format!("r5-enrollment-{archetype}"))
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
         VALUES ($1,$2,'r6-v1','active','{}'::jsonb,$3,$4,'fixture','fixture://bundle',$5,'windows-r5','h1', \
                 'boring-h1','passed','0.1.0',clock_timestamp(),clock_timestamp())",
    )
    .bind(bundle)
    .bind(artifact_version)
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
    Ok(())
}

async fn stage_enrollment_secret(
    storage: &PgStorage,
    enrollment_id: Uuid,
    kind: &str,
    plaintext: &[u8],
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let key_version = 1_u64;
    let root = storage.load_database_business_key(1).await?;
    let service = EnvelopeService::new(LocalAesKeyProvider::new(
        "business",
        key_version,
        root.expose().to_vec(),
    )?);
    let secret_id = Uuid::now_v7();
    let aad = EnvelopeAad {
        schema_version: 1,
        secret_id,
        secret_kind: kind.to_owned(),
        provider_role: "business".to_owned(),
        owner_type: "credential_enrollment".to_owned(),
        owner_id: enrollment_id.to_string(),
        purpose: if kind == "oauth_callback_material" {
            "oauth_callback".to_owned()
        } else {
            "credential_enrollment".to_owned()
        },
        key_version,
    };
    let envelope = service.encrypt(&SecretBytes::new(plaintext.to_vec()), aad.clone())?;
    sqlx::query(
        "INSERT INTO security.encrypted_secret \
         (id,secret_kind_code,provider_role_code,cipher_suite_code,ciphertext,nonce,wrapped_dek,key_version, \
          aad_schema_version,owner_type_code,owner_id,purpose_code,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp())",
    )
    .bind(secret_id)
    .bind(&aad.secret_kind)
    .bind(&aad.provider_role)
    .bind(&envelope.cipher_suite)
    .bind(STANDARD.decode(&envelope.ciphertext_base64)?)
    .bind(STANDARD.decode(&envelope.nonce_base64)?)
    .bind(STANDARD.decode(&envelope.wrapped_dek_base64)?)
    .bind(i64::try_from(key_version)?)
    .bind(i32::try_from(aad.schema_version)?)
    .bind(&aad.owner_type)
    .bind(&aad.owner_id)
    .bind(&aad.purpose)
    .execute(&storage.pool())
    .await?;
    Ok(secret_id)
}
