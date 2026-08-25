//! Production `PostgreSQL` adapters for subscription authentication maintenance.
#![allow(missing_docs, clippy::missing_errors_doc, clippy::too_many_lines)]

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gateway_domain::{
    AnthropicAccountUuid, AuthKind, CredentialId, EgressBindingId, EgressBindingSnapshot, EgressMode,
    MaintenanceTrigger, ProxyEndpointId, SecretBytes, SecretId, SecretValue,
};
use gateway_storage::{
    AuthCandidateRecord, AuthCasPrecondition, MaintenanceFailureUpdate, MaintenanceOperationCreate, PgStorage,
    StorageError,
};
use http::Uri;
use serde_json::Value;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    credential::{AuthCandidate, AuthCommit, AuthMaintenanceRepository, AuthOperationSnapshot, CredentialServiceError},
    credential_provider::{
        OAuthRefreshMaterial, ProviderEndpointProfile, ProviderRequestEncoding, RefreshMaterialPort,
    },
    security::{EnvelopeAad, EnvelopeService, LocalAesKeyProvider, SecretEnvelope},
};

#[derive(Debug)]
pub struct PgAuthMaintenanceRepository {
    storage: Arc<PgStorage>,
    poll_interval: Duration,
}

impl PgAuthMaintenanceRepository {
    #[must_use]
    pub fn new(storage: Arc<PgStorage>, poll_interval: Duration) -> Arc<Self> {
        Arc::new(Self {
            storage,
            poll_interval: poll_interval.max(Duration::from_millis(10)),
        })
    }
}

#[derive(Debug)]
pub struct PgRefreshMaterialPort {
    storage: Arc<PgStorage>,
}

impl PgRefreshMaterialPort {
    #[must_use]
    pub fn new(storage: Arc<PgStorage>) -> Arc<Self> {
        Arc::new(Self { storage })
    }
}

#[async_trait]
impl AuthMaintenanceRepository for PgAuthMaintenanceRepository {
    async fn begin_or_join(
        &self,
        credential_id: &CredentialId,
        trigger: MaintenanceTrigger,
    ) -> Result<AuthOperationSnapshot, CredentialServiceError> {
        let credential_uuid = parse_typed_uuid(credential_id.as_str())?;
        let row = sqlx::query(
            "SELECT c.account_uuid,c.auth_kind_code,c.revision,c.token_version,c.provider_profile_id, \
                    b.id AS binding_id,b.mode_code,b.proxy_id,b.egress_epoch \
             FROM gateway.anthropic_credential c \
             JOIN gateway.credential_egress_binding b ON b.credential_id=c.id AND b.lifecycle_code='active' \
             WHERE c.id=$1 AND c.lifecycle_state_code NOT IN ('revoked','archived')",
        )
        .bind(credential_uuid)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(map_sqlx)?
        .ok_or(CredentialServiceError::WaitingEgress)?;
        let expected_revision: i64 = row.try_get("revision").map_err(map_sqlx)?;
        let expected_token_version: i64 = row.try_get("token_version").map_err(map_sqlx)?;
        let provider_profile_id: Option<Uuid> = row.try_get("provider_profile_id").map_err(map_sqlx)?;
        let provider_profile_id = provider_profile_id.ok_or(CredentialServiceError::EvidencePending)?;
        let binding_id: Uuid = row.try_get("binding_id").map_err(map_sqlx)?;
        let egress_epoch: i64 = row.try_get("egress_epoch").map_err(map_sqlx)?;

        let resumed = sqlx::query(
            "UPDATE gateway.maintenance_operation o SET state_code='planned', \
                    operation_generation=operation_generation+1,retry_after=NULL,error_category_code=NULL, \
                    heartbeat_at=clock_timestamp(),updated_at=clock_timestamp() \
             WHERE o.credential_id=$1 AND o.conflict_class_code='auth_material_write' \
               AND ((o.state_code='waiting_backoff' AND o.retry_after<=clock_timestamp()) \
                    OR (o.state_code='waiting_egress' AND o.egress_binding_id=$2 AND o.egress_epoch_snapshot=$3)) \
             RETURNING o.id,o.operation_generation",
        )
        .bind(credential_uuid)
        .bind(binding_id)
        .bind(egress_epoch)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(map_sqlx)?;
        let (operation_id, operation_generation, joined_existing) = if let Some(resumed) = resumed {
            (
                resumed.try_get("id").map_err(map_sqlx)?,
                resumed.try_get("operation_generation").map_err(map_sqlx)?,
                false,
            )
        } else {
            let created = self
                .storage
                .create_or_join_maintenance_operation(&MaintenanceOperationCreate {
                    operation_id: Uuid::now_v7(),
                    credential_id: credential_uuid,
                    kind: "refresh".to_owned(),
                    trigger: maintenance_trigger_code(trigger).to_owned(),
                    conflict_class: "auth_material_write".to_owned(),
                    expected_revision,
                    expected_token_version,
                    egress_binding_id: binding_id,
                    egress_epoch,
                    adapter_code: Some("subscription_oauth_refresh".to_owned()),
                    adapter_version: None,
                    provider_profile_id: Some(provider_profile_id),
                })
                .await
                .map_err(map_storage)?;
            (created.operation_id, created.generation, created.joined_existing)
        };
        let operation = sqlx::query(
            "SELECT o.expected_credential_revision,o.expected_token_version,o.egress_binding_id, \
                    o.egress_epoch_snapshot,o.provider_profile_id,o.operation_generation, \
                    c.account_uuid,c.auth_kind_code,c.revision,c.token_version, \
                    b.mode_code,b.proxy_id,b.egress_epoch \
             FROM gateway.maintenance_operation o \
             JOIN gateway.anthropic_credential c ON c.id=o.credential_id \
             JOIN gateway.credential_egress_binding b ON b.id=o.egress_binding_id AND b.credential_id=c.id \
             WHERE o.id=$1 AND o.credential_id=$2",
        )
        .bind(operation_id)
        .bind(credential_uuid)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(map_sqlx)?
        .ok_or(CredentialServiceError::Conflict)?;
        if operation
            .try_get::<i64, _>("expected_credential_revision")
            .map_err(map_sqlx)?
            != operation.try_get::<i64, _>("revision").map_err(map_sqlx)?
            || operation
                .try_get::<i64, _>("expected_token_version")
                .map_err(map_sqlx)?
                != operation.try_get::<i64, _>("token_version").map_err(map_sqlx)?
            || operation.try_get::<i64, _>("egress_epoch_snapshot").map_err(map_sqlx)?
                != operation.try_get::<i64, _>("egress_epoch").map_err(map_sqlx)?
            || operation
                .try_get::<Option<Uuid>, _>("provider_profile_id")
                .map_err(map_sqlx)?
                != Some(provider_profile_id)
        {
            return Err(CredentialServiceError::Conflict);
        }
        let auth_kind = parse_auth_kind(&operation.try_get::<String, _>("auth_kind_code").map_err(map_sqlx)?)?;
        let account_uuid = operation
            .try_get::<Option<Uuid>, _>("account_uuid")
            .map_err(map_sqlx)?
            .map(AnthropicAccountUuid::new);
        let egress = egress_snapshot(
            operation.try_get("egress_binding_id").map_err(map_sqlx)?,
            &operation.try_get::<String, _>("mode_code").map_err(map_sqlx)?,
            operation.try_get("proxy_id").map_err(map_sqlx)?,
            operation.try_get("egress_epoch_snapshot").map_err(map_sqlx)?,
        )?;
        Ok(AuthOperationSnapshot {
            credential_id: credential_id.clone(),
            account_uuid,
            auth_kind,
            credential_revision: u64_from_i64(expected_revision)?,
            token_version: u64_from_i64(expected_token_version)?,
            egress,
            operation_id: operation_id.to_string().into_boxed_str(),
            operation_generation: u64_from_i64(operation_generation)?,
            joined_existing,
        })
    }

    async fn await_persisted_operation(
        &self,
        operation: &AuthOperationSnapshot,
    ) -> Result<AuthCommit, CredentialServiceError> {
        let operation_id = parse_typed_uuid(&operation.operation_id)?;
        let credential_id = parse_typed_uuid(operation.credential_id.as_str())?;
        loop {
            let row = sqlx::query(
                "SELECT state_code,outcome_code,error_category_code,result_summary,retry_after \
                 FROM gateway.maintenance_operation WHERE id=$1 AND credential_id=$2",
            )
            .bind(operation_id)
            .bind(credential_id)
            .fetch_optional(&self.storage.pool())
            .await
            .map_err(map_sqlx)?
            .ok_or(CredentialServiceError::Conflict)?;
            let state: String = row.try_get("state_code").map_err(map_sqlx)?;
            match state.as_str() {
                "succeeded" => {
                    let result: Value = row.try_get("result_summary").map_err(map_sqlx)?;
                    return Ok(AuthCommit {
                        token_version: json_u64(&result, "token_version")?,
                        credential_revision: json_u64(&result, "credential_revision")?,
                    });
                }
                "failed" | "cancelled" | "expired" => {
                    return Err(map_persisted_failure(
                        row.try_get::<Option<String>, _>("error_category_code")
                            .map_err(map_sqlx)?
                            .as_deref(),
                    ));
                }
                "waiting_egress" => return Err(CredentialServiceError::WaitingEgress),
                "waiting_backoff" => {
                    let seconds: Option<i64> = sqlx::query_scalar(
                        "SELECT GREATEST(0,CEIL(EXTRACT(EPOCH FROM retry_after-clock_timestamp())))::bigint \
                         FROM gateway.maintenance_operation WHERE id=$1",
                    )
                    .bind(operation_id)
                    .fetch_optional(&self.storage.pool())
                    .await
                    .map_err(map_sqlx)?
                    .flatten();
                    return Err(CredentialServiceError::RateLimited(Duration::from_secs(
                        u64::try_from(seconds.unwrap_or(1)).unwrap_or(1),
                    )));
                }
                "needs_attention" => return Err(CredentialServiceError::EvidencePending),
                _ => tokio::time::sleep(self.poll_interval).await,
            }
        }
    }

    async fn commit_candidate(
        &self,
        operation: &AuthOperationSnapshot,
        candidate: &AuthCandidate,
    ) -> Result<AuthCommit, CredentialServiceError> {
        let credential_id = parse_typed_uuid(operation.credential_id.as_str())?;
        let expires_at_epoch_seconds = candidate.expires_after.map(|duration| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            i64::try_from(now.saturating_add(duration.as_secs())).unwrap_or(i64::MAX)
        });
        let committed = self
            .storage
            .commit_auth_candidate(
                &AuthCandidateRecord {
                    auth_version_id: Uuid::now_v7(),
                    credential_id,
                    auth_kind: operation.auth_kind,
                    access_secret_id: candidate
                        .access_secret_id
                        .as_ref()
                        .map(|id| parse_typed_uuid(id.as_str()))
                        .transpose()?,
                    refresh_secret_id: candidate
                        .refresh_secret_id
                        .as_ref()
                        .map(|id| parse_typed_uuid(id.as_str()))
                        .transpose()?,
                    console_secret_id: candidate
                        .console_secret_id
                        .as_ref()
                        .map(|id| parse_typed_uuid(id.as_str()))
                        .transpose()?,
                    verified_account_uuid: candidate.verified_account_uuid.map(AnthropicAccountUuid::get),
                    expires_at_epoch_seconds,
                    adapter_code: Some(candidate.adapter_code.to_string()),
                    adapter_version: Some(candidate.adapter_version.to_string()),
                },
                &AuthCasPrecondition {
                    expected_credential_revision: i64_from_u64(operation.credential_revision)?,
                    expected_token_version: i64_from_u64(operation.token_version)?,
                    expected_account_uuid: operation.account_uuid.map(AnthropicAccountUuid::get),
                    expected_egress_binding_id: parse_typed_uuid(operation.egress.binding_id.as_str())?,
                    expected_egress_epoch: i64_from_u64(operation.egress.egress_epoch)?,
                    operation_id: parse_typed_uuid(&operation.operation_id)?,
                    operation_generation: i64_from_u64(operation.operation_generation)?,
                    durable_job_fence: None,
                },
            )
            .await
            .map_err(map_storage)?;
        Ok(AuthCommit {
            token_version: u64_from_i64(committed.token_version)?,
            credential_revision: u64_from_i64(committed.credential_revision)?,
        })
    }

    async fn mark_failure(
        &self,
        operation: &AuthOperationSnapshot,
        error: &CredentialServiceError,
    ) -> Result<(), CredentialServiceError> {
        let (state, outcome, category, retry_after, auth_state, block_scheduling) = match error {
            CredentialServiceError::WaitingEgress => (
                "waiting_egress",
                "waiting_egress",
                "egress_unavailable",
                None,
                Some("reauth_waiting_egress"),
                false,
            ),
            CredentialServiceError::RateLimited(delay) => (
                "waiting_backoff",
                "rate_limited",
                "rate_limited",
                Some(delay.as_secs().min(900)),
                Some("reauth_retrying"),
                false,
            ),
            CredentialServiceError::Transient => (
                "waiting_backoff",
                "transient",
                "transient",
                Some(5),
                Some("reauth_retrying"),
                false,
            ),
            CredentialServiceError::InvalidAuthentication => (
                "failed",
                "invalid_authentication",
                "invalid_authentication",
                None,
                Some("manual_recovery_required"),
                true,
            ),
            CredentialServiceError::AccountMismatch => (
                "failed",
                "account_mismatch",
                "account_mismatch",
                None,
                Some("manual_recovery_required"),
                true,
            ),
            CredentialServiceError::ManualRecoveryRequired(_) => (
                "needs_attention",
                "manual_recovery_required",
                "challenge",
                None,
                Some("manual_recovery_required"),
                true,
            ),
            CredentialServiceError::EvidencePending => (
                "needs_attention",
                "evidence_pending",
                "evidence_pending",
                None,
                None,
                false,
            ),
            CredentialServiceError::Conflict => ("failed", "cas_conflict", "conflict", None, None, false),
            CredentialServiceError::WorkerTimeout => (
                "failed",
                "worker_timeout",
                "worker_timeout",
                None,
                Some("reauth_retrying"),
                false,
            ),
        };
        self.storage
            .fail_auth_maintenance(&MaintenanceFailureUpdate {
                credential_id: parse_typed_uuid(operation.credential_id.as_str())?,
                operation_id: parse_typed_uuid(&operation.operation_id)?,
                operation_generation: i64_from_u64(operation.operation_generation)?,
                state: state.to_owned(),
                outcome: outcome.to_owned(),
                error_category: category.to_owned(),
                retry_after_seconds: retry_after.map(|seconds| i64::try_from(seconds).unwrap_or(900)),
                credential_auth_state: auth_state.map(str::to_owned),
                block_scheduling,
            })
            .await
            .map_err(map_storage)
    }
}

#[async_trait]
impl RefreshMaterialPort for PgRefreshMaterialPort {
    async fn load(&self, operation: &AuthOperationSnapshot) -> Result<OAuthRefreshMaterial, CredentialServiceError> {
        let operation_id = parse_typed_uuid(&operation.operation_id)?;
        let credential_id = parse_typed_uuid(operation.credential_id.as_str())?;
        let generation = i64_from_u64(operation.operation_generation)?;
        let mut transaction = self.storage.pool().begin().await.map_err(map_sqlx)?;
        sqlx::query(
            "UPDATE gateway.maintenance_operation SET state_code='leased',heartbeat_at=clock_timestamp(), \
             updated_at=clock_timestamp() WHERE id=$1 AND credential_id=$2 AND operation_generation=$3 AND state_code='planned'",
        )
        .bind(operation_id)
        .bind(credential_id)
        .bind(generation)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let changed = sqlx::query(
            "UPDATE gateway.maintenance_operation SET state_code='running',started_at=COALESCE(started_at,clock_timestamp()), \
             heartbeat_at=clock_timestamp(),updated_at=clock_timestamp() \
             WHERE id=$1 AND credential_id=$2 AND operation_generation=$3 AND state_code IN ('leased','running')",
        )
        .bind(operation_id)
        .bind(credential_id)
        .bind(generation)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if changed.rows_affected() != 1 {
            return Err(CredentialServiceError::Conflict);
        }
        let row = sqlx::query(
            "SELECT p.profile_code,p.profile_version,p.token_endpoint,p.client_id,p.scopes,p.request_encoding_code,p.max_response_bytes, \
                    p.response_schema_code,s.id AS secret_id,s.secret_kind_code,s.provider_role_code,s.cipher_suite_code, \
                    s.ciphertext,s.nonce,s.wrapped_dek,s.key_version,s.aad_schema_version,s.owner_type_code,s.owner_id,s.purpose_code \
             FROM gateway.maintenance_operation o \
             JOIN gateway.anthropic_credential c ON c.id=o.credential_id \
             JOIN gateway.credential_auth_version av ON av.id=c.active_auth_version_id \
             JOIN security.encrypted_secret s ON s.id=av.refresh_secret_id \
             JOIN gateway.credential_provider_profile p ON p.id=o.provider_profile_id \
             WHERE o.id=$1 AND o.credential_id=$2 AND o.operation_generation=$3 AND o.state_code='running' \
               AND c.revision=o.expected_credential_revision AND c.token_version=o.expected_token_version \
               AND av.token_version=o.expected_token_version AND av.material_state_code='active' \
               AND av.verified_account_uuid IS NOT DISTINCT FROM c.account_uuid \
               AND c.auth_kind_code IN ('oauth_subscription','setup_token_subscription') \
               AND s.secret_kind_code='oauth_refresh_token' AND s.provider_role_code='business' \
               AND s.owner_type_code='credential' AND s.owner_id=c.id::text AND s.purpose_code='anthropic_auth' \
               AND s.superseded_at IS NULL AND s.destroyed_at IS NULL \
               AND p.lifecycle_code='active' AND p.auth_kind_codes ? c.auth_kind_code",
        )
        .bind(operation_id)
        .bind(credential_id)
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(CredentialServiceError::EvidencePending)?;
        if row.try_get::<String, _>("response_schema_code").map_err(map_sqlx)? != "oauth_token_v1" {
            return Err(CredentialServiceError::EvidencePending);
        }
        transaction.commit().await.map_err(map_sqlx)?;
        let key_version: i64 = row.try_get("key_version").map_err(map_sqlx)?;
        let root_key = self
            .storage
            .load_database_business_key(key_version)
            .await
            .map_err(map_storage)?;
        let aad = EnvelopeAad {
            schema_version: u32::try_from(row.try_get::<i32, _>("aad_schema_version").map_err(map_sqlx)?)
                .map_err(|_| CredentialServiceError::InvalidAuthentication)?,
            secret_id: row.try_get("secret_id").map_err(map_sqlx)?,
            secret_kind: row.try_get("secret_kind_code").map_err(map_sqlx)?,
            provider_role: row.try_get("provider_role_code").map_err(map_sqlx)?,
            owner_type: row.try_get("owner_type_code").map_err(map_sqlx)?,
            owner_id: row.try_get("owner_id").map_err(map_sqlx)?,
            purpose: row.try_get("purpose_code").map_err(map_sqlx)?,
            key_version: u64_from_i64(key_version)?,
        };
        let envelope = SecretEnvelope {
            schema_version: aad.schema_version,
            cipher_suite: row.try_get("cipher_suite_code").map_err(map_sqlx)?,
            provider_role: aad.provider_role.clone(),
            key_version: aad.key_version,
            ciphertext_base64: STANDARD.encode(row.try_get::<Vec<u8>, _>("ciphertext").map_err(map_sqlx)?),
            nonce_base64: STANDARD.encode(row.try_get::<Vec<u8>, _>("nonce").map_err(map_sqlx)?),
            wrapped_dek_base64: STANDARD.encode(row.try_get::<Vec<u8>, _>("wrapped_dek").map_err(map_sqlx)?),
        };
        let provider = LocalAesKeyProvider::new("business", aad.key_version, root_key.expose().to_vec())
            .map_err(|_| CredentialServiceError::InvalidAuthentication)?;
        let refresh_token = EnvelopeService::new(provider)
            .decrypt(&envelope, &aad)
            .map_err(|_| CredentialServiceError::InvalidAuthentication)?;
        let scopes_value: Value = row.try_get("scopes").map_err(map_sqlx)?;
        let scopes = parse_scopes(&scopes_value)?;
        let token_endpoint = row
            .try_get::<String, _>("token_endpoint")
            .map_err(map_sqlx)?
            .parse::<Uri>()
            .map_err(|_| CredentialServiceError::EvidencePending)?;
        Ok(OAuthRefreshMaterial {
            profile: ProviderEndpointProfile {
                profile_code: row
                    .try_get::<String, _>("profile_code")
                    .map_err(map_sqlx)?
                    .into_boxed_str(),
                version: u64_from_i64(row.try_get("profile_version").map_err(map_sqlx)?)?,
                token_endpoint,
                client_id: row
                    .try_get::<String, _>("client_id")
                    .map_err(map_sqlx)?
                    .into_boxed_str(),
                scopes,
                request_encoding: match row
                    .try_get::<String, _>("request_encoding_code")
                    .map_err(map_sqlx)?
                    .as_str()
                {
                    "application_json" => ProviderRequestEncoding::ApplicationJson,
                    "form_urlencoded" => ProviderRequestEncoding::FormUrlencoded,
                    _ => return Err(CredentialServiceError::EvidencePending),
                },
                max_response_bytes: usize::try_from(row.try_get::<i32, _>("max_response_bytes").map_err(map_sqlx)?)
                    .map_err(|_| CredentialServiceError::EvidencePending)?,
            },
            refresh_token,
        })
    }

    async fn stage_candidate(
        &self,
        operation: &AuthOperationSnapshot,
        access_token: SecretValue,
        refresh_token: SecretValue,
        expires_after: Option<Duration>,
        adapter_version: &str,
    ) -> Result<AuthCandidate, CredentialServiceError> {
        let operation_id = parse_typed_uuid(&operation.operation_id)?;
        let credential_id = parse_typed_uuid(operation.credential_id.as_str())?;
        let generation = i64_from_u64(operation.operation_generation)?;
        let candidate_token_version = operation
            .token_version
            .checked_add(1)
            .ok_or(CredentialServiceError::Conflict)?;
        let key_version: i64 = sqlx::query_scalar(
            "SELECT key_version FROM security.business_key_material WHERE provider_code='database' AND state_code='active'",
        )
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(map_sqlx)?
        .ok_or(CredentialServiceError::EvidencePending)?;
        let root_key = self
            .storage
            .load_database_business_key(key_version)
            .await
            .map_err(map_storage)?;
        let access_id = Uuid::now_v7();
        let refresh_id = Uuid::now_v7();
        let provider = LocalAesKeyProvider::new("business", u64_from_i64(key_version)?, root_key.expose().to_vec())
            .map_err(|_| CredentialServiceError::EvidencePending)?;
        let envelope_service = EnvelopeService::new(provider);
        let access_aad = credential_secret_aad(access_id, credential_id, "oauth_access_token", key_version)?;
        let refresh_aad = credential_secret_aad(refresh_id, credential_id, "oauth_refresh_token", key_version)?;
        let access_envelope = envelope_service
            .encrypt(
                &SecretBytes::new(access_token.expose().as_bytes().to_vec()),
                access_aad.clone(),
            )
            .map_err(|_| CredentialServiceError::Transient)?;
        let refresh_envelope = envelope_service
            .encrypt(
                &SecretBytes::new(refresh_token.expose().as_bytes().to_vec()),
                refresh_aad.clone(),
            )
            .map_err(|_| CredentialServiceError::Transient)?;
        let mut transaction = self.storage.pool().begin().await.map_err(map_sqlx)?;
        let locked = sqlx::query(
            "SELECT 1 FROM gateway.maintenance_operation WHERE id=$1 AND credential_id=$2 \
             AND operation_generation=$3 AND state_code='running' FOR UPDATE",
        )
        .bind(operation_id)
        .bind(credential_id)
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if locked.is_none() {
            return Err(CredentialServiceError::Conflict);
        }
        insert_secret(&mut transaction, &access_aad, &access_envelope).await?;
        insert_secret(&mut transaction, &refresh_aad, &refresh_envelope).await?;
        sqlx::query(
            "INSERT INTO gateway.credential_auth_secret_stage \
             (operation_id,operation_generation,credential_id,candidate_token_version,access_secret_id,refresh_secret_id) \
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(operation_id)
        .bind(generation)
        .bind(credential_id)
        .bind(i64_from_u64(candidate_token_version)?)
        .bind(access_id)
        .bind(refresh_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        sqlx::query(
            "UPDATE gateway.maintenance_operation SET state_code='verifying_account',adapter_version=$4, \
             heartbeat_at=clock_timestamp(),updated_at=clock_timestamp() \
             WHERE id=$1 AND credential_id=$2 AND operation_generation=$3 AND state_code='running'",
        )
        .bind(operation_id)
        .bind(credential_id)
        .bind(generation)
        .bind(adapter_version)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(AuthCandidate {
            access_secret_id: Some(typed_secret_id(access_id)?),
            refresh_secret_id: Some(typed_secret_id(refresh_id)?),
            console_secret_id: None,
            verified_account_uuid: operation.account_uuid,
            expires_after,
            adapter_code: "subscription_oauth_refresh".into(),
            adapter_version: adapter_version.to_owned().into_boxed_str(),
        })
    }
}

async fn insert_secret(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    aad: &EnvelopeAad,
    envelope: &SecretEnvelope,
) -> Result<(), CredentialServiceError> {
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext_base64)
        .map_err(|_| CredentialServiceError::Transient)?;
    let nonce = STANDARD
        .decode(&envelope.nonce_base64)
        .map_err(|_| CredentialServiceError::Transient)?;
    let wrapped_dek = STANDARD
        .decode(&envelope.wrapped_dek_base64)
        .map_err(|_| CredentialServiceError::Transient)?;
    sqlx::query(
        "INSERT INTO security.encrypted_secret \
         (id,secret_kind_code,provider_role_code,cipher_suite_code,ciphertext,nonce,wrapped_dek,key_version, \
          aad_schema_version,owner_type_code,owner_id,purpose_code,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp())",
    )
    .bind(aad.secret_id)
    .bind(&aad.secret_kind)
    .bind(&aad.provider_role)
    .bind(&envelope.cipher_suite)
    .bind(ciphertext)
    .bind(nonce)
    .bind(wrapped_dek)
    .bind(i64_from_u64(envelope.key_version)?)
    .bind(i32::try_from(envelope.schema_version).map_err(|_| CredentialServiceError::Transient)?)
    .bind(&aad.owner_type)
    .bind(&aad.owner_id)
    .bind(&aad.purpose)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

fn credential_secret_aad(
    secret_id: Uuid,
    credential_id: Uuid,
    secret_kind: &str,
    key_version: i64,
) -> Result<EnvelopeAad, CredentialServiceError> {
    Ok(EnvelopeAad {
        schema_version: 1,
        secret_id,
        secret_kind: secret_kind.to_owned(),
        provider_role: "business".to_owned(),
        owner_type: "credential".to_owned(),
        owner_id: credential_id.to_string(),
        purpose: "anthropic_auth".to_owned(),
        key_version: u64_from_i64(key_version)?,
    })
}

fn egress_snapshot(
    binding_id: Uuid,
    mode: &str,
    proxy_id: Option<Uuid>,
    egress_epoch: i64,
) -> Result<EgressBindingSnapshot, CredentialServiceError> {
    let mode = match mode {
        "direct" => EgressMode::Direct,
        "proxy" => EgressMode::Proxy,
        _ => return Err(CredentialServiceError::WaitingEgress),
    };
    if (mode == EgressMode::Direct) != proxy_id.is_none() {
        return Err(CredentialServiceError::WaitingEgress);
    }
    Ok(EgressBindingSnapshot {
        binding_id: EgressBindingId::new(binding_id.to_string()).map_err(|_| CredentialServiceError::Conflict)?,
        mode,
        proxy_id: proxy_id
            .map(|id| ProxyEndpointId::new(id.to_string()).map_err(|_| CredentialServiceError::Conflict))
            .transpose()?,
        egress_epoch: u64_from_i64(egress_epoch)?,
    })
}

fn parse_scopes(value: &Value) -> Result<Vec<Box<str>>, CredentialServiceError> {
    value
        .as_array()
        .ok_or(CredentialServiceError::EvidencePending)?
        .iter()
        .map(|scope| {
            scope
                .as_str()
                .filter(|scope| !scope.trim().is_empty())
                .map(|scope| scope.to_owned().into_boxed_str())
                .ok_or(CredentialServiceError::EvidencePending)
        })
        .collect()
}

fn parse_auth_kind(value: &str) -> Result<AuthKind, CredentialServiceError> {
    match value {
        "oauth_subscription" => Ok(AuthKind::OauthSubscription),
        "setup_token_subscription" => Ok(AuthKind::SetupTokenSubscription),
        "console_api_key" => Ok(AuthKind::ConsoleApiKey),
        _ => Err(CredentialServiceError::InvalidAuthentication),
    }
}

const fn maintenance_trigger_code(value: MaintenanceTrigger) -> &'static str {
    match value {
        MaintenanceTrigger::Enrollment => "enrollment",
        MaintenanceTrigger::Scheduled => "scheduled",
        MaintenanceTrigger::ExpiryGuard => "expiry_guard",
        MaintenanceTrigger::Upstream401 => "upstream_401",
        MaintenanceTrigger::Admin => "admin",
        MaintenanceTrigger::ManualRecovery => "manual_recovery",
        MaintenanceTrigger::StrategyHealth => "strategy_health",
    }
}

fn map_persisted_failure(category: Option<&str>) -> CredentialServiceError {
    match category {
        Some("invalid_authentication") => CredentialServiceError::InvalidAuthentication,
        Some("account_mismatch") => CredentialServiceError::AccountMismatch,
        Some("evidence_pending") => CredentialServiceError::EvidencePending,
        Some("worker_timeout") => CredentialServiceError::WorkerTimeout,
        Some("egress_unavailable") => CredentialServiceError::WaitingEgress,
        Some("conflict") => CredentialServiceError::Conflict,
        _ => CredentialServiceError::Transient,
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "used directly as a Result::map_err function"
)]
fn map_storage(error: StorageError) -> CredentialServiceError {
    match error {
        StorageError::RevisionConflict | StorageError::AccountConflict => CredentialServiceError::Conflict,
        StorageError::AccountMismatch => CredentialServiceError::AccountMismatch,
        StorageError::EgressUnavailable => CredentialServiceError::WaitingEgress,
        StorageError::IntegrityViolation => CredentialServiceError::InvalidAuthentication,
        _ => CredentialServiceError::Transient,
    }
}

fn map_sqlx(_error: sqlx::Error) -> CredentialServiceError {
    CredentialServiceError::Transient
}

fn parse_typed_uuid(value: &str) -> Result<Uuid, CredentialServiceError> {
    Uuid::parse_str(value).map_err(|_| CredentialServiceError::Conflict)
}

fn typed_secret_id(value: Uuid) -> Result<SecretId, CredentialServiceError> {
    SecretId::new(value.to_string()).map_err(|_| CredentialServiceError::Conflict)
}

fn i64_from_u64(value: u64) -> Result<i64, CredentialServiceError> {
    i64::try_from(value).map_err(|_| CredentialServiceError::Conflict)
}

fn u64_from_i64(value: i64) -> Result<u64, CredentialServiceError> {
    u64::try_from(value).map_err(|_| CredentialServiceError::Conflict)
}

fn json_u64(value: &Value, key: &str) -> Result<u64, CredentialServiceError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(CredentialServiceError::Conflict)
}

#[cfg(test)]
mod tests {
    use gateway_domain::MaintenanceTrigger;

    use super::{maintenance_trigger_code, parse_scopes};

    #[test]
    fn trigger_codes_and_scope_parser_are_closed() {
        assert_eq!(
            maintenance_trigger_code(MaintenanceTrigger::Upstream401),
            "upstream_401"
        );
        assert!(parse_scopes(&serde_json::json!(["scope:a", "scope:b"])).is_ok());
        assert!(parse_scopes(&serde_json::json!([""])).is_err());
        assert!(parse_scopes(&serde_json::json!({})).is_err());
    }
}
