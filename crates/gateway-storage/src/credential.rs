//! Transactional `PostgreSQL` commands for the frozen R5 Credential lifecycle.
#![allow(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use gateway_domain::{
    AuthKind, CredentialPurpose, EgressPolicy, EnrollmentAuthMethod, EnrollmentMode, ManagementClass,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Transaction};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::{AuditOutboxRecord, PgStorage, StorageError};

const EGRESS_ALLOCATION_LOCK: i64 = 0x4757_4547_5245_5353;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableJobFence {
    pub job_id: Uuid,
    pub generation: i64,
    pub kind: String,
}

#[derive(Clone, Debug)]
pub struct CredentialEnrollmentCreate {
    pub enrollment_id: Uuid,
    pub credential_id: Uuid,
    pub group_id: Uuid,
    pub created_by: Option<Uuid>,
    pub mode: EnrollmentMode,
    pub auth_method: EnrollmentAuthMethod,
    pub auth_kind: AuthKind,
    pub purpose: CredentialPurpose,
    pub management_class: ManagementClass,
    pub recovery_credential_id: Option<Uuid>,
    pub expected_credential_revision: Option<i64>,
    pub expires_in_seconds: i32,
    pub callback_window_seconds: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentRecord {
    pub enrollment_id: Uuid,
    pub credential_id: Uuid,
    pub state: String,
    pub next_action: String,
    pub revision: i64,
}

#[derive(Clone, Debug)]
pub struct EgressAllocationRequest {
    pub enrollment_id: Uuid,
    pub credential_id: Uuid,
    pub binding_id: Uuid,
    pub expected_enrollment_revision: i64,
    pub expected_credential_revision: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressAllocation {
    Direct {
        binding_id: Uuid,
        egress_epoch: i64,
    },
    Proxy {
        binding_id: Uuid,
        proxy_id: Uuid,
        egress_epoch: i64,
    },
    WaitForEgress,
}

#[derive(Clone, Debug)]
pub struct CredentialProfileProvision {
    pub enrollment_id: Uuid,
    pub credential_id: Uuid,
    pub profile_id: Uuid,
    pub device_identity_id: Uuid,
    pub archetype_version_id: Uuid,
    pub installation_secret_id: Uuid,
    pub client_secret_id: Uuid,
    pub profile_seed_secret_id: Uuid,
    pub session_hmac_secret_id: Uuid,
    pub installation_digest: Vec<u8>,
    pub client_digest: Vec<u8>,
    pub capture_cohort: String,
    pub allocation_evidence: Value,
    pub expected_enrollment_revision: i64,
    pub expected_credential_revision: i64,
    pub durable_job_fence: Option<DurableJobFence>,
}

#[derive(Clone, Debug)]
pub struct MaintenanceOperationCreate {
    pub operation_id: Uuid,
    pub credential_id: Uuid,
    pub kind: String,
    pub trigger: String,
    pub conflict_class: String,
    pub expected_revision: i64,
    pub expected_token_version: i64,
    pub egress_binding_id: Uuid,
    pub egress_epoch: i64,
    pub adapter_code: Option<String>,
    pub adapter_version: Option<String>,
    pub provider_profile_id: Option<Uuid>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenanceOperationRecord {
    pub operation_id: Uuid,
    pub state: String,
    pub generation: i64,
    pub joined_existing: bool,
}

#[derive(Clone, Debug)]
pub struct AuthCandidateRecord {
    pub auth_version_id: Uuid,
    pub credential_id: Uuid,
    pub auth_kind: AuthKind,
    pub access_secret_id: Option<Uuid>,
    pub refresh_secret_id: Option<Uuid>,
    pub console_secret_id: Option<Uuid>,
    pub verified_account_uuid: Option<Uuid>,
    pub expires_at_epoch_seconds: Option<i64>,
    pub adapter_code: Option<String>,
    pub adapter_version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuthCasPrecondition {
    pub expected_credential_revision: i64,
    pub expected_token_version: i64,
    pub expected_account_uuid: Option<Uuid>,
    pub expected_egress_binding_id: Uuid,
    pub expected_egress_epoch: i64,
    pub operation_id: Uuid,
    pub operation_generation: i64,
    pub durable_job_fence: Option<DurableJobFence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OAuthCallbackClaim {
    Claimed(i64),
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCandidateCommit {
    pub auth_version_id: Uuid,
    pub token_version: i64,
    pub credential_revision: i64,
}

#[derive(Clone, Debug)]
pub struct MaintenanceFailureUpdate {
    pub credential_id: Uuid,
    pub operation_id: Uuid,
    pub operation_generation: i64,
    pub state: String,
    pub outcome: String,
    pub error_category: String,
    pub retry_after_seconds: Option<i64>,
    pub credential_auth_state: Option<String>,
    pub block_scheduling: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialR5Snapshot {
    pub credential_id: Uuid,
    pub group_id: Uuid,
    pub account_uuid: Option<Uuid>,
    pub lifecycle: String,
    pub attachment: String,
    pub auth: String,
    pub capacity: String,
    pub transport: String,
    pub management_class: String,
    pub token_version: i64,
    pub revision: i64,
    pub profile_epoch: Option<i64>,
    pub device_epoch: Option<i64>,
    pub egress_epoch: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct PlanObservationCommit {
    pub observation_id: Uuid,
    pub credential_id: Uuid,
    pub source: String,
    pub raw_plan_code: Option<String>,
    pub normalized_plan_code: String,
    pub raw_redacted: Value,
    pub raw_digest: Option<Vec<u8>>,
    pub temporary_display_name: Option<String>,
    pub mapping_version: Option<i64>,
    pub mapping_artifact_id: Option<Uuid>,
    pub adapter_version: Option<String>,
    pub success: bool,
    pub failure_category: Option<String>,
    pub failure_summary: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PlanObservationFence {
    pub credential_revision: i64,
    pub token_version: i64,
    pub provider_profile_id: Uuid,
    pub egress_binding_id: Uuid,
    pub egress_epoch: i64,
    pub job_id: Uuid,
    pub job_generation: i64,
}

#[derive(Clone, Debug)]
pub struct PlanMappingArtifactCreate {
    pub artifact_id: Uuid,
    pub artifact_version: i64,
    pub mappings: Value,
    pub content_hash: Vec<u8>,
    pub created_by: Uuid,
}

#[derive(Clone, Debug)]
pub struct PlanMappingActivation {
    pub artifact_id: Uuid,
    pub pointer_id: Uuid,
    pub recompute_job_id: Uuid,
    pub activated_by: Uuid,
    pub expected_pointer_revision: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanMappingActivationCommit {
    pub pointer_revision: i64,
    pub recompute_job_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanMappingRecomputeCommit {
    pub affected_observations: i64,
    pub affected_credentials: i64,
}

#[derive(Clone, Debug)]
pub struct ManagedBrowserStrategyCreate {
    pub strategy_id: Uuid,
    pub credential_id: Uuid,
    pub expected_credential_revision: i64,
    pub browser_provider_code: String,
    pub adapter_version: String,
}

#[derive(Clone, Debug)]
pub struct BrowserMaterialCandidate {
    pub material_version_id: Uuid,
    pub strategy_id: Uuid,
    pub credential_id: Uuid,
    pub material_version: i64,
    pub cookie_secret_id: Uuid,
    pub storage_secret_id: Option<Uuid>,
    pub profile_secret_id: Uuid,
    pub verified_account_uuid: Uuid,
    pub adapter_version: String,
}

#[derive(Clone, Debug)]
pub struct BrowserCasPrecondition {
    pub strategy_revision: i64,
    pub auth: AuthCasPrecondition,
    pub durable_job_id: Option<Uuid>,
    pub durable_job_generation: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserReauthCommit {
    pub auth: AuthCandidateCommit,
    pub material_version: i64,
    pub strategy_revision: i64,
}

#[derive(Clone, Debug)]
pub struct CredentialGroupMigrationBegin {
    pub migration_id: Uuid,
    pub credential_id: Uuid,
    pub source_group_id: Uuid,
    pub target_group_id: Uuid,
    pub expected_credential_revision: i64,
    pub requested_by: Uuid,
    pub drain_seconds: i32,
}

#[derive(Clone, Debug)]
pub struct ProfileCohortUpgrade {
    pub change_id: Uuid,
    pub credential_id: Uuid,
    pub target_archetype_version_id: Uuid,
    pub target_capture_cohort: String,
    pub reason_code: String,
    pub approved_by: Uuid,
    pub expected_credential_revision: i64,
    pub expected_profile_epoch: i64,
    pub allow_explicit_rollback: bool,
}

#[derive(Clone, Debug)]
pub struct DeviceIdentityRebuild {
    pub change_id: Uuid,
    pub credential_id: Uuid,
    pub installation_secret_id: Uuid,
    pub client_secret_id: Uuid,
    pub profile_seed_secret_id: Uuid,
    pub session_hmac_secret_id: Uuid,
    pub installation_digest: Vec<u8>,
    pub client_digest: Vec<u8>,
    pub requested_by: Uuid,
    pub approved_by: Uuid,
    pub reason_code: String,
    pub expected_credential_revision: i64,
    pub expected_profile_epoch: i64,
    pub expected_device_epoch: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileContinuityCommit {
    pub credential_revision: i64,
    pub profile_epoch: i64,
    pub device_epoch: i64,
    pub egress_epoch: i64,
}

#[derive(Clone, Debug)]
pub struct CredentialLifecycleCommand {
    pub credential_id: Uuid,
    pub expected_revision: i64,
    pub actor_id: Uuid,
    pub reason_code: String,
}

impl PgStorage {
    pub async fn configure_enrollment_oauth_pkce(
        &self,
        enrollment_id: Uuid,
        expected_revision: i64,
        authorization_uri: &str,
        callback_uri: &str,
        state_digest: &[u8],
        callback_nonce_digest: &[u8],
        verifier_secret_id: Uuid,
    ) -> Result<i64, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let revision = self
            .configure_enrollment_oauth_pkce_in(
                &mut transaction,
                enrollment_id,
                expected_revision,
                authorization_uri,
                callback_uri,
                state_digest,
                callback_nonce_digest,
                verifier_secret_id,
            )
            .await?;
        transaction.commit().await.map_err(transaction_error)?;
        Ok(revision)
    }

    pub async fn configure_enrollment_oauth_pkce_in(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        enrollment_id: Uuid,
        expected_revision: i64,
        authorization_uri: &str,
        callback_uri: &str,
        state_digest: &[u8],
        callback_nonce_digest: &[u8],
        verifier_secret_id: Uuid,
    ) -> Result<i64, StorageError> {
        if authorization_uri.is_empty()
            || callback_uri.is_empty()
            || state_digest.len() != 32
            || callback_nonce_digest.len() != 32
        {
            return Err(StorageError::TransactionFailed);
        }
        let revision: Option<i64> = sqlx::query_scalar(
            "UPDATE gateway.credential_enrollment SET authorization_uri=$3,callback_uri=$4,pkce_state_digest=$5, \
             callback_nonce_digest=$6,pkce_verifier_secret_id=$7,next_action_code='open_authorization_url', \
             revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND auth_method_code='oauth_pkce' AND state_code='awaiting_user_action' \
               AND callback_consumed_at IS NULL AND expires_at>clock_timestamp() \
               AND EXISTS (SELECT 1 FROM security.encrypted_secret s WHERE s.id=$7 \
                 AND s.owner_type_code='credential_enrollment' AND s.owner_id=$1::text \
                 AND s.secret_kind_code='pkce_verifier' AND s.purpose_code='credential_enrollment' \
                 AND s.destroyed_at IS NULL AND s.superseded_at IS NULL) RETURNING revision",
        )
        .bind(enrollment_id)
        .bind(expected_revision)
        .bind(authorization_uri)
        .bind(callback_uri)
        .bind(state_digest)
        .bind(callback_nonce_digest)
        .bind(verifier_secret_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(transaction_error)?;
        revision.ok_or(StorageError::RevisionConflict)
    }

    pub async fn claim_oauth_callback(
        &self,
        enrollment_id: Uuid,
        expected_revision: i64,
        state_digest: &[u8],
        callback_nonce_digest: &[u8],
        callback_material_secret_id: Uuid,
    ) -> Result<i64, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let outcome = self
            .claim_oauth_callback_in(
                &mut transaction,
                enrollment_id,
                expected_revision,
                state_digest,
                callback_nonce_digest,
                callback_material_secret_id,
            )
            .await?;
        transaction.commit().await.map_err(transaction_error)?;
        match outcome {
            OAuthCallbackClaim::Claimed(revision) => Ok(revision),
            OAuthCallbackClaim::Rejected => Err(StorageError::InvalidLifecycle),
        }
    }

    pub async fn claim_oauth_callback_in(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        enrollment_id: Uuid,
        expected_revision: i64,
        state_digest: &[u8],
        callback_nonce_digest: &[u8],
        callback_material_secret_id: Uuid,
    ) -> Result<OAuthCallbackClaim, StorageError> {
        if state_digest.len() != 32 || callback_nonce_digest.len() != 32 {
            return Err(StorageError::InvalidLifecycle);
        }
        let row = sqlx::query(
            "SELECT e.revision,e.state_code,e.pkce_state_digest,e.callback_nonce_digest, \
                    (e.callback_consumed_at IS NOT NULL) AS consumed, \
                    (e.callback_expires_at>clock_timestamp() AND e.expires_at>clock_timestamp()) AS within_window, \
                    e.pkce_verifier_secret_id,e.pending_credential_id,c.revision AS credential_revision, \
                    EXISTS (SELECT 1 FROM security.encrypted_secret s WHERE s.id=$2 \
                      AND s.owner_type_code='credential_enrollment' AND s.owner_id=e.id::text \
                      AND s.secret_kind_code='oauth_callback_material' AND s.purpose_code='oauth_callback' \
                      AND s.destroyed_at IS NULL AND s.superseded_at IS NULL) AS callback_secret_valid \
             FROM gateway.credential_enrollment e JOIN gateway.anthropic_credential c ON c.id=e.pending_credential_id \
             WHERE e.id=$1 FOR UPDATE OF e",
        )
        .bind(enrollment_id)
        .bind(callback_material_secret_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let credential_id: Uuid = row.try_get("pending_credential_id").map_err(transaction_error)?;
        let credential_revision: i64 = row.try_get("credential_revision").map_err(transaction_error)?;
        let revision: i64 = row.try_get("revision").map_err(transaction_error)?;
        let state: String = row.try_get("state_code").map_err(transaction_error)?;
        let stored_state: Option<Vec<u8>> = row.try_get("pkce_state_digest").map_err(transaction_error)?;
        let stored_nonce: Option<Vec<u8>> = row.try_get("callback_nonce_digest").map_err(transaction_error)?;
        let consumed: bool = row.try_get("consumed").map_err(transaction_error)?;
        let within_window: bool = row.try_get("within_window").map_err(transaction_error)?;
        let callback_secret_valid: bool = row.try_get("callback_secret_valid").map_err(transaction_error)?;
        if revision != expected_revision {
            return Err(StorageError::RevisionConflict);
        }
        if !callback_secret_valid {
            return Err(StorageError::InvalidLifecycle);
        }
        let digest_matches = |stored: Option<&[u8]>, submitted: &[u8]| {
            stored.is_some_and(|value| value.len() == submitted.len() && bool::from(value.ct_eq(submitted)))
        };
        let valid = state == "awaiting_user_action"
            && !consumed
            && within_window
            && digest_matches(stored_state.as_deref(), state_digest)
            && digest_matches(stored_nonce.as_deref(), callback_nonce_digest);
        if !valid {
            if state == "awaiting_user_action" && !consumed {
                sqlx::query(
                    "UPDATE gateway.credential_enrollment SET state_code='failed',next_action_code='none', \
                     error_code='oauth_callback_binding_invalid',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
                )
                .bind(enrollment_id)
                .execute(&mut **transaction)
                .await
                .map_err(transaction_error)?;
                let mut rejected_secret_ids = vec![callback_material_secret_id];
                if let Some(verifier_secret_id) = row
                    .try_get::<Option<Uuid>, _>("pkce_verifier_secret_id")
                    .map_err(transaction_error)?
                {
                    rejected_secret_ids.push(verifier_secret_id);
                }
                destroy_secret_ids(transaction, &rejected_secret_ids).await?;
                append_credential_event(
                    transaction,
                    credential_id,
                    Some(enrollment_id),
                    None,
                    "oauth_callback_rejected",
                    credential_revision,
                    json!({"reason": "binding_or_expiry"}),
                )
                .await?;
            } else {
                destroy_secret_ids(transaction, &[callback_material_secret_id]).await?;
                append_credential_event(
                    transaction,
                    credential_id,
                    Some(enrollment_id),
                    None,
                    "oauth_callback_replay_rejected",
                    credential_revision,
                    json!({"reason": "already_claimed_or_state_changed"}),
                )
                .await?;
            }
            return Ok(OAuthCallbackClaim::Rejected);
        }
        let next_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.credential_enrollment SET state_code='exchanging_material',next_action_code='retry', \
             callback_claimed_at=clock_timestamp(),callback_consumed_at=clock_timestamp(), \
             material_secret_refs=array_append(material_secret_refs,$2),operation_checkpoint_code='callback_claimed', \
             revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
        )
        .bind(enrollment_id)
        .bind(callback_material_secret_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            transaction,
            credential_id,
            Some(enrollment_id),
            None,
            "oauth_callback_claimed",
            credential_revision,
            json!({"enrollment_revision": next_revision}),
        )
        .await?;
        sqlx::query(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'credential_enrollment_exchange',$2,'scheduled',1,$3,clock_timestamp(),0,0,10, \
                     clock_timestamp(),clock_timestamp()) \
             ON CONFLICT (kind_code,idempotency_key) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(format!("enrollment:{enrollment_id}:callback:{next_revision}"))
        .bind(json!({"enrollment_id":enrollment_id,"credential_id":credential_id,"material_count":1}))
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
        Ok(OAuthCallbackClaim::Claimed(next_revision))
    }

    pub async fn advance_credential_enrollment(
        &self,
        enrollment_id: Uuid,
        expected_revision: i64,
        from_state: &str,
        to_state: &str,
        next_action: &str,
    ) -> Result<i64, StorageError> {
        if !valid_enrollment_transition(from_state, to_state)
            || (matches!(to_state, "succeeded" | "failed" | "cancelled" | "expired") && next_action != "none")
        {
            return Err(StorageError::InvalidLifecycle);
        }
        let row = sqlx::query(
            "UPDATE gateway.credential_enrollment SET state_code=$4,next_action_code=$5,revision=revision+1, \
             updated_at=clock_timestamp() WHERE id=$1 AND revision=$2 AND state_code=$3 \
             AND expires_at>clock_timestamp() RETURNING revision",
        )
        .bind(enrollment_id)
        .bind(expected_revision)
        .bind(from_state)
        .bind(to_state)
        .bind(next_action)
        .fetch_optional(&self.pool)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::RevisionConflict)?;
        row.try_get("revision").map_err(transaction_error)
    }

    pub async fn fail_credential_enrollment(
        &self,
        enrollment_id: Uuid,
        expected_revision: i64,
        error_code: &str,
    ) -> Result<(), StorageError> {
        self.terminalize_credential_enrollment(enrollment_id, expected_revision, "failed", error_code, None)
            .await
    }

    pub async fn fail_credential_enrollment_for_job(
        &self,
        enrollment_id: Uuid,
        expected_revision: i64,
        error_code: &str,
        fence: &DurableJobFence,
    ) -> Result<(), StorageError> {
        self.terminalize_credential_enrollment(enrollment_id, expected_revision, "failed", error_code, Some(fence))
            .await
    }

    pub async fn cancel_credential_enrollment(
        &self,
        enrollment_id: Uuid,
        expected_revision: i64,
    ) -> Result<(), StorageError> {
        self.terminalize_credential_enrollment(
            enrollment_id,
            expected_revision,
            "cancelled",
            "cancelled_by_admin",
            None,
        )
        .await
    }

    pub async fn expire_credential_enrollments(&self, limit: i64) -> Result<u64, StorageError> {
        if !(1..=1_000).contains(&limit) {
            return Err(StorageError::InvalidLifecycle);
        }
        let rows = sqlx::query(
            "SELECT id,revision FROM gateway.credential_enrollment \
             WHERE expires_at<=clock_timestamp() AND state_code NOT IN ('succeeded','failed','cancelled','expired') \
             ORDER BY expires_at,id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(transaction_error)?;
        let mut expired = 0_u64;
        for row in rows {
            let enrollment_id: Uuid = row.try_get("id").map_err(transaction_error)?;
            let revision: i64 = row.try_get("revision").map_err(transaction_error)?;
            match self
                .terminalize_credential_enrollment(enrollment_id, revision, "expired", "enrollment_expired", None)
                .await
            {
                Ok(()) => expired = expired.saturating_add(1),
                Err(StorageError::RevisionConflict | StorageError::InvalidLifecycle) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(expired)
    }

    async fn terminalize_credential_enrollment(
        &self,
        enrollment_id: Uuid,
        expected_revision: i64,
        terminal_state: &str,
        error_code: &str,
        durable_job_fence: Option<&DurableJobFence>,
    ) -> Result<(), StorageError> {
        if error_code.is_empty()
            || error_code.len() > 128
            || !error_code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || !matches!(terminal_state, "failed" | "cancelled" | "expired")
        {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        require_durable_job_fence(&mut transaction, durable_job_fence).await?;
        let row = sqlx::query(
            "SELECT e.revision,e.kind_code,e.state_code,e.pending_credential_id,e.material_secret_refs, \
                    e.pkce_verifier_secret_id,c.revision AS credential_revision \
             FROM gateway.credential_enrollment e \
             LEFT JOIN gateway.anthropic_credential c ON c.id=e.pending_credential_id \
             WHERE e.id=$1 FOR UPDATE OF e,c",
        )
        .bind(enrollment_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let revision: i64 = row.try_get("revision").map_err(transaction_error)?;
        let state: String = row.try_get("state_code").map_err(transaction_error)?;
        if revision != expected_revision || matches!(state.as_str(), "succeeded" | "failed" | "cancelled" | "expired") {
            return Err(StorageError::RevisionConflict);
        }
        let credential_id: Option<Uuid> = row.try_get("pending_credential_id").map_err(transaction_error)?;
        let mode: String = row.try_get("kind_code").map_err(transaction_error)?;
        let mut secret_ids = row
            .try_get::<Vec<Uuid>, _>("material_secret_refs")
            .map_err(transaction_error)?;
        if let Some(secret_id) = row
            .try_get::<Option<Uuid>, _>("pkce_verifier_secret_id")
            .map_err(transaction_error)?
        {
            secret_ids.push(secret_id);
        }
        destroy_secret_ids(&mut transaction, &secret_ids).await?;
        if let Some(credential_id) = credential_id {
            append_credential_event(
                &mut transaction,
                credential_id,
                Some(enrollment_id),
                None,
                match terminal_state {
                    "failed" => "enrollment_failed",
                    "cancelled" => "enrollment_cancelled",
                    "expired" => "enrollment_expired",
                    _ => return Err(StorageError::InvalidLifecycle),
                },
                row.try_get::<Option<i64>, _>("credential_revision")
                    .map_err(transaction_error)?
                    .unwrap_or(1),
                json!({"error_code": error_code}),
            )
            .await?;
        }
        if mode == "create"
            && let Some(credential_id) = credential_id
        {
            cleanup_pending_credential(
                &mut transaction,
                enrollment_id,
                credential_id,
                terminal_state,
                error_code,
            )
            .await?;
        } else {
            sqlx::query(
                "UPDATE gateway.credential_enrollment SET state_code=$3,next_action_code='none',error_code=$2, \
                  material_secret_refs='{}',pkce_verifier_secret_id=NULL,revision=revision+1,updated_at=clock_timestamp() \
                  WHERE id=$1",
            )
            .bind(enrollment_id)
            .bind(error_code)
            .bind(terminal_state)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        }
        sqlx::query(
            "UPDATE ops.durable_job SET state_code='cancelled',lease_owner=NULL,lease_expires_at=NULL, \
             completed_at=clock_timestamp(),updated_at=clock_timestamp(),last_error_code=$2 \
             WHERE kind_code='credential_enrollment_exchange' AND payload->>'enrollment_id'=$1 \
               AND state_code IN ('scheduled','retry_wait','leased')",
        )
        .bind(enrollment_id.to_string())
        .bind(error_code)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)
    }

    pub async fn create_credential_enrollment(
        &self,
        command: &CredentialEnrollmentCreate,
    ) -> Result<EnrollmentRecord, StorageError> {
        if command.expires_in_seconds < 1
            || command.callback_window_seconds < 1
            || command.callback_window_seconds > command.expires_in_seconds
        {
            return Err(StorageError::TransactionFailed);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let group_defaults = sqlx::query(
            "SELECT config.default_credential_concurrency,config.default_credential_rpm \
             FROM gateway.credential_group g \
             JOIN gateway.group_active_config active ON active.group_id=g.id \
             JOIN gateway.group_config config ON config.id=active.config_id \
             WHERE g.id=$1 AND g.status_code='active' AND config.lifecycle_code='active'",
        )
        .bind(command.group_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let default_credential_concurrency: i32 = group_defaults
            .try_get("default_credential_concurrency")
            .map_err(transaction_error)?;
        let default_credential_rpm: i32 = group_defaults
            .try_get("default_credential_rpm")
            .map_err(transaction_error)?;

        let provider_profile_id = if matches!(command.auth_kind, AuthKind::ConsoleApiKey) {
            None
        } else {
            let profiles = sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM gateway.credential_provider_profile \
                 WHERE lifecycle_code='active' AND auth_kind_codes ? $1 ORDER BY profile_code,id LIMIT 2",
            )
            .bind(auth_kind_code(command.auth_kind))
            .fetch_all(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            if profiles.len() != 1 {
                return Err(StorageError::InvalidLifecycle);
            }
            profiles.into_iter().next()
        };

        let (credential_id, initial_state, initial_action, egress_binding_id, egress_epoch, event_revision) =
            match command.mode {
                EnrollmentMode::Create => {
                    sqlx::query(
                    "INSERT INTO gateway.anthropic_credential \
                     (id,group_id,purpose_code,auth_kind_code,lifecycle_state_code,attachment_state_code,auth_state_code, \
                      capacity_state_code,scheduling_state_code,quota_state_code,transport_state_code,management_class_code, \
                      provider_profile_id,token_version,revision,created_at,updated_at) \
                     VALUES ($1,$2,$3,$4,'pending_egress','attached','needs_admin_reauth','available','blocked','unknown', \
                             'transport_unavailable',$5,$6,1,1,clock_timestamp(),clock_timestamp())",
                )
                .bind(command.credential_id)
                .bind(command.group_id)
                .bind(purpose_code(command.purpose))
                .bind(auth_kind_code(command.auth_kind))
                .bind(management_class_code(command.management_class))
                .bind(provider_profile_id)
                .execute(&mut *transaction)
                .await
                .map_err(transaction_error)?;
                    let scheduling_config_id = Uuid::now_v7();
                    let scheduling_document = json!({
                        "enabled": true,
                        "max_concurrency": default_credential_concurrency,
                        "max_active_sessions": null,
                        "new_session_wait_ms": 5000,
                        "priority_layer": 100,
                        "rpm_burst": 10,
                        "rpm_limit": default_credential_rpm,
                        "session_capacity_enabled": false,
                        "session_idle_ttl_ms": 1_800_000,
                        "weight_scaled": 1000
                    });
                    let scheduling_hash = Sha256::digest(canonical_json_bytes(&scheduling_document)?).to_vec();
                    sqlx::query(
                        "INSERT INTO gateway.credential_scheduling_config \
                         (id,credential_id,config_version,max_concurrency,rpm_limit,rpm_burst,priority_layer,weight, \
                          enabled,session_capacity_enabled,max_active_sessions,session_idle_ttl_ms,new_session_wait_ms, \
                          content_hash,created_at) \
                         VALUES ($1,$2,1,$3,$4,10,100,1,true,false,NULL,1800000,5000,$5,clock_timestamp())",
                    )
                    .bind(scheduling_config_id)
                    .bind(command.credential_id)
                    .bind(default_credential_concurrency)
                    .bind(default_credential_rpm)
                    .bind(scheduling_hash)
                    .execute(&mut *transaction)
                    .await
                    .map_err(transaction_error)?;
                    sqlx::query(
                        "INSERT INTO gateway.credential_active_scheduling_config \
                         (credential_id,config_id,revision,activated_at) VALUES ($1,$2,1,clock_timestamp())",
                    )
                    .bind(command.credential_id)
                    .bind(scheduling_config_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(transaction_error)?;
                    (command.credential_id, "created", "retry", None::<Uuid>, None::<i64>, 1)
                }
                EnrollmentMode::Recover => {
                    let recovery_id = command.recovery_credential_id.ok_or(StorageError::InvalidLifecycle)?;
                    let expected_revision = command
                        .expected_credential_revision
                        .ok_or(StorageError::RevisionConflict)?;
                    let row = sqlx::query(
                        "SELECT c.revision,c.auth_state_code,c.group_id,c.auth_kind_code,c.provider_profile_id, \
                            b.id AS egress_binding_id,b.egress_epoch \
                     FROM gateway.anthropic_credential c \
                     JOIN gateway.credential_profile p ON p.credential_id=c.id AND p.lifecycle_code='active' \
                     JOIN gateway.device_identity d ON d.credential_id=c.id AND d.id=p.device_identity_id \
                     JOIN gateway.credential_egress_binding b ON b.id=p.egress_binding_id \
                       AND b.credential_id=c.id AND b.lifecycle_code='active' AND b.stability_code='stable' \
                     WHERE c.id=$1 FOR UPDATE OF c,p,d,b",
                    )
                    .bind(recovery_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(transaction_error)?
                    .ok_or(StorageError::InvalidLifecycle)?;
                    let revision: i64 = row.try_get("revision").map_err(transaction_error)?;
                    let auth_state: String = row.try_get("auth_state_code").map_err(transaction_error)?;
                    let group_id: Uuid = row.try_get("group_id").map_err(transaction_error)?;
                    let recovery_auth_kind: String = row.try_get("auth_kind_code").map_err(transaction_error)?;
                    let recovery_provider_profile_id: Option<Uuid> =
                        row.try_get("provider_profile_id").map_err(transaction_error)?;
                    if revision != expected_revision
                        || auth_state != "manual_recovery_required"
                        || group_id != command.group_id
                        || recovery_auth_kind != auth_kind_code(command.auth_kind)
                        || recovery_provider_profile_id != provider_profile_id
                    {
                        return Err(StorageError::InvalidLifecycle);
                    }
                    (
                        recovery_id,
                        "awaiting_user_action",
                        next_action_for_auth_method(enrollment_auth_method_code(command.auth_method)),
                        Some(row.try_get::<Uuid, _>("egress_binding_id").map_err(transaction_error)?),
                        Some(row.try_get::<i64, _>("egress_epoch").map_err(transaction_error)?),
                        revision,
                    )
                }
            };

        sqlx::query(
            "INSERT INTO gateway.credential_enrollment \
             (id,kind_code,state_code,next_action_code,requested_group_id,recover_credential_id, \
               expected_credential_revision,auth_method_code,pending_credential_id,egress_binding_id,egress_epoch, \
               attempt_count,expires_at,callback_expires_at,revision,created_by,provider_profile_id,created_at,updated_at) \
              VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0, \
                      clock_timestamp()+($12*interval '1 second'), \
                      clock_timestamp()+($13*interval '1 second'),1,$14,$15,clock_timestamp(),clock_timestamp())",
        )
        .bind(command.enrollment_id)
        .bind(enrollment_mode_code(command.mode))
        .bind(initial_state)
        .bind(initial_action)
        .bind(command.group_id)
        .bind(command.recovery_credential_id)
        .bind(command.expected_credential_revision)
        .bind(enrollment_auth_method_code(command.auth_method))
        .bind(credential_id)
        .bind(egress_binding_id)
        .bind(egress_epoch)
        .bind(command.expires_in_seconds)
        .bind(command.callback_window_seconds)
        .bind(command.created_by)
        .bind(provider_profile_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            credential_id,
            Some(command.enrollment_id),
            None,
            "enrollment_created",
            event_revision,
            json!({"mode": enrollment_mode_code(command.mode), "auth_method": enrollment_auth_method_code(command.auth_method)}),
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)?;
        Ok(EnrollmentRecord {
            enrollment_id: command.enrollment_id,
            credential_id,
            state: initial_state.to_owned(),
            next_action: initial_action.to_owned(),
            revision: 1,
        })
    }

    pub async fn allocate_enrollment_egress(
        &self,
        command: &EgressAllocationRequest,
    ) -> Result<EgressAllocation, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(EGRESS_ALLOCATION_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        let row = sqlx::query(
            "SELECT e.revision AS enrollment_revision,e.auth_method_code,e.requested_group_id,c.revision AS credential_revision \
             FROM gateway.credential_enrollment e JOIN gateway.anthropic_credential c ON c.id=e.pending_credential_id \
             WHERE e.id=$1 AND c.id=$2 AND e.state_code IN ('created','resolving_egress') \
               AND e.expires_at>clock_timestamp() FOR UPDATE OF e,c",
        )
        .bind(command.enrollment_id)
        .bind(command.credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let enrollment_revision: i64 = row.try_get("enrollment_revision").map_err(transaction_error)?;
        let credential_revision: i64 = row.try_get("credential_revision").map_err(transaction_error)?;
        if enrollment_revision != command.expected_enrollment_revision
            || credential_revision != command.expected_credential_revision
        {
            return Err(StorageError::RevisionConflict);
        }
        let auth_method: String = row.try_get("auth_method_code").map_err(transaction_error)?;
        let group_id: Uuid = row.try_get("requested_group_id").map_err(transaction_error)?;
        let policy: String = sqlx::query_scalar(
            "SELECT COALESCE((SELECT config.proxy_policy_code FROM gateway.group_active_config active \
                              JOIN gateway.group_config config ON config.id=active.config_id \
                              WHERE active.group_id=$1),'auto')",
        )
        .bind(group_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;

        let proxy = if policy == "direct" {
            None
        } else {
            sqlx::query(
                "SELECT proxy.id FROM gateway.proxy_endpoint proxy \
                 WHERE proxy.lifecycle_code='active' AND proxy.health_code='healthy' \
                   AND proxy.stability_code='static' \
                   AND (SELECT count(*) FROM gateway.credential_egress_binding binding \
                        WHERE binding.proxy_id=proxy.id AND binding.lifecycle_code IN ('pending','active','transport_unavailable','rebinding')) \
                       < proxy.max_active_bindings \
                 ORDER BY ((SELECT count(*) FROM gateway.credential_egress_binding binding \
                            WHERE binding.proxy_id=proxy.id AND binding.lifecycle_code IN ('pending','active','transport_unavailable','rebinding'))::numeric \
                           / proxy.max_active_bindings::numeric),proxy.id LIMIT 1 FOR UPDATE OF proxy",
            )
            .fetch_optional(&mut *transaction)
            .await
            .map_err(transaction_error)?
        };
        if proxy.is_none() && policy == "proxy_required" {
            sqlx::query(
                "UPDATE gateway.credential_enrollment SET state_code='resolving_egress',next_action_code='wait_for_egress', \
                 revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(command.enrollment_id)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            transaction.commit().await.map_err(transaction_error)?;
            return Ok(EgressAllocation::WaitForEgress);
        }
        let proxy_id = proxy
            .as_ref()
            .map(|candidate| candidate.try_get("id"))
            .transpose()
            .map_err(transaction_error)?;
        let mode = if proxy_id.is_some() { "proxy" } else { "direct" };
        sqlx::query(
            "INSERT INTO gateway.credential_egress_binding \
             (id,credential_id,mode_code,proxy_id,stability_code,lifecycle_code,egress_epoch,revision,created_at,updated_at) \
             VALUES ($1,$2,$3,$4,'stable','active',1,1,clock_timestamp(),clock_timestamp())",
        )
        .bind(command.binding_id)
        .bind(command.credential_id)
        .bind(mode)
        .bind(proxy_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_capacity_error)?;
        let next_action = next_action_for_auth_method(&auth_method);
        sqlx::query(
            "UPDATE gateway.credential_enrollment SET state_code='awaiting_user_action',next_action_code=$2, \
             egress_binding_id=$3,egress_epoch=1,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(command.enrollment_id)
        .bind(next_action)
        .bind(command.binding_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.anthropic_credential SET lifecycle_state_code='pending_verify',revision=revision+1, \
             updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(command.credential_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            command.credential_id,
            Some(command.enrollment_id),
            None,
            "egress_reserved",
            credential_revision + 1,
            json!({"binding_id": command.binding_id, "mode": mode, "egress_epoch": 1}),
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)?;
        Ok(match proxy_id {
            Some(proxy_id) => EgressAllocation::Proxy {
                binding_id: command.binding_id,
                proxy_id,
                egress_epoch: 1,
            },
            None => EgressAllocation::Direct {
                binding_id: command.binding_id,
                egress_epoch: 1,
            },
        })
    }

    pub async fn claim_verified_account(
        &self,
        enrollment_id: Uuid,
        credential_id: Uuid,
        account_uuid: Uuid,
        expected_enrollment_revision: i64,
        expected_credential_revision: i64,
    ) -> Result<(), StorageError> {
        self.claim_verified_account_inner(
            enrollment_id,
            credential_id,
            account_uuid,
            expected_enrollment_revision,
            expected_credential_revision,
            None,
        )
        .await
    }

    pub async fn claim_verified_account_for_job(
        &self,
        enrollment_id: Uuid,
        credential_id: Uuid,
        account_uuid: Uuid,
        expected_enrollment_revision: i64,
        expected_credential_revision: i64,
        fence: &DurableJobFence,
    ) -> Result<(), StorageError> {
        self.claim_verified_account_inner(
            enrollment_id,
            credential_id,
            account_uuid,
            expected_enrollment_revision,
            expected_credential_revision,
            Some(fence),
        )
        .await
    }

    async fn claim_verified_account_inner(
        &self,
        enrollment_id: Uuid,
        credential_id: Uuid,
        account_uuid: Uuid,
        expected_enrollment_revision: i64,
        expected_credential_revision: i64,
        durable_job_fence: Option<&DurableJobFence>,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        require_durable_job_fence(&mut transaction, durable_job_fence).await?;
        let row = sqlx::query(
            "SELECT e.kind_code,e.recover_credential_id,e.revision AS enrollment_revision,e.state_code, \
                    c.revision AS credential_revision,c.account_uuid,c.auth_state_code \
             FROM gateway.credential_enrollment e JOIN gateway.anthropic_credential c ON c.id=e.pending_credential_id \
             WHERE e.id=$1 AND c.id=$2 AND e.expires_at>clock_timestamp() FOR UPDATE OF e,c",
        )
        .bind(enrollment_id)
        .bind(credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let enrollment_revision: i64 = row.try_get("enrollment_revision").map_err(transaction_error)?;
        let credential_revision: i64 = row.try_get("credential_revision").map_err(transaction_error)?;
        let state: String = row.try_get("state_code").map_err(transaction_error)?;
        if enrollment_revision != expected_enrollment_revision
            || credential_revision != expected_credential_revision
            || !matches!(state.as_str(), "verifying_account" | "deduplicating")
        {
            return Err(StorageError::RevisionConflict);
        }
        let mode: String = row.try_get("kind_code").map_err(transaction_error)?;
        let existing_account: Option<Uuid> = row.try_get("account_uuid").map_err(transaction_error)?;
        if mode == "recover" {
            let recovery_id: Option<Uuid> = row.try_get("recover_credential_id").map_err(transaction_error)?;
            let auth_state: String = row.try_get("auth_state_code").map_err(transaction_error)?;
            if recovery_id != Some(credential_id)
                || existing_account != Some(account_uuid)
                || auth_state != "manual_recovery_required"
            {
                return Err(StorageError::AccountMismatch);
            }
            sqlx::query(
                "UPDATE gateway.credential_enrollment SET state_code='recovering_existing',next_action_code='retry', \
                 identified_account_uuid=$2,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(enrollment_id)
            .bind(account_uuid)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        } else {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))")
                .bind(account_uuid)
                .execute(&mut *transaction)
                .await
                .map_err(transaction_error)?;
            let conflict: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM gateway.anthropic_credential WHERE account_uuid=$1 AND id<>$2 FOR UPDATE",
            )
            .bind(account_uuid)
            .bind(credential_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            if conflict.is_some() {
                append_credential_event(
                    &mut transaction,
                    credential_id,
                    Some(enrollment_id),
                    None,
                    "credential_account_conflict",
                    credential_revision,
                    json!({"account_mask": masked_account(account_uuid)}),
                )
                .await?;
                cleanup_pending_credential(
                    &mut transaction,
                    enrollment_id,
                    credential_id,
                    "failed",
                    "credential_account_exists",
                )
                .await?;
                transaction.commit().await.map_err(transaction_error)?;
                return Err(StorageError::AccountConflict);
            }
            let update = sqlx::query(
                "UPDATE gateway.anthropic_credential SET account_uuid=$2,lifecycle_state_code='pending_profile', \
                 revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 AND account_uuid IS NULL",
            )
            .bind(credential_id)
            .bind(account_uuid)
            .execute(&mut *transaction)
            .await;
            match update {
                Ok(result) if result.rows_affected() == 1 => {}
                Ok(_) => return Err(StorageError::RevisionConflict),
                Err(error) if is_unique_violation(&error) => {
                    cleanup_pending_credential(
                        &mut transaction,
                        enrollment_id,
                        credential_id,
                        "failed",
                        "credential_account_exists",
                    )
                    .await?;
                    transaction.commit().await.map_err(transaction_error)?;
                    return Err(StorageError::AccountConflict);
                }
                Err(error) => return Err(transaction_error(error)),
            }
            sqlx::query(
                "UPDATE gateway.credential_enrollment SET state_code='provisioning_identity',next_action_code='retry', \
                 identified_account_uuid=$2,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(enrollment_id)
            .bind(account_uuid)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        }
        append_credential_event(
            &mut transaction,
            credential_id,
            Some(enrollment_id),
            None,
            "account_verified",
            credential_revision + i64::from(mode != "recover"),
            json!({"account_mask": masked_account(account_uuid), "mode": mode}),
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)
    }

    pub async fn provision_credential_profile(&self, command: &CredentialProfileProvision) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        require_durable_job_fence(&mut transaction, command.durable_job_fence.as_ref()).await?;
        let row = sqlx::query(
            "SELECT e.revision AS enrollment_revision,e.state_code,c.revision AS credential_revision, \
                    c.lifecycle_state_code,b.id AS binding_id,b.egress_epoch \
             FROM gateway.credential_enrollment e JOIN gateway.anthropic_credential c ON c.id=e.pending_credential_id \
             JOIN gateway.credential_egress_binding b ON b.credential_id=c.id \
             WHERE e.id=$1 AND c.id=$2 FOR UPDATE OF e,c,b",
        )
        .bind(command.enrollment_id)
        .bind(command.credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let enrollment_revision: i64 = row.try_get("enrollment_revision").map_err(transaction_error)?;
        let credential_revision: i64 = row.try_get("credential_revision").map_err(transaction_error)?;
        let enrollment_state: String = row.try_get("state_code").map_err(transaction_error)?;
        if enrollment_revision != command.expected_enrollment_revision
            || credential_revision != command.expected_credential_revision
            || enrollment_state != "provisioning_identity"
        {
            return Err(StorageError::RevisionConflict);
        }
        let archetype_eligible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM catalog.environment_archetype_version version \
             JOIN catalog.archetype_bundle_binding binding ON binding.archetype_version_id=version.id AND binding.state_code='active' \
             JOIN catalog.transport_bundle bundle ON bundle.id=binding.transport_bundle_id AND bundle.lifecycle_code='active' \
             JOIN catalog.archetype_capacity_policy capacity ON capacity.archetype_version_id=version.id \
             WHERE version.id=$1 AND version.lifecycle_code='active' \
               AND (SELECT count(*) FROM gateway.credential_profile profile WHERE profile.archetype_version_id=version.id \
                    AND profile.lifecycle_code IN ('pending','active','upgrading')) < capacity.max_credentials)",
        )
        .bind(command.archetype_version_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if !archetype_eligible {
            return Err(StorageError::CapacityExceeded);
        }
        sqlx::query(
            "INSERT INTO gateway.device_identity \
             (id,credential_id,installation_id_secret_id,client_id_secret_id,profile_seed_secret_id,session_hmac_secret_id, \
              installation_id_digest,client_id_digest,device_epoch,revision,created_at,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1,1,clock_timestamp(),clock_timestamp())",
        )
        .bind(command.device_identity_id)
        .bind(command.credential_id)
        .bind(command.installation_secret_id)
        .bind(command.client_secret_id)
        .bind(command.profile_seed_secret_id)
        .bind(command.session_hmac_secret_id)
        .bind(&command.installation_digest)
        .bind(&command.client_digest)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let binding_id: Uuid = row.try_get("binding_id").map_err(transaction_error)?;
        let egress_epoch: i64 = row.try_get("egress_epoch").map_err(transaction_error)?;
        sqlx::query(
            "INSERT INTO gateway.credential_profile \
             (id,credential_id,archetype_version_id,device_identity_id,egress_binding_id,profile_epoch,lifecycle_code, \
              capture_cohort,session_derivation_version,allocation_evidence,revision,created_at,updated_at) \
             VALUES ($1,$2,$3,$4,$5,1,'active',$6,1,$7,1,clock_timestamp(),clock_timestamp())",
        )
        .bind(command.profile_id)
        .bind(command.credential_id)
        .bind(command.archetype_version_id)
        .bind(command.device_identity_id)
        .bind(binding_id)
        .bind(&command.capture_cohort)
        .bind(&command.allocation_evidence)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.anthropic_credential SET lifecycle_state_code='pending_verify',revision=revision+1, \
             updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(command.credential_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.credential_enrollment SET state_code='configuring_reauth',next_action_code='retry', \
             revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(command.enrollment_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            command.credential_id,
            Some(command.enrollment_id),
            None,
            "profile_provisioned",
            credential_revision + 1,
            json!({"profile_id": command.profile_id, "device_identity_id": command.device_identity_id,
                   "archetype_version_id": command.archetype_version_id, "profile_epoch": 1,
                   "device_epoch": 1, "egress_epoch": egress_epoch}),
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)
    }

    pub async fn create_or_join_maintenance_operation(
        &self,
        command: &MaintenanceOperationCreate,
    ) -> Result<MaintenanceOperationRecord, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        if let Some(existing) =
            load_active_operation(&mut transaction, command.credential_id, &command.conflict_class).await?
        {
            transaction.commit().await.map_err(transaction_error)?;
            return Ok(MaintenanceOperationRecord {
                operation_id: existing.0,
                state: existing.1,
                generation: existing.2,
                joined_existing: true,
            });
        }
        let insert = sqlx::query(
            "INSERT INTO gateway.maintenance_operation \
             (id,credential_id,kind_code,trigger_code,conflict_class_code,state_code,expected_credential_revision, \
              expected_token_version,egress_binding_id,egress_epoch_snapshot,operation_generation,adapter_code, \
              adapter_version,provider_profile_id,retry_count,result_summary,created_at,updated_at) \
             VALUES ($1,$2,$3,$4,$5,'planned',$6,$7,$8,$9,1,$10,$11,$12,0,'{}'::jsonb,clock_timestamp(),clock_timestamp())",
        )
        .bind(command.operation_id)
        .bind(command.credential_id)
        .bind(&command.kind)
        .bind(&command.trigger)
        .bind(&command.conflict_class)
        .bind(command.expected_revision)
        .bind(command.expected_token_version)
        .bind(command.egress_binding_id)
        .bind(command.egress_epoch)
        .bind(&command.adapter_code)
        .bind(&command.adapter_version)
        .bind(command.provider_profile_id)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = insert {
            if is_unique_violation(&error) {
                transaction.rollback().await.map_err(transaction_error)?;
                let mut retry = self.pool.begin().await.map_err(transaction_error)?;
                let existing = load_active_operation(&mut retry, command.credential_id, &command.conflict_class)
                    .await?
                    .ok_or(StorageError::RevisionConflict)?;
                retry.commit().await.map_err(transaction_error)?;
                return Ok(MaintenanceOperationRecord {
                    operation_id: existing.0,
                    state: existing.1,
                    generation: existing.2,
                    joined_existing: true,
                });
            }
            return Err(transaction_error(error));
        }
        transaction.commit().await.map_err(transaction_error)?;
        Ok(MaintenanceOperationRecord {
            operation_id: command.operation_id,
            state: "planned".to_owned(),
            generation: 1,
            joined_existing: false,
        })
    }

    pub async fn supersede_attention_operations_for_recovery(
        &self,
        credential_id: Uuid,
        expected_credential_revision: i64,
        enrollment_id: Uuid,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let row =
            sqlx::query("SELECT revision,auth_state_code FROM gateway.anthropic_credential WHERE id=$1 FOR UPDATE")
                .bind(credential_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(transaction_error)?
                .ok_or(StorageError::InvalidLifecycle)?;
        let revision: i64 = row.try_get("revision").map_err(transaction_error)?;
        let auth_state: String = row.try_get("auth_state_code").map_err(transaction_error)?;
        if revision != expected_credential_revision || auth_state != "manual_recovery_required" {
            return Err(StorageError::RevisionConflict);
        }
        let superseded = sqlx::query(
            "UPDATE gateway.maintenance_operation SET state_code='failed', \
             outcome_code='superseded_by_manual_recovery',completed_at=clock_timestamp(),updated_at=clock_timestamp() \
             WHERE credential_id=$1 AND conflict_class_code='auth_material_write' AND state_code='needs_attention' \
             RETURNING id",
        )
        .bind(credential_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if !superseded.is_empty() {
            append_credential_event(
                &mut transaction,
                credential_id,
                Some(enrollment_id),
                None,
                "manual_recovery_started",
                revision,
                json!({"superseded_operations": superseded.len()}),
            )
            .await?;
        }
        transaction.commit().await.map_err(transaction_error)
    }

    pub async fn commit_auth_candidate(
        &self,
        candidate: &AuthCandidateRecord,
        precondition: &AuthCasPrecondition,
    ) -> Result<AuthCandidateCommit, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        require_durable_job_fence(&mut transaction, precondition.durable_job_fence.as_ref()).await?;
        let next_token = precondition
            .expected_token_version
            .checked_add(1)
            .ok_or(StorageError::TransactionFailed)?;
        sqlx::query(
            "INSERT INTO gateway.credential_auth_version \
             (id,credential_id,token_version,auth_kind_code,access_secret_id,refresh_secret_id,console_secret_id, \
              verified_account_uuid,expires_at,operation_id,material_state_code,adapter_code,adapter_version,created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $9::bigint IS NULL THEN NULL ELSE to_timestamp($9) END, \
                     $10,'candidate',$11,$12,clock_timestamp())",
        )
        .bind(candidate.auth_version_id)
        .bind(candidate.credential_id)
        .bind(next_token)
        .bind(auth_kind_code(candidate.auth_kind))
        .bind(candidate.access_secret_id)
        .bind(candidate.refresh_secret_id)
        .bind(candidate.console_secret_id)
        .bind(candidate.verified_account_uuid)
        .bind(candidate.expires_at_epoch_seconds)
        .bind(precondition.operation_id)
        .bind(&candidate.adapter_code)
        .bind(&candidate.adapter_version)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let snapshot = sqlx::query(
            "SELECT c.revision,c.token_version,c.account_uuid,c.lifecycle_state_code,c.active_auth_version_id, \
                    b.id AS binding_id,b.egress_epoch, \
                    o.operation_generation,o.state_code AS operation_state \
             FROM gateway.anthropic_credential c JOIN gateway.credential_egress_binding b ON b.credential_id=c.id \
             JOIN gateway.maintenance_operation o ON o.id=$2 AND o.credential_id=c.id \
             WHERE c.id=$1 FOR UPDATE OF c,b,o",
        )
        .bind(candidate.credential_id)
        .bind(precondition.operation_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let cas_matches = snapshot.as_ref().is_some_and(|row| {
            row.try_get::<i64, _>("revision").ok() == Some(precondition.expected_credential_revision)
                && row.try_get::<i64, _>("token_version").ok() == Some(precondition.expected_token_version)
                && row.try_get::<Option<Uuid>, _>("account_uuid").ok() == Some(precondition.expected_account_uuid)
                && row.try_get::<Uuid, _>("binding_id").ok() == Some(precondition.expected_egress_binding_id)
                && row.try_get::<i64, _>("egress_epoch").ok() == Some(precondition.expected_egress_epoch)
                && row.try_get::<i64, _>("operation_generation").ok() == Some(precondition.operation_generation)
                && row.try_get::<String, _>("operation_state").ok().is_some_and(|state| {
                    matches!(
                        state.as_str(),
                        "planned" | "leased" | "running" | "verifying_account" | "committing"
                    )
                })
                && row
                    .try_get::<String, _>("lifecycle_state_code")
                    .ok()
                    .is_some_and(|state| !matches!(state.as_str(), "revoked" | "archived"))
        });
        let candidate_account_matches = candidate.verified_account_uuid == precondition.expected_account_uuid
            || (candidate.auth_kind == AuthKind::ConsoleApiKey
                && candidate.verified_account_uuid.is_none()
                && precondition.expected_account_uuid.is_none());
        if !cas_matches || !candidate_account_matches {
            destroy_candidate(&mut transaction, candidate).await?;
            sqlx::query(
                "DELETE FROM gateway.credential_auth_secret_stage \
                 WHERE operation_id=$1 AND operation_generation=$2",
            )
            .bind(precondition.operation_id)
            .bind(precondition.operation_generation)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            sqlx::query(
                "UPDATE gateway.maintenance_operation SET state_code='failed',outcome_code='cas_conflict', \
                 completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND operation_generation=$2",
            )
            .bind(precondition.operation_id)
            .bind(precondition.operation_generation)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            transaction.commit().await.map_err(transaction_error)?;
            return Err(if candidate_account_matches {
                StorageError::RevisionConflict
            } else {
                StorageError::AccountMismatch
            });
        }
        let old_auth_version_id = snapshot
            .as_ref()
            .and_then(|row| row.try_get::<Option<Uuid>, _>("active_auth_version_id").ok())
            .flatten();
        sqlx::query(
            "UPDATE gateway.credential_auth_version SET material_state_code='superseded',superseded_at=clock_timestamp() \
             WHERE id=(SELECT active_auth_version_id FROM gateway.anthropic_credential WHERE id=$1) AND id<>$2",
        )
        .bind(candidate.credential_id)
        .bind(candidate.auth_version_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if let Some(old_auth_version_id) = old_auth_version_id {
            sqlx::query(
                "UPDATE security.encrypted_secret SET superseded_at=COALESCE(superseded_at,clock_timestamp()) \
                 WHERE id IN ( \
                   SELECT access_secret_id FROM gateway.credential_auth_version WHERE id=$1 \
                   UNION SELECT refresh_secret_id FROM gateway.credential_auth_version WHERE id=$1 \
                   UNION SELECT console_secret_id FROM gateway.credential_auth_version WHERE id=$1 \
                 ) AND destroyed_at IS NULL",
            )
            .bind(old_auth_version_id)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        }
        let row = sqlx::query(
            "UPDATE gateway.anthropic_credential SET active_auth_version_id=$2,token_version=$3,auth_state_code='healthy', \
             revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
        )
        .bind(candidate.credential_id)
        .bind(candidate.auth_version_id)
        .bind(next_token)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let credential_revision: i64 = row.try_get("revision").map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.credential_auth_version SET material_state_code='active',activated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(candidate.auth_version_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.maintenance_operation SET state_code='succeeded',outcome_code='success', \
             result_summary=jsonb_build_object('token_version',$3,'credential_revision',$4), \
             completed_at=clock_timestamp(),updated_at=clock_timestamp() \
             WHERE id=$1 AND operation_generation=$2",
        )
        .bind(precondition.operation_id)
        .bind(precondition.operation_generation)
        .bind(next_token)
        .bind(credential_revision)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "DELETE FROM gateway.credential_auth_secret_stage WHERE operation_id=$1 AND operation_generation=$2",
        )
        .bind(precondition.operation_id)
        .bind(precondition.operation_generation)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            candidate.credential_id,
            None,
            Some(precondition.operation_id),
            "auth_candidate_activated",
            credential_revision,
            json!({"token_version": next_token, "auth_kind": auth_kind_code(candidate.auth_kind),
                   "egress_binding_id": precondition.expected_egress_binding_id,
                   "egress_epoch": precondition.expected_egress_epoch}),
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)?;
        Ok(AuthCandidateCommit {
            auth_version_id: candidate.auth_version_id,
            token_version: next_token,
            credential_revision,
        })
    }

    pub async fn fail_auth_maintenance(&self, update: &MaintenanceFailureUpdate) -> Result<(), StorageError> {
        if !matches!(
            update.state.as_str(),
            "waiting_backoff" | "waiting_egress" | "needs_attention" | "failed"
        ) || update.outcome.trim().is_empty()
            || update.error_category.trim().is_empty()
            || update.retry_after_seconds.is_some_and(|seconds| seconds < 0)
        {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let _credential_revision: i64 =
            sqlx::query_scalar("SELECT revision FROM gateway.anthropic_credential WHERE id=$1 FOR UPDATE")
                .bind(update.credential_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(transaction_error)?
                .ok_or(StorageError::RevisionConflict)?;
        let changed = sqlx::query(
            "UPDATE gateway.maintenance_operation SET state_code=$4,outcome_code=$5,error_category_code=$6, \
             retry_after=CASE WHEN $7::bigint IS NULL THEN NULL ELSE clock_timestamp()+make_interval(secs=>$7) END, \
             completed_at=CASE WHEN $4='failed' THEN clock_timestamp() ELSE NULL END,updated_at=clock_timestamp() \
             WHERE id=$1 AND credential_id=$2 AND operation_generation=$3 \
               AND state_code NOT IN ('succeeded','failed','cancelled','expired')",
        )
        .bind(update.operation_id)
        .bind(update.credential_id)
        .bind(update.operation_generation)
        .bind(&update.state)
        .bind(&update.outcome)
        .bind(&update.error_category)
        .bind(update.retry_after_seconds)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if changed.rows_affected() != 1 {
            transaction.rollback().await.map_err(transaction_error)?;
            return Err(StorageError::RevisionConflict);
        }
        let staged_rows = sqlx::query(
            "DELETE FROM gateway.credential_auth_secret_stage WHERE operation_id=$1 AND operation_generation=$2 \
             RETURNING access_secret_id,refresh_secret_id",
        )
        .bind(update.operation_id)
        .bind(update.operation_generation)
        .fetch_all(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let mut staged_secret_ids = Vec::with_capacity(staged_rows.len() * 2);
        for row in staged_rows {
            staged_secret_ids.push(row.try_get::<Uuid, _>("access_secret_id").map_err(transaction_error)?);
            if let Some(refresh_secret_id) = row
                .try_get::<Option<Uuid>, _>("refresh_secret_id")
                .map_err(transaction_error)?
            {
                staged_secret_ids.push(refresh_secret_id);
            }
        }
        destroy_secret_ids(&mut transaction, &staged_secret_ids).await?;
        let next_revision = if let Some(auth_state) = &update.credential_auth_state {
            sqlx::query_scalar(
                "UPDATE gateway.anthropic_credential SET auth_state_code=$2, \
                 scheduling_state_code=CASE WHEN $3 THEN 'blocked' ELSE scheduling_state_code END, \
                 revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
            )
            .bind(update.credential_id)
            .bind(auth_state)
            .bind(update.block_scheduling)
            .fetch_one(&mut *transaction)
            .await
            .map_err(transaction_error)?
        } else {
            sqlx::query_scalar(
                "UPDATE gateway.anthropic_credential SET revision=revision+1,updated_at=clock_timestamp() \
                 WHERE id=$1 RETURNING revision",
            )
            .bind(update.credential_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(transaction_error)?
        };
        append_credential_event_with_outcome(
            &mut transaction,
            update.credential_id,
            None,
            Some(update.operation_id),
            "auth_maintenance_failed",
            next_revision,
            json!({"operation_generation": update.operation_generation, "state": update.state,
                   "outcome": update.outcome, "error_category": update.error_category}),
            "failed",
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)
    }

    pub async fn create_managed_browser_strategy(
        &self,
        command: &ManagedBrowserStrategyCreate,
    ) -> Result<i64, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let row = sqlx::query(
            "SELECT c.revision,b.lifecycle_code FROM gateway.anthropic_credential c \
             JOIN gateway.credential_egress_binding b ON b.credential_id=c.id \
             WHERE c.id=$1 AND c.lifecycle_state_code NOT IN ('revoked','archived') FOR UPDATE OF c,b",
        )
        .bind(command.credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        if row.try_get::<i64, _>("revision").map_err(transaction_error)? != command.expected_credential_revision
            || row.try_get::<String, _>("lifecycle_code").map_err(transaction_error)? != "active"
        {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "INSERT INTO gateway.auto_reauth_strategy \
             (id,credential_id,strategy_kind_code,priority,state_code,browser_provider_code,adapter_version,revision,created_at,updated_at) \
             VALUES ($1,$2,'managed_browser_session',100,'pending',$3,$4,1,clock_timestamp(),clock_timestamp())",
        )
        .bind(command.strategy_id)
        .bind(command.credential_id)
        .bind(&command.browser_provider_code)
        .bind(&command.adapter_version)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let credential_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET management_class_code='pending_reauth_strategy', \
             lifecycle_state_code=CASE WHEN lifecycle_state_code='active' THEN 'pending_reauth_strategy' ELSE lifecycle_state_code END, \
             scheduling_state_code='blocked',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
        )
        .bind(command.credential_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            command.credential_id,
            None,
            None,
            "managed_browser_strategy_created",
            credential_revision,
            json!({"strategy_id": command.strategy_id, "state": "pending"}),
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)?;
        Ok(credential_revision)
    }

    pub async fn commit_browser_reauth_candidate(
        &self,
        auth: &AuthCandidateRecord,
        browser: &BrowserMaterialCandidate,
        precondition: &BrowserCasPrecondition,
    ) -> Result<BrowserReauthCommit, StorageError> {
        if auth.credential_id != browser.credential_id
            || auth.verified_account_uuid != Some(browser.verified_account_uuid)
            || precondition.auth.expected_account_uuid != Some(browser.verified_account_uuid)
        {
            return Err(StorageError::AccountMismatch);
        }
        let next_token = precondition
            .auth
            .expected_token_version
            .checked_add(1)
            .ok_or(StorageError::TransactionFailed)?;
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        match (precondition.durable_job_id, precondition.durable_job_generation) {
            (Some(job_id), Some(job_generation)) => {
                let valid: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM ops.durable_job WHERE id=$1 \
                     AND kind_code='credential_managed_browser_v1' AND state_code='leased' \
                     AND lease_generation=$2 FOR UPDATE)",
                )
                .bind(job_id)
                .bind(job_generation)
                .fetch_one(&mut *transaction)
                .await
                .map_err(transaction_error)?;
                if !valid {
                    return Err(StorageError::RevisionConflict);
                }
            }
            (None, None) => {}
            _ => return Err(StorageError::InvalidLifecycle),
        }
        sqlx::query(
            "INSERT INTO gateway.credential_auth_version \
             (id,credential_id,token_version,auth_kind_code,access_secret_id,refresh_secret_id,console_secret_id, \
              verified_account_uuid,expires_at,operation_id,material_state_code,adapter_code,adapter_version,created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $9::bigint IS NULL THEN NULL ELSE to_timestamp($9) END, \
                     $10,'candidate',$11,$12,clock_timestamp())",
        )
        .bind(auth.auth_version_id)
        .bind(auth.credential_id)
        .bind(next_token)
        .bind(auth_kind_code(auth.auth_kind))
        .bind(auth.access_secret_id)
        .bind(auth.refresh_secret_id)
        .bind(auth.console_secret_id)
        .bind(auth.verified_account_uuid)
        .bind(auth.expires_at_epoch_seconds)
        .bind(precondition.auth.operation_id)
        .bind(&auth.adapter_code)
        .bind(&auth.adapter_version)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "INSERT INTO gateway.managed_browser_material_version \
             (id,credential_id,strategy_id,material_version,secret_id,cookie_secret_id,storage_secret_id,profile_secret_id, \
              verified_account_uuid,adapter_version,egress_epoch,state_code,created_at) \
             VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,'candidate',clock_timestamp())",
        )
        .bind(browser.material_version_id)
        .bind(browser.credential_id)
        .bind(browser.strategy_id)
        .bind(browser.material_version)
        .bind(browser.cookie_secret_id)
        .bind(browser.storage_secret_id)
        .bind(browser.profile_secret_id)
        .bind(browser.verified_account_uuid)
        .bind(&browser.adapter_version)
        .bind(precondition.auth.expected_egress_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let snapshot = sqlx::query(
            "SELECT c.revision,c.token_version,c.account_uuid,c.lifecycle_state_code,b.id AS binding_id,b.egress_epoch, \
                    strategy.revision AS strategy_revision,strategy.state_code AS strategy_state, \
                    operation.operation_generation,operation.state_code AS operation_state \
             FROM gateway.anthropic_credential c JOIN gateway.credential_egress_binding b ON b.credential_id=c.id \
             JOIN gateway.auto_reauth_strategy strategy ON strategy.id=$2 AND strategy.credential_id=c.id \
             JOIN gateway.maintenance_operation operation ON operation.id=$3 AND operation.credential_id=c.id \
             WHERE c.id=$1 FOR UPDATE OF c,b,strategy,operation",
        )
        .bind(auth.credential_id)
        .bind(browser.strategy_id)
        .bind(precondition.auth.operation_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let cas_matches = snapshot.as_ref().is_some_and(|row| {
            row.try_get::<i64, _>("revision").ok() == Some(precondition.auth.expected_credential_revision)
                && row.try_get::<i64, _>("token_version").ok() == Some(precondition.auth.expected_token_version)
                && row.try_get::<Option<Uuid>, _>("account_uuid").ok() == Some(precondition.auth.expected_account_uuid)
                && row.try_get::<Uuid, _>("binding_id").ok() == Some(precondition.auth.expected_egress_binding_id)
                && row.try_get::<i64, _>("egress_epoch").ok() == Some(precondition.auth.expected_egress_epoch)
                && row.try_get::<i64, _>("strategy_revision").ok() == Some(precondition.strategy_revision)
                && row
                    .try_get::<String, _>("strategy_state")
                    .ok()
                    .is_some_and(|state| matches!(state.as_str(), "pending" | "healthy" | "degraded"))
                && row.try_get::<i64, _>("operation_generation").ok() == Some(precondition.auth.operation_generation)
                && row.try_get::<String, _>("operation_state").ok().is_some_and(|state| {
                    matches!(
                        state.as_str(),
                        "planned" | "leased" | "running" | "verifying_account" | "committing"
                    )
                })
                && row
                    .try_get::<String, _>("lifecycle_state_code")
                    .ok()
                    .is_some_and(|state| !matches!(state.as_str(), "revoked" | "archived"))
        });
        if !cas_matches {
            destroy_candidate(&mut transaction, auth).await?;
            destroy_browser_candidate(&mut transaction, browser).await?;
            sqlx::query(
                "DELETE FROM gateway.credential_auth_secret_stage \
                 WHERE operation_id=$1 AND operation_generation=$2",
            )
            .bind(precondition.auth.operation_id)
            .bind(precondition.auth.operation_generation)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            sqlx::query(
                "DELETE FROM gateway.managed_browser_secret_stage \
                 WHERE operation_id=$1 AND operation_generation=$2",
            )
            .bind(precondition.auth.operation_id)
            .bind(precondition.auth.operation_generation)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            sqlx::query(
                "UPDATE gateway.maintenance_operation SET state_code='failed',outcome_code='cas_conflict', \
                 completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND operation_generation=$2",
            )
            .bind(precondition.auth.operation_id)
            .bind(precondition.auth.operation_generation)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            transaction.commit().await.map_err(transaction_error)?;
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "UPDATE gateway.credential_auth_version SET material_state_code='superseded',superseded_at=clock_timestamp() \
             WHERE id=(SELECT active_auth_version_id FROM gateway.anthropic_credential WHERE id=$1) AND id<>$2",
        )
        .bind(auth.credential_id)
        .bind(auth.auth_version_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.managed_browser_material_version SET state_code='superseded',superseded_at=clock_timestamp() \
             WHERE id=(SELECT active_material_version_id FROM gateway.auto_reauth_strategy WHERE id=$1) AND id<>$2",
        )
        .bind(browser.strategy_id)
        .bind(browser.material_version_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let credential_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET active_auth_version_id=$2,token_version=$3,auth_state_code='healthy', \
             management_class_code='fully_managed', \
             lifecycle_state_code=CASE WHEN lifecycle_state_code='pending_reauth_strategy' THEN 'active' ELSE lifecycle_state_code END, \
             scheduling_state_code=CASE WHEN lifecycle_state_code='pending_reauth_strategy' THEN 'eligible' ELSE scheduling_state_code END, \
             transport_state_code=CASE WHEN lifecycle_state_code='pending_reauth_strategy' THEN 'ready' ELSE transport_state_code END, \
             revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
        )
        .bind(auth.credential_id)
        .bind(auth.auth_version_id)
        .bind(next_token)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.credential_auth_version SET material_state_code='active',activated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(auth.auth_version_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.managed_browser_material_version SET state_code='active',activated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(browser.material_version_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let strategy_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.auto_reauth_strategy SET active_material_version_id=$2,state_code='healthy', \
             last_verified_at=clock_timestamp(),last_error_code=NULL,revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 RETURNING revision",
        )
        .bind(browser.strategy_id)
        .bind(browser.material_version_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.maintenance_operation SET state_code='succeeded',outcome_code='success', \
             result_summary=jsonb_build_object('token_version',$3,'browser_material_version',$4), \
             completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND operation_generation=$2",
        )
        .bind(precondition.auth.operation_id)
        .bind(precondition.auth.operation_generation)
        .bind(next_token)
        .bind(browser.material_version)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            auth.credential_id,
            None,
            Some(precondition.auth.operation_id),
            "browser_reauth_activated",
            credential_revision,
            json!({"strategy_id": browser.strategy_id, "material_version": browser.material_version,
                   "token_version": next_token, "egress_epoch": precondition.auth.expected_egress_epoch}),
        )
        .await?;
        sqlx::query(
            "DELETE FROM gateway.credential_auth_secret_stage \
             WHERE operation_id=$1 AND operation_generation=$2",
        )
        .bind(precondition.auth.operation_id)
        .bind(precondition.auth.operation_generation)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "DELETE FROM gateway.managed_browser_secret_stage \
             WHERE operation_id=$1 AND operation_generation=$2",
        )
        .bind(precondition.auth.operation_id)
        .bind(precondition.auth.operation_generation)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if let (Some(job_id), Some(job_generation)) = (precondition.durable_job_id, precondition.durable_job_generation)
        {
            let changed = sqlx::query(
                "UPDATE ops.durable_job SET checkpoint=$3,updated_at=clock_timestamp() \
                 WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
            )
            .bind(job_id)
            .bind(job_generation)
            .bind(
                json!({"phase":"browser_material_committed","credential_id":auth.credential_id,
              "token_version":next_token,"credential_revision":credential_revision}),
            )
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            if changed.rows_affected() != 1 {
                return Err(StorageError::RevisionConflict);
            }
        }
        transaction.commit().await.map_err(transaction_error)?;
        Ok(BrowserReauthCommit {
            auth: AuthCandidateCommit {
                auth_version_id: auth.auth_version_id,
                token_version: next_token,
                credential_revision,
            },
            material_version: browser.material_version,
            strategy_revision,
        })
    }

    pub async fn begin_credential_group_migration(
        &self,
        command: &CredentialGroupMigrationBegin,
    ) -> Result<i64, StorageError> {
        if command.drain_seconds < 1 || command.source_group_id == command.target_group_id {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let target_valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM gateway.credential_group WHERE id=$1 AND status_code='active')",
        )
        .bind(command.target_group_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if !target_valid {
            return Err(StorageError::InvalidLifecycle);
        }
        let revision: Option<i64> = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET attachment_state_code='draining',attachment_target_group_id=$3, \
             attachment_deadline=clock_timestamp()+($4*interval '1 second'),revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND group_id=$2 AND revision=$5 AND lifecycle_state_code NOT IN ('revoked','archived') \
               AND attachment_state_code='attached' RETURNING revision",
        )
        .bind(command.credential_id)
        .bind(command.source_group_id)
        .bind(command.target_group_id)
        .bind(command.drain_seconds)
        .bind(command.expected_credential_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let revision = revision.ok_or(StorageError::RevisionConflict)?;
        sqlx::query(
            "INSERT INTO gateway.credential_group_migration \
             (id,credential_id,source_group_id,target_group_id,state_code,expected_revision,requested_by,created_at) \
             VALUES ($1,$2,$3,$4,'draining',$5,$6,clock_timestamp())",
        )
        .bind(command.migration_id)
        .bind(command.credential_id)
        .bind(command.source_group_id)
        .bind(command.target_group_id)
        .bind(revision)
        .bind(command.requested_by)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            command.credential_id,
            None,
            None,
            "group_migration_started",
            revision,
            json!({"migration_id": command.migration_id, "source_group_id": command.source_group_id,
                   "target_group_id": command.target_group_id}),
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)?;
        Ok(revision)
    }

    pub async fn finish_credential_group_migration(
        &self,
        migration_id: Uuid,
        expected_credential_revision: i64,
        active_leases: u32,
    ) -> Result<i64, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let row = sqlx::query(
            "SELECT migration.credential_id,migration.source_group_id,migration.target_group_id,migration.state_code, \
                    credential.revision,(credential.attachment_deadline<=clock_timestamp()) AS expired \
             FROM gateway.credential_group_migration migration JOIN gateway.anthropic_credential credential \
               ON credential.id=migration.credential_id WHERE migration.id=$1 FOR UPDATE OF migration,credential",
        )
        .bind(migration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let credential_id: Uuid = row.try_get("credential_id").map_err(transaction_error)?;
        let revision: i64 = row.try_get("revision").map_err(transaction_error)?;
        let expired: bool = row.try_get("expired").map_err(transaction_error)?;
        if revision != expected_credential_revision
            || row.try_get::<String, _>("state_code").map_err(transaction_error)? != "draining"
        {
            return Err(StorageError::RevisionConflict);
        }
        if active_leases > 0 {
            if !expired {
                return Err(StorageError::InvalidLifecycle);
            }
            let next_revision: i64 = sqlx::query_scalar(
                "UPDATE gateway.anthropic_credential SET attachment_state_code='attached',attachment_target_group_id=NULL, \
                 attachment_deadline=NULL,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
            )
            .bind(credential_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            sqlx::query(
                "UPDATE gateway.credential_group_migration SET state_code='failed',completed_at=clock_timestamp() WHERE id=$1",
            )
            .bind(migration_id)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            append_credential_event(
                &mut transaction,
                credential_id,
                None,
                None,
                "group_migration_timed_out",
                next_revision,
                json!({"migration_id": migration_id, "active_leases": active_leases}),
            )
            .await?;
            transaction.commit().await.map_err(transaction_error)?;
            return Ok(next_revision);
        }
        let target_group_id: Uuid = row.try_get("target_group_id").map_err(transaction_error)?;
        let source_group_id: Uuid = row.try_get("source_group_id").map_err(transaction_error)?;
        let next_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET group_id=$2,attachment_state_code='attached',attachment_target_group_id=NULL, \
             attachment_deadline=NULL,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
        )
        .bind(credential_id)
        .bind(target_group_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.credential_group_migration SET state_code='committed',completed_at=clock_timestamp() WHERE id=$1",
        )
        .bind(migration_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            credential_id,
            None,
            None,
            "group_migration_committed",
            next_revision,
            json!({"migration_id": migration_id, "source_group_id": source_group_id,
                   "target_group_id": target_group_id}),
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)?;
        Ok(next_revision)
    }

    pub async fn activate_credential(
        &self,
        enrollment_id: Uuid,
        credential_id: Uuid,
        expected_credential_revision: i64,
    ) -> Result<i64, StorageError> {
        self.activate_credential_inner(enrollment_id, credential_id, expected_credential_revision, None)
            .await
    }

    pub async fn activate_credential_for_job(
        &self,
        enrollment_id: Uuid,
        credential_id: Uuid,
        expected_credential_revision: i64,
        fence: &DurableJobFence,
    ) -> Result<i64, StorageError> {
        self.activate_credential_inner(enrollment_id, credential_id, expected_credential_revision, Some(fence))
            .await
    }

    async fn activate_credential_inner(
        &self,
        enrollment_id: Uuid,
        credential_id: Uuid,
        expected_credential_revision: i64,
        durable_job_fence: Option<&DurableJobFence>,
    ) -> Result<i64, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        require_durable_job_fence(&mut transaction, durable_job_fence).await?;
        let row = sqlx::query(
            "SELECT c.revision,c.auth_state_code,c.management_class_code,c.active_auth_version_id, \
                     p.lifecycle_code AS profile_state,b.lifecycle_code AS egress_state,version.lifecycle_code AS archetype_state, \
                     bundle.lifecycle_code AS bundle_state,e.revision AS enrollment_revision,e.state_code AS enrollment_state, \
                     e.pkce_verifier_secret_id,e.material_secret_refs \
              FROM gateway.anthropic_credential c JOIN gateway.credential_profile p ON p.credential_id=c.id \
              JOIN gateway.credential_egress_binding b ON b.id=p.egress_binding_id \
              JOIN catalog.environment_archetype_version version ON version.id=p.archetype_version_id \
              JOIN catalog.archetype_bundle_binding pointer ON pointer.archetype_version_id=version.id AND pointer.state_code='active' \
              JOIN catalog.transport_bundle bundle ON bundle.id=pointer.transport_bundle_id \
              JOIN gateway.credential_enrollment e ON e.id=$2 AND e.pending_credential_id=c.id \
              WHERE c.id=$1 FOR UPDATE OF c,p,b,e",
        )
        .bind(credential_id)
        .bind(enrollment_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let revision: i64 = row.try_get("revision").map_err(transaction_error)?;
        let management: String = row.try_get("management_class_code").map_err(transaction_error)?;
        let strategy_healthy: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM gateway.auto_reauth_strategy WHERE credential_id=$1 \
             AND strategy_kind_code='managed_browser_session' AND state_code='healthy')",
        )
        .bind(credential_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let ready = revision == expected_credential_revision
            && row.try_get::<String, _>("auth_state_code").ok().as_deref() == Some("healthy")
            && row
                .try_get::<Option<Uuid>, _>("active_auth_version_id")
                .ok()
                .flatten()
                .is_some()
            && row.try_get::<String, _>("profile_state").ok().as_deref() == Some("active")
            && row.try_get::<String, _>("egress_state").ok().as_deref() == Some("active")
            && row
                .try_get::<String, _>("archetype_state")
                .ok()
                .is_some_and(|value| matches!(value.as_str(), "canary" | "active"))
            && row
                .try_get::<String, _>("bundle_state")
                .ok()
                .is_some_and(|value| matches!(value.as_str(), "canary" | "active"))
            && row.try_get::<String, _>("enrollment_state").ok().is_some_and(|value| {
                matches!(
                    value.as_str(),
                    "recovering_existing" | "configuring_reauth" | "activation_check"
                )
            })
            && (management != "fully_managed" || strategy_healthy);
        if !ready {
            return Err(StorageError::InvalidLifecycle);
        }
        let next_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET lifecycle_state_code='active',scheduling_state_code='eligible', \
             transport_state_code='ready',capacity_state_code='available',revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 RETURNING revision",
        )
        .bind(credential_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let enrollment_revision: i64 = row.try_get("enrollment_revision").map_err(transaction_error)?;
        let mut temporary_secret_ids: Vec<Uuid> = row.try_get("material_secret_refs").map_err(transaction_error)?;
        if let Some(verifier) = row
            .try_get::<Option<Uuid>, _>("pkce_verifier_secret_id")
            .map_err(transaction_error)?
        {
            temporary_secret_ids.push(verifier);
        }
        destroy_secret_ids(&mut transaction, &temporary_secret_ids).await?;
        let enrollment_changed = sqlx::query(
            "UPDATE gateway.credential_enrollment SET state_code='succeeded',next_action_code='none', \
              pkce_verifier_secret_id=NULL,material_secret_refs='{}',revision=revision+1,updated_at=clock_timestamp() \
              WHERE id=$1 AND pending_credential_id=$2 AND revision=$3 \
              AND state_code IN ('recovering_existing','configuring_reauth','activation_check')",
        )
        .bind(enrollment_id)
        .bind(credential_id)
        .bind(enrollment_revision)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if enrollment_changed.rows_affected() != 1 {
            transaction.rollback().await.map_err(transaction_error)?;
            return Err(StorageError::RevisionConflict);
        }
        append_credential_event(
            &mut transaction,
            credential_id,
            Some(enrollment_id),
            None,
            "credential_activated",
            next_revision,
            json!({"lifecycle": "active"}),
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)?;
        Ok(next_revision)
    }

    pub async fn load_credential_r5_snapshot(&self, credential_id: Uuid) -> Result<CredentialR5Snapshot, StorageError> {
        let row = sqlx::query(
            "SELECT c.id,c.group_id,c.account_uuid,c.lifecycle_state_code,c.attachment_state_code,c.auth_state_code, \
                    c.capacity_state_code,c.transport_state_code,c.management_class_code,c.token_version,c.revision, \
                    p.profile_epoch,d.device_epoch,b.egress_epoch \
             FROM gateway.anthropic_credential c LEFT JOIN gateway.credential_profile p ON p.credential_id=c.id \
             LEFT JOIN gateway.device_identity d ON d.credential_id=c.id \
             LEFT JOIN gateway.credential_egress_binding b ON b.credential_id=c.id WHERE c.id=$1",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        Ok(CredentialR5Snapshot {
            credential_id: row.try_get("id").map_err(transaction_error)?,
            group_id: row.try_get("group_id").map_err(transaction_error)?,
            account_uuid: row.try_get("account_uuid").map_err(transaction_error)?,
            lifecycle: row.try_get("lifecycle_state_code").map_err(transaction_error)?,
            attachment: row.try_get("attachment_state_code").map_err(transaction_error)?,
            auth: row.try_get("auth_state_code").map_err(transaction_error)?,
            capacity: row.try_get("capacity_state_code").map_err(transaction_error)?,
            transport: row.try_get("transport_state_code").map_err(transaction_error)?,
            management_class: row.try_get("management_class_code").map_err(transaction_error)?,
            token_version: row.try_get("token_version").map_err(transaction_error)?,
            revision: row.try_get("revision").map_err(transaction_error)?,
            profile_epoch: row.try_get("profile_epoch").map_err(transaction_error)?,
            device_epoch: row.try_get("device_epoch").map_err(transaction_error)?,
            egress_epoch: row.try_get("egress_epoch").map_err(transaction_error)?,
        })
    }

    pub async fn upgrade_profile_cohort(
        &self,
        command: &ProfileCohortUpgrade,
    ) -> Result<ProfileContinuityCommit, StorageError> {
        self.upgrade_profile_cohort_internal(command, None).await
    }

    pub async fn upgrade_profile_cohort_with_audit(
        &self,
        command: &ProfileCohortUpgrade,
        audit: &AuditOutboxRecord,
    ) -> Result<ProfileContinuityCommit, StorageError> {
        self.upgrade_profile_cohort_internal(command, Some(audit)).await
    }

    async fn upgrade_profile_cohort_internal(
        &self,
        command: &ProfileCohortUpgrade,
        audit: Option<&AuditOutboxRecord>,
    ) -> Result<ProfileContinuityCommit, StorageError> {
        if command.target_capture_cohort.trim().is_empty() || command.reason_code.trim().is_empty() {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let current = sqlx::query(
            "SELECT c.revision,c.lifecycle_state_code,p.id AS profile_id,p.archetype_version_id,p.profile_epoch, \
                    d.device_epoch,b.egress_epoch,current_version.version AS current_version \
             FROM gateway.anthropic_credential c JOIN gateway.credential_profile p ON p.credential_id=c.id \
             JOIN gateway.device_identity d ON d.id=p.device_identity_id \
             JOIN gateway.credential_egress_binding b ON b.id=p.egress_binding_id \
             JOIN catalog.environment_archetype_version current_version ON current_version.id=p.archetype_version_id \
             WHERE c.id=$1 FOR UPDATE OF c,p,d,b",
        )
        .bind(command.credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let credential_revision: i64 = current.try_get("revision").map_err(transaction_error)?;
        let profile_epoch: i64 = current.try_get("profile_epoch").map_err(transaction_error)?;
        let lifecycle: String = current.try_get("lifecycle_state_code").map_err(transaction_error)?;
        if credential_revision != command.expected_credential_revision
            || profile_epoch != command.expected_profile_epoch
            || !matches!(lifecycle.as_str(), "active" | "disabled")
        {
            return Err(StorageError::RevisionConflict);
        }
        let from_archetype: Uuid = current.try_get("archetype_version_id").map_err(transaction_error)?;
        if from_archetype == command.target_archetype_version_id {
            return Err(StorageError::InvalidLifecycle);
        }
        let current_version: i64 = current.try_get("current_version").map_err(transaction_error)?;
        let target = sqlx::query(
            "SELECT version.lifecycle_code,version.version,version.capture_cohort, \
                    EXISTS(SELECT 1 FROM catalog.archetype_bundle_binding binding \
                      JOIN catalog.transport_bundle bundle ON bundle.id=binding.transport_bundle_id \
                      WHERE binding.archetype_version_id=version.id AND binding.state_code='active' \
                        AND bundle.lifecycle_code IN ('canary','active') \
                        AND bundle.evidence_gate_code='passed' AND bundle.runtime_state_code='loadable') AS bundle_ready, \
                    capacity.max_credentials, \
                    (SELECT count(*) FROM gateway.credential_profile used \
                      WHERE used.archetype_version_id=version.id AND used.credential_id<>$2 \
                        AND used.lifecycle_code IN ('pending','active','upgrading')) AS used_credentials \
             FROM catalog.environment_archetype_version version \
             JOIN catalog.archetype_capacity_policy capacity ON capacity.archetype_version_id=version.id \
             WHERE version.id=$1 FOR UPDATE OF capacity",
        )
        .bind(command.target_archetype_version_id)
        .bind(command.credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let target_state: String = target.try_get("lifecycle_code").map_err(transaction_error)?;
        let bundle_ready: bool = target.try_get("bundle_ready").map_err(transaction_error)?;
        let target_version: i64 = target.try_get("version").map_err(transaction_error)?;
        let declared_cohort: Option<String> = target.try_get("capture_cohort").map_err(transaction_error)?;
        let max_credentials: i32 = target.try_get("max_credentials").map_err(transaction_error)?;
        let used_credentials: i64 = target.try_get("used_credentials").map_err(transaction_error)?;
        if !matches!(target_state.as_str(), "canary" | "active")
            || !bundle_ready
            || used_credentials >= i64::from(max_credentials)
            || declared_cohort.as_deref() != Some(command.target_capture_cohort.as_str())
            || (target_version < current_version && !command.allow_explicit_rollback)
        {
            return Err(StorageError::InvalidLifecycle);
        }
        let next_profile_epoch = profile_epoch.checked_add(1).ok_or(StorageError::TransactionFailed)?;
        let next_credential_revision = credential_revision
            .checked_add(1)
            .ok_or(StorageError::TransactionFailed)?;
        let profile_id: Uuid = current.try_get("profile_id").map_err(transaction_error)?;
        let device_epoch: i64 = current.try_get("device_epoch").map_err(transaction_error)?;
        let egress_epoch: i64 = current.try_get("egress_epoch").map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.credential_profile SET archetype_version_id=$2,capture_cohort=$3,profile_epoch=$4, \
               lifecycle_code='active',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(profile_id)
        .bind(command.target_archetype_version_id)
        .bind(&command.target_capture_cohort)
        .bind(next_profile_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query("UPDATE gateway.anthropic_credential SET revision=$2,updated_at=clock_timestamp() WHERE id=$1")
            .bind(command.credential_id)
            .bind(next_credential_revision)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        sqlx::query(
            "INSERT INTO gateway.credential_profile_change \
             (id,credential_profile_id,credential_id,from_archetype_version_id,to_archetype_version_id, \
              from_profile_epoch,to_profile_epoch,reason_code,cohort_code,approved_by,change_kind_code, \
              from_device_epoch,to_device_epoch,from_egress_epoch,to_egress_epoch,changed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'cohort',$11,$11,$12,$12,clock_timestamp())",
        )
        .bind(command.change_id)
        .bind(profile_id)
        .bind(command.credential_id)
        .bind(from_archetype)
        .bind(command.target_archetype_version_id)
        .bind(profile_epoch)
        .bind(next_profile_epoch)
        .bind(&command.reason_code)
        .bind(&command.target_capture_cohort)
        .bind(command.approved_by)
        .bind(device_epoch)
        .bind(egress_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            command.credential_id,
            None,
            None,
            "profile_cohort_upgraded",
            next_credential_revision,
            json!({"change_id": command.change_id, "from_archetype_version_id": from_archetype,
                   "to_archetype_version_id": command.target_archetype_version_id,
                   "profile_epoch": next_profile_epoch, "device_epoch": device_epoch,
                   "egress_epoch": egress_epoch, "pool_action": "drain"}),
        )
        .await?;
        if let Some(audit) = audit {
            self.append_audit_outbox_in(&mut transaction, audit).await?;
        }
        transaction.commit().await.map_err(transaction_error)?;
        Ok(ProfileContinuityCommit {
            credential_revision: next_credential_revision,
            profile_epoch: next_profile_epoch,
            device_epoch,
            egress_epoch,
        })
    }

    pub async fn rebuild_device_identity(
        &self,
        command: &DeviceIdentityRebuild,
    ) -> Result<ProfileContinuityCommit, StorageError> {
        let candidate_secret_ids = [
            command.installation_secret_id,
            command.client_secret_id,
            command.profile_seed_secret_id,
            command.session_hmac_secret_id,
        ];
        if command.requested_by == command.approved_by
            || command.reason_code.trim().is_empty()
            || command.installation_digest.is_empty()
            || command.client_digest.is_empty()
        {
            self.destroy_secrets_after_rejected_command(&candidate_secret_ids)
                .await?;
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let result = self.rebuild_device_identity_in(&mut transaction, command, None).await;
        match result {
            Ok(commit) => {
                transaction.commit().await.map_err(transaction_error)?;
                Ok(commit)
            }
            Err(error) => {
                transaction.rollback().await.map_err(transaction_error)?;
                self.destroy_secrets_after_rejected_command(&candidate_secret_ids)
                    .await?;
                Err(error)
            }
        }
    }

    pub async fn rebuild_device_identity_in(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        command: &DeviceIdentityRebuild,
        audit: Option<&AuditOutboxRecord>,
    ) -> Result<ProfileContinuityCommit, StorageError> {
        if command.requested_by == command.approved_by
            || command.reason_code.trim().is_empty()
            || command.installation_digest.is_empty()
            || command.client_digest.is_empty()
        {
            return Err(StorageError::InvalidLifecycle);
        }
        let current = sqlx::query(
            "SELECT c.revision,c.lifecycle_state_code,p.id AS profile_id,p.archetype_version_id,p.profile_epoch, \
                    p.capture_cohort,d.id AS device_id,d.installation_id_secret_id,d.client_id_secret_id, \
                    d.profile_seed_secret_id,d.session_hmac_secret_id,d.device_epoch,b.egress_epoch \
             FROM gateway.anthropic_credential c JOIN gateway.credential_profile p ON p.credential_id=c.id \
             JOIN gateway.device_identity d ON d.id=p.device_identity_id \
             JOIN gateway.credential_egress_binding b ON b.id=p.egress_binding_id \
             WHERE c.id=$1 FOR UPDATE OF c,p,d,b",
        )
        .bind(command.credential_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let credential_revision: i64 = current.try_get("revision").map_err(transaction_error)?;
        let profile_epoch: i64 = current.try_get("profile_epoch").map_err(transaction_error)?;
        let device_epoch: i64 = current.try_get("device_epoch").map_err(transaction_error)?;
        let lifecycle: String = current.try_get("lifecycle_state_code").map_err(transaction_error)?;
        if credential_revision != command.expected_credential_revision
            || profile_epoch != command.expected_profile_epoch
            || device_epoch != command.expected_device_epoch
            || !matches!(lifecycle.as_str(), "active" | "disabled")
        {
            return Err(StorageError::RevisionConflict);
        }
        let old_secret_ids = [
            current
                .try_get("installation_id_secret_id")
                .map_err(transaction_error)?,
            current.try_get("client_id_secret_id").map_err(transaction_error)?,
            current.try_get("profile_seed_secret_id").map_err(transaction_error)?,
            current.try_get("session_hmac_secret_id").map_err(transaction_error)?,
        ];
        let next_device_epoch = device_epoch.checked_add(1).ok_or(StorageError::TransactionFailed)?;
        let next_profile_epoch = profile_epoch.checked_add(1).ok_or(StorageError::TransactionFailed)?;
        let next_credential_revision = credential_revision
            .checked_add(1)
            .ok_or(StorageError::TransactionFailed)?;
        let device_id: Uuid = current.try_get("device_id").map_err(transaction_error)?;
        let profile_id: Uuid = current.try_get("profile_id").map_err(transaction_error)?;
        let archetype_version_id: Uuid = current.try_get("archetype_version_id").map_err(transaction_error)?;
        let cohort: String = current.try_get("capture_cohort").map_err(transaction_error)?;
        let egress_epoch: i64 = current.try_get("egress_epoch").map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.device_identity SET installation_id_secret_id=$2,client_id_secret_id=$3, \
               profile_seed_secret_id=$4,session_hmac_secret_id=$5,installation_id_digest=$6,client_id_digest=$7, \
               device_epoch=$8,revision=revision+1,rebuilt_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(device_id)
        .bind(command.installation_secret_id)
        .bind(command.client_secret_id)
        .bind(command.profile_seed_secret_id)
        .bind(command.session_hmac_secret_id)
        .bind(&command.installation_digest)
        .bind(&command.client_digest)
        .bind(next_device_epoch)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.credential_profile SET profile_epoch=$2,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(profile_id)
        .bind(next_profile_epoch)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query("UPDATE gateway.anthropic_credential SET revision=$2,updated_at=clock_timestamp() WHERE id=$1")
            .bind(command.credential_id)
            .bind(next_credential_revision)
            .execute(&mut **transaction)
            .await
            .map_err(transaction_error)?;
        destroy_secret_ids(transaction, &old_secret_ids).await?;
        sqlx::query(
            "INSERT INTO gateway.credential_profile_change \
             (id,credential_profile_id,credential_id,from_archetype_version_id,to_archetype_version_id, \
              from_profile_epoch,to_profile_epoch,reason_code,cohort_code,approved_by,change_kind_code, \
              from_device_epoch,to_device_epoch,from_egress_epoch,to_egress_epoch,changed_at) \
             VALUES ($1,$2,$3,$4,$4,$5,$6,$7,$8,$9,'device_rebuild',$10,$11,$12,$12,clock_timestamp())",
        )
        .bind(command.change_id)
        .bind(profile_id)
        .bind(command.credential_id)
        .bind(archetype_version_id)
        .bind(profile_epoch)
        .bind(next_profile_epoch)
        .bind(&command.reason_code)
        .bind(&cohort)
        .bind(command.approved_by)
        .bind(device_epoch)
        .bind(next_device_epoch)
        .bind(egress_epoch)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            transaction,
            command.credential_id,
            None,
            None,
            "device_identity_rebuilt",
            next_credential_revision,
            json!({"change_id": command.change_id, "requested_by": command.requested_by,
                   "approved_by": command.approved_by, "profile_epoch": next_profile_epoch,
                   "device_epoch": next_device_epoch, "egress_epoch": egress_epoch,
                   "affinity_action": "clear", "pool_action": "drain"}),
        )
        .await?;
        if let Some(audit) = audit {
            self.append_audit_outbox_in(transaction, audit).await?;
        }
        Ok(ProfileContinuityCommit {
            credential_revision: next_credential_revision,
            profile_epoch: next_profile_epoch,
            device_epoch: next_device_epoch,
            egress_epoch,
        })
    }

    async fn destroy_secrets_after_rejected_command(&self, secret_ids: &[Uuid]) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE security.encrypted_secret SET superseded_at=COALESCE(superseded_at,clock_timestamp()), \
               destroyed_at=clock_timestamp(),ciphertext='\\x'::bytea,wrapped_dek='\\x'::bytea \
             WHERE id=ANY($1) AND destroyed_at IS NULL",
        )
        .bind(secret_ids)
        .execute(&self.pool)
        .await
        .map_err(transaction_error)?;
        Ok(())
    }

    pub async fn disable_credential(&self, command: &CredentialLifecycleCommand) -> Result<i64, StorageError> {
        self.disable_credential_internal(command, None).await
    }

    pub async fn disable_credential_with_audit(
        &self,
        command: &CredentialLifecycleCommand,
        audit: &AuditOutboxRecord,
    ) -> Result<i64, StorageError> {
        self.disable_credential_internal(command, Some(audit)).await
    }

    async fn disable_credential_internal(
        &self,
        command: &CredentialLifecycleCommand,
        audit: Option<&AuditOutboxRecord>,
    ) -> Result<i64, StorageError> {
        validate_lifecycle_command(command)?;
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let next_revision: Option<i64> = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET lifecycle_state_code='disabled',scheduling_state_code='blocked', \
               revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND lifecycle_state_code='active' RETURNING revision",
        )
        .bind(command.credential_id)
        .bind(command.expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let next_revision = next_revision.ok_or(StorageError::RevisionConflict)?;
        append_credential_event(
            &mut transaction,
            command.credential_id,
            None,
            None,
            "credential_disabled",
            next_revision,
            json!({"actor_id": command.actor_id, "reason_code": command.reason_code}),
        )
        .await?;
        if let Some(audit) = audit {
            self.append_audit_outbox_in(&mut transaction, audit).await?;
        }
        transaction.commit().await.map_err(transaction_error)?;
        Ok(next_revision)
    }

    pub async fn reactivate_credential(&self, command: &CredentialLifecycleCommand) -> Result<i64, StorageError> {
        self.reactivate_credential_internal(command, None).await
    }

    pub async fn reactivate_credential_with_audit(
        &self,
        command: &CredentialLifecycleCommand,
        audit: &AuditOutboxRecord,
    ) -> Result<i64, StorageError> {
        self.reactivate_credential_internal(command, Some(audit)).await
    }

    async fn reactivate_credential_internal(
        &self,
        command: &CredentialLifecycleCommand,
        audit: Option<&AuditOutboxRecord>,
    ) -> Result<i64, StorageError> {
        validate_lifecycle_command(command)?;
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let row = sqlx::query(
            "SELECT c.revision,c.lifecycle_state_code,c.auth_state_code,c.management_class_code,c.active_auth_version_id, \
                    c.attachment_state_code,g.status_code AS group_state,p.lifecycle_code AS profile_state, \
                    b.lifecycle_code AS egress_state,version.lifecycle_code AS archetype_state,bundle.lifecycle_code AS bundle_state \
             FROM gateway.anthropic_credential c JOIN gateway.credential_group g ON g.id=c.group_id \
             JOIN gateway.credential_profile p ON p.credential_id=c.id \
             JOIN gateway.credential_egress_binding b ON b.id=p.egress_binding_id \
             JOIN catalog.environment_archetype_version version ON version.id=p.archetype_version_id \
             JOIN catalog.archetype_bundle_binding pointer ON pointer.archetype_version_id=version.id AND pointer.state_code='active' \
             JOIN catalog.transport_bundle bundle ON bundle.id=pointer.transport_bundle_id \
             WHERE c.id=$1 FOR UPDATE OF c,p,b",
        )
        .bind(command.credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let revision: i64 = row.try_get("revision").map_err(transaction_error)?;
        let management: String = row.try_get("management_class_code").map_err(transaction_error)?;
        let strategy_healthy: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM gateway.auto_reauth_strategy WHERE credential_id=$1 \
             AND strategy_kind_code='managed_browser_session' AND state_code='healthy')",
        )
        .bind(command.credential_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let ready = revision == command.expected_revision
            && row.try_get::<String, _>("lifecycle_state_code").ok().as_deref() == Some("disabled")
            && row.try_get::<String, _>("auth_state_code").ok().as_deref() == Some("healthy")
            && row
                .try_get::<Option<Uuid>, _>("active_auth_version_id")
                .ok()
                .flatten()
                .is_some()
            && row.try_get::<String, _>("attachment_state_code").ok().as_deref() == Some("attached")
            && row.try_get::<String, _>("group_state").ok().as_deref() == Some("active")
            && row.try_get::<String, _>("profile_state").ok().as_deref() == Some("active")
            && row.try_get::<String, _>("egress_state").ok().as_deref() == Some("active")
            && row
                .try_get::<String, _>("archetype_state")
                .ok()
                .is_some_and(|state| matches!(state.as_str(), "canary" | "active"))
            && row
                .try_get::<String, _>("bundle_state")
                .ok()
                .is_some_and(|state| matches!(state.as_str(), "canary" | "active"))
            && (management != "fully_managed" || strategy_healthy);
        if !ready {
            return Err(StorageError::InvalidLifecycle);
        }
        let next_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET lifecycle_state_code='active',scheduling_state_code='eligible', \
             transport_state_code='ready',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
        )
        .bind(command.credential_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            command.credential_id,
            None,
            None,
            "credential_reactivated",
            next_revision,
            json!({"actor_id": command.actor_id, "reason_code": command.reason_code}),
        )
        .await?;
        if let Some(audit) = audit {
            self.append_audit_outbox_in(&mut transaction, audit).await?;
        }
        transaction.commit().await.map_err(transaction_error)?;
        Ok(next_revision)
    }

    pub async fn revoke_credential(&self, command: &CredentialLifecycleCommand) -> Result<i64, StorageError> {
        self.revoke_credential_internal(command, None).await
    }

    pub async fn revoke_credential_with_audit(
        &self,
        command: &CredentialLifecycleCommand,
        audit: &AuditOutboxRecord,
    ) -> Result<i64, StorageError> {
        self.revoke_credential_internal(command, Some(audit)).await
    }

    async fn revoke_credential_internal(
        &self,
        command: &CredentialLifecycleCommand,
        audit: Option<&AuditOutboxRecord>,
    ) -> Result<i64, StorageError> {
        validate_lifecycle_command(command)?;
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let next_revision: Option<i64> = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET lifecycle_state_code='revoked',scheduling_state_code='blocked', \
               auth_state_code='auth_broken',revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND lifecycle_state_code IN \
               ('pending_verify','pending_profile','pending_egress','pending_reauth_strategy','active','disabled') \
             RETURNING revision",
        )
        .bind(command.credential_id)
        .bind(command.expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let next_revision = next_revision.ok_or(StorageError::RevisionConflict)?;
        append_credential_event(
            &mut transaction,
            command.credential_id,
            None,
            None,
            "credential_revoked",
            next_revision,
            json!({"actor_id": command.actor_id, "reason_code": command.reason_code,
                   "secret_cleanup": "after_lease_and_maintenance_drain"}),
        )
        .await?;
        if let Some(audit) = audit {
            self.append_audit_outbox_in(&mut transaction, audit).await?;
        }
        transaction.commit().await.map_err(transaction_error)?;
        Ok(next_revision)
    }

    pub async fn finalize_revoked_credential(
        &self,
        credential_id: Uuid,
        expected_revision: i64,
        active_leases: u32,
    ) -> Result<(), StorageError> {
        if active_leases != 0 {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let active_operations: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM gateway.maintenance_operation WHERE credential_id=$1 AND state_code IN \
             ('planned','leased','running','verifying_account','committing','waiting_backoff','waiting_egress','needs_attention')",
        )
        .bind(credential_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let lifecycle: Option<String> = sqlx::query_scalar(
            "SELECT lifecycle_state_code FROM gateway.anthropic_credential \
             WHERE id=$1 AND revision=$2 FOR UPDATE",
        )
        .bind(credential_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if lifecycle.as_deref() != Some("revoked") || active_operations != 0 {
            return Err(StorageError::InvalidLifecycle);
        }
        destroy_all_credential_secrets(&mut transaction, credential_id).await?;
        sqlx::query(
            "UPDATE gateway.credential_auth_version SET material_state_code='destroyed' \
             WHERE credential_id=$1 AND material_state_code IN ('candidate','active','superseded')",
        )
        .bind(credential_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE gateway.managed_browser_material_version SET state_code='destroyed',superseded_at=COALESCE(superseded_at,clock_timestamp()) \
             WHERE credential_id=$1 AND state_code IN ('candidate','active','superseded','invalid')",
        )
        .bind(credential_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            credential_id,
            None,
            None,
            "credential_revoke_finalized",
            expected_revision,
            json!({"secrets": "destroyed"}),
        )
        .await?;
        transaction.commit().await.map_err(transaction_error)
    }

    pub async fn archive_credential(
        &self,
        command: &CredentialLifecycleCommand,
        active_leases: u32,
    ) -> Result<i64, StorageError> {
        self.archive_credential_internal(command, active_leases, None).await
    }

    pub async fn archive_credential_with_audit(
        &self,
        command: &CredentialLifecycleCommand,
        active_leases: u32,
        audit: &AuditOutboxRecord,
    ) -> Result<i64, StorageError> {
        self.archive_credential_internal(command, active_leases, Some(audit))
            .await
    }

    async fn archive_credential_internal(
        &self,
        command: &CredentialLifecycleCommand,
        active_leases: u32,
        audit: Option<&AuditOutboxRecord>,
    ) -> Result<i64, StorageError> {
        validate_lifecycle_command(command)?;
        if active_leases != 0 {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let blockers: i64 = sqlx::query_scalar(
            "SELECT \
               (SELECT count(*) FROM gateway.maintenance_operation WHERE credential_id=$1 AND state_code IN \
                 ('planned','leased','running','verifying_account','committing','waiting_backoff','waiting_egress','needs_attention')) + \
               (SELECT count(*) FROM gateway.credential_group_migration WHERE credential_id=$1 AND state_code IN ('draining','committing'))",
        )
        .bind(command.credential_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if blockers != 0 {
            return Err(StorageError::InvalidLifecycle);
        }
        let next_revision: Option<i64> = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET lifecycle_state_code='archived',scheduling_state_code='blocked', \
               attachment_state_code='detached',revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND lifecycle_state_code IN ('disabled','revoked') RETURNING revision",
        )
        .bind(command.credential_id)
        .bind(command.expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let next_revision = next_revision.ok_or(StorageError::RevisionConflict)?;
        destroy_all_credential_secrets(&mut transaction, command.credential_id).await?;
        sqlx::query("UPDATE gateway.credential_profile SET lifecycle_code='disabled',updated_at=clock_timestamp() WHERE credential_id=$1")
            .bind(command.credential_id)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        sqlx::query("UPDATE gateway.credential_egress_binding SET lifecycle_code='disabled',updated_at=clock_timestamp() WHERE credential_id=$1")
            .bind(command.credential_id)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        append_credential_event(
            &mut transaction,
            command.credential_id,
            None,
            None,
            "credential_archived",
            next_revision,
            json!({"actor_id": command.actor_id, "reason_code": command.reason_code,
                   "account_uuid_tombstone": "retained"}),
        )
        .await?;
        if let Some(audit) = audit {
            self.append_audit_outbox_in(&mut transaction, audit).await?;
        }
        transaction.commit().await.map_err(transaction_error)?;
        Ok(next_revision)
    }

    pub async fn commit_plan_observation(&self, command: &PlanObservationCommit) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        insert_plan_observation_in(&mut transaction, command).await?;
        transaction.commit().await.map_err(transaction_error)
    }

    pub async fn commit_plan_observation_with_job(
        &self,
        command: &PlanObservationCommit,
        fence: &PlanObservationFence,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM gateway.anthropic_credential credential \
             JOIN gateway.credential_auth_version auth ON auth.id=credential.active_auth_version_id \
               AND auth.credential_id=credential.id AND auth.material_state_code='active' \
             JOIN gateway.credential_provider_profile provider ON provider.id=credential.provider_profile_id \
               AND provider.lifecycle_code='active' \
             JOIN gateway.credential_egress_binding binding ON binding.id=$5 AND binding.credential_id=credential.id \
               AND binding.lifecycle_code='active' AND binding.stability_code='stable' \
             WHERE credential.id=$1 AND credential.revision=$2 AND credential.token_version=$3 \
               AND credential.provider_profile_id=$4 AND auth.token_version=$3 \
               AND binding.egress_epoch=$6 AND credential.lifecycle_state_code NOT IN ('revoked','archived'))",
        )
        .bind(command.credential_id)
        .bind(fence.credential_revision)
        .bind(fence.token_version)
        .bind(fence.provider_profile_id)
        .bind(fence.egress_binding_id)
        .bind(fence.egress_epoch)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if !valid {
            return Err(StorageError::RevisionConflict);
        }
        let leased: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ops.durable_job WHERE id=$1 \
             AND kind_code='credential_plan_collect_v1' AND state_code='leased' AND lease_generation=$2 FOR UPDATE)",
        )
        .bind(fence.job_id)
        .bind(fence.job_generation)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if !leased {
            return Err(StorageError::RevisionConflict);
        }
        insert_plan_observation_in(&mut transaction, command).await?;
        let completed = sqlx::query(
            "UPDATE ops.durable_job SET state_code='succeeded',checkpoint=$3,lease_owner=NULL,lease_expires_at=NULL, \
               updated_at=clock_timestamp(),completed_at=clock_timestamp() \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
        )
        .bind(fence.job_id)
        .bind(fence.job_generation)
        .bind(
            json!({"phase":"observation_committed","observation_id":command.observation_id,
          "outcome":if command.success {"success"} else {"failed"}}),
        )
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if completed.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,'leased','succeeded',$3,$4,jsonb_build_object('observation_id',$5::uuid),clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(fence.job_id)
        .bind(fence.job_generation)
        .bind(if command.success {
            "plan_observed"
        } else {
            "plan_collection_failed_observed"
        })
        .bind(command.observation_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)
    }
}

async fn insert_plan_observation_in(
    transaction: &mut Transaction<'_, Postgres>,
    command: &PlanObservationCommit,
) -> Result<(), StorageError> {
    let freshness = if command.source == "not_applicable" {
        "not_applicable"
    } else if command.success {
        "fresh"
    } else {
        "unknown"
    };
    sqlx::query(
            "INSERT INTO telemetry.subscription_plan_observation \
             (id,credential_id,source_code,raw_plan_code,normalized_plan_code,freshness_code,observed_at,expires_at, \
              raw_redacted,raw_digest,temporary_display_name,normalized_at,attempt_outcome_code,failure_category_code, \
              failure_summary,attempted_at,mapping_version,mapping_artifact_id,adapter_version) \
             VALUES ($1,$2,$3,$4,$5,$6,clock_timestamp(),CASE WHEN $7 THEN clock_timestamp()+interval '48 hours' ELSE NULL END, \
                     $8,$9,$10,CASE WHEN $7 THEN clock_timestamp() ELSE NULL END,CASE WHEN $7 THEN 'success' ELSE 'failed' END, \
                     $11,$12,clock_timestamp(),$13,$14,$15)",
        )
        .bind(command.observation_id)
        .bind(command.credential_id)
        .bind(&command.source)
        .bind(&command.raw_plan_code)
        .bind(&command.normalized_plan_code)
        .bind(freshness)
        .bind(command.success)
        .bind(&command.raw_redacted)
        .bind(&command.raw_digest)
        .bind(&command.temporary_display_name)
        .bind(&command.failure_category)
        .bind(&command.failure_summary)
        .bind(command.mapping_version)
        .bind(command.mapping_artifact_id)
        .bind(&command.adapter_version)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
    if command.success {
        sqlx::query(
                "INSERT INTO telemetry.subscription_plan_current \
                 (credential_id,observation_id,normalized_plan_code,freshness_code,observed_at,expires_at,revision, \
                  last_attempted_at,last_refresh_failed,temporary_display_name,billing_mode_code) \
                 VALUES ($1,$2,$3,$4,clock_timestamp(),CASE WHEN $4='not_applicable' THEN NULL ELSE clock_timestamp()+interval '48 hours' END, \
                         1,clock_timestamp(),false,$5,CASE WHEN $4='not_applicable' THEN 'api_payg' ELSE 'subscription' END) \
                 ON CONFLICT (credential_id) DO UPDATE SET observation_id=EXCLUDED.observation_id, \
                  normalized_plan_code=EXCLUDED.normalized_plan_code,freshness_code=EXCLUDED.freshness_code, \
                  observed_at=EXCLUDED.observed_at,expires_at=EXCLUDED.expires_at,revision=telemetry.subscription_plan_current.revision+1, \
                  last_attempted_at=EXCLUDED.last_attempted_at,last_refresh_failed=false,last_failure_at=NULL, \
                  last_failure_category_code=NULL,temporary_display_name=EXCLUDED.temporary_display_name, \
                  billing_mode_code=EXCLUDED.billing_mode_code",
            )
            .bind(command.credential_id)
            .bind(command.observation_id)
            .bind(&command.normalized_plan_code)
            .bind(freshness)
            .bind(&command.temporary_display_name)
            .execute(&mut **transaction)
            .await
            .map_err(transaction_error)?;
    } else {
        sqlx::query(
                "INSERT INTO telemetry.subscription_plan_current \
                 (credential_id,observation_id,normalized_plan_code,freshness_code,observed_at,expires_at,revision, \
                  last_attempted_at,last_refresh_failed,last_failure_at,last_failure_category_code,temporary_display_name,billing_mode_code) \
                 VALUES ($1,$2,'unknown','unknown',clock_timestamp(),NULL,1,clock_timestamp(),true,clock_timestamp(),$3,NULL,'subscription') \
                 ON CONFLICT (credential_id) DO UPDATE SET last_attempted_at=clock_timestamp(),last_refresh_failed=true, \
                  last_failure_at=clock_timestamp(),last_failure_category_code=$3, \
                  revision=telemetry.subscription_plan_current.revision+1",
            )
            .bind(command.credential_id)
            .bind(command.observation_id)
            .bind(&command.failure_category)
            .execute(&mut **transaction)
            .await
            .map_err(transaction_error)?;
    }
    Ok(())
}

impl PgStorage {
    pub async fn create_plan_mapping_artifact(&self, command: &PlanMappingArtifactCreate) -> Result<(), StorageError> {
        validate_plan_mappings(&command.mappings)?;
        if command.artifact_version < 1 || command.content_hash.len() != 32 {
            return Err(StorageError::InvalidLifecycle);
        }
        sqlx::query(
            "INSERT INTO catalog.versioned_artifact \
             (id,artifact_kind_code,scope_type_code,scope_id,artifact_version,lifecycle_code,payload,content_hash, \
              schema_version,created_by,created_at) \
             VALUES ($1,'plan_mapping',NULL,NULL,$2,'eligible',$3,$4,1,$5,clock_timestamp())",
        )
        .bind(command.artifact_id)
        .bind(command.artifact_version)
        .bind(json!({"mappings": command.mappings}))
        .bind(&command.content_hash)
        .bind(command.created_by)
        .execute(&self.pool)
        .await
        .map_err(transaction_error)?;
        Ok(())
    }

    pub async fn activate_plan_mapping(
        &self,
        command: &PlanMappingActivation,
    ) -> Result<PlanMappingActivationCommit, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let target = sqlx::query(
            "SELECT artifact_version,lifecycle_code FROM catalog.versioned_artifact \
             WHERE id=$1 AND artifact_kind_code='plan_mapping' AND scope_type_code IS NULL AND scope_id IS NULL FOR UPDATE",
        )
        .bind(command.artifact_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let target_state: String = target.try_get("lifecycle_code").map_err(transaction_error)?;
        if !matches!(target_state.as_str(), "eligible" | "canary" | "active") {
            return Err(StorageError::InvalidLifecycle);
        }
        let pointer = sqlx::query(
            "SELECT id,artifact_id,revision FROM catalog.active_artifact_pointer \
             WHERE artifact_kind_code='plan_mapping' AND scope_type_code IS NULL AND scope_id IS NULL FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let pointer_revision = if let Some(pointer) = pointer {
            let current_revision: i64 = pointer.try_get("revision").map_err(transaction_error)?;
            if command.expected_pointer_revision != Some(current_revision) {
                return Err(StorageError::RevisionConflict);
            }
            let previous_artifact: Uuid = pointer.try_get("artifact_id").map_err(transaction_error)?;
            if previous_artifact != command.artifact_id {
                sqlx::query(
                    "UPDATE catalog.versioned_artifact SET lifecycle_code='eligible' \
                         WHERE id=$1 AND lifecycle_code='active'",
                )
                .bind(previous_artifact)
                .execute(&mut *transaction)
                .await
                .map_err(transaction_error)?;
            }
            let next = current_revision.checked_add(1).ok_or(StorageError::TransactionFailed)?;
            sqlx::query(
                "UPDATE catalog.active_artifact_pointer SET artifact_id=$2,revision=$3,activated_by=$4, \
                       activated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(pointer.try_get::<Uuid, _>("id").map_err(transaction_error)?)
            .bind(command.artifact_id)
            .bind(next)
            .bind(command.activated_by)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            next
        } else {
            if command.expected_pointer_revision.is_some() {
                return Err(StorageError::RevisionConflict);
            }
            sqlx::query(
                "INSERT INTO catalog.active_artifact_pointer \
                     (id,artifact_kind_code,scope_type_code,scope_id,artifact_id,revision,activated_by,activated_at) \
                     VALUES ($1,'plan_mapping',NULL,NULL,$2,1,$3,clock_timestamp())",
            )
            .bind(command.pointer_id)
            .bind(command.artifact_id)
            .bind(command.activated_by)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            1
        };
        sqlx::query("UPDATE catalog.versioned_artifact SET lifecycle_code='active' WHERE id=$1")
            .bind(command.artifact_id)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        sqlx::query(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'plan_mapping_recompute',$2,'scheduled',1,$3,clock_timestamp(),0,0,8,clock_timestamp(),clock_timestamp())",
        )
        .bind(command.recompute_job_id)
        .bind(format!("plan-mapping:{}:{pointer_revision}", command.artifact_id))
        .bind(json!({"mapping_artifact_id": command.artifact_id, "pointer_revision": pointer_revision}))
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)?;
        Ok(PlanMappingActivationCommit {
            pointer_revision,
            recompute_job_id: command.recompute_job_id,
        })
    }

    pub async fn recompute_plan_mapping(
        &self,
        artifact_id: Uuid,
        job_generation: i64,
    ) -> Result<PlanMappingRecomputeCommit, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let artifact = sqlx::query(
            "SELECT artifact_version,payload FROM catalog.versioned_artifact artifact \
             JOIN catalog.active_artifact_pointer pointer ON pointer.artifact_id=artifact.id \
             WHERE artifact.id=$1 AND artifact.artifact_kind_code='plan_mapping' \
               AND pointer.artifact_kind_code='plan_mapping' FOR SHARE OF artifact,pointer",
        )
        .bind(artifact_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::RevisionConflict)?;
        let artifact_version: i64 = artifact.try_get("artifact_version").map_err(transaction_error)?;
        let payload: Value = artifact.try_get("payload").map_err(transaction_error)?;
        let mappings = payload.get("mappings").cloned().ok_or(StorageError::InvalidLifecycle)?;
        validate_plan_mappings(&mappings)?;
        let affected_observations = i64::try_from(
            sqlx::query(
                "UPDATE telemetry.subscription_plan_observation observation SET \
               normalized_plan_code=COALESCE(($2::jsonb->>observation.raw_plan_code),'unknown'), \
               mapping_version=$3,mapping_artifact_id=$1,normalized_at=clock_timestamp() \
             WHERE observation.source_code<>'not_applicable' AND observation.raw_plan_code IS NOT NULL",
            )
            .bind(artifact_id)
            .bind(&mappings)
            .bind(artifact_version)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?
            .rows_affected(),
        )
        .map_err(|_| StorageError::TransactionFailed)?;
        let affected_credentials = i64::try_from(
            sqlx::query(
                "UPDATE telemetry.subscription_plan_current current SET \
               normalized_plan_code=observation.normalized_plan_code,mapping_artifact_id=$1, \
               temporary_display_name=CASE WHEN observation.normalized_plan_code='unknown' \
                 THEN current.temporary_display_name ELSE NULL END,revision=current.revision+1 \
             FROM telemetry.subscription_plan_observation observation \
             WHERE observation.id=current.observation_id AND observation.source_code<>'not_applicable'",
            )
            .bind(artifact_id)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?
            .rows_affected(),
        )
        .map_err(|_| StorageError::TransactionFailed)?;
        let job_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM ops.durable_job WHERE kind_code='plan_mapping_recompute' \
             AND payload->>'mapping_artifact_id'=$1 AND state_code='leased' AND lease_generation=$2 FOR UPDATE",
        )
        .bind(artifact_id.to_string())
        .bind(job_generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if let Some(job_id) = job_id {
            let completed = sqlx::query(
                "UPDATE ops.durable_job SET state_code='succeeded',lease_owner=NULL,lease_expires_at=NULL, \
                    updated_at=clock_timestamp(),completed_at=clock_timestamp() WHERE id=$1 AND lease_generation=$2",
            )
            .bind(job_id)
            .bind(job_generation)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            if completed.rows_affected() != 1 {
                return Err(StorageError::RevisionConflict);
            }
            sqlx::query(
                "INSERT INTO ops.durable_job_history \
                 (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
                 VALUES ($1,$2,'leased','succeeded',$3,'plan_mapping_recomputed', \
                   jsonb_build_object('artifact_id',$4,'affected_observations',$5,'affected_credentials',$6), \
                   clock_timestamp())",
            )
            .bind(Uuid::now_v7())
            .bind(job_id)
            .bind(job_generation)
            .bind(artifact_id)
            .bind(affected_observations)
            .bind(affected_credentials)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        } else {
            return Err(StorageError::RevisionConflict);
        }
        transaction.commit().await.map_err(transaction_error)?;
        Ok(PlanMappingRecomputeCommit {
            affected_observations,
            affected_credentials,
        })
    }
}

fn validate_plan_mappings(mappings: &Value) -> Result<(), StorageError> {
    let object = mappings.as_object().ok_or(StorageError::InvalidLifecycle)?;
    if object.len() > 1_000
        || object.iter().any(|(raw, normalized)| {
            raw.is_empty()
                || raw.len() > 256
                || normalized
                    .as_str()
                    .is_none_or(|value| value.is_empty() || value.len() > 128)
        })
    {
        return Err(StorageError::InvalidLifecycle);
    }
    Ok(())
}

fn validate_lifecycle_command(command: &CredentialLifecycleCommand) -> Result<(), StorageError> {
    if command.expected_revision < 1 || command.reason_code.trim().is_empty() {
        return Err(StorageError::InvalidLifecycle);
    }
    Ok(())
}

async fn destroy_all_credential_secrets(
    transaction: &mut Transaction<'_, Postgres>,
    credential_id: Uuid,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE security.encrypted_secret SET superseded_at=COALESCE(superseded_at,clock_timestamp()), \
         destroyed_at=clock_timestamp(),ciphertext='\\x'::bytea,wrapped_dek='\\x'::bytea \
         WHERE owner_type_code='credential' AND owner_id=$1 AND destroyed_at IS NULL",
    )
    .bind(credential_id.to_string())
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    Ok(())
}

async fn load_active_operation(
    transaction: &mut Transaction<'_, Postgres>,
    credential_id: Uuid,
    conflict_class: &str,
) -> Result<Option<(Uuid, String, i64)>, StorageError> {
    let row = sqlx::query(
        "SELECT id,state_code,operation_generation FROM gateway.maintenance_operation \
         WHERE credential_id=$1 AND conflict_class_code=$2 \
           AND state_code IN ('planned','leased','running','verifying_account','committing','waiting_backoff','waiting_egress','needs_attention') \
         FOR UPDATE",
    )
    .bind(credential_id)
    .bind(conflict_class)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    row.map(|row| {
        Ok((
            row.try_get("id").map_err(transaction_error)?,
            row.try_get("state_code").map_err(transaction_error)?,
            row.try_get("operation_generation").map_err(transaction_error)?,
        ))
    })
    .transpose()
}

async fn cleanup_pending_credential(
    transaction: &mut Transaction<'_, Postgres>,
    enrollment_id: Uuid,
    credential_id: Uuid,
    terminal_state: &str,
    error_code: &str,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE gateway.credential_enrollment SET state_code=$3,next_action_code='none',error_code=$2, \
         pending_credential_id=NULL,egress_binding_id=NULL,egress_epoch=NULL,revision=revision+1, \
         updated_at=clock_timestamp() WHERE id=$1",
    )
    .bind(enrollment_id)
    .bind(error_code)
    .bind(terminal_state)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    sqlx::query(
        "UPDATE security.encrypted_secret SET superseded_at=COALESCE(superseded_at,clock_timestamp()),destroyed_at=clock_timestamp(), \
         ciphertext='\\x'::bytea,wrapped_dek='\\x'::bytea \
         WHERE owner_type_code IN ('credential','enrollment','credential_enrollment') \
         AND owner_id IN ($1,$2) AND destroyed_at IS NULL",
    )
    .bind(credential_id.to_string())
    .bind(enrollment_id.to_string())
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    sqlx::query("DELETE FROM gateway.credential_egress_binding WHERE credential_id=$1")
        .bind(credential_id)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
    sqlx::query("DELETE FROM gateway.credential_active_scheduling_config WHERE credential_id=$1")
        .bind(credential_id)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
    sqlx::query("DELETE FROM gateway.credential_scheduling_config WHERE credential_id=$1")
        .bind(credential_id)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
    sqlx::query("DELETE FROM gateway.anthropic_credential WHERE id=$1 AND account_uuid IS NULL")
        .bind(credential_id)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
    Ok(())
}

async fn require_durable_job_fence(
    transaction: &mut Transaction<'_, Postgres>,
    fence: Option<&DurableJobFence>,
) -> Result<(), StorageError> {
    let Some(fence) = fence else {
        return Ok(());
    };
    let leased = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM ops.durable_job WHERE id=$1 AND kind_code=$2 AND state_code='leased' \
         AND lease_generation=$3 AND lease_expires_at>=clock_timestamp() FOR SHARE",
    )
    .bind(fence.job_id)
    .bind(&fence.kind)
    .bind(fence.generation)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    if leased != Some(fence.job_id) {
        return Err(StorageError::RevisionConflict);
    }
    Ok(())
}

async fn destroy_candidate(
    transaction: &mut Transaction<'_, Postgres>,
    candidate: &AuthCandidateRecord,
) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM gateway.credential_auth_version WHERE id=$1 AND material_state_code='candidate'")
        .bind(candidate.auth_version_id)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
    let secret_ids: Vec<Uuid> = [
        candidate.access_secret_id,
        candidate.refresh_secret_id,
        candidate.console_secret_id,
    ]
    .into_iter()
    .flatten()
    .collect();
    sqlx::query(
        "UPDATE security.encrypted_secret s SET superseded_at=COALESCE(s.superseded_at,clock_timestamp()), \
         destroyed_at=clock_timestamp(),ciphertext='\\x'::bytea,wrapped_dek='\\x'::bytea \
         WHERE s.id=ANY($1) AND s.destroyed_at IS NULL AND NOT EXISTS ( \
           SELECT 1 FROM gateway.credential_auth_version v \
           WHERE v.material_state_code IN ('active','superseded') \
             AND s.id IN (v.access_secret_id,v.refresh_secret_id,v.console_secret_id))",
    )
    .bind(&secret_ids)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    Ok(())
}

async fn destroy_browser_candidate(
    transaction: &mut Transaction<'_, Postgres>,
    candidate: &BrowserMaterialCandidate,
) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM gateway.managed_browser_material_version WHERE id=$1 AND state_code='candidate'")
        .bind(candidate.material_version_id)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
    let secret_ids: Vec<Uuid> = [
        Some(candidate.cookie_secret_id),
        candidate.storage_secret_id,
        Some(candidate.profile_secret_id),
    ]
    .into_iter()
    .flatten()
    .collect();
    destroy_secret_ids(transaction, &secret_ids).await
}

async fn destroy_secret_ids(
    transaction: &mut Transaction<'_, Postgres>,
    secret_ids: &[Uuid],
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE security.encrypted_secret SET superseded_at=COALESCE(superseded_at,clock_timestamp()),destroyed_at=clock_timestamp(), \
         ciphertext='\\x'::bytea,wrapped_dek='\\x'::bytea WHERE id=ANY($1) AND destroyed_at IS NULL",
    )
    .bind(secret_ids)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    Ok(())
}

pub(crate) async fn append_credential_event(
    transaction: &mut Transaction<'_, Postgres>,
    credential_id: Uuid,
    enrollment_id: Option<Uuid>,
    operation_id: Option<Uuid>,
    action: &str,
    revision: i64,
    detail: Value,
) -> Result<(), StorageError> {
    append_credential_event_with_outcome(
        transaction,
        credential_id,
        enrollment_id,
        operation_id,
        action,
        revision,
        detail,
        "success",
    )
    .await
}

async fn append_credential_event_with_outcome(
    transaction: &mut Transaction<'_, Postgres>,
    credential_id: Uuid,
    enrollment_id: Option<Uuid>,
    operation_id: Option<Uuid>,
    action: &str,
    revision: i64,
    detail: Value,
    outcome: &str,
) -> Result<(), StorageError> {
    if !matches!(outcome, "success" | "denied" | "failed") {
        return Err(StorageError::InvalidLifecycle);
    }
    let lifecycle_event_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO gateway.credential_lifecycle_event \
         (id,credential_id,enrollment_id,operation_id,event_kind_code,aggregate_revision,redacted_detail,occurred_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp())",
    )
    .bind(lifecycle_event_id)
    .bind(credential_id)
    .bind(enrollment_id)
    .bind(operation_id)
    .bind(action)
    .bind(revision)
    .bind(&detail)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    let audit_id = Uuid::now_v7();
    let canonical = json!({
        "action": action,
        "actor": "system",
        "credential_id": credential_id,
        "detail": detail,
        "outcome": outcome,
        "revision": revision
    });
    let event_day: String = sqlx::query_scalar("SELECT CURRENT_DATE::text")
        .fetch_one(&mut **transaction)
        .await
        .map_err(transaction_error)?;
    sqlx::query(
        "INSERT INTO security.audit_chain_head (event_day,event_count,last_sequence,updated_at) \
         VALUES ($1::date,0,0,clock_timestamp()) ON CONFLICT (event_day) DO NOTHING",
    )
    .bind(&event_day)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    let head = sqlx::query(
        "SELECT last_sequence,last_event_hash FROM security.audit_chain_head WHERE event_day=$1::date FOR UPDATE",
    )
    .bind(&event_day)
    .fetch_one(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    let sequence: i64 = head
        .try_get::<i64, _>("last_sequence")
        .map_err(transaction_error)?
        .checked_add(1)
        .ok_or(StorageError::TransactionFailed)?;
    let previous: Option<Vec<u8>> = head.try_get("last_event_hash").map_err(transaction_error)?;
    let bytes = canonical_json_bytes(&canonical)?;
    let hash = audit_hash(&event_day, sequence, &bytes, previous.as_deref());
    sqlx::query(
        "INSERT INTO security.audit_event \
         (event_day,event_id,daily_sequence,actor_type_code,action_code,object_type_code,object_id,outcome_code, \
          canonical_redacted_event,previous_hash,event_hash,occurred_at) \
         VALUES ($1::date,$2,$3,'system',$4,'anthropic_credential',$5,$6,$7,$8,$9,clock_timestamp())",
    )
    .bind(&event_day)
    .bind(audit_id)
    .bind(sequence)
    .bind(action)
    .bind(credential_id.to_string())
    .bind(outcome)
    .bind(&canonical)
    .bind(&previous)
    .bind(hash.as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    sqlx::query(
        "UPDATE security.audit_chain_head SET event_count=$2,last_sequence=$2,last_event_hash=$3,updated_at=clock_timestamp() \
         WHERE event_day=$1::date",
    )
    .bind(&event_day)
    .bind(sequence)
    .bind(hash.as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    sqlx::query(
        "INSERT INTO ops.outbox_message \
         (id,event_id,topic_code,aggregate_type,aggregate_id,aggregate_revision,payload_schema_version,payload,state_code, \
          lease_generation,attempt_count,available_at,created_at) \
         VALUES ($1,$2,$3,'anthropic_credential',$4,$5,1,$6,'pending',0,0,clock_timestamp(),clock_timestamp())",
    )
    .bind(Uuid::now_v7())
    .bind(audit_id)
    .bind(format!("credential.{action}"))
    .bind(credential_id)
    .bind(revision)
    .bind(json!({"credential_id": credential_id, "event": action, "revision": revision}))
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    Ok(())
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, StorageError> {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort_unstable();
                Value::Object(keys.into_iter().map(|key| (key.clone(), sort(&map[key]))).collect())
            }
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            scalar => scalar.clone(),
        }
    }
    serde_json::to_vec(&sort(value)).map_err(|_| StorageError::TransactionFailed)
}

fn audit_hash(day: &str, sequence: i64, canonical: &[u8], previous: Option<&[u8]>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gateway-audit-event-v1");
    digest.update(day.as_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update(canonical);
    if let Some(previous) = previous {
        digest.update(previous);
    }
    digest.finalize().into()
}

fn masked_account(account: Uuid) -> String {
    let value = account.simple().to_string();
    format!("{}...{}", &value[..6], &value[value.len() - 4..])
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.code().as_deref() == Some("23505"))
}

fn map_capacity_error(error: sqlx::Error) -> StorageError {
    if is_unique_violation(&error) {
        StorageError::CapacityExceeded
    } else {
        transaction_error(error)
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the function is passed directly to Result::map_err"
)]
fn transaction_error(error: sqlx::Error) -> StorageError {
    tracing::error!(error = %error, "credential persistence command failed");
    StorageError::TransactionFailed
}

const fn enrollment_mode_code(value: EnrollmentMode) -> &'static str {
    match value {
        EnrollmentMode::Create => "create",
        EnrollmentMode::Recover => "recover",
    }
}

const fn enrollment_auth_method_code(value: EnrollmentAuthMethod) -> &'static str {
    match value {
        EnrollmentAuthMethod::OauthPkce => "oauth_pkce",
        EnrollmentAuthMethod::SetupToken => "setup_token",
        EnrollmentAuthMethod::ExistingOauth => "existing_oauth",
        EnrollmentAuthMethod::BrowserSessionImport => "browser_session_import",
        EnrollmentAuthMethod::ConsoleApiKey => "console_api_key",
    }
}

const fn auth_kind_code(value: AuthKind) -> &'static str {
    match value {
        AuthKind::OauthSubscription => "oauth_subscription",
        AuthKind::SetupTokenSubscription => "setup_token_subscription",
        AuthKind::ConsoleApiKey => "console_api_key",
    }
}

const fn purpose_code(value: CredentialPurpose) -> &'static str {
    match value {
        CredentialPurpose::Business => "business",
        CredentialPurpose::VerificationOnly => "verification_only",
        CredentialPurpose::CountTokens => "count_tokens",
    }
}

const fn management_class_code(value: ManagementClass) -> &'static str {
    match value {
        ManagementClass::FullyManaged => "fully_managed",
        ManagementClass::NonManaged => "non_managed",
        ManagementClass::PendingReauthStrategy => "pending_reauth_strategy",
        ManagementClass::ManualRecoveryRequired => "manual_recovery_required",
    }
}

fn next_action_for_auth_method(value: &str) -> &'static str {
    match value {
        "oauth_pkce" => "open_authorization_url",
        "setup_token" => "submit_setup_material",
        "existing_oauth" | "console_api_key" => "submit_existing_oauth_material",
        "browser_session_import" => "complete_browser_login",
        _ => "retry",
    }
}

fn valid_enrollment_transition(from: &str, to: &str) -> bool {
    matches!(to, "failed" | "cancelled" | "expired")
        || matches!(
            (from, to),
            ("created", "resolving_egress")
                | ("resolving_egress", "awaiting_user_action")
                | ("awaiting_user_action", "exchanging_material")
                | ("exchanging_material", "verifying_account")
                | ("verifying_account", "deduplicating")
                | ("deduplicating", "provisioning_identity" | "recovering_existing")
                | ("recovering_existing" | "provisioning_identity", "configuring_reauth")
                | ("configuring_reauth", "activation_check")
                | ("activation_check", "succeeded")
        )
}

#[allow(dead_code)]
const fn _egress_policy_code(value: EgressPolicy) -> &'static str {
    match value {
        EgressPolicy::Auto => "auto",
        EgressPolicy::ProxyRequired => "proxy_required",
        EgressPolicy::Direct => "direct",
    }
}
