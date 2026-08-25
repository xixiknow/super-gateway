//! `PostgreSQL` orchestration for restart-safe Credential Enrollment jobs.
#![allow(clippy::missing_errors_doc, clippy::too_many_arguments, clippy::too_many_lines)]

use std::{sync::Arc, time::SystemTime};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD};
use gateway_domain::{
    AuthKind, EgressBindingId, EgressBindingSnapshot, EgressMode, ProxyEndpointId, SecretBytes, SecretValue,
};
use gateway_storage::{
    AuthCandidateRecord, AuthCasPrecondition, CredentialProfileProvision, DurableJobFence, MaintenanceOperationCreate,
    PgStorage, StorageError,
};
use http::Uri;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    credential::CredentialServiceError,
    credential_enrollment::{
        EnrollmentProviderProfile, SetupTokenVerificationError, SubscriptionEnrollmentAdapter,
        VerifiedEnrollmentMaterial,
    },
    credential_provider::ProviderHttpPort,
    operations::{CredentialEnrollmentJobAttempt, CredentialEnrollmentJobExecutor, JobAttemptDecision},
    security::{EnvelopeAad, EnvelopeService, LocalAesKeyProvider, SecretEnvelope},
};

/// Restart-safe production executor. It currently activates verified Existing
/// OAuth imports; other enrollment methods remain explicit evidence-gated
/// branches rather than being inferred from an opaque secret.
pub struct PgCredentialEnrollmentExecutor<H> {
    storage: Arc<PgStorage>,
    http: Arc<H>,
}

impl<H> PgCredentialEnrollmentExecutor<H>
where
    H: ProviderHttpPort,
{
    /// Construct the durable executor.
    #[must_use]
    pub fn new(storage: Arc<PgStorage>, http: Arc<H>) -> Arc<Self> {
        Arc::new(Self { storage, http })
    }

    async fn run(&self, attempt: &CredentialEnrollmentJobAttempt) -> Result<(), EnrollmentRunError> {
        let enrollment_id = attempt.enrollment_id;
        let credential_id = attempt.credential_id;
        let durable_job_fence = DurableJobFence {
            job_id: attempt.job_id,
            generation: attempt.job_generation,
            kind: "credential_enrollment_exchange".to_owned(),
        };
        ensure_durable_job_fence(&self.storage, &durable_job_fence).await?;
        let mut snapshot = load_snapshot(&self.storage, enrollment_id, credential_id).await?;
        if snapshot.state == "succeeded" {
            return Ok(());
        }
        if matches!(snapshot.state.as_str(), "failed" | "cancelled" | "expired") {
            return Err(EnrollmentRunError::Terminal("enrollment_terminal"));
        }
        if !matches!(
            snapshot.auth_method.as_str(),
            "existing_oauth" | "oauth_pkce" | "setup_token"
        ) {
            return Err(EnrollmentRunError::EvidencePending(
                "enrollment_method_evidence_pending",
            ));
        }

        if snapshot.identified_account_uuid.is_none() && snapshot.state == "exchanging_material" {
            let profile = snapshot
                .provider_profile
                .clone()
                .ok_or(EnrollmentRunError::EvidencePending("provider_profile_unavailable"))?;
            let adapter =
                SubscriptionEnrollmentAdapter::new(self.http.clone(), profile).map_err(EnrollmentRunError::Provider)?;
            let verified = match snapshot.auth_method.as_str() {
                "existing_oauth" => {
                    let staged = load_oauth_tokens(&self.storage, &snapshot, false).await?;
                    adapter
                        .verify_existing_oauth(staged.access_token, staged.refresh_token, snapshot.egress.clone())
                        .await
                        .map_err(EnrollmentRunError::Provider)?
                }
                "oauth_pkce" => {
                    let callback = load_oauth_callback_material(&self.storage, &snapshot).await?;
                    adapter
                        .exchange_authorization_code(
                            &callback.authorization_code,
                            &callback.state,
                            &callback.verifier,
                            snapshot.egress.clone(),
                        )
                        .await
                        .map_err(EnrollmentRunError::Provider)?
                }
                "setup_token" => {
                    let setup_token = load_setup_token(&self.storage, &snapshot).await?;
                    adapter
                        .verify_setup_token(setup_token, snapshot.egress.clone())
                        .await
                        .map_err(|error| match error {
                            SetupTokenVerificationError::Provider(error) => EnrollmentRunError::Provider(error),
                            SetupTokenVerificationError::AccountIdentityUnavailable => {
                                EnrollmentRunError::SetupAccountIdentityUnavailable
                            }
                        })?
                }
                _ => {
                    return Err(EnrollmentRunError::EvidencePending(
                        "enrollment_method_evidence_pending",
                    ));
                }
            };
            checkpoint_verified_material(&self.storage, &snapshot, &verified, &durable_job_fence).await?;
            snapshot = load_snapshot(&self.storage, enrollment_id, credential_id).await?;
        }
        if snapshot.state == "verifying_account" {
            let account_uuid = snapshot
                .identified_account_uuid
                .ok_or(EnrollmentRunError::Retry("verified_account_checkpoint_missing"))?;
            self.storage
                .claim_verified_account_for_job(
                    enrollment_id,
                    credential_id,
                    account_uuid,
                    snapshot.enrollment_revision,
                    snapshot.credential_revision,
                    &durable_job_fence,
                )
                .await?;
            snapshot = load_snapshot(&self.storage, enrollment_id, credential_id).await?;
        }
        let staged = if snapshot.auth_method == "setup_token" {
            OauthTokenMaterial {
                access_token: load_setup_token(&self.storage, &snapshot).await?,
                refresh_token: None,
            }
        } else {
            load_oauth_tokens(&self.storage, &snapshot, snapshot.auth_method == "oauth_pkce").await?
        };
        let verified = VerifiedEnrollmentMaterial {
            access_token: staged.access_token,
            refresh_token: staged.refresh_token,
            account_uuid: snapshot
                .account_uuid
                .ok_or(EnrollmentRunError::Retry("account_projection_missing"))?,
            organization_uuid: None,
            expires_after: None,
            adapter_version: snapshot.provider_profile.as_ref().map_or_else(
                || "unknown".into(),
                |profile| profile.adapter_version().into_boxed_str(),
            ),
        };

        snapshot = load_snapshot(&self.storage, enrollment_id, credential_id).await?;
        if !snapshot.profile_exists {
            if snapshot.state != "provisioning_identity" {
                return Err(EnrollmentRunError::Retry("profile_state_race"));
            }
            let allocation = allocate_device_identity(&self.storage, credential_id).await?;
            let allocated_secret_ids = allocation.all_secret_ids();
            let archetype = select_archetype(&self.storage).await?;
            let provision = CredentialProfileProvision {
                enrollment_id,
                credential_id,
                profile_id: Uuid::now_v7(),
                device_identity_id: Uuid::now_v7(),
                archetype_version_id: archetype.id,
                installation_secret_id: allocation.installation_secret_id,
                client_secret_id: allocation.client_secret_id,
                profile_seed_secret_id: allocation.profile_seed_secret_id,
                session_hmac_secret_id: allocation.session_hmac_secret_id,
                installation_digest: allocation.installation_digest.clone(),
                client_digest: allocation.client_digest.clone(),
                capture_cohort: archetype.capture_cohort,
                allocation_evidence: json!({
                    "allocator":"active_archetype_least_loaded_v1",
                    "provider_profile_id":snapshot.provider_profile_id,
                }),
                expected_enrollment_revision: snapshot.enrollment_revision,
                expected_credential_revision: snapshot.credential_revision,
                durable_job_fence: Some(durable_job_fence.clone()),
            };
            if let Err(error) = self.storage.provision_credential_profile(&provision).await {
                destroy_secret_ids(&self.storage, &allocated_secret_ids).await;
                return Err(error.into());
            }
        }

        snapshot = load_snapshot(&self.storage, enrollment_id, credential_id).await?;
        if snapshot.kind == "recover" || snapshot.active_auth_version_id.is_none() {
            let provider_profile_id = snapshot
                .provider_profile_id
                .ok_or(EnrollmentRunError::EvidencePending("provider_profile_unavailable"))?;
            if snapshot.kind == "recover" {
                self.storage
                    .supersede_attention_operations_for_recovery(
                        credential_id,
                        snapshot.credential_revision,
                        enrollment_id,
                    )
                    .await?;
            }
            let operation = self
                .storage
                .create_or_join_maintenance_operation(&MaintenanceOperationCreate {
                    operation_id: Uuid::now_v7(),
                    credential_id,
                    kind: if snapshot.kind == "recover" {
                        "manual_recovery".to_owned()
                    } else {
                        "verify".to_owned()
                    },
                    trigger: if snapshot.kind == "recover" {
                        "manual_recovery".to_owned()
                    } else {
                        "enrollment".to_owned()
                    },
                    conflict_class: "auth_material_write".to_owned(),
                    expected_revision: snapshot.credential_revision,
                    expected_token_version: snapshot.token_version,
                    egress_binding_id: snapshot.egress_binding_id,
                    egress_epoch: snapshot.egress_epoch,
                    adapter_code: Some(snapshot.auth_method.clone()),
                    adapter_version: Some(verified.adapter_version.to_string()),
                    provider_profile_id: Some(provider_profile_id),
                })
                .await?;
            let auth_secrets = load_or_stage_auth_material(
                &self.storage,
                credential_id,
                operation.operation_id,
                operation.generation,
                snapshot.token_version + 1,
                &verified.access_token,
                verified.refresh_token.as_ref(),
                if snapshot.auth_method == "setup_token" {
                    "setup_token"
                } else {
                    "oauth_access_token"
                },
                &durable_job_fence,
            )
            .await?;
            let expires_at_epoch_seconds = verified.expires_after.and_then(|duration| {
                SystemTime::now()
                    .checked_add(duration)?
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .and_then(|value| i64::try_from(value.as_secs()).ok())
            });
            let commit = self
                .storage
                .commit_auth_candidate(
                    &AuthCandidateRecord {
                        auth_version_id: Uuid::now_v7(),
                        credential_id,
                        auth_kind: snapshot.auth_kind,
                        access_secret_id: Some(auth_secrets.access_secret_id),
                        refresh_secret_id: auth_secrets.refresh_secret_id,
                        console_secret_id: None,
                        verified_account_uuid: Some(verified.account_uuid),
                        expires_at_epoch_seconds,
                        adapter_code: Some(snapshot.auth_method.clone()),
                        adapter_version: Some(verified.adapter_version.to_string()),
                    },
                    &AuthCasPrecondition {
                        expected_credential_revision: snapshot.credential_revision,
                        expected_token_version: snapshot.token_version,
                        expected_account_uuid: Some(verified.account_uuid),
                        expected_egress_binding_id: snapshot.egress_binding_id,
                        expected_egress_epoch: snapshot.egress_epoch,
                        operation_id: operation.operation_id,
                        operation_generation: operation.generation,
                        durable_job_fence: Some(durable_job_fence.clone()),
                    },
                )
                .await;
            if let Err(error) = commit {
                // The stage is shared by all retries of this maintenance generation.
                // Storage owns candidate cleanup under its CAS transaction; deleting
                // or destroying it here could erase a concurrent winner's active token.
                return Err(error.into());
            }
        }

        snapshot = load_snapshot(&self.storage, enrollment_id, credential_id).await?;
        if snapshot.kind == "recover" || snapshot.lifecycle != "active" {
            self.storage
                .activate_credential_for_job(
                    enrollment_id,
                    credential_id,
                    snapshot.credential_revision,
                    &durable_job_fence,
                )
                .await?;
        }
        Ok(())
    }

    async fn terminal_failure(
        &self,
        attempt: &CredentialEnrollmentJobAttempt,
        error_code: &'static str,
    ) -> JobAttemptDecision {
        let enrollment_id = attempt.enrollment_id;
        let durable_job_fence = DurableJobFence {
            job_id: attempt.job_id,
            generation: attempt.job_generation,
            kind: "credential_enrollment_exchange".to_owned(),
        };
        let Some(revision) = load_enrollment_revision(&self.storage, enrollment_id).await else {
            return JobAttemptDecision::Retry {
                error_code: "enrollment_terminal_cleanup_pending".to_owned(),
                retry_after_seconds: 30,
                checkpoint: Some(json!({"stage":"terminal_cleanup"})),
            };
        };
        match self
            .storage
            .fail_credential_enrollment_for_job(enrollment_id, revision, error_code, &durable_job_fence)
            .await
        {
            Ok(()) => JobAttemptDecision::DeadLetter {
                error_code: error_code.to_owned(),
                checkpoint: Some(json!({"stage":"terminal_cleanup_complete"})),
            },
            Err(_) => JobAttemptDecision::Retry {
                error_code: "enrollment_terminal_cleanup_pending".to_owned(),
                retry_after_seconds: 30,
                checkpoint: Some(json!({"stage":"terminal_cleanup"})),
            },
        }
    }
}

/// Load one active, evidence-versioned enrollment provider profile.
pub async fn load_active_enrollment_provider_profile(
    storage: &PgStorage,
    profile_id: Uuid,
) -> Result<EnrollmentProviderProfile, CredentialServiceError> {
    let row = sqlx::query(
        "SELECT profile_code,profile_version,evidence_version,authorize_endpoint,token_endpoint, \
                profile_endpoint,bootstrap_endpoint,client_id,redirect_uri,scopes,max_response_bytes \
         FROM gateway.credential_provider_profile WHERE id=$1 AND lifecycle_code='active'",
    )
    .bind(profile_id)
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| CredentialServiceError::Transient)?
    .ok_or(CredentialServiceError::EvidencePending)?;
    provider_profile_from_row(&row).map_err(|_| CredentialServiceError::EvidencePending)
}

#[async_trait]
impl<H> CredentialEnrollmentJobExecutor for PgCredentialEnrollmentExecutor<H>
where
    H: ProviderHttpPort,
{
    async fn execute(&self, attempt: CredentialEnrollmentJobAttempt) -> JobAttemptDecision {
        match self.run(&attempt).await {
            Ok(()) => JobAttemptDecision::Succeeded {
                outcome_code: "credential_activated".to_owned(),
            },
            Err(EnrollmentRunError::Provider(CredentialServiceError::RateLimited(duration))) => {
                JobAttemptDecision::Retry {
                    error_code: "enrollment_rate_limited".to_owned(),
                    retry_after_seconds: u32::try_from(duration.as_secs().clamp(1, 900)).unwrap_or(900),
                    checkpoint: Some(json!({"stage":"provider_call"})),
                }
            }
            Err(EnrollmentRunError::Provider(CredentialServiceError::WaitingEgress)) => JobAttemptDecision::Retry {
                error_code: "enrollment_waiting_egress".to_owned(),
                retry_after_seconds: 30,
                checkpoint: Some(json!({"stage":"provider_call"})),
            },
            Err(EnrollmentRunError::Provider(CredentialServiceError::InvalidAuthentication)) => {
                self.terminal_failure(&attempt, "invalid_authentication").await
            }
            Err(EnrollmentRunError::SetupAccountIdentityUnavailable) => {
                self.terminal_failure(&attempt, "setup_token_account_identity_unavailable")
                    .await
            }
            Err(EnrollmentRunError::Storage(StorageError::AccountConflict)) => {
                self.terminal_failure(&attempt, "credential_account_exists").await
            }
            Err(
                EnrollmentRunError::Storage(StorageError::AccountMismatch)
                | EnrollmentRunError::Provider(CredentialServiceError::AccountMismatch),
            ) => self.terminal_failure(&attempt, "credential_account_mismatch").await,
            Err(EnrollmentRunError::Terminal(error_code)) => JobAttemptDecision::DeadLetter {
                error_code: error_code.to_owned(),
                checkpoint: None,
            },
            Err(EnrollmentRunError::EvidencePending(error_code)) => JobAttemptDecision::Retry {
                error_code: error_code.to_owned(),
                retry_after_seconds: 300,
                checkpoint: Some(json!({"stage":"evidence_gate"})),
            },
            Err(EnrollmentRunError::Retry(error_code)) => JobAttemptDecision::Retry {
                error_code: error_code.to_owned(),
                retry_after_seconds: 30,
                checkpoint: Some(json!({"stage":"state_machine"})),
            },
            Err(EnrollmentRunError::Storage(
                StorageError::RevisionConflict | StorageError::CapacityExceeded | StorageError::EgressUnavailable,
            )) => JobAttemptDecision::Retry {
                error_code: "enrollment_state_retry".to_owned(),
                retry_after_seconds: 30,
                checkpoint: Some(json!({"stage":"state_machine"})),
            },
            Err(EnrollmentRunError::Provider(_) | EnrollmentRunError::Storage(_)) => JobAttemptDecision::Retry {
                error_code: "enrollment_transient".to_owned(),
                retry_after_seconds: 30,
                checkpoint: Some(json!({"stage":"state_machine"})),
            },
        }
    }
}

#[derive(Debug)]
enum EnrollmentRunError {
    Provider(CredentialServiceError),
    Storage(StorageError),
    Retry(&'static str),
    EvidencePending(&'static str),
    SetupAccountIdentityUnavailable,
    Terminal(&'static str),
}

impl From<CredentialServiceError> for EnrollmentRunError {
    fn from(value: CredentialServiceError) -> Self {
        Self::Provider(value)
    }
}

impl From<StorageError> for EnrollmentRunError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

struct EnrollmentSnapshot {
    enrollment_id: Uuid,
    kind: String,
    state: String,
    auth_method: String,
    enrollment_revision: i64,
    material_secret_refs: Vec<Uuid>,
    credential_revision: i64,
    token_version: i64,
    lifecycle: String,
    auth_kind: AuthKind,
    account_uuid: Option<Uuid>,
    identified_account_uuid: Option<Uuid>,
    pkce_verifier_secret_id: Option<Uuid>,
    active_auth_version_id: Option<Uuid>,
    profile_exists: bool,
    provider_profile_id: Option<Uuid>,
    provider_profile: Option<EnrollmentProviderProfile>,
    egress_binding_id: Uuid,
    egress_epoch: i64,
    egress: EgressBindingSnapshot,
}

async fn load_snapshot(
    storage: &PgStorage,
    enrollment_id: Uuid,
    credential_id: Uuid,
) -> Result<EnrollmentSnapshot, EnrollmentRunError> {
    let row = sqlx::query(
        "SELECT e.kind_code,e.state_code,e.auth_method_code,e.revision AS enrollment_revision,e.material_secret_refs, \
                e.identified_account_uuid,e.pkce_verifier_secret_id, \
                e.provider_profile_id,c.revision AS credential_revision,c.token_version,c.lifecycle_state_code, \
                c.auth_kind_code,c.account_uuid,c.active_auth_version_id, \
                EXISTS(SELECT 1 FROM gateway.credential_profile cp WHERE cp.credential_id=c.id) AS profile_exists, \
                b.id AS egress_binding_id,b.mode_code,b.proxy_id, \
                e.egress_epoch AS frozen_egress_epoch,b.egress_epoch AS current_egress_epoch, \
                b.lifecycle_code AS egress_lifecycle,b.stability_code AS egress_stability, \
                p.profile_code,p.profile_version,p.evidence_version,p.authorize_endpoint,p.token_endpoint, \
                p.profile_endpoint,p.bootstrap_endpoint,p.client_id,p.redirect_uri,p.scopes,p.max_response_bytes \
         FROM gateway.credential_enrollment e \
         JOIN gateway.anthropic_credential c ON c.id=e.pending_credential_id \
         JOIN gateway.credential_egress_binding b ON b.id=e.egress_binding_id AND b.credential_id=c.id \
         LEFT JOIN gateway.credential_provider_profile p ON p.id=e.provider_profile_id AND p.lifecycle_code='active' \
         WHERE e.id=$1 AND c.id=$2",
    )
    .bind(enrollment_id)
    .bind(credential_id)
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?
    .ok_or(EnrollmentRunError::Terminal("enrollment_missing"))?;
    let mode: String = row
        .try_get("mode_code")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let proxy_id: Option<Uuid> = row
        .try_get("proxy_id")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let binding_id: Uuid = row
        .try_get("egress_binding_id")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let frozen_egress_epoch: i64 = row
        .try_get("frozen_egress_epoch")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let current_egress_epoch: i64 = row
        .try_get("current_egress_epoch")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let egress_lifecycle: String = row
        .try_get("egress_lifecycle")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let egress_stability: String = row
        .try_get("egress_stability")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    if frozen_egress_epoch != current_egress_epoch || egress_lifecycle != "active" || egress_stability != "stable" {
        return Err(EnrollmentRunError::Provider(CredentialServiceError::WaitingEgress));
    }
    let egress = EgressBindingSnapshot {
        binding_id: EgressBindingId::new(binding_id.to_string())
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        mode: match mode.as_str() {
            "direct" => EgressMode::Direct,
            "proxy" => EgressMode::Proxy,
            _ => return Err(EnrollmentRunError::Storage(StorageError::TransactionFailed)),
        },
        proxy_id: proxy_id
            .map(|id| ProxyEndpointId::new(id.to_string()))
            .transpose()
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        egress_epoch: u64::try_from(frozen_egress_epoch)
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
    };
    let provider_profile_id: Option<Uuid> = row
        .try_get("provider_profile_id")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let provider_profile = if provider_profile_id.is_some() {
        Some(provider_profile_from_row(&row)?)
    } else {
        None
    };
    Ok(EnrollmentSnapshot {
        enrollment_id,
        kind: row
            .try_get("kind_code")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        state: row
            .try_get("state_code")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        auth_method: row
            .try_get("auth_method_code")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        enrollment_revision: row
            .try_get("enrollment_revision")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        material_secret_refs: row
            .try_get("material_secret_refs")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        credential_revision: row
            .try_get("credential_revision")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        token_version: row
            .try_get("token_version")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        lifecycle: row
            .try_get("lifecycle_state_code")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        auth_kind: parse_auth_kind(
            &row.try_get::<String, _>("auth_kind_code")
                .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        )?,
        account_uuid: row
            .try_get("account_uuid")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        identified_account_uuid: row
            .try_get("identified_account_uuid")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        pkce_verifier_secret_id: row
            .try_get("pkce_verifier_secret_id")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        active_auth_version_id: row
            .try_get("active_auth_version_id")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        profile_exists: row
            .try_get("profile_exists")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        provider_profile_id,
        provider_profile,
        egress_binding_id: binding_id,
        egress_epoch: frozen_egress_epoch,
        egress,
    })
}

fn provider_profile_from_row(row: &sqlx::postgres::PgRow) -> Result<EnrollmentProviderProfile, EnrollmentRunError> {
    let scopes: Value = row
        .try_get("scopes")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let scopes = scopes
        .as_array()
        .ok_or(EnrollmentRunError::EvidencePending("provider_profile_invalid"))?
        .iter()
        .map(|scope| {
            scope
                .as_str()
                .filter(|value| !value.is_empty())
                .map(|value| value.to_owned().into_boxed_str())
                .ok_or(EnrollmentRunError::EvidencePending("provider_profile_invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let parse_uri = |column| -> Result<Uri, EnrollmentRunError> {
        row.try_get::<String, _>(column)
            .map_err(|_| EnrollmentRunError::EvidencePending("provider_profile_invalid"))?
            .parse()
            .map_err(|_| EnrollmentRunError::EvidencePending("provider_profile_invalid"))
    };
    Ok(EnrollmentProviderProfile {
        profile_code: row
            .try_get::<String, _>("profile_code")
            .map_err(|_| EnrollmentRunError::EvidencePending("provider_profile_invalid"))?
            .into_boxed_str(),
        version: u64::try_from(
            row.try_get::<i64, _>("profile_version")
                .map_err(|_| EnrollmentRunError::EvidencePending("provider_profile_invalid"))?,
        )
        .map_err(|_| EnrollmentRunError::EvidencePending("provider_profile_invalid"))?,
        evidence_version: row
            .try_get::<String, _>("evidence_version")
            .map_err(|_| EnrollmentRunError::EvidencePending("provider_profile_invalid"))?
            .into_boxed_str(),
        authorize_endpoint: parse_uri("authorize_endpoint")?,
        token_endpoint: parse_uri("token_endpoint")?,
        profile_endpoint: parse_uri("profile_endpoint")?,
        bootstrap_endpoint: parse_uri("bootstrap_endpoint")?,
        client_id: row
            .try_get::<String, _>("client_id")
            .map_err(|_| EnrollmentRunError::EvidencePending("provider_profile_invalid"))?
            .into_boxed_str(),
        redirect_uri: parse_uri("redirect_uri")?,
        scopes,
        max_response_bytes: usize::try_from(
            row.try_get::<i32, _>("max_response_bytes")
                .map_err(|_| EnrollmentRunError::EvidencePending("provider_profile_invalid"))?,
        )
        .map_err(|_| EnrollmentRunError::EvidencePending("provider_profile_invalid"))?,
    })
}

struct OauthTokenMaterial {
    access_token: SecretValue,
    refresh_token: Option<SecretValue>,
}

async fn load_setup_token(
    storage: &PgStorage,
    snapshot: &EnrollmentSnapshot,
) -> Result<SecretValue, EnrollmentRunError> {
    if snapshot.material_secret_refs.len() != 1 {
        return Err(EnrollmentRunError::Provider(
            CredentialServiceError::InvalidAuthentication,
        ));
    }
    let (kind, bytes) = decrypt_secret(
        storage,
        snapshot.material_secret_refs[0],
        "credential_enrollment",
        &snapshot.enrollment_id.to_string(),
    )
    .await?;
    if kind != "setup_token" {
        return Err(EnrollmentRunError::Provider(
            CredentialServiceError::InvalidAuthentication,
        ));
    }
    let token = String::from_utf8(bytes.expose().to_vec())
        .map_err(|_| EnrollmentRunError::Provider(CredentialServiceError::InvalidAuthentication))?;
    if token.is_empty() {
        return Err(EnrollmentRunError::Provider(
            CredentialServiceError::InvalidAuthentication,
        ));
    }
    Ok(SecretValue::new(token))
}

async fn load_oauth_tokens(
    storage: &PgStorage,
    snapshot: &EnrollmentSnapshot,
    allow_callback_material: bool,
) -> Result<OauthTokenMaterial, EnrollmentRunError> {
    let mut access_token = None;
    let mut refresh_token = None;
    for secret_id in &snapshot.material_secret_refs {
        let (kind, bytes) = decrypt_secret(
            storage,
            *secret_id,
            "credential_enrollment",
            &snapshot.enrollment_id.to_string(),
        )
        .await?;
        let value = String::from_utf8(bytes.expose().to_vec())
            .map_err(|_| EnrollmentRunError::Provider(CredentialServiceError::InvalidAuthentication))?;
        match kind.as_str() {
            "oauth_access_token" if access_token.is_none() => access_token = Some(SecretValue::new(value)),
            "oauth_refresh_token" if refresh_token.is_none() => refresh_token = Some(SecretValue::new(value)),
            "oauth_callback_material" if allow_callback_material => {}
            _ => {
                return Err(EnrollmentRunError::Provider(
                    CredentialServiceError::InvalidAuthentication,
                ));
            }
        }
    }
    Ok(OauthTokenMaterial {
        access_token: access_token.ok_or(EnrollmentRunError::Provider(
            CredentialServiceError::InvalidAuthentication,
        ))?,
        refresh_token,
    })
}

#[derive(Deserialize)]
struct OAuthCallbackDocument {
    authorization_code: String,
    state: String,
}

struct OAuthCallbackMaterial {
    authorization_code: SecretValue,
    state: SecretValue,
    verifier: SecretValue,
}

async fn load_oauth_callback_material(
    storage: &PgStorage,
    snapshot: &EnrollmentSnapshot,
) -> Result<OAuthCallbackMaterial, EnrollmentRunError> {
    let mut callback = None;
    for secret_id in &snapshot.material_secret_refs {
        let (kind, bytes) = decrypt_secret(
            storage,
            *secret_id,
            "credential_enrollment",
            &snapshot.enrollment_id.to_string(),
        )
        .await?;
        if kind == "oauth_callback_material" {
            if callback.is_some() {
                return Err(EnrollmentRunError::Provider(
                    CredentialServiceError::InvalidAuthentication,
                ));
            }
            let document: OAuthCallbackDocument = serde_json::from_slice(bytes.expose())
                .map_err(|_| EnrollmentRunError::Provider(CredentialServiceError::InvalidAuthentication))?;
            callback = Some((
                SecretValue::new(document.authorization_code),
                SecretValue::new(document.state),
            ));
        }
    }
    let verifier_secret_id = snapshot.pkce_verifier_secret_id.ok_or(EnrollmentRunError::Provider(
        CredentialServiceError::InvalidAuthentication,
    ))?;
    let (kind, verifier) = decrypt_secret(
        storage,
        verifier_secret_id,
        "credential_enrollment",
        &snapshot.enrollment_id.to_string(),
    )
    .await?;
    if kind != "pkce_verifier" {
        return Err(EnrollmentRunError::Provider(
            CredentialServiceError::InvalidAuthentication,
        ));
    }
    let verifier = String::from_utf8(verifier.expose().to_vec())
        .map_err(|_| EnrollmentRunError::Provider(CredentialServiceError::InvalidAuthentication))?;
    let (authorization_code, state) = callback.ok_or(EnrollmentRunError::Provider(
        CredentialServiceError::InvalidAuthentication,
    ))?;
    Ok(OAuthCallbackMaterial {
        authorization_code,
        state,
        verifier: SecretValue::new(verifier),
    })
}

async fn checkpoint_verified_material(
    storage: &PgStorage,
    snapshot: &EnrollmentSnapshot,
    verified: &VerifiedEnrollmentMaterial,
    durable_job_fence: &DurableJobFence,
) -> Result<(), EnrollmentRunError> {
    let values = if snapshot.auth_method == "oauth_pkce" {
        let refresh_token = verified
            .refresh_token
            .as_ref()
            .ok_or(EnrollmentRunError::EvidencePending("refresh_material_required"))?;
        vec![
            (
                "oauth_access_token",
                "credential_enrollment",
                verified.access_token.expose().as_bytes().to_vec(),
            ),
            (
                "oauth_refresh_token",
                "credential_enrollment",
                refresh_token.expose().as_bytes().to_vec(),
            ),
        ]
    } else {
        Vec::new()
    };
    let encrypted = prepare_owned_secrets(
        storage,
        "credential_enrollment",
        &snapshot.enrollment_id.to_string(),
        values,
    )
    .await?;
    let secret_ids = encrypted.iter().map(|(aad, _)| aad.secret_id).collect::<Vec<_>>();
    let mut transaction = storage
        .pool()
        .begin()
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
    require_durable_job_fence_in(&mut transaction, durable_job_fence).await?;
    for (aad, envelope) in &encrypted {
        insert_secret(&mut transaction, aad, envelope).await?;
    }
    let changed = sqlx::query(
        "UPDATE gateway.credential_enrollment SET state_code='verifying_account',next_action_code='retry', \
         identified_account_uuid=$3,material_secret_refs=material_secret_refs || $4::uuid[], \
         operation_checkpoint_code='account_verified_by_provider',revision=revision+1,updated_at=clock_timestamp() \
         WHERE id=$1 AND revision=$2 AND state_code='exchanging_material'",
    )
    .bind(snapshot.enrollment_id)
    .bind(snapshot.enrollment_revision)
    .bind(verified.account_uuid)
    .bind(&secret_ids)
    .execute(&mut *transaction)
    .await
    .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    if changed.rows_affected() != 1 {
        return Err(EnrollmentRunError::Storage(StorageError::RevisionConflict));
    }
    transaction
        .commit()
        .await
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))
}

async fn ensure_durable_job_fence(storage: &PgStorage, fence: &DurableJobFence) -> Result<(), EnrollmentRunError> {
    let mut transaction = storage
        .pool()
        .begin()
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
    require_durable_job_fence_in(&mut transaction, fence).await?;
    transaction
        .commit()
        .await
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))
}

async fn require_durable_job_fence_in(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &DurableJobFence,
) -> Result<(), EnrollmentRunError> {
    let leased = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM ops.durable_job WHERE id=$1 AND kind_code=$2 AND state_code='leased' \
         AND lease_generation=$3 AND lease_expires_at>=clock_timestamp() FOR SHARE",
    )
    .bind(fence.job_id)
    .bind(&fence.kind)
    .bind(fence.generation)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    if leased != Some(fence.job_id) {
        return Err(EnrollmentRunError::Storage(StorageError::RevisionConflict));
    }
    Ok(())
}

struct ArchetypeAllocation {
    id: Uuid,
    capture_cohort: String,
}

async fn select_archetype(storage: &PgStorage) -> Result<ArchetypeAllocation, EnrollmentRunError> {
    let row = sqlx::query(
        "SELECT version.id,COALESCE(evidence.capture_cohort,version.protocol_profile->>'capture_cohort','default') AS capture_cohort \
         FROM catalog.environment_archetype_version version \
         JOIN catalog.archetype_bundle_binding binding ON binding.archetype_version_id=version.id AND binding.state_code='active' \
         JOIN catalog.transport_bundle bundle ON bundle.id=binding.transport_bundle_id AND bundle.lifecycle_code='active' \
         JOIN catalog.archetype_capacity_policy capacity ON capacity.archetype_version_id=version.id \
         LEFT JOIN catalog.evidence_set evidence ON evidence.id=version.evidence_set_id \
         WHERE version.lifecycle_code='active' \
           AND (SELECT count(*) FROM gateway.credential_profile profile WHERE profile.archetype_version_id=version.id \
                AND profile.lifecycle_code IN ('pending','active','upgrading')) < capacity.max_credentials \
         ORDER BY ((SELECT count(*) FROM gateway.credential_profile profile WHERE profile.archetype_version_id=version.id \
                    AND profile.lifecycle_code IN ('pending','active','upgrading'))::numeric/capacity.max_credentials::numeric),version.id \
         LIMIT 1",
    )
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?
    .ok_or(EnrollmentRunError::Retry("archetype_capacity_unavailable"))?;
    Ok(ArchetypeAllocation {
        id: row
            .try_get("id")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        capture_cohort: row
            .try_get("capture_cohort")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
    })
}

struct DeviceSecretAllocation {
    installation_secret_id: Uuid,
    client_secret_id: Uuid,
    profile_seed_secret_id: Uuid,
    session_hmac_secret_id: Uuid,
    installation_digest: Vec<u8>,
    client_digest: Vec<u8>,
}

impl DeviceSecretAllocation {
    fn all_secret_ids(&self) -> Vec<Uuid> {
        vec![
            self.installation_secret_id,
            self.client_secret_id,
            self.profile_seed_secret_id,
            self.session_hmac_secret_id,
        ]
    }
}

async fn allocate_device_identity(
    storage: &PgStorage,
    credential_id: Uuid,
) -> Result<DeviceSecretAllocation, EnrollmentRunError> {
    let mut installation_bytes = [0_u8; 32];
    let mut profile_seed = [0_u8; 32];
    let mut session_hmac = [0_u8; 32];
    getrandom::fill(&mut installation_bytes)
        .and_then(|()| getrandom::fill(&mut profile_seed))
        .and_then(|()| getrandom::fill(&mut session_hmac))
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let installation = URL_SAFE_NO_PAD.encode(installation_bytes);
    let client = Uuid::now_v7().to_string();
    let values = vec![
        ("device_identity", "device_identity", installation.as_bytes().to_vec()),
        ("device_identity", "device_identity", client.as_bytes().to_vec()),
        ("device_identity", "device_identity", profile_seed.to_vec()),
        ("session_hmac", "session_derivation", session_hmac.to_vec()),
    ];
    let ids = store_credential_secrets(storage, credential_id, values).await?;
    Ok(DeviceSecretAllocation {
        installation_secret_id: ids[0],
        client_secret_id: ids[1],
        profile_seed_secret_id: ids[2],
        session_hmac_secret_id: ids[3],
        installation_digest: Sha256::digest(installation.as_bytes()).to_vec(),
        client_digest: Sha256::digest(client.as_bytes()).to_vec(),
    })
}

struct AuthSecretAllocation {
    access_secret_id: Uuid,
    refresh_secret_id: Option<Uuid>,
}

async fn load_or_stage_auth_material(
    storage: &PgStorage,
    credential_id: Uuid,
    operation_id: Uuid,
    operation_generation: i64,
    candidate_token_version: i64,
    access_token: &SecretValue,
    refresh_token: Option<&SecretValue>,
    access_secret_kind: &'static str,
    durable_job_fence: &DurableJobFence,
) -> Result<AuthSecretAllocation, EnrollmentRunError> {
    ensure_durable_job_fence(storage, durable_job_fence).await?;
    if let Some(row) = sqlx::query(
        "SELECT access_secret_id,refresh_secret_id FROM gateway.credential_auth_secret_stage \
         WHERE operation_id=$1 AND operation_generation=$2 AND credential_id=$3 \
           AND candidate_token_version=$4",
    )
    .bind(operation_id)
    .bind(operation_generation)
    .bind(credential_id)
    .bind(candidate_token_version)
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?
    {
        return Ok(AuthSecretAllocation {
            access_secret_id: row
                .try_get("access_secret_id")
                .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
            refresh_secret_id: row
                .try_get("refresh_secret_id")
                .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        });
    }
    let mut values = vec![(
        access_secret_kind,
        "anthropic_auth",
        access_token.expose().as_bytes().to_vec(),
    )];
    if let Some(refresh_token) = refresh_token {
        values.push((
            "oauth_refresh_token",
            "anthropic_auth",
            refresh_token.expose().as_bytes().to_vec(),
        ));
    }
    let encrypted = prepare_credential_secrets(storage, credential_id, values).await?;
    let ids = encrypted.iter().map(|(aad, _)| aad.secret_id).collect::<Vec<_>>();
    let refresh_secret_id = ids.get(1).copied();
    let mut transaction = storage
        .pool()
        .begin()
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
    require_durable_job_fence_in(&mut transaction, durable_job_fence).await?;
    for (aad, envelope) in &encrypted {
        insert_secret(&mut transaction, aad, envelope).await?;
    }
    sqlx::query(
        "INSERT INTO gateway.credential_auth_secret_stage \
         (operation_id,operation_generation,credential_id,candidate_token_version,access_secret_id,refresh_secret_id) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(operation_id)
    .bind(operation_generation)
    .bind(credential_id)
    .bind(candidate_token_version)
    .bind(ids[0])
    .bind(refresh_secret_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    transaction
        .commit()
        .await
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    Ok(AuthSecretAllocation {
        access_secret_id: ids[0],
        refresh_secret_id,
    })
}

async fn store_credential_secrets(
    storage: &PgStorage,
    credential_id: Uuid,
    values: Vec<(&str, &str, Vec<u8>)>,
) -> Result<Vec<Uuid>, EnrollmentRunError> {
    let encrypted = prepare_credential_secrets(storage, credential_id, values).await?;
    let mut transaction = storage
        .pool()
        .begin()
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
    for (aad, envelope) in &encrypted {
        insert_secret(&mut transaction, aad, envelope).await?;
    }
    transaction
        .commit()
        .await
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    Ok(encrypted.into_iter().map(|(aad, _)| aad.secret_id).collect())
}

async fn prepare_credential_secrets(
    storage: &PgStorage,
    credential_id: Uuid,
    values: Vec<(&str, &str, Vec<u8>)>,
) -> Result<Vec<(EnvelopeAad, SecretEnvelope)>, EnrollmentRunError> {
    prepare_owned_secrets(storage, "credential", &credential_id.to_string(), values).await
}

async fn prepare_owned_secrets(
    storage: &PgStorage,
    owner_type: &str,
    owner_id: &str,
    values: Vec<(&str, &str, Vec<u8>)>,
) -> Result<Vec<(EnvelopeAad, SecretEnvelope)>, EnrollmentRunError> {
    let key_version: i64 = sqlx::query_scalar(
        "SELECT key_version FROM security.business_key_material WHERE provider_code='database' AND state_code='active'",
    )
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?
    .ok_or(EnrollmentRunError::EvidencePending("business_key_unavailable"))?;
    let root_key = storage.load_database_business_key(key_version).await?;
    let key_version_u64 =
        u64::try_from(key_version).map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let envelope_service = EnvelopeService::new(
        LocalAesKeyProvider::new("business", key_version_u64, root_key.expose().to_vec())
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
    );
    let mut encrypted = Vec::with_capacity(values.len());
    for (secret_kind, purpose, plaintext) in values {
        let secret_id = Uuid::now_v7();
        let aad = EnvelopeAad {
            schema_version: 1,
            secret_id,
            secret_kind: secret_kind.to_owned(),
            provider_role: "business".to_owned(),
            owner_type: owner_type.to_owned(),
            owner_id: owner_id.to_owned(),
            purpose: purpose.to_owned(),
            key_version: key_version_u64,
        };
        let envelope = envelope_service
            .encrypt(&SecretBytes::new(plaintext), aad.clone())
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
        encrypted.push((aad, envelope));
    }
    Ok(encrypted)
}

async fn decrypt_secret(
    storage: &PgStorage,
    secret_id: Uuid,
    expected_owner_type: &str,
    expected_owner_id: &str,
) -> Result<(String, SecretBytes), EnrollmentRunError> {
    let row = sqlx::query(
        "SELECT secret_kind_code,provider_role_code,cipher_suite_code,ciphertext,nonce,wrapped_dek,key_version, \
                aad_schema_version,owner_type_code,owner_id,purpose_code \
         FROM security.encrypted_secret WHERE id=$1 AND destroyed_at IS NULL AND superseded_at IS NULL",
    )
    .bind(secret_id)
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?
    .ok_or(EnrollmentRunError::Provider(
        CredentialServiceError::InvalidAuthentication,
    ))?;
    let owner_type: String = row
        .try_get("owner_type_code")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let owner_id: String = row
        .try_get("owner_id")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    if owner_type != expected_owner_type || owner_id != expected_owner_id {
        return Err(EnrollmentRunError::Provider(
            CredentialServiceError::InvalidAuthentication,
        ));
    }
    let key_version: i64 = row
        .try_get("key_version")
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let key_version_u64 =
        u64::try_from(key_version).map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let aad = EnvelopeAad {
        schema_version: u32::try_from(
            row.try_get::<i32, _>("aad_schema_version")
                .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        )
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        secret_id,
        secret_kind: row
            .try_get("secret_kind_code")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        provider_role: row
            .try_get("provider_role_code")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        owner_type,
        owner_id: row
            .try_get("owner_id")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        purpose: row
            .try_get("purpose_code")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        key_version: key_version_u64,
    };
    let envelope = SecretEnvelope {
        schema_version: aad.schema_version,
        cipher_suite: row
            .try_get("cipher_suite_code")
            .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        provider_role: aad.provider_role.clone(),
        key_version: key_version_u64,
        ciphertext_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("ciphertext")
                .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        ),
        nonce_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("nonce")
                .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        ),
        wrapped_dek_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("wrapped_dek")
                .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?,
        ),
    };
    let root_key = storage.load_database_business_key(key_version).await?;
    let provider = LocalAesKeyProvider::new("business", key_version_u64, root_key.expose().to_vec())
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let plaintext = EnvelopeService::new(provider)
        .decrypt(&envelope, &aad)
        .map_err(|_| EnrollmentRunError::Provider(CredentialServiceError::InvalidAuthentication))?;
    Ok((aad.secret_kind, plaintext))
}

async fn insert_secret(
    transaction: &mut Transaction<'_, Postgres>,
    aad: &EnvelopeAad,
    envelope: &SecretEnvelope,
) -> Result<(), EnrollmentRunError> {
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext_base64)
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let nonce = STANDARD
        .decode(&envelope.nonce_base64)
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    let wrapped_dek = STANDARD
        .decode(&envelope.wrapped_dek_base64)
        .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
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
    .bind(i64::try_from(envelope.key_version).map_err(|_| StorageError::TransactionFailed)?)
    .bind(i32::try_from(envelope.schema_version).map_err(|_| StorageError::TransactionFailed)?)
    .bind(&aad.owner_type)
    .bind(&aad.owner_id)
    .bind(&aad.purpose)
    .execute(&mut **transaction)
    .await
    .map_err(|_| EnrollmentRunError::Storage(StorageError::TransactionFailed))?;
    Ok(())
}

async fn destroy_secret_ids(storage: &PgStorage, secret_ids: &[Uuid]) {
    let _ = sqlx::query(
        "UPDATE security.encrypted_secret SET superseded_at=COALESCE(superseded_at,clock_timestamp()), \
         destroyed_at=clock_timestamp(),ciphertext='\\x'::bytea,wrapped_dek='\\x'::bytea \
         WHERE id=ANY($1) AND destroyed_at IS NULL",
    )
    .bind(secret_ids)
    .execute(&storage.pool())
    .await;
}

async fn load_enrollment_revision(storage: &PgStorage, enrollment_id: Uuid) -> Option<i64> {
    sqlx::query_scalar("SELECT revision FROM gateway.credential_enrollment WHERE id=$1")
        .bind(enrollment_id)
        .fetch_optional(&storage.pool())
        .await
        .ok()
        .flatten()
}

fn parse_auth_kind(value: &str) -> Result<AuthKind, EnrollmentRunError> {
    match value {
        "oauth_subscription" => Ok(AuthKind::OauthSubscription),
        "setup_token_subscription" => Ok(AuthKind::SetupTokenSubscription),
        "console_api_key" => Ok(AuthKind::ConsoleApiKey),
        _ => Err(EnrollmentRunError::Storage(StorageError::TransactionFailed)),
    }
}
