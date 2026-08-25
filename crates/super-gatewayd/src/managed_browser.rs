//! Automatic Managed Browser credential maintenance through a bounded helper process.
#![allow(
    clippy::manual_let_else,
    clippy::needless_pass_by_value,
    clippy::struct_field_names,
    clippy::too_many_lines
)]

use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gateway_domain::{
    AuthKind, EgressBindingId, EgressBindingSnapshot, EgressMode, EgressRouteSnapshot, ProxyEndpointId, SecretBytes,
    SecretValue,
};
use gateway_services::{
    credential::CredentialServiceError,
    credential_enrollment::{SubscriptionEnrollmentAdapter, VerifiedEnrollmentMaterial},
    credential_enrollment_postgres::load_active_enrollment_provider_profile,
    credential_provider::{ProviderHttpPort, ProviderHttpRequest, ProviderHttpResponse},
    security::{EnvelopeAad, EnvelopeService, LocalAesKeyProvider, SecretEnvelope},
};
use gateway_storage::{
    AuthCandidateRecord, AuthCasPrecondition, BrowserCasPrecondition, BrowserMaterialCandidate, JobLease, PgStorage,
    StorageError,
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row as _, Transaction};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::Command,
};
use uuid::Uuid;
use zeroize::Zeroize as _;

const MAX_HELPER_OUTPUT: u64 = 32 * 1024 * 1024;
const MAX_BROWSER_COMPONENT: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct CommandManagedBrowserExecutor {
    storage: Arc<PgStorage>,
    provider_http: Arc<SharedProviderHttp>,
    egress_resolver: Arc<dyn ManagedBrowserEgressResolver>,
    tool: PathBuf,
    timeout: Duration,
}

impl CommandManagedBrowserExecutor {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn new(
        storage: Arc<PgStorage>,
        provider_http: Arc<dyn ProviderHttpPort>,
        egress_resolver: Arc<dyn ManagedBrowserEgressResolver>,
        tool: PathBuf,
        timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            storage,
            provider_http: Arc::new(SharedProviderHttp(provider_http)),
            egress_resolver,
            tool,
            timeout,
        })
    }

    pub(crate) async fn execute(&self, job: &JobLease) -> Result<ManagedBrowserCommit, ManagedBrowserFailure> {
        if job
            .checkpoint
            .as_ref()
            .and_then(|value| value.get("phase"))
            .and_then(serde_json::Value::as_str)
            == Some("browser_material_committed")
        {
            return committed_from_checkpoint(job);
        }
        let payload = BrowserJobPayload::parse(job)?;
        let snapshot = self.claim_operation(&payload, job).await?;
        if let Some(staged) = self.load_staged_candidates(&snapshot, job).await? {
            return self.commit_candidates(&snapshot, staged, job).await;
        }
        let profile = load_active_enrollment_provider_profile(&self.storage, snapshot.provider_profile_id)
            .await
            .map_err(map_provider_failure)?;
        let route = self
            .egress_resolver
            .resolve(&snapshot.egress)
            .await
            .map_err(map_provider_failure)?;
        let existing = self.load_existing_browser_material(&snapshot).await?;
        if snapshot.intent == "reactivate" && existing.is_none() {
            return Err(ManagedBrowserFailure::terminal("managed_browser_material_missing"));
        }
        let mut input = HelperInput::new(&snapshot, &profile, &route, existing);
        let encoded = serde_json::to_vec(&input)
            .map(SecretBytes::new)
            .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_input_invalid"))?;
        input.zeroize();
        let mut output = self.run_helper(&encoded).await?;
        output.validate()?;
        let access_token = SecretValue::new(std::mem::take(&mut output.access_token));
        let refresh_token = SecretValue::new(std::mem::take(&mut output.refresh_token));
        let adapter =
            SubscriptionEnrollmentAdapter::new(self.provider_http.clone(), profile).map_err(map_provider_failure)?;
        let verified = adapter
            .verify_existing_oauth(access_token, Some(refresh_token), snapshot.egress.clone())
            .await
            .map_err(map_provider_failure)?;
        if verified.account_uuid != snapshot.account_uuid {
            return Err(ManagedBrowserFailure::terminal("managed_browser_account_mismatch"));
        }
        let browser = output.decode_browser_material()?;
        let staged = self
            .stage_candidates(
                &snapshot,
                verified,
                browser,
                &output.adapter_version,
                output.expires_in_seconds,
            )
            .await?;
        self.commit_candidates(&snapshot, staged, job).await
    }

    async fn claim_operation(
        &self,
        payload: &BrowserJobPayload,
        job: &JobLease,
    ) -> Result<BrowserSnapshot, ManagedBrowserFailure> {
        let mut transaction = self.storage.pool().begin().await.map_err(storage_retry)?;
        let row = sqlx::query(
            "SELECT credential.group_id,credential.revision AS credential_revision,credential.token_version, \
                    credential.account_uuid,credential.provider_profile_id,credential.auth_kind_code, \
                    binding.id AS binding_id,binding.mode_code,binding.proxy_id,binding.egress_epoch, \
                    strategy.revision AS strategy_revision,strategy.active_material_version_id, \
                    operation.operation_generation,operation.state_code AS operation_state \
             FROM ops.durable_job job \
             JOIN gateway.maintenance_operation operation ON operation.durable_job_id=job.id \
             JOIN gateway.anthropic_credential credential ON credential.id=operation.credential_id \
             JOIN gateway.credential_egress_binding binding ON binding.id=operation.egress_binding_id \
               AND binding.credential_id=credential.id \
             JOIN gateway.auto_reauth_strategy strategy ON strategy.id=$3 AND strategy.credential_id=credential.id \
             WHERE job.id=$1 AND job.kind_code='credential_managed_browser_v1' AND job.state_code='leased' \
               AND job.lease_generation=$2 AND operation.id=$4 AND credential.id=$5 \
             FOR UPDATE OF job,operation,credential,binding,strategy",
        )
        .bind(job.job_id)
        .bind(job.generation)
        .bind(payload.strategy_id)
        .bind(payload.operation_id)
        .bind(payload.credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_retry)?
        .ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_snapshot_stale"))?;
        let operation_generation: i64 = required(&row, "operation_generation")?;
        let operation_state: String = required(&row, "operation_state")?;
        if operation_generation != payload.operation_generation
            || !matches!(
                operation_state.as_str(),
                "planned"
                    | "leased"
                    | "running"
                    | "verifying_account"
                    | "committing"
                    | "waiting_backoff"
                    | "waiting_egress"
            )
        {
            return Err(ManagedBrowserFailure::terminal("managed_browser_operation_stale"));
        }
        let credential_revision: i64 = required(&row, "credential_revision")?;
        let token_version: i64 = required(&row, "token_version")?;
        let strategy_revision: i64 = required(&row, "strategy_revision")?;
        let account_uuid: Uuid = required(&row, "account_uuid")?;
        let provider_profile_id: Uuid = required(&row, "provider_profile_id")?;
        let binding_id: Uuid = required(&row, "binding_id")?;
        let egress_epoch: i64 = required(&row, "egress_epoch")?;
        if credential_revision != payload.credential_revision
            || token_version != payload.token_version
            || strategy_revision != payload.strategy_revision
            || account_uuid != payload.account_uuid
            || provider_profile_id != payload.provider_profile_id
            || binding_id != payload.binding_id
            || egress_epoch != payload.egress_epoch
            || required::<String>(&row, "auth_kind_code")? != "oauth_subscription"
        {
            return Err(ManagedBrowserFailure::terminal(
                "managed_browser_material_snapshot_changed",
            ));
        }
        let changed = sqlx::query(
            "UPDATE gateway.maintenance_operation SET state_code='running',started_at=COALESCE(started_at,clock_timestamp()), \
               heartbeat_at=clock_timestamp(),retry_after=NULL,updated_at=clock_timestamp() \
             WHERE id=$1 AND operation_generation=$2 AND state_code=$3",
        )
        .bind(payload.operation_id)
        .bind(operation_generation)
        .bind(&operation_state)
        .execute(&mut *transaction)
        .await
        .map_err(storage_retry)?;
        if changed.rows_affected() != 1 {
            return Err(ManagedBrowserFailure::retry(
                "managed_browser_operation_claim_conflict",
                5,
            ));
        }
        transaction.commit().await.map_err(storage_retry)?;
        let mode_code: String = required(&row, "mode_code")?;
        let proxy_id: Option<Uuid> = required(&row, "proxy_id")?;
        let mode = match mode_code.as_str() {
            "direct" if proxy_id.is_none() => EgressMode::Direct,
            "proxy" if proxy_id.is_some() => EgressMode::Proxy,
            _ => return Err(ManagedBrowserFailure::retry("managed_browser_egress_unavailable", 30)),
        };
        Ok(BrowserSnapshot {
            credential_id: payload.credential_id,
            group_id: required(&row, "group_id")?,
            credential_revision,
            token_version,
            account_uuid,
            provider_profile_id,
            binding_id,
            egress_epoch,
            strategy_id: payload.strategy_id,
            strategy_revision,
            operation_id: payload.operation_id,
            operation_generation,
            active_material_version_id: required(&row, "active_material_version_id")?,
            intent: payload.intent.clone(),
            egress: EgressBindingSnapshot {
                binding_id: EgressBindingId::new(binding_id.to_string())
                    .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_binding_invalid"))?,
                mode,
                proxy_id: proxy_id
                    .map(|id| ProxyEndpointId::new(id.to_string()))
                    .transpose()
                    .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_proxy_invalid"))?,
                egress_epoch: u64::try_from(egress_epoch)
                    .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_egress_invalid"))?,
            },
        })
    }

    async fn load_existing_browser_material(
        &self,
        snapshot: &BrowserSnapshot,
    ) -> Result<Option<ExistingBrowserMaterial>, ManagedBrowserFailure> {
        let Some(material_id) = snapshot.active_material_version_id else {
            return Ok(None);
        };
        let row = sqlx::query(
            "SELECT cookie_secret_id,storage_secret_id,profile_secret_id FROM gateway.managed_browser_material_version \
             WHERE id=$1 AND credential_id=$2 AND strategy_id=$3 AND state_code='active' AND egress_epoch=$4",
        )
        .bind(material_id)
        .bind(snapshot.credential_id)
        .bind(snapshot.strategy_id)
        .bind(snapshot.egress_epoch)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(storage_retry)?
        .ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_material_invalid"))?;
        let cookie = self
            .decrypt_browser_secret(
                required(&row, "cookie_secret_id")?,
                snapshot.credential_id,
                "managed_browser_cookie",
            )
            .await?;
        let storage = match required::<Option<Uuid>>(&row, "storage_secret_id")? {
            Some(id) => Some(
                self.decrypt_browser_secret(id, snapshot.credential_id, "managed_browser_storage")
                    .await?,
            ),
            None => None,
        };
        let profile = self
            .decrypt_browser_secret(
                required(&row, "profile_secret_id")?,
                snapshot.credential_id,
                "managed_browser_profile",
            )
            .await?;
        Ok(Some(ExistingBrowserMaterial {
            cookie,
            storage,
            profile,
        }))
    }

    async fn decrypt_browser_secret(
        &self,
        secret_id: Uuid,
        credential_id: Uuid,
        expected_purpose: &str,
    ) -> Result<SecretBytes, ManagedBrowserFailure> {
        let row = sqlx::query(
            "SELECT secret_kind_code,provider_role_code,cipher_suite_code,ciphertext,nonce,wrapped_dek,key_version, \
                    aad_schema_version,owner_type_code,owner_id,purpose_code \
             FROM security.encrypted_secret WHERE id=$1 AND destroyed_at IS NULL AND superseded_at IS NULL",
        )
        .bind(secret_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(storage_retry)?
        .ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_secret_missing"))?;
        let owner_id = credential_id.to_string();
        if required::<String>(&row, "secret_kind_code")? != "managed_browser"
            || required::<String>(&row, "provider_role_code")? != "business"
            || required::<String>(&row, "owner_type_code")? != "credential"
            || required::<String>(&row, "owner_id")? != owner_id
            || required::<String>(&row, "purpose_code")? != expected_purpose
        {
            return Err(ManagedBrowserFailure::terminal("managed_browser_secret_scope_invalid"));
        }
        decrypt_envelope(&self.storage, secret_id, &row).await
    }

    async fn run_helper(&self, input: &SecretBytes) -> Result<HelperOutput, ManagedBrowserFailure> {
        let mut child = Command::new(&self.tool)
            .arg("reauthenticate")
            .arg("--json-stdin")
            .arg("--json-stdout")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| ManagedBrowserFailure::retry("managed_browser_helper_unavailable", 30))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| ManagedBrowserFailure::retry("managed_browser_helper_unavailable", 30))?;
        stdin
            .write_all(input.expose())
            .await
            .map_err(|_| ManagedBrowserFailure::retry("managed_browser_helper_io_failed", 30))?;
        drop(stdin);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ManagedBrowserFailure::retry("managed_browser_helper_unavailable", 30))?;
        let mut bounded = stdout.take(MAX_HELPER_OUTPUT + 1);
        let (status, bytes) = tokio::time::timeout(self.timeout, async {
            let mut bytes = Vec::new();
            let (status, _) = tokio::try_join!(child.wait(), bounded.read_to_end(&mut bytes))?;
            Ok::<_, std::io::Error>((status, bytes))
        })
        .await
        .map_err(|_| ManagedBrowserFailure::retry("managed_browser_helper_timeout", 30))?
        .map_err(|_| ManagedBrowserFailure::retry("managed_browser_helper_io_failed", 30))?;
        let bytes = SecretBytes::new(bytes);
        if bytes.expose().len() > usize::try_from(MAX_HELPER_OUTPUT).unwrap_or(usize::MAX) {
            return Err(ManagedBrowserFailure::terminal(
                "managed_browser_helper_output_too_large",
            ));
        }
        if !status.success() {
            return Err(if status.code() == Some(75) {
                ManagedBrowserFailure::retry("managed_browser_helper_transient", 30)
            } else {
                ManagedBrowserFailure::terminal("managed_browser_session_invalid")
            });
        }
        serde_json::from_slice(bytes.expose())
            .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_helper_output_invalid"))
    }

    async fn stage_candidates(
        &self,
        snapshot: &BrowserSnapshot,
        verified: VerifiedEnrollmentMaterial,
        browser: DecodedBrowserMaterial,
        browser_adapter_version: &str,
        expires_in_seconds: Option<u64>,
    ) -> Result<StagedCandidates, ManagedBrowserFailure> {
        let refresh = verified
            .refresh_token
            .as_ref()
            .ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_refresh_token_missing"))?;
        let key_version: i64 = sqlx::query_scalar(
            "SELECT key_version FROM security.business_key_material WHERE provider_code='database' AND state_code='active'",
        )
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(storage_retry)?
        .ok_or_else(|| ManagedBrowserFailure::retry("managed_browser_key_unavailable", 30))?;
        let key = self
            .storage
            .load_database_business_key(key_version)
            .await
            .map_err(storage_failure)?;
        let provider = LocalAesKeyProvider::new(
            "business",
            u64::try_from(key_version).map_err(|_| ManagedBrowserFailure::terminal("managed_browser_key_invalid"))?,
            key.expose().to_vec(),
        )
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_key_invalid"))?;
        let service = EnvelopeService::new(provider);
        let access = encrypt_credential_secret(
            &service,
            snapshot.credential_id,
            "oauth_access_token",
            "anthropic_auth",
            &SecretBytes::new(verified.access_token.expose().as_bytes().to_vec()),
            key_version,
        )?;
        let refresh = encrypt_credential_secret(
            &service,
            snapshot.credential_id,
            "oauth_refresh_token",
            "anthropic_auth",
            &SecretBytes::new(refresh.expose().as_bytes().to_vec()),
            key_version,
        )?;
        let cookie = encrypt_credential_secret(
            &service,
            snapshot.credential_id,
            "managed_browser",
            "managed_browser_cookie",
            &browser.cookie,
            key_version,
        )?;
        let storage_secret = browser
            .storage
            .as_ref()
            .map(|value| {
                encrypt_credential_secret(
                    &service,
                    snapshot.credential_id,
                    "managed_browser",
                    "managed_browser_storage",
                    value,
                    key_version,
                )
            })
            .transpose()?;
        let profile = encrypt_credential_secret(
            &service,
            snapshot.credential_id,
            "managed_browser",
            "managed_browser_profile",
            &browser.profile,
            key_version,
        )?;
        let mut transaction = self.storage.pool().begin().await.map_err(storage_retry)?;
        let row = sqlx::query(
            "SELECT strategy.revision, \
                    (SELECT COALESCE(MAX(material.material_version),0)+1 \
                     FROM gateway.managed_browser_material_version material WHERE material.strategy_id=strategy.id) \
                    AS next_material_version \
             FROM gateway.auto_reauth_strategy strategy \
             WHERE strategy.id=$1 AND strategy.credential_id=$2 FOR UPDATE OF strategy",
        )
        .bind(snapshot.strategy_id)
        .bind(snapshot.credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_retry)?
        .ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_strategy_missing"))?;
        if required::<i64>(&row, "revision")? != snapshot.strategy_revision {
            return Err(ManagedBrowserFailure::terminal("managed_browser_strategy_stale"));
        }
        let material_version: i64 = required(&row, "next_material_version")?;
        for secret in [&access, &refresh, &cookie, &profile] {
            insert_secret(&mut transaction, secret).await?;
        }
        if let Some(secret) = &storage_secret {
            insert_secret(&mut transaction, secret).await?;
        }
        sqlx::query(
            "INSERT INTO gateway.credential_auth_secret_stage \
             (operation_id,operation_generation,credential_id,candidate_token_version,access_secret_id,refresh_secret_id) \
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(snapshot.operation_id)
        .bind(snapshot.operation_generation)
        .bind(snapshot.credential_id)
        .bind(snapshot.token_version + 1)
        .bind(access.aad.secret_id)
        .bind(refresh.aad.secret_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_retry)?;
        sqlx::query(
            "INSERT INTO gateway.managed_browser_secret_stage \
             (operation_id,operation_generation,credential_id,strategy_id,candidate_material_version, \
              cookie_secret_id,storage_secret_id,profile_secret_id,verified_account_uuid,adapter_version) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(snapshot.operation_id)
        .bind(snapshot.operation_generation)
        .bind(snapshot.credential_id)
        .bind(snapshot.strategy_id)
        .bind(material_version)
        .bind(cookie.aad.secret_id)
        .bind(storage_secret.as_ref().map(|secret| secret.aad.secret_id))
        .bind(profile.aad.secret_id)
        .bind(verified.account_uuid)
        .bind(browser_adapter_version)
        .execute(&mut *transaction)
        .await
        .map_err(storage_retry)?;
        transaction.commit().await.map_err(storage_retry)?;
        let expires_at_epoch_seconds = expires_in_seconds
            .and_then(|seconds| i64::try_from(seconds).ok())
            .and_then(|seconds| chrono_epoch_seconds().checked_add(seconds));
        Ok(StagedCandidates {
            access_secret_id: access.aad.secret_id,
            refresh_secret_id: refresh.aad.secret_id,
            cookie_secret_id: cookie.aad.secret_id,
            storage_secret_id: storage_secret.as_ref().map(|secret| secret.aad.secret_id),
            profile_secret_id: profile.aad.secret_id,
            material_version,
            browser_adapter_version: browser_adapter_version.to_owned(),
            auth_adapter_version: verified.adapter_version.into_string(),
            expires_at_epoch_seconds,
        })
    }

    async fn load_staged_candidates(
        &self,
        snapshot: &BrowserSnapshot,
        job: &JobLease,
    ) -> Result<Option<StagedCandidates>, ManagedBrowserFailure> {
        let row = sqlx::query(
            "SELECT auth.access_secret_id,auth.refresh_secret_id,browser.cookie_secret_id,browser.storage_secret_id, \
                    browser.profile_secret_id,browser.candidate_material_version,browser.adapter_version \
             FROM gateway.credential_auth_secret_stage auth \
             JOIN gateway.managed_browser_secret_stage browser ON browser.operation_id=auth.operation_id \
               AND browser.operation_generation=auth.operation_generation AND browser.credential_id=auth.credential_id \
             JOIN ops.durable_job job ON job.id=$4 AND job.state_code='leased' AND job.lease_generation=$5 \
             WHERE auth.operation_id=$1 AND auth.operation_generation=$2 AND auth.credential_id=$3",
        )
        .bind(snapshot.operation_id)
        .bind(snapshot.operation_generation)
        .bind(snapshot.credential_id)
        .bind(job.job_id)
        .bind(job.generation)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(storage_retry)?;
        row.map(|row| {
            Ok(StagedCandidates {
                access_secret_id: required(&row, "access_secret_id")?,
                refresh_secret_id: required(&row, "refresh_secret_id")?,
                cookie_secret_id: required(&row, "cookie_secret_id")?,
                storage_secret_id: required(&row, "storage_secret_id")?,
                profile_secret_id: required(&row, "profile_secret_id")?,
                material_version: required(&row, "candidate_material_version")?,
                browser_adapter_version: required(&row, "adapter_version")?,
                auth_adapter_version: "managed-browser-resume-v1".to_owned(),
                expires_at_epoch_seconds: None,
            })
        })
        .transpose()
    }

    async fn commit_candidates(
        &self,
        snapshot: &BrowserSnapshot,
        staged: StagedCandidates,
        job: &JobLease,
    ) -> Result<ManagedBrowserCommit, ManagedBrowserFailure> {
        let result = self
            .storage
            .commit_browser_reauth_candidate(
                &AuthCandidateRecord {
                    auth_version_id: Uuid::now_v7(),
                    credential_id: snapshot.credential_id,
                    auth_kind: AuthKind::OauthSubscription,
                    access_secret_id: Some(staged.access_secret_id),
                    refresh_secret_id: Some(staged.refresh_secret_id),
                    console_secret_id: None,
                    verified_account_uuid: Some(snapshot.account_uuid),
                    expires_at_epoch_seconds: staged.expires_at_epoch_seconds,
                    adapter_code: Some("managed_browser".to_owned()),
                    adapter_version: Some(staged.auth_adapter_version),
                },
                &BrowserMaterialCandidate {
                    material_version_id: Uuid::now_v7(),
                    strategy_id: snapshot.strategy_id,
                    credential_id: snapshot.credential_id,
                    material_version: staged.material_version,
                    cookie_secret_id: staged.cookie_secret_id,
                    storage_secret_id: staged.storage_secret_id,
                    profile_secret_id: staged.profile_secret_id,
                    verified_account_uuid: snapshot.account_uuid,
                    adapter_version: staged.browser_adapter_version,
                },
                &BrowserCasPrecondition {
                    strategy_revision: snapshot.strategy_revision,
                    auth: AuthCasPrecondition {
                        expected_credential_revision: snapshot.credential_revision,
                        expected_token_version: snapshot.token_version,
                        expected_account_uuid: Some(snapshot.account_uuid),
                        expected_egress_binding_id: snapshot.binding_id,
                        expected_egress_epoch: snapshot.egress_epoch,
                        operation_id: snapshot.operation_id,
                        operation_generation: snapshot.operation_generation,
                        durable_job_fence: None,
                    },
                    durable_job_id: Some(job.job_id),
                    durable_job_generation: Some(job.generation),
                },
            )
            .await
            .map_err(storage_failure)?;
        Ok(ManagedBrowserCommit {
            credential_id: snapshot.credential_id,
            group_id: snapshot.group_id,
            credential_revision: result.auth.credential_revision,
            token_version: result.auth.token_version,
        })
    }

    pub(crate) async fn record_retry(&self, job: &JobLease, failure: &ManagedBrowserFailure) {
        let operation_id = payload_uuid(&job.payload, "operation_id");
        let operation_generation = job
            .payload
            .get("operation_generation")
            .and_then(serde_json::Value::as_i64);
        if let (Some(operation_id), Some(operation_generation)) = (operation_id, operation_generation) {
            let state = if failure.code.contains("egress") {
                "waiting_egress"
            } else {
                "waiting_backoff"
            };
            let _ = sqlx::query(
                "UPDATE gateway.maintenance_operation SET state_code=$3,error_category_code=$4,retry_count=retry_count+1, \
                   retry_after=clock_timestamp()+make_interval(secs=>$5),heartbeat_at=clock_timestamp(),updated_at=clock_timestamp() \
                 WHERE id=$1 AND operation_generation=$2 \
                   AND EXISTS(SELECT 1 FROM ops.durable_job WHERE id=$6 AND state_code='leased' AND lease_generation=$7) \
                   AND state_code NOT IN ('succeeded','failed','cancelled','expired')",
            )
            .bind(operation_id)
            .bind(operation_generation)
            .bind(state)
            .bind(failure.code)
            .bind(i64::from(failure.retry_after_seconds.unwrap_or(30)))
            .bind(job.job_id)
            .bind(job.generation)
            .execute(&self.storage.pool())
            .await;
        }
    }

    pub(crate) async fn record_terminal(&self, job: &JobLease, failure: &ManagedBrowserFailure) {
        let Some(operation_id) = payload_uuid(&job.payload, "operation_id") else {
            return;
        };
        let strategy_id = payload_uuid(&job.payload, "strategy_id");
        let credential_id = payload_uuid(&job.payload, "credential_id");
        let operation_generation = job
            .payload
            .get("operation_generation")
            .and_then(serde_json::Value::as_i64);
        let (Some(strategy_id), Some(credential_id), Some(operation_generation)) =
            (strategy_id, credential_id, operation_generation)
        else {
            return;
        };
        let mut transaction = match self.storage.pool().begin().await {
            Ok(transaction) => transaction,
            Err(_) => return,
        };
        let current_job: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ops.durable_job WHERE id=$1 AND state_code='leased' \
             AND lease_generation=$2 FOR UPDATE)",
        )
        .bind(job.job_id)
        .bind(job.generation)
        .fetch_one(&mut *transaction)
        .await
        .unwrap_or(false);
        if !current_job {
            return;
        }
        let _ = sqlx::query(
            "UPDATE gateway.maintenance_operation SET state_code='failed',outcome_code='browser_reauth_failed', \
               error_category_code=$4,completed_at=clock_timestamp(),updated_at=clock_timestamp() \
             WHERE id=$1 AND credential_id=$2 AND operation_generation=$3 \
               AND state_code NOT IN ('succeeded','failed','cancelled','expired')",
        )
        .bind(operation_id)
        .bind(credential_id)
        .bind(operation_generation)
        .bind(failure.code)
        .execute(&mut *transaction)
        .await;
        let _ = sqlx::query(
            "UPDATE gateway.auto_reauth_strategy SET state_code='invalid',last_error_code=$2,revision=revision+1, \
               updated_at=clock_timestamp() WHERE id=$1 AND state_code<>'disabled'",
        )
        .bind(strategy_id)
        .bind(failure.code)
        .execute(&mut *transaction)
        .await;
        let _ = sqlx::query(
            "UPDATE security.encrypted_secret SET superseded_at=COALESCE(superseded_at,clock_timestamp()), \
               destroyed_at=COALESCE(destroyed_at,clock_timestamp()),ciphertext='\\x'::bytea,nonce='\\x000000000000000000000000'::bytea,wrapped_dek='\\x'::bytea \
             WHERE id IN (SELECT access_secret_id FROM gateway.credential_auth_secret_stage WHERE operation_id=$1 AND operation_generation=$2 \
                          UNION SELECT refresh_secret_id FROM gateway.credential_auth_secret_stage WHERE operation_id=$1 AND operation_generation=$2 \
                          UNION SELECT cookie_secret_id FROM gateway.managed_browser_secret_stage WHERE operation_id=$1 AND operation_generation=$2 \
                          UNION SELECT storage_secret_id FROM gateway.managed_browser_secret_stage WHERE operation_id=$1 AND operation_generation=$2 \
                          UNION SELECT profile_secret_id FROM gateway.managed_browser_secret_stage WHERE operation_id=$1 AND operation_generation=$2)",
        )
        .bind(operation_id)
        .bind(operation_generation)
        .execute(&mut *transaction)
        .await;
        let _ = sqlx::query(
            "DELETE FROM gateway.managed_browser_secret_stage WHERE operation_id=$1 AND operation_generation=$2",
        )
        .bind(operation_id)
        .bind(operation_generation)
        .execute(&mut *transaction)
        .await;
        let _ = sqlx::query(
            "DELETE FROM gateway.credential_auth_secret_stage WHERE operation_id=$1 AND operation_generation=$2",
        )
        .bind(operation_id)
        .bind(operation_generation)
        .execute(&mut *transaction)
        .await;
        let _ = transaction.commit().await;
    }
}

#[async_trait::async_trait]
pub(crate) trait ManagedBrowserEgressResolver: Send + Sync {
    async fn resolve(&self, snapshot: &EgressBindingSnapshot) -> Result<EgressRouteSnapshot, CredentialServiceError>;
}

#[derive(Clone)]
struct SharedProviderHttp(Arc<dyn ProviderHttpPort>);

#[async_trait::async_trait]
impl ProviderHttpPort for SharedProviderHttp {
    async fn execute(&self, request: ProviderHttpRequest) -> Result<ProviderHttpResponse, CredentialServiceError> {
        self.0.execute(request).await
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedBrowserCommit {
    pub(crate) credential_id: Uuid,
    pub(crate) group_id: Uuid,
    pub(crate) credential_revision: i64,
    pub(crate) token_version: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedBrowserFailure {
    pub(crate) code: &'static str,
    pub(crate) retry_after_seconds: Option<u32>,
}

impl ManagedBrowserFailure {
    fn retry(code: &'static str, seconds: u32) -> Self {
        Self {
            code,
            retry_after_seconds: Some(seconds),
        }
    }

    fn terminal(code: &'static str) -> Self {
        Self {
            code,
            retry_after_seconds: None,
        }
    }
}

struct BrowserSnapshot {
    credential_id: Uuid,
    group_id: Uuid,
    credential_revision: i64,
    token_version: i64,
    account_uuid: Uuid,
    provider_profile_id: Uuid,
    binding_id: Uuid,
    egress_epoch: i64,
    strategy_id: Uuid,
    strategy_revision: i64,
    operation_id: Uuid,
    operation_generation: i64,
    active_material_version_id: Option<Uuid>,
    intent: String,
    egress: EgressBindingSnapshot,
}

struct StagedCandidates {
    access_secret_id: Uuid,
    refresh_secret_id: Uuid,
    cookie_secret_id: Uuid,
    storage_secret_id: Option<Uuid>,
    profile_secret_id: Uuid,
    material_version: i64,
    browser_adapter_version: String,
    auth_adapter_version: String,
    expires_at_epoch_seconds: Option<i64>,
}

struct ExistingBrowserMaterial {
    cookie: SecretBytes,
    storage: Option<SecretBytes>,
    profile: SecretBytes,
}

struct DecodedBrowserMaterial {
    cookie: SecretBytes,
    storage: Option<SecretBytes>,
    profile: SecretBytes,
}

#[derive(Serialize)]
struct HelperInput {
    schema_version: u32,
    intent: String,
    credential_id: String,
    account_uuid: String,
    authorize_endpoint: String,
    token_endpoint: String,
    profile_endpoint: String,
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    egress: HelperEgress,
    existing: Option<HelperExistingMaterial>,
}

impl HelperInput {
    fn new(
        snapshot: &BrowserSnapshot,
        profile: &gateway_services::credential_enrollment::EnrollmentProviderProfile,
        route: &EgressRouteSnapshot,
        existing: Option<ExistingBrowserMaterial>,
    ) -> Self {
        Self {
            schema_version: 1,
            intent: snapshot.intent.clone(),
            credential_id: snapshot.credential_id.to_string(),
            account_uuid: snapshot.account_uuid.to_string(),
            authorize_endpoint: profile.authorize_endpoint.to_string(),
            token_endpoint: profile.token_endpoint.to_string(),
            profile_endpoint: profile.profile_endpoint.to_string(),
            client_id: profile.client_id.to_string(),
            redirect_uri: profile.redirect_uri.to_string(),
            scopes: profile.scopes.iter().map(ToString::to_string).collect(),
            egress: HelperEgress::from_route(route),
            existing: existing.map(HelperExistingMaterial::from),
        }
    }

    fn zeroize(&mut self) {
        self.intent.zeroize();
        self.credential_id.zeroize();
        self.account_uuid.zeroize();
        self.authorize_endpoint.zeroize();
        self.token_endpoint.zeroize();
        self.profile_endpoint.zeroize();
        self.client_id.zeroize();
        self.redirect_uri.zeroize();
        self.scopes.zeroize();
        self.egress.zeroize();
        if let Some(existing) = &mut self.existing {
            existing.zeroize();
        }
    }
}

impl Drop for HelperInput {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Serialize)]
struct HelperEgress {
    mode: String,
    proxy_type: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    remote_dns: bool,
}

impl HelperEgress {
    fn from_route(route: &EgressRouteSnapshot) -> Self {
        match route {
            EgressRouteSnapshot::Direct => Self {
                mode: "direct".to_owned(),
                proxy_type: None,
                host: None,
                port: None,
                username: None,
                password: None,
                remote_dns: false,
            },
            EgressRouteSnapshot::HttpConnect {
                host,
                port,
                credentials,
            } => Self {
                mode: "proxy".to_owned(),
                proxy_type: Some("http_connect".to_owned()),
                host: Some(host.to_string()),
                port: Some(*port),
                username: credentials.as_ref().map(|value| value.username.expose().to_owned()),
                password: credentials.as_ref().map(|value| value.password.expose().to_owned()),
                remote_dns: true,
            },
            EgressRouteSnapshot::Socks5 {
                host,
                port,
                dns,
                credentials,
            } => Self {
                mode: "proxy".to_owned(),
                proxy_type: Some("socks5".to_owned()),
                host: Some(host.to_string()),
                port: Some(*port),
                username: credentials.as_ref().map(|value| value.username.expose().to_owned()),
                password: credentials.as_ref().map(|value| value.password.expose().to_owned()),
                remote_dns: matches!(dns, gateway_domain::Socks5DnsMode::Remote),
            },
        }
    }

    fn zeroize(&mut self) {
        self.mode.zeroize();
        self.proxy_type.zeroize();
        self.host.zeroize();
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Serialize)]
struct HelperExistingMaterial {
    cookie_jar_base64: String,
    web_storage_base64: Option<String>,
    profile_state_base64: String,
}

impl From<ExistingBrowserMaterial> for HelperExistingMaterial {
    fn from(value: ExistingBrowserMaterial) -> Self {
        Self {
            cookie_jar_base64: STANDARD.encode(value.cookie.expose()),
            web_storage_base64: value.storage.as_ref().map(|value| STANDARD.encode(value.expose())),
            profile_state_base64: STANDARD.encode(value.profile.expose()),
        }
    }
}

impl HelperExistingMaterial {
    fn zeroize(&mut self) {
        self.cookie_jar_base64.zeroize();
        self.web_storage_base64.zeroize();
        self.profile_state_base64.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperOutput {
    schema_version: u32,
    access_token: String,
    refresh_token: String,
    expires_in_seconds: Option<u64>,
    cookie_jar_base64: String,
    web_storage_base64: Option<String>,
    profile_state_base64: String,
    adapter_version: String,
}

impl Drop for HelperOutput {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.cookie_jar_base64.zeroize();
        self.web_storage_base64.zeroize();
        self.profile_state_base64.zeroize();
        self.adapter_version.zeroize();
    }
}

impl HelperOutput {
    fn validate(&self) -> Result<(), ManagedBrowserFailure> {
        if self.schema_version != 1
            || self.access_token.is_empty()
            || self.refresh_token.is_empty()
            || self.adapter_version.trim().is_empty()
            || self.adapter_version.len() > 128
            || self
                .expires_in_seconds
                .is_some_and(|seconds| seconds == 0 || seconds > 366 * 24 * 60 * 60)
        {
            return Err(ManagedBrowserFailure::terminal("managed_browser_helper_output_invalid"));
        }
        Ok(())
    }

    fn decode_browser_material(&self) -> Result<DecodedBrowserMaterial, ManagedBrowserFailure> {
        let cookie = decode_component(&self.cookie_jar_base64)?;
        let storage = self.web_storage_base64.as_deref().map(decode_component).transpose()?;
        let profile = decode_component(&self.profile_state_base64)?;
        if cookie.expose().is_empty() || profile.expose().is_empty() {
            return Err(ManagedBrowserFailure::terminal("managed_browser_material_invalid"));
        }
        Ok(DecodedBrowserMaterial {
            cookie,
            storage,
            profile,
        })
    }
}

struct BrowserJobPayload {
    credential_id: Uuid,
    strategy_id: Uuid,
    operation_id: Uuid,
    operation_generation: i64,
    credential_revision: i64,
    token_version: i64,
    strategy_revision: i64,
    account_uuid: Uuid,
    provider_profile_id: Uuid,
    binding_id: Uuid,
    egress_epoch: i64,
    intent: String,
}

impl BrowserJobPayload {
    fn parse(job: &JobLease) -> Result<Self, ManagedBrowserFailure> {
        let intent = job
            .payload
            .get("intent")
            .and_then(serde_json::Value::as_str)
            .filter(|value| matches!(*value, "initialize" | "reactivate" | "refresh_fallback"))
            .ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_payload_invalid"))?
            .to_owned();
        Ok(Self {
            credential_id: required_payload_uuid(job, "credential_id")?,
            strategy_id: required_payload_uuid(job, "strategy_id")?,
            operation_id: required_payload_uuid(job, "operation_id")?,
            operation_generation: required_payload_i64(job, "operation_generation")?,
            credential_revision: required_payload_i64(job, "credential_revision")?,
            token_version: required_payload_i64(job, "token_version")?,
            strategy_revision: required_payload_i64(job, "strategy_revision")?,
            account_uuid: required_payload_uuid(job, "account_uuid")?,
            provider_profile_id: required_payload_uuid(job, "provider_profile_id")?,
            binding_id: required_payload_uuid(job, "binding_id")?,
            egress_epoch: required_payload_i64(job, "egress_epoch")?,
            intent,
        })
    }
}

struct PreparedSecret {
    aad: EnvelopeAad,
    envelope: SecretEnvelope,
}

fn encrypt_credential_secret(
    service: &EnvelopeService<LocalAesKeyProvider>,
    credential_id: Uuid,
    kind: &str,
    purpose: &str,
    plaintext: &SecretBytes,
    key_version: i64,
) -> Result<PreparedSecret, ManagedBrowserFailure> {
    let aad = EnvelopeAad {
        schema_version: 1,
        secret_id: Uuid::now_v7(),
        secret_kind: kind.to_owned(),
        provider_role: "business".to_owned(),
        owner_type: "credential".to_owned(),
        owner_id: credential_id.to_string(),
        purpose: purpose.to_owned(),
        key_version: u64::try_from(key_version)
            .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_key_invalid"))?,
    };
    let envelope = service
        .encrypt(plaintext, aad.clone())
        .map_err(|_| ManagedBrowserFailure::retry("managed_browser_encrypt_failed", 30))?;
    Ok(PreparedSecret { aad, envelope })
}

async fn insert_secret(
    transaction: &mut Transaction<'_, Postgres>,
    secret: &PreparedSecret,
) -> Result<(), ManagedBrowserFailure> {
    let ciphertext = STANDARD
        .decode(&secret.envelope.ciphertext_base64)
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_envelope_invalid"))?;
    let nonce = STANDARD
        .decode(&secret.envelope.nonce_base64)
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_envelope_invalid"))?;
    let wrapped_dek = STANDARD
        .decode(&secret.envelope.wrapped_dek_base64)
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_envelope_invalid"))?;
    let key_version = i64::try_from(secret.envelope.key_version)
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_envelope_invalid"))?;
    let schema_version = i32::try_from(secret.envelope.schema_version)
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_envelope_invalid"))?;
    sqlx::query(
        "INSERT INTO security.encrypted_secret \
         (id,secret_kind_code,provider_role_code,cipher_suite_code,ciphertext,nonce,wrapped_dek,key_version, \
          aad_schema_version,owner_type_code,owner_id,purpose_code,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp())",
    )
    .bind(secret.aad.secret_id)
    .bind(&secret.aad.secret_kind)
    .bind(&secret.aad.provider_role)
    .bind(&secret.envelope.cipher_suite)
    .bind(ciphertext)
    .bind(nonce)
    .bind(wrapped_dek)
    .bind(key_version)
    .bind(schema_version)
    .bind(&secret.aad.owner_type)
    .bind(&secret.aad.owner_id)
    .bind(&secret.aad.purpose)
    .execute(&mut **transaction)
    .await
    .map_err(storage_retry)?;
    Ok(())
}

async fn decrypt_envelope(
    storage: &PgStorage,
    secret_id: Uuid,
    row: &sqlx::postgres::PgRow,
) -> Result<SecretBytes, ManagedBrowserFailure> {
    let key_version: i64 = required(row, "key_version")?;
    let schema_version = u32::try_from(required::<i32>(row, "aad_schema_version")?)
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_secret_invalid"))?;
    let aad = EnvelopeAad {
        schema_version,
        secret_id,
        secret_kind: required(row, "secret_kind_code")?,
        provider_role: required(row, "provider_role_code")?,
        owner_type: required(row, "owner_type_code")?,
        owner_id: required(row, "owner_id")?,
        purpose: required(row, "purpose_code")?,
        key_version: u64::try_from(key_version)
            .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_secret_invalid"))?,
    };
    let envelope = SecretEnvelope {
        schema_version,
        cipher_suite: required(row, "cipher_suite_code")?,
        provider_role: aad.provider_role.clone(),
        key_version: aad.key_version,
        ciphertext_base64: STANDARD.encode(required::<Vec<u8>>(row, "ciphertext")?),
        nonce_base64: STANDARD.encode(required::<Vec<u8>>(row, "nonce")?),
        wrapped_dek_base64: STANDARD.encode(required::<Vec<u8>>(row, "wrapped_dek")?),
    };
    let key = storage
        .load_database_business_key(key_version)
        .await
        .map_err(storage_failure)?;
    let provider = LocalAesKeyProvider::new("business", aad.key_version, key.expose().to_vec())
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_secret_invalid"))?;
    EnvelopeService::new(provider)
        .decrypt(&envelope, &aad)
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_secret_invalid"))
}

fn decode_component(value: &str) -> Result<SecretBytes, ManagedBrowserFailure> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_material_invalid"))?;
    if decoded.len() > MAX_BROWSER_COMPONENT {
        return Err(ManagedBrowserFailure::terminal("managed_browser_material_too_large"));
    }
    Ok(SecretBytes::new(decoded))
}

fn committed_from_checkpoint(job: &JobLease) -> Result<ManagedBrowserCommit, ManagedBrowserFailure> {
    let checkpoint = job
        .checkpoint
        .as_ref()
        .ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_checkpoint_invalid"))?;
    Ok(ManagedBrowserCommit {
        credential_id: required_payload_uuid(job, "credential_id")?,
        group_id: required_payload_uuid(job, "group_id")?,
        credential_revision: checkpoint
            .get("credential_revision")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_checkpoint_invalid"))?,
        token_version: checkpoint
            .get("token_version")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_checkpoint_invalid"))?,
    })
}

fn required<T>(row: &sqlx::postgres::PgRow, column: &str) -> Result<T, ManagedBrowserFailure>
where
    for<'r> T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column)
        .map_err(|_| ManagedBrowserFailure::terminal("managed_browser_snapshot_invalid"))
}

fn payload_uuid(payload: &serde_json::Value, field: &str) -> Option<Uuid> {
    payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
}

fn required_payload_uuid(job: &JobLease, field: &str) -> Result<Uuid, ManagedBrowserFailure> {
    payload_uuid(&job.payload, field).ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_payload_invalid"))
}

fn required_payload_i64(job: &JobLease, field: &str) -> Result<i64, ManagedBrowserFailure> {
    job.payload
        .get(field)
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| ManagedBrowserFailure::terminal("managed_browser_payload_invalid"))
}

fn map_provider_failure(error: CredentialServiceError) -> ManagedBrowserFailure {
    match error {
        CredentialServiceError::RateLimited(duration) => ManagedBrowserFailure::retry(
            "managed_browser_rate_limited",
            u32::try_from(duration.as_secs().clamp(1, 900)).unwrap_or(900),
        ),
        CredentialServiceError::WaitingEgress => ManagedBrowserFailure::retry("managed_browser_egress_unavailable", 30),
        CredentialServiceError::Transient | CredentialServiceError::WorkerTimeout => {
            ManagedBrowserFailure::retry("managed_browser_provider_transient", 30)
        }
        CredentialServiceError::AccountMismatch => ManagedBrowserFailure::terminal("managed_browser_account_mismatch"),
        CredentialServiceError::InvalidAuthentication => {
            ManagedBrowserFailure::terminal("managed_browser_authentication_invalid")
        }
        _ => ManagedBrowserFailure::terminal("managed_browser_provider_rejected"),
    }
}

fn storage_failure(error: StorageError) -> ManagedBrowserFailure {
    match error {
        StorageError::RevisionConflict | StorageError::InvalidLifecycle => {
            ManagedBrowserFailure::terminal("managed_browser_commit_conflict")
        }
        _ => ManagedBrowserFailure::retry("managed_browser_storage_transient", 30),
    }
}

fn storage_retry(_error: sqlx::Error) -> ManagedBrowserFailure {
    ManagedBrowserFailure::retry("managed_browser_storage_transient", 30)
}

fn chrono_epoch_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use gateway_domain::SecretBytes;
    use serde_json::json;
    use uuid::Uuid;

    use super::{BrowserJobPayload, HelperOutput, ManagedBrowserFailure, committed_from_checkpoint};
    use gateway_storage::JobLease;

    fn job() -> JobLease {
        let credential_id = Uuid::now_v7();
        JobLease {
            job_id: Uuid::now_v7(),
            kind: "credential_managed_browser_v1".to_owned(),
            payload: json!({
                "credential_id":credential_id,
                "group_id":Uuid::now_v7(),
                "strategy_id":Uuid::now_v7(),
                "operation_id":Uuid::now_v7(),
                "operation_generation":1,
                "credential_revision":7,
                "token_version":3,
                "strategy_revision":2,
                "account_uuid":Uuid::now_v7(),
                "provider_profile_id":Uuid::now_v7(),
                "binding_id":Uuid::now_v7(),
                "egress_epoch":4,
                "intent":"reactivate"
            }),
            checkpoint: None,
            generation: 1,
            attempt: 1,
            max_attempts: 5,
        }
    }

    #[test]
    fn helper_output_is_strict_bounded_and_decodes_only_complete_material() {
        let output = HelperOutput {
            schema_version: 1,
            access_token: "access".to_owned(),
            refresh_token: "refresh".to_owned(),
            expires_in_seconds: Some(3600),
            cookie_jar_base64: STANDARD.encode(b"cookie"),
            web_storage_base64: Some(STANDARD.encode(b"storage")),
            profile_state_base64: STANDARD.encode(b"profile"),
            adapter_version: "fixture-v1".to_owned(),
        };
        output.validate().expect("valid helper output");
        let decoded = output.decode_browser_material().expect("valid browser material");
        assert_eq!(decoded.cookie.expose(), b"cookie");
        assert_eq!(
            decoded.storage.as_ref().map(SecretBytes::expose),
            Some(b"storage".as_slice())
        );
        assert_eq!(decoded.profile.expose(), b"profile");
    }

    #[test]
    fn payload_and_commit_checkpoint_are_closed_contracts() {
        let mut lease = job();
        let payload = BrowserJobPayload::parse(&lease).expect("valid payload");
        assert_eq!(payload.intent, "reactivate");
        lease.checkpoint = Some(json!({
            "phase":"browser_material_committed",
            "credential_revision":8,
            "token_version":4
        }));
        let commit = committed_from_checkpoint(&lease).expect("valid checkpoint");
        assert_eq!(commit.credential_revision, 8);
        assert_eq!(commit.token_version, 4);
        lease.payload["intent"] = json!("unknown");
        assert!(matches!(
            BrowserJobPayload::parse(&lease),
            Err(ManagedBrowserFailure { .. })
        ));
    }
}
