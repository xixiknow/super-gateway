//! Authoritative Anthropic model discovery commit.
#![allow(missing_docs, clippy::missing_errors_doc, clippy::too_many_lines)]

use std::collections::BTreeSet;

use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{AuditOutboxRecord, PgStorage, StorageError};

#[derive(Clone, Debug)]
pub struct DiscoveredModel {
    pub upstream_model_id: String,
    pub display_name: String,
    pub created_at: Option<String>,
    pub max_input_tokens: Option<i64>,
    pub max_output_tokens: Option<i64>,
    pub provider_capabilities: Option<Value>,
    pub capability_candidate: Option<DiscoveredCapabilityCandidate>,
    pub content_digest: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DiscoveredCapabilityCandidate {
    pub schema_payload: Value,
    pub content_hash: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum ModelDiscoverySource {
    AnthropicModelsApi {
        credential_id: Uuid,
        credential_revision: i64,
        token_version: i64,
        egress_binding_id: Uuid,
        egress_epoch: i64,
    },
    AnthropicPublicDocs,
    BuiltinSnapshot,
}

#[derive(Clone, Debug)]
pub struct ModelDiscoveryCommit {
    pub run_id: Uuid,
    pub job_id: Uuid,
    pub job_generation: i64,
    pub source: ModelDiscoverySource,
    pub source_digest: Vec<u8>,
    pub sanitized_manifest: Value,
    pub models: Vec<DiscoveredModel>,
}

impl PgStorage {
    pub async fn commit_model_discovery(&self, commit: &ModelDiscoveryCommit) -> Result<(), StorageError> {
        if commit.source_digest.len() != 32 || commit.models.len() > 10_000 || !commit.sanitized_manifest.is_object() {
            return Err(StorageError::InvalidLifecycle);
        }
        if let ModelDiscoverySource::AnthropicModelsApi {
            credential_revision,
            token_version,
            egress_epoch,
            ..
        } = &commit.source
            && (*credential_revision < 1 || *token_version < 1 || *egress_epoch < 1)
        {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut ids = BTreeSet::new();
        if commit.models.iter().any(|model| {
            model.upstream_model_id.is_empty()
                || model.upstream_model_id.len() > 256
                || model.display_name.is_empty()
                || model.display_name.len() > 256
                || model.max_input_tokens.is_some_and(|value| value <= 0)
                || model.max_output_tokens.is_some_and(|value| value <= 0)
                || model.provider_capabilities.as_ref().is_some_and(|value| {
                    !value.is_object() || serde_json::to_vec(value).map_or(true, |encoded| encoded.len() > 64 * 1024)
                })
                || model.capability_candidate.as_ref().is_some_and(|candidate| {
                    !candidate.schema_payload.is_object()
                        || candidate.content_hash.len() != 32
                        || serde_json::to_vec(&candidate.schema_payload)
                            .map_or(true, |encoded| encoded.len() > 256 * 1024)
                })
                || model.content_digest.len() != 32
                || !ids.insert(model.upstream_model_id.clone())
        }) {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let valid: bool = match &commit.source {
            ModelDiscoverySource::AnthropicModelsApi {
                credential_id,
                credential_revision,
                token_version,
                egress_binding_id,
                egress_epoch,
            } => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM ops.durable_job job \
                     JOIN gateway.anthropic_credential credential ON credential.id=$3 \
                     JOIN gateway.credential_auth_version auth ON auth.id=credential.active_auth_version_id \
                       AND auth.credential_id=credential.id AND auth.material_state_code='active' \
                     JOIN gateway.credential_egress_binding binding ON binding.id=$6 AND binding.credential_id=credential.id \
                       AND binding.lifecycle_code='active' AND binding.stability_code='stable' \
                     WHERE job.id=$1 AND job.kind_code='model_catalog_discovery_v1' \
                       AND job.state_code='leased' AND job.lease_generation=$2 \
                       AND credential.revision=$4 AND credential.token_version=$5 AND auth.token_version=$5 \
                       AND credential.auth_kind_code='console_api_key' AND binding.egress_epoch=$7 \
                       AND credential.lifecycle_state_code NOT IN ('revoked','archived') FOR UPDATE)",
                )
                .bind(commit.job_id)
                .bind(commit.job_generation)
                .bind(credential_id)
                .bind(credential_revision)
                .bind(token_version)
                .bind(egress_binding_id)
                .bind(egress_epoch)
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sqlx)?
            }
            ModelDiscoverySource::AnthropicPublicDocs | ModelDiscoverySource::BuiltinSnapshot => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM ops.durable_job job \
                     WHERE job.id=$1 AND job.kind_code='model_catalog_discovery_v1' \
                       AND job.state_code='leased' AND job.lease_generation=$2 \
                       AND job.payload->>'source'='public_model_directory' FOR UPDATE)",
                )
                .bind(commit.job_id)
                .bind(commit.job_generation)
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sqlx)?
            }
        };
        if !valid {
            return Err(StorageError::RevisionConflict);
        }
        let (source_code, credential_id, credential_revision, token_version, egress_epoch, verified) =
            match &commit.source {
                ModelDiscoverySource::AnthropicModelsApi {
                    credential_id,
                    credential_revision,
                    token_version,
                    egress_epoch,
                    ..
                } => (
                    "anthropic_models_api",
                    Some(*credential_id),
                    Some(*credential_revision),
                    Some(*token_version),
                    Some(*egress_epoch),
                    true,
                ),
                ModelDiscoverySource::AnthropicPublicDocs => ("anthropic_public_docs", None, None, None, None, false),
                ModelDiscoverySource::BuiltinSnapshot => ("builtin_snapshot", None, None, None, None, false),
            };
        sqlx::query(
            "INSERT INTO catalog.model_discovery_run \
             (id,durable_job_id,source_credential_id,source_credential_revision,source_token_version,source_egress_epoch, \
              source_code,source_digest,item_count,complete,sanitized_manifest,fetched_at,created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true,$10,clock_timestamp(),clock_timestamp())",
        )
        .bind(commit.run_id)
        .bind(commit.job_id)
        .bind(credential_id)
        .bind(credential_revision)
        .bind(token_version)
        .bind(egress_epoch)
        .bind(source_code)
        .bind(&commit.source_digest)
        .bind(i32::try_from(commit.models.len()).map_err(|_| StorageError::InvalidLifecycle)?)
        .bind(&commit.sanitized_manifest)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let mut candidate_count = 0_u32;
        for model in &commit.models {
            let existing = sqlx::query(
                "SELECT id,display_name,lifecycle_code,disabled_by_system FROM catalog.model_definition \
                 WHERE upstream_model_id=$1 FOR UPDATE",
            )
            .bind(&model.upstream_model_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            let model_id = if let Some(existing) = existing {
                let model_id: Uuid = existing.try_get("id").map_err(map_sqlx)?;
                let lifecycle: String = existing.try_get("lifecycle_code").map_err(map_sqlx)?;
                let system_disabled: bool = existing.try_get("disabled_by_system").map_err(map_sqlx)?;
                let reappeared = verified && lifecycle == "disabled" && system_disabled;
                sqlx::query(
                    "UPDATE catalog.model_definition SET display_name=$2,last_seen_at=clock_timestamp(), \
                       last_verified_at=CASE WHEN $5 THEN clock_timestamp() ELSE last_verified_at END, \
                       last_discovery_run_id=$3,missing_streak=CASE WHEN $5 THEN 0 ELSE missing_streak END, \
                       lifecycle_code=CASE WHEN $4 THEN 'reviewing' ELSE lifecycle_code END, \
                       disable_reason_code=CASE WHEN $4 THEN NULL ELSE disable_reason_code END, \
                       disabled_by_system=CASE WHEN $4 THEN false ELSE disabled_by_system END,revision=revision+1 \
                     WHERE id=$1",
                )
                .bind(model_id)
                .bind(&model.display_name)
                .bind(commit.run_id)
                .bind(reappeared)
                .bind(verified)
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
                model_id
            } else {
                let model_id = Uuid::now_v7();
                sqlx::query(
                    "INSERT INTO catalog.model_definition \
                     (id,upstream_model_id,display_name,lifecycle_code,first_seen_at,last_seen_at,revision, \
                      last_discovery_run_id,missing_streak,disabled_by_system,last_verified_at) \
                     VALUES ($1,$2,$3,'discovered',clock_timestamp(),clock_timestamp(),1,$4,0,false, \
                       CASE WHEN $5 THEN clock_timestamp() ELSE NULL END)",
                )
                .bind(model_id)
                .bind(&model.upstream_model_id)
                .bind(&model.display_name)
                .bind(commit.run_id)
                .bind(verified)
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
                model_id
            };
            sqlx::query(
                "INSERT INTO catalog.model_discovery_observation \
                 (run_id,model_definition_id,upstream_model_id,display_name,observed_created_at,content_digest, \
                  max_input_tokens,max_output_tokens,provider_capabilities) \
                 VALUES ($1,$2,$3,$4,NULLIF($5,'')::timestamptz,$6,$7,$8,$9)",
            )
            .bind(commit.run_id)
            .bind(model_id)
            .bind(&model.upstream_model_id)
            .bind(&model.display_name)
            .bind(model.created_at.as_deref().unwrap_or(""))
            .bind(&model.content_digest)
            .bind(model.max_input_tokens)
            .bind(model.max_output_tokens)
            .bind(&model.provider_capabilities)
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            if let Some(candidate) = &model.capability_candidate {
                let version: i64 = sqlx::query_scalar(
                    "SELECT COALESCE(MAX(capability_version),0)+1 FROM catalog.model_capability WHERE model_id=$1",
                )
                .bind(model_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
                let inserted = sqlx::query(
                    "INSERT INTO catalog.model_capability \
                     (id,model_id,capability_version,lifecycle_code,schema_payload,content_hash,created_at, \
                      origin_code,source_discovery_run_id) \
                     VALUES ($1,$2,$3,'candidate',$4,$5,clock_timestamp(),'system_discovery',$6) \
                     ON CONFLICT (model_id,content_hash) DO NOTHING",
                )
                .bind(Uuid::now_v7())
                .bind(model_id)
                .bind(version)
                .bind(&candidate.schema_payload)
                .bind(&candidate.content_hash)
                .bind(commit.run_id)
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
                candidate_count = candidate_count
                    .checked_add(u32::try_from(inserted.rows_affected()).map_err(|_| StorageError::InvalidLifecycle)?)
                    .ok_or(StorageError::InvalidLifecycle)?;
            }
        }
        if verified {
            sqlx::query(
                "UPDATE catalog.model_definition model SET missing_streak=model.missing_streak+1, \
                   lifecycle_code=CASE WHEN model.missing_streak+1>=3 AND model.last_seen_at<clock_timestamp()-interval '24 hours' \
                                          THEN 'disabled' ELSE model.lifecycle_code END, \
                   disable_reason_code=CASE WHEN model.missing_streak+1>=3 AND model.last_seen_at<clock_timestamp()-interval '24 hours' \
                                             THEN 'authoritative_catalog_missing' ELSE model.disable_reason_code END, \
                   disabled_by_system=CASE WHEN model.missing_streak+1>=3 AND model.last_seen_at<clock_timestamp()-interval '24 hours' \
                                            THEN true ELSE model.disabled_by_system END, \
                   last_discovery_run_id=$1,revision=revision+1 \
                 WHERE model.lifecycle_code IN ('discovered','reviewing','published') \
                   AND NOT EXISTS(SELECT 1 FROM catalog.model_discovery_observation observation \
                                  WHERE observation.run_id=$1 AND observation.model_definition_id=model.id)",
            )
            .bind(commit.run_id)
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        }
        let completed = sqlx::query(
            "UPDATE ops.durable_job SET state_code='succeeded',checkpoint=$3,lease_owner=NULL,lease_expires_at=NULL, \
               updated_at=clock_timestamp(),completed_at=clock_timestamp() \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
        )
        .bind(commit.job_id)
        .bind(commit.job_generation)
        .bind(json!({"phase":"catalog_committed","run_id":commit.run_id,"item_count":commit.models.len(),"capability_candidate_count":candidate_count}))
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if completed.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,'leased','succeeded',$3,'model_catalog_discovered', \
               jsonb_build_object('run_id',$4::uuid,'item_count',$5::integer),clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(commit.job_id)
        .bind(commit.job_generation)
        .bind(commit.run_id)
        .bind(i32::try_from(commit.models.len()).map_err(|_| StorageError::InvalidLifecycle)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        self.append_audit_outbox_in(
            &mut transaction,
            &AuditOutboxRecord {
                actor_type: "system".to_owned(),
                actor_id: None,
                action: "model_catalog_discovered".to_owned(),
                object_type: "model_discovery_run".to_owned(),
                object_id: Some(commit.run_id.to_string()),
                outcome: "success".to_owned(),
                redacted_detail: json!({"item_count":commit.models.len(),"capability_candidate_count":candidate_count,"complete":true,"source":source_code}),
                topic: "catalog.models.discovered".to_owned(),
                aggregate_id: commit.run_id,
                aggregate_revision: 1,
                payload: json!({"run_id":commit.run_id,"item_count":commit.models.len(),"capability_candidate_count":candidate_count,"source":source_code}),
            },
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)
    }
}

fn map_sqlx(_: sqlx::Error) -> StorageError {
    StorageError::TransactionFailed
}
