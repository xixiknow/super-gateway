//! Durable usage-export persistence and generation fencing.
#![allow(missing_docs, clippy::missing_errors_doc, clippy::too_many_lines)]

use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{AuditOutboxRecord, PgStorage, StorageError};

#[derive(Clone, Debug)]
pub struct UsageExportWork {
    pub export_id: Uuid,
    pub requested_by: Uuid,
    pub scope: String,
    pub dataset: String,
    pub format: String,
    pub query: Value,
    pub query_sha256: Vec<u8>,
    pub rows: Vec<UsageExportDataRow>,
}

#[derive(Clone, Debug)]
pub struct UsageExportDataRow {
    pub request_id: Uuid,
    pub created_at: String,
    pub owner_user_id: Uuid,
    pub platform_key_id: Uuid,
    pub platform_key_name: String,
    pub group_id: Uuid,
    pub group_name: String,
    pub model_id: Option<Uuid>,
    pub upstream_model_id: Option<String>,
    pub endpoint: String,
    pub outcome: Option<String>,
    pub http_status: Option<i32>,
    pub usage_source: Option<String>,
    pub usage_completeness: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cache_creation_input_tokens: Option<i64>,
    pub cache_read_input_tokens: Option<i64>,
    pub amount: Option<String>,
    pub currency: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UsageExportArtifactCommit {
    pub export_id: Uuid,
    pub job_id: Uuid,
    pub generation: i64,
    pub object_uri: String,
    pub content_sha256: Vec<u8>,
    pub row_count: i64,
    pub content_length: i64,
    pub cipher_suite: String,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub key_version: i64,
}

#[derive(Clone, Debug)]
pub struct UsageExportDownload {
    pub export_id: Uuid,
    pub requested_by: Uuid,
    pub dataset: String,
    pub format: String,
    pub query_sha256: Vec<u8>,
    pub object_uri: String,
    pub content_sha256: Vec<u8>,
    pub content_length: i64,
    pub cipher_suite: String,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub key_version: i64,
    pub revision: i64,
}

impl PgStorage {
    pub async fn start_usage_export(
        &self,
        export_id: Uuid,
        job_id: Uuid,
        generation: i64,
    ) -> Result<UsageExportWork, StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let export = sqlx::query(
            "SELECT e.requested_by,e.scope_code,e.dataset_code,e.format_code,e.query,e.query_sha256 \
             FROM ops.export_job e JOIN ops.durable_job j ON j.id=e.durable_job_id \
             WHERE e.id=$1 AND j.id=$2 AND j.state_code='leased' AND j.lease_generation=$3 \
               AND e.state_code IN ('queued','running') FOR UPDATE OF e,j",
        )
        .bind(export_id)
        .bind(job_id)
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        sqlx::query(
            "UPDATE ops.export_job SET state_code='running',revision=revision+1 \
             WHERE id=$1 AND state_code='queued'",
        )
        .bind(export_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let requested_by: Uuid = export.try_get("requested_by").map_err(map_sqlx)?;
        let scope: String = export.try_get("scope_code").map_err(map_sqlx)?;
        let query: Value = export.try_get("query").map_err(map_sqlx)?;
        let rows = sqlx::query(
            "SELECT r.request_id,r.created_at::text AS created_at,k.owner_user_id, \
                    k.id AS platform_key_id,k.name AS platform_key_name,g.id AS group_id,g.name AS group_name, \
                    r.model_id,m.upstream_model_id,r.endpoint_code,r.outcome_code,r.http_status, \
                    u.source_code AS usage_source,u.completeness_code AS usage_completeness, \
                    u.input_tokens,u.output_tokens,u.cache_creation_input_tokens,u.cache_read_input_tokens, \
                    c.amount::text AS amount,c.currency_code AS currency \
             FROM telemetry.request_record r \
             JOIN iam.platform_key k ON k.id=r.platform_key_id \
             JOIN gateway.credential_group g ON g.id=r.group_id \
             LEFT JOIN catalog.model_definition m ON m.id=r.model_id \
             LEFT JOIN telemetry.usage_observation u ON u.request_month=r.request_month \
                  AND u.request_id=r.request_id AND u.is_final_basis \
             LEFT JOIN telemetry.cost_estimate c ON c.request_month=r.request_month \
                  AND c.request_id=r.request_id AND c.is_current \
             WHERE r.created_at >= ($1->>'from')::timestamptz \
               AND r.created_at < ($1->>'to')::timestamptz \
               AND ($2='all' OR k.owner_user_id=$3) \
               AND (NULLIF($1#>>'{filters,platform_key_id}','') IS NULL \
                    OR r.platform_key_id=(NULLIF($1#>>'{filters,platform_key_id}',''))::uuid) \
               AND (NULLIF($1#>>'{filters,group_id}','') IS NULL \
                    OR r.group_id=(NULLIF($1#>>'{filters,group_id}',''))::uuid) \
               AND (NULLIF($1#>>'{filters,model_id}','') IS NULL \
                    OR r.model_id=(NULLIF($1#>>'{filters,model_id}',''))::uuid) \
               AND (NULLIF($1#>>'{filters,completeness}','') IS NULL \
                    OR u.completeness_code=NULLIF($1#>>'{filters,completeness}','')) \
             ORDER BY r.created_at,r.request_id LIMIT 10001",
        )
        .bind(&query)
        .bind(&scope)
        .bind(requested_by)
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .into_iter()
        .map(|row| {
            Ok(UsageExportDataRow {
                request_id: row.try_get("request_id").map_err(map_sqlx)?,
                created_at: row.try_get("created_at").map_err(map_sqlx)?,
                owner_user_id: row.try_get("owner_user_id").map_err(map_sqlx)?,
                platform_key_id: row.try_get("platform_key_id").map_err(map_sqlx)?,
                platform_key_name: row.try_get("platform_key_name").map_err(map_sqlx)?,
                group_id: row.try_get("group_id").map_err(map_sqlx)?,
                group_name: row.try_get("group_name").map_err(map_sqlx)?,
                model_id: row.try_get("model_id").map_err(map_sqlx)?,
                upstream_model_id: row.try_get("upstream_model_id").map_err(map_sqlx)?,
                endpoint: row.try_get("endpoint_code").map_err(map_sqlx)?,
                outcome: row.try_get("outcome_code").map_err(map_sqlx)?,
                http_status: row.try_get("http_status").map_err(map_sqlx)?,
                usage_source: row.try_get("usage_source").map_err(map_sqlx)?,
                usage_completeness: row.try_get("usage_completeness").map_err(map_sqlx)?,
                input_tokens: row.try_get("input_tokens").map_err(map_sqlx)?,
                output_tokens: row.try_get("output_tokens").map_err(map_sqlx)?,
                cache_creation_input_tokens: row.try_get("cache_creation_input_tokens").map_err(map_sqlx)?,
                cache_read_input_tokens: row.try_get("cache_read_input_tokens").map_err(map_sqlx)?,
                amount: row.try_get("amount").map_err(map_sqlx)?,
                currency: row.try_get("currency").map_err(map_sqlx)?,
            })
        })
        .collect::<Result<Vec<_>, StorageError>>()?;
        let work = UsageExportWork {
            export_id,
            requested_by,
            scope,
            dataset: export.try_get("dataset_code").map_err(map_sqlx)?,
            format: export.try_get("format_code").map_err(map_sqlx)?,
            query,
            query_sha256: export.try_get("query_sha256").map_err(map_sqlx)?,
            rows,
        };
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(work)
    }

    pub async fn commit_usage_export(&self, commit: &UsageExportArtifactCommit) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let committed = sqlx::query(
            "UPDATE ops.export_job e SET state_code='succeeded',object_uri=$4,content_sha256=$5, \
                    expires_at=clock_timestamp()+interval '24 hours',completed_at=clock_timestamp(),row_count=$6, \
                    content_length=$7,cipher_suite_code=$8,nonce=$9,wrapped_dek=$10,key_version=$11, \
                    last_error_code=NULL,revision=revision+1 \
             FROM ops.durable_job j WHERE e.id=$1 AND e.durable_job_id=j.id AND j.id=$2 \
               AND j.state_code='leased' AND j.lease_generation=$3 AND e.state_code='running' \
             RETURNING e.revision,e.dataset_code",
        )
        .bind(commit.export_id)
        .bind(commit.job_id)
        .bind(commit.generation)
        .bind(&commit.object_uri)
        .bind(&commit.content_sha256)
        .bind(commit.row_count)
        .bind(commit.content_length)
        .bind(&commit.cipher_suite)
        .bind(&commit.nonce)
        .bind(&commit.wrapped_dek)
        .bind(commit.key_version)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        let revision: i64 = committed.try_get("revision").map_err(map_sqlx)?;
        let dataset: String = committed.try_get("dataset_code").map_err(map_sqlx)?;
        let content_audit = dataset == "content_audit_record_v1";
        let action = if content_audit {
            "content_audit_export_generated"
        } else {
            "usage_export_generated"
        };
        let object_type = if content_audit {
            "content_audit_export"
        } else {
            "usage_export"
        };
        complete_job_in(&mut transaction, commit.job_id, commit.generation, action).await?;
        self.append_audit_outbox_in(
            &mut transaction,
            &AuditOutboxRecord {
                actor_type: "system".to_owned(),
                actor_id: None,
                action: action.to_owned(),
                object_type: object_type.to_owned(),
                object_id: Some(commit.export_id.to_string()),
                outcome: "success".to_owned(),
                redacted_detail: json!({"row_count":commit.row_count,"content_length":commit.content_length}),
                topic: format!("{object_type}.generated"),
                aggregate_id: commit.export_id,
                aggregate_revision: revision,
                payload: json!({"object_id":commit.export_id,"state":"succeeded"}),
            },
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)
    }

    pub async fn fail_usage_export(
        &self,
        export_id: Uuid,
        job_id: Uuid,
        generation: i64,
        error_code: &str,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let changed = sqlx::query(
            "UPDATE ops.export_job e SET state_code='failed',last_error_code=$4,completed_at=clock_timestamp(), \
                    object_uri=NULL,nonce=NULL,wrapped_dek=NULL,revision=revision+1 \
             FROM ops.durable_job j WHERE e.id=$1 AND e.durable_job_id=j.id AND j.id=$2 \
               AND j.state_code='leased' AND j.lease_generation=$3 AND e.state_code IN ('queued','running')",
        )
        .bind(export_id)
        .bind(job_id)
        .bind(generation)
        .bind(error_code)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if changed.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        finish_job_in(&mut transaction, job_id, generation, "dead_letter", error_code).await?;
        transaction.commit().await.map_err(map_sqlx)
    }

    pub async fn load_usage_export_download(
        &self,
        export_id: Uuid,
        requested_by: Uuid,
    ) -> Result<UsageExportDownload, StorageError> {
        let row = sqlx::query(
            "SELECT id,requested_by,dataset_code,format_code,query_sha256,object_uri,content_sha256,content_length, \
                    cipher_suite_code,nonce,wrapped_dek,key_version,revision \
             FROM ops.export_job WHERE id=$1 AND requested_by=$2 AND state_code='succeeded' \
               AND download_count=0 AND expires_at>clock_timestamp()",
        )
        .bind(export_id)
        .bind(requested_by)
        .fetch_optional(&self.pool())
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        Ok(UsageExportDownload {
            export_id: row.try_get("id").map_err(map_sqlx)?,
            requested_by: row.try_get("requested_by").map_err(map_sqlx)?,
            dataset: row.try_get("dataset_code").map_err(map_sqlx)?,
            format: row.try_get("format_code").map_err(map_sqlx)?,
            query_sha256: row.try_get("query_sha256").map_err(map_sqlx)?,
            object_uri: row.try_get("object_uri").map_err(map_sqlx)?,
            content_sha256: row.try_get("content_sha256").map_err(map_sqlx)?,
            content_length: row.try_get("content_length").map_err(map_sqlx)?,
            cipher_suite: row.try_get("cipher_suite_code").map_err(map_sqlx)?,
            nonce: row.try_get("nonce").map_err(map_sqlx)?,
            wrapped_dek: row.try_get("wrapped_dek").map_err(map_sqlx)?,
            key_version: row.try_get("key_version").map_err(map_sqlx)?,
            revision: row.try_get("revision").map_err(map_sqlx)?,
        })
    }

    pub async fn consume_usage_export_download(
        &self,
        export_id: Uuid,
        requested_by: Uuid,
        expected_revision: i64,
        actor_type: &str,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let consumed = sqlx::query(
            "UPDATE ops.export_job SET state_code='expired',object_uri=NULL,nonce=NULL,wrapped_dek=NULL, \
                    download_count=1,downloaded_at=clock_timestamp(),revision=revision+1 \
             WHERE id=$1 AND requested_by=$2 AND revision=$3 AND state_code='succeeded' \
               AND download_count=0 AND expires_at>clock_timestamp() RETURNING revision,dataset_code",
        )
        .bind(export_id)
        .bind(requested_by)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        let revision: i64 = consumed.try_get("revision").map_err(map_sqlx)?;
        let dataset: String = consumed.try_get("dataset_code").map_err(map_sqlx)?;
        let content_audit = dataset == "content_audit_record_v1";
        let action = if content_audit {
            "content_audit_export_downloaded"
        } else {
            "usage_export_downloaded"
        };
        let object_type = if content_audit {
            "content_audit_export"
        } else {
            "usage_export"
        };
        self.append_audit_outbox_in(
            &mut transaction,
            &AuditOutboxRecord {
                actor_type: actor_type.to_owned(),
                actor_id: Some(requested_by),
                action: action.to_owned(),
                object_type: object_type.to_owned(),
                object_id: Some(export_id.to_string()),
                outcome: "success".to_owned(),
                redacted_detail: json!({"one_shot":true}),
                topic: format!("{object_type}.downloaded"),
                aggregate_id: export_id,
                aggregate_revision: revision,
                payload: json!({"object_id":export_id,"state":"expired"}),
            },
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)
    }

    pub async fn expire_usage_exports(&self, limit: i64) -> Result<Vec<String>, StorageError> {
        let rows = sqlx::query(
            "WITH candidates AS ( \
               SELECT id,object_uri FROM ops.export_job WHERE state_code='succeeded' \
                 AND expires_at<=clock_timestamp() ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT $1 \
             ), updated AS ( \
               UPDATE ops.export_job e SET state_code='expired',object_uri=NULL,nonce=NULL,wrapped_dek=NULL, \
                 revision=revision+1 FROM candidates c WHERE e.id=c.id RETURNING e.id \
             ) SELECT c.object_uri FROM candidates c JOIN updated u ON u.id=c.id",
        )
        .bind(limit.max(1))
        .fetch_all(&self.pool())
        .await
        .map_err(map_sqlx)?;
        rows.into_iter()
            .map(|row| row.try_get("object_uri").map_err(map_sqlx))
            .collect()
    }
}

async fn complete_job_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: Uuid,
    generation: i64,
    outcome: &str,
) -> Result<(), StorageError> {
    let changed = sqlx::query(
        "UPDATE ops.durable_job SET state_code='succeeded',lease_owner=NULL,lease_expires_at=NULL, \
           updated_at=clock_timestamp(),completed_at=clock_timestamp() \
         WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
    )
    .bind(job_id)
    .bind(generation)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    if changed.rows_affected() != 1 {
        return Err(StorageError::RevisionConflict);
    }
    sqlx::query(
        "INSERT INTO ops.durable_job_history \
         (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,occurred_at) \
         VALUES ($1,$2,'leased','succeeded',$3,$4,clock_timestamp())",
    )
    .bind(Uuid::now_v7())
    .bind(job_id)
    .bind(generation)
    .bind(outcome)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

async fn finish_job_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: Uuid,
    generation: i64,
    state: &str,
    outcome: &str,
) -> Result<(), StorageError> {
    let changed = sqlx::query(
        "UPDATE ops.durable_job SET state_code=$3,lease_owner=NULL,lease_expires_at=NULL,last_error_code=$4, \
           updated_at=clock_timestamp(),completed_at=clock_timestamp() \
         WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
    )
    .bind(job_id)
    .bind(generation)
    .bind(state)
    .bind(outcome)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    if changed.rows_affected() != 1 {
        return Err(StorageError::RevisionConflict);
    }
    sqlx::query(
        "INSERT INTO ops.durable_job_history \
         (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,occurred_at) \
         VALUES ($1,$2,'leased',$3,$4,$5,clock_timestamp())",
    )
    .bind(Uuid::now_v7())
    .bind(job_id)
    .bind(state)
    .bind(generation)
    .bind(outcome)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

fn map_sqlx(_error: sqlx::Error) -> StorageError {
    StorageError::TransactionFailed
}
