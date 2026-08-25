//! Durable backup and isolated-restore projections.
#![allow(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{AuditOutboxRecord, PgStorage, StorageError};

#[derive(Clone, Debug)]
pub struct BackupRunCommit {
    pub run_id: Uuid,
    pub job_id: Uuid,
    pub generation: i64,
    pub manifest: Value,
    pub manifest_sha256: Vec<u8>,
    pub database_system_id: String,
    pub timeline: i64,
    pub lsn_start: String,
    pub lsn_end: String,
    pub wal_archived_at: String,
    pub watermarks: Value,
    pub backup_key_version: i64,
    pub repository_ref: String,
    pub bytes_written: i64,
}

#[derive(Clone, Debug)]
pub struct RestoreOperationWork {
    pub drill_id: Uuid,
    pub kind: String,
    pub backup_run_id: Uuid,
    pub recovery_point: Option<String>,
    pub manifest: Value,
    pub manifest_sha256: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RestoreValidationCommit {
    pub drill_id: Uuid,
    pub job_id: Uuid,
    pub generation: i64,
    pub manifest_sha256: Vec<u8>,
    pub checks: Value,
    pub lineage: Value,
}

#[derive(Clone, Debug)]
pub struct RestoreDrillCommit {
    pub drill_id: Uuid,
    pub job_id: Uuid,
    pub generation: i64,
    pub manifest_sha256: Vec<u8>,
    pub isolated_environment_id: String,
    pub db_recovered: bool,
    pub object_replayed: bool,
    pub ledger_replayed: bool,
    pub checks: Value,
    pub lineage: Value,
    pub rpo_seconds: i64,
    pub rto_seconds: i64,
    pub serving_simulated: bool,
    pub destroyed: bool,
}

impl PgStorage {
    pub async fn start_backup_run(&self, run_id: Uuid, job_id: Uuid, generation: i64) -> Result<(), StorageError> {
        let changed = sqlx::query(
            "UPDATE ops.backup_run b SET state_code='running',started_at=COALESCE(started_at,clock_timestamp()), \
               revision=revision+1 FROM ops.durable_job j WHERE b.id=$1 AND b.durable_job_id=j.id AND j.id=$2 \
               AND j.state_code='leased' AND j.lease_generation=$3 AND b.state_code IN ('queued','running')",
        )
        .bind(run_id)
        .bind(job_id)
        .bind(generation)
        .execute(&self.pool())
        .await
        .map_err(map_sqlx)?;
        if changed.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        Ok(())
    }

    pub async fn complete_backup_run(&self, commit: &BackupRunCommit) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let revision: i64 = sqlx::query_scalar(
            "UPDATE ops.backup_run b SET state_code='succeeded',manifest=$4,manifest_sha256=$5, \
               database_system_id=$6,timeline=$7,lsn_start=$8::pg_lsn,lsn_end=$9::pg_lsn,wal_archived_at=$10::timestamptz, \
               watermarks=$11,backup_key_version=$12,repository_ref=$13,bytes_written=$14,error_code=NULL, \
               completed_at=clock_timestamp(),revision=revision+1 FROM ops.durable_job j \
             WHERE b.id=$1 AND b.durable_job_id=j.id AND j.id=$2 AND j.state_code='leased' \
               AND j.lease_generation=$3 AND b.state_code='running' RETURNING b.revision",
        )
        .bind(commit.run_id)
        .bind(commit.job_id)
        .bind(commit.generation)
        .bind(&commit.manifest)
        .bind(&commit.manifest_sha256)
        .bind(&commit.database_system_id)
        .bind(commit.timeline)
        .bind(&commit.lsn_start)
        .bind(&commit.lsn_end)
        .bind(&commit.wal_archived_at)
        .bind(&commit.watermarks)
        .bind(commit.backup_key_version)
        .bind(&commit.repository_ref)
        .bind(commit.bytes_written)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        complete_job_in(&mut transaction, commit.job_id, commit.generation, "backup_succeeded").await?;
        self.append_audit_outbox_in(
            &mut transaction,
            &system_audit("backup_succeeded", "backup_run", commit.run_id, revision),
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)
    }

    pub async fn start_restore_operation(
        &self,
        drill_id: Uuid,
        job_id: Uuid,
        generation: i64,
    ) -> Result<RestoreOperationWork, StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let row = sqlx::query(
            "SELECT d.kind_code,d.backup_run_id,d.recovery_point::text AS recovery_point,b.manifest,b.manifest_sha256 \
             FROM ops.restore_drill d JOIN ops.backup_run b ON b.id=d.backup_run_id \
             JOIN ops.durable_job j ON j.id=d.durable_job_id WHERE d.id=$1 AND j.id=$2 \
               AND j.state_code='leased' AND j.lease_generation=$3 AND d.state_code IN ('queued','running') \
               AND b.state_code='succeeded' FOR UPDATE OF d,j",
        )
        .bind(drill_id)
        .bind(job_id)
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        sqlx::query(
            "UPDATE ops.restore_drill SET state_code='running',started_at=COALESCE(started_at,clock_timestamp()), \
               revision=revision+1 WHERE id=$1",
        )
        .bind(drill_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let work = RestoreOperationWork {
            drill_id,
            kind: row.try_get("kind_code").map_err(map_sqlx)?,
            backup_run_id: row.try_get("backup_run_id").map_err(map_sqlx)?,
            recovery_point: row.try_get("recovery_point").map_err(map_sqlx)?,
            manifest: row.try_get("manifest").map_err(map_sqlx)?,
            manifest_sha256: row.try_get("manifest_sha256").map_err(map_sqlx)?,
        };
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(work)
    }

    pub async fn complete_restore_validation(&self, commit: &RestoreValidationCommit) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let revision: i64 = sqlx::query_scalar(
            "UPDATE ops.restore_drill d SET state_code='succeeded',manifest_sha256=$4,checks=$5,lineage=$6, \
               result=jsonb_build_object('validated',true),completed_at=clock_timestamp(),revision=revision+1 \
             FROM ops.durable_job j WHERE d.id=$1 AND d.durable_job_id=j.id AND j.id=$2 \
               AND j.state_code='leased' AND j.lease_generation=$3 AND d.state_code='running' \
               AND d.kind_code='manifest_validation' RETURNING d.revision",
        )
        .bind(commit.drill_id)
        .bind(commit.job_id)
        .bind(commit.generation)
        .bind(&commit.manifest_sha256)
        .bind(&commit.checks)
        .bind(&commit.lineage)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        complete_job_in(
            &mut transaction,
            commit.job_id,
            commit.generation,
            "restore_validation_succeeded",
        )
        .await?;
        self.append_audit_outbox_in(
            &mut transaction,
            &system_audit(
                "restore_validation_succeeded",
                "restore_validation",
                commit.drill_id,
                revision,
            ),
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)
    }

    pub async fn complete_restore_drill(&self, commit: &RestoreDrillCommit) -> Result<(), StorageError> {
        if !commit.serving_simulated || !commit.destroyed {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let revision: i64 = sqlx::query_scalar(
            "UPDATE ops.restore_drill d SET state_code='succeeded',manifest_sha256=$4,isolated_environment_id=$5, \
               db_recovered=$6,object_replayed=$7,ledger_replayed=$8,checks=$9,lineage=$10,rpo_seconds=$11, \
               rto_seconds=$12,serving_simulated_at=clock_timestamp(),destroyed_at=clock_timestamp(), \
               result=jsonb_build_object('validated',true,'network','disabled','notifications','disabled'), \
               completed_at=clock_timestamp(),revision=revision+1 FROM ops.durable_job j \
             WHERE d.id=$1 AND d.durable_job_id=j.id AND j.id=$2 AND j.state_code='leased' \
               AND j.lease_generation=$3 AND d.state_code='running' AND d.kind_code='full_restore_drill' \
             RETURNING d.revision",
        )
        .bind(commit.drill_id)
        .bind(commit.job_id)
        .bind(commit.generation)
        .bind(&commit.manifest_sha256)
        .bind(&commit.isolated_environment_id)
        .bind(commit.db_recovered)
        .bind(commit.object_replayed)
        .bind(commit.ledger_replayed)
        .bind(&commit.checks)
        .bind(&commit.lineage)
        .bind(commit.rpo_seconds)
        .bind(commit.rto_seconds)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        complete_job_in(
            &mut transaction,
            commit.job_id,
            commit.generation,
            "restore_drill_succeeded",
        )
        .await?;
        self.append_audit_outbox_in(
            &mut transaction,
            &system_audit("restore_drill_succeeded", "restore_drill", commit.drill_id, revision),
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)
    }

    pub async fn fail_backup_operation(
        &self,
        projection: &str,
        projection_id: Uuid,
        job_id: Uuid,
        generation: i64,
        error_code: &str,
    ) -> Result<(), StorageError> {
        let table = match projection {
            "backup_run" => "ops.backup_run",
            "restore_drill" => "ops.restore_drill",
            _ => return Err(StorageError::InvalidLifecycle),
        };
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let query = format!(
            "UPDATE {table} p SET state_code='failed',error_code=$4,completed_at=clock_timestamp(),revision=revision+1 \
             FROM ops.durable_job j WHERE p.id=$1 AND p.durable_job_id=j.id AND j.id=$2 \
               AND j.state_code='leased' AND j.lease_generation=$3 AND p.state_code IN ('queued','running')"
        );
        let changed = sqlx::query(&query)
            .bind(projection_id)
            .bind(job_id)
            .bind(generation)
            .bind(error_code)
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        if changed.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        fail_job_in(&mut transaction, job_id, generation, error_code).await?;
        transaction.commit().await.map_err(map_sqlx)
    }
}

fn system_audit(action: &str, object_type: &str, object_id: Uuid, revision: i64) -> AuditOutboxRecord {
    AuditOutboxRecord {
        actor_type: "system".to_owned(),
        actor_id: None,
        action: action.to_owned(),
        object_type: object_type.to_owned(),
        object_id: Some(object_id.to_string()),
        outcome: "success".to_owned(),
        redacted_detail: json!({}),
        topic: action.replace('_', "."),
        aggregate_id: object_id,
        aggregate_revision: revision,
        payload: json!({"object_id":object_id,"state":"succeeded"}),
    }
}

async fn complete_job_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: Uuid,
    generation: i64,
    outcome: &str,
) -> Result<(), StorageError> {
    finish_job_in(transaction, job_id, generation, "succeeded", outcome).await
}

async fn fail_job_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: Uuid,
    generation: i64,
    outcome: &str,
) -> Result<(), StorageError> {
    finish_job_in(transaction, job_id, generation, "dead_letter", outcome).await
}

async fn finish_job_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: Uuid,
    generation: i64,
    state: &str,
    outcome: &str,
) -> Result<(), StorageError> {
    let changed = sqlx::query(
        "UPDATE ops.durable_job SET state_code=$3,lease_owner=NULL,lease_expires_at=NULL,last_error_code= \
           CASE WHEN $3='dead_letter' THEN $4 ELSE NULL END,updated_at=clock_timestamp(),completed_at=clock_timestamp() \
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
