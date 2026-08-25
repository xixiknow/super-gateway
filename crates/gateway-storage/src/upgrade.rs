//! Durable upgrade-preflight projections.
#![allow(missing_docs, clippy::missing_errors_doc)]

use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{AuditOutboxRecord, PgStorage, StorageError};

#[derive(Clone, Debug)]
pub struct UpgradePreflightWork {
    pub run_id: Uuid,
    pub release_version: String,
    pub candidate_digest: Vec<u8>,
    pub manifest: Value,
}

#[derive(Clone, Debug)]
pub struct UpgradeGateCommit {
    pub code: String,
    pub state: String,
    pub detail: Value,
}

#[derive(Clone, Debug)]
pub struct UpgradePreflightCommit {
    pub run_id: Uuid,
    pub job_id: Uuid,
    pub generation: i64,
    pub state: String,
    pub result: Value,
    pub gates: Vec<UpgradeGateCommit>,
}

impl PgStorage {
    pub async fn start_upgrade_preflight(
        &self,
        run_id: Uuid,
        job_id: Uuid,
        generation: i64,
    ) -> Result<UpgradePreflightWork, StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let row = sqlx::query(
            "SELECT release.release_version,release.manifest_sha256,release.manifest \
             FROM ops.upgrade_run run JOIN ops.release_manifest release ON release.id=run.to_release_id \
             JOIN ops.durable_job job ON job.id=run.durable_job_id \
             WHERE run.id=$1 AND job.id=$2 AND job.state_code='leased' AND job.lease_generation=$3 \
               AND run.preflight_state_code IN ('queued','running') FOR UPDATE OF run,job",
        )
        .bind(run_id)
        .bind(job_id)
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        sqlx::query(
            "UPDATE ops.upgrade_run SET preflight_state_code='running', \
               preflight_started_at=COALESCE(preflight_started_at,clock_timestamp()),revision=revision+1 WHERE id=$1",
        )
        .bind(run_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let work = UpgradePreflightWork {
            run_id,
            release_version: row.try_get("release_version").map_err(map_sqlx)?,
            candidate_digest: row.try_get("manifest_sha256").map_err(map_sqlx)?,
            manifest: row.try_get("manifest").map_err(map_sqlx)?,
        };
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(work)
    }

    pub async fn complete_upgrade_preflight(&self, commit: &UpgradePreflightCommit) -> Result<(), StorageError> {
        if !matches!(commit.state.as_str(), "passed" | "failed" | "blocked_external")
            || commit.gates.is_empty()
            || commit
                .gates
                .iter()
                .any(|gate| !matches!(gate.state.as_str(), "passed" | "failed" | "blocked_external"))
        {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let row = sqlx::query(
            "SELECT release.release_version,release.manifest_sha256 \
             FROM ops.upgrade_run run JOIN ops.release_manifest release ON release.id=run.to_release_id \
             JOIN ops.durable_job job ON job.id=run.durable_job_id \
             WHERE run.id=$1 AND job.id=$2 AND job.state_code='leased' AND job.lease_generation=$3 \
               AND run.preflight_state_code='running' FOR UPDATE OF run,job",
        )
        .bind(commit.run_id)
        .bind(commit.job_id)
        .bind(commit.generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        let release_version: String = row.try_get("release_version").map_err(map_sqlx)?;
        let candidate_digest: Vec<u8> = row.try_get("manifest_sha256").map_err(map_sqlx)?;
        for gate in &commit.gates {
            sqlx::query(
                "INSERT INTO ops.release_gate_run \
                 (id,release_version,candidate_digest,gate_code,state_code,detail,started_at,completed_at,created_at,upgrade_run_id) \
                 VALUES ($1,$2,$3,$4,$5,$6,clock_timestamp(),clock_timestamp(),clock_timestamp(),$7)",
            )
            .bind(Uuid::now_v7())
            .bind(&release_version)
            .bind(&candidate_digest)
            .bind(&gate.code)
            .bind(&gate.state)
            .bind(&gate.detail)
            .bind(commit.run_id)
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        }
        let revision: i64 = sqlx::query_scalar(
            "UPDATE ops.upgrade_run SET preflight_state_code=$2,preflight_result=$3, \
               preflight_completed_at=clock_timestamp(),preflight_valid_until=clock_timestamp()+interval '30 minutes', \
               error_code=NULL,revision=revision+1 WHERE id=$1 RETURNING revision",
        )
        .bind(commit.run_id)
        .bind(&commit.state)
        .bind(&commit.result)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        complete_job_in(
            &mut transaction,
            commit.job_id,
            commit.generation,
            &format!("upgrade_preflight_{}", commit.state),
        )
        .await?;
        self.append_audit_outbox_in(
            &mut transaction,
            &system_audit("upgrade_preflight_completed", commit.run_id, revision, &commit.state),
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)
    }

    pub async fn fail_upgrade_preflight(
        &self,
        run_id: Uuid,
        job_id: Uuid,
        generation: i64,
        error_code: &str,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let revision: i64 = sqlx::query_scalar(
            "UPDATE ops.upgrade_run run SET preflight_state_code='failed',error_code=$4, \
               preflight_completed_at=clock_timestamp(),preflight_valid_until=NULL,revision=revision+1 \
             FROM ops.durable_job job WHERE run.id=$1 AND run.durable_job_id=job.id AND job.id=$2 \
               AND job.state_code='leased' AND job.lease_generation=$3 \
               AND run.preflight_state_code IN ('queued','running') RETURNING run.revision",
        )
        .bind(run_id)
        .bind(job_id)
        .bind(generation)
        .bind(error_code)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        fail_job_in(&mut transaction, job_id, generation, error_code).await?;
        self.append_audit_outbox_in(
            &mut transaction,
            &system_audit("upgrade_preflight_failed", run_id, revision, "failed"),
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)
    }
}

fn system_audit(action: &str, object_id: Uuid, revision: i64, state: &str) -> AuditOutboxRecord {
    AuditOutboxRecord {
        actor_type: "system".to_owned(),
        actor_id: None,
        action: action.to_owned(),
        object_type: "upgrade_check".to_owned(),
        object_id: Some(object_id.to_string()),
        outcome: "success".to_owned(),
        redacted_detail: json!({"state":state}),
        topic: action.replace('_', "."),
        aggregate_id: object_id,
        aggregate_revision: revision,
        payload: json!({"upgrade_check_id":object_id,"state":state}),
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
        "UPDATE ops.durable_job SET state_code=$3,lease_owner=NULL,lease_expires_at=NULL, \
           last_error_code=CASE WHEN $3='dead_letter' THEN $4 ELSE NULL END,updated_at=clock_timestamp(), \
           completed_at=clock_timestamp() WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
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
         (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
         VALUES ($1,$2,'leased',$3,$4,$5,'{}'::jsonb,clock_timestamp())",
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

fn map_sqlx(_: sqlx::Error) -> StorageError {
    StorageError::TransactionFailed
}
