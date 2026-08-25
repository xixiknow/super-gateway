//! Durable Credential Group migration orchestration.
#![allow(missing_docs, clippy::missing_errors_doc)]

use serde_json::json;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{AuditOutboxRecord, CredentialGroupMigrationBegin, PgStorage, StorageError};

#[derive(Clone, Debug)]
pub struct CredentialGroupMigrationWork {
    pub migration_id: Uuid,
    pub credential_id: Uuid,
    pub source_group_id: Uuid,
    pub target_group_id: Uuid,
    pub expected_credential_revision: i64,
    pub expired: bool,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialGroupMigrationCommit {
    pub credential_revision: i64,
    pub state: String,
    pub source_group_id: Uuid,
    pub target_group_id: Uuid,
}

impl PgStorage {
    pub async fn begin_credential_group_migration_with_job(
        &self,
        command: &CredentialGroupMigrationBegin,
        job_id: Uuid,
        audit: &AuditOutboxRecord,
    ) -> Result<(i64, String), StorageError> {
        if command.drain_seconds < 1
            || command.drain_seconds > 300
            || command.source_group_id == command.target_group_id
        {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let compatible: bool = sqlx::query_scalar(
            "SELECT EXISTS( \
               SELECT 1 FROM gateway.anthropic_credential credential \
               JOIN gateway.credential_group target ON target.id=$2 AND target.status_code='active' \
               JOIN gateway.group_active_config pointer ON pointer.group_id=target.id \
               JOIN gateway.group_config config ON config.id=pointer.config_id \
               WHERE credential.id=$1 AND credential.group_id=$3 \
                 AND (NOT config.fully_managed_required OR credential.management_class_code='fully_managed') \
                 AND NOT EXISTS (SELECT 1 FROM gateway.credential_maintenance_operation maintenance \
                   WHERE maintenance.credential_id=credential.id \
                     AND maintenance.state_code IN ('pending','running','retry_wait','waiting_egress')) \
             )",
        )
        .bind(command.credential_id)
        .bind(command.target_group_id)
        .bind(command.source_group_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if !compatible {
            return Err(StorageError::InvalidLifecycle);
        }
        let revision: Option<i64> = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET attachment_state_code='draining',attachment_target_group_id=$3, \
               attachment_deadline=clock_timestamp()+($4*interval '1 second'),revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND group_id=$2 AND revision=$5 AND lifecycle_state_code='active' \
               AND attachment_state_code='attached' RETURNING revision",
        )
        .bind(command.credential_id)
        .bind(command.source_group_id)
        .bind(command.target_group_id)
        .bind(command.drain_seconds)
        .bind(command.expected_credential_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let revision = revision.ok_or(StorageError::RevisionConflict)?;
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'credential_group_migration_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,200,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("credential-group-migration:{}", command.migration_id))
        .bind(json!({"migration_id":command.migration_id}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,NULL,'scheduled',0,'credential_group_migration_scheduled','{}'::jsonb,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        sqlx::query(
            "INSERT INTO gateway.credential_group_migration \
             (id,credential_id,source_group_id,target_group_id,state_code,expected_revision,requested_by,created_at, \
              durable_job_id,drain_deadline,checkpoint,revision) \
             VALUES ($1,$2,$3,$4,'draining',$5,$6,clock_timestamp(),$7, \
               clock_timestamp()+($8*interval '1 second'),'{}'::jsonb,1)",
        )
        .bind(command.migration_id)
        .bind(command.credential_id)
        .bind(command.source_group_id)
        .bind(command.target_group_id)
        .bind(revision)
        .bind(command.requested_by)
        .bind(job_id)
        .bind(command.drain_seconds)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        self.append_audit_outbox_in(&mut transaction, audit).await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok((revision, created_at))
    }

    pub async fn load_credential_group_migration_work(
        &self,
        migration_id: Uuid,
        job_id: Uuid,
        generation: i64,
    ) -> Result<CredentialGroupMigrationWork, StorageError> {
        let row = sqlx::query(
            "SELECT migration.credential_id,migration.source_group_id,migration.target_group_id,migration.state_code, \
                    migration.expected_revision,COALESCE(migration.drain_deadline<=clock_timestamp(),true) AS expired \
             FROM gateway.credential_group_migration migration JOIN ops.durable_job job ON job.id=migration.durable_job_id \
             WHERE migration.id=$1 AND job.id=$2 AND job.state_code='leased' AND job.lease_generation=$3 \
               AND migration.state_code IN ('draining','committed','failed')",
        )
        .bind(migration_id)
        .bind(job_id)
        .bind(generation)
        .fetch_optional(&self.pool())
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        Ok(CredentialGroupMigrationWork {
            migration_id,
            credential_id: row.try_get("credential_id").map_err(map_sqlx)?,
            source_group_id: row.try_get("source_group_id").map_err(map_sqlx)?,
            target_group_id: row.try_get("target_group_id").map_err(map_sqlx)?,
            expected_credential_revision: row.try_get("expected_revision").map_err(map_sqlx)?,
            expired: row.try_get("expired").map_err(map_sqlx)?,
            state: row.try_get("state_code").map_err(map_sqlx)?,
        })
    }

    pub async fn finish_credential_group_migration_with_job(
        &self,
        work: &CredentialGroupMigrationWork,
        job_id: Uuid,
        generation: i64,
        active_leases: u32,
    ) -> Result<CredentialGroupMigrationCommit, StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let row = sqlx::query(
            "SELECT credential.revision,(credential.attachment_deadline<=clock_timestamp()) AS expired \
             FROM gateway.credential_group_migration migration \
             JOIN gateway.anthropic_credential credential ON credential.id=migration.credential_id \
             JOIN ops.durable_job job ON job.id=migration.durable_job_id \
             WHERE migration.id=$1 AND job.id=$2 AND job.state_code='leased' AND job.lease_generation=$3 \
               AND migration.state_code='draining' FOR UPDATE OF migration,credential,job",
        )
        .bind(work.migration_id)
        .bind(job_id)
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        let revision: i64 = row.try_get("revision").map_err(map_sqlx)?;
        let expired: bool = row.try_get("expired").map_err(map_sqlx)?;
        if revision != work.expected_credential_revision {
            return Err(StorageError::RevisionConflict);
        }
        if active_leases > 0 && !expired {
            return Err(StorageError::CapacityExceeded);
        }
        let (state, next_revision) = if active_leases > 0 {
            let next_revision: i64 = sqlx::query_scalar(
                "UPDATE gateway.anthropic_credential SET attachment_state_code='attached',attachment_target_group_id=NULL, \
                   attachment_deadline=NULL,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
            )
            .bind(work.credential_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            ("failed", next_revision)
        } else {
            let next_revision: i64 = sqlx::query_scalar(
                "UPDATE gateway.anthropic_credential SET group_id=$2,attachment_state_code='attached', \
                   attachment_target_group_id=NULL,attachment_deadline=NULL,revision=revision+1,updated_at=clock_timestamp() \
                 WHERE id=$1 RETURNING revision",
            )
            .bind(work.credential_id)
            .bind(work.target_group_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            ("committed", next_revision)
        };
        sqlx::query(
            "UPDATE gateway.credential_group_migration SET state_code=$2,completed_at=clock_timestamp(), \
               checkpoint=jsonb_build_object('active_leases',$3::bigint),revision=revision+1 WHERE id=$1",
        )
        .bind(work.migration_id)
        .bind(state)
        .bind(i64::from(active_leases))
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        self.append_audit_outbox_in(&mut transaction, &system_audit(work, next_revision, state))
            .await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(CredentialGroupMigrationCommit {
            credential_revision: next_revision,
            state: state.to_owned(),
            source_group_id: work.source_group_id,
            target_group_id: work.target_group_id,
        })
    }

    pub async fn complete_credential_group_migration_job(
        &self,
        migration_id: Uuid,
        job_id: Uuid,
        generation: i64,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let state: String = sqlx::query_scalar(
            "SELECT migration.state_code FROM gateway.credential_group_migration migration \
             JOIN ops.durable_job job ON job.id=migration.durable_job_id \
             WHERE migration.id=$1 AND job.id=$2 AND job.state_code='leased' AND job.lease_generation=$3 \
               AND migration.state_code IN ('committed','failed') FOR UPDATE OF migration,job",
        )
        .bind(migration_id)
        .bind(job_id)
        .bind(generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        let outcome = if state == "committed" {
            "credential_group_migration_committed"
        } else {
            "credential_group_migration_timed_out"
        };
        complete_job_in(&mut transaction, job_id, generation, outcome).await?;
        transaction.commit().await.map_err(map_sqlx)
    }
}

fn system_audit(work: &CredentialGroupMigrationWork, revision: i64, state: &str) -> AuditOutboxRecord {
    AuditOutboxRecord {
        actor_type: "system".to_owned(),
        actor_id: None,
        action: format!("credential_group_migration_{state}"),
        object_type: "credential".to_owned(),
        object_id: Some(work.credential_id.to_string()),
        outcome: "success".to_owned(),
        redacted_detail: json!({"migration_id":work.migration_id,"source_group_id":work.source_group_id,
          "target_group_id":work.target_group_id,"state":state}),
        topic: "credential.group.migration.completed".to_owned(),
        aggregate_id: work.credential_id,
        aggregate_revision: revision,
        payload: json!({"credential_id":work.credential_id,"migration_id":work.migration_id,"state":state}),
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
           last_error_code=NULL,updated_at=clock_timestamp(),completed_at=clock_timestamp() \
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
         (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
         VALUES ($1,$2,'leased','succeeded',$3,$4,'{}'::jsonb,clock_timestamp())",
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

fn map_sqlx(_: sqlx::Error) -> StorageError {
    StorageError::TransactionFailed
}
