//! Generation-fenced Credential Egress rebind commit.
#![allow(missing_docs, clippy::missing_errors_doc, clippy::too_many_lines)]

use serde_json::json;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{AuditOutboxRecord, PgStorage, ProfileContinuityCommit, StorageError};

#[derive(Clone, Debug)]
pub struct EgressRebindCommit {
    pub credential_id: Uuid,
    pub expected_credential_revision: i64,
    pub expected_profile_epoch: i64,
    pub expected_egress_epoch: i64,
    pub mode: String,
    pub proxy_id: Option<Uuid>,
    pub observed_ip: Option<String>,
    pub latency_ms: i32,
    pub reason: String,
    pub job_id: Uuid,
    pub generation: i64,
}

impl PgStorage {
    pub async fn commit_credential_egress_rebind(
        &self,
        commit: &EgressRebindCommit,
    ) -> Result<ProfileContinuityCommit, StorageError> {
        if !matches!(commit.mode.as_str(), "direct" | "proxy")
            || (commit.mode == "proxy") != commit.proxy_id.is_some()
            || commit.expected_profile_epoch < 1
            || commit.expected_egress_epoch < 1
            || commit.latency_ms < 0
            || commit.reason.trim().is_empty()
        {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let row = sqlx::query(
            "SELECT credential.group_id,credential.revision,profile.id AS profile_id,profile.archetype_version_id, \
                    profile.profile_epoch,device.device_epoch,binding.id AS binding_id,binding.egress_epoch, \
                    binding.mode_code,binding.proxy_id,config.proxy_policy_code \
             FROM ops.durable_job job \
             JOIN gateway.anthropic_credential credential ON credential.id=$1 \
             JOIN gateway.credential_profile profile ON profile.credential_id=credential.id \
             JOIN gateway.device_identity device ON device.id=profile.device_identity_id \
             JOIN gateway.credential_egress_binding binding ON binding.id=profile.egress_binding_id \
             JOIN gateway.group_active_config pointer ON pointer.group_id=credential.group_id \
             JOIN gateway.group_config config ON config.id=pointer.config_id \
             WHERE job.id=$2 AND job.kind_code='credential_egress_rebind_v1' \
               AND job.state_code='leased' AND job.lease_generation=$3 \
               AND credential.lifecycle_state_code IN ('active','disabled') \
               AND profile.lifecycle_code='active' AND binding.lifecycle_code='active' \
             FOR UPDATE OF job,credential,profile,device,binding",
        )
        .bind(commit.credential_id)
        .bind(commit.job_id)
        .bind(commit.generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        let revision: i64 = row.try_get("revision").map_err(map_sqlx)?;
        let profile_epoch: i64 = row.try_get("profile_epoch").map_err(map_sqlx)?;
        let egress_epoch: i64 = row.try_get("egress_epoch").map_err(map_sqlx)?;
        if revision != commit.expected_credential_revision
            || profile_epoch != commit.expected_profile_epoch
            || egress_epoch != commit.expected_egress_epoch
        {
            return Err(StorageError::RevisionConflict);
        }
        let current_mode: String = row.try_get("mode_code").map_err(map_sqlx)?;
        let current_proxy: Option<Uuid> = row.try_get("proxy_id").map_err(map_sqlx)?;
        if current_mode == commit.mode && current_proxy == commit.proxy_id {
            return Err(StorageError::InvalidLifecycle);
        }
        let policy: String = row.try_get("proxy_policy_code").map_err(map_sqlx)?;
        if (policy == "direct" && commit.mode != "direct") || (policy == "proxy_required" && commit.mode != "proxy") {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut target_expected_ip = None;
        if let Some(proxy_id) = commit.proxy_id {
            let proxy = sqlx::query(
                "SELECT max_active_bindings,host(expected_egress_ip) AS expected_ip,lifecycle_code,health_code,stability_code \
                 FROM gateway.proxy_endpoint WHERE id=$1 FOR UPDATE",
            )
            .bind(proxy_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_sqlx)?
            .ok_or(StorageError::EgressUnavailable)?;
            if proxy.try_get::<String, _>("lifecycle_code").map_err(map_sqlx)? != "active"
                || proxy.try_get::<String, _>("health_code").map_err(map_sqlx)? != "healthy"
                || proxy.try_get::<String, _>("stability_code").map_err(map_sqlx)? != "static"
            {
                return Err(StorageError::EgressUnavailable);
            }
            let expected_ip: Option<String> = proxy.try_get("expected_ip").map_err(map_sqlx)?;
            if expected_ip
                .as_deref()
                .zip(commit.observed_ip.as_deref())
                .is_some_and(|(expected, observed)| expected != observed)
            {
                return Err(StorageError::EgressUnavailable);
            }
            target_expected_ip = expected_ip;
            let used: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM gateway.credential_egress_binding \
                 WHERE proxy_id=$1 AND credential_id<>$2 \
                   AND lifecycle_code IN ('pending','active','transport_unavailable','rebinding')",
            )
            .bind(proxy_id)
            .bind(commit.credential_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            let maximum: i32 = proxy.try_get("max_active_bindings").map_err(map_sqlx)?;
            if used >= i64::from(maximum) {
                return Err(StorageError::CapacityExceeded);
            }
        }
        let profile_id: Uuid = row.try_get("profile_id").map_err(map_sqlx)?;
        let binding_id: Uuid = row.try_get("binding_id").map_err(map_sqlx)?;
        let archetype_version_id: Uuid = row.try_get("archetype_version_id").map_err(map_sqlx)?;
        let device_epoch: i64 = row.try_get("device_epoch").map_err(map_sqlx)?;
        let next_egress_epoch = egress_epoch.checked_add(1).ok_or(StorageError::TransactionFailed)?;
        let next_profile_epoch = profile_epoch.checked_add(1).ok_or(StorageError::TransactionFailed)?;
        let binding_changed = sqlx::query(
            "UPDATE gateway.credential_egress_binding SET mode_code=$2,proxy_id=$3,stability_code='stable', \
               lifecycle_code='active',egress_epoch=$4,observed_egress_ip=$5::inet,observed_at=clock_timestamp(), \
               rebound_at=clock_timestamp(),rebind_reason_code=$6,expected_egress_ip=$7::inet, \
               revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND egress_epoch=$8",
        )
        .bind(binding_id)
        .bind(&commit.mode)
        .bind(commit.proxy_id)
        .bind(next_egress_epoch)
        .bind(&commit.observed_ip)
        .bind(&commit.reason)
        .bind(&target_expected_ip)
        .bind(egress_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if binding_changed.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        let profile_changed = sqlx::query(
            "UPDATE gateway.credential_profile SET profile_epoch=$2,revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND profile_epoch=$3",
        )
        .bind(profile_id)
        .bind(next_profile_epoch)
        .bind(profile_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if profile_changed.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        let next_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET revision=revision+1,transport_state_code='ready', \
               scheduling_state_code=CASE WHEN scheduling_state_code='transport_unavailable' \
                 THEN CASE WHEN cooldown_until>clock_timestamp() THEN 'cooldown' ELSE 'eligible' END \
                 ELSE scheduling_state_code END, \
               updated_at=clock_timestamp() WHERE id=$1 AND revision=$2 RETURNING revision",
        )
        .bind(commit.credential_id)
        .bind(revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .ok_or(StorageError::RevisionConflict)?;
        sqlx::query(
            "INSERT INTO gateway.credential_profile_change \
             (id,credential_profile_id,credential_id,from_archetype_version_id,to_archetype_version_id, \
              from_profile_epoch,to_profile_epoch,change_kind_code,from_egress_epoch,to_egress_epoch, \
              reason_code,cohort_code,changed_at) \
             VALUES ($1,$2,$3,$4,$4,$5,$6,'egress_rebind',$7,$8,$9,'explicit',clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(profile_id)
        .bind(commit.credential_id)
        .bind(archetype_version_id)
        .bind(profile_epoch)
        .bind(next_profile_epoch)
        .bind(egress_epoch)
        .bind(next_egress_epoch)
        .bind(&commit.reason)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        sqlx::query(
            "INSERT INTO gateway.egress_observation \
             (id,egress_binding_id,egress_epoch,observed_ip,probe_code,latency_ms,observed_at) \
             VALUES ($1,$2,$3,$4::inet,'success',$5,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(binding_id)
        .bind(next_egress_epoch)
        .bind(&commit.observed_ip)
        .bind(commit.latency_ms)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        super::credential::append_credential_event(
            &mut transaction,
            commit.credential_id,
            None,
            None,
            "egress_rebound",
            next_revision,
            json!({"binding_id":binding_id,"mode":commit.mode,"proxy_id":commit.proxy_id,
              "profile_epoch":next_profile_epoch,"egress_epoch":next_egress_epoch}),
        )
        .await?;
        let checkpoint = json!({"phase":"binding_committed","credential_revision":next_revision,
          "profile_epoch":next_profile_epoch,"egress_epoch":next_egress_epoch,"binding_id":binding_id});
        let changed = sqlx::query(
            "UPDATE ops.durable_job SET checkpoint=$4,updated_at=clock_timestamp() \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2 AND kind_code=$3",
        )
        .bind(commit.job_id)
        .bind(commit.generation)
        .bind("credential_egress_rebind_v1")
        .bind(&checkpoint)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if changed.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        self.append_audit_outbox_in(
            &mut transaction,
            &system_audit(commit, next_revision, next_profile_epoch, next_egress_epoch),
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(ProfileContinuityCommit {
            credential_revision: next_revision,
            profile_epoch: next_profile_epoch,
            device_epoch,
            egress_epoch: next_egress_epoch,
        })
    }
}

fn system_audit(
    commit: &EgressRebindCommit,
    revision: i64,
    profile_epoch: i64,
    egress_epoch: i64,
) -> AuditOutboxRecord {
    AuditOutboxRecord {
        actor_type: "system".to_owned(),
        actor_id: None,
        action: "credential_egress_rebound".to_owned(),
        object_type: "credential".to_owned(),
        object_id: Some(commit.credential_id.to_string()),
        outcome: "success".to_owned(),
        redacted_detail: json!({"mode":commit.mode,"proxy_id":commit.proxy_id,
          "profile_epoch":profile_epoch,"egress_epoch":egress_epoch}),
        topic: "credential.egress.rebound".to_owned(),
        aggregate_id: commit.credential_id,
        aggregate_revision: revision,
        payload: json!({"credential_id":commit.credential_id,"revision":revision,
          "profile_epoch":profile_epoch,"egress_epoch":egress_epoch}),
    }
}

fn map_sqlx(_: sqlx::Error) -> StorageError {
    StorageError::TransactionFailed
}
