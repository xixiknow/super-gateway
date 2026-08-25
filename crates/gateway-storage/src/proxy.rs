//! Durable Proxy probe projection and generation-fenced state changes.
#![allow(missing_docs, clippy::missing_errors_doc, clippy::too_many_lines)]

use serde_json::Value;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{AuditOutboxRecord, PgStorage, StorageError};

/// Secret-free evidence produced by one full-path Proxy probe.
pub struct ProxyProbeCommit {
    pub proxy_id: Uuid,
    pub job_id: Uuid,
    pub job_generation: i64,
    pub probe_generation: i64,
    pub result_code: String,
    pub observed_exit_ip: Option<String>,
    pub latency_ms: Option<i32>,
    pub negotiated_alpn: Option<String>,
    pub certificate_sha256: Option<[u8; 32]>,
    pub redacted_detail: Value,
}

impl PgStorage {
    /// Atomically commit probe evidence, Proxy/Binding/Credential projections,
    /// the durable Job terminal state, Audit and Outbox.
    pub async fn complete_proxy_probe(&self, commit: &ProxyProbeCommit) -> Result<(), StorageError> {
        if !matches!(
            commit.result_code.as_str(),
            "healthy"
                | "dns_failed"
                | "connect_failed"
                | "auth_failed"
                | "tunnel_failed"
                | "tls_intercepted"
                | "egress_mismatch"
                | "cancelled"
        ) || commit.latency_ms.is_some_and(|value| value < 0)
            || commit
                .negotiated_alpn
                .as_deref()
                .is_some_and(|value| !matches!(value, "h1" | "h2"))
        {
            return Err(StorageError::TransactionFailed);
        }
        let credential_ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT credential_id FROM gateway.credential_egress_binding WHERE proxy_id=$1 ORDER BY credential_id",
        )
        .bind(commit.proxy_id)
        .fetch_all(&self.pool())
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        let mut transaction = self.pool().begin().await.map_err(|_| StorageError::TransactionFailed)?;
        for credential_id in &credential_ids {
            sqlx::query("SELECT id FROM gateway.anthropic_credential WHERE id=$1 FOR UPDATE")
                .bind(credential_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| StorageError::TransactionFailed)?;
            sqlx::query("SELECT id FROM gateway.credential_egress_binding WHERE credential_id=$1 FOR UPDATE")
                .bind(credential_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| StorageError::TransactionFailed)?;
        }
        let proxy = sqlx::query(
            "SELECT host(expected_egress_ip) AS expected_egress_ip,lifecycle_code,revision FROM gateway.proxy_endpoint \
             WHERE id=$1 AND probe_generation=$2 AND health_code='probing' AND lifecycle_code IN ('active','disabled') \
             FOR UPDATE",
        )
        .bind(commit.proxy_id)
        .bind(commit.probe_generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?
        .ok_or(StorageError::RevisionConflict)?;
        let expected_ip: Option<String> = proxy
            .try_get("expected_egress_ip")
            .map_err(|_| StorageError::TransactionFailed)?;
        let proxy_lifecycle: String = proxy
            .try_get("lifecycle_code")
            .map_err(|_| StorageError::TransactionFailed)?;
        let observed_ip = commit.observed_exit_ip.as_deref();
        let egress_mismatch = commit.result_code == "healthy"
            && expected_ip
                .as_deref()
                .zip(observed_ip)
                .is_some_and(|(expected, observed)| expected != observed);
        let result_code = if egress_mismatch {
            "egress_mismatch"
        } else {
            commit.result_code.as_str()
        };
        let health_code = match result_code {
            "healthy" => "healthy",
            "dns_failed" => "unhealthy_dns",
            "auth_failed" => "unhealthy_auth",
            "tunnel_failed" | "egress_mismatch" => "unhealthy_tunnel",
            "tls_intercepted" => "unhealthy_tls_passthrough",
            _ => "unhealthy_connect",
        };
        let healthy = health_code == "healthy";
        let schedulable = healthy && proxy_lifecycle == "active";
        let updated = sqlx::query(
            "UPDATE gateway.proxy_endpoint SET health_code=$3, \
               expected_egress_ip=CASE WHEN $4 AND expected_egress_ip IS NULL THEN $5::inet ELSE expected_egress_ip END, \
               observed_egress_ip=CASE WHEN $5::text IS NULL THEN observed_egress_ip ELSE $5::inet END, \
               consecutive_successes=CASE WHEN $4 THEN consecutive_successes+1 ELSE 0 END, \
               consecutive_failures=CASE WHEN $4 THEN 0 ELSE consecutive_failures+1 END, \
               last_success_at=CASE WHEN $4 THEN clock_timestamp() ELSE last_success_at END, \
               failure_window_started_at=CASE WHEN $4 THEN NULL ELSE COALESCE(failure_window_started_at,clock_timestamp()) END, \
               last_error_code=CASE WHEN $4 THEN NULL ELSE $6 END,last_probed_at=clock_timestamp(), \
               revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND probe_generation=$2 RETURNING revision",
        )
        .bind(commit.proxy_id)
        .bind(commit.probe_generation)
        .bind(health_code)
        .bind(healthy)
        .bind(observed_ip)
        .bind(result_code)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        let revision: i64 = updated
            .try_get("revision")
            .map_err(|_| StorageError::TransactionFailed)?;
        if schedulable {
            sqlx::query(
                "UPDATE gateway.credential_egress_binding SET stability_code='stable',lifecycle_code='active', \
                   rebind_reason_code=NULL,observed_egress_ip=COALESCE($2::inet,observed_egress_ip),observed_at=clock_timestamp(), \
                   revision=revision+1,updated_at=clock_timestamp() \
                 WHERE proxy_id=$1 AND lifecycle_code='transport_unavailable' AND rebind_reason_code='proxy_probe_failed'",
            )
            .bind(commit.proxy_id)
            .bind(observed_ip)
            .execute(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
            sqlx::query(
                "UPDATE gateway.anthropic_credential c SET transport_state_code='ready',revision=revision+1, \
                   updated_at=clock_timestamp() WHERE id=ANY($1) AND EXISTS (SELECT 1 FROM gateway.credential_egress_binding b \
                     WHERE b.credential_id=c.id AND b.proxy_id=$2 AND b.lifecycle_code='active' AND b.stability_code='stable')",
            )
            .bind(&credential_ids)
            .bind(commit.proxy_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
        } else {
            sqlx::query(
                "UPDATE gateway.credential_egress_binding SET stability_code=CASE WHEN $2='egress_mismatch' THEN 'drifted' ELSE 'unavailable' END, \
                   lifecycle_code='transport_unavailable',rebind_reason_code='proxy_probe_failed',observed_at=clock_timestamp(), \
                   revision=revision+1,updated_at=clock_timestamp() WHERE proxy_id=$1 AND lifecycle_code<>'disabled'",
            )
            .bind(commit.proxy_id)
            .bind(result_code)
            .execute(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
            sqlx::query(
                "UPDATE gateway.anthropic_credential SET transport_state_code='transport_unavailable', \
                   revision=revision+1,updated_at=clock_timestamp() WHERE id=ANY($1)",
            )
            .bind(&credential_ids)
            .execute(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
        }
        sqlx::query(
            "INSERT INTO gateway.proxy_probe_observation \
             (id,proxy_id,durable_job_id,probe_generation,result_code,latency_ms,observed_egress_ip, \
              negotiated_alpn,certificate_sha256,redacted_detail,observed_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7::inet,$8,$9,$10,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(commit.proxy_id)
        .bind(commit.job_id)
        .bind(commit.probe_generation)
        .bind(result_code)
        .bind(commit.latency_ms)
        .bind(observed_ip)
        .bind(commit.negotiated_alpn.as_deref())
        .bind(commit.certificate_sha256.as_ref().map(<[u8; 32]>::as_slice))
        .bind(&commit.redacted_detail)
        .execute(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        let job = sqlx::query(
            "UPDATE ops.durable_job SET state_code='succeeded',lease_owner=NULL,lease_expires_at=NULL, \
               checkpoint=jsonb_build_object('result',$3,'proxy_revision',$4),updated_at=clock_timestamp(),completed_at=clock_timestamp() \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2 RETURNING id",
        )
        .bind(commit.job_id)
        .bind(commit.job_generation)
        .bind(result_code)
        .bind(revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        if job.is_none() {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,'leased','succeeded',$3,$4,jsonb_build_object('proxy_id',$5,'probe_generation',$6),clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(commit.job_id)
        .bind(commit.job_generation)
        .bind(result_code)
        .bind(commit.proxy_id)
        .bind(commit.probe_generation)
        .execute(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        self.append_audit_outbox_in(
            &mut transaction,
            &AuditOutboxRecord {
                actor_type: "system".to_owned(),
                actor_id: None,
                action: "proxy_probe_completed".to_owned(),
                object_type: "proxy".to_owned(),
                object_id: Some(commit.proxy_id.to_string()),
                outcome: if healthy { "success" } else { "failed" }.to_owned(),
                redacted_detail: serde_json::json!({"result":result_code,"probe_generation":commit.probe_generation}),
                topic: "proxy.probe.completed".to_owned(),
                aggregate_id: commit.proxy_id,
                aggregate_revision: revision,
                payload: serde_json::json!({"proxy_id":commit.proxy_id,"result":result_code,"revision":revision}),
            },
        )
        .await?;
        transaction.commit().await.map_err(|_| StorageError::TransactionFailed)
    }
}
