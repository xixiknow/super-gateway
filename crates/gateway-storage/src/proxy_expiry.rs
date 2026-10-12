//! Proxy validity window: pre-expiry reminders and expiry policy execution.
#![allow(missing_docs, clippy::missing_errors_doc, clippy::too_many_lines)]

use std::collections::HashMap;

use serde_json::json;
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{PgStorage, StorageError};

/// Counts produced by one expiry sweep.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxyExpirySweep {
    /// Proxies that received their pre-expiry reminder.
    pub reminded: u64,
    /// Proxies that expired and had their expiry policy applied.
    pub expired: u64,
}

/// Selectable replacement proxy with its remaining capacity.
struct ProxySlot {
    id: Uuid,
    used: i64,
    maximum: i64,
}

/// Where one Credential bound to an expired proxy should be moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RebindTarget {
    Direct,
    Proxy(Uuid),
    /// No acceptable route: the Credential stays unavailable until an operator acts.
    Stay,
}

/// What happened to one Credential bound to an expired proxy.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BindingOutcome {
    Direct,
    Switched,
    Unavailable,
}

impl PgStorage {
    /// Send due reminders, then expire due proxies. Each expired proxy commits in its own transaction.
    pub async fn sweep_proxy_expiry(&self, limit: i64) -> Result<ProxyExpirySweep, StorageError> {
        let reminded = self.remind_expiring_proxies(limit).await?;
        let due = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM gateway.proxy_endpoint \
             WHERE expired_at IS NULL AND expires_at IS NOT NULL AND expires_at<=clock_timestamp() \
               AND lifecycle_code<>'archived' ORDER BY expires_at,id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool())
        .await
        .map_err(map_sqlx)?;
        let mut expired = 0;
        for proxy_id in due {
            if self.expire_proxy(proxy_id).await? {
                expired += 1;
            }
        }
        Ok(ProxyExpirySweep { reminded, expired })
    }

    async fn remind_expiring_proxies(&self, limit: i64) -> Result<u64, StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let rows = sqlx::query(
            "SELECT id,name,to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI') AS expires_label, \
                    expiry_policy_code \
             FROM gateway.proxy_endpoint \
             WHERE lifecycle_code IN ('active','draining') AND expired_at IS NULL AND expiry_reminded_at IS NULL \
               AND remind_before_hours>0 AND expires_at IS NOT NULL AND expires_at>clock_timestamp() \
               AND expires_at-make_interval(hours=>remind_before_hours)<=clock_timestamp() \
             ORDER BY expires_at,id LIMIT $1 FOR UPDATE SKIP LOCKED",
        )
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        for row in &rows {
            let proxy_id: Uuid = row.try_get("id").map_err(map_sqlx)?;
            let name: String = row.try_get("name").map_err(map_sqlx)?;
            let expires: String = row.try_get("expires_label").map_err(map_sqlx)?;
            let policy: String = row.try_get("expiry_policy_code").map_err(map_sqlx)?;
            let summary = format!(
                "代理「{name}」将于 {expires} (UTC) 到期，到期策略：{}",
                policy_label(&policy)
            );
            open_alert(
                &mut transaction,
                &format!("proxy_expiring:{proxy_id}"),
                "warning",
                "proxy_expiring",
                proxy_id,
                &summary,
            )
            .await?;
            sqlx::query("UPDATE gateway.proxy_endpoint SET expiry_reminded_at=clock_timestamp() WHERE id=$1")
                .bind(proxy_id)
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        }
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(u64::try_from(rows.len()).unwrap_or(u64::MAX))
    }

    async fn expire_proxy(&self, proxy_id: Uuid) -> Result<bool, StorageError> {
        let mut transaction = self.pool().begin().await.map_err(map_sqlx)?;
        let Some(proxy) = sqlx::query(
            "SELECT name,expiry_policy_code FROM gateway.proxy_endpoint \
             WHERE id=$1 AND expired_at IS NULL AND expires_at<=clock_timestamp() AND lifecycle_code<>'archived' \
             FOR UPDATE SKIP LOCKED",
        )
        .bind(proxy_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        else {
            return Ok(false);
        };
        let name: String = proxy.try_get("name").map_err(map_sqlx)?;
        let policy: String = proxy.try_get("expiry_policy_code").map_err(map_sqlx)?;
        sqlx::query(
            "UPDATE gateway.proxy_endpoint SET lifecycle_code='disabled',drain_deadline_at=NULL, \
               drained_at=COALESCE(drained_at,clock_timestamp()),expired_at=clock_timestamp(), \
               revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
        )
        .bind(proxy_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;

        let mut slots = if policy == "switch_proxy" {
            replacement_slots(&mut transaction, proxy_id).await?
        } else {
            Vec::new()
        };
        let bindings = sqlx::query(
            "SELECT credential.id AS credential_id,credential.group_id,credential.revision,profile.profile_epoch, \
                    binding.egress_epoch,config.proxy_policy_code \
             FROM gateway.credential_egress_binding binding \
             JOIN gateway.anthropic_credential credential ON credential.id=binding.credential_id \
             JOIN gateway.credential_profile profile ON profile.egress_binding_id=binding.id \
             JOIN gateway.group_active_config pointer ON pointer.group_id=credential.group_id \
             JOIN gateway.group_config config ON config.id=pointer.config_id \
             WHERE binding.proxy_id=$1 AND binding.lifecycle_code='active' AND profile.lifecycle_code='active' \
               AND credential.lifecycle_state_code IN ('active','disabled') \
             ORDER BY credential.id FOR UPDATE OF credential,binding",
        )
        .bind(proxy_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let mut outcomes: HashMap<&'static str, usize> = HashMap::new();
        for binding in &bindings {
            let credential_id: Uuid = binding.try_get("credential_id").map_err(map_sqlx)?;
            let group_policy: String = binding.try_get("proxy_policy_code").map_err(map_sqlx)?;
            let target = choose_target(&policy, &group_policy, &mut slots);
            let outcome = match target {
                RebindTarget::Direct | RebindTarget::Proxy(_) => {
                    let target_proxy = match target {
                        RebindTarget::Proxy(id) => Some(id),
                        _ => None,
                    };
                    let enqueued = enqueue_credential_egress_rebind(
                        &mut transaction,
                        &EgressRebindRequest {
                            credential_id,
                            group_id: binding.try_get("group_id").map_err(map_sqlx)?,
                            credential_revision: binding.try_get("revision").map_err(map_sqlx)?,
                            profile_epoch: binding.try_get("profile_epoch").map_err(map_sqlx)?,
                            egress_epoch: binding.try_get("egress_epoch").map_err(map_sqlx)?,
                            proxy_id: target_proxy,
                            reason: if target_proxy.is_some() {
                                "proxy_expired_switch"
                            } else {
                                "proxy_expired_fallback_direct"
                            }
                            .to_owned(),
                        },
                    )
                    .await?;
                    if enqueued.is_some() {
                        if target_proxy.is_some() {
                            BindingOutcome::Switched
                        } else {
                            BindingOutcome::Direct
                        }
                    } else {
                        BindingOutcome::Unavailable
                    }
                }
                RebindTarget::Stay => BindingOutcome::Unavailable,
            };
            if outcome == BindingOutcome::Unavailable {
                sqlx::query(
                    "UPDATE gateway.credential_egress_binding SET stability_code='unavailable', \
                       lifecycle_code='transport_unavailable',rebind_reason_code='proxy_expired',revision=revision+1, \
                       updated_at=clock_timestamp() WHERE proxy_id=$1 AND credential_id=$2",
                )
                .bind(proxy_id)
                .bind(credential_id)
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
            }
            // Traffic stops immediately; a committed rebind restores `ready` on the new route.
            sqlx::query(
                "UPDATE gateway.anthropic_credential SET transport_state_code='transport_unavailable', \
                   revision=revision+1,updated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(credential_id)
            .execute(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            *outcomes
                .entry(match outcome {
                    BindingOutcome::Direct => "direct",
                    BindingOutcome::Switched => "switched",
                    BindingOutcome::Unavailable => "unavailable",
                })
                .or_default() += 1;
        }
        // Bindings that were already pending/quarantined cannot be rebound; keep them off the expired proxy.
        sqlx::query(
            "UPDATE gateway.credential_egress_binding SET stability_code='unavailable', \
               lifecycle_code='transport_unavailable',rebind_reason_code='proxy_expired',revision=revision+1, \
               updated_at=clock_timestamp() \
             WHERE proxy_id=$1 AND lifecycle_code IN ('pending','rebinding')",
        )
        .bind(proxy_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;

        let openai_moved = migrate_openai_accounts(&mut transaction, proxy_id, &policy, &mut slots).await?;

        let unavailable = outcomes.get("unavailable").copied().unwrap_or(0);
        let summary = format!(
            "代理「{name}」已到期并停用，到期策略：{}；凭据改直连 {} 个、换代理 {} 个、不可用 {} 个；OpenAI 账号迁移 {} 个",
            policy_label(&policy),
            outcomes.get("direct").copied().unwrap_or(0),
            outcomes.get("switched").copied().unwrap_or(0),
            unavailable,
            openai_moved,
        );
        open_alert(
            &mut transaction,
            &format!("proxy_expired:{proxy_id}"),
            if unavailable > 0 { "critical" } else { "warning" },
            "proxy_expired",
            proxy_id,
            &summary,
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(true)
    }
}

/// Inputs for one generation-fenced Credential egress rebind job.
pub struct EgressRebindRequest {
    pub credential_id: Uuid,
    pub group_id: Uuid,
    pub credential_revision: i64,
    pub profile_epoch: i64,
    pub egress_epoch: i64,
    /// `None` rebinds to direct egress.
    pub proxy_id: Option<Uuid>,
    pub reason: String,
}

/// Queue a `credential_egress_rebind_v1` job and return its id and creation time.
///
/// Returns `None` when a job for the same Credential generation already exists.
pub async fn enqueue_credential_egress_rebind(
    transaction: &mut Transaction<'_, Postgres>,
    request: &EgressRebindRequest,
) -> Result<Option<(Uuid, String)>, StorageError> {
    let job_id = Uuid::now_v7();
    let mode = if request.proxy_id.is_some() { "proxy" } else { "direct" };
    let inserted = sqlx::query_scalar::<_, String>(
        "INSERT INTO ops.durable_job \
         (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
          attempt_count,max_attempts,created_at,updated_at) \
         VALUES ($1,'credential_egress_rebind_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,200, \
                 clock_timestamp(),clock_timestamp()) \
         ON CONFLICT (kind_code,idempotency_key) DO NOTHING RETURNING created_at::text",
    )
    .bind(job_id)
    .bind(format!(
        "credential-egress-rebind:{}:{}:{}:{}",
        request.credential_id, request.credential_revision, request.profile_epoch, request.egress_epoch
    ))
    .bind(
        json!({"credential_id":request.credential_id,"group_id":request.group_id,
      "credential_revision":request.credential_revision,"profile_epoch":request.profile_epoch,
      "egress_epoch":request.egress_epoch,"mode":mode,"proxy_id":request.proxy_id,"reason":request.reason}),
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    let Some(created_at) = inserted else {
        return Ok(None);
    };
    sqlx::query(
        "INSERT INTO ops.durable_job_history \
         (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
         VALUES ($1,$2,NULL,'scheduled',0,'credential_egress_rebind_scheduled','{}'::jsonb,clock_timestamp())",
    )
    .bind(Uuid::now_v7())
    .bind(job_id)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(Some((job_id, created_at)))
}

/// Resolve open reminder/expiry alerts after an operator renews a proxy's validity window.
pub async fn resolve_proxy_expiry_alerts(
    transaction: &mut Transaction<'_, Postgres>,
    proxy_id: Uuid,
) -> Result<(), StorageError> {
    for fingerprint in [
        format!("proxy_expiring:{proxy_id}"),
        format!("proxy_expired:{proxy_id}"),
    ] {
        sqlx::query(
            "WITH resolved AS ( \
               UPDATE ops.alert SET state_code='resolved',resolved_at=clock_timestamp(),last_seen_at=clock_timestamp(), \
                 detail=detail||jsonb_build_object('resolution','proxy_validity_renewed'),revision=revision+1 \
               WHERE fingerprint=$1 AND state_code IN ('open','acknowledged','silenced') \
               RETURNING id,revision,severity_code,summary \
             ) \
             INSERT INTO ops.outbox_message \
              (id,event_id,topic_code,aggregate_type,aggregate_id,aggregate_revision,payload_schema_version,payload, \
               state_code,lease_generation,attempt_count,available_at,created_at) \
             SELECT $2,$3,'alert.alert_resolved','alert',id,revision,1, \
               jsonb_build_object('severity',severity_code,'summary',summary), \
               'pending',0,0,clock_timestamp(),clock_timestamp() FROM resolved",
        )
        .bind(&fingerprint)
        .bind(Uuid::now_v7())
        .bind(Uuid::now_v7())
        .execute(&mut **transaction)
        .await
        .map_err(map_sqlx)?;
    }
    Ok(())
}

/// Pick the rebind target for one Credential according to the proxy expiry policy and group policy.
fn choose_target(policy: &str, group_policy: &str, slots: &mut [ProxySlot]) -> RebindTarget {
    let direct = if group_policy == "proxy_required" {
        RebindTarget::Stay
    } else {
        RebindTarget::Direct
    };
    match policy {
        "fallback_direct" => direct,
        "switch_proxy" => {
            if group_policy != "direct"
                && let Some(slot) = least_loaded(slots)
            {
                slot.used += 1;
                return RebindTarget::Proxy(slot.id);
            }
            direct
        }
        _ => RebindTarget::Stay,
    }
}

fn least_loaded(slots: &mut [ProxySlot]) -> Option<&mut ProxySlot> {
    slots
        .iter_mut()
        .filter(|slot| slot.used < slot.maximum)
        .min_by(|left, right| {
            (i128::from(left.used) * i128::from(right.maximum))
                .cmp(&(i128::from(right.used) * i128::from(left.maximum)))
                .then_with(|| left.id.cmp(&right.id))
        })
}

async fn replacement_slots(
    transaction: &mut Transaction<'_, Postgres>,
    expired_proxy: Uuid,
) -> Result<Vec<ProxySlot>, StorageError> {
    let rows = sqlx::query(
        "SELECT proxy.id,proxy.max_active_bindings::bigint AS maximum, \
                (SELECT count(*) FROM gateway.credential_egress_binding binding \
                  WHERE binding.proxy_id=proxy.id \
                    AND binding.lifecycle_code IN ('pending','active','transport_unavailable','rebinding'))::bigint AS used \
         FROM gateway.proxy_endpoint proxy \
         WHERE proxy.id<>$1 AND proxy.lifecycle_code='active' AND proxy.health_code='healthy' \
           AND proxy.stability_code='static' AND proxy.starts_at<=clock_timestamp() \
           AND (proxy.expires_at IS NULL OR proxy.expires_at>clock_timestamp()) \
         ORDER BY proxy.id",
    )
    .bind(expired_proxy)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    rows.iter()
        .map(|row| {
            Ok(ProxySlot {
                id: row.try_get("id").map_err(map_sqlx)?,
                used: row.try_get("used").map_err(map_sqlx)?,
                maximum: row.try_get("maximum").map_err(map_sqlx)?,
            })
        })
        .collect()
}

/// `OpenAI` accounts reference proxies directly and are re-pointed in place.
async fn migrate_openai_accounts(
    transaction: &mut Transaction<'_, Postgres>,
    proxy_id: Uuid,
    policy: &str,
    slots: &mut [ProxySlot],
) -> Result<u64, StorageError> {
    let target = match policy {
        "fallback_direct" => None,
        "switch_proxy" => least_loaded(slots).map(|slot| slot.id),
        _ => return Ok(0),
    };
    // Switching falls back to direct when no replacement exists, unless the group requires a proxy.
    let changed = sqlx::query(
        "UPDATE gateway.openai_account account SET proxy_id=$2,revision=revision+1,updated_at=clock_timestamp() \
         WHERE account.proxy_id=$1 AND EXISTS ( \
           SELECT 1 FROM gateway.group_active_config pointer JOIN gateway.group_config config ON config.id=pointer.config_id \
           WHERE pointer.group_id=account.group_id \
             AND CASE WHEN $2::uuid IS NULL THEN config.proxy_policy_code<>'proxy_required' \
                      ELSE config.proxy_policy_code<>'direct' END)",
    )
    .bind(proxy_id)
    .bind(target)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(changed.rows_affected())
}

async fn open_alert(
    transaction: &mut Transaction<'_, Postgres>,
    fingerprint: &str,
    severity: &str,
    type_code: &str,
    proxy_id: Uuid,
    summary: &str,
) -> Result<(), StorageError> {
    // The notification event is emitted only when the alert is newly opened.
    sqlx::query(
        "WITH current_alert AS ( \
           INSERT INTO ops.alert \
            (id,fingerprint,severity_code,type_code,state_code,object_type_code,object_id,summary,detail, \
             first_seen_at,last_seen_at,revision) \
           VALUES ($1,$2,$3,$4,'open','proxy_endpoint',$5,$6,'{}'::jsonb,clock_timestamp(),clock_timestamp(),1) \
           ON CONFLICT (fingerprint) WHERE state_code IN ('open','acknowledged','silenced') \
           DO UPDATE SET last_seen_at=clock_timestamp(),summary=EXCLUDED.summary,revision=ops.alert.revision+1 \
           RETURNING id,revision,(xmax=0) AS newly_opened \
         ) \
         INSERT INTO ops.outbox_message \
          (id,event_id,topic_code,aggregate_type,aggregate_id,aggregate_revision,payload_schema_version,payload, \
           state_code,lease_generation,attempt_count,available_at,created_at) \
         SELECT $7,$8,'alert.critical','alert',id,revision,1,$9,'pending',0,0,clock_timestamp(),clock_timestamp() \
         FROM current_alert WHERE newly_opened \
         ON CONFLICT (aggregate_type,aggregate_id,aggregate_revision,topic_code) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(fingerprint)
    .bind(severity)
    .bind(type_code)
    .bind(proxy_id.to_string())
    .bind(summary)
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .bind(json!({"severity":severity,"summary":summary}))
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

fn policy_label(policy: &str) -> &'static str {
    match policy {
        "fallback_direct" => "回退直连",
        "switch_proxy" => "更换其他代理",
        _ => "不回退",
    }
}

fn map_sqlx(_: sqlx::Error) -> StorageError {
    StorageError::TransactionFailed
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{ProxySlot, RebindTarget, choose_target};

    fn slot(id: u128, used: i64, maximum: i64) -> ProxySlot {
        ProxySlot {
            id: Uuid::from_u128(id),
            used,
            maximum,
        }
    }

    #[test]
    fn fallback_direct_respects_proxy_required_groups() {
        assert_eq!(choose_target("fallback_direct", "auto", &mut []), RebindTarget::Direct);
        assert_eq!(
            choose_target("fallback_direct", "proxy_required", &mut []),
            RebindTarget::Stay
        );
        assert_eq!(choose_target("none", "auto", &mut [slot(1, 0, 5)]), RebindTarget::Stay);
    }

    #[test]
    fn switch_spreads_load_and_falls_back_when_exhausted() {
        let mut slots = [slot(1, 0, 1), slot(2, 0, 2)];
        assert_eq!(
            choose_target("switch_proxy", "auto", &mut slots),
            RebindTarget::Proxy(Uuid::from_u128(1))
        );
        assert_eq!(
            choose_target("switch_proxy", "auto", &mut slots),
            RebindTarget::Proxy(Uuid::from_u128(2))
        );
        assert_eq!(
            choose_target("switch_proxy", "auto", &mut slots),
            RebindTarget::Proxy(Uuid::from_u128(2))
        );
        assert_eq!(choose_target("switch_proxy", "auto", &mut slots), RebindTarget::Direct);
        assert_eq!(
            choose_target("switch_proxy", "proxy_required", &mut slots),
            RebindTarget::Stay
        );
    }

    #[test]
    fn switch_never_selects_a_proxy_for_direct_only_groups() {
        assert_eq!(
            choose_target("switch_proxy", "direct", &mut [slot(1, 0, 5)]),
            RebindTarget::Direct
        );
    }
}
