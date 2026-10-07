//! R7 request, submission, delivery, usage and cost persistence.
#![allow(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::time::Duration;

use gateway_domain::{
    ClientOs, CostEstimate, DeliveryOutcome, OsResolution, PriceSnapshot, ResponseMode, UsageCompleteness,
    UsageObservation, UsageSource,
};
use serde_json::Value;
use sqlx::Postgres;
use uuid::Uuid;

use crate::{PgStorage, StorageError};

#[derive(Clone, Debug)]
pub struct RequestCreate {
    pub request_id: Uuid,
    pub platform_key_id: Uuid,
    pub group_id: Uuid,
    pub owner_executor_id: Box<str>,
    pub owner_generation: i64,
    pub endpoint_code: Box<str>,
    pub client_class_code: Box<str>,
    pub client_os: ClientOs,
    pub os_resolution: OsResolution,
    pub os_mismatch: bool,
    pub model_id: Option<Uuid>,
    pub request_body_bytes: i64,
    pub response_mode: ResponseMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyCaptureConfig {
    pub enabled: bool,
    pub retention_days: i32,
    pub max_bytes: usize,
}

impl Default for BodyCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_days: 7,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

impl BodyCaptureConfig {
    /// Each capture stage has its own byte limit; oversized stages do not hide others.
    #[must_use]
    pub fn request_json(self, body: &[u8]) -> Option<Value> {
        if !self.enabled || body.len() > self.max_bytes {
            return None;
        }
        serde_json::from_slice(body).ok()
    }
}

fn request_reasoning_effort(body: &[u8]) -> Option<String> {
    let body: Value = serde_json::from_slice(body).ok()?;
    for path in ["/reasoning/effort", "/reasoning_effort", "/output_config/effort"] {
        if let Some(effort) = body.pointer(path).and_then(Value::as_str) {
            return Some(effort.chars().take(64).collect());
        }
    }
    let thinking = body.pointer("/thinking/type")?.as_str()?;
    if thinking == "enabled"
        && let Some(budget) = body.pointer("/thinking/budget_tokens").and_then(Value::as_u64)
    {
        return Some(format!("budget:{budget}"));
    }
    Some(thinking.chars().take(64).collect())
}

/// Operator-tunable runtime thresholds stored in `ops.system_setting`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeSettings {
    /// Hours between scheduled `LiteLLM` price synchronizations.
    pub price_sync_interval_hours: i32,
    /// Sliding window used to evaluate upstream third-party rejections.
    pub third_party_window_minutes: i32,
    /// Minimum rejected attempts inside the window before alerting.
    pub third_party_min_rejections: i32,
    /// Rejected/total attempt ratio (percent) inside the window before alerting.
    pub third_party_ratio_percent: i32,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            price_sync_interval_hours: 24,
            third_party_window_minutes: 15,
            third_party_min_rejections: 3,
            third_party_ratio_percent: 20,
        }
    }
}

impl RuntimeSettings {
    pub const PRICE_SYNC_INTERVAL_HOURS: std::ops::RangeInclusive<i32> = 1..=168;
    pub const THIRD_PARTY_WINDOW_MINUTES: std::ops::RangeInclusive<i32> = 1..=1440;
    pub const THIRD_PARTY_MIN_REJECTIONS: std::ops::RangeInclusive<i32> = 1..=1000;
    pub const THIRD_PARTY_RATIO_PERCENT: std::ops::RangeInclusive<i32> = 1..=100;

    #[must_use]
    pub fn is_valid(&self) -> bool {
        Self::PRICE_SYNC_INTERVAL_HOURS.contains(&self.price_sync_interval_hours)
            && Self::THIRD_PARTY_WINDOW_MINUTES.contains(&self.third_party_window_minutes)
            && Self::THIRD_PARTY_MIN_REJECTIONS.contains(&self.third_party_min_rejections)
            && Self::THIRD_PARTY_RATIO_PERCENT.contains(&self.third_party_ratio_percent)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestBodyCapture {
    pub request_id: Uuid,
    pub original_headers: Option<Value>,
    pub final_upstream_headers: Option<Value>,
    pub upstream_response_headers: Option<Value>,
    pub original_request: Option<Value>,
    pub policy_request: Option<Value>,
    pub final_upstream_request: Option<Value>,
    pub upstream_response: Option<String>,
    pub upstream_response_final: Option<Value>,
    pub captured_at: String,
    pub body_digest_mismatch: bool,
}

#[derive(Clone, Debug)]
pub struct SubmissionIntentArm {
    pub intent_id: Uuid,
    pub request_id: Uuid,
    pub ordinal: i16,
    pub credential_id: Uuid,
    pub token_version: i64,
    pub profile_epoch: i64,
    pub egress_epoch: i64,
    pub transport_bundle_id: Uuid,
    pub generic_adjusted_request_hash: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DeliveryStart {
    pub delivery_id: Uuid,
    pub request_id: Uuid,
    pub attempt_id: Option<Uuid>,
    pub streaming: bool,
    pub buffer_tier_code: Option<Box<str>>,
    pub client_write_idle_ms: i64,
}

#[derive(Clone, Debug)]
pub struct DeliveryComplete {
    pub delivery_id: Uuid,
    pub outcome: DeliveryOutcome,
    pub response_committed: bool,
    pub upstream_bytes_received: i64,
    pub bytes_delivered: i64,
    pub peak_backpressure_bytes: i64,
    pub spill_bytes: i64,
}

#[derive(Clone, Debug)]
pub struct RequestLifecycleComplete {
    pub request_id: Uuid,
    pub attempt_id: Uuid,
    pub delivery: DeliveryComplete,
}

#[derive(Clone, Debug)]
pub struct UsagePersist {
    pub observation_id: Uuid,
    pub request_id: Uuid,
    pub attempt_id: Option<Uuid>,
    pub model_id: Option<Uuid>,
    pub observation: UsageObservation,
    pub select_as_final: bool,
    pub selection_reason_code: Option<Box<str>>,
    pub cancel_evidence: Option<CancelEstimateEvidencePersist>,
}

#[derive(Clone, Debug)]
pub struct CancelEstimateEvidencePersist {
    pub input_basis_digest: [u8; 32],
    pub sse_complete_event_ordinal: Option<i64>,
    pub sse_content_event_ordinal: Option<i64>,
    pub sse_decoded_end_offset: Option<i64>,
    pub sse_last_event_type: Option<Box<str>>,
    pub sse_gap: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct CostPersist {
    pub cost_id: Uuid,
    pub usage_observation_id: Uuid,
    pub price_entry_id: Option<Uuid>,
    pub price_snapshot: PriceSnapshot,
    pub estimate: CostEstimate,
    pub amount_pico_usd: Option<Box<str>>,
    pub known_field_mask: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriceBasis {
    pub price_entry_id: Uuid,
    pub snapshot: PriceSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaObservationPersist {
    pub observation_id: Uuid,
    pub window_kind_code: Box<str>,
    pub utilization_nanos: u32,
    pub reset_epoch_seconds: u64,
    pub header_digest: Vec<u8>,
    pub parser_version: Box<str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaCurrentProjection {
    pub observation_version: Uuid,
    pub used_basis_points: u16,
    pub reset_after: Duration,
}

impl PgStorage {
    /// Lightweight request metadata survives body/header retention cleanup.
    pub async fn record_request_client(
        &self,
        request_id: Uuid,
        identity: &gateway_domain::ClientIdentity,
        request_type: &str,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE telemetry.request_record SET client_name=$2,client_version=$3,request_type=$4 WHERE request_id=$1",
        )
        .bind(request_id)
        .bind(&identity.name)
        .bind(&identity.version)
        .bind(request_type)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        Ok(())
    }

    /// First output and completion arrive independently; neither may erase the other.
    pub async fn record_request_timing(
        &self,
        request_id: Uuid,
        first_content_ms: Option<i64>,
        duration_ms: Option<i64>,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE telemetry.request_record SET first_content_ms=COALESCE(first_content_ms,$2),duration_ms=COALESCE(duration_ms,$3) WHERE request_id=$1")
            .bind(request_id).bind(first_content_ms).bind(duration_ms)
            .execute(&self.pool()).await.map_err(transaction_error)?;
        Ok(())
    }

    /// Store the effective reasoning setting independently of optional body retention.
    pub async fn record_request_reasoning(&self, request_id: Uuid, body: &[u8]) -> Result<(), StorageError> {
        sqlx::query("UPDATE telemetry.request_record SET reasoning_effort=$2 WHERE request_id=$1")
            .bind(request_id)
            .bind(request_reasoning_effort(body))
            .execute(&self.pool())
            .await
            .map_err(transaction_error)?;
        Ok(())
    }

    pub async fn body_capture_config(&self) -> Result<BodyCaptureConfig, StorageError> {
        let rows = sqlx::query("SELECT key,value FROM ops.system_setting WHERE key LIKE 'body_capture.%'")
            .fetch_all(&self.pool())
            .await
            .map_err(transaction_error)?;
        let mut config = BodyCaptureConfig::default();
        for row in rows {
            let key: String = sqlx::Row::try_get(&row, "key").map_err(transaction_error)?;
            let value: Value = sqlx::Row::try_get(&row, "value").map_err(transaction_error)?;
            match key.as_str() {
                "body_capture.enabled" => config.enabled = value.as_bool().unwrap_or(false),
                "body_capture.retention_days" => {
                    config.retention_days = value
                        .as_i64()
                        .and_then(|v| i32::try_from(v).ok())
                        .unwrap_or(7)
                        .clamp(1, 365);
                }
                "body_capture.max_bytes" => {
                    config.max_bytes = value
                        .as_u64()
                        .and_then(|v| usize::try_from(v).ok())
                        .unwrap_or(4 * 1024 * 1024)
                        .clamp(1, 64 * 1024 * 1024);
                }
                _ => {}
            }
        }
        Ok(config)
    }

    pub async fn update_body_capture_config(
        &self,
        config: BodyCaptureConfig,
        updated_by: Uuid,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(transaction_error)?;
        for (key, value) in [
            ("body_capture.enabled", Value::Bool(config.enabled)),
            ("body_capture.retention_days", Value::from(config.retention_days)),
            (
                "body_capture.max_bytes",
                Value::from(u64::try_from(config.max_bytes).map_err(|_| StorageError::TransactionFailed)?),
            ),
        ] {
            sqlx::query(
                "INSERT INTO ops.system_setting(key,value,updated_by,updated_at) VALUES($1,$2,$3,clock_timestamp()) \
                 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=EXCLUDED.updated_at",
            )
            .bind(key)
            .bind(value)
            .bind(updated_by)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        }
        transaction.commit().await.map_err(transaction_error)
    }

    pub async fn runtime_settings(&self) -> Result<RuntimeSettings, StorageError> {
        let rows = sqlx::query(
            "SELECT key,value FROM ops.system_setting WHERE key LIKE 'price_sync.%' OR key LIKE 'third_party.%'",
        )
        .fetch_all(&self.pool())
        .await
        .map_err(transaction_error)?;
        let mut settings = RuntimeSettings::default();
        let defaults = RuntimeSettings::default();
        for row in rows {
            let key: String = sqlx::Row::try_get(&row, "key").map_err(transaction_error)?;
            let value: Value = sqlx::Row::try_get(&row, "value").map_err(transaction_error)?;
            let integer = |fallback: i32, range: std::ops::RangeInclusive<i32>| {
                value
                    .as_i64()
                    .and_then(|v| i32::try_from(v).ok())
                    .filter(|v| range.contains(v))
                    .unwrap_or(fallback)
            };
            match key.as_str() {
                "price_sync.interval_hours" => {
                    settings.price_sync_interval_hours = integer(
                        defaults.price_sync_interval_hours,
                        RuntimeSettings::PRICE_SYNC_INTERVAL_HOURS,
                    );
                }
                "third_party.window_minutes" => {
                    settings.third_party_window_minutes = integer(
                        defaults.third_party_window_minutes,
                        RuntimeSettings::THIRD_PARTY_WINDOW_MINUTES,
                    );
                }
                "third_party.min_rejections" => {
                    settings.third_party_min_rejections = integer(
                        defaults.third_party_min_rejections,
                        RuntimeSettings::THIRD_PARTY_MIN_REJECTIONS,
                    );
                }
                "third_party.ratio_percent" => {
                    settings.third_party_ratio_percent = integer(
                        defaults.third_party_ratio_percent,
                        RuntimeSettings::THIRD_PARTY_RATIO_PERCENT,
                    );
                }
                _ => {}
            }
        }
        Ok(settings)
    }

    pub async fn update_runtime_settings(
        &self,
        settings: RuntimeSettings,
        updated_by: Uuid,
    ) -> Result<(), StorageError> {
        if !settings.is_valid() {
            return Err(StorageError::InvalidLifecycle);
        }
        let mut transaction = self.pool().begin().await.map_err(transaction_error)?;
        for (key, value) in [
            ("price_sync.interval_hours", settings.price_sync_interval_hours),
            ("third_party.window_minutes", settings.third_party_window_minutes),
            ("third_party.min_rejections", settings.third_party_min_rejections),
            ("third_party.ratio_percent", settings.third_party_ratio_percent),
        ] {
            sqlx::query(
                "INSERT INTO ops.system_setting(key,value,updated_by,updated_at) VALUES($1,$2,$3,clock_timestamp()) \
                 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=EXCLUDED.updated_at",
            )
            .bind(key)
            .bind(Value::from(value))
            .bind(updated_by)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        }
        transaction.commit().await.map_err(transaction_error)
    }

    pub async fn capture_original_headers(
        &self,
        request_id: Uuid,
        headers: &gateway_domain::HeaderSnapshot,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "INSERT INTO telemetry.request_body(request_month,request_id,original_headers) \
             SELECT request_month,$1,$2 FROM telemetry.request_record WHERE request_id=$1 \
             ON CONFLICT(request_month,request_id) DO UPDATE SET original_headers=EXCLUDED.original_headers,captured_at=clock_timestamp()",
        ).bind(request_id).bind(serde_json::to_value(headers).map_err(|_| StorageError::TransactionFailed)?)
            .execute(&self.pool()).await.map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    /// Reset both upstream snapshots together before preparing a new attempt.
    pub async fn begin_header_attempt(&self, request_id: Uuid, ordinal: u32) -> Result<(), StorageError> {
        let result = sqlx::query(
            "INSERT INTO telemetry.request_body(request_month,request_id,header_attempt_ordinal) \
             SELECT request_month,$1,$2 FROM telemetry.request_record WHERE request_id=$1 \
             ON CONFLICT(request_month,request_id) DO UPDATE SET header_attempt_ordinal=EXCLUDED.header_attempt_ordinal, \
               final_upstream_headers=NULL,upstream_response_headers=NULL,captured_at=clock_timestamp()",
        ).bind(request_id).bind(i32::try_from(ordinal).map_err(|_| StorageError::TransactionFailed)?)
            .execute(&self.pool()).await.map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    /// The ordinal fence rejects stale capture events from an older attempt.
    pub async fn capture_upstream_headers(
        &self,
        request_id: Uuid,
        response: bool,
        headers: &gateway_domain::HeaderSnapshot,
    ) -> Result<(), StorageError> {
        let ordinal = headers.attempt_ordinal.ok_or(StorageError::TransactionFailed)?;
        let result = sqlx::query(
            "UPDATE telemetry.request_body SET \
               final_upstream_headers=CASE WHEN $3 THEN final_upstream_headers ELSE $4 END, \
               upstream_response_headers=CASE WHEN $3 THEN $4 ELSE upstream_response_headers END,captured_at=clock_timestamp() \
             WHERE request_id=$1 AND header_attempt_ordinal=$2",
        ).bind(request_id).bind(i32::try_from(ordinal).map_err(|_| StorageError::TransactionFailed)?)
            .bind(response).bind(serde_json::to_value(headers).map_err(|_| StorageError::TransactionFailed)?)
            .execute(&self.pool()).await.map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    pub async fn capture_request_body(
        &self,
        request_id: Uuid,
        original_request: Option<Value>,
        policy_request: Option<Value>,
        final_upstream_request: Option<Value>,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "INSERT INTO telemetry.request_body(request_month,request_id,original_request,policy_request,final_upstream_request) \
             SELECT request_month,$1,$2,$3,$4 FROM telemetry.request_record WHERE request_id=$1 \
             ON CONFLICT(request_month,request_id) DO UPDATE SET \
               original_request=COALESCE(EXCLUDED.original_request,telemetry.request_body.original_request), \
               policy_request=COALESCE(EXCLUDED.policy_request,telemetry.request_body.policy_request), \
               final_upstream_request=COALESCE(EXCLUDED.final_upstream_request,telemetry.request_body.final_upstream_request), \
               captured_at=clock_timestamp()",
        )
        .bind(request_id)
        .bind(original_request)
        .bind(policy_request)
        .bind(final_upstream_request)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    /// Replace this stage even when an attempt exceeds the capture limit, so a
    /// previous attempt's final body is never presented as the current one.
    pub async fn capture_final_request_body(&self, request_id: Uuid, body: Option<Value>) -> Result<(), StorageError> {
        let result = sqlx::query(
            "INSERT INTO telemetry.request_body(request_month,request_id,final_upstream_request) \
             SELECT request_month,$1,$2 FROM telemetry.request_record WHERE request_id=$1 \
             ON CONFLICT(request_month,request_id) DO UPDATE SET \
               final_upstream_request=EXCLUDED.final_upstream_request,body_digest_mismatch=false,captured_at=clock_timestamp()",
        )
        .bind(request_id)
        .bind(body)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    pub async fn mark_body_digest_mismatch(&self, request_id: Uuid) -> Result<(), StorageError> {
        sqlx::query("UPDATE telemetry.request_body SET body_digest_mismatch=true WHERE request_id=$1")
            .bind(request_id)
            .execute(&self.pool())
            .await
            .map_err(transaction_error)?;
        Ok(())
    }

    pub async fn capture_response_body(
        &self,
        request_id: Uuid,
        body: &[u8],
        _complete: bool,
        max_bytes: usize,
    ) -> Result<(), StorageError> {
        let body = &body[..body.len().min(max_bytes)];
        let text = String::from_utf8_lossy(body).into_owned();
        let final_value = serde_json::from_slice::<Value>(body)
            .ok()
            .or_else(|| aggregate_sse_message(body));
        let result = sqlx::query(
            "UPDATE telemetry.request_body rb SET upstream_response=$2,upstream_response_final=$3,captured_at=clock_timestamp() \
             FROM telemetry.request_record r WHERE rb.request_id=$1 AND rb.request_month=r.request_month AND r.request_id=$1",
        )
        .bind(request_id)
        .bind(text)
        .bind(final_value)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        if result.rows_affected() == 0 {
            self.capture_request_body(request_id, None, None, None).await?;
            sqlx::query(
                "UPDATE telemetry.request_body rb SET upstream_response=$2,upstream_response_final=$3,captured_at=clock_timestamp() \
                 FROM telemetry.request_record r WHERE rb.request_id=$1 AND rb.request_month=r.request_month AND r.request_id=$1",
            )
            .bind(request_id)
            .bind(String::from_utf8_lossy(body).into_owned())
            .bind(serde_json::from_slice::<Value>(body).ok().or_else(|| aggregate_sse_message(body)))
            .execute(&self.pool())
            .await
            .map_err(transaction_error)?;
        }
        Ok(())
    }

    pub async fn get_request_body(&self, request_id: Uuid) -> Result<Option<RequestBodyCapture>, StorageError> {
        let row = sqlx::query(
            "SELECT rb.request_id,rb.original_headers,rb.final_upstream_headers,rb.upstream_response_headers,rb.original_request,rb.policy_request,rb.final_upstream_request,rb.upstream_response,rb.upstream_response_final,rb.captured_at::text AS captured_at,rb.body_digest_mismatch \
             FROM telemetry.request_body rb WHERE rb.request_id=$1 ORDER BY rb.request_month DESC LIMIT 1",
        )
        .bind(request_id)
        .fetch_optional(&self.pool())
        .await
        .map_err(transaction_error)?;
        row.map(|row| {
            Ok(RequestBodyCapture {
                request_id: sqlx::Row::try_get(&row, "request_id").map_err(transaction_error)?,
                original_headers: sqlx::Row::try_get(&row, "original_headers").map_err(transaction_error)?,
                final_upstream_headers: sqlx::Row::try_get(&row, "final_upstream_headers")
                    .map_err(transaction_error)?,
                upstream_response_headers: sqlx::Row::try_get(&row, "upstream_response_headers")
                    .map_err(transaction_error)?,
                original_request: sqlx::Row::try_get(&row, "original_request").map_err(transaction_error)?,
                policy_request: sqlx::Row::try_get(&row, "policy_request").map_err(transaction_error)?,
                final_upstream_request: sqlx::Row::try_get(&row, "final_upstream_request")
                    .map_err(transaction_error)?,
                upstream_response: sqlx::Row::try_get(&row, "upstream_response").map_err(transaction_error)?,
                upstream_response_final: sqlx::Row::try_get(&row, "upstream_response_final")
                    .map_err(transaction_error)?,
                captured_at: sqlx::Row::try_get(&row, "captured_at").map_err(transaction_error)?,
                body_digest_mismatch: sqlx::Row::try_get(&row, "body_digest_mismatch").map_err(transaction_error)?,
            })
        })
        .transpose()
    }

    pub async fn purge_expired_body_captures(&self, limit: i64) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM telemetry.request_body WHERE request_id IN (SELECT request_id FROM telemetry.request_body WHERE captured_at < clock_timestamp() - make_interval(days => COALESCE((SELECT (value #>> '{}')::int FROM ops.system_setting WHERE key='body_capture.retention_days'),7)) ORDER BY captured_at LIMIT $1)",
        )
        .bind(limit)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        Ok(result.rows_affected())
    }

    /// Reconcile stale non-terminal telemetry whose exact Group owner
    /// generation no longer exists. This is the crash/ACK-loss fallback for
    /// the normal single-transaction terminal path.
    pub async fn reconcile_stale_request_lifecycles(&self) -> Result<u64, StorageError> {
        let mut transaction = self.pool().begin().await.map_err(transaction_error)?;
        let rows = sqlx::query_scalar::<_, Uuid>(
            "SELECT r.request_id FROM telemetry.request_record r \
             LEFT JOIN gateway.credential_group g ON g.id=r.group_id \
             WHERE r.completed_at IS NULL AND r.created_at<clock_timestamp()-interval '10 minutes' \
               AND (g.owner_executor_id IS NULL OR g.owner_executor_id<>r.owner_executor_id \
                    OR g.owner_generation<>r.owner_generation) \
             ORDER BY r.created_at FOR UPDATE OF r SKIP LOCKED LIMIT 1000",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if rows.is_empty() {
            transaction.commit().await.map_err(transaction_error)?;
            return Ok(0);
        }
        sqlx::query(
            "UPDATE telemetry.response_delivery_record SET outcome_code='client_disconnected', \
               completed_at=clock_timestamp(),usage_observation_complete=false \
             WHERE request_id=ANY($1) AND completed_at IS NULL",
        )
        .bind(&rows)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        close_request_attempts(&mut transaction, &rows, "cancelled").await?;
        sqlx::query(
            "UPDATE telemetry.request_record SET phase_code='cancelled', \
               terminal_kind_code=CASE WHEN client_commit_state_code='committed' \
                 THEN 'cancelled_after_commit' ELSE 'cancelled_before_commit' END,completed_at=clock_timestamp() \
             WHERE request_id=ANY($1) AND completed_at IS NULL",
        )
        .bind(&rows)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)?;
        u64::try_from(rows.len()).map_err(|_| StorageError::TransactionFailed)
    }

    /// Persist the Request immediately after authentication and before scheduler admission.
    pub async fn create_request_after_auth(&self, record: &RequestCreate) -> Result<(), StorageError> {
        let result = sqlx::query(
            "WITH accepted AS (SELECT clock_timestamp() AS at), selected_price AS ( \
               SELECT p.id FROM catalog.price_entry p,accepted \
               WHERE p.model_id=$12 AND p.effective_from<=accepted.at \
                 AND (p.effective_to IS NULL OR p.effective_to>accepted.at) \
               ORDER BY p.effective_from DESC,p.price_version DESC LIMIT 1) \
             INSERT INTO telemetry.request_record \
             (request_month,request_id,platform_key_id,group_id,owner_executor_id,owner_generation,endpoint_code, \
              client_class_code,client_os_family,os_resolution_code,os_mismatch,unknown_os,model_id,price_entry_id, \
              phase_code,request_body_bytes,response_mode_code,client_commit_state_code,created_at) \
             SELECT date_trunc('month',accepted.at)::date,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,selected_price.id, \
                    'accepted',$13,$14,'uncommitted',accepted.at FROM accepted LEFT JOIN selected_price ON true",
        )
        .bind(record.request_id)
        .bind(record.platform_key_id)
        .bind(record.group_id)
        .bind(record.owner_executor_id.as_ref())
        .bind(record.owner_generation)
        .bind(record.endpoint_code.as_ref())
        .bind(record.client_class_code.as_ref())
        .bind(record.client_os.as_str())
        .bind(record.os_resolution.as_str())
        .bind(record.os_mismatch)
        .bind(matches!(
            record.os_resolution,
            OsResolution::SessionSticky | OsResolution::GroupDefault
        ))
        .bind(record.model_id)
        .bind(record.request_body_bytes)
        .bind(response_mode_code(record.response_mode))
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    /// Persist the exact southbound body digest before any upstream byte is written.
    /// Retries must reproduce the same body for the request.
    pub async fn record_upstream_body_digest(&self, request_id: Uuid, digest: &[u8; 32]) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE telemetry.request_record \
             SET upstream_body_digest=COALESCE(upstream_body_digest,$2) \
             WHERE request_id=$1 AND (upstream_body_digest IS NULL OR upstream_body_digest=$2)",
        )
        .bind(request_id)
        .bind(digest.as_slice())
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    /// Resolve the immutable model row selected by the validated request.
    pub async fn resolve_model_id(&self, upstream_model_id: &str) -> Result<Option<Uuid>, StorageError> {
        sqlx::query_scalar(
            "SELECT id FROM catalog.model_definition WHERE upstream_model_id=$1 AND provider_code='anthropic'",
        )
        .bind(upstream_model_id)
        .fetch_optional(&self.pool())
        .await
        .map_err(transaction_error)
    }

    /// Load the price that was effective when the request was accepted.
    pub async fn price_basis_for_request(
        &self,
        request_id: Uuid,
        model_id: Uuid,
    ) -> Result<Option<PriceBasis>, StorageError> {
        let row = sqlx::query(
            "SELECT p.id,p.input_per_million::text AS input_per_million, \
                    p.output_per_million::text AS output_per_million, \
                    p.cache_write_per_million::text AS cache_write_per_million, \
                    p.cache_read_per_million::text AS cache_read_per_million \
             FROM telemetry.request_record r JOIN catalog.price_entry p ON p.id=COALESCE( \
               r.price_entry_id,(SELECT fallback.id FROM catalog.price_entry fallback \
                 WHERE fallback.model_id=$2 AND fallback.effective_from<=r.created_at \
                   AND (fallback.effective_to IS NULL OR fallback.effective_to>r.created_at) \
                 ORDER BY fallback.effective_from DESC,fallback.price_version DESC LIMIT 1)) \
             WHERE r.request_id=$1 AND p.model_id=$2 LIMIT 1",
        )
        .bind(request_id)
        .bind(model_id)
        .fetch_optional(&self.pool())
        .await
        .map_err(transaction_error)?;
        row.map(|row| {
            Ok(PriceBasis {
                price_entry_id: sqlx::Row::try_get(&row, "id").map_err(transaction_error)?,
                snapshot: PriceSnapshot {
                    input_per_million_pico_usd: decimal_usd_to_pico(
                        &sqlx::Row::try_get::<String, _>(&row, "input_per_million").map_err(transaction_error)?,
                    )?,
                    output_per_million_pico_usd: decimal_usd_to_pico(
                        &sqlx::Row::try_get::<String, _>(&row, "output_per_million").map_err(transaction_error)?,
                    )?,
                    cache_creation_per_million_pico_usd: decimal_usd_to_pico(
                        &sqlx::Row::try_get::<String, _>(&row, "cache_write_per_million").map_err(transaction_error)?,
                    )?,
                    cache_read_per_million_pico_usd: decimal_usd_to_pico(
                        &sqlx::Row::try_get::<String, _>(&row, "cache_read_per_million").map_err(transaction_error)?,
                    )?,
                },
            })
        })
        .transpose()
    }

    /// Append captured subscription quota history and advance global current
    /// rows by `UUIDv7` observation order in one Credential-scoped transaction.
    #[allow(clippy::too_many_lines)]
    pub async fn persist_credential_quota_observations(
        &self,
        credential_id: Uuid,
        observations: &[QuotaObservationPersist],
    ) -> Result<Option<QuotaCurrentProjection>, StorageError> {
        if observations.is_empty() {
            return Ok(None);
        }
        let mut transaction = self.pool().begin().await.map_err(transaction_error)?;
        sqlx::query("SELECT id FROM gateway.anthropic_credential WHERE id=$1 FOR UPDATE")
            .bind(credential_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(transaction_error)?
            .ok_or(StorageError::RevisionConflict)?;
        for observation in observations {
            if !matches!(observation.window_kind_code.as_ref(), "five_hour" | "seven_day")
                || observation.utilization_nanos > 1_000_000_000
                || observation.header_digest.len() != 32
                || observation.parser_version.is_empty()
                || observation.parser_version.len() > 128
            {
                return Err(StorageError::TransactionFailed);
            }
            let reset_epoch =
                i64::try_from(observation.reset_epoch_seconds).map_err(|_| StorageError::TransactionFailed)?;
            let utilization = quota_nanos_decimal(observation.utilization_nanos);
            let inserted = sqlx::query(
                "INSERT INTO telemetry.credential_quota_observation \
                 (id,credential_id,window_kind_code,model_id,utilization,resets_at,source_code,observed_at, \
                  raw_redacted,confidence_code,header_digest,parser_version) \
                 VALUES ($1,$2,$3,NULL,CAST($4 AS numeric),to_timestamp($5),'header',clock_timestamp(), \
                         $6,'observed',$7,$8)",
            )
            .bind(observation.observation_id)
            .bind(credential_id)
            .bind(observation.window_kind_code.as_ref())
            .bind(&utilization)
            .bind(reset_epoch)
            .bind(serde_json::json!({
                "utilization_nanos": observation.utilization_nanos,
                "reset_epoch_seconds": observation.reset_epoch_seconds
            }))
            .bind(&observation.header_digest)
            .bind(observation.parser_version.as_ref())
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            require_single(inserted.rows_affected())?;
            sqlx::query(
                "INSERT INTO telemetry.credential_quota_current \
                 (credential_id,window_kind_code,model_id,observation_id,utilization,resets_at,observed_at, \
                  rate_limited_until,confidence_code) \
                 SELECT credential_id,window_kind_code,model_id,id,utilization,resets_at,observed_at, \
                        rate_limited_until,confidence_code \
                 FROM telemetry.credential_quota_observation WHERE id=$1 \
                 ON CONFLICT (credential_id,window_kind_code) WHERE model_id IS NULL DO UPDATE SET \
                   observation_id=EXCLUDED.observation_id,utilization=EXCLUDED.utilization, \
                   resets_at=EXCLUDED.resets_at,observed_at=EXCLUDED.observed_at, \
                   rate_limited_until=EXCLUDED.rate_limited_until,confidence_code=EXCLUDED.confidence_code \
                 WHERE EXCLUDED.observation_id>telemetry.credential_quota_current.observation_id",
            )
            .bind(observation.observation_id)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        }
        let rows = sqlx::query(
            "SELECT observation_id,LEAST(10000,CEIL(utilization*10000))::integer AS used_basis_points, \
                    CEIL(EXTRACT(EPOCH FROM GREATEST( \
                      COALESCE(rate_limited_until,resets_at)-clock_timestamp(),interval '0')))::bigint AS reset_after_seconds \
             FROM telemetry.credential_quota_current \
             WHERE credential_id=$1 AND model_id IS NULL AND confidence_code='observed' AND utilization IS NOT NULL \
               AND window_kind_code IN ('five_hour','seven_day') \
             ORDER BY utilization DESC,observation_id DESC",
        )
        .bind(credential_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let projection = if let Some(pressure) = rows.first() {
            let observation_version = rows
                .iter()
                .map(|row| sqlx::Row::try_get::<Uuid, _>(row, "observation_id").map_err(transaction_error))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .max_by_key(Uuid::as_u128)
                .ok_or(StorageError::TransactionFailed)?;
            Some(QuotaCurrentProjection {
                observation_version,
                used_basis_points: u16::try_from(
                    sqlx::Row::try_get::<i32, _>(pressure, "used_basis_points").map_err(transaction_error)?,
                )
                .map_err(|_| StorageError::TransactionFailed)?,
                reset_after: Duration::from_secs(
                    u64::try_from(
                        sqlx::Row::try_get::<i64, _>(pressure, "reset_after_seconds").map_err(transaction_error)?,
                    )
                    .map_err(|_| StorageError::TransactionFailed)?,
                ),
            })
        } else {
            None
        };
        transaction.commit().await.map_err(transaction_error)?;
        Ok(projection)
    }

    /// Compare-and-set one request phase. Stale writers receive a revision conflict.
    pub async fn advance_request_phase(
        &self,
        request_id: Uuid,
        expected: &str,
        next: &str,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE telemetry.request_record SET phase_code=$2, \
               queued_at=CASE WHEN $2='queued' THEN COALESCE(queued_at,clock_timestamp()) ELSE queued_at END, \
               first_submitted_at=CASE WHEN $2='submitting' THEN COALESCE(first_submitted_at,clock_timestamp()) ELSE first_submitted_at END \
             WHERE request_id=$1 AND phase_code=$3",
        )
        .bind(request_id)
        .bind(next)
        .bind(expected)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        Ok(())
    }

    /// Idempotently terminalize a request that never reached a client response
    /// commit. Cancellation/error guards use this as their durable fallback.
    pub async fn terminalize_uncommitted_request(
        &self,
        request_id: Uuid,
        terminal_kind: &str,
    ) -> Result<(), StorageError> {
        if !matches!(terminal_kind, "failed_before_commit" | "cancelled_before_commit") {
            return Err(StorageError::TransactionFailed);
        }
        let mut transaction = self.pool().begin().await.map_err(transaction_error)?;
        let request_ids = [request_id];
        close_request_attempts(
            &mut transaction,
            &request_ids,
            if terminal_kind == "cancelled_before_commit" {
                "cancelled"
            } else {
                "failed"
            },
        )
        .await?;
        sqlx::query(
            "UPDATE telemetry.request_record \
             SET phase_code=CASE WHEN $2='cancelled_before_commit' THEN 'cancelled' ELSE 'failed' END, \
                 terminal_kind_code=$2,completed_at=clock_timestamp() \
             WHERE request_id=$1 AND completed_at IS NULL AND client_commit_state_code='uncommitted'",
        )
        .bind(request_id)
        .bind(terminal_kind)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)
    }

    /// Arm a submission intent before any upstream request byte is written.
    pub async fn arm_submission_intent(&self, record: &SubmissionIntentArm) -> Result<(), StorageError> {
        let result = sqlx::query(
            "INSERT INTO telemetry.attempt_submission_intent \
             (id,request_month,request_id,ordinal,credential_id,token_version,profile_epoch,egress_epoch, \
              transport_bundle_id,generic_adjusted_request_hash,state_code,created_at,armed_at) \
             SELECT $1,request_month,request_id,$3,$4,$5,$6,$7,$8,$9,'armed',clock_timestamp(),clock_timestamp() \
             FROM telemetry.request_record WHERE request_id=$2",
        )
        .bind(record.intent_id)
        .bind(record.request_id)
        .bind(record.ordinal)
        .bind(record.credential_id)
        .bind(record.token_version)
        .bind(record.profile_epoch)
        .bind(record.egress_epoch)
        .bind(record.transport_bundle_id)
        .bind(&record.generic_adjusted_request_hash)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    /// Promote exactly once at the first upstream request byte.
    pub async fn promote_submission_intent(
        &self,
        intent_id: Uuid,
        request_bytes_written: i64,
    ) -> Result<(), StorageError> {
        if request_bytes_written <= 0 {
            return Err(StorageError::TransactionFailed);
        }
        let result = sqlx::query(
            "UPDATE telemetry.attempt_submission_intent \
             SET state_code='promoted',promoted_at=clock_timestamp(),request_bytes_written=$2 \
             WHERE id=$1 AND state_code='armed'",
        )
        .bind(intent_id)
        .bind(request_bytes_written)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        Ok(())
    }

    /// Create the single delivery record before client commit.
    pub async fn start_response_delivery(&self, record: &DeliveryStart) -> Result<(), StorageError> {
        let result = sqlx::query(
            "INSERT INTO telemetry.response_delivery_record \
             (id,request_month,request_id,attempt_id,streaming,response_committed,bytes_delivered,buffer_tier_code, \
              client_write_idle_ms) \
             SELECT $1,request_month,request_id,$3,$4,false,0,$5,$6 \
             FROM telemetry.request_record WHERE request_id=$2",
        )
        .bind(record.delivery_id)
        .bind(record.request_id)
        .bind(record.attempt_id)
        .bind(record.streaming)
        .bind(record.buffer_tier_code.as_deref())
        .bind(record.client_write_idle_ms)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    /// Atomically commit the client response headers and Request commit fence.
    pub async fn commit_client_response(&self, request_id: Uuid, delivery_id: Uuid) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(transaction_error)?;
        let delivery = sqlx::query(
            "UPDATE telemetry.response_delivery_record SET response_committed=true,first_byte_at=clock_timestamp() \
             WHERE id=$1 AND request_id=$2 AND completed_at IS NULL AND response_committed=false",
        )
        .bind(delivery_id)
        .bind(request_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let request = sqlx::query(
            "UPDATE telemetry.request_record SET phase_code='response_committed',client_commit_state_code='committed', \
              response_committed_at=clock_timestamp() \
             WHERE request_id=$1 AND completed_at IS NULL AND client_commit_state_code='uncommitted'",
        )
        .bind(request_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        require_single(delivery.rows_affected())?;
        require_single(request.rows_affected())?;
        transaction.commit().await.map_err(transaction_error)
    }

    /// Monotonically record how many encoded upstream body bytes reached the
    /// response observer. This may arrive before or after client delivery ends.
    pub async fn observe_delivery_upstream_bytes(
        &self,
        request_id: Uuid,
        delivery_id: Uuid,
        upstream_bytes_received: i64,
    ) -> Result<(), StorageError> {
        if upstream_bytes_received < 0 {
            return Err(StorageError::TransactionFailed);
        }
        let result = sqlx::query(
            "UPDATE telemetry.response_delivery_record \
             SET upstream_bytes_received=GREATEST(upstream_bytes_received,$3) \
             WHERE id=$1 AND request_id=$2",
        )
        .bind(delivery_id)
        .bind(request_id)
        .bind(upstream_bytes_received)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    /// Persist the delivery terminal without changing retry decisions.
    pub async fn complete_response_delivery(&self, record: &DeliveryComplete) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE telemetry.response_delivery_record SET outcome_code=$2,completed_at=clock_timestamp(), \
              response_committed=response_committed OR $3,upstream_bytes_received=GREATEST(upstream_bytes_received,$4),bytes_delivered=$5,peak_backpressure_bytes=$6, \
              spill_bytes=$7 WHERE id=$1 AND completed_at IS NULL",
        )
        .bind(record.delivery_id)
        .bind(delivery_outcome_code(record.outcome))
        .bind(record.response_committed)
        .bind(record.upstream_bytes_received)
        .bind(record.bytes_delivered)
        .bind(record.peak_backpressure_bytes)
        .bind(record.spill_bytes)
        .execute(&self.pool())
        .await
        .map_err(transaction_error)?;
        require_single(result.rows_affected())
    }

    /// Atomically close Delivery, Request and Attempt. Commit state is
    /// monotonic and the terminal classification is derived from the durable
    /// commit fence, so an ACK-loss retry cannot downgrade a committed response.
    pub async fn complete_request_lifecycle(&self, record: &RequestLifecycleComplete) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(transaction_error)?;
        let committed = sqlx::query_scalar::<_, bool>(
            "UPDATE telemetry.response_delivery_record SET outcome_code=$2,completed_at=clock_timestamp(), \
               response_committed=response_committed OR $3,upstream_bytes_received=GREATEST(upstream_bytes_received,$4),bytes_delivered=$5, \
               peak_backpressure_bytes=$6,spill_bytes=$7 \
             WHERE id=$1 AND completed_at IS NULL RETURNING response_committed",
        )
        .bind(record.delivery.delivery_id)
        .bind(delivery_outcome_code(record.delivery.outcome))
        .bind(record.delivery.response_committed)
        .bind(record.delivery.upstream_bytes_received)
        .bind(record.delivery.bytes_delivered)
        .bind(record.delivery.peak_backpressure_bytes)
        .bind(record.delivery.spill_bytes)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let committed = if let Some(value) = committed {
            value
        } else {
            sqlx::query_scalar("SELECT response_committed FROM telemetry.response_delivery_record WHERE id=$1")
                .bind(record.delivery.delivery_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(transaction_error)?
                .ok_or(StorageError::RevisionConflict)?
        };
        let complete = matches!(record.delivery.outcome, DeliveryOutcome::Complete);
        let cancelled = matches!(
            record.delivery.outcome,
            DeliveryOutcome::ClientDisconnected | DeliveryOutcome::CancelledBeforeCommit
        );
        let phase = if complete {
            "completed"
        } else if cancelled {
            "cancelled"
        } else {
            "failed"
        };
        let terminal = if complete {
            "completed"
        } else if cancelled && committed {
            "cancelled_after_commit"
        } else if cancelled {
            "cancelled_before_commit"
        } else if committed {
            "client_delivery_failed"
        } else {
            "failed_before_commit"
        };
        sqlx::query(
            "UPDATE telemetry.request_record SET phase_code=$2,terminal_kind_code=$3,response_body_bytes=$4, \
               completed_at=COALESCE(completed_at,clock_timestamp()) WHERE request_id=$1",
        )
        .bind(record.request_id)
        .bind(phase)
        .bind(terminal)
        .bind(record.delivery.bytes_delivered)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE telemetry.attempt_record SET state_code=$2,is_final=true, \
               completed_at=COALESCE(completed_at,clock_timestamp()) WHERE id=$1",
        )
        .bind(record.attempt_id)
        .bind(if complete {
            "completed"
        } else if cancelled {
            "cancelled"
        } else {
            "failed"
        })
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)
    }

    /// Append a usage fact and optionally elect it as the single final basis with its cost.
    #[allow(clippy::too_many_lines)]
    pub async fn append_usage(&self, record: &UsagePersist, cost: Option<&CostPersist>) -> Result<(), StorageError> {
        let mut transaction = self.pool().begin().await.map_err(transaction_error)?;
        sqlx::query("SELECT request_id FROM telemetry.request_record WHERE request_id=$1 FOR UPDATE")
            .bind(record.request_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(transaction_error)?
            .ok_or(StorageError::RevisionConflict)?;
        if let Some(attempt_id) = record.attempt_id {
            sqlx::query("SELECT id FROM telemetry.attempt_record WHERE id=$1 AND request_id=$2 FOR SHARE")
                .bind(attempt_id)
                .bind(record.request_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(transaction_error)?
                .ok_or(StorageError::RevisionConflict)?;
        }
        let counts = record.observation.counts;
        // A lost commit acknowledgement may replay the same official observation ID.
        // Validate its contents before accepting the retry; never append another cost basis.
        if record.observation.source == UsageSource::Official {
            let existing = sqlx::query("SELECT is_final_basis,attempt_id,model_id,source_code,completeness_code,input_tokens,output_tokens,cache_creation_input_tokens,cache_read_input_tokens FROM telemetry.usage_observation WHERE id=$1 AND request_id=$2")
                .bind(record.observation_id).bind(record.request_id).fetch_optional(&mut *transaction).await.map_err(transaction_error)?;
            if let Some(row) = existing {
                use sqlx::Row as _;
                let same = row
                    .try_get::<Option<Uuid>, _>("attempt_id")
                    .map_err(transaction_error)?
                    == record.attempt_id
                    && row.try_get::<Option<Uuid>, _>("model_id").map_err(transaction_error)? == record.model_id
                    && row.try_get::<String, _>("source_code").map_err(transaction_error)? == "official"
                    && row
                        .try_get::<String, _>("completeness_code")
                        .map_err(transaction_error)?
                        == usage_completeness_code(record.observation.completeness);
                let same_counts = [
                    ("input_tokens", counts.input_tokens),
                    ("output_tokens", counts.output_tokens),
                    ("cache_creation_input_tokens", counts.cache_creation_input_tokens),
                    ("cache_read_input_tokens", counts.cache_read_input_tokens),
                ]
                .into_iter()
                .all(|(name, value)| {
                    row.try_get::<Option<i64>, _>(name).ok() == Some(value.and_then(|v| i64::try_from(v).ok()))
                });
                if !same || !same_counts {
                    return Err(StorageError::RevisionConflict);
                }
                let selected: bool = row.try_get("is_final_basis").map_err(transaction_error)?;
                if let Some(cost) = cost {
                    persist_cost(&mut transaction, record, cost, selected).await?;
                }
                if selected {
                    refresh_usage_aggregates(&mut transaction, record, cost).await?;
                }
                return transaction.commit().await.map_err(transaction_error);
            }
        }
        let cancel = record.cancel_evidence.as_ref();
        let usage_row = sqlx::query(
            "INSERT INTO telemetry.usage_observation \
             (id,request_month,request_id,attempt_id,source_code,completeness_code,model_id,input_tokens,output_tokens, \
              cache_creation_input_tokens,cache_read_input_tokens,algorithm_version,observed_at,is_final_basis,selected_at, \
              selection_reason_code,input_basis_digest,sse_complete_event_ordinal,sse_content_event_ordinal, \
              sse_decoded_end_offset,sse_last_event_type,sse_gap) \
             SELECT $1,request_month,request_id,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp(),false,NULL,NULL, \
                    $12,$13,$14,$15,$16,$17 \
             FROM telemetry.request_record WHERE request_id=$2 \
             ON CONFLICT (request_month,request_id,attempt_id,source_code,algorithm_version) \
               WHERE source_code='cancel_estimate' DO UPDATE SET id=usage_observation.id \
               WHERE usage_observation.completeness_code=EXCLUDED.completeness_code \
                 AND usage_observation.model_id IS NOT DISTINCT FROM EXCLUDED.model_id \
                 AND usage_observation.input_tokens IS NOT DISTINCT FROM EXCLUDED.input_tokens \
                 AND usage_observation.output_tokens IS NOT DISTINCT FROM EXCLUDED.output_tokens \
                 AND usage_observation.cache_creation_input_tokens IS NOT DISTINCT FROM EXCLUDED.cache_creation_input_tokens \
                 AND usage_observation.cache_read_input_tokens IS NOT DISTINCT FROM EXCLUDED.cache_read_input_tokens \
                 AND usage_observation.input_basis_digest IS NOT DISTINCT FROM EXCLUDED.input_basis_digest \
                 AND usage_observation.sse_complete_event_ordinal IS NOT DISTINCT FROM EXCLUDED.sse_complete_event_ordinal \
                 AND usage_observation.sse_content_event_ordinal IS NOT DISTINCT FROM EXCLUDED.sse_content_event_ordinal \
                 AND usage_observation.sse_decoded_end_offset IS NOT DISTINCT FROM EXCLUDED.sse_decoded_end_offset \
                 AND usage_observation.sse_last_event_type IS NOT DISTINCT FROM EXCLUDED.sse_last_event_type \
                 AND usage_observation.sse_gap IS NOT DISTINCT FROM EXCLUDED.sse_gap \
             RETURNING id,is_final_basis",
        )
        .bind(record.observation_id)
        .bind(record.request_id)
        .bind(record.attempt_id)
        .bind(usage_source_code(record.observation.source))
        .bind(usage_completeness_code(record.observation.completeness))
        .bind(record.model_id)
        .bind(counts.input_tokens.and_then(|value| i64::try_from(value).ok()))
        .bind(counts.output_tokens.and_then(|value| i64::try_from(value).ok()))
        .bind(counts.cache_creation_input_tokens.and_then(|value| i64::try_from(value).ok()))
        .bind(counts.cache_read_input_tokens.and_then(|value| i64::try_from(value).ok()))
        .bind(record.observation.algorithm_version.as_deref())
        .bind(cancel.map(|value| value.input_basis_digest.as_slice()))
        .bind(cancel.and_then(|value| value.sse_complete_event_ordinal))
        .bind(cancel.and_then(|value| value.sse_content_event_ordinal))
        .bind(cancel.and_then(|value| value.sse_decoded_end_offset))
        .bind(cancel.and_then(|value| value.sse_last_event_type.as_deref()))
        .bind(cancel.and_then(|value| value.sse_gap))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::RevisionConflict)?;
        let canonical_observation_id: Uuid = sqlx::Row::try_get(&usage_row, "id").map_err(transaction_error)?;
        let canonical_is_final: bool = sqlx::Row::try_get(&usage_row, "is_final_basis").map_err(transaction_error)?;
        let mut canonical_record = record.clone();
        canonical_record.observation_id = canonical_observation_id;
        let canonical_cost = cost.cloned().map(|mut value| {
            value.usage_observation_id = canonical_observation_id;
            value
        });
        let record = &canonical_record;
        let cost = canonical_cost.as_ref();

        if !record.select_as_final {
            if let Some(cost) = cost {
                persist_cost(&mut transaction, record, cost, canonical_is_final).await?;
            }
            if canonical_is_final {
                refresh_usage_aggregates(&mut transaction, record, cost).await?;
            }
            return transaction.commit().await.map_err(transaction_error);
        }

        let current = sqlx::query(
            "SELECT id,source_code,completeness_code,input_tokens,output_tokens, \
                    cache_creation_input_tokens,cache_read_input_tokens \
             FROM telemetry.usage_observation \
              WHERE request_id=$1 AND is_final_basis FOR UPDATE",
        )
        .bind(record.request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if current
            .as_ref()
            .and_then(|row| sqlx::Row::try_get::<Uuid, _>(row, "id").ok())
            == Some(record.observation_id)
        {
            if let Some(cost) = cost {
                persist_cost(&mut transaction, record, cost, true).await?;
            }
            refresh_usage_aggregates(&mut transaction, record, cost).await?;
            return transaction.commit().await.map_err(transaction_error);
        }
        let new_rank = usage_basis_rank(record.observation.source, record.observation.completeness);
        let current_rank = current
            .as_ref()
            .map(|row| {
                usage_basis_rank_code(
                    sqlx::Row::try_get::<String, _>(row, "source_code")
                        .map_err(transaction_error)?
                        .as_str(),
                    sqlx::Row::try_get::<String, _>(row, "completeness_code")
                        .map_err(transaction_error)?
                        .as_str(),
                )
            })
            .transpose()?;
        let new_known_fields = [
            counts.input_tokens,
            counts.output_tokens,
            counts.cache_creation_input_tokens,
            counts.cache_read_input_tokens,
        ]
        .into_iter()
        .flatten()
        .count();
        let current_known_fields = current.as_ref().map(|row| {
            [
                sqlx::Row::try_get::<Option<i64>, _>(row, "input_tokens").ok().flatten(),
                sqlx::Row::try_get::<Option<i64>, _>(row, "output_tokens")
                    .ok()
                    .flatten(),
                sqlx::Row::try_get::<Option<i64>, _>(row, "cache_creation_input_tokens")
                    .ok()
                    .flatten(),
                sqlx::Row::try_get::<Option<i64>, _>(row, "cache_read_input_tokens")
                    .ok()
                    .flatten(),
            ]
            .into_iter()
            .flatten()
            .count()
        });
        if current_rank.is_some_and(|rank| rank > new_rank)
            || current_rank == Some(new_rank) && current_known_fields.is_some_and(|known| known >= new_known_fields)
        {
            if let Some(cost) = cost {
                persist_cost(&mut transaction, record, cost, false).await?;
            }
            return transaction.commit().await.map_err(transaction_error);
        }
        if let Some(current) = &current {
            let current_id: Uuid = sqlx::Row::try_get(current, "id").map_err(transaction_error)?;
            let demoted = sqlx::query(
                "UPDATE telemetry.usage_observation SET is_final_basis=false \
                 WHERE id=$1 AND request_id=$2 AND is_final_basis",
            )
            .bind(current_id)
            .bind(record.request_id)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            require_single(demoted.rows_affected())?;
        }
        sqlx::query("UPDATE telemetry.cost_estimate SET is_current=false WHERE request_id=$1 AND is_current")
            .bind(record.request_id)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        let promoted = sqlx::query(
            "UPDATE telemetry.usage_observation SET is_final_basis=true,selected_at=clock_timestamp(), \
                    selection_reason_code=$3 WHERE id=$1 AND request_id=$2 AND NOT is_final_basis",
        )
        .bind(record.observation_id)
        .bind(record.request_id)
        .bind(record.selection_reason_code.as_deref())
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        require_single(promoted.rows_affected())?;
        let completeness = usage_completeness_code(record.observation.completeness);
        sqlx::query("UPDATE telemetry.request_record SET usage_completeness_code=$2 WHERE request_id=$1")
            .bind(record.request_id)
            .bind(completeness)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        sqlx::query(
            "UPDATE telemetry.response_delivery_record SET usage_observation_complete=($2='complete') \
             WHERE request_id=$1",
        )
        .bind(record.request_id)
        .bind(completeness)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if let Some(cost) = cost {
            persist_cost(&mut transaction, record, cost, true).await?;
        }
        refresh_usage_aggregates(&mut transaction, record, cost).await?;
        transaction.commit().await.map_err(transaction_error)
    }
}

/// Build the final Anthropic message from a captured SSE event stream. Unknown
/// event types are ignored so newer upstream events do not make the snapshot
/// unreadable.
pub fn aggregate_sse_message(body: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(body)
        .ok()?
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    if !text.contains("data:") {
        return None;
    }
    let mut message: Option<serde_json::Map<String, Value>> = None;
    let mut blocks = Vec::<Value>::new();
    for event in text.split("\n\n") {
        let data = event
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        match value.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                if let Some(start) = value.get("message").and_then(Value::as_object) {
                    message = Some(start.clone());
                    if let Some(content) = message
                        .as_ref()
                        .and_then(|m| m.get("content"))
                        .and_then(Value::as_array)
                    {
                        blocks.clone_from(content);
                    }
                }
            }
            Some("content_block_start") => {
                if let Some(index) = value
                    .get("index")
                    .and_then(Value::as_u64)
                    .and_then(|v| usize::try_from(v).ok())
                {
                    if blocks.len() <= index {
                        blocks.resize(index + 1, Value::Object(serde_json::Map::new()));
                    }
                    if let Some(block) = value.get("content_block") {
                        blocks[index] = block.clone();
                    }
                }
            }
            Some("content_block_delta") => {
                let Some(index) = value
                    .get("index")
                    .and_then(Value::as_u64)
                    .and_then(|v| usize::try_from(v).ok())
                else {
                    continue;
                };
                if blocks.len() <= index {
                    blocks.resize(index + 1, Value::Object(serde_json::Map::new()));
                }
                let Some(delta) = value.get("delta").and_then(Value::as_object) else {
                    continue;
                };
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        let text = delta.get("text").and_then(Value::as_str).unwrap_or_default();
                        let block = blocks[index].as_object_mut()?;
                        let current = block.get("text").and_then(Value::as_str).unwrap_or_default();
                        block.insert("text".to_owned(), Value::String(format!("{current}{text}")));
                        block
                            .entry("type".to_owned())
                            .or_insert_with(|| Value::String("text".to_owned()));
                    }
                    Some("input_json_delta") => {
                        let piece = delta.get("partial_json").and_then(Value::as_str).unwrap_or_default();
                        let block = blocks[index].as_object_mut()?;
                        let current = block
                            .remove("_partial_json")
                            .and_then(|value| match value {
                                Value::String(text) => Some(text),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let combined = format!("{current}{piece}");
                        if let Ok(parsed) = serde_json::from_str::<Value>(&combined) {
                            block.insert("input".to_owned(), parsed);
                        } else {
                            block.insert("_partial_json".to_owned(), Value::String(combined));
                        }
                    }
                    Some("thinking_delta") => {
                        let text = delta.get("thinking").and_then(Value::as_str).unwrap_or_default();
                        let block = blocks[index].as_object_mut()?;
                        let current = block.get("thinking").and_then(Value::as_str).unwrap_or_default();
                        block.insert("thinking".to_owned(), Value::String(format!("{current}{text}")));
                        block
                            .entry("type".to_owned())
                            .or_insert_with(|| Value::String("thinking".to_owned()));
                    }
                    _ => {
                        if let Some(block) = blocks[index].as_object_mut() {
                            block.insert("delta".to_owned(), Value::Object(delta.clone()));
                        }
                    }
                }
            }
            Some("message_delta") => {
                if let Some(usage) = value.get("usage") {
                    let object = message.get_or_insert_with(serde_json::Map::new);
                    let target = object
                        .entry("usage")
                        .or_insert_with(|| Value::Object(serde_json::Map::new()));
                    if let Some(target) = target.as_object_mut()
                        && let Some(source) = usage.as_object()
                    {
                        target.extend(source.clone());
                    }
                }
                if let Some(delta) = value.get("delta") {
                    let object = message.get_or_insert_with(serde_json::Map::new);
                    if let Some(stop_reason) = delta.get("stop_reason") {
                        object.insert("stop_reason".to_owned(), stop_reason.clone());
                    }
                    if let Some(stop_sequence) = delta.get("stop_sequence") {
                        object.insert("stop_sequence".to_owned(), stop_sequence.clone());
                    }
                }
            }
            _ => {}
        }
    }
    let mut message = message?;
    message.insert("content".to_owned(), Value::Array(blocks));
    Some(Value::Object(message))
}

async fn close_request_attempts(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    request_ids: &[Uuid],
    terminal_state: &str,
) -> Result<(), StorageError> {
    if !matches!(terminal_state, "failed" | "cancelled") {
        return Err(StorageError::TransactionFailed);
    }
    sqlx::query(
        "UPDATE telemetry.attempt_submission_intent SET state_code='commit_unknown' \
         WHERE request_id=ANY($1) AND state_code='armed'",
    )
    .bind(request_ids)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    sqlx::query(
        "UPDATE telemetry.connection_attempt_record SET state_code='failed_before_first_byte',retry_safe=false, \
         completed_at=COALESCE(completed_at,clock_timestamp()) \
         WHERE request_id=ANY($1) AND state_code='planned'",
    )
    .bind(request_ids)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    sqlx::query("UPDATE telemetry.attempt_record SET is_final=false WHERE request_id=ANY($1) AND is_final")
        .bind(request_ids)
        .execute(&mut **transaction)
        .await
        .map_err(transaction_error)?;
    sqlx::query(
        "UPDATE telemetry.attempt_record SET state_code=$2,completed_at=COALESCE(completed_at,clock_timestamp()) \
         WHERE request_id=ANY($1) AND completed_at IS NULL",
    )
    .bind(request_ids)
    .bind(terminal_state)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    sqlx::query(
        "WITH selected AS ( \
           SELECT DISTINCT ON (request_id) id FROM telemetry.attempt_record \
           WHERE request_id=ANY($1) ORDER BY request_id,ordinal DESC,submitted_at DESC NULLS LAST,id DESC \
         ) \
         UPDATE telemetry.attempt_record a SET is_final=true FROM selected s WHERE a.id=s.id",
    )
    .bind(request_ids)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct UsageAggregateKey {
    hour_epoch: i64,
    bucket_day: String,
    platform_key_id: Uuid,
    group_id: Uuid,
    credential_id: Uuid,
    model_id: Uuid,
}

async fn refresh_usage_aggregates(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    usage: &UsagePersist,
    cost: Option<&CostPersist>,
) -> Result<(), StorageError> {
    let Some(attempt_id) = usage.attempt_id else {
        return Ok(());
    };
    let current = sqlx::query(
        "SELECT EXTRACT(EPOCH FROM date_trunc('hour',r.created_at))::bigint AS hour_epoch, \
                r.created_at::date::text AS bucket_day,r.platform_key_id,r.group_id,a.credential_id, \
                COALESCE($3,r.model_id) AS model_id,r.request_month::text AS request_month \
         FROM telemetry.request_record r JOIN telemetry.attempt_record a ON a.id=$2 AND a.request_id=r.request_id \
         WHERE r.request_id=$1",
    )
    .bind(usage.request_id)
    .bind(attempt_id)
    .bind(usage.model_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    let current = current.ok_or(StorageError::RevisionConflict)?;
    let model_id: Option<Uuid> = sqlx::Row::try_get(&current, "model_id").map_err(transaction_error)?;
    let Some(model_id) = model_id else {
        return Ok(());
    };
    let current_key = UsageAggregateKey {
        hour_epoch: sqlx::Row::try_get(&current, "hour_epoch").map_err(transaction_error)?,
        bucket_day: sqlx::Row::try_get(&current, "bucket_day").map_err(transaction_error)?,
        platform_key_id: sqlx::Row::try_get(&current, "platform_key_id").map_err(transaction_error)?,
        group_id: sqlx::Row::try_get(&current, "group_id").map_err(transaction_error)?,
        credential_id: sqlx::Row::try_get(&current, "credential_id").map_err(transaction_error)?,
        model_id,
    };
    let request_month: String = sqlx::Row::try_get(&current, "request_month").map_err(transaction_error)?;
    let previous = sqlx::query(
        "SELECT EXTRACT(EPOCH FROM bucket_start)::bigint AS hour_epoch,bucket_day::text AS bucket_day, \
                platform_key_id,group_id,credential_id,model_id \
         FROM telemetry.usage_aggregate_contribution WHERE request_id=$1 FOR UPDATE",
    )
    .bind(usage.request_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(transaction_error)?
    .map(|row| {
        Ok::<_, StorageError>(UsageAggregateKey {
            hour_epoch: sqlx::Row::try_get(&row, "hour_epoch").map_err(transaction_error)?,
            bucket_day: sqlx::Row::try_get(&row, "bucket_day").map_err(transaction_error)?,
            platform_key_id: sqlx::Row::try_get(&row, "platform_key_id").map_err(transaction_error)?,
            group_id: sqlx::Row::try_get(&row, "group_id").map_err(transaction_error)?,
            credential_id: sqlx::Row::try_get(&row, "credential_id").map_err(transaction_error)?,
            model_id: sqlx::Row::try_get(&row, "model_id").map_err(transaction_error)?,
        })
    })
    .transpose()?;
    let mut keys = vec![current_key.clone()];
    if let Some(previous) = previous
        && previous != current_key
    {
        keys.push(previous);
    }
    keys.sort();
    keys.dedup();
    for key in &keys {
        let lock_key = format!(
            "usage:{}:{}:{}:{}:{}:{}",
            key.hour_epoch, key.bucket_day, key.platform_key_id, key.group_id, key.credential_id, key.model_id
        );
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(lock_key)
            .execute(&mut **transaction)
            .await
            .map_err(transaction_error)?;
    }
    let counts = usage.observation.counts;
    sqlx::query(
        "INSERT INTO telemetry.usage_aggregate_contribution \
         (request_month,request_id,bucket_start,bucket_day,platform_key_id,group_id,credential_id,model_id, \
          input_tokens,output_tokens,estimated_amount,completeness_code,updated_at) \
         VALUES ($1::date,$2,to_timestamp($3),$4::date,$5,$6,$7,$8,$9,$10,CAST($11 AS numeric),$12,clock_timestamp()) \
         ON CONFLICT (request_month,request_id) DO UPDATE SET \
          bucket_start=EXCLUDED.bucket_start,bucket_day=EXCLUDED.bucket_day,platform_key_id=EXCLUDED.platform_key_id, \
          group_id=EXCLUDED.group_id,credential_id=EXCLUDED.credential_id,model_id=EXCLUDED.model_id, \
          input_tokens=EXCLUDED.input_tokens,output_tokens=EXCLUDED.output_tokens, \
          estimated_amount=EXCLUDED.estimated_amount,completeness_code=EXCLUDED.completeness_code,updated_at=clock_timestamp()",
    )
    .bind(request_month)
    .bind(usage.request_id)
    .bind(current_key.hour_epoch)
    .bind(&current_key.bucket_day)
    .bind(current_key.platform_key_id)
    .bind(current_key.group_id)
    .bind(current_key.credential_id)
    .bind(current_key.model_id)
    .bind(counts.input_tokens.and_then(|value| i64::try_from(value).ok()))
    .bind(counts.output_tokens.and_then(|value| i64::try_from(value).ok()))
    .bind(cost.and_then(|value| value.estimate.amount_usd.as_deref()))
    .bind(usage_completeness_code(usage.observation.completeness))
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    for key in &keys {
        rebuild_usage_aggregate_key(transaction, key).await?;
    }
    Ok(())
}

async fn rebuild_usage_aggregate_key(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    key: &UsageAggregateKey,
) -> Result<(), StorageError> {
    sqlx::query(
        "DELETE FROM telemetry.usage_hourly WHERE bucket_start=to_timestamp($1) AND platform_key_id=$2 \
         AND group_id=$3 AND credential_id=$4 AND model_id=$5",
    )
    .bind(key.hour_epoch)
    .bind(key.platform_key_id)
    .bind(key.group_id)
    .bind(key.credential_id)
    .bind(key.model_id)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    sqlx::query(
        "INSERT INTO telemetry.usage_hourly \
         (bucket_start,platform_key_id,group_id,credential_id,model_id,request_count,input_tokens,output_tokens, \
          estimated_amount,completeness_code,updated_at) \
         SELECT to_timestamp($1),$2,$3,$4,$5,count(*),SUM(input_tokens),SUM(output_tokens),SUM(estimated_amount), \
          CASE WHEN BOOL_OR(completeness_code='unknown') THEN 'unknown' \
               WHEN BOOL_OR(completeness_code='partial') THEN 'partial' ELSE 'complete' END,clock_timestamp() \
         FROM telemetry.usage_aggregate_contribution WHERE bucket_start=to_timestamp($1) AND platform_key_id=$2 \
          AND group_id=$3 AND credential_id=$4 AND model_id=$5 HAVING count(*)>0",
    )
    .bind(key.hour_epoch)
    .bind(key.platform_key_id)
    .bind(key.group_id)
    .bind(key.credential_id)
    .bind(key.model_id)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    sqlx::query(
        "DELETE FROM telemetry.usage_daily WHERE bucket_day=$1::date AND platform_key_id=$2 \
         AND group_id=$3 AND credential_id=$4 AND model_id=$5",
    )
    .bind(&key.bucket_day)
    .bind(key.platform_key_id)
    .bind(key.group_id)
    .bind(key.credential_id)
    .bind(key.model_id)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    sqlx::query(
        "INSERT INTO telemetry.usage_daily \
         (bucket_day,platform_key_id,group_id,credential_id,model_id,request_count,input_tokens,output_tokens, \
          estimated_amount,completeness_code,updated_at) \
         SELECT $1::date,$2,$3,$4,$5,count(*),SUM(input_tokens),SUM(output_tokens),SUM(estimated_amount), \
          CASE WHEN BOOL_OR(completeness_code='unknown') THEN 'unknown' \
               WHEN BOOL_OR(completeness_code='partial') THEN 'partial' ELSE 'complete' END,clock_timestamp() \
         FROM telemetry.usage_aggregate_contribution WHERE bucket_day=$1::date AND platform_key_id=$2 \
          AND group_id=$3 AND credential_id=$4 AND model_id=$5 HAVING count(*)>0",
    )
    .bind(&key.bucket_day)
    .bind(key.platform_key_id)
    .bind(key.group_id)
    .bind(key.credential_id)
    .bind(key.model_id)
    .execute(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    Ok(())
}

async fn persist_cost(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    usage: &UsagePersist,
    cost: &CostPersist,
    is_current: bool,
) -> Result<(), StorageError> {
    if cost.usage_observation_id != usage.observation_id {
        return Err(StorageError::TransactionFailed);
    }
    let snapshot: Value = serde_json::to_value(cost.price_snapshot).map_err(|_| StorageError::TransactionFailed)?;
    let result = sqlx::query(
        "INSERT INTO telemetry.cost_estimate \
         (id,request_month,request_id,usage_observation_id,price_entry_id,price_snapshot,usage_completeness_code, \
          algorithm_version,amount,currency_code,is_current,calculated_at,amount_pico_usd,known_field_mask) \
         SELECT $1,request_month,request_id,$3,$4,$5,$6,$7,CAST($8 AS numeric),'USD',$11,clock_timestamp(), \
                CAST($9 AS numeric),$10 FROM telemetry.request_record WHERE request_id=$2 \
         ON CONFLICT (usage_observation_id) DO UPDATE SET is_current=EXCLUDED.is_current \
          WHERE cost_estimate.price_entry_id IS NOT DISTINCT FROM EXCLUDED.price_entry_id \
            AND cost_estimate.price_snapshot=EXCLUDED.price_snapshot \
            AND cost_estimate.usage_completeness_code=EXCLUDED.usage_completeness_code \
            AND cost_estimate.algorithm_version=EXCLUDED.algorithm_version \
            AND cost_estimate.amount IS NOT DISTINCT FROM EXCLUDED.amount \
            AND cost_estimate.currency_code=EXCLUDED.currency_code \
            AND cost_estimate.amount_pico_usd IS NOT DISTINCT FROM EXCLUDED.amount_pico_usd \
            AND cost_estimate.known_field_mask=EXCLUDED.known_field_mask \
         RETURNING id",
    )
    .bind(cost.cost_id)
    .bind(usage.request_id)
    .bind(cost.usage_observation_id)
    .bind(cost.price_entry_id)
    .bind(snapshot)
    .bind(usage_completeness_code(cost.estimate.usage_completeness))
    .bind(cost.estimate.algorithm_version.as_ref())
    .bind(cost.estimate.amount_usd.as_deref())
    .bind(cost.amount_pico_usd.as_deref())
    .bind(cost.known_field_mask)
    .bind(is_current)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(transaction_error)?;
    result.map_or(Err(StorageError::RevisionConflict), |_| Ok(()))
}

fn require_single(rows: u64) -> Result<(), StorageError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(StorageError::RevisionConflict)
    }
}

const fn response_mode_code(value: ResponseMode) -> &'static str {
    match value {
        ResponseMode::Streaming => "streaming",
        ResponseMode::NonStreaming => "non_streaming",
    }
}

const fn delivery_outcome_code(value: DeliveryOutcome) -> &'static str {
    match value {
        DeliveryOutcome::Complete => "complete",
        DeliveryOutcome::ClientDisconnected => "client_disconnected",
        DeliveryOutcome::ClientWriteTimeout => "client_write_timeout",
        DeliveryOutcome::UpstreamBodyError => "upstream_body_error",
        DeliveryOutcome::BufferRejected => "buffer_rejected",
        DeliveryOutcome::CancelledBeforeCommit => "cancelled_before_commit",
    }
}

const fn usage_source_code(value: UsageSource) -> &'static str {
    match value {
        UsageSource::Official => "official",
        UsageSource::LocalEstimate => "local_estimate",
        UsageSource::ConsoleCount => "console_count",
        UsageSource::CancelEstimate => "cancel_estimate",
    }
}

const fn usage_completeness_code(value: UsageCompleteness) -> &'static str {
    match value {
        UsageCompleteness::Unknown => "unknown",
        UsageCompleteness::Partial => "partial",
        UsageCompleteness::Complete => "complete",
    }
}

const fn usage_basis_rank(source: UsageSource, completeness: UsageCompleteness) -> (u8, u8, u8) {
    let known = if matches!(completeness, UsageCompleteness::Unknown) {
        0
    } else {
        1
    };
    let source = match source {
        UsageSource::Official => 4,
        UsageSource::ConsoleCount => 3,
        UsageSource::LocalEstimate => 2,
        UsageSource::CancelEstimate => 1,
    };
    let completeness = match completeness {
        UsageCompleteness::Complete => 3,
        UsageCompleteness::Partial => 2,
        UsageCompleteness::Unknown => 1,
    };
    (known, source, completeness)
}

fn usage_basis_rank_code(source: &str, completeness: &str) -> Result<(u8, u8, u8), StorageError> {
    let source = match source {
        "official" => 4,
        "console_count" => 3,
        "local_estimate" => 2,
        "cancel_estimate" => 1,
        _ => return Err(StorageError::TransactionFailed),
    };
    let completeness = match completeness {
        "complete" => 3,
        "partial" => 2,
        "unknown" => 1,
        _ => return Err(StorageError::TransactionFailed),
    };
    let known = u8::from(completeness > 1);
    Ok((known, source, completeness))
}

fn decimal_usd_to_pico(value: &str) -> Result<u128, StorageError> {
    const SCALE: u128 = 1_000_000_000_000;
    let (whole, fractional) = value.split_once('.').map_or((value, ""), |parts| parts);
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.len() > 12
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(StorageError::TransactionFailed);
    }
    let whole = whole
        .parse::<u128>()
        .map_err(|_| StorageError::TransactionFailed)?
        .checked_mul(SCALE)
        .ok_or(StorageError::TransactionFailed)?;
    let fractional = if fractional.is_empty() {
        0
    } else {
        fractional
            .parse::<u128>()
            .map_err(|_| StorageError::TransactionFailed)?
            .checked_mul(
                10_u128.pow(u32::try_from(12 - fractional.len()).map_err(|_| StorageError::TransactionFailed)?),
            )
            .ok_or(StorageError::TransactionFailed)?
    };
    whole.checked_add(fractional).ok_or(StorageError::TransactionFailed)
}

fn quota_nanos_decimal(value: u32) -> String {
    if value == 1_000_000_000 {
        "1.000000000".to_owned()
    } else {
        format!("0.{value:09}")
    }
}

fn transaction_error(error: sqlx::Error) -> StorageError {
    match error {
        sqlx::Error::Database(database) => {
            tracing::error!(
                database_code = database.code().as_deref().unwrap_or("unknown"),
                constraint = database.constraint().unwrap_or("unknown"),
                "sanitized telemetry persistence failure"
            );
        }
        other => {
            tracing::error!(error_kind = ?std::mem::discriminant(&other), "sanitized telemetry adapter failure");
        }
    }
    StorageError::TransactionFailed
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "SSE fixtures must aggregate successfully")]
mod tests {
    use gateway_domain::{UsageCompleteness, UsageSource};

    use super::{aggregate_sse_message, decimal_usd_to_pico, quota_nanos_decimal, usage_basis_rank};

    #[test]
    fn reasoning_metadata_supports_both_providers_without_body_capture() {
        for (body, expected) in [
            (r#"{"reasoning":{"effort":"high"}}"#, Some("high")),
            (r#"{"reasoning_effort":"low"}"#, Some("low")),
            (
                r#"{"output_config":{"effort":"max"},"thinking":{"type":"adaptive"}}"#,
                Some("max"),
            ),
            (r#"{"thinking":{"type":"adaptive"}}"#, Some("adaptive")),
            (
                r#"{"thinking":{"type":"enabled","budget_tokens":4096}}"#,
                Some("budget:4096"),
            ),
            (r#"{"thinking":{"type":"disabled"}}"#, Some("disabled")),
            (r#"{"messages":[]}"#, None),
            (r#"{"reasoning":{"effort":42}}"#, None),
        ] {
            assert_eq!(super::request_reasoning_effort(body.as_bytes()).as_deref(), expected);
        }
    }

    #[test]
    fn request_capture_is_opt_in_and_bounded_per_stage() {
        let small = br#"{"model":"test"}"#;
        assert!(super::BodyCaptureConfig::default().request_json(small).is_none());
        let config = super::BodyCaptureConfig {
            enabled: true,
            max_bytes: small.len(),
            ..Default::default()
        };
        assert!(config.request_json(small).is_some());
        assert!(config.request_json(br#"{"model":"oversized"}"#).is_none());
        assert!(config.request_json(b"invalid").is_none());
        // A skipped stage must not prevent a later smaller stage from being captured.
        assert!(config.request_json(small).is_some());
    }

    #[test]
    fn catalog_prices_convert_to_pico_usd_exactly() {
        assert!(matches!(decimal_usd_to_pico("3.000000000000"), Ok(3_000_000_000_000)));
        assert!(matches!(decimal_usd_to_pico("0.000000000001"), Ok(1)));
        assert!(decimal_usd_to_pico("0.0000000000001").is_err());
        assert!(decimal_usd_to_pico("-1").is_err());
    }

    #[test]
    fn quota_utilization_is_persisted_as_fixed_decimal() {
        assert_eq!(quota_nanos_decimal(0), "0.000000000");
        assert_eq!(quota_nanos_decimal(950_000_001), "0.950000001");
        assert_eq!(quota_nanos_decimal(1_000_000_000), "1.000000000");
    }

    #[test]
    fn known_cancel_estimate_outranks_unknown_official_usage() {
        assert!(
            usage_basis_rank(UsageSource::CancelEstimate, UsageCompleteness::Partial)
                > usage_basis_rank(UsageSource::Official, UsageCompleteness::Unknown)
        );
        assert!(
            usage_basis_rank(UsageSource::Official, UsageCompleteness::Partial)
                > usage_basis_rank(UsageSource::CancelEstimate, UsageCompleteness::Partial)
        );
    }

    #[test]
    fn sse_events_are_aggregated_into_a_final_message() {
        let body = br#"event: message_start
data: {"type":"message_start","message":{"id":"msg_1","role":"assistant","content":[],"usage":{"input_tokens":7}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}

event: message_stop
data: {"type":"message_stop"}

"#;
        let message = aggregate_sse_message(body).expect("aggregated message");
        assert_eq!(message["id"], "msg_1");
        assert_eq!(message["content"][0]["text"], "hello");
        assert_eq!(message["usage"]["output_tokens"], 3);
    }

    #[test]
    fn sse_tool_and_thinking_deltas_are_accumulated() {
        let body = br#"event: message_start
data: {"type":"message_start","message":{"id":"msg_2","role":"assistant","content":[]}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"plan"}}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"x","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":"}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"1}"}}

"#;
        let message = aggregate_sse_message(body).expect("aggregated message");
        assert_eq!(message["content"][0]["thinking"], "plan");
        assert_eq!(message["content"][1]["input"]["a"], 1);
    }
}
