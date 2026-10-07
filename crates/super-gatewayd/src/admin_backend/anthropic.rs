//! `Anthropic` management operations, using the shared authorization boundary.
use super::*;

const ANTHROPIC_USAGE_HOST: &str = "api.anthropic.com";
const ANTHROPIC_USAGE_PATH: &str = "/api/oauth/usage";
const ANTHROPIC_USAGE_BETA: &str = "oauth-2025-04-20";
const ANTHROPIC_USAGE_USER_AGENT: &str = "claude-code/2.1.7";
const USAGE_PROBE_PARSER_VERSION: &str = "anthropic_usage_probe_v1";

impl PgManagementBackend {
    pub(super) async fn probe_credential_usage(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let id = path_uuid(request, "id")?;
        let revision = request_revision(request)?;
        self.probe_credential_usage_internal(Some(principal), id, revision)
            .await
    }

    /// Fetch the official `/api/oauth/usage` windows for a subscription OAuth
    /// credential through its bound egress and persist them as quota
    /// observations. `principal=None` marks the periodic maintenance caller.
    pub(super) async fn probe_credential_usage_internal(
        &self,
        _principal: Option<&ManagementPrincipal>,
        id: Uuid,
        revision: i64,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        use gateway_domain::{EgressRouteSnapshot, Socks5DnsMode};
        use gateway_transport::{
            ProviderHttpsClient, ProviderHttpsHeader, ProviderHttpsRequest, ProviderHttpsTimeouts,
        };
        let row = sqlx::query(
            "SELECT c.auth_kind_code,c.lifecycle_state_code,av.access_secret_id, \
                    b.mode_code AS egress_mode,p.host,p.port,p.auth_secret_id,p.proxy_type_code, \
                    p.lifecycle_code AS proxy_lifecycle \
             FROM gateway.anthropic_credential c \
             JOIN gateway.credential_auth_version av ON av.credential_id=c.id AND av.token_version=c.token_version \
             LEFT JOIN gateway.credential_egress_binding b ON b.credential_id=c.id AND b.lifecycle_code='active' \
             LEFT JOIN gateway.proxy_endpoint p ON p.id=b.proxy_id \
             WHERE c.id=$1 AND c.revision=$2",
        )
        .bind(id)
        .bind(revision)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        if required::<String>(&row, "auth_kind_code")? != "oauth_subscription"
            || required::<String>(&row, "lifecycle_state_code")? != "active"
        {
            return Err(ManagementBackendError::Precondition);
        }
        let egress = if required::<Option<String>>(&row, "egress_mode")?.as_deref() == Some("proxy") {
            if required::<Option<String>>(&row, "proxy_lifecycle")?.as_deref() != Some("active") {
                return Err(ManagementBackendError::Precondition);
            }
            let credentials = if let Some(secret_id) = required::<Option<Uuid>>(&row, "auth_secret_id")? {
                let secret = crate::production_dispatcher::decrypt_secret(&self.storage, secret_id)
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?;
                Some(Arc::new(
                    crate::production_dispatcher::parse_proxy_credentials(&secret)
                        .map_err(|_| ManagementBackendError::Precondition)?,
                ))
            } else {
                None
            };
            let host = required::<String>(&row, "host")?.into_boxed_str();
            let port =
                u16::try_from(required::<i32>(&row, "port")?).map_err(|_| ManagementBackendError::Precondition)?;
            match required::<String>(&row, "proxy_type_code")?.as_str() {
                "connect" => EgressRouteSnapshot::HttpConnect {
                    host,
                    port,
                    credentials,
                },
                "socks5" => EgressRouteSnapshot::Socks5 {
                    host,
                    port,
                    credentials,
                    dns: Socks5DnsMode::Remote,
                },
                _ => return Err(ManagementBackendError::Precondition),
            }
        } else {
            EgressRouteSnapshot::Direct
        };
        let token = crate::production_dispatcher::decrypt_secret(&self.storage, required(&row, "access_secret_id")?)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut bearer = b"Bearer ".to_vec();
        bearer.extend_from_slice(token.expose());
        let headers = vec![
            ProviderHttpsHeader {
                name: "authorization",
                value: SecretBytes::new(bearer),
            },
            ProviderHttpsHeader {
                name: "anthropic-beta",
                value: SecretBytes::new(ANTHROPIC_USAGE_BETA.as_bytes().to_vec()),
            },
            ProviderHttpsHeader {
                name: "user-agent",
                value: SecretBytes::new(ANTHROPIC_USAGE_USER_AGENT.as_bytes().to_vec()),
            },
        ];
        let client = ProviderHttpsClient::new(ProviderHttpsTimeouts {
            connect: std::time::Duration::from_secs(10),
            tls: std::time::Duration::from_secs(10),
            write: std::time::Duration::from_secs(10),
            response: std::time::Duration::from_secs(30),
        });
        let response = client
            .execute(ProviderHttpsRequest {
                method: http::Method::GET,
                host: ANTHROPIC_USAGE_HOST.into(),
                port: 443,
                host_header: ANTHROPIC_USAGE_HOST.into(),
                path_and_query: SecretValue::new(ANTHROPIC_USAGE_PATH.into()),
                headers,
                body: SecretBytes::new(Vec::new()),
                response_limit: 1024 * 1024,
                egress,
                cancellation: tokio_util::sync::CancellationToken::new(),
            })
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if response.status != 200 {
            return Err(ManagementBackendError::Precondition);
        }
        let document: Value =
            serde_json::from_slice(response.body.expose()).map_err(|_| ManagementBackendError::Precondition)?;
        let windows = parse_usage_windows(&document)?;
        let header_digest: Vec<u8> = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(response.body.expose());
            hasher.finalize().to_vec()
        };
        let observations = windows
            .iter()
            .map(
                |(kind, utilization_nanos, reset_epoch_seconds)| gateway_storage::QuotaObservationPersist {
                    observation_id: Uuid::now_v7(),
                    window_kind_code: (*kind).into(),
                    utilization_nanos: *utilization_nanos,
                    reset_epoch_seconds: *reset_epoch_seconds,
                    header_digest: header_digest.clone(),
                    parser_version: USAGE_PROBE_PARSER_VERSION.into(),
                },
            )
            .collect::<Vec<_>>();
        self.storage
            .persist_credential_quota_observations(id, &observations)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let windows_json = document
            .as_object()
            .map(|entries| {
                Value::Object(
                    entries
                        .iter()
                        .filter(|(key, _)| key.ends_with("hour") || key.ends_with("day"))
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                )
            })
            .unwrap_or_else(|| json!({}));
        Ok(single_response(
            &json!({"id":id,"windows":windows_json,"windows_persisted":windows.len()}),
            revision,
        ))
    }

    /// Periodic staleness probe: refresh official usage windows for active
    /// subscription OAuth credentials whose five-hour observation went stale.
    pub(crate) fn spawn_credential_usage_probe(
        self: Arc<Self>,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let cancel = cancel.child_token();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(std::time::Duration::from_mins(5)) => {}
                }
                let rows = sqlx::query(
                    "SELECT c.id,c.revision FROM gateway.anthropic_credential c \
                     WHERE c.lifecycle_state_code='active' AND c.auth_kind_code='oauth_subscription' \
                       AND (c.cooldown_until IS NULL OR c.cooldown_until<=clock_timestamp()) \
                       AND NOT EXISTS ( \
                         SELECT 1 FROM telemetry.credential_quota_current q \
                         WHERE q.credential_id=c.id AND q.window_kind_code='five_hour' \
                           AND q.observed_at>=clock_timestamp()-interval '15 minutes') \
                     ORDER BY c.id LIMIT 4",
                )
                .fetch_all(&self.storage.pool())
                .await
                .unwrap_or_default();
                for row in rows {
                    let (Ok(id), Ok(revision)) = (row.try_get::<Uuid, _>("id"), row.try_get::<i64, _>("revision"))
                    else {
                        continue;
                    };
                    if cancel.is_cancelled() {
                        return;
                    }
                    // A concurrent revision bump (cooldown, config edit) simply skips this cycle.
                    let _ = self.probe_credential_usage_internal(None, id, revision).await;
                }
            }
        })
    }
}

/// Extract the `five_hour`/`seven_day` windows from the usage document.
/// `seven_day_sonnet` and other model-scoped windows need a `model_id` to
/// persist and are reported but not recorded here.
fn parse_usage_windows(document: &Value) -> Result<Vec<(&'static str, u32, u64)>, ManagementBackendError> {
    let mut windows = Vec::new();
    for (key, kind) in [("five_hour", "five_hour"), ("seven_day", "seven_day")] {
        let window = document.get(key).ok_or(ManagementBackendError::Precondition)?;
        let utilization = window
            .get("utilization")
            .and_then(Value::as_f64)
            .ok_or(ManagementBackendError::Precondition)?;
        if !(0.0..=1.0).contains(&utilization) {
            return Err(ManagementBackendError::Precondition);
        }
        // Range is validated above; the float is a whole number within u32 span here.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let utilization_nanos = (utilization * 1_000_000_000.0).round() as u32;
        let reset_text = window
            .get("resets_at")
            .and_then(Value::as_str)
            .ok_or(ManagementBackendError::Precondition)?;
        let reset_epoch_seconds =
            parse_rfc3339_epoch_seconds(reset_text).ok_or(ManagementBackendError::Precondition)?;
        windows.push((kind, utilization_nanos, reset_epoch_seconds));
    }
    Ok(windows)
}

/// Minimal RFC 3339 parser (`2026-10-04T12:34:56[.fff][Z|±HH:MM]`) producing
/// Unix seconds; the workspace carries no date-time library.
fn parse_rfc3339_epoch_seconds(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let year: i64 = text.get(0..4)?.parse().ok()?;
    if bytes[4] != b'-' || bytes[7] != b'-' || (bytes[10] != b'T' && bytes[10] != b't') {
        return None;
    }
    let month: i64 = text.get(5..7)?.parse().ok()?;
    let day: i64 = text.get(8..10)?.parse().ok()?;
    let hour: i64 = text.get(11..13)?.parse().ok()?;
    if bytes[13] != b':' {
        return None;
    }
    let minute: i64 = text.get(14..16)?.parse().ok()?;
    if bytes[16] != b':' {
        return None;
    }
    let second: i64 = text.get(17..19)?.parse().ok()?;
    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        let start = index + 1;
        let mut end = start;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start {
            return None;
        }
        index = end;
    }
    let mut offset_seconds: i64 = 0;
    match bytes.get(index) {
        Some(b'Z' | b'z') => {}
        Some(b'+' | b'-') => {
            let sign: i64 = if bytes[index] == b'+' { 1 } else { -1 };
            let offset_hour: i64 = text.get(index + 1..index + 3)?.parse().ok()?;
            if bytes.get(index + 3) != Some(&b':') {
                return None;
            }
            let offset_minute: i64 = text.get(index + 4..index + 6)?.parse().ok()?;
            offset_seconds = sign * (offset_hour * 3600 + offset_minute * 60);
        }
        _ => return None,
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let epoch = days * 86400 + hour * 3600 + minute * 60 + second - offset_seconds;
    u64::try_from(epoch).ok()
}
