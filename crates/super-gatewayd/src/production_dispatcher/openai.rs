//! Official `OpenAI` dispatch using the shared group owner and accounting lifecycle.
use super::*;
use gateway_domain::{
    OpenAiAuthKind, OpenAiEndpoint, PinReason, Portability, ResponseMode, UsageObservation, UsageSource,
};
use gateway_services::openai::{
    protocol,
    usage::{ResponseObserver, SseDecoder},
};
use gateway_services::response::{PreparedClientResponse, PreparedDeliveryState};
use gateway_transport::{OpenAiHttpRequest, execute_openai_http, execute_openai_websocket};
use serde_json::{Value, json};

pub(super) async fn load_credentials(storage: &PgStorage, group: Uuid) -> anyhow::Result<Vec<CredentialConfig>> {
    let rows=sqlx::query("SELECT a.id,a.revision,a.token_version,a.max_concurrency,a.priority,a.models \
        FROM gateway.openai_account a JOIN gateway.credential_group g ON g.id=a.group_id AND g.provider_code='openai' \
        CROSS JOIN gateway.openai_settings s WHERE a.group_id=$1 AND s.enabled AND a.enabled AND a.verified_at IS NOT NULL \
        AND a.auth_state_code IN ('healthy','manual_update') AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) \
        AND (a.cooldown_until IS NULL OR a.cooldown_until<=clock_timestamp()) \
        AND COALESCE(a.quota_snapshot #>> '{rate_limit,allowed}','true')<>'false'")
        .bind(group).fetch_all(&storage.pool()).await?;
    rows.into_iter()
        .map(|r| {
            let revision = u64::try_from(r.try_get::<i64, _>("revision")?)?;
            let models: Value = r.try_get("models")?;
            Ok(CredentialConfig {
                id: CredentialId::new(r.try_get::<Uuid, _>("id")?.to_string())?,
                credential_projection_revision: revision,
                scheduling_projection_revision: revision,
                concurrency_limit: u32::try_from(r.try_get::<i32, _>("max_concurrency")?)?,
                rate_limit: BucketConfig {
                    requests_per_minute: 60000,
                    burst: 1000,
                },
                priority: u16::try_from(r.try_get::<i32, _>("priority")?.clamp(0, 65535))?,
                weight: 1000,
                model_scope: models
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(Box::from)
                    .collect(),
                attribution_optional: true,
                session_capacity: SessionCapacityConfig::default(),
                token_version: u64::try_from(r.try_get::<i64, _>("token_version")?)?,
                openai_transport: Some(gateway_scheduler::OpenAiTransportConfig {
                    revision,
                    egress_epoch: revision,
                }),
                profiles: BTreeMap::new(),
                quota_observation_version: None,
                state: CredentialState::default(),
            })
        })
        .collect()
}

impl ProductionDispatcher {
    pub(super) async fn dispatch_openai(
        &self,
        mut request: DispatchRequest,
        endpoint: OpenAiEndpoint,
    ) -> Result<UpstreamResponse, DispatchError> {
        let group = self
            .runtime_group(&request.group_id)
            .ok_or(DispatchError::DeterministicUnavailable)?;
        let limits = *group.request_limits.read().await;
        let request_id = request_uuid(&request)?;
        let key_id = parse_uuid(request.platform_key_id.as_str())?;
        let group_id = parse_uuid(request.group_id.as_str())?;
        let settings=sqlx::query("SELECT s.*,p.max_reasoning_effort,p.reasoning_over_limit FROM gateway.openai_settings s \
            JOIN gateway.credential_group g ON g.id=$1 AND g.provider_code='openai' LEFT JOIN gateway.openai_group_policy p ON p.group_id=g.id WHERE s.enabled")
            .bind(group_id).fetch_optional(&self.storage.pool()).await.map_err(|_|DispatchError::Unavailable)?.ok_or(DispatchError::DeterministicUnavailable)?;
        let (model_id, model_metadata):(Uuid, Option<Value>)=sqlx::query_as("SELECT id,openai_metadata FROM catalog.model_definition WHERE upstream_model_id=$1 AND provider_code='openai' AND lifecycle_code='published'")
            .bind(request.generic.model_id.as_ref()).fetch_optional(&self.storage.pool()).await.map_err(|_|DispatchError::Unavailable)?.ok_or(DispatchError::DeterministicUnavailable)?;
        let body: Value = serde_json::from_slice(request.generic.replay_body.bytes())
            .map_err(|_| DispatchError::DeterministicUnavailable)?;
        if let Some(connection) = &request.openai_connection {
            if !value::<bool>(&settings, "websocket_enabled")? {
                return Err(DispatchError::DeterministicUnavailable);
            }
            if let Some(account) = connection.lock().await.account.clone() {
                Arc::make_mut(&mut request.generic).portability = Portability::Pinned {
                    credential_id: Some(CredentialId::new(account).map_err(|_| DispatchError::Unavailable)?),
                    reasons: vec![PinReason::Continuation],
                };
            }
        }
        if let Some(previous) = body.get("previous_response_id") {
            let previous = previous.as_str().ok_or(DispatchError::InvalidRequest)?;
            let account:Uuid=sqlx::query_scalar("SELECT account_id FROM gateway.openai_response_binding WHERE platform_key_id=$1 AND response_id=$2 AND expires_at>clock_timestamp()")
                .bind(key_id).bind(previous).fetch_optional(&self.storage.pool()).await.map_err(|_|DispatchError::Unavailable)?.ok_or(DispatchError::ContinuationUnavailable)?;
            if let Portability::Pinned {
                credential_id: Some(id),
                ..
            } = &request.generic.portability
                && id.as_str() != account.to_string()
            {
                return Err(DispatchError::ContinuationUnavailable);
            }
            Arc::make_mut(&mut request.generic).portability = Portability::Pinned {
                credential_id: Some(CredentialId::new(account.to_string()).map_err(|_| DispatchError::Unavailable)?),
                reasons: vec![PinReason::Continuation],
            };
        }
        self.storage
            .create_request_after_auth(&RequestCreate {
                request_id,
                platform_key_id: key_id,
                group_id,
                owner_executor_id: group.executor_id.clone(),
                owner_generation: i64::try_from(group.generation.get()).map_err(|_| DispatchError::Unavailable)?,
                endpoint_code: match endpoint {
                    OpenAiEndpoint::Responses => "responses",
                    OpenAiEndpoint::ChatCompletions => "chat_completions",
                    OpenAiEndpoint::Compact => "responses_compact",
                }
                .into(),
                client_class_code: "non_claude_code_cli".into(),
                client_os: request.client_os,
                os_resolution: request.os_resolution,
                os_mismatch: false,
                model_id: Some(model_id),
                request_body_bytes: i64::try_from(request.original_body.len())
                    .map_err(|_| DispatchError::Unavailable)?,
                response_mode: if request.generic.stream {
                    ResponseMode::Streaming
                } else {
                    ResponseMode::NonStreaming
                },
            })
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        let mut request_guard = RequestTerminalGuard::new(self.storage.clone(), request_id, request.started_at);
        let request_type = if request.openai_connection.is_some() {
            "websocket"
        } else if request.generic.stream {
            "streaming"
        } else {
            "sync"
        };
        if self
            .storage
            .record_request_client(request_id, &request.client_identity, request_type)
            .await
            .is_err()
        {
            tracing::warn!(request_id=%request_id, "request client metadata persistence failed");
        }
        if self
            .storage
            .record_request_reasoning(request_id, request.generic.replay_body.bytes())
            .await
            .is_err()
        {
            tracing::warn!(%request_id, "request reasoning metadata persistence failed");
        }
        let capture = self.storage.body_capture_config().await.unwrap_or_else(|_| {
            tracing::warn!(%request_id, "body capture settings unavailable");
            Default::default()
        });
        if capture.enabled
            && let Some(headers) = &request.original_headers
            && self
                .storage
                .capture_original_headers(request_id, headers)
                .await
                .is_err()
        {
            tracing::warn!(%request_id, "ingress header capture failed");
        }
        if capture.enabled
            && self
                .storage
                .capture_request_body(
                    request_id,
                    capture.request_json(&request.original_body),
                    capture.request_json(request.generic.replay_body.bytes()),
                    None,
                )
                .await
                .is_err()
        {
            tracing::warn!(%request_id, "original request body capture failed");
        }
        self.refresh_group_credentials(&group).await;
        let deadline = request.accepted_at.saturating_add(limits.pre_upstream_wait);
        let entry = ScheduleEntry {
            request_id: request.request_id.clone(),
            owner_user_id: request.owner_user_id.clone(),
            platform_key_id: request.platform_key_id.clone(),
            group_id: request.group_id.clone(),
            base_session_id: request.base_session_id.clone(),
            agent_id: request.agent_id.clone(),
            client_os: request.client_os,
            generic: request.generic.clone(),
            accepted_at: request.accepted_at,
            pre_upstream_deadline: deadline,
            bypass_queue: false,
        };
        let (lease, phase) = match group.admit(entry).await? {
            RuntimeAdmission::Granted(lease) => (lease, "accepted"),
            RuntimeAdmission::Queued { receiver, mut guard } => {
                self.storage
                    .advance_request_phase(request_id, "accepted", "queued")
                    .await
                    .map_err(|_| DispatchError::Unavailable)?;
                (
                    group
                        .wait_for_resolution(&request.request_id, deadline, receiver, &mut guard, limits)
                        .await?,
                    "queued",
                )
            }
            RuntimeAdmission::Rejected(r) => {
                return Err(if matches!(request.generic.portability, Portability::Pinned { .. }) {
                    DispatchError::ContinuationUnavailable
                } else {
                    map_rejection(&r, limits)
                });
            }
        };
        let mut lease_guard = LeaseGuard::new(group.clone(), lease.clone());
        let account_id = parse_uuid(lease.credential_id.as_str())?;
        let row=sqlx::query("SELECT a.*,p.host,p.port,p.auth_secret_id,p.proxy_type_code,p.lifecycle_code AS proxy_lifecycle,gc.proxy_policy_code \
            FROM gateway.openai_account a LEFT JOIN gateway.proxy_endpoint p ON p.id=a.proxy_id \
            JOIN gateway.group_active_config ac ON ac.group_id=a.group_id JOIN gateway.group_config gc ON gc.id=ac.config_id \
            WHERE a.id=$1 AND a.group_id=$2 AND a.token_version=$3 AND a.enabled AND a.auth_state_code IN ('healthy','manual_update')")
            .bind(account_id).bind(group_id).bind(i64::try_from(lease.token_version).map_err(|_|DispatchError::Unavailable)?)
            .fetch_optional(&self.storage.pool()).await.map_err(|_|DispatchError::Unavailable)?.ok_or(DispatchError::DeterministicUnavailable)?;
        let auth = if value::<String>(&row, "auth_kind_code")? == "oauth" {
            OpenAiAuthKind::Oauth
        } else {
            OpenAiAuthKind::ApiKey
        };
        if request.openai_connection.is_some() && !value::<bool>(&row, "websocket_enabled")? {
            return Err(DispatchError::DeterministicUnavailable);
        }
        let mut adjusted = protocol::prepare(&body, endpoint, auth).map_err(|_| DispatchError::InvalidRequest)?;
        protocol::ReasoningPolicy {
            maximum: value(&settings, "max_reasoning_effort")?,
            downgrade: value::<Option<String>>(&settings, "reasoning_over_limit")?.as_deref() == Some("downgrade"),
        }
        .apply(&mut adjusted, &["none", "minimal", "low", "medium", "high", "xhigh"])
        .map_err(|_| DispatchError::InvalidRequest)?;
        if auth == OpenAiAuthKind::Oauth {
            protocol::validate_capabilities(&adjusted, model_metadata.as_ref())
                .map_err(|_| DispatchError::InvalidRequest)?;
        }
        let secret = decrypt_secret(&self.storage, value(&row, "access_secret_id")?).await?;
        let mut headers = http::HeaderMap::new();
        let bearer = format!(
            "Bearer {}",
            std::str::from_utf8(secret.expose()).map_err(|_| DispatchError::Unavailable)?
        );
        headers.insert(
            "authorization",
            http::HeaderValue::from_str(&bearer).map_err(|_| DispatchError::DeterministicUnavailable)?,
        );
        if auth == OpenAiAuthKind::Oauth {
            headers.insert(
                "chatgpt-account-id",
                http::HeaderValue::from_str(&value::<String>(&row, "account_id")?)
                    .map_err(|_| DispatchError::DeterministicUnavailable)?,
            );
            headers.insert("originator", http::HeaderValue::from_static("codex_cli_rs"));
            let namespace: Uuid = value(&row, "session_namespace")?;
            let seed = SecretBytes::new(Sha256::digest(namespace.as_bytes()).to_vec());
            let session = gateway_services::openai::session::isolate_session(
                &seed,
                &key_id.to_string(),
                &account_id.to_string(),
                request.base_session_id.as_str(),
            )
            .map_err(|_| DispatchError::Unavailable)?;
            headers.insert(
                "session_id",
                http::HeaderValue::from_str(&session).map_err(|_| DispatchError::Unavailable)?,
            );
            if let Some(cache) = adjusted.get("prompt_cache_key").and_then(Value::as_str) {
                let isolated = gateway_services::openai::session::isolate_session(
                    &seed,
                    &key_id.to_string(),
                    &account_id.to_string(),
                    cache,
                )
                .map_err(|_| DispatchError::InvalidRequest)?;
                adjusted["prompt_cache_key"] = json!(isolated);
            }
        }
        let egress = account_egress(&self.storage, &row).await?;
        let bytes = serde_json::to_vec(&adjusted).map_err(|_| DispatchError::Unavailable)?;
        if self.storage.record_request_reasoning(request_id, &bytes).await.is_err() {
            tracing::warn!(%request_id, "final reasoning metadata persistence failed");
        }
        if capture.enabled
            && self
                .storage
                .capture_final_request_body(request_id, capture.request_json(&bytes))
                .await
                .is_err()
        {
            tracing::warn!(%request_id, "final request body capture failed");
        }
        self.storage
            .advance_request_phase(request_id, phase, "submitting")
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        let (intent, attempt) = arm_attempt(&self.storage, request_id, account_id, lease.token_version, &bytes).await?;
        let cancellation = self.request_cancellation.child_token();
        let guard = cancellation.clone().drop_guard();
        let downstream_cancellation = cancellation.clone();
        let url = endpoint.upstream_url(auth);
        let (host, path) = if let Some(path) = url.strip_prefix("https://api.openai.com") {
            ("api.openai.com", path)
        } else {
            (
                "chatgpt.com",
                url.strip_prefix("https://chatgpt.com")
                    .ok_or(DispatchError::Unavailable)?,
            )
        };
        let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (header_tx, mut header_rx) = tokio::sync::mpsc::channel(2);
        if capture.enabled && self.storage.begin_header_attempt(request_id, 1).await.is_err() {
            tracing::warn!(%request_id, "header attempt initialization failed");
        }
        let upstream_request = OpenAiHttpRequest {
            header_capture: capture.enabled.then_some(header_tx),
            retry_connect: matches!(request.generic.portability, Portability::Portable),
            written: written.clone(),
            host,
            path,
            headers,
            body: SecretBytes::new(bytes),
            egress,
            connect_timeout: Duration::from_secs(
                u64::try_from(value::<i32>(&settings, "connect_timeout_seconds")?)
                    .map_err(|_| DispatchError::Unavailable)?,
            ),
            idle_timeout: Duration::from_secs(
                u64::try_from(value::<i32>(&settings, "response_timeout_seconds")?)
                    .map_err(|_| DispatchError::Unavailable)?,
            ),
            cancellation: cancellation.clone(),
        };
        let result = if let Some(connection) = request.openai_connection.clone() {
            // Quota probes update the account revision but do not change connection identity.
            // Only token, egress and transport changes invalidate a retained upstream socket.
            let identity = json!([
                lease.token_version,
                value::<Option<Uuid>>(&row, "proxy_id")?,
                value::<Option<String>>(&row, "host")?,
                value::<Option<i32>>(&row, "port")?,
                value::<Option<Uuid>>(&row, "auth_secret_id")?,
                value::<Option<String>>(&row, "proxy_type_code")?,
                value::<i64>(&settings, "revision")?
            ]);
            let digest = Sha256::digest(identity.to_string().as_bytes());
            let mut version = [0_u8; 8];
            version.copy_from_slice(&digest[..8]);
            execute_openai_websocket(
                upstream_request,
                connection,
                account_id.to_string(),
                u64::from_be_bytes(version),
            )
            .await
        } else {
            execute_openai_http(upstream_request).await
        };
        let byte_count = i64::try_from(written.load(Ordering::Acquire)).unwrap_or(i64::MAX);
        while let Ok(event) = header_rx.try_recv() {
            let (response, mut headers) = match event {
                gateway_transport::OpenAiHeaderEvent::Request(h) => (false, h),
                gateway_transport::OpenAiHeaderEvent::Response(h) => (true, h),
            };
            headers.attempt_ordinal = Some(1);
            if self
                .storage
                .capture_upstream_headers(request_id, response, &headers)
                .await
                .is_err()
            {
                tracing::warn!(%request_id, "upstream header capture failed");
            }
        }
        let Ok(mut raw) = result else {
            if byte_count > 0 {
                promote(&self.storage, request_id, intent, attempt, None, byte_count)
                    .await
                    .map_err(|_| DispatchError::DeterministicUnavailable)?;
                return Err(DispatchError::DeterministicUnavailable);
            }
            let _=sqlx::query("UPDATE telemetry.connection_attempt_record SET state_code='failed_before_first_byte',completed_at=clock_timestamp(),retry_safe=true WHERE submission_intent_id=$1").bind(intent).execute(&self.storage.pool()).await;
            return Err(DispatchError::Unavailable);
        };
        promote(&self.storage, request_id, intent, attempt, Some(raw.status), byte_count)
            .await
            .map_err(|_| DispatchError::DeterministicUnavailable)?;
        if raw.status == 401 {
            let _=sqlx::query("UPDATE gateway.openai_account SET auth_state_code=CASE WHEN refresh_secret_id IS NULL THEN 'needs_reauth' ELSE 'healthy' END,expires_at=clock_timestamp(),last_error_code='auth_failure',last_error_message='upstream rejected credentials (401)',last_error_at=clock_timestamp(),revision=revision+1 WHERE id=$1 AND token_version=$2 AND auth_state_code<>'refreshing'")
                .bind(account_id).bind(i64::try_from(lease.token_version).unwrap_or(i64::MAX)).execute(&self.storage.pool()).await;
        } else if raw.status == 403 {
            let _=sqlx::query("UPDATE gateway.openai_account SET auth_state_code='manual_update',last_error_code='account_forbidden',last_error_message='upstream forbidden the account (403)',last_error_at=clock_timestamp(),revision=revision+1 WHERE id=$1")
                .bind(account_id).execute(&self.storage.pool()).await;
        } else if raw.status == 429 || raw.status >= 500 {
            let cooldown = raw
                .headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(if raw.status == 429 { 60 } else { 15 })
                .clamp(1, 1800);
            let _=sqlx::query("UPDATE gateway.openai_account SET cooldown_until=clock_timestamp()+$2*interval '1 second',last_error_code=CASE WHEN $3 THEN 'rate_limit' ELSE 'upstream_error' END,last_error_message=CASE WHEN $3 THEN 'upstream rate limited (429)' ELSE 'upstream server error' END,last_error_at=clock_timestamp(),revision=revision+1 WHERE id=$1")
                .bind(account_id).bind(cooldown).bind(raw.status == 429).execute(&self.storage.pool()).await;
        } else if raw.status < 400 {
            let _=sqlx::query("UPDATE gateway.openai_account SET last_error_code=NULL,last_error_message=NULL,last_error_at=NULL,revision=revision+1 WHERE id=$1 AND last_error_at IS NOT NULL")
                .bind(account_id).execute(&self.storage.pool()).await;
        }
        let delivery_id = Uuid::now_v7();
        self.storage
            .start_response_delivery(&DeliveryStart {
                delivery_id,
                request_id,
                attempt_id: Some(attempt),
                streaming: request.generic.stream,
                buffer_tier_code: if request.generic.stream {
                    None
                } else {
                    Some("memory".into())
                },
                client_write_idle_ms: 120_000,
            })
            .await
            .map_err(|_| DispatchError::DeterministicUnavailable)?;
        let terminal = CancellationToken::new();
        let completion = Arc::new(RequestCompletion {
            started_at: request.started_at,
            endpoint: request.endpoint,
            storage: self.storage.clone(),
            group: group.clone(),
            lease: Some(lease),
            request_id: request.request_id.clone(),
            request_uuid: request_id,
            delivery_id,
            attempt_id: attempt,
            model_id,
            clock: self.clock.clone(),
            committed: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            transport_terminal: terminal.clone(),
            cancel_grace: limits.cancel_grace,
            cancel_input_tokens: 0,
            cancel_input_basis_digest: [0; 32],
            usage_terminal: Mutex::new(UsageTerminalLatch::default()),
        });
        let upstream_sse = raw
            .headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|s| s.contains("text/event-stream"));
        let converted = auth == OpenAiAuthKind::Oauth && endpoint == OpenAiEndpoint::ChatCompletions;
        let stream = request.generic.stream && raw.status < 400;
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (usage_tx, usage_rx) = oneshot::channel();
        let state = PreparedDeliveryState::default();
        let producer_state = state.clone();
        let storage = self.storage.clone();
        let task_completion = completion.clone();
        let status = raw.status;
        let headers = if converted || (upstream_sse && !stream && status < 400) {
            vec![(
                "content-type".into(),
                Bytes::from_static(if stream {
                    b"text/event-stream"
                } else {
                    b"application/json"
                }),
            )]
        } else {
            raw.headers
                .iter()
                .filter(|(k, _)| !matches!(k.as_str(), "content-length" | "transfer-encoding" | "connection"))
                .map(|(k, v)| (k.as_str().into(), Bytes::copy_from_slice(v.as_bytes())))
                .collect()
        };
        let request_model = request.generic.model_id.clone();
        let include_usage = body
            .pointer("/stream_options/include_usage")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        tokio::spawn(async move {
            let _cancel_guard = guard;
            let mut observer = ResponseObserver::default();
            let mut decoder = SseDecoder::new(4 * 1024 * 1024);
            let mut buffered = Vec::new();
            let mut final_response = None;
            let mut count = 0_u64;
            let mut good = true;
            let mut chat = ChatStream {
                include_usage,
                ..Default::default()
            };
            let mut bound_response = None;
            while let Some(chunk) =
                tokio::select! {()=cancellation.cancelled()=>{good=false;None},chunk=raw.body.recv()=>chunk}
            {
                let Ok(chunk) = chunk else {
                    good = false;
                    break;
                };
                count = count.saturating_add(chunk.len() as u64);
                if upstream_sse {
                    match decoder.push(&chunk) {
                        Ok(events) => {
                            for event in events {
                                let already_terminal = observer.terminal.is_some();
                                if observer.observe(&event).is_err() {
                                    good = false;
                                }
                                if endpoint != OpenAiEndpoint::ChatCompletions
                                    && let Some(id) = &observer.response_id
                                    && bound_response.as_ref() != Some(id)
                                {
                                    if !bind_response(&storage, key_id, account_id, id).await {
                                        good = false;
                                        break;
                                    }
                                    bound_response = Some(id.clone());
                                }
                                if !already_terminal
                                    && matches!(
                                        event.get("type").and_then(Value::as_str),
                                        Some("response.completed" | "response.incomplete" | "response.failed")
                                    )
                                {
                                    final_response = event.get("response").cloned();
                                }
                                if converted && stream && !already_terminal {
                                    for bytes in chat.event(&event) {
                                        if !send_chunk(&tx, bytes, &cancellation).await {
                                            good = false;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => good = false,
                    }
                } else {
                    if buffered.len() + chunk.len() > 64 * 1024 * 1024 {
                        good = false;
                        break;
                    }
                    buffered.extend_from_slice(&chunk);
                }
                if !good {
                    break;
                }
                if stream && !converted && !send_chunk(&tx, chunk, &cancellation).await {
                    good = false;
                    break;
                }
                if observer.terminal.is_some() || (endpoint == OpenAiEndpoint::ChatCompletions && decoder.is_done()) {
                    break;
                }
            }
            if upstream_sse && !converted && endpoint == OpenAiEndpoint::ChatCompletions && decoder.is_done() {
                observer.terminal = Some("chat.done".into());
            }
            if !upstream_sse && let Ok(document) = serde_json::from_slice::<Value>(&buffered) {
                if observer.observe(&document).is_err() {
                    good = false;
                }
                if good {
                    observer.terminal = Some("json.complete".into());
                }
            }
            if upstream_sse && (!good || decoder.has_partial_event() || observer.terminal.is_none()) {
                good = false;
            }
            if let Some(id) = observer
                .response_id
                .as_ref()
                .filter(|_| good && status < 400 && endpoint != OpenAiEndpoint::ChatCompletions)
            {
                good = bind_response(&storage, key_id, account_id, id).await;
            }
            if !stream {
                let payload = if upstream_sse && status < 400 {
                    final_response
                        .and_then(|r| {
                            if converted {
                                protocol::responses_to_chat(&r).ok()
                            } else {
                                Some(r)
                            }
                        })
                        .and_then(|r| serde_json::to_vec(&r).ok())
                } else {
                    Some(buffered)
                };
                if let Some(bytes) = payload {
                    if !send_chunk(&tx, Bytes::from(bytes), &cancellation).await {
                        good = false;
                    }
                } else {
                    good = false;
                }
            }
            if !good {
                let _ = tx.try_send(Err(ResponseError::ResponseTotalTimeout));
            }
            let usage = UsageObservation {
                source: UsageSource::Official,
                completeness: observer.completeness(),
                counts: observer.usage.cost_counts(),
                algorithm_version: None,
            };
            if !task_completion.persist_usage_observation(usage.clone(), None).await {
                good = false;
            }
            let outcome = if !good {
                "incomplete_stream"
            } else if status >= 400 {
                "upstream_http_error"
            } else {
                observer.terminal.as_deref().unwrap_or("missing_terminal")
            };
            let _ =
                sqlx::query("UPDATE telemetry.request_record SET outcome_code=$2,http_status=$3 WHERE request_id=$1")
                    .bind(request_id)
                    .bind(outcome)
                    .bind(i32::from(status))
                    .execute(&storage.pool())
                    .await;
            let _=sqlx::query("UPDATE telemetry.usage_observation SET reasoning_tokens=$1,request_model=$2,upstream_model=$2,response_model=$3 WHERE request_id=$4 AND attempt_id=$5")
                .bind(observer.usage.reasoning.and_then(|v|i64::try_from(v).ok())).bind(request_model.as_ref()).bind(observer.model).bind(request_id).bind(attempt).execute(&storage.pool()).await;
            let _ = usage_tx.send(ObservedResponseUsage {
                first_content_at: observer.first_content_at,
                official: usage,
                sse: None,
                upstream_bytes_received: count,
            });
            producer_state.finish_external(good);
            terminal.cancel();
            let _ = ready_tx.send(good);
        });
        if !stream && !ready_rx.await.unwrap_or(false) {
            return Err(DispatchError::DeterministicUnavailable);
        }
        lease_guard.disarm();
        request_guard.disarm();
        Ok(PreparedClientResponse {
            status,
            headers,
            mode: if stream {
                ResponseMode::Streaming
            } else {
                ResponseMode::NonStreaming
            },
            buffer_tier: if stream {
                None
            } else {
                Some(gateway_domain::BufferTier::Memory)
            },
            body: rx,
            usage: usage_rx,
            delivery_state: state,
            completion: Some(completion),
            cancellation: downstream_cancellation,
            admission: None,
        })
    }
}

async fn send_chunk(
    tx: &tokio::sync::mpsc::Sender<Result<Bytes, ResponseError>>,
    bytes: Bytes,
    cancel: &CancellationToken,
) -> bool {
    tokio::select! {
        () = cancel.cancelled() => false,
        result = tokio::time::timeout(Duration::from_mins(2), tx.send(Ok(bytes))) => matches!(result, Ok(Ok(()))),
    }
}

async fn bind_response(storage: &PgStorage, key: Uuid, account: Uuid, response: &str) -> bool {
    sqlx::query("INSERT INTO gateway.openai_response_binding(platform_key_id,response_id,account_id,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '24 hours') ON CONFLICT(platform_key_id,response_id) DO UPDATE SET expires_at=EXCLUDED.expires_at WHERE openai_response_binding.account_id=EXCLUDED.account_id")
        .bind(key).bind(response).bind(account).execute(&storage.pool()).await.is_ok_and(|result| result.rows_affected() == 1)
}

fn value<T>(row: &sqlx::postgres::PgRow, name: &str) -> Result<T, DispatchError>
where
    for<'a> T: sqlx::Decode<'a, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(name).map_err(|_| DispatchError::Unavailable)
}

async fn account_egress(
    storage: &PgStorage,
    row: &sqlx::postgres::PgRow,
) -> Result<EgressRouteSnapshot, DispatchError> {
    let proxy = value::<Option<Uuid>>(row, "proxy_id")?;
    let policy = value::<String>(row, "proxy_policy_code")?;
    if (policy == "proxy_required" && proxy.is_none()) || (policy == "direct" && proxy.is_some()) {
        return Err(DispatchError::DeterministicUnavailable);
    }
    if proxy.is_none() {
        return Ok(EgressRouteSnapshot::Direct);
    }
    if value::<String>(row, "proxy_lifecycle")? != "active" {
        return Err(DispatchError::DeterministicUnavailable);
    }
    let credentials = if let Some(id) = value::<Option<Uuid>>(row, "auth_secret_id")? {
        Some(Arc::new(parse_proxy_credentials(&decrypt_secret(storage, id).await?)?))
    } else {
        None
    };
    let host = value::<String>(row, "host")?.into();
    let port = u16::try_from(value::<i32>(row, "port")?).map_err(|_| DispatchError::Unavailable)?;
    match value::<String>(row, "proxy_type_code")?.as_str() {
        "connect" => Ok(EgressRouteSnapshot::HttpConnect {
            host,
            port,
            credentials,
        }),
        "socks5" => Ok(EgressRouteSnapshot::Socks5 {
            host,
            port,
            credentials,
            dns: Socks5DnsMode::Remote,
        }),
        _ => Err(DispatchError::DeterministicUnavailable),
    }
}

async fn arm_attempt(
    storage: &PgStorage,
    request: Uuid,
    account: Uuid,
    version: u64,
    body: &[u8],
) -> Result<(Uuid, Uuid), DispatchError> {
    let intent = Uuid::now_v7();
    let attempt = Uuid::now_v7();
    sqlx::query("INSERT INTO telemetry.attempt_submission_intent(id,request_month,request_id,ordinal,credential_id,token_version,egress_epoch,generic_adjusted_request_hash,state_code,created_at,armed_at) SELECT $1,request_month,request_id,1,$3,$4,1,$5,'armed',clock_timestamp(),clock_timestamp() FROM telemetry.request_record WHERE request_id=$2")
        .bind(intent).bind(request).bind(account).bind(i64::try_from(version).map_err(|_|DispatchError::Unavailable)?).bind(Sha256::digest(body).to_vec()).execute(&storage.pool()).await.map_err(|_|DispatchError::Unavailable)?;
    sqlx::query("INSERT INTO telemetry.connection_attempt_record(id,request_month,request_id,ordinal,submission_intent_id,credential_id,egress_epoch,state_code,started_at) SELECT $1,request_month,request_id,1,id,credential_id,egress_epoch,'planned',clock_timestamp() FROM telemetry.attempt_submission_intent WHERE id=$2")
        .bind(Uuid::now_v7()).bind(intent).execute(&storage.pool()).await.map_err(|_|DispatchError::Unavailable)?;
    Ok((intent, attempt))
}
async fn promote(
    storage: &PgStorage,
    request: Uuid,
    intent: Uuid,
    attempt: Uuid,
    status: Option<u16>,
    written: i64,
) -> Result<(), DispatchError> {
    let mut tx = storage.pool().begin().await.map_err(|_| DispatchError::Unavailable)?;
    sqlx::query("UPDATE telemetry.attempt_submission_intent SET state_code='promoted',promoted_at=clock_timestamp(),request_bytes_written=$2 WHERE id=$1 AND state_code='armed'").bind(intent).bind(written).execute(&mut *tx).await.map_err(|_|DispatchError::Unavailable)?;
    sqlx::query("UPDATE telemetry.connection_attempt_record SET state_code='promoted_on_first_byte',request_bytes_written=$2,retry_safe=false,completed_at=clock_timestamp() WHERE submission_intent_id=$1").bind(intent).bind(written).execute(&mut *tx).await.map_err(|_|DispatchError::Unavailable)?;
    sqlx::query("INSERT INTO telemetry.attempt_record(id,request_month,request_id,ordinal,submission_intent_id,credential_id,token_version,egress_epoch,reason_code,state_code,submitted_at,http_status,is_final) SELECT $1,request_month,request_id,1,id,credential_id,token_version,egress_epoch,'initial','receiving',clock_timestamp(),$3,true FROM telemetry.attempt_submission_intent WHERE id=$2")
        .bind(attempt).bind(intent).bind(status.map(i32::from)).execute(&mut *tx).await.map_err(|_|DispatchError::Unavailable)?;
    sqlx::query("UPDATE telemetry.request_record SET first_submitted_at=COALESCE(first_submitted_at,clock_timestamp()) WHERE request_id=$1").bind(request).execute(&mut *tx).await.map_err(|_|DispatchError::Unavailable)?;
    sqlx::query("UPDATE telemetry.attempt_record SET connection_attempt_id=(SELECT id FROM telemetry.connection_attempt_record WHERE submission_intent_id=$2) WHERE id=$1").bind(attempt).bind(intent).execute(&mut *tx).await.map_err(|_|DispatchError::Unavailable)?;
    tx.commit().await.map_err(|_| DispatchError::Unavailable)?;
    let _ = request;
    Ok(())
}

#[derive(Default)]
struct ChatStream {
    include_usage: bool,
    id: String,
    model: String,
    calls: usize,
    call_indices: BTreeMap<String, usize>,
    terminal: bool,
}
impl ChatStream {
    fn event(&mut self, event: &Value) -> Vec<Bytes> {
        if self.terminal {
            return Vec::new();
        }
        let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
        if let Some(response) = event.get("response") {
            self.id = response.get("id").and_then(Value::as_str).unwrap_or(&self.id).into();
            self.model = response
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or(&self.model)
                .into();
        }
        let (delta, finish) = match kind {
            "response.created" => (json!({"role":"assistant","content":""}), Value::Null),
            "response.output_text.delta" => (json!({"content":event["delta"]}), Value::Null),
            "response.output_item.added"
                if event.pointer("/item/type").and_then(Value::as_str) == Some("function_call") =>
            {
                let index = self.calls;
                self.calls += 1;
                if let Some(id) = event.pointer("/item/id").and_then(Value::as_str) {
                    self.call_indices.insert(id.into(), index);
                }
                (
                    json!({"tool_calls":[{"index":index,"id":event["item"]["call_id"],"type":"function","function":{"name":event["item"]["name"],"arguments":""}}]}),
                    Value::Null,
                )
            }
            "response.function_call_arguments.delta" => (
                json!({"tool_calls":[{"index":event.get("item_id").and_then(Value::as_str).and_then(|id|self.call_indices.get(id)).copied().unwrap_or(event.get("output_index").and_then(Value::as_u64).and_then(|v|usize::try_from(v).ok()).unwrap_or(0)),"function":{"arguments":event["delta"]}}]}),
                Value::Null,
            ),
            "response.completed" => (json!({}), json!(if self.calls > 0 { "tool_calls" } else { "stop" })),
            "response.incomplete" => (json!({}), json!("length")),
            "response.failed" => {
                self.terminal = true;
                let error = event
                    .pointer("/response/error")
                    .cloned()
                    .unwrap_or_else(|| json!({"code":"upstream_failed","message":"Upstream response failed."}));
                return vec![Bytes::from(format!("data: {}\n\n", json!({"error":error})))];
            }
            _ => return Vec::new(),
        };
        let terminal = !finish.is_null();
        let chunk = json!({"id":self.id,"object":"chat.completion.chunk","created":0,"model":self.model,"choices":[{"index":0,"delta":delta,"finish_reason":finish}]});
        let mut result = vec![Bytes::from(format!("data: {chunk}\n\n"))];
        if terminal {
            self.terminal = true;
            if self.include_usage
                && let Some(response) = event.get("response")
                && let Ok(document) = protocol::responses_to_chat(response)
                && let Some(usage) = document.get("usage")
            {
                let chunk = json!({"id":self.id,"object":"chat.completion.chunk","created":0,"model":self.model,"choices":[],"usage":usage});
                result.push(Bytes::from(format!("data: {chunk}\n\n")));
            }
            result.push(Bytes::from_static(b"data: [DONE]\n\n"));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_interleaved_tools_and_duplicate_terminal() {
        let mut stream = ChatStream::default();
        for (id, index) in [("a", 0), ("b", 1)] {
            let chunks = stream.event(&json!({"type":"response.output_item.added","item":{"type":"function_call","id":id,"call_id":id,"name":"tool"}}));
            assert!(String::from_utf8_lossy(&chunks[0]).contains(&format!("\"index\":{index}")));
        }
        let chunks = stream.event(&json!({"type":"response.function_call_arguments.delta","item_id":"a","delta":"{}"}));
        assert!(String::from_utf8_lossy(&chunks[0]).contains("\"index\":0"));
        assert_eq!(stream.event(&json!({"type":"response.completed"})).len(), 2);
        assert!(stream.event(&json!({"type":"response.completed"})).is_empty());
    }

    #[tokio::test]
    async fn openai_attempt_and_delivery_postgres() -> Result<(), Box<dyn std::error::Error>> {
        let Ok(url) = std::env::var("TEST_OPENAI_DATABASE_URL") else {
            return Ok(());
        };
        let url = gateway_domain::SecretValue::new(url);
        PgStorage::migrate(&url).await?;
        let storage = PgStorage::connect(&url, gateway_storage::RuntimeRolePolicy::AllowPrivilegedTest).await?;
        storage.ensure_database_business_key().await?;
        let pool = storage.pool();
        let user = Uuid::now_v7();
        let group = Uuid::now_v7();
        let account = Uuid::now_v7();
        let key = Uuid::now_v7();
        let secret = Uuid::now_v7();
        let model = Uuid::now_v7();
        let request = Uuid::now_v7();
        sqlx::query("INSERT INTO iam.user_account(id,username,username_normalized,role_code,status_code,created_at,updated_at) VALUES($1,$2,$2,'key_owner','active',now(),now())").bind(user).bind(user.to_string()).execute(&pool).await?;
        sqlx::query("INSERT INTO gateway.credential_group(id,name,status_code,provider_code,created_at,updated_at) VALUES($1,$2,'active','openai',now(),now())").bind(group).bind(group.to_string()).execute(&pool).await?;
        sqlx::query("INSERT INTO security.encrypted_secret(id,secret_kind_code,provider_role_code,ciphertext,nonce,wrapped_dek,key_version,aad_schema_version,owner_type_code,owner_id,purpose_code,created_at) SELECT $1,'platform_key','business',decode('01','hex'),decode(repeat('01',12),'hex'),decode('01','hex'),key_version,1,'platform_key',$2,'authentication',now() FROM security.business_key_material WHERE state_code='active'").bind(secret).bind(key.to_string()).execute(&pool).await?;
        sqlx::query("INSERT INTO iam.platform_key(id,owner_user_id,group_id,name,secret_id,status_code,created_at,updated_at) VALUES($1,$2,$3,'fixture',$4,'active',now(),now())").bind(key).bind(user).bind(group).bind(secret).execute(&pool).await?;
        sqlx::query("INSERT INTO gateway.openai_account(id,group_id,name,auth_kind_code,access_secret_id) VALUES($1,$2,'fixture','api_key',$3)").bind(account).bind(group).bind(secret).execute(&pool).await?;
        let name = format!("fixture-{model}");
        for (id, provider) in [(model, "openai"), (Uuid::now_v7(), "anthropic")] {
            sqlx::query("INSERT INTO catalog.model_definition(id,upstream_model_id,display_name,provider_code,lifecycle_code,first_seen_at,last_seen_at) VALUES($1,$2,$2,$3,'discovered',now(),now())").bind(id).bind(&name).bind(provider).execute(&pool).await?;
        }
        storage
            .create_request_after_auth(&RequestCreate {
                request_id: request,
                platform_key_id: key,
                group_id: group,
                owner_executor_id: "fixture".into(),
                owner_generation: 1,
                endpoint_code: "responses".into(),
                client_class_code: "non_claude_code_cli".into(),
                client_os: gateway_domain::ClientOs::Windows,
                os_resolution: gateway_domain::OsResolution::GroupDefault,
                os_mismatch: false,
                model_id: Some(model),
                request_body_bytes: 2,
                response_mode: ResponseMode::NonStreaming,
            })
            .await?;
        let (intent, attempt) = arm_attempt(&storage, request, account, 1, b"{}")
            .await
            .map_err(|_| "arm failed")?;
        promote(&storage, request, intent, attempt, Some(200), 2)
            .await
            .map_err(|_| "promote failed")?;
        let delivery = Uuid::now_v7();
        storage
            .start_response_delivery(&DeliveryStart {
                delivery_id: delivery,
                request_id: request,
                attempt_id: Some(attempt),
                streaming: false,
                buffer_tier_code: Some("memory".into()),
                client_write_idle_ms: 120_000,
            })
            .await?;
        storage.commit_client_response(request, delivery).await?;
        assert!(bind_response(&storage, key, account, "fixture-response").await);
        let usage = gateway_storage::UsagePersist {
            observation_id: Uuid::now_v7(),
            request_id: request,
            attempt_id: Some(attempt),
            model_id: Some(model),
            observation: UsageObservation {
                source: UsageSource::Official,
                completeness: gateway_domain::UsageCompleteness::Complete,
                counts: gateway_services::openai::usage::OpenAiUsage {
                    input: Some(100),
                    output: Some(40),
                    cached: Some(60),
                    reasoning: Some(30),
                }
                .cost_counts(),
                algorithm_version: None,
            },
            select_as_final: true,
            selection_reason_code: Some("official_complete".into()),
            cancel_evidence: None,
        };
        storage.append_usage(&usage, None).await?;
        storage.append_usage(&usage, None).await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM telemetry.usage_observation WHERE request_id=$1")
            .bind(request)
            .fetch_one(&pool)
            .await?;
        assert_eq!(count, 1);
        storage
            .complete_request_lifecycle(&gateway_storage::RequestLifecycleComplete {
                request_id: request,
                attempt_id: attempt,
                delivery: gateway_storage::DeliveryComplete {
                    delivery_id: delivery,
                    outcome: gateway_domain::DeliveryOutcome::Complete,
                    response_committed: true,
                    upstream_bytes_received: 2,
                    bytes_delivered: 2,
                    peak_backpressure_bytes: 0,
                    spill_bytes: 0,
                },
            })
            .await?;
        Ok(())
    }
}
