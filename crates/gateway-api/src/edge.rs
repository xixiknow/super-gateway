//! Auth-first business routing and resource-free request gates.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_core::Stream;
use futures_util::SinkExt as _;
use gateway_domain::{
    AgentId, ClientClass, ClientOs, Clock, Digest, OsResolution, PlatformKeyId, RequestId, SecretValue, SessionId,
    SystemClock,
};
use gateway_policy::{OsFamily, PolicyContext, PolicyError, parse_system_segments};
use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;
use subtle::ConstantTimeEq as _;

use crate::{
    AccessGrant, AccessResolver, DataPlaneState, DispatchEndpoint, DispatchError, DispatchRequest, EndpointPermission,
    ModelCatalog, RateLimit, data::ModelRecord, probes::probe_router,
};

const DEFAULT_PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const CONTENT_TYPE_JSON: &str = "application/json";

/// Trusted reverse-proxy networks used only to derive the source address for ingress policy.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxyConfig {
    networks: Arc<[IpNet]>,
}

impl TrustedProxyConfig {
    /// Create an immutable trusted-proxy snapshot.
    #[must_use]
    pub fn new(networks: Vec<IpNet>) -> Self {
        Self {
            networks: networks.into(),
        }
    }

    fn contains(&self, address: IpAddr) -> bool {
        self.networks.iter().any(|network| network.contains(&address))
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Duration,
}

/// Process-local fast-path Key/Probe limiter. R4 adds owner-authoritative Group admission.
#[derive(Clone)]
pub struct BusinessRateLimiter {
    clock: Arc<dyn Clock>,
    buckets: Arc<Mutex<HashMap<Box<str>, Bucket>>>,
}

impl std::fmt::Debug for BusinessRateLimiter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("BusinessRateLimiter").finish_non_exhaustive()
    }
}

impl Default for BusinessRateLimiter {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock::new()))
    }
}

impl BusinessRateLimiter {
    /// Construct with an injectable monotonic clock.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn now(&self) -> Duration {
        self.clock.now().monotonic
    }

    fn allow(&self, key: Box<str>, config: RateLimit) -> RateDecision {
        if config.requests_per_minute == 0 || config.burst == 0 {
            return RateDecision::Limited { retry_after: 60 };
        }
        let now = self.clock.now().monotonic;
        let mut buckets = lock(&self.buckets);
        if buckets.len() > 32_768 {
            let stale_before = now.saturating_sub(Duration::from_hours(1));
            buckets.retain(|_, bucket| bucket.last_refill >= stale_before);
        }
        let burst = f64::from(config.burst);
        let refill_per_second = f64::from(config.requests_per_minute) / 60.0;
        let bucket = buckets.entry(key).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
        });
        let elapsed = now.saturating_sub(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_second).min(burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateDecision::Allowed
        } else {
            let seconds = ((1.0 - bucket.tokens) / refill_per_second).ceil().max(1.0);
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let retry_after = seconds as u64;
            RateDecision::Limited { retry_after }
        }
    }
}

enum RateDecision {
    Allowed,
    Limited { retry_after: u64 },
}

#[derive(Debug, Default)]
struct ConcurrencyState {
    active: HashMap<Box<str>, u32>,
}

/// Per-Platform-Key hard concurrency gate.
#[derive(Clone, Debug, Default)]
pub struct KeyConcurrencyLimiter {
    state: Arc<Mutex<ConcurrencyState>>,
}

impl KeyConcurrencyLimiter {
    fn try_acquire(&self, key: &PlatformKeyId, limit: u32) -> Option<KeyPermit> {
        let mut state = lock(&self.state);
        let active = state.active.entry(Box::from(key.as_str())).or_default();
        if *active >= limit {
            return None;
        }
        *active += 1;
        Some(KeyPermit {
            key: Box::from(key.as_str()),
            state: self.state.clone(),
        })
    }
}

struct KeyPermit {
    key: Box<str>,
    state: Arc<Mutex<ConcurrencyState>>,
}

impl Drop for KeyPermit {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        if let Some(active) = state.active.get_mut(&self.key) {
            *active = active.saturating_sub(1);
            if *active == 0 {
                state.active.remove(&self.key);
            }
        }
    }
}

/// Build the data-plane router with unauthenticated probes and an auth-first business fallback.
pub fn data_plane_router(state: DataPlaneState) -> Router {
    probe_router(state.probe.clone()).fallback(edge_entry).with_state(state)
}

async fn edge_entry(State(state): State<DataPlaneState>, mut request: Request) -> Response {
    request.extensions_mut().insert(Instant::now());
    let request_id = format!("req_{}", uuid::Uuid::now_v7().simple());
    let route = classify_route(request.uri().path());
    let runtime = state.runtime.snapshot();
    let ws_auth_headers = request.headers().clone();
    let original_headers = gateway_domain::HeaderSnapshot::capture(
        gateway_domain::HeaderTransport::Http,
        request
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes())),
    );
    request.extensions_mut().insert(original_headers);
    let Some(grant) = authenticate(request.headers_mut(), runtime.access.as_ref()) else {
        return GatewayError::authentication().response(&request_id);
    };
    if matches!(route, BusinessRoute::OpenAi(_)) != (grant.provider == gateway_domain::Provider::Openai)
        && !matches!(route, BusinessRoute::Models | BusinessRoute::Unknown)
    {
        return GatewayError::permission().response(&request_id);
    }
    let websocket = request.method() == Method::GET
        && matches!(route, BusinessRoute::OpenAi(gateway_domain::OpenAiEndpoint::Responses));
    if !websocket && request.method() != route.expected_method() {
        return route.method_error().response(&request_id);
    }
    if let Some(permission) = route.permission()
        && !grant.permissions.contains(&permission)
    {
        return GatewayError::permission().response(&request_id);
    }
    let source = source_ip(&request, &state.trusted_proxies);
    if !grant.ip_allowlist.is_empty() && !grant.ip_allowlist.iter().any(|network| network.contains(&source)) {
        return GatewayError::permission().response(&request_id);
    }
    if websocket {
        return openai_websocket(state, request, ws_auth_headers, request_id).await;
    }
    match route {
        BusinessRoute::OpenAi(endpoint) => {
            messages(state, request, grant, request_id, DispatchEndpoint::OpenAi(endpoint)).await
        }
        BusinessRoute::Messages => messages(state, request, grant, request_id, DispatchEndpoint::Messages).await,
        BusinessRoute::CountTokens => messages(state, request, grant, request_id, DispatchEndpoint::CountTokens).await,
        BusinessRoute::Models => models(&state, runtime.models.as_ref(), request.uri(), &grant, &request_id),
        BusinessRoute::Unknown => GatewayError::not_found().response(&request_id),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the ordered request gates share one resource acquisition boundary"
)]
async fn messages(
    state: DataPlaneState,
    request: Request,
    grant: Arc<AccessGrant>,
    request_id: String,
    endpoint: DispatchEndpoint,
) -> Response {
    let accepted_at = state.business_rates.now();
    let started_at = request
        .extensions()
        .get::<Instant>()
        .copied()
        .unwrap_or_else(Instant::now);
    let client_identity = gateway_domain::ClientIdentity::from_user_agent(
        request.headers().get(header::USER_AGENT).and_then(|h| h.to_str().ok()),
    );
    if let Err(error) = validate_framing(request.headers()) {
        return error.response(&request_id);
    }
    let effective_limit = grant.body_limit_bytes.min(state.platform_body_limit_bytes.max(1));
    if content_length(request.headers()).is_some_and(|length| length > effective_limit) {
        return GatewayError::too_large().response(&request_id);
    }
    let protocol_headers = protocol_headers(request.headers());
    let original_headers = request.extensions().get::<gateway_domain::HeaderSnapshot>().cloned();
    let openai_connection = request
        .extensions()
        .get::<Arc<tokio::sync::Mutex<gateway_transport::OpenAiConnection>>>()
        .cloned();
    let classification_headers = request.headers().clone();
    let body = match to_bytes(request.into_body(), effective_limit).await {
        Ok(body) => Arc::<[u8]>::from(body.as_ref()),
        Err(_) => return GatewayError::too_large().response(&request_id),
    };
    let classification_tree: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return GatewayError::invalid_body().response(&request_id),
    };
    let mut classified_client = classify_client(&classification_headers, &classification_tree, &grant.platform_key_id);
    if grant.provider == gateway_domain::Provider::Openai {
        let session = header_string(&classification_headers, "session_id")
            .or_else(|| header_string(&classification_headers, "x-session-id"))
            .unwrap_or_else(|| request_id.clone().into());
        let digest = Digest::of(session.as_bytes());
        let Ok(base_session) = SessionId::new(format!("ses_{}", &digest.as_str()[..32])) else {
            return GatewayError::invalid_body().response(&request_id);
        };
        classified_client.base_session = base_session;
        classified_client.class = ClientClass::NonClaudeCodeCli;
    }
    let client_class = classified_client.class;
    let client_app = header_string(&classification_headers, "x-app");
    if !grant.accepted_client_classes.contains(&client_class) {
        return GatewayError::permission().response(&request_id);
    }
    let Some(model) = classification_tree.get("model").and_then(Value::as_str) else {
        return GatewayError::invalid_body().response(&request_id);
    };
    if !model_in_scope(model, &grant.group_model_scope) || !model_in_scope(model, &grant.key_model_scope) {
        return GatewayError::model_unavailable().response(&request_id);
    }
    let (client_os, os_resolution, os_mismatch) = resolve_client_os(
        &classification_headers,
        &classification_tree,
        grant.default_os_family,
        classified_client.session_cache_key.as_deref(),
        &state.client_os_sessions,
    );
    let context = PolicyContext {
        client_class,
        client_os,
        protocol_headers,
        affinity_credential: None,
    };
    let original_body = body.clone();
    let generic = match if matches!(endpoint, DispatchEndpoint::OpenAi(_)) {
        if !state
            .runtime
            .snapshot()
            .models
            .published()
            .iter()
            .any(|m| m.provider == grant.provider && m.id.as_ref() == model)
        {
            return GatewayError::model_unavailable().response(&request_id);
        }
        if classification_tree.get("stream").is_some_and(|v| !v.is_boolean()) {
            return GatewayError::invalid_body().response(&request_id);
        }
        Ok(gateway_domain::GenericAdjustedRequest {
            body_digest: Digest::of(&body),
            model_id: model.into(),
            stream: classification_tree
                .get("stream")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            replay_body: Arc::new(gateway_domain::RequestReplayBody::new(
                body,
                Arc::new(classification_tree.clone()),
                true,
            )),
            portability: gateway_domain::Portability::Portable,
            attribution_suppressed: true,
            system_template_pending: false,
            change_set: Arc::from([]),
            snapshot_set: grant.policy.snapshots.clone(),
        })
    } else if matches!(endpoint, DispatchEndpoint::CountTokens) {
        grant.policy.process_count_tokens(body, &context)
    } else {
        grant.policy.process(body, &context)
    } {
        Ok(generic) => Arc::new(generic),
        Err(error) => return map_policy_error(error).response(&request_id),
    };
    if !matches!(endpoint, DispatchEndpoint::CountTokens)
        && let Err(error) = authorize_spend(&state, &grant).await
    {
        return error.response(&request_id);
    }
    let rate_key = format!(
        "{}:{}",
        if matches!(endpoint, DispatchEndpoint::CountTokens) {
            "count_tokens"
        } else {
            "messages"
        },
        grant.platform_key_id
    )
    .into_boxed_str();
    let rate = if matches!(endpoint, DispatchEndpoint::CountTokens) {
        grant.count_tokens_rate
    } else {
        grant.messages_rate
    };
    if let RateDecision::Limited { retry_after } = state.business_rates.allow(rate_key, rate) {
        return GatewayError::rate_limited(retry_after).response(&request_id);
    }
    let Some(permit) = state
        .concurrency
        .try_acquire(&grant.platform_key_id, grant.concurrency_limit)
    else {
        return GatewayError::rate_limited(2).response(&request_id);
    };
    let websocket = openai_connection.is_some();
    let dispatch = DispatchRequest {
        started_at,
        client_identity,
        original_headers,
        openai_connection,
        endpoint,
        request_id: RequestId::new(request_id.clone()).unwrap_or_else(|_| unreachable_request("req_fallback")),
        owner_user_id: grant.owner_user_id.clone(),
        platform_key_id: grant.platform_key_id.clone(),
        group_id: grant.group_id.clone(),
        base_session_id: classified_client.base_session,
        agent_id: classified_client.agent,
        client_class,
        client_app,
        client_os,
        os_resolution,
        os_mismatch,
        identity_conflict: classified_client.identity_conflict,
        accepted_at,
        pre_upstream_deadline: accepted_at.saturating_add(Duration::from_secs(30)),
        original_body,
        generic,
        anthropic_version: header_string(&classification_headers, "anthropic-version"),
        anthropic_beta: header_string(&classification_headers, "anthropic-beta"),
    };
    state.observability.accepted();
    match state.dispatcher.dispatch(dispatch).await {
        Err(DispatchError::InvalidRequest) => GatewayError::invalid_body().response(&request_id),
        Err(DispatchError::ContinuationUnavailable) => with_request_id((StatusCode::CONFLICT, Json(serde_json::json!({"error":{"type":"invalid_request_error","code":"continuation_unavailable","message":"The response is unknown to this key or its account is unavailable."}}))).into_response(), &request_id),
        Ok(response) => match upstream_response(response, permit, state.observability.clone(), websocket).await {
            Ok(response) => response,
            Err(()) => GatewayError::unavailable_without_retry().response(&request_id),
        },
        Err(DispatchError::Unavailable) => GatewayError::unavailable(1).response(&request_id),
        Err(DispatchError::BundleUnavailable) => GatewayError::bundle_unavailable().response(&request_id),
        Err(
            DispatchError::Overloaded { retry_after_seconds }
            | DispatchError::QueueFull { retry_after_seconds }
            | DispatchError::PreUpstreamTimeout { retry_after_seconds },
        ) => GatewayError::unavailable(retry_after_seconds).response(&request_id),
        Err(
            DispatchError::GroupRateLimited { retry_after_seconds }
            | DispatchError::CredentialCooldown { retry_after_seconds },
        ) => GatewayError::rate_limited(retry_after_seconds).response(&request_id),
        Err(DispatchError::DeterministicUnavailable | DispatchError::Cancelled) => {
            GatewayError::unavailable_without_retry().response(&request_id)
        }
        Err(DispatchError::DeadlineExceeded) => GatewayError::timeout().response(&request_id),
    }
}

async fn authorize_spend(state: &DataPlaneState, grant: &AccessGrant) -> Result<(), GatewayError> {
    match state
        .spend_authorizer
        .authorize(&grant.owner_user_id, &grant.platform_key_id)
        .await
    {
        crate::SpendDecision::Allowed => Ok(()),
        crate::SpendDecision::Limited => Err(GatewayError::rate_limited(60)),
        crate::SpendDecision::Unavailable => Err(GatewayError::unavailable(1)),
    }
}

async fn openai_websocket(state: DataPlaneState, request: Request, headers: HeaderMap, request_id: String) -> Response {
    static CONNECTIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1024);
    static KEYS: std::sync::LazyLock<KeyConcurrencyLimiter> = std::sync::LazyLock::new(KeyConcurrencyLimiter::default);
    use axum::extract::{
        FromRequestParts as _,
        ws::{Message, WebSocketUpgrade},
    };
    use http_body_util::BodyExt as _;
    let Some(idle) = state.dispatcher.openai_websocket_idle().await else {
        return GatewayError::unavailable_without_retry().response(&request_id);
    };
    let source = source_ip(&request, &state.trusted_proxies);
    let mut auth = headers.clone();
    let Some(grant) = authenticate(&mut auth, state.runtime.snapshot().access.as_ref()) else {
        return GatewayError::authentication().response(&request_id);
    };
    let Some(key_permit) = KEYS.try_acquire(&grant.platform_key_id, 32) else {
        return GatewayError::rate_limited(2).response(&request_id);
    };
    let (mut parts, _) = request.into_parts();
    let Ok(upgrade) = WebSocketUpgrade::from_request_parts(&mut parts, &state).await else {
        return GatewayError::invalid_body().response(&request_id);
    };
    // A separate bounded connection count; each response also acquires a normal execution permit.
    let Ok(connection_permit) = CONNECTIONS.try_acquire() else {
        return GatewayError::rate_limited(2).response(&request_id);
    };
    let mut ingress_headers = gateway_domain::HeaderSnapshot::capture(
        gateway_domain::HeaderTransport::WebsocketHandshake,
        headers.iter().map(|(name, value)| (name.as_str(), value.as_bytes())),
    );
    upgrade.max_message_size(state.platform_body_limit_bytes).on_upgrade(move |mut socket|async move {
        let _connection_permit=connection_permit;
        let _key_permit=key_permit;
        let connection=Arc::new(tokio::sync::Mutex::new(gateway_transport::OpenAiConnection::default()));
        let mut next_frame=None;
        loop {
            let (incoming, queued_at)=if let Some((text, at))=next_frame.take(){(Ok(Some(Ok(Message::Text(text)))),Some(at))}else{(tokio::time::timeout(idle,socket.recv()).await,None)};
            let started_at=queued_at.unwrap_or_else(Instant::now);
            let text=match incoming { Ok(Some(Ok(Message::Text(text))))=>text, Ok(Some(Ok(Message::Ping(bytes))))=>{if socket.send(Message::Pong(bytes)).await.is_err(){break;}continue;},Ok(Some(Ok(Message::Pong(_))))=>continue,_=>break};
            let mut body:Value=match serde_json::from_str(text.as_str()){Ok(value)=>value,Err(_)=>break};
            if body.get("type").and_then(Value::as_str)!=Some("response.create"){break;}
            let Some(object)=body.as_object_mut() else {break;};object.remove("type");object.insert("stream".into(),Value::Bool(true));
            let mut auth=headers.clone();
            let Some(grant)=authenticate(&mut auth,state.runtime.snapshot().access.as_ref()) else {break;};
            if grant.provider!=gateway_domain::Provider::Openai || !grant.permissions.contains(&EndpointPermission::Messages){break;}
            if !grant.ip_allowlist.is_empty() && !grant.ip_allowlist.iter().any(|network|network.contains(&source)){break;}
            let Ok(mut request)=Request::builder().method("POST").uri("/v1/responses").body(Body::from(body.to_string())) else {break;};
            *request.headers_mut()=auth;
            request.extensions_mut().insert(connection.clone());
            request.extensions_mut().insert(started_at);
            request.extensions_mut().insert(ingress_headers.clone());
            ingress_headers.reused = true;
            let pending=messages(state.clone(),request,grant,format!("req_{}",uuid::Uuid::now_v7().simple()),DispatchEndpoint::OpenAi(gateway_domain::OpenAiEndpoint::Responses));
            tokio::pin!(pending);
            let response=loop {tokio::select! {
                response=&mut pending=>break Some(response),
                incoming=socket.recv()=>match incoming {
                    Some(Ok(Message::Ping(bytes)))=>{if socket.send(Message::Pong(bytes)).await.is_err(){break None;}},
                    Some(Ok(Message::Pong(_)))=>{},
                    _=>break None,
                }
            }};
            let Some(mut response)=response else {break;};
            let delivery=response.extensions_mut().remove::<Arc<Mutex<WebSocketDelivery>>>();
            if !response.status().is_success(){let _=socket.send(Message::Text(serde_json::json!({"type":"error","error":{"code":"request_failed","message":"Response admission or upstream request failed."}}).to_string().into())).await;break;}
            let mut stream=response.into_body();
            let mut decoder=gateway_services::openai::usage::SseDecoder::new(4*1024*1024);
            let mut good=true;
            let mut terminal_sent=false;
            loop {
                tokio::select! {
                    incoming=socket.recv(), if next_frame.is_none()=>{match incoming {Some(Ok(Message::Text(text))) if terminal_sent=>{next_frame=Some((text,Instant::now()));},Some(Ok(Message::Ping(bytes)))=>{if socket.send(Message::Pong(bytes)).await.is_err(){good=false;break;}},Some(Ok(Message::Pong(_)))=>{},_=>{good=false;break;}}},
                    frame=stream.frame()=>{
                        let Some(frame)=frame else {break;};
                        let Ok(frame)=frame else {good=false;break;};
                        let Ok(bytes)=frame.into_data() else {continue;};
                        let Ok(events)=decoder.push(&bytes) else {good=false;break;};
                        for event in events {terminal_sent |= matches!(event.get("type").and_then(Value::as_str),Some("response.completed"|"response.failed"|"response.incomplete"));let payload=event.to_string();let delivered=payload.len() as u64;if !matches!(tokio::time::timeout(idle,socket.send(Message::Text(payload.into()))).await,Ok(Ok(()))){good=false;break;}if let Some(delivery)=&delivery {let mut delivery=delivery.lock().unwrap_or_else(std::sync::PoisonError::into_inner);delivery.bytes_delivered=delivery.bytes_delivered.saturating_add(delivered);}}
                        if !good {break;}
                    }
                }
            }
            if let Some(delivery)=&delivery {let mut delivery=delivery.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let outcome=if good {delivery.state.eof_outcome()} else {gateway_domain::DeliveryOutcome::ClientDisconnected};delivery.finish(outcome);}
            if !good {break;}
        }
        let _=socket.close().await;
    }).into_response()
}

fn models(
    state: &DataPlaneState,
    catalog: &dyn ModelCatalog,
    uri: &Uri,
    grant: &AccessGrant,
    request_id: &str,
) -> Response {
    let rate_key = format!("models:{}", grant.platform_key_id).into_boxed_str();
    if let RateDecision::Limited { retry_after } = state.business_rates.allow(rate_key, grant.models_rate) {
        return GatewayError::rate_limited(retry_after).response(request_id);
    }
    let visible = catalog
        .published()
        .iter()
        .filter(|model| model.provider == grant.provider)
        .filter(|model| model_in_scope(&model.id, &grant.group_model_scope))
        .filter(|model| model_in_scope(&model.id, &grant.key_model_scope))
        .cloned()
        .collect::<Vec<_>>();
    if grant.provider == gateway_domain::Provider::Openai {
        if let Some(id) = uri
            .path()
            .strip_prefix("/v1/models/")
            .or_else(|| uri.path().strip_prefix("/models/"))
        {
            let Some(model) = visible.iter().find(|model| model.id.as_ref() == id) else {
                return GatewayError::not_found().response(request_id);
            };
            return with_request_id(Json(serde_json::json!({"id":model.id,"object":"model","created":model.created_at.parse::<i64>().unwrap_or(0),"owned_by":"openai"})).into_response(), request_id);
        }
        if uri.path() == "/backend-api/codex/models"
            || uri
                .query()
                .is_some_and(|query| query.split('&').any(|pair| pair.starts_with("client_version=")))
        {
            let models = visible
                .iter()
                .filter_map(|model| model.openai_metadata.clone())
                .collect::<Vec<_>>();
            return with_request_id(Json(serde_json::json!({"models":models})).into_response(), request_id);
        }
        let data = visible.iter().map(|m| serde_json::json!({"id":m.id,"object":"model","created":m.created_at.parse::<i64>().unwrap_or(0),"owned_by":"openai"})).collect::<Vec<_>>();
        return with_request_id(
            Json(serde_json::json!({"object":"list","data":data})).into_response(),
            request_id,
        );
    }
    let query = match ModelsQuery::parse(uri.query()) {
        Ok(query) => query,
        Err(error) => return error.response(request_id),
    };
    let start = match query.after_id {
        None => 0,
        Some(after_id) => match visible.iter().position(|model| model.id == after_id) {
            Some(index) => index + 1,
            None => return GatewayError::invalid_body().response(request_id),
        },
    };
    let end = start.saturating_add(query.limit).min(visible.len());
    let page = &visible[start..end];
    let response = ModelsResponse {
        data: page.iter().map(ModelDto::from).collect(),
        has_more: end < visible.len(),
        first_id: page.first().map(|model| model.id.as_ref()),
        last_id: page.last().map(|model| model.id.as_ref()),
    };
    with_request_id((StatusCode::OK, Json(response)).into_response(), request_id)
}

#[derive(Clone, Copy)]
enum BusinessRoute {
    OpenAi(gateway_domain::OpenAiEndpoint),
    Messages,
    CountTokens,
    Models,
    Unknown,
}

impl BusinessRoute {
    fn expected_method(self) -> &'static Method {
        match self {
            Self::Messages | Self::CountTokens | Self::OpenAi(_) => &Method::POST,
            Self::Models | Self::Unknown => &Method::GET,
        }
    }

    fn permission(self) -> Option<EndpointPermission> {
        match self {
            Self::Messages | Self::CountTokens | Self::OpenAi(_) => Some(EndpointPermission::Messages),
            Self::Models => Some(EndpointPermission::Models),
            Self::Unknown => None,
        }
    }

    fn method_error(self) -> GatewayError {
        match self {
            Self::Messages | Self::CountTokens | Self::OpenAi(_) => GatewayError::method("POST"),
            Self::Models => GatewayError::method("GET"),
            Self::Unknown => GatewayError::not_found(),
        }
    }
}

fn classify_route(path: &str) -> BusinessRoute {
    match path {
        "/v1/responses" | "/responses" => BusinessRoute::OpenAi(gateway_domain::OpenAiEndpoint::Responses),
        "/v1/chat/completions" | "/chat/completions" => {
            BusinessRoute::OpenAi(gateway_domain::OpenAiEndpoint::ChatCompletions)
        }
        "/v1/responses/compact" | "/responses/compact" => {
            BusinessRoute::OpenAi(gateway_domain::OpenAiEndpoint::Compact)
        }
        "/v1/messages" => BusinessRoute::Messages,
        "/v1/messages/count_tokens" => BusinessRoute::CountTokens,
        "/v1/models" | "/models" | "/backend-api/codex/models" => BusinessRoute::Models,
        path if path.starts_with("/v1/models/") || path.starts_with("/models/") => BusinessRoute::Models,
        _ => BusinessRoute::Unknown,
    }
}

fn authenticate(headers: &mut HeaderMap, access: &dyn AccessResolver) -> Option<Arc<AccessGrant>> {
    let api_values = headers.get_all("x-api-key").iter().collect::<Vec<_>>();
    let auth_values = headers.get_all(header::AUTHORIZATION).iter().collect::<Vec<_>>();
    if api_values.len() > 1 || auth_values.len() > 1 || api_values.is_empty() && auth_values.is_empty() {
        scrub_auth(headers);
        return None;
    }
    let api = api_values
        .first()
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_api_key);
    let bearer = auth_values
        .first()
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_bearer);
    let selected = match (api, bearer) {
        (Some(api), Some(bearer)) if constant_equal(api, bearer) => Some(api),
        (Some(api), None) if auth_values.is_empty() => Some(api),
        (None, Some(bearer)) if api_values.is_empty() => Some(bearer),
        _ => None,
    }
    .map(str::to_owned);
    scrub_auth(headers);
    selected.and_then(|secret| access.resolve(&SecretValue::new(secret)))
}

fn normalize_api_key(value: &str) -> Option<&str> {
    if value.is_empty() || value.trim() != value || value.len() > 512 || value.contains(',') {
        None
    } else {
        Some(value)
    }
}

fn normalize_bearer(value: &str) -> Option<&str> {
    let (scheme, secret) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || secret.contains(' ') {
        return None;
    }
    normalize_api_key(secret)
}

fn constant_equal(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn scrub_auth(headers: &mut HeaderMap) {
    headers.remove("x-api-key");
    headers.remove(header::AUTHORIZATION);
}

fn validate_framing(headers: &HeaderMap) -> Result<(), GatewayError> {
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers.get_all(header::CONTENT_LENGTH).iter().count() > 1
        || headers.get_all(header::TRANSFER_ENCODING).iter().count() > 1
        || headers.contains_key(header::CONTENT_LENGTH) && headers.contains_key(header::TRANSFER_ENCODING)
    {
        return Err(GatewayError::invalid_body());
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(GatewayError::invalid_body)?;
    if !valid_content_type(content_type) {
        return Err(GatewayError::invalid_body());
    }
    if headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err(GatewayError::invalid_body());
    }
    if headers.contains_key(header::CONTENT_LENGTH) && content_length(headers).is_none() {
        return Err(GatewayError::invalid_body());
    }
    Ok(())
}

fn valid_content_type(value: &str) -> bool {
    let mut parts = value.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|media| media.eq_ignore_ascii_case(CONTENT_TYPE_JSON))
    {
        return false;
    }
    parts.all(|parameter| {
        parameter.split_once('=').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("charset") && value.trim().eq_ignore_ascii_case("utf-8")
        })
    })
}

fn content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn source_ip(request: &Request, trusted: &TrustedProxyConfig) -> IpAddr {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(DEFAULT_PEER, |ConnectInfo(address)| address.ip());
    if !trusted.contains(peer) {
        return peer;
    }
    let Some(forwarded) = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    else {
        return peer;
    };
    let mut chain = forwarded
        .split(',')
        .map(str::trim)
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();
    chain.push(peer);
    chain
        .into_iter()
        .rev()
        .find(|address| !trusted.contains(*address))
        .unwrap_or(peer)
}

struct ClassifiedClient {
    class: ClientClass,
    base_session: SessionId,
    agent: AgentId,
    session_cache_key: Option<Box<str>>,
    identity_conflict: bool,
}

fn classify_client(headers: &HeaderMap, tree: &Value, platform_key_id: &PlatformKeyId) -> ClassifiedClient {
    let mut signals = 0_u8;
    if header_contains(headers, header::USER_AGENT.as_str(), "claude-code") {
        signals += 1;
    }
    if header_string(headers, "x-claude-code-session-id").is_some() {
        signals += 1;
    }
    if header_contains(headers, "x-app", "claude") || header_contains(headers, "x-stainless-lang", "js") {
        signals += 1;
    }
    if tree
        .pointer("/metadata/user_id")
        .and_then(Value::as_str)
        .is_some_and(|value| value.contains("session") || value.starts_with("user_"))
    {
        signals += 1;
    }
    if tree
        .get("system")
        .is_some_and(|system| system.to_string().to_ascii_lowercase().contains("claude code"))
    {
        signals += 1;
    }
    let class = if signals >= 2 {
        ClientClass::ClaudeCodeCli
    } else {
        ClientClass::NonClaudeCodeCli
    };
    let header_session =
        header_string(headers, "x-claude-code-session-id").filter(|value| valid_identity_component(value));
    let session_cache_key = header_session.as_deref().map(|session| {
        let digest = Digest::of(format!("client-os-session:v1|{session}").as_bytes());
        Box::<str>::from(digest.as_str())
    });
    let metadata_session = metadata_session_id(tree).filter(|value| valid_identity_component(value));
    let identity_conflict = header_session
        .as_deref()
        .zip(metadata_session.as_deref())
        .is_some_and(|(header, metadata)| header != metadata);
    let selected_session = if identity_conflict {
        None
    } else {
        header_session.or(metadata_session)
    };
    let session_seed = selected_session.map_or_else(
        || format!("anonymous-session:v1|{}|{class:?}", platform_key_id.as_str()),
        |session| format!("claude-session:v1|{session}"),
    );
    let session_digest = Digest::of(session_seed.as_bytes());
    let base_session = SessionId::new(format!("ses_{}", &session_digest.as_str()[..32]))
        .unwrap_or_else(|_| unreachable_id("ses_fallback"));
    let agent_source = header_string(headers, "x-claude-code-agent-id")
        .filter(|value| valid_identity_component(value))
        .unwrap_or_else(|| Box::from("main"));
    let agent_digest = Digest::of(format!("claude-agent:v1|{agent_source}").as_bytes());
    let agent = AgentId::new(format!("agt_{}", &agent_digest.as_str()[..32]))
        .unwrap_or_else(|_| unreachable_agent("agt_fallback"));
    ClassifiedClient {
        class,
        base_session,
        agent,
        session_cache_key,
        identity_conflict,
    }
}

fn resolve_client_os(
    headers: &HeaderMap,
    tree: &Value,
    default_os: ClientOs,
    session_cache_key: Option<&str>,
    sessions: &crate::ClientOsSessionCache,
) -> (ClientOs, OsResolution, bool) {
    let header_os = header_string(headers, "x-stainless-os").and_then(|value| parse_client_os(&value));
    let environment_os = tree
        .get("system")
        .map(parse_system_segments)
        .and_then(|segments| {
            segments
                .environment
                .and_then(|environment| environment.platform_normalized)
        })
        .map(|os| match os {
            OsFamily::Windows => ClientOs::Windows,
            OsFamily::Macos => ClientOs::MacOs,
            OsFamily::Linux => ClientOs::Linux,
        });
    let mismatch = header_os
        .zip(environment_os)
        .is_some_and(|(header, environment)| header != environment);
    if let Some(os) = header_os {
        if let Some(key) = session_cache_key {
            sessions.remember(key, os);
        }
        return (os, OsResolution::Header, mismatch);
    }
    if let Some(os) = environment_os {
        if let Some(key) = session_cache_key {
            sessions.remember(key, os);
        }
        return (os, OsResolution::EnvironmentOnly, false);
    }
    if let Some(os) = session_cache_key.and_then(|key| sessions.resolve(key)) {
        return (os, OsResolution::SessionSticky, false);
    }
    (default_os, OsResolution::GroupDefault, false)
}

fn parse_client_os(value: &str) -> Option<ClientOs> {
    match value.trim().to_ascii_lowercase().as_str() {
        "windows" => Some(ClientOs::Windows),
        "macos" | "mac_os" | "mac os" => Some(ClientOs::MacOs),
        "linux" => Some(ClientOs::Linux),
        _ => None,
    }
}

fn metadata_session_id(tree: &Value) -> Option<Box<str>> {
    let user_id = tree.pointer("/metadata/user_id")?.as_str()?.trim();
    if let Some((_, suffix)) = user_id.rsplit_once("_session_") {
        return Some(Box::from(suffix.trim()));
    }
    if user_id.starts_with('{') {
        return serde_json::from_str::<Value>(user_id)
            .ok()?
            .get("session_id")?
            .as_str()
            .map(str::trim)
            .map(Box::from);
    }
    None
}

fn valid_identity_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

fn unreachable_id(value: &str) -> SessionId {
    SessionId::new(value).unwrap_or_else(|_| std::process::abort())
}

fn unreachable_agent(value: &str) -> AgentId {
    AgentId::new(value).unwrap_or_else(|_| std::process::abort())
}

fn unreachable_request(value: &str) -> RequestId {
    RequestId::new(value).unwrap_or_else(|_| std::process::abort())
}

fn protocol_headers(headers: &HeaderMap) -> std::collections::BTreeMap<Box<str>, Value> {
    ["anthropic-version", "anthropic-beta"]
        .into_iter()
        .filter_map(|name| {
            header_string(headers, name).map(|value| (Box::<str>::from(name), Value::String(value.into())))
        })
        .collect()
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<Box<str>> {
    let values = headers.get_all(name).iter().collect::<Vec<_>>();
    if values.len() != 1 {
        return None;
    }
    values[0]
        .to_str()
        .ok()
        .filter(|value| !value.is_empty() && value.len() <= 1_024)
        .map(Box::from)
}

fn header_contains(headers: &HeaderMap, name: &str, needle: &str) -> bool {
    header_string(headers, name).is_some_and(|value| value.to_ascii_lowercase().contains(needle))
}

fn model_in_scope(model: &str, scope: &std::collections::BTreeSet<Box<str>>) -> bool {
    scope.is_empty() || scope.contains(model)
}

async fn upstream_response(
    mut response: crate::UpstreamResponse,
    permit: KeyPermit,
    observability: gateway_services::observability::DataPlaneObservability,
    websocket: bool,
) -> Result<Response, ()> {
    if let Some(completion) = response.completion.clone() {
        let usage = response.usage;
        tokio::spawn(async move {
            if let Ok(usage) = usage.await {
                completion.usage_observed(usage).await;
            }
        });
    }
    if let Some(completion) = response.completion.as_ref() {
        completion.committed().await.map_err(|_| ())?;
    }
    observability.response_committed();
    let websocket_completion = websocket.then(|| WebSocketDelivery {
        completion: response.completion.take(),
        state: response.delivery_state.clone(),
        bytes_delivered: 0,
    });
    let nominated = connection_nominated_headers(&response.headers);
    let stream = ClientBodyStream {
        receiver: response.body,
        permit: Some(permit),
        cancellation: response.cancellation,
        completion: response.completion.take(),
        delivery_state: response.delivery_state,
        observability,
        bytes_delivered: 0,
        completed: false,
        _response_admission: response.admission.take(),
    };
    let mut output = Response::new(Body::from_stream(stream));
    if let Some(completion) = websocket_completion {
        output.extensions_mut().insert(Arc::new(Mutex::new(completion)));
    }
    *output.status_mut() = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    for (name, value) in response.headers.drain(..) {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        if !safe_upstream_header(&name, &nominated) {
            continue;
        }
        if let Ok(value) = HeaderValue::from_bytes(&value) {
            output.headers_mut().append(name, value);
        }
    }
    Ok(output)
}

fn connection_nominated_headers(headers: &[(Box<str>, Bytes)]) -> std::collections::BTreeSet<Box<str>> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| {
            String::from_utf8_lossy(value)
                .split(',')
                .map(str::trim)
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>()
        })
        .filter(|value| !value.is_empty())
        .map(String::into_boxed_str)
        .collect()
}

fn safe_upstream_header(name: &HeaderName, nominated: &std::collections::BTreeSet<Box<str>>) -> bool {
    let name = name.as_str();
    !nominated.contains(name)
        && matches!(
            name,
            "content-type"
                | "content-encoding"
                | "content-length"
                | "cache-control"
                | "request-id"
                | "anthropic-request-id"
                | "x-request-id"
        )
}

// The WS socket owns completion; reading its internal SSE body is not delivery.
struct WebSocketDelivery {
    completion: Option<Arc<dyn gateway_services::response::DeliveryCompletion>>,
    state: gateway_services::response::PreparedDeliveryState,
    bytes_delivered: u64,
}

impl WebSocketDelivery {
    fn finish(&mut self, outcome: gateway_domain::DeliveryOutcome) {
        if let Some(completion) = self.completion.take() {
            let report = gateway_services::response::DeliveryReport {
                finished_at: Instant::now(),
                outcome,
                bytes_delivered: self.bytes_delivered,
            };
            tokio::spawn(async move {
                completion.completed(report).await;
            });
        }
    }
}

impl Drop for WebSocketDelivery {
    fn drop(&mut self) {
        self.finish(gateway_domain::DeliveryOutcome::ClientDisconnected);
    }
}

struct ClientBodyStream {
    receiver: tokio::sync::mpsc::Receiver<gateway_services::response::PreparedBodyItem>,
    permit: Option<KeyPermit>,
    cancellation: tokio_util::sync::CancellationToken,
    completion: Option<std::sync::Arc<dyn gateway_services::response::DeliveryCompletion>>,
    delivery_state: gateway_services::response::PreparedDeliveryState,
    observability: gateway_services::observability::DataPlaneObservability,
    bytes_delivered: u64,
    completed: bool,
    _response_admission: Option<gateway_services::response::ResponseReservation>,
}

impl ClientBodyStream {
    fn finish(&mut self, outcome: gateway_domain::DeliveryOutcome) {
        self.completed = true;
        self.permit.take();
        self.observability.delivery_finished(outcome, self.bytes_delivered);
        if let Some(completion) = self.completion.take() {
            let report = gateway_services::response::DeliveryReport {
                finished_at: Instant::now(),
                outcome,
                bytes_delivered: self.bytes_delivered,
            };
            tokio::spawn(async move {
                completion.completed(report).await;
            });
        }
    }
}

impl Stream for ClientBodyStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.receiver.poll_recv(context) {
            std::task::Poll::Ready(Some(Ok(bytes))) => {
                this.bytes_delivered = this.bytes_delivered.saturating_add(bytes.len() as u64);
                std::task::Poll::Ready(Some(Ok(bytes)))
            }
            std::task::Poll::Ready(Some(Err(error))) => {
                let outcome = match error {
                    gateway_services::response::ResponseError::ClientWriteTimeout => {
                        gateway_domain::DeliveryOutcome::ClientWriteTimeout
                    }
                    gateway_services::response::ResponseError::Cancelled
                    | gateway_services::response::ResponseError::ClientDisconnected => {
                        gateway_domain::DeliveryOutcome::ClientDisconnected
                    }
                    _ => gateway_domain::DeliveryOutcome::UpstreamBodyError,
                };
                this.cancellation.cancel();
                this.finish(outcome);
                std::task::Poll::Ready(Some(Err(std::io::Error::other("upstream response body interrupted"))))
            }
            std::task::Poll::Ready(None) => {
                this.finish(this.delivery_state.eof_outcome());
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl Drop for ClientBodyStream {
    fn drop(&mut self) {
        if !self.completed {
            self.cancellation.cancel();
            self.finish(gateway_domain::DeliveryOutcome::ClientDisconnected);
        }
        self.permit.take();
    }
}

fn map_policy_error(error: PolicyError) -> GatewayError {
    match error {
        PolicyError::ModelUnavailable => GatewayError::model_unavailable(),
        PolicyError::Capability(diagnostics) => {
            diagnostics
                .first()
                .map_or_else(GatewayError::invalid_body, |diagnostic| {
                    GatewayError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_request_error",
                        format!("Invalid request at {}: {}.", diagnostic.path, diagnostic.code),
                    )
                })
        }
        PolicyError::CapabilityRuntimeConflict | PolicyError::Serializer => GatewayError::internal(),
        PolicyError::CapabilityPathExpansionLimit | PolicyError::Parse(_) | PolicyError::InvalidStructure => {
            GatewayError::invalid_body()
        }
    }
}

#[derive(Debug)]
struct ModelsQuery {
    limit: usize,
    after_id: Option<Box<str>>,
}

impl ModelsQuery {
    fn parse(query: Option<&str>) -> Result<Self, GatewayError> {
        let mut limit = None;
        let mut after_id = None;
        for pair in query.unwrap_or_default().split('&').filter(|value| !value.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value).ok_or_else(GatewayError::invalid_body)?;
            match name {
                "limit" if limit.is_none() => {
                    let parsed = value.parse::<usize>().map_err(|_| GatewayError::invalid_body())?;
                    if !(1..=100).contains(&parsed) {
                        return Err(GatewayError::invalid_body());
                    }
                    limit = Some(parsed);
                }
                "after_id" if after_id.is_none() && !value.is_empty() => after_id = Some(value.into_boxed_str()),
                _ => return Err(GatewayError::invalid_body()),
            }
        }
        Ok(Self {
            limit: limit.unwrap_or(20),
            after_id,
        })
    }
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let high = hex(bytes[index + 1])?;
                let low = hex(bytes[index + 2])?;
                output.push(high * 16 + low);
                index += 3;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(output).ok()
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Serialize)]
struct ModelDto<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    display_name: &'a str,
    created_at: &'a str,
}

impl<'a> From<&'a ModelRecord> for ModelDto<'a> {
    fn from(model: &'a ModelRecord) -> Self {
        Self {
            id: &model.id,
            kind: "model",
            display_name: &model.display_name,
            created_at: &model.created_at,
        }
    }
}

#[derive(Serialize)]
struct ModelsResponse<'a> {
    data: Vec<ModelDto<'a>>,
    has_more: bool,
    first_id: Option<&'a str>,
    last_id: Option<&'a str>,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    error: ErrorDetail<'a>,
    request_id: &'a str,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    message: &'a str,
}

struct GatewayError {
    status: StatusCode,
    kind: &'static str,
    message: String,
    retry_after: Option<u64>,
    allow: Option<&'static str>,
}

impl GatewayError {
    fn new(status: StatusCode, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            kind,
            message: message.into(),
            retry_after: None,
            allow: None,
        }
    }

    fn authentication() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "authentication_error", "Invalid API key.")
    }

    fn permission() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "permission_error",
            "This request is not permitted.",
        )
    }

    fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found_error",
            "The requested resource could not be found.",
        )
    }

    fn method(allow: &'static str) -> Self {
        let mut error = Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "invalid_request_error",
            "Method not allowed.",
        );
        error.allow = Some(allow);
        error
    }

    fn invalid_body() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "Invalid request body.",
        )
    }

    fn model_unavailable() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "The requested model is not available for this API key.",
        )
    }

    fn bundle_unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "bundle_unavailable",
            "The requested client environment is temporarily unavailable.",
        )
    }

    fn too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            "Request is too large.",
        )
    }

    fn rate_limited(retry_after: u64) -> Self {
        let mut error = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            "Rate limit exceeded.",
        );
        error.retry_after = Some(retry_after.max(1));
        error
    }

    fn unavailable(retry_after: u64) -> Self {
        let mut error = Self::new(StatusCode::SERVICE_UNAVAILABLE, "api_error", "Service unavailable.");
        error.retry_after = Some(retry_after.max(1));
        error
    }

    fn unavailable_without_retry() -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "api_error", "Service unavailable.")
    }

    fn timeout() -> Self {
        Self::new(StatusCode::GATEWAY_TIMEOUT, "timeout_error", "Request timed out.")
    }

    fn internal() -> Self {
        let mut error = Self::new(StatusCode::INTERNAL_SERVER_ERROR, "api_error", "Internal server error.");
        error.retry_after = Some(1);
        error
    }

    fn response(&self, request_id: &str) -> Response {
        let body = ErrorEnvelope {
            kind: "error",
            error: ErrorDetail {
                kind: self.kind,
                message: &self.message,
            },
            request_id,
        };
        let mut response = (self.status, Json(body)).into_response();
        if let Some(retry_after) = self.retry_after
            && let Ok(value) = HeaderValue::from_str(&retry_after.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        if let Some(allow) = self.allow {
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static(allow));
        }
        with_request_id(response, request_id)
    }
}

fn with_request_id(mut response: Response, request_id: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("request-id"), value);
    }
    response
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use axum::{body::Body, http::Request};
    use bytes::Bytes;
    use gateway_domain::{
        ApplicationLifecycle, ClientClass, ClientOs, InternalReadiness, RequestSnapshotSet, SecretValue,
        SnapshotVersion, SystemClock,
    };
    use gateway_policy::RequestPolicy;
    use gateway_services::ReadinessCoordinator;
    use http::{HeaderMap, HeaderValue, StatusCode};
    use http_body_util::BodyExt as _;
    use serde_json::Value;
    use tower::ServiceExt as _;

    use super::{BusinessRateLimiter, KeyConcurrencyLimiter, TrustedProxyConfig, classify_client, data_plane_router};
    use crate::{
        AccessGrant, DataPlaneState, DispatchEndpoint, DispatchError, DispatchRequest, EndpointPermission,
        InMemoryAccessResolver, MessageDispatcher, ModelRecord, ProbeRateLimit, ProbeRateLimiter, ProbeState,
        RateLimit, StaticModelCatalog, UpstreamResponse,
    };

    #[derive(Default)]
    struct CapturingDispatcher {
        captured: Mutex<Vec<DispatchRequest>>,
        next_error: Mutex<Option<DispatchError>>,
    }

    #[derive(Default)]
    struct RecordingCompletion(Mutex<Vec<gateway_services::response::DeliveryReport>>);

    #[async_trait]
    impl gateway_services::response::DeliveryCompletion for RecordingCompletion {
        async fn committed(&self) -> Result<(), gateway_services::response::DeliveryCompletionError> {
            Ok(())
        }
        async fn completed(&self, report: gateway_services::response::DeliveryReport) {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push(report);
        }
    }

    #[tokio::test]
    async fn websocket_completion_waits_for_socket_delivery_and_is_exactly_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let completion = Arc::new(RecordingCompletion::default());
        let mut prepared = UpstreamResponse::from_bytes(200, vec![], Bytes::from_static(b"fixture"));
        prepared.completion = Some(completion.clone());
        let limiter = KeyConcurrencyLimiter::default();
        let key = gateway_domain::PlatformKeyId::new("key-timing")?;
        let permit = limiter.try_acquire(&key, 1).ok_or("permit")?;
        let mut response = super::upstream_response(prepared, permit, Default::default(), true)
            .await
            .map_err(|()| "response")?;
        let delivery = response
            .extensions_mut()
            .remove::<Arc<Mutex<super::WebSocketDelivery>>>()
            .ok_or("completion")?;
        response.into_body().collect().await?;
        tokio::task::yield_now().await;
        assert!(completion.0.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
        let socket_finished = std::time::Instant::now();
        {
            let mut delivery = delivery.lock().unwrap_or_else(|e| e.into_inner());
            delivery.bytes_delivered = 42;
            delivery.finish(gateway_domain::DeliveryOutcome::Complete);
            delivery.finish(gateway_domain::DeliveryOutcome::ClientDisconnected);
        }
        drop(delivery);
        tokio::task::yield_now().await;
        let reports = completion.0.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].bytes_delivered, 42);
        assert!(reports[0].finished_at >= socket_finished);
        Ok(())
    }

    #[tokio::test]
    async fn caller_version_and_ingress_timestamp_survive_dispatch() -> Result<(), Box<dyn std::error::Error>> {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let started = std::time::Instant::now();
        let response = test_app(dispatcher.clone())
            .oneshot(
                Request::post("/v1/messages")
                    .header("content-type", "application/json")
                    .header("x-api-key", "platform-secret")
                    .header("user-agent", "claude-cli/2.1.245 (external, cli)")
                    .body(Body::from(
                        r#"{"model":"model-a","max_tokens":32,"messages":[{"role":"user","content":"fixture"}]}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), 200);
        let captured = dispatcher.captured.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(captured[0].client_identity.version.as_deref(), Some("2.1.245"));
        assert!(captured[0].started_at >= started);
        Ok(())
    }

    #[async_trait]
    impl MessageDispatcher for CapturingDispatcher {
        async fn dispatch(&self, request: DispatchRequest) -> Result<UpstreamResponse, DispatchError> {
            self.captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request);
            if let Some(error) = self
                .next_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                return Err(error);
            }
            Ok(UpstreamResponse::from_bytes(
                StatusCode::OK.as_u16(),
                vec![
                    (Box::from("request-id"), Bytes::from_static(b"upstream-1")),
                    (Box::from("content-type"), Bytes::from_static(b"application/json")),
                    (Box::from("connection"), Bytes::from_static(b"x-hop")),
                    (Box::from("x-hop"), Bytes::from_static(b"must-not-leak")),
                    (Box::from("set-cookie"), Bytes::from_static(b"must-not-leak")),
                ],
                Bytes::from_static(br#"{"type":"message","id":"msg_1"}"#),
            ))
        }
    }

    fn snapshots() -> Arc<RequestSnapshotSet> {
        let v = || SnapshotVersion::new("v1");
        Arc::new(RequestSnapshotSet {
            access_policy: v(),
            group_config: v(),
            enforcement: v(),
            ruleset: None,
            capability: v(),
            client_profile_catalog: v(),
            price: v(),
            serializer: v(),
        })
    }

    fn test_app(dispatcher: Arc<CapturingDispatcher>) -> axum::Router {
        let policy = Arc::new(
            RequestPolicy::base_for_models(["model-a", "model-b"], snapshots())
                .unwrap_or_else(|error| panic!("test policy must compile: {error}")),
        );
        let grant = Arc::new(AccessGrant {
            provider: gateway_domain::Provider::Anthropic,
            owner_user_id: gateway_domain::UserId::new("user-1").unwrap_or_else(|error| panic!("id: {error}")),
            platform_key_id: gateway_domain::PlatformKeyId::new("key-1").unwrap_or_else(|error| panic!("id: {error}")),
            group_id: gateway_domain::GroupId::new("group-1").unwrap_or_else(|error| panic!("id: {error}")),
            permissions: BTreeSet::from([EndpointPermission::Messages, EndpointPermission::Models]),
            key_model_scope: BTreeSet::from([Box::from("model-a")]),
            group_model_scope: BTreeSet::new(),
            body_limit_bytes: 1024 * 1024,
            messages_rate: RateLimit {
                requests_per_minute: 10_000,
                burst: 100,
            },
            count_tokens_rate: RateLimit {
                requests_per_minute: 10_000,
                burst: 100,
            },
            models_rate: RateLimit::DEFAULT_MODELS,
            concurrency_limit: 5,
            ip_allowlist: Vec::new(),
            accepted_client_classes: BTreeSet::from([ClientClass::ClaudeCodeCli, ClientClass::NonClaudeCodeCli]),
            default_os_family: ClientOs::Windows,
            policy,
        });
        let access = Arc::new(InMemoryAccessResolver::new(vec![(
            SecretValue::new("platform-secret".to_owned()),
            grant,
        )]));
        let readiness = ReadinessCoordinator::new(InternalReadiness {
            lifecycle: ApplicationLifecycle::Serving,
            static_configuration_ready: true,
            database_schema_ready: true,
            bootstrap_ready: true,
            business_key_provider_ready: true,
            active_configuration_ready: true,
            transport_core_ready: true,
            required_bundles_ready: true,
        });
        let clock: Arc<dyn gateway_domain::Clock> = Arc::new(SystemClock::new());
        let probe = ProbeState::new(
            readiness,
            Arc::new(ProbeRateLimiter::new(ProbeRateLimit::default(), clock.clone())),
        );
        let runtime = crate::ManagementRuntimeBridge::new(
            access,
            Arc::new(StaticModelCatalog::new(vec![
                ModelRecord {
                    provider: gateway_domain::Provider::Anthropic,
                    openai_metadata: None,
                    id: Box::from("model-a"),
                    display_name: Box::from("Model A"),
                    created_at: Box::from("2026-08-24T00:00:00Z"),
                },
                ModelRecord {
                    provider: gateway_domain::Provider::Anthropic,
                    openai_metadata: None,
                    id: Box::from("model-b"),
                    display_name: Box::from("Model B"),
                    created_at: Box::from("2026-08-24T00:00:00Z"),
                },
            ])),
        );
        data_plane_router(DataPlaneState {
            probe,
            runtime,
            dispatcher,
            observability: gateway_services::observability::DataPlaneObservability::default(),
            business_rates: BusinessRateLimiter::new(clock.clone()),
            client_os_sessions: crate::ClientOsSessionCache::new(clock, Duration::from_hours(24), 1_024),
            concurrency: KeyConcurrencyLimiter::default(),
            spend_authorizer: Arc::new(crate::AllowAllSpendAuthorizer),
            trusted_proxies: TrustedProxyConfig::default(),
            platform_body_limit_bytes: 64 * 1024 * 1024,
        })
    }

    fn messages_request(key: Option<&str>) -> Request<Body> {
        let mut builder = Request::post("/v1/messages").header("content-type", "application/json");
        if let Some(key) = key {
            builder = builder.header("x-api-key", key);
        }
        builder
            .body(Body::from(
                br#"{"model":"model-a","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}"#.as_slice(),
            ))
            .unwrap_or_else(|error| panic!("request: {error}"))
    }

    #[tokio::test]
    async fn route_and_method_are_auth_first_and_count_tokens_is_forwarded() -> Result<(), Box<dyn std::error::Error>> {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let app = test_app(dispatcher.clone());
        let invalid_unknown = app
            .clone()
            .oneshot(Request::post("/v1/messages/count_tokens").body(Body::empty())?)
            .await?;
        assert_eq!(invalid_unknown.status(), 401);
        let valid_count_tokens = app
            .clone()
            .oneshot(
                Request::post("/v1/messages/count_tokens")
                    .header("x-api-key", "platform-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"model":"model-a","messages":[{"role":"user","content":"hello"}]}"#.as_slice(),
                    ))?,
            )
            .await?;
        assert_eq!(valid_count_tokens.status(), 200);
        {
            let captured = dispatcher
                .captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(captured.len(), 1);
            assert_eq!(captured[0].endpoint, DispatchEndpoint::CountTokens);
        }
        let invalid_method = app
            .oneshot(
                Request::get("/v1/messages")
                    .header("x-api-key", "platform-secret")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(invalid_method.status(), 405);
        assert_eq!(invalid_method.headers()["allow"], "POST");
        Ok(())
    }

    #[tokio::test]
    async fn dual_auth_must_match_and_platform_identity_never_reaches_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let app = test_app(dispatcher.clone());
        let conflict = app
            .clone()
            .oneshot(
                Request::post("/v1/messages")
                    .header("content-type", "application/json")
                    .header("x-api-key", "platform-secret")
                    .header("authorization", "Bearer other")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(conflict.status(), 401);
        let success = app
            .oneshot(
                Request::post("/v1/messages")
                    .header("content-type", "application/json")
                    .header("x-api-key", "platform-secret")
                    .header("authorization", "Bearer platform-secret")
                    .header("user-agent", "identity-canary")
                    .body(Body::from(
                        br#"{"model":"model-a","max_tokens":32,"messages":[]}"#.as_slice(),
                    ))?,
            )
            .await?;
        assert_eq!(success.status(), 200);
        let captured = dispatcher
            .captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let debug = format!("{:?}", captured[0]);
        assert!(!debug.contains("platform-secret"));
        assert!(!debug.contains("identity-canary"));
        let headers = captured[0].original_headers.as_ref().ok_or("missing ingress headers")?;
        assert!(
            headers
                .entries
                .iter()
                .any(|h| h.name == "user-agent" && h.value == "identity-canary")
        );
        assert!(
            headers
                .entries
                .iter()
                .filter(|h| h.name == "authorization" || h.name == "x-api-key")
                .all(|h| h.redacted && h.value == "[REDACTED]")
        );
        Ok(())
    }

    #[tokio::test]
    async fn messages_preserve_upstream_body_and_model_scope() -> Result<(), Box<dyn std::error::Error>> {
        let app = test_app(Arc::new(CapturingDispatcher::default()));
        let response = app.clone().oneshot(messages_request(Some("platform-secret"))).await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["request-id"], "upstream-1");
        assert_eq!(response.headers()["content-type"], "application/json");
        assert!(!response.headers().contains_key("connection"));
        assert!(!response.headers().contains_key("x-hop"));
        assert!(!response.headers().contains_key("set-cookie"));
        let body = response.into_body().collect().await?.to_bytes();
        assert_eq!(body.as_ref(), br#"{"type":"message","id":"msg_1"}"#);

        let denied = app
            .oneshot(
                Request::post("/v1/messages")
                    .header("content-type", "application/json")
                    .header("x-api-key", "platform-secret")
                    .body(Body::from(
                        br#"{"model":"model-b","max_tokens":32,"messages":[]}"#.as_slice(),
                    ))?,
            )
            .await?;
        assert_eq!(denied.status(), 400);
        Ok(())
    }

    #[tokio::test]
    async fn upstream_deadline_uses_stable_timeout_envelope() -> Result<(), Box<dyn std::error::Error>> {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        *dispatcher
            .next_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(DispatchError::DeadlineExceeded);
        let response = test_app(dispatcher)
            .oneshot(messages_request(Some("platform-secret")))
            .await?;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(!response.headers().contains_key("retry-after"));
        let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
        assert_eq!(body["error"]["type"], "timeout_error");
        assert_eq!(body["error"]["message"], "Request timed out.");
        Ok(())
    }

    #[tokio::test]
    async fn pre_upstream_timeout_is_retryable_service_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        *dispatcher
            .next_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(DispatchError::PreUpstreamTimeout { retry_after_seconds: 5 });
        let response = test_app(dispatcher)
            .oneshot(messages_request(Some("platform-secret")))
            .await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["retry-after"], "5");
        Ok(())
    }

    #[tokio::test]
    async fn platform_key_permit_is_held_until_client_body_drop() -> Result<(), Box<dyn std::error::Error>> {
        let app = test_app(Arc::new(CapturingDispatcher::default()));
        let mut active = Vec::new();
        for _ in 0..5 {
            let response = app.clone().oneshot(messages_request(Some("platform-secret"))).await?;
            assert_eq!(response.status(), 200);
            active.push(response);
        }
        let saturated = app.clone().oneshot(messages_request(Some("platform-secret"))).await?;
        assert_eq!(saturated.status(), 429);

        drop(active.pop());
        let admitted = app.oneshot(messages_request(Some("platform-secret"))).await?;
        assert_eq!(admitted.status(), 200);
        Ok(())
    }

    #[tokio::test]
    async fn models_are_stable_scoped_and_paginated() -> Result<(), Box<dyn std::error::Error>> {
        let app = test_app(Arc::new(CapturingDispatcher::default()));
        let response = app
            .oneshot(
                Request::get("/v1/models?limit=1")
                    .header("authorization", "Bearer platform-secret")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), 200);
        let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
        assert_eq!(body["data"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["data"][0]["id"], "model-a");
        assert_eq!(body["has_more"], false);
        Ok(())
    }

    #[tokio::test]
    async fn framing_and_duplicate_json_are_rejected_before_dispatch() -> Result<(), Box<dyn std::error::Error>> {
        let dispatcher = Arc::new(CapturingDispatcher::default());
        let app = test_app(dispatcher.clone());
        let framing = app
            .clone()
            .oneshot(
                Request::post("/v1/messages")
                    .header("x-api-key", "platform-secret")
                    .header("content-type", "application/json")
                    .header("content-length", "2")
                    .header("transfer-encoding", "chunked")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(framing.status(), 400);
        let duplicate = app
            .oneshot(
                Request::post("/v1/messages")
                    .header("x-api-key", "platform-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"model":"model-a","model":"model-a","max_tokens":1,"messages":[]}"#.as_slice(),
                    ))?,
            )
            .await?;
        assert_eq!(duplicate.status(), 400);
        assert!(
            dispatcher
                .captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn session_is_stable_per_key_and_subagents_are_distinct() -> Result<(), Box<dyn std::error::Error>> {
        let key = gateway_domain::PlatformKeyId::new("key-1")?;
        let body = serde_json::json!({
            "metadata": {"user_id": "account_session_11111111-1111-1111-1111-111111111111"}
        });
        let mut main_headers = HeaderMap::new();
        main_headers.insert("user-agent", HeaderValue::from_static("claude-code/2.1.220"));
        main_headers.insert(
            "x-claude-code-session-id",
            HeaderValue::from_static("11111111-1111-1111-1111-111111111111"),
        );
        let main = classify_client(&main_headers, &body, &key);
        let repeated = classify_client(&main_headers, &body, &key);
        assert_eq!(main.base_session, repeated.base_session);
        assert_eq!(main.agent, repeated.agent);
        assert_eq!(main.class, ClientClass::ClaudeCodeCli);

        let mut subagent_headers = main_headers.clone();
        subagent_headers.insert("x-claude-code-agent-id", HeaderValue::from_static("subagent-9"));
        let subagent = classify_client(&subagent_headers, &body, &key);
        assert_eq!(main.base_session, subagent.base_session);
        assert_ne!(main.agent, subagent.agent);
        Ok(())
    }

    #[test]
    fn one_key_with_forty_requests_gets_five_hard_permits() -> Result<(), Box<dyn std::error::Error>> {
        let limiter = KeyConcurrencyLimiter::default();
        let key = gateway_domain::PlatformKeyId::new("key-40")?;
        let permits = (0..5).filter_map(|_| limiter.try_acquire(&key, 5)).collect::<Vec<_>>();
        assert_eq!(permits.len(), 5);
        let rejected = (0..35).filter(|_| limiter.try_acquire(&key, 5).is_none()).count();
        assert_eq!(rejected, 35);
        drop(permits);
        assert!(limiter.try_acquire(&key, 5).is_some());
        Ok(())
    }

    #[tokio::test]
    async fn platform_errors_do_not_echo_identity_canaries() -> Result<(), Box<dyn std::error::Error>> {
        let app = test_app(Arc::new(CapturingDispatcher::default()));
        let response = app
            .oneshot(
                Request::post("/v1/messages")
                    .header("x-api-key", "synthetic-platform-key-canary")
                    .header("user-agent", "synthetic-client-identity-canary")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(response.status(), 401);
        let rendered = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
        assert!(!rendered.contains("synthetic-platform-key-canary"));
        assert!(!rendered.contains("synthetic-client-identity-canary"));
        Ok(())
    }
}
