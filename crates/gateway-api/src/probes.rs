//! Privacy-safe health and readiness endpoints.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension},
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use gateway_domain::{Clock, PublicReadiness};
use gateway_services::ReadinessCoordinator;
use serde::Serialize;

const RESPONSE_SOURCE_HEADER: HeaderName = HeaderName::from_static("x-gateway-response-source");
const RESPONSE_SOURCE_VALUE: HeaderValue = HeaderValue::from_static("gateway");
const DEFAULT_PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Health/readiness source-IP token bucket configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeRateLimit {
    /// Refill rate in requests per minute.
    pub requests_per_minute: u32,
    /// Maximum accumulated tokens.
    pub burst: u32,
}

impl Default for ProbeRateLimit {
    fn default() -> Self {
        Self {
            requests_per_minute: 120,
            burst: 20,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Duration,
}

/// Process-local limiter isolated from every business rate/concurrency budget.
pub struct ProbeRateLimiter {
    config: ProbeRateLimit,
    clock: Arc<dyn Clock>,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl ProbeRateLimiter {
    /// Create a limiter with an injected deterministic clock.
    #[must_use]
    pub fn new(config: ProbeRateLimit, clock: Arc<dyn Clock>) -> Self {
        Self {
            config,
            clock,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, peer: IpAddr) -> ProbeDecision {
        let now = self.clock.now().monotonic;
        let mut buckets = self.lock_buckets();
        if buckets.len() > 4_096 {
            let stale_before = now.saturating_sub(Duration::from_mins(10));
            buckets.retain(|_, bucket| bucket.last_refill >= stale_before);
        }
        let burst = f64::from(self.config.burst);
        let refill_per_second = f64::from(self.config.requests_per_minute) / 60.0;
        let bucket = buckets.entry(peer).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
        });
        let elapsed = now.saturating_sub(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_second).min(burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            ProbeDecision::Allowed
        } else {
            let seconds = ((1.0 - bucket.tokens) / refill_per_second).ceil().max(1.0);
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let retry_after_seconds = seconds as u64;
            ProbeDecision::RateLimited { retry_after_seconds }
        }
    }

    fn lock_buckets(&self) -> MutexGuard<'_, HashMap<IpAddr, Bucket>> {
        self.buckets.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

enum ProbeDecision {
    Allowed,
    RateLimited { retry_after_seconds: u64 },
}

/// Shared state for the unauthenticated probes.
#[derive(Clone)]
pub struct ProbeState {
    readiness: ReadinessCoordinator,
    limiter: Arc<ProbeRateLimiter>,
}

impl ProbeState {
    /// Construct isolated probe state.
    #[must_use]
    pub fn new(readiness: ReadinessCoordinator, limiter: Arc<ProbeRateLimiter>) -> Self {
        Self { readiness, limiter }
    }
}

#[derive(Serialize)]
struct ProbeBody {
    status: &'static str,
}

/// Build the probe routes with isolated state carried as an extension.
pub(crate) fn probe_router<S>(state: ProbeState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::<S>::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .layer(Extension(state))
}

async fn health(
    Extension(state): Extension<ProbeState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    respond_with_limit(&state, peer_ip(connect), StatusCode::OK, "ok")
}

async fn ready(
    Extension(state): Extension<ProbeState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    let (status_code, status) = match state.readiness.public() {
        PublicReadiness::Ready => (StatusCode::OK, "ready"),
        PublicReadiness::NotReady => (StatusCode::SERVICE_UNAVAILABLE, "not_ready"),
    };
    respond_with_limit(&state, peer_ip(connect), status_code, status)
}

fn peer_ip(connect: Option<Extension<ConnectInfo<SocketAddr>>>) -> IpAddr {
    connect.map_or(DEFAULT_PEER, |Extension(ConnectInfo(address))| address.ip())
}

fn respond_with_limit(state: &ProbeState, peer: IpAddr, status_code: StatusCode, status: &'static str) -> Response {
    let mut response = match state.limiter.allow(peer) {
        ProbeDecision::Allowed => (status_code, Json(ProbeBody { status })).into_response(),
        ProbeDecision::RateLimited { retry_after_seconds } => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ProbeBody { status: "rate_limited" }),
            )
                .into_response();
            if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
    };
    response
        .headers_mut()
        .insert(RESPONSE_SOURCE_HEADER, RESPONSE_SOURCE_VALUE);
    response
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{body::Body, http::Request};
    use gateway_domain::{ApplicationLifecycle, InternalReadiness, SystemClock};
    use gateway_services::ReadinessCoordinator;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::{ProbeRateLimit, ProbeRateLimiter, ProbeState, probe_router};

    fn ready_state() -> ReadinessCoordinator {
        ReadinessCoordinator::new(InternalReadiness {
            lifecycle: ApplicationLifecycle::Serving,
            static_configuration_ready: true,
            database_schema_ready: true,
            bootstrap_ready: true,
            business_key_provider_ready: true,
            audit_integrity_ready: true,
            active_configuration_ready: true,
            transport_core_ready: true,
            required_bundles_ready: true,
            content_audit_ready: true,
        })
    }

    fn router(readiness: ReadinessCoordinator, rate: ProbeRateLimit) -> axum::Router {
        let limiter = Arc::new(ProbeRateLimiter::new(rate, Arc::new(SystemClock::new())));
        probe_router(ProbeState::new(readiness, limiter))
    }

    #[tokio::test]
    async fn health_body_is_fixed_and_private() -> Result<(), Box<dyn std::error::Error>> {
        let response = router(ready_state(), ProbeRateLimit::default())
            .oneshot(Request::get("/healthz").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["x-gateway-response-source"], "gateway");
        let bytes = response.into_body().collect().await?.to_bytes();
        assert_eq!(bytes.as_ref(), br#"{"status":"ok"}"#);
        Ok(())
    }

    #[tokio::test]
    async fn readiness_exposes_only_overall_status() -> Result<(), Box<dyn std::error::Error>> {
        let readiness = ReadinessCoordinator::default();
        let response = router(readiness, ProbeRateLimit::default())
            .oneshot(Request::get("/readyz").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), 503);
        let bytes = response.into_body().collect().await?.to_bytes();
        assert_eq!(bytes.as_ref(), br#"{"status":"not_ready"}"#);
        Ok(())
    }

    #[tokio::test]
    async fn readiness_returns_ready_after_all_hard_checks() -> Result<(), Box<dyn std::error::Error>> {
        let response = router(ready_state(), ProbeRateLimit::default())
            .oneshot(Request::get("/readyz").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), 200);
        let bytes = response.into_body().collect().await?.to_bytes();
        assert_eq!(bytes.as_ref(), br#"{"status":"ready"}"#);
        Ok(())
    }

    #[tokio::test]
    async fn probe_limiter_is_independent_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let app = router(
            ready_state(),
            ProbeRateLimit {
                requests_per_minute: 1,
                burst: 1,
            },
        );
        let first = app
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty())?)
            .await?;
        let second = app.oneshot(Request::get("/healthz").body(Body::empty())?).await?;
        assert_eq!(first.status(), 200);
        assert_eq!(second.status(), 429);
        assert_eq!(second.headers()["retry-after"], "60");
        assert_eq!(second.headers()["x-gateway-response-source"], "gateway");
        let bytes = second.into_body().collect().await?.to_bytes();
        assert_eq!(bytes.as_ref(), br#"{"status":"rate_limited"}"#);
        Ok(())
    }
}
