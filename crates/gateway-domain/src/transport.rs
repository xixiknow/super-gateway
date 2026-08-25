//! Immutable values crossing the policy, scheduler and transport boundaries.

use std::{fmt, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    ArchetypeVersionId, AttemptPlanId, CredentialId, CredentialProfileId, DeviceIdentityId, Digest, EgressBindingId,
    ProxyEndpointId, RequestId, SecretValue, TransportBundleId,
};

/// Application protocol selected by a verified Transport Bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpProtocol {
    /// HTTP/1.1 with an ordered low-level writer.
    H1,
    /// HTTP/2 with Bundle-controlled settings and stream behavior.
    H2,
}

/// One ordered upstream header after Profile application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamHeader {
    /// Exact header name/casing selected by the Profile and Bundle.
    pub name: Box<str>,
    /// Exact wire value. Formatting of this type must never be used for audit output.
    pub value: Arc<[u8]>,
}

/// Final Credential-specific request consumed by Transport without JSON reserialization.
#[derive(Clone)]
pub struct FinalUpstreamRequest {
    /// HTTP method, normally `POST`.
    pub method: Box<str>,
    /// Fixed origin scheme.
    pub scheme: Box<str>,
    /// Fixed Anthropic authority.
    pub authority: Box<str>,
    /// Origin-form path and query.
    pub path_and_query: Box<str>,
    /// Exact ordered headers. Hop-by-hop and proxy headers are absent.
    pub headers: Arc<[UpstreamHeader]>,
    /// Exact deterministic request body.
    pub body: Arc<[u8]>,
    /// Whether the response is expected to be an SSE stream.
    pub stream: bool,
}

impl fmt::Debug for FinalUpstreamRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalUpstreamRequest")
            .field("method", &self.method)
            .field("scheme", &self.scheme)
            .field("authority", &self.authority)
            .field("path_and_query", &self.path_and_query)
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .field("body_digest", &Digest::of(&self.body))
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

/// DNS behavior for a SOCKS5 proxy route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socks5DnsMode {
    /// Resolve the fixed Anthropic hostname locally and pass an IP to the proxy.
    Local,
    /// Pass the allowlisted Anthropic hostname to the proxy.
    Remote,
}

/// In-memory proxy authentication material.
pub struct ProxyCredentials {
    /// Username bytes.
    pub username: SecretValue,
    /// Password bytes.
    pub password: SecretValue,
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyCredentials([REDACTED])")
    }
}

/// Frozen route for one Transport Attempt. Transport never re-queries the database.
#[derive(Clone, Debug)]
pub enum EgressRouteSnapshot {
    /// Connect directly from the gateway host.
    Direct,
    /// Establish a TLS pass-through HTTP CONNECT tunnel.
    HttpConnect {
        /// Proxy host or IP.
        host: Box<str>,
        /// Proxy TCP port.
        port: u16,
        /// Optional Basic credentials, redacted and zeroized by the domain secret types.
        credentials: Option<Arc<ProxyCredentials>>,
    },
    /// Establish a TLS pass-through SOCKS5 tunnel.
    Socks5 {
        /// Proxy host or IP.
        host: Box<str>,
        /// Proxy TCP port.
        port: u16,
        /// Local or proxy-side DNS behavior.
        dns: Socks5DnsMode,
        /// Optional username/password credentials.
        credentials: Option<Arc<ProxyCredentials>>,
    },
}

/// Complete immutable identity used by one upstream connection/message attempt.
#[derive(Clone, Debug)]
pub struct AttemptIdentitySnapshot {
    /// Selected Credential.
    pub credential_id: CredentialId,
    /// Access/refresh token generation.
    pub token_version: u64,
    /// Fixed Credential Profile.
    pub profile_id: CredentialProfileId,
    /// Profile/Archetype epoch.
    pub profile_epoch: u64,
    /// Unique device identity.
    pub device_identity_id: DeviceIdentityId,
    /// Device rebuild epoch.
    pub device_epoch: u64,
    /// Selected environment cohort.
    pub archetype_version_id: ArchetypeVersionId,
    /// Verified Bundle artifact.
    pub bundle_id: TransportBundleId,
    /// Bundle artifact version.
    pub bundle_version: u64,
    /// Canonical Bundle payload digest.
    pub bundle_hash: Digest,
    /// Fixed egress binding.
    pub egress_binding_id: EgressBindingId,
    /// Optional proxy used by the binding.
    pub proxy_endpoint_id: Option<ProxyEndpointId>,
    /// Egress rebind epoch.
    pub egress_epoch: u64,
    /// Session derivation algorithm version.
    pub session_derivation_version: u32,
}

/// Deadlines shared by all await points in one Transport Attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptDeadlines {
    /// DNS/TCP/proxy/TLS/ALPN budget.
    pub connect: Duration,
    /// Remaining total upstream budget for non-streaming requests.
    pub upstream_total: Duration,
    /// Streaming read idle timeout.
    pub stream_idle: Duration,
    /// Grace period between cancellation and forced connection termination.
    pub cancel_grace: Duration,
}

impl Default for AttemptDeadlines {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            upstream_total: Duration::from_mins(5),
            stream_idle: Duration::from_secs(30),
            cancel_grace: Duration::from_secs(2),
        }
    }
}

/// Complete request-scoped Transport input before a cancellation token is attached.
#[derive(Clone, Debug)]
pub struct TransportAttemptSnapshot {
    /// Gateway request identity.
    pub request_id: RequestId,
    /// Scheduler attempt-plan identity.
    pub attempt_plan_id: AttemptPlanId,
    /// Frozen Credential/Profile/Egress/Bundle facts.
    pub identity: AttemptIdentitySnapshot,
    /// Frozen Egress route and temporary proxy material.
    pub egress: EgressRouteSnapshot,
    /// Final Profile-specific request.
    pub request: Arc<FinalUpstreamRequest>,
    /// All transport deadlines.
    pub deadlines: AttemptDeadlines,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::FinalUpstreamRequest;

    #[test]
    fn final_request_debug_redacts_headers_and_body() {
        let request = FinalUpstreamRequest {
            method: "POST".into(),
            scheme: "https".into(),
            authority: "api.anthropic.com".into(),
            path_and_query: "/v1/messages".into(),
            headers: Arc::from([]),
            body: Arc::from(br#"{"secret":"transport-canary"}"#.as_slice()),
            stream: true,
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("transport-canary"));
        assert!(rendered.contains("body_digest"));
    }
}
