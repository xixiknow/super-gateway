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

/// One proxy hop of an egress route: a TCP endpoint plus the tunnel protocol
/// spoken on it. TLS-protected hops terminate their own TLS before tunneling.
#[derive(Clone, Debug)]
pub enum ProxyHop {
    /// HTTP CONNECT tunnel in cleartext TCP.
    HttpConnect {
        /// Proxy host or IP.
        host: Box<str>,
        /// Proxy TCP port.
        port: u16,
        /// Optional Basic credentials, redacted and zeroized by the domain secret types.
        credentials: Option<Arc<ProxyCredentials>>,
    },
    /// HTTP CONNECT tunnel over TLS to the proxy itself.
    HttpsConnect {
        /// Proxy host or IP.
        host: Box<str>,
        /// Proxy TCP port.
        port: u16,
        /// Optional Basic credentials, redacted and zeroized by the domain secret types.
        credentials: Option<Arc<ProxyCredentials>>,
    },
    /// SOCKS5 tunnel in cleartext TCP.
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

impl ProxyHop {
    /// Map a persisted proxy protocol code to one hop. SOCKS5 resolves names proxy-side.
    ///
    /// Returns `None` for unknown protocol codes.
    #[must_use]
    pub fn from_row(
        proxy_type_code: &str,
        host: Box<str>,
        port: u16,
        credentials: Option<Arc<ProxyCredentials>>,
    ) -> Option<Self> {
        match proxy_type_code {
            "http_connect" => Some(Self::HttpConnect {
                host,
                port,
                credentials,
            }),
            "https_connect" => Some(Self::HttpsConnect {
                host,
                port,
                credentials,
            }),
            "socks5" => Some(Self::Socks5 {
                host,
                port,
                dns: Socks5DnsMode::Remote,
                credentials,
            }),
            _ => None,
        }
    }

    /// TCP endpoint this hop dials.
    #[must_use]
    pub fn endpoint(&self) -> (&str, u16) {
        match self {
            Self::HttpConnect { host, port, .. }
            | Self::HttpsConnect { host, port, .. }
            | Self::Socks5 { host, port, .. } => (host.as_ref(), *port),
        }
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
    /// Establish a TLS pass-through HTTP CONNECT tunnel over TLS to the proxy itself.
    HttpsConnect {
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
    /// Primary proxy reached through a relay (first-hop) proxy. The gateway dials
    /// the primary directly first; the relay path is used only when the direct
    /// attempt fails with an unreachable-class error (TCP/DNS/timeout).
    WithRelay {
        /// Final proxy hop, tunneling to the fixed provider target.
        primary: Box<ProxyHop>,
        /// Relay hop dialed first, tunneling to the primary endpoint.
        relay: Box<ProxyHop>,
    },
}

impl EgressRouteSnapshot {
    /// Map a persisted proxy protocol code to a frozen route. SOCKS5 resolves names proxy-side.
    ///
    /// Returns `None` for unknown protocol codes.
    #[must_use]
    pub fn from_proxy_row(
        proxy_type_code: &str,
        host: Box<str>,
        port: u16,
        credentials: Option<Arc<ProxyCredentials>>,
    ) -> Option<Self> {
        match proxy_type_code {
            "http_connect" => Some(Self::HttpConnect {
                host,
                port,
                credentials,
            }),
            "https_connect" => Some(Self::HttpsConnect {
                host,
                port,
                credentials,
            }),
            "socks5" => Some(Self::Socks5 {
                host,
                port,
                dns: Socks5DnsMode::Remote,
                credentials,
            }),
            _ => None,
        }
    }

    /// Assemble a frozen route from fully resolved hops. A relay present on a
    /// proxy route turns it into a [`Self::WithRelay`] fallback route; without
    /// one this restores the single-hop variant.
    #[must_use]
    pub fn from_hops(primary: ProxyHop, relay: Option<ProxyHop>) -> Self {
        match relay {
            None => match primary {
                ProxyHop::HttpConnect {
                    host,
                    port,
                    credentials,
                } => Self::HttpConnect {
                    host,
                    port,
                    credentials,
                },
                ProxyHop::HttpsConnect {
                    host,
                    port,
                    credentials,
                } => Self::HttpsConnect {
                    host,
                    port,
                    credentials,
                },
                ProxyHop::Socks5 {
                    host,
                    port,
                    dns,
                    credentials,
                } => Self::Socks5 {
                    host,
                    port,
                    dns,
                    credentials,
                },
            },
            Some(relay) => Self::WithRelay {
                primary: Box::new(primary),
                relay: Box::new(relay),
            },
        }
    }

    /// Whether this route traverses a proxy endpoint.
    #[must_use]
    pub const fn is_proxied(&self) -> bool {
        !matches!(self, Self::Direct)
    }
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

    #[test]
    fn proxy_protocol_codes_map_to_routes() {
        use super::{EgressRouteSnapshot, Socks5DnsMode};
        assert!(matches!(
            EgressRouteSnapshot::from_proxy_row("http_connect", "proxy".into(), 8080, None),
            Some(EgressRouteSnapshot::HttpConnect { port: 8080, .. })
        ));
        assert!(matches!(
            EgressRouteSnapshot::from_proxy_row("https_connect", "proxy".into(), 443, None),
            Some(EgressRouteSnapshot::HttpsConnect { port: 443, .. })
        ));
        assert!(matches!(
            EgressRouteSnapshot::from_proxy_row("socks5", "proxy".into(), 1080, None),
            Some(EgressRouteSnapshot::Socks5 {
                dns: Socks5DnsMode::Remote,
                ..
            })
        ));
        assert!(EgressRouteSnapshot::from_proxy_row("connect", "proxy".into(), 8080, None).is_none());
        assert!(!EgressRouteSnapshot::Direct.is_proxied());
    }

    #[test]
    fn relay_rows_produce_fallback_routes() {
        use super::{EgressRouteSnapshot, ProxyHop, Socks5DnsMode};
        let relay = ProxyHop::from_row("socks5", "relay".into(), 7890, None);
        assert!(matches!(
            &relay,
            Some(ProxyHop::Socks5 {
                dns: Socks5DnsMode::Remote,
                ..
            })
        ));
        let primary = ProxyHop::from_row("http_connect", "proxy".into(), 8080, None);
        assert!(matches!(&primary, Some(ProxyHop::HttpConnect { port: 8080, .. })));
        let Some(relay) = relay else {
            return;
        };
        let Some(primary) = primary else {
            return;
        };
        assert!(matches!(
            EgressRouteSnapshot::from_hops(primary.clone(), Some(relay)),
            EgressRouteSnapshot::WithRelay { .. }
        ));
        assert!(matches!(
            EgressRouteSnapshot::from_hops(primary, None),
            EgressRouteSnapshot::HttpConnect { port: 8080, .. }
        ));
    }
}
