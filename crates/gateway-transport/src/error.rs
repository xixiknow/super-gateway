//! Stable transport failures and connection disposition facts.

use thiserror::Error;

/// Phase in which a Transport failure occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportPhase {
    /// Bundle selection or compilation.
    Bundle,
    /// Connection pool checkout.
    Pool,
    /// DNS resolution.
    Resolve,
    /// Direct/proxy TCP establishment.
    TcpConnect,
    /// CONNECT or SOCKS5 handshake.
    ProxyTunnel,
    /// TLS handshake and certificate verification.
    TlsHandshake,
    /// ALPN verification.
    Alpn,
    /// Request upload.
    RequestUpload,
    /// Waiting for upstream headers.
    ResponseHeaders,
    /// Reading upstream body/SSE bytes.
    ResponseBody,
    /// Cancellation cleanup.
    Cancel,
}

/// Component or external path to which the failure is attributed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributionDomain {
    /// Name resolution.
    Resolver,
    /// Direct network egress.
    DirectEgress,
    /// Configured proxy.
    Proxy,
    /// Bundle/compiler/wire runtime.
    BundleRuntime,
    /// Anthropic origin or incident.
    AnthropicIncident,
    /// Local process/runtime.
    LocalRuntime,
    /// Client or internal cancellation.
    Cancellation,
}

/// Scope that should be considered unhealthy after a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureScope {
    /// Only this request/stream.
    Attempt,
    /// One pooled connection.
    Connection,
    /// One Egress path.
    Egress,
    /// One Bundle runtime.
    Bundle,
    /// The process-local Transport Core.
    Core,
}

/// Whether an upper layer may safely construct another attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetrySafety {
    /// No upstream request byte was written.
    SafeBeforeSubmission,
    /// Submission status is unknown; retry requires explicit policy.
    CommitUnknown,
    /// A request was submitted and must not be retried transparently.
    UnsafeSubmitted,
}

/// Required treatment of the current protocol connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionDisposition {
    /// Return the connection to the exact-key pool.
    Reusable,
    /// Remove and dispose of an indeterminate connection.
    Evict,
    /// Reset only the affected H2 stream.
    ResetStream,
    /// Stop new streams and gracefully drain the connection.
    DrainConnection,
    /// Immediately close the connection.
    CloseConnection,
}

/// Projectable health fact. Transport itself never changes Credential state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthEffect {
    /// No health change, including client cancellation.
    None,
    /// Count one transient failure against a circuit.
    TransientFailure,
    /// Quarantine the Egress path immediately.
    QuarantineEgress,
    /// Quarantine the Bundle immediately.
    QuarantineBundle,
    /// Record a successful full-path probe.
    SuccessfulProbe,
}

/// Stable transport error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportErrorCode {
    /// Matching verified Bundle/engine is not loaded.
    EngineUnavailable,
    /// Bundle envelope, hash, signature, ABI or evidence is invalid.
    BundleRejected,
    /// DNS resolution failed.
    ResolverFailure,
    /// TCP establishment failed.
    TcpConnectFailure,
    /// Proxy authentication failed.
    ProxyAuthentication,
    /// Proxy rejected or malformed the tunnel.
    ProxyProtocol,
    /// TLS certificate/hostname verification failed.
    TlsCertificate,
    /// TLS handshake failed.
    TlsHandshake,
    /// ALPN differs from the selected Bundle.
    AlpnMismatch,
    /// HTTP/1 framing is ambiguous or malformed.
    H1Framing,
    /// HTTP/2 connection or stream protocol failed.
    H2Protocol,
    /// A configured deadline elapsed.
    Timeout,
    /// The request was cancelled.
    Cancelled,
    /// Cancellation grace elapsed and forced termination was required.
    CancelGraceExpired,
    /// An internal invariant failed closed.
    InternalInvariant,
}

/// Redacted fact returned to the scheduler/request task.
#[derive(Debug, Error)]
#[error("transport {code:?} during {phase:?}: {diagnostic}")]
pub struct TransportError {
    /// Stable category.
    pub code: TransportErrorCode,
    /// Failure phase.
    pub phase: TransportPhase,
    /// Attribution domain.
    pub attribution_domain: AttributionDomain,
    /// Affected scope.
    pub failure_scope: FailureScope,
    /// Retry fact.
    pub retry_safety: RetrySafety,
    /// Number of upstream request bytes observed written.
    pub upstream_request_bytes_written: u64,
    /// Whether the complete upstream submission was observed.
    pub upstream_submission_complete: bool,
    /// Required connection cleanup.
    pub connection_disposition: ConnectionDisposition,
    /// Projectable health effect.
    pub health_effect: HealthEffect,
    /// Stable redacted diagnostic; secrets and raw payloads are prohibited.
    pub diagnostic: Box<str>,
}

impl TransportError {
    /// Construct a fail-closed pre-submission engine error.
    #[must_use]
    pub fn engine_unavailable(diagnostic: impl Into<Box<str>>) -> Self {
        Self {
            code: TransportErrorCode::EngineUnavailable,
            phase: TransportPhase::Bundle,
            attribution_domain: AttributionDomain::BundleRuntime,
            failure_scope: FailureScope::Bundle,
            retry_safety: RetrySafety::SafeBeforeSubmission,
            upstream_request_bytes_written: 0,
            upstream_submission_complete: false,
            connection_disposition: ConnectionDisposition::Evict,
            health_effect: HealthEffect::None,
            diagnostic: diagnostic.into(),
        }
    }
}
