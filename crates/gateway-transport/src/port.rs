//! Async Transport Port and raw upstream response boundary.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use gateway_domain::{ConnectionAttemptId, CredentialId, HttpProtocol, TransportAttemptSnapshot};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{ActivationGeneration, CompiledTransportEngine, TransportError, TransportEventSink};

/// Public readiness state of the process-local transport core.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportCoreState {
    /// Bundle catalog and engine backends are still loading.
    #[default]
    Loading,
    /// Required verified engines are available.
    Ready,
    /// A deterministic local failure prevents new attempts.
    Unavailable,
}

/// Complete runtime attempt with immutable engine and cancellation ownership.
pub struct TransportAttempt {
    /// `ConnectionAttempt` persistence/trace identity.
    pub connection_attempt_id: ConnectionAttemptId,
    /// `ConnectionAttempt` ordinal, bounded by the upper layer to one through three.
    pub ordinal: u8,
    /// Credential/Profile/Egress/request/deadline snapshot.
    pub snapshot: TransportAttemptSnapshot,
    /// Immutable engine resolved from the same Request snapshot generation.
    pub engine: Arc<CompiledTransportEngine>,
    /// Catalog generation from which `engine` was resolved.
    ///
    /// This is part of the attempt snapshot: an in-flight attempt keeps using the
    /// old generation even when a newer Catalog is atomically published.
    pub activation_generation: ActivationGeneration,
    /// Shared cancellation token observed by every await point.
    pub cancellation: CancellationToken,
}

impl std::fmt::Debug for TransportAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransportAttempt")
            .field("connection_attempt_id", &self.connection_attempt_id)
            .field("ordinal", &self.ordinal)
            .field("snapshot", &self.snapshot)
            .field("engine_key", &self.engine.key)
            .field("activation_generation", &self.activation_generation)
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish_non_exhaustive()
    }
}

/// Body stream preserves Anthropic bytes and surfaces errors occurring after response headers.
#[derive(Debug)]
pub enum RawResponseBody {
    /// SSE byte chunks; no event parsing, merging, decompression or injection occurs here.
    Sse(mpsc::Receiver<Result<Bytes, TransportError>>),
    /// Non-stream raw byte chunks, later buffered/spilled by the Response Pump.
    NonStream(mpsc::Receiver<Result<Bytes, TransportError>>),
}

/// Raw upstream status, ordered headers and byte stream.
#[derive(Debug)]
pub struct RawUpstreamResponse {
    /// Status code returned by Anthropic.
    pub status: u16,
    /// Ordered response headers before the upper-layer privacy filter.
    pub headers: Vec<(Box<str>, Bytes)>,
    /// Original content-encoding value when present.
    pub content_encoding: Option<Box<str>>,
    /// Negotiated protocol.
    pub protocol: HttpProtocol,
    /// Raw Body/SSE channel.
    pub body: RawResponseBody,
}

/// Attempt-independent process-local transport boundary.
#[async_trait]
pub trait TransportCore: Send + Sync + 'static {
    /// Return local readiness without sending a Messages request.
    fn state(&self) -> TransportCoreState;

    /// Advance one Credential's minimum reusable Profile epoch. Implementations
    /// must also reject late check-in of connections below the watermark.
    fn advance_credential_profile_epoch(&self, _credential_id: &CredentialId, _minimum_profile_epoch: u64) -> usize {
        0
    }

    /// Drain idle resources from an obsolete Catalog generation and prevent
    /// in-flight attempts from checking old resources back into the pool.
    fn drain_generation(&self, _generation: ActivationGeneration) -> usize {
        0
    }

    /// Execute one immutable upstream attempt.
    ///
    /// # Errors
    ///
    /// Returns classified facts only. Retry, Credential switching and client delivery remain upper-layer decisions.
    async fn execute(
        &self,
        attempt: TransportAttempt,
        sink: Arc<dyn TransportEventSink>,
    ) -> Result<RawUpstreamResponse, TransportError>;
}

/// Fail-closed adapter used before a production Engine Catalog is loaded.
#[derive(Debug, Default)]
pub struct NoopTransportCore;

#[async_trait]
impl TransportCore for NoopTransportCore {
    fn state(&self) -> TransportCoreState {
        TransportCoreState::Unavailable
    }

    async fn execute(
        &self,
        _attempt: TransportAttempt,
        _sink: Arc<dyn TransportEventSink>,
    ) -> Result<RawUpstreamResponse, TransportError> {
        Err(TransportError::engine_unavailable("transport_core_not_configured"))
    }
}
