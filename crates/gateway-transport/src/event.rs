//! Monotonic Transport event stream and promotion invariant.

use std::sync::{Arc, Mutex};

use gateway_domain::{AttemptPlanId, ConnectionAttemptId, RequestId};

use crate::{ConnectionDisposition, TransportError, TransportErrorCode};

/// Transport lifecycle event kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportEventKind {
    /// A pool hit or new protocol connection is ready.
    ConnectionReady,
    /// Exactly one promotion point for a Messages Attempt.
    FirstUpstreamRequestByte,
    /// Request upload completed.
    RequestBodyComplete,
    /// Upstream response headers completed.
    ResponseHeaders,
    /// First response Body/SSE byte.
    FirstResponseBodyByte,
    /// Upstream body boundary completed.
    ResponseComplete,
    /// Cancellation was observed.
    CancelRequested,
    /// Stream/socket is no longer usable by this request.
    CancelConfirmed,
    /// Final connection disposition was selected.
    ConnectionDisposition,
}

/// One redacted event emitted by a Transport task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportEvent {
    /// Gateway request.
    pub request_id: RequestId,
    /// Scheduler attempt plan.
    pub attempt_plan_id: AttemptPlanId,
    /// Connection attempt.
    pub connection_attempt_id: ConnectionAttemptId,
    /// Strictly increasing per-attempt sequence starting at one.
    pub sequence: u64,
    /// Monotonic process-local timestamp.
    pub monotonic_ns: u64,
    /// Event kind.
    pub kind: TransportEventKind,
    /// Request bytes observed written.
    pub request_bytes_written: u64,
    /// Response bytes observed read.
    pub response_bytes_read: u64,
    /// Whether complete submission is known.
    pub upstream_submission_complete: bool,
    /// Terminal connection treatment when known.
    pub connection_disposition: Option<ConnectionDisposition>,
    /// Stable redacted detail code.
    pub diagnostic_code: Option<Box<str>>,
}

/// Synchronous sink so event ordering is determined by the Transport task itself.
pub trait TransportEventSink: Send + Sync + 'static {
    /// Persist or project one event.
    ///
    /// # Errors
    ///
    /// Returns a stable invariant error when the sink cannot durably accept the event.
    fn emit(&self, event: TransportEvent) -> Result<(), TransportError>;
}

/// Test/adapter sink that retains events without payload data.
#[derive(Debug, Default)]
pub struct InMemoryEventSink {
    events: Mutex<Vec<TransportEvent>>,
}

impl InMemoryEventSink {
    /// Return a point-in-time event copy. Poisoned state fails closed to an empty view.
    #[must_use]
    pub fn snapshot(&self) -> Vec<TransportEvent> {
        self.events.lock().map(|events| events.clone()).unwrap_or_default()
    }
}

impl TransportEventSink for InMemoryEventSink {
    fn emit(&self, event: TransportEvent) -> Result<(), TransportError> {
        self.events
            .lock()
            .map_err(|_| invariant("transport_event_sink_poisoned"))?
            .push(event);
        Ok(())
    }
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct SequenceState {
    last_sequence: u64,
    last_main_rank: u8,
    promotion_seen: bool,
    cancel_requested: bool,
    cancel_confirmed: bool,
    disposition_seen: bool,
}

/// Validating decorator rejecting gaps, regressions and duplicate promotion/terminal events.
pub struct MonotonicEventSink {
    inner: Arc<dyn TransportEventSink>,
    state: Mutex<SequenceState>,
}

impl MonotonicEventSink {
    /// Wrap a persistence/observer sink.
    #[must_use]
    pub fn new(inner: Arc<dyn TransportEventSink>) -> Self {
        Self {
            inner,
            state: Mutex::new(SequenceState::default()),
        }
    }
}

impl TransportEventSink for MonotonicEventSink {
    fn emit(&self, event: TransportEvent) -> Result<(), TransportError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invariant("transport_event_sequence_poisoned"))?;
        if event.sequence != state.last_sequence.saturating_add(1) {
            return Err(invariant("transport_event_sequence_gap"));
        }
        match event.kind {
            TransportEventKind::ConnectionReady
            | TransportEventKind::FirstUpstreamRequestByte
            | TransportEventKind::RequestBodyComplete
            | TransportEventKind::ResponseHeaders
            | TransportEventKind::FirstResponseBodyByte
            | TransportEventKind::ResponseComplete => {
                let rank = main_rank(event.kind);
                let valid_rank = rank == state.last_main_rank.saturating_add(1)
                    || (event.kind == TransportEventKind::ResponseComplete && state.last_main_rank == 4);
                if !valid_rank
                    || state.cancel_requested
                    || state.disposition_seen
                    || (event.kind == TransportEventKind::FirstUpstreamRequestByte && state.promotion_seen)
                {
                    return Err(invariant("transport_event_phase_regression"));
                }
                state.last_main_rank = rank;
                if event.kind == TransportEventKind::FirstUpstreamRequestByte {
                    state.promotion_seen = true;
                }
            }
            TransportEventKind::CancelRequested => {
                if state.cancel_requested || state.cancel_confirmed || state.disposition_seen {
                    return Err(invariant("transport_cancel_event_duplicate"));
                }
                state.cancel_requested = true;
            }
            TransportEventKind::CancelConfirmed => {
                if !state.cancel_requested || state.cancel_confirmed || state.disposition_seen {
                    return Err(invariant("transport_cancel_confirmation_invalid"));
                }
                state.cancel_confirmed = true;
            }
            TransportEventKind::ConnectionDisposition => {
                if state.disposition_seen || event.connection_disposition.is_none() {
                    return Err(invariant("transport_disposition_event_invalid"));
                }
                state.disposition_seen = true;
            }
        }
        self.inner.emit(event.clone())?;
        state.last_sequence = event.sequence;
        Ok(())
    }
}

fn main_rank(kind: TransportEventKind) -> u8 {
    match kind {
        TransportEventKind::ConnectionReady => 1,
        TransportEventKind::FirstUpstreamRequestByte => 2,
        TransportEventKind::RequestBodyComplete => 3,
        TransportEventKind::ResponseHeaders => 4,
        TransportEventKind::FirstResponseBodyByte => 5,
        TransportEventKind::ResponseComplete => 6,
        TransportEventKind::CancelRequested
        | TransportEventKind::CancelConfirmed
        | TransportEventKind::ConnectionDisposition => 0,
    }
}

fn invariant(code: &'static str) -> TransportError {
    let mut error = TransportError::engine_unavailable(code);
    error.code = TransportErrorCode::InternalInvariant;
    error
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::sync::Arc;

    use gateway_domain::{AttemptPlanId, ConnectionAttemptId, RequestId};

    use super::{InMemoryEventSink, MonotonicEventSink, TransportEvent, TransportEventKind, TransportEventSink};

    fn id<T>(value: Result<T, gateway_domain::DomainError>) -> T {
        match value {
            Ok(value) => value,
            Err(error) => std::panic::panic_any(error),
        }
    }

    fn event(sequence: u64, kind: TransportEventKind) -> TransportEvent {
        TransportEvent {
            request_id: id(RequestId::new("request_1")),
            attempt_plan_id: id(AttemptPlanId::new("plan_1")),
            connection_attempt_id: id(ConnectionAttemptId::new("connection_1")),
            sequence,
            monotonic_ns: sequence,
            kind,
            request_bytes_written: 0,
            response_bytes_read: 0,
            upstream_submission_complete: false,
            connection_disposition: None,
            diagnostic_code: None,
        }
    }

    #[test]
    fn rejects_duplicate_promotion_and_sequence_gaps() {
        let memory = Arc::new(InMemoryEventSink::default());
        let sink = MonotonicEventSink::new(memory.clone());
        assert!(sink.emit(event(1, TransportEventKind::ConnectionReady)).is_ok());
        assert!(
            sink.emit(event(2, TransportEventKind::FirstUpstreamRequestByte))
                .is_ok()
        );
        assert!(
            sink.emit(event(3, TransportEventKind::FirstUpstreamRequestByte))
                .is_err()
        );
        assert_eq!(memory.snapshot().len(), 2);
    }
}
