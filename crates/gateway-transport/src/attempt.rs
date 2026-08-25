//! `ConnectionAttempt` state machine; Messages promotion happens only on first request byte.

use crate::{TransportError, TransportErrorCode};

/// Observable `ConnectionAttempt` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionAttemptState {
    /// Attempt allocated but no resource lookup performed.
    Planned,
    /// Exact `PoolKey` lookup.
    PoolLookup,
    /// DNS resolution.
    Resolving,
    /// TCP connection.
    TcpConnecting,
    /// Optional CONNECT/SOCKS5 tunnel.
    ProxyTunneling,
    /// TLS handshake.
    TlsHandshaking,
    /// ALPN verification.
    AlpnNegotiating,
    /// Protocol is ready but no request byte was written.
    ProtocolReady,
    /// First upstream request byte was written; one Messages Attempt exists.
    PromotedOnFirstByte,
    /// Terminal failure with zero Messages Attempts.
    FailedBeforeFirstByte,
    /// Terminal cancellation with zero Messages Attempts.
    CancelledBeforeFirstByte,
}

/// Strict transition holder for one connection attempt.
#[derive(Clone, Debug)]
pub struct ConnectionAttemptMachine {
    state: ConnectionAttemptState,
    promoted: bool,
}

impl Default for ConnectionAttemptMachine {
    fn default() -> Self {
        Self {
            state: ConnectionAttemptState::Planned,
            promoted: false,
        }
    }
}

impl ConnectionAttemptMachine {
    /// Current state.
    #[must_use]
    pub fn state(&self) -> ConnectionAttemptState {
        self.state
    }

    /// Whether a Messages Attempt was promoted.
    #[must_use]
    pub fn promoted(&self) -> bool {
        self.promoted
    }

    /// Move to a valid next phase.
    ///
    /// # Errors
    ///
    /// Returns an invariant error for phase regression, a second promotion, or a terminal transition after promotion.
    #[allow(clippy::unnested_or_patterns)]
    pub fn transition(&mut self, next: ConnectionAttemptState) -> Result<(), TransportError> {
        let valid = match (self.state, next) {
            (ConnectionAttemptState::Planned, ConnectionAttemptState::PoolLookup)
            | (ConnectionAttemptState::PoolLookup, ConnectionAttemptState::Resolving)
            | (ConnectionAttemptState::PoolLookup, ConnectionAttemptState::ProtocolReady)
            | (ConnectionAttemptState::Resolving, ConnectionAttemptState::TcpConnecting)
            | (ConnectionAttemptState::TcpConnecting, ConnectionAttemptState::ProxyTunneling)
            | (ConnectionAttemptState::TcpConnecting, ConnectionAttemptState::TlsHandshaking)
            | (ConnectionAttemptState::ProxyTunneling, ConnectionAttemptState::TlsHandshaking)
            | (ConnectionAttemptState::TlsHandshaking, ConnectionAttemptState::AlpnNegotiating)
            | (ConnectionAttemptState::AlpnNegotiating, ConnectionAttemptState::ProtocolReady)
            | (ConnectionAttemptState::ProtocolReady, ConnectionAttemptState::PromotedOnFirstByte) => true,
            (
                state,
                ConnectionAttemptState::FailedBeforeFirstByte | ConnectionAttemptState::CancelledBeforeFirstByte,
            ) => {
                state != ConnectionAttemptState::PromotedOnFirstByte
                    && !matches!(
                        state,
                        ConnectionAttemptState::FailedBeforeFirstByte
                            | ConnectionAttemptState::CancelledBeforeFirstByte
                    )
            }
            _ => false,
        };
        if !valid {
            let mut error = TransportError::engine_unavailable("connection_attempt_invalid_transition");
            error.code = TransportErrorCode::InternalInvariant;
            return Err(error);
        }
        self.state = next;
        if next == ConnectionAttemptState::PromotedOnFirstByte {
            self.promoted = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionAttemptMachine, ConnectionAttemptState};

    #[test]
    fn three_pre_byte_failures_never_promote_messages_attempts() {
        for _ in 0..3 {
            let mut attempt = ConnectionAttemptMachine::default();
            assert!(attempt.transition(ConnectionAttemptState::PoolLookup).is_ok());
            assert!(attempt.transition(ConnectionAttemptState::Resolving).is_ok());
            assert!(
                attempt
                    .transition(ConnectionAttemptState::FailedBeforeFirstByte)
                    .is_ok()
            );
            assert!(!attempt.promoted());
        }
    }

    #[test]
    fn promotion_is_single_and_terminal_pre_byte_state_is_rejected_afterward() {
        let mut attempt = ConnectionAttemptMachine::default();
        for next in [
            ConnectionAttemptState::PoolLookup,
            ConnectionAttemptState::ProtocolReady,
            ConnectionAttemptState::PromotedOnFirstByte,
        ] {
            assert!(attempt.transition(next).is_ok());
        }
        assert!(attempt.promoted());
        assert!(attempt.transition(ConnectionAttemptState::PromotedOnFirstByte).is_err());
        assert!(
            attempt
                .transition(ConnectionAttemptState::FailedBeforeFirstByte)
                .is_err()
        );
    }
}
