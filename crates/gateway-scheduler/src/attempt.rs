//! Request/connection attempt accounting and cancellation boundaries.
#![allow(missing_docs, clippy::missing_errors_doc, clippy::struct_excessive_bools)]

use thiserror::Error;

/// Upstream protocol determines the safe cancellation action after upload starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamProtocol {
    Http1,
    Http2,
}

/// Request phase relevant to submission and delivery cancellation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttemptPhase {
    #[default]
    Accepted,
    Connecting,
    Connected,
    Uploading,
    WaitingHeaders,
    StreamingCommitted,
    BufferedReady,
    Completed,
    Cancelled,
}

/// Usage knowledge is monotonic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum UsageKnowledge {
    #[default]
    Absent,
    Unknown,
    Partial,
    Complete,
}

/// Required transport cleanup for a cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportCancelAction {
    None,
    ResetHttp2Stream,
    CloseAndEvictHttp1Connection,
    AwaitTransportConfirmation,
}

/// Complete, auditable cancellation result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelDisposition {
    pub transport_action: TransportCancelAction,
    pub usage: UsageKnowledge,
    pub messages_attempts: u8,
    pub retry_allowed: bool,
    pub lease_release_after_transport: bool,
    pub destroy_buffer_before_reservation_release: bool,
    pub preserve_delivered_prefix: bool,
}

/// Per-request accounting state. Connection and Messages ordinals are intentionally separate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttemptState {
    phase: AttemptPhase,
    connection_attempts: u8,
    messages_attempts: u8,
    usage: UsageKnowledge,
    terminal: bool,
}

impl AttemptState {
    pub fn begin_connection(&mut self) -> Result<u8, AttemptStateError> {
        self.ensure_active()?;
        if self.connection_attempts >= 3 {
            return Err(AttemptStateError::ConnectionBudgetExhausted);
        }
        self.connection_attempts += 1;
        self.phase = AttemptPhase::Connecting;
        Ok(self.connection_attempts)
    }

    pub fn connection_established(&mut self) -> Result<(), AttemptStateError> {
        self.ensure_phase(AttemptPhase::Connecting)?;
        self.phase = AttemptPhase::Connected;
        Ok(())
    }

    /// Promote a submission intent to a Messages Attempt exactly at the first upstream request byte.
    pub fn first_request_byte(&mut self) -> Result<u8, AttemptStateError> {
        self.ensure_phase(AttemptPhase::Connected)?;
        if self.messages_attempts >= 3 {
            return Err(AttemptStateError::MessagesBudgetExhausted);
        }
        self.messages_attempts += 1;
        self.usage = UsageKnowledge::Unknown;
        self.phase = AttemptPhase::Uploading;
        Ok(self.messages_attempts)
    }

    pub fn request_upload_complete(&mut self) -> Result<(), AttemptStateError> {
        self.ensure_phase(AttemptPhase::Uploading)?;
        self.phase = AttemptPhase::WaitingHeaders;
        Ok(())
    }

    pub fn commit_streaming_response(&mut self) -> Result<(), AttemptStateError> {
        if !matches!(self.phase, AttemptPhase::Uploading | AttemptPhase::WaitingHeaders) {
            return Err(AttemptStateError::InvalidTransition);
        }
        self.phase = AttemptPhase::StreamingCommitted;
        Ok(())
    }

    pub fn buffer_complete(&mut self) -> Result<(), AttemptStateError> {
        if !matches!(self.phase, AttemptPhase::Uploading | AttemptPhase::WaitingHeaders) {
            return Err(AttemptStateError::InvalidTransition);
        }
        self.phase = AttemptPhase::BufferedReady;
        Ok(())
    }

    /// Advance usage knowledge independently from response delivery state.
    pub fn observe_usage(&mut self, knowledge: UsageKnowledge) -> Result<(), AttemptStateError> {
        self.ensure_active()?;
        if self.messages_attempts == 0 || knowledge == UsageKnowledge::Absent || knowledge < self.usage {
            return Err(AttemptStateError::InvalidUsageKnowledge);
        }
        self.usage = knowledge;
        Ok(())
    }

    pub fn complete_delivery(&mut self) -> Result<(), AttemptStateError> {
        if !matches!(
            self.phase,
            AttemptPhase::StreamingCommitted | AttemptPhase::BufferedReady
        ) {
            return Err(AttemptStateError::InvalidTransition);
        }
        self.phase = AttemptPhase::Completed;
        self.terminal = true;
        Ok(())
    }

    pub fn cancel(&mut self, protocol: UpstreamProtocol) -> Result<CancelDisposition, AttemptStateError> {
        self.ensure_active()?;
        let disposition = match self.phase {
            AttemptPhase::Accepted | AttemptPhase::Connecting | AttemptPhase::Connected => CancelDisposition {
                transport_action: if self.phase == AttemptPhase::Accepted {
                    TransportCancelAction::None
                } else {
                    TransportCancelAction::AwaitTransportConfirmation
                },
                usage: UsageKnowledge::Absent,
                messages_attempts: self.messages_attempts,
                retry_allowed: false,
                lease_release_after_transport: self.phase != AttemptPhase::Accepted,
                destroy_buffer_before_reservation_release: false,
                preserve_delivered_prefix: false,
            },
            AttemptPhase::Uploading | AttemptPhase::WaitingHeaders => CancelDisposition {
                transport_action: match protocol {
                    UpstreamProtocol::Http1 => TransportCancelAction::CloseAndEvictHttp1Connection,
                    UpstreamProtocol::Http2 => TransportCancelAction::ResetHttp2Stream,
                },
                usage: UsageKnowledge::Unknown,
                messages_attempts: self.messages_attempts,
                retry_allowed: false,
                lease_release_after_transport: true,
                destroy_buffer_before_reservation_release: false,
                preserve_delivered_prefix: false,
            },
            AttemptPhase::BufferedReady => CancelDisposition {
                transport_action: TransportCancelAction::None,
                usage: self.usage,
                messages_attempts: self.messages_attempts,
                retry_allowed: false,
                lease_release_after_transport: false,
                destroy_buffer_before_reservation_release: true,
                preserve_delivered_prefix: false,
            },
            AttemptPhase::StreamingCommitted => CancelDisposition {
                transport_action: match protocol {
                    UpstreamProtocol::Http1 => TransportCancelAction::CloseAndEvictHttp1Connection,
                    UpstreamProtocol::Http2 => TransportCancelAction::ResetHttp2Stream,
                },
                usage: UsageKnowledge::Unknown,
                messages_attempts: self.messages_attempts,
                retry_allowed: false,
                lease_release_after_transport: true,
                destroy_buffer_before_reservation_release: false,
                preserve_delivered_prefix: true,
            },
            AttemptPhase::Completed | AttemptPhase::Cancelled => return Err(AttemptStateError::AlreadyTerminal),
        };
        self.phase = AttemptPhase::Cancelled;
        self.usage = disposition.usage;
        self.terminal = true;
        Ok(disposition)
    }

    #[must_use]
    pub fn connection_attempts(&self) -> u8 {
        self.connection_attempts
    }

    #[must_use]
    pub fn messages_attempts(&self) -> u8 {
        self.messages_attempts
    }

    #[must_use]
    pub fn usage(&self) -> UsageKnowledge {
        self.usage
    }

    fn ensure_active(&self) -> Result<(), AttemptStateError> {
        if self.terminal {
            Err(AttemptStateError::AlreadyTerminal)
        } else {
            Ok(())
        }
    }

    fn ensure_phase(&self, expected: AttemptPhase) -> Result<(), AttemptStateError> {
        self.ensure_active()?;
        if self.phase == expected {
            Ok(())
        } else {
            Err(AttemptStateError::InvalidTransition)
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AttemptStateError {
    #[error("invalid attempt transition")]
    InvalidTransition,
    #[error("connection attempt budget exhausted")]
    ConnectionBudgetExhausted,
    #[error("messages attempt budget exhausted")]
    MessagesBudgetExhausted,
    #[error("request already reached a terminal state")]
    AlreadyTerminal,
    #[error("usage knowledge transition is invalid")]
    InvalidUsageKnowledge,
}

#[cfg(test)]
mod tests {
    use super::{AttemptState, TransportCancelAction, UpstreamProtocol, UsageKnowledge};

    #[test]
    fn three_connection_failures_create_zero_messages_attempts() {
        let mut state = AttemptState::default();
        assert!(state.begin_connection().is_ok());
        assert!(state.begin_connection().is_ok());
        assert!(state.begin_connection().is_ok());
        assert!(state.begin_connection().is_err());
        assert_eq!(state.connection_attempts(), 3);
        assert_eq!(state.messages_attempts(), 0);
        assert_eq!(state.usage(), UsageKnowledge::Absent);
    }

    #[test]
    fn cancel_before_first_byte_has_no_messages_attempt_or_usage() {
        let mut state = AttemptState::default();
        assert!(state.begin_connection().is_ok());
        assert!(state.connection_established().is_ok());
        let disposition = state.cancel(UpstreamProtocol::Http2);
        assert!(matches!(
            disposition,
            Ok(value)
                if value.messages_attempts == 0
                    && value.usage == UsageKnowledge::Absent
                    && value.transport_action == TransportCancelAction::AwaitTransportConfirmation
        ));
    }

    #[test]
    fn upload_cancel_resets_h2_or_evicts_h1_and_marks_usage_unknown() {
        for (protocol, expected) in [
            (UpstreamProtocol::Http2, TransportCancelAction::ResetHttp2Stream),
            (
                UpstreamProtocol::Http1,
                TransportCancelAction::CloseAndEvictHttp1Connection,
            ),
        ] {
            let mut state = AttemptState::default();
            assert!(state.begin_connection().is_ok());
            assert!(state.connection_established().is_ok());
            assert!(state.first_request_byte().is_ok());
            let disposition = state.cancel(protocol);
            assert!(matches!(
                disposition,
                Ok(value)
                    if value.transport_action == expected
                        && value.messages_attempts == 1
                        && value.usage == UsageKnowledge::Unknown
            ));
        }
    }

    #[test]
    fn buffered_cancel_destroys_body_before_reservation_release_without_inventing_usage() {
        let mut state = AttemptState::default();
        assert!(state.begin_connection().is_ok());
        assert!(state.connection_established().is_ok());
        assert!(state.first_request_byte().is_ok());
        assert!(state.request_upload_complete().is_ok());
        assert!(state.buffer_complete().is_ok());
        let disposition = state.cancel(UpstreamProtocol::Http2);
        assert!(matches!(
            disposition,
            Ok(value)
                if value.usage == UsageKnowledge::Unknown
                    && value.destroy_buffer_before_reservation_release
                    && !value.lease_release_after_transport
        ));
    }

    #[test]
    fn usage_knowledge_is_monotonic_and_independent_from_buffer_completion() {
        let mut state = AttemptState::default();
        assert!(state.begin_connection().is_ok());
        assert!(state.connection_established().is_ok());
        assert!(state.first_request_byte().is_ok());
        assert!(state.observe_usage(UsageKnowledge::Partial).is_ok());
        assert!(state.buffer_complete().is_ok());
        assert_eq!(state.usage(), UsageKnowledge::Partial);
        assert!(state.observe_usage(UsageKnowledge::Unknown).is_err());
        assert!(state.observe_usage(UsageKnowledge::Complete).is_ok());
        assert_eq!(state.usage(), UsageKnowledge::Complete);
    }

    #[test]
    fn committed_stream_cancel_preserves_prefix_and_never_retries() {
        let mut state = AttemptState::default();
        assert!(state.begin_connection().is_ok());
        assert!(state.connection_established().is_ok());
        assert!(state.first_request_byte().is_ok());
        assert!(state.commit_streaming_response().is_ok());
        let disposition = state.cancel(UpstreamProtocol::Http2);
        assert!(matches!(
            disposition,
            Ok(value) if value.preserve_delivered_prefix && !value.retry_allowed
        ));
        assert!(state.cancel(UpstreamProtocol::Http2).is_err());
    }
}
