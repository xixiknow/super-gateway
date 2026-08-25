//! Stable domain errors.

use thiserror::Error;

/// Errors emitted by pure domain validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    /// A typed identifier was empty or outside its bounded representation.
    #[error("invalid typed identifier")]
    InvalidIdentifier,
    /// A state transition violates the frozen lifecycle.
    #[error("invalid state transition")]
    InvalidStateTransition,
    /// A generation, revision or epoch did not match the expected value.
    #[error("stale generation or revision")]
    StaleGeneration,
    /// A bounded value, epoch, deadline, or configuration is outside the contract.
    #[error("invalid domain value")]
    InvalidValue,
    /// Candidate authentication material belongs to a different upstream account.
    #[error("upstream account identity mismatch")]
    AccountMismatch,
    /// A command attempted to mutate an aggregate after its terminal state.
    #[error("aggregate is terminal")]
    TerminalState,
}

/// Result alias for domain operations.
pub type DomainResult<T> = Result<T, DomainError>;
