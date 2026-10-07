//! OpenAI-specific credential and protocol adapters.
//!
//! These adapters deliberately do not apply Claude profile rules to Codex.

pub mod account;
pub mod protocol;
pub mod session;
pub mod usage;
pub mod websocket;

/// Adapter error codes contain no credentials or upstream body text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpenAiError {
    /// Invalid or unsupported request structure.
    #[error("invalid OpenAI request")]
    InvalidRequest,
    /// Credential document is missing required material.
    #[error("invalid OpenAI credential material")]
    InvalidCredential,
    /// Imported or refreshed identity differs from the registered identity.
    #[error("OpenAI account identity conflict")]
    IdentityConflict,
    /// Explicit group policy rejected a requested reasoning effort.
    #[error("reasoning effort exceeds group policy")]
    ReasoningLimit,
    /// Response continuation is missing or belongs to a different account.
    #[error("response continuation account is unavailable")]
    ContinuationUnavailable,
    /// A stream exceeded its bounded event size.
    #[error("OpenAI stream event exceeds size limit")]
    EventTooLarge,
    /// Upstream usage contains contradictory fields.
    #[error("invalid OpenAI usage")]
    InvalidUsage,
}
