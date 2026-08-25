//! Response delivery, usage and exact-cost value objects.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

/// Client-facing response mode selected by the request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    /// Anthropic SSE bytes are relayed with bounded backpressure.
    Streaming,
    /// The complete response is buffered before client commit.
    NonStreaming,
}

/// Data-plane phase persisted for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestPhase {
    Accepted,
    Validated,
    Queued,
    Reserved,
    Submitting,
    ResponseCommitted,
    Streaming,
    Completed,
    Failed,
    Cancelled,
}

/// Whether client-visible headers have crossed the commit fence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientCommitState {
    #[default]
    Uncommitted,
    Committed,
}

/// Terminal delivery classification, independent from upstream success.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome {
    Complete,
    ClientDisconnected,
    ClientWriteTimeout,
    UpstreamBodyError,
    BufferRejected,
    CancelledBeforeCommit,
}

/// Storage tier chosen for a non-stream response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BufferTier {
    Memory,
    EncryptedSpill,
}

/// Origin of one usage observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    Official,
    LocalEstimate,
    ConsoleCount,
    CancelEstimate,
}

/// Knowledge level for the fields carried by one usage observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageCompleteness {
    Unknown,
    Partial,
    Complete,
}

/// Token fields are independently optional; absence is never serialized as zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenCounts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_input_tokens: Option<u64>,
}

impl TokenCounts {
    /// True when no token field has been observed.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.input_tokens.is_none()
            && self.output_tokens.is_none()
            && self.cache_creation_input_tokens.is_none()
            && self.cache_read_input_tokens.is_none()
    }
}

/// Immutable usage fact. Source and completeness are intentionally orthogonal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageObservation {
    pub source: UsageSource,
    pub completeness: UsageCompleteness,
    pub counts: TokenCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_version: Option<Box<str>>,
}

impl UsageObservation {
    /// Build an observation while enforcing that `unknown` carries no invented counts.
    ///
    /// # Errors
    ///
    /// Returns [`UsageObservationError::UnknownWithCounts`] for contradictory input.
    pub fn new(
        source: UsageSource,
        completeness: UsageCompleteness,
        counts: TokenCounts,
        algorithm_version: Option<Box<str>>,
    ) -> Result<Self, UsageObservationError> {
        if completeness == UsageCompleteness::Unknown && !counts.is_empty() {
            return Err(UsageObservationError::UnknownWithCounts);
        }
        Ok(Self {
            source,
            completeness,
            counts,
            algorithm_version,
        })
    }
}

/// Invalid usage fact.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum UsageObservationError {
    #[error("unknown usage cannot contain token counts")]
    UnknownWithCounts,
}

/// Frozen prices expressed as pico-USD (10^-12 USD) per million tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceSnapshot {
    pub input_per_million_pico_usd: u128,
    pub output_per_million_pico_usd: u128,
    pub cache_creation_per_million_pico_usd: u128,
    pub cache_read_per_million_pico_usd: u128,
}

/// Exact cost estimate. `None` means there was no known token field to price.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostEstimate {
    /// Decimal string; JSON floating point is never used for money.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_usd: Option<Box<str>>,
    pub usage_completeness: UsageCompleteness,
    pub algorithm_version: Box<str>,
}

#[cfg(test)]
mod tests {
    use super::{TokenCounts, UsageCompleteness, UsageObservation, UsageSource};

    #[test]
    fn source_and_completeness_are_orthogonal_and_missing_is_not_zero() {
        let partial = UsageObservation::new(
            UsageSource::Official,
            UsageCompleteness::Partial,
            TokenCounts {
                input_tokens: Some(7),
                output_tokens: None,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            None,
        );
        assert!(partial.is_ok());
        let json = serde_json::to_string(&partial.ok()).unwrap_or_default();
        assert!(json.contains("input_tokens"));
        assert!(!json.contains("output_tokens"));

        assert!(
            UsageObservation::new(
                UsageSource::CancelEstimate,
                UsageCompleteness::Unknown,
                TokenCounts {
                    input_tokens: Some(0),
                    ..TokenCounts::default()
                },
                Some("estimate-v1".into()),
            )
            .is_err()
        );
    }
}
