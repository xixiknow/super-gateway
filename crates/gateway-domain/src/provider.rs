//! Provider identity is independent of the credential authentication mechanism.

use serde::{Deserialize, Serialize};

/// Upstream provider. Missing fields in older contracts mean Anthropic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Existing Claude gateway credentials and model catalog.
    #[default]
    Anthropic,
    /// Official `OpenAI` API and `ChatGPT` Codex subscriptions.
    Openai,
}

impl Provider {
    /// Stable database and wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Openai => "openai",
        }
    }
}

/// `OpenAI` authentication; setup tokens are intentionally not a refreshable type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAiAuthKind {
    /// `ChatGPT` OAuth access token, optionally accompanied by a refresh token.
    Oauth,
    /// Official `OpenAI` API key.
    ApiKey,
}

/// Public request protocol, separate from both provider and authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAiEndpoint {
    /// Responses JSON or SSE.
    Responses,
    /// Chat Completions JSON or SSE.
    ChatCompletions,
    /// Responses compaction uses unary JSON.
    Compact,
}

impl OpenAiEndpoint {
    /// Fixed official upstream endpoint, never a client-controlled URL.
    #[must_use]
    pub const fn upstream_url(self, auth: OpenAiAuthKind) -> &'static str {
        match (auth, self) {
            (OpenAiAuthKind::Oauth, Self::Compact) => "https://chatgpt.com/backend-api/codex/responses/compact",
            (OpenAiAuthKind::Oauth, _) => "https://chatgpt.com/backend-api/codex/responses",
            (OpenAiAuthKind::ApiKey, Self::Responses) => "https://api.openai.com/v1/responses",
            (OpenAiAuthKind::ApiKey, Self::ChatCompletions) => "https://api.openai.com/v1/chat/completions",
            (OpenAiAuthKind::ApiKey, Self::Compact) => "https://api.openai.com/v1/responses/compact",
        }
    }
}
