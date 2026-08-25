//! Credential-neutral, immutable request artifacts shared by the policy and scheduling stages.

use std::{fmt, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::CredentialId;

/// A stable SHA-256 digest rendered as lowercase hexadecimal.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(Box<str>);

impl Digest {
    /// Hash an exact byte sequence.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut rendered = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(rendered, "{byte:02x}");
        }
        Self(rendered.into_boxed_str())
    }

    /// Parse an already-computed SHA-256 digest without hashing the textual
    /// representation a second time.
    ///
    /// # Errors
    ///
    /// The value must be exactly 64 lowercase hexadecimal ASCII characters.
    pub fn parse_sha256_hex(value: impl Into<Box<str>>) -> crate::DomainResult<Self> {
        let value = value.into();
        if value.len() != 64
            || !value.as_bytes().iter().all(u8::is_ascii_hexdigit)
            || value.bytes().any(|b| b.is_ascii_uppercase())
        {
            return Err(crate::DomainError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    /// Return the lowercase wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

/// Presence is independent of a field's value/type constraints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldPresence {
    /// The object does not contain the field.
    Missing,
    /// The field is explicitly JSON null.
    Null,
    /// The field has a non-null value.
    Value,
}

/// Northbound client classes used by Group enforcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientClass {
    /// A Claude Code CLI request supported by at least two structural signals.
    ClaudeCodeCli,
    /// Every other client, including ambiguous self-identification.
    NonClaudeCodeCli,
}

/// Business traffic classification. Suspected probes always keep business semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrafficClass {
    /// Ordinary business traffic.
    Normal,
    /// A deterministically authorized/published probe template.
    ExplicitProbe {
        /// Published template or authorized marker identity.
        template_id: Box<str>,
    },
    /// Heuristic signals used only for telemetry and alerts.
    SuspectedProbe {
        /// Heuristic score; it never changes request admission semantics.
        score: u8,
        /// Stable non-secret telemetry signal names.
        signals: Vec<Box<str>>,
    },
    /// A gateway-owned upstream reachability probe.
    InternalUpstreamProbe,
}

/// Immutable artifact/config version selected before the first business mutation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotVersion(pub Box<str>);

impl SnapshotVersion {
    /// Construct a snapshot version.
    #[must_use]
    pub fn new(value: impl Into<Box<str>>) -> Self {
        Self(value.into())
    }
}

/// Complete request-scoped configuration frozen across queueing and retry attempts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestSnapshotSet {
    /// Access policy/config version used to authorize this request.
    pub access_policy: SnapshotVersion,
    /// Group configuration version.
    pub group_config: SnapshotVersion,
    /// Non-overridable Group enforcement version.
    pub enforcement: SnapshotVersion,
    /// Optional effective `RuleSet` version after platform/client/group/key composition.
    pub ruleset: Option<SnapshotVersion>,
    /// Model capability version.
    pub capability: SnapshotVersion,
    /// Background/probe catalog version.
    pub background_catalog: SnapshotVersion,
    /// Client-profile classifier catalog version.
    pub client_profile_catalog: SnapshotVersion,
    /// Price catalog version recorded for downstream usage accounting.
    pub price: SnapshotVersion,
    /// Deterministic serializer version.
    pub serializer: SnapshotVersion,
}

/// Why a request must stay with a single upstream Credential.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinReason {
    /// Provider continuation state/token.
    Continuation,
    /// File, container, batch, or another account-owned remote object.
    AccountResource,
    /// An explicitly credential-scoped extension.
    CredentialExtension,
    /// An unclassified extension with potentially account-bound semantics.
    UnknownExtension,
}

/// Whether a request may be rebuilt using another Credential before submission commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Portability {
    /// Self-contained request; a new attempt may use another eligible Credential.
    Portable,
    /// Request must use an existing affinity Credential, or the first Credential selected.
    Pinned {
        /// Existing affinity target. `None` means the first selected Credential becomes the target.
        credential_id: Option<CredentialId>,
        /// Stable, deduplicated reasons.
        reasons: Vec<PinReason>,
    },
}

/// Risk class attached to a deterministic policy change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRisk {
    /// Defaulting, bounded normalization, or another low-risk change.
    Low,
    /// Explicit field replacement or clamping.
    Medium,
    /// System replacement or destructive deletion requiring stronger publication controls.
    High,
}

/// Auditable metadata for one explicit RuleSet/Enforcement mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedChange {
    /// Published rule identifier.
    pub rule_id: Box<str>,
    /// JSON pointer changed by the rule.
    pub path: Box<str>,
    /// Digest before the mutation (`missing` is represented by a fixed sentinel digest).
    pub before_digest: Digest,
    /// Digest after the mutation.
    pub after_digest: Digest,
    /// Stable non-secret reason code.
    pub reason: Box<str>,
    /// Publication risk class.
    pub risk: ChangeRisk,
}

/// Immutable replay holder. Its bytes/tree live only for the in-flight request task.
#[derive(Clone)]
pub struct RequestReplayBody {
    bytes: Arc<[u8]>,
    tree: Arc<Value>,
    reused_original: bool,
}

impl RequestReplayBody {
    /// Freeze final deterministic bytes and their semantic tree.
    #[must_use]
    pub fn new(bytes: Arc<[u8]>, tree: Arc<Value>, reused_original: bool) -> Self {
        Self {
            bytes,
            tree,
            reused_original,
        }
    }

    /// Exact request bytes to use for every attempt before Profile application.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Credential-neutral semantic tree.
    #[must_use]
    pub fn tree(&self) -> &Value {
        &self.tree
    }

    /// Whether the parser's original bytes were safe to reuse exactly.
    #[must_use]
    pub fn reused_original(&self) -> bool {
        self.reused_original
    }
}

impl fmt::Debug for RequestReplayBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestReplayBody")
            .field("len", &self.bytes.len())
            .field("digest", &Digest::of(&self.bytes))
            .field("reused_original", &self.reused_original)
            .finish_non_exhaustive()
    }
}

/// Final Credential-neutral request reused by all scheduling/transport attempts.
#[derive(Clone, Debug)]
pub struct GenericAdjustedRequest {
    /// Immutable body bytes/tree.
    pub replay_body: Arc<RequestReplayBody>,
    /// Digest of exact replay bytes.
    pub body_digest: Digest,
    /// Original client model ID. Policy and scheduling never rewrite it.
    pub model_id: Box<str>,
    /// Response mode selected exclusively from the JSON body.
    pub stream: bool,
    /// Cross-Credential eligibility.
    pub portability: Portability,
    /// Whether Profile Attribution must remain suppressed.
    pub attribution_suppressed: bool,
    /// Ordered deterministic policy changes.
    pub change_set: Arc<[AppliedChange]>,
    /// Configuration versions frozen for the whole request.
    pub snapshot_set: Arc<RequestSnapshotSet>,
}

impl GenericAdjustedRequest {
    /// Verify the replay holder matches the stored digest.
    #[must_use]
    pub fn digest_is_valid(&self) -> bool {
        Digest::of(self.replay_body.bytes()) == self.body_digest
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::{Digest, RequestReplayBody};

    #[test]
    fn replay_debug_omits_body_content() {
        let body = Arc::<[u8]>::from(br#"{"secret":"request-canary"}"#.as_slice());
        let replay = RequestReplayBody::new(body, Arc::new(json!({"secret":"request-canary"})), true);
        let debug = format!("{replay:?}");
        assert!(!debug.contains("request-canary"));
        assert!(debug.contains(Digest::of(replay.bytes()).as_str()));
    }
}
