//! Fixture provenance metadata.

use serde::{Deserialize, Serialize};

/// Origin class of a fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureSource {
    /// Fully synthetic test input.
    Synthetic,
    /// Normalized and privacy-scanned capture.
    NormalizedCapture,
    /// Generated property/model counterexample promoted to regression.
    Regression,
}

/// Minimum provenance attached to every checked-in fixture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureManifest {
    /// Stable fixture ID.
    pub fixture_id: String,
    /// Source class.
    pub source: FixtureSource,
    /// Scenario exercised by the fixture.
    pub scenario: String,
    /// Schema version used by the fixture.
    pub schema_version: String,
    /// Normalizer version, when applicable.
    pub normalizer_version: Option<String>,
    /// SHA-256 over canonical fixture bytes.
    pub content_sha256: String,
    /// Privacy scanner version/result reference.
    pub privacy_scan: String,
    /// Deterministic generation command.
    pub generation_command: String,
    /// Compatibility declaration.
    pub compatibility: Vec<String>,
    /// Expiration or recapture policy.
    pub expiration_policy: String,
    /// Optional OS family.
    pub os_family: Option<String>,
    /// Optional runtime version.
    pub runtime_version: Option<String>,
    /// Optional client version.
    pub client_version: Option<String>,
    /// Optional architecture.
    pub architecture: Option<String>,
    /// Optional capture cohort.
    pub capture_cohort: Option<String>,
}
