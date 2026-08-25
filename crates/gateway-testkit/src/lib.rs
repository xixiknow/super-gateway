#![forbid(unsafe_code)]
//! Versioned deterministic fixtures shared by gateway crates.

mod clock;
mod ids;
mod manifest;
mod synthetic_anthropic;

pub use clock::ManualClock;
pub use ids::DeterministicIdGenerator;
pub use manifest::{FixtureManifest, FixtureSource};
pub use synthetic_anthropic::{SyntheticAnthropic, SyntheticResponse};

/// Version of the shared testkit ABI.
pub const TESTKIT_ABI_VERSION: &str = "gateway-testkit-r1-v1";
