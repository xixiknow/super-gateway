#![forbid(unsafe_code)]
//! Pure, side-effect-free request parsing, capability validation, and explicit policy adjustment.

mod billing;
mod capability;
mod engine;
mod parser;
mod system_rewrite;
mod system_segments;

pub use billing::{
    BillingAction, BillingError, CchPolicy, cch_policy_for_version, ensure_billing_block, first_user_text, fp3,
    render_billing_block,
};
pub use capability::{
    CapabilityAction, CapabilityCatalog, CapabilityCompileError, CapabilityCondition, CapabilityDiagnostic,
    CapabilityRule, CompiledCapabilitySnapshot, JsonType, MatchMode, RuntimeCapabilityError,
};
pub use engine::{
    CompiledRuleSet, Enforcement, PolicyContext, PolicyError, RequestPolicy, RuleAction, RuleDefinition, RulePhase,
    SchemaMode, SystemPolicy, canonicalize_system_order,
};
pub use parser::{KnownMessagesProjection, ParseError, ParsedRequest, parse_messages_request};
pub use system_rewrite::{SystemRewrite, is_empty_replacement, replace_system_static, strip_client_system};
pub use system_segments::{
    Billing, Boundary, DynamicSection, EnvironmentBlock, EnvironmentField, Flag, OsFamily, SystemSegments,
};

/// Parse Claude Code system content into stable segments.
pub use system_segments::parse as parse_system_segments;
