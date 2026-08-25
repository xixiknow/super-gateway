#![forbid(unsafe_code)]
//! Pure, side-effect-free request parsing, capability validation, and explicit policy adjustment.

mod capability;
mod engine;
mod parser;

pub use capability::{
    CapabilityAction, CapabilityCatalog, CapabilityCompileError, CapabilityCondition, CapabilityDiagnostic,
    CapabilityRule, CompiledCapabilitySnapshot, JsonType, MatchMode, RuntimeCapabilityError,
};
pub use engine::{
    CompiledRuleSet, Enforcement, PolicyContext, PolicyError, RequestPolicy, RuleAction, RuleDefinition, RulePhase,
    SchemaMode, SystemPolicy,
};
pub use parser::{KnownMessagesProjection, ParseError, ParsedRequest, parse_messages_request};
