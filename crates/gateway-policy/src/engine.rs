//! Frozen policy composition and deterministic request adjustment.
#![allow(missing_docs, clippy::doc_markdown)]

use std::{collections::BTreeSet, sync::Arc};

use gateway_domain::{
    AppliedChange, ChangeRisk, ClientClass, ClientOs, CredentialId, Digest, GenericAdjustedRequest, PinReason,
    Portability, RequestReplayBody, RequestSnapshotSet,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::{
    CapabilityCatalog, CapabilityCompileError, CapabilityCondition, CapabilityDiagnostic, CompiledCapabilitySnapshot,
    JsonType, ParseError, ParsedRequest,
    capability::{EvaluationContext, RuntimeCapabilityError, condition_matches, validate_condition},
    parse_messages_request,
    system_rewrite::{is_empty_replacement, replace_system_static, strip_client_system},
};

/// Unknown-extension behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaMode {
    /// Preserve unknown fields/blocks and conservatively pin the request.
    Compatible,
    /// Reject the first stable-sorted unknown path.
    Strict,
}

/// Non-overridable Group System policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SystemPolicy {
    Preserve,
    StripClient,
    Replace {
        platform_system_ref: Box<str>,
        content: Value,
    },
    StripAll,
}

/// Group constraints applied after lower-level rules and again before Generic construction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Enforcement {
    pub system: SystemPolicy,
}

impl Default for Enforcement {
    fn default() -> Self {
        Self {
            system: SystemPolicy::Preserve,
        }
    }
}

/// Fixed action phase. Serialized order never controls execution order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePhase {
    StructureRepair,
    Default,
    Range,
    System,
    Tools,
    ThinkingCache,
    BetaMetadata,
}

/// Explicit RuleSet mutation actions. Model and attempt-scoped identity are absent by design.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RuleAction {
    SetDefault {
        path: Box<str>,
        value: Value,
    },
    Set {
        path: Box<str>,
        value: Value,
    },
    Remove {
        path: Box<str>,
    },
    ClampNumber {
        path: Box<str>,
        minimum: Option<f64>,
        maximum: Option<f64>,
    },
}

impl RuleAction {
    fn path(&self) -> &str {
        match self {
            Self::SetDefault { path, .. }
            | Self::Set { path, .. }
            | Self::Remove { path }
            | Self::ClampNumber { path, .. } => path,
        }
    }
}

/// One published deterministic RuleSet definition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleDefinition {
    pub id: Box<str>,
    pub phase: RulePhase,
    pub action: RuleAction,
    pub when: CapabilityCondition,
    pub reason: Box<str>,
    pub risk: ChangeRisk,
}

/// Immutable compiled RuleSet, ordered by phase then stable identifier.
#[derive(Clone, Debug)]
pub struct CompiledRuleSet {
    id: Box<str>,
    rules: Arc<[RuleDefinition]>,
}

/// Privacy-safe result of applying one RuleSet to an administrator-supplied
/// synthetic request. Values before and after each mutation remain represented
/// only by their digests in `changes`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleSimulation {
    pub adjusted_request_digest: Digest,
    pub changes: Vec<AppliedChange>,
}

impl CompiledRuleSet {
    /// Compile rules and reject mutation of the model or non-body namespaces.
    ///
    /// # Errors
    ///
    /// Returns a compile error for malformed identifiers, paths, conditions, or ranges.
    pub fn compile(id: impl Into<Box<str>>, mut rules: Vec<RuleDefinition>) -> Result<Self, CapabilityCompileError> {
        Self::compile_layers(id, vec![std::mem::take(&mut rules)])
    }

    /// Compile ordered policy layers while preserving the declared inheritance
    /// order inside every execution phase. Later layers therefore observe and
    /// may explicitly override mutations made by earlier layers.
    ///
    /// # Errors
    ///
    /// Returns a compile error for malformed identifiers, paths, conditions, or ranges.
    pub fn compile_layers(
        id: impl Into<Box<str>>,
        layers: Vec<Vec<RuleDefinition>>,
    ) -> Result<Self, CapabilityCompileError> {
        let id = id.into();
        if id.is_empty()
            || layers
                .iter()
                .flatten()
                .any(|rule| rule.id.is_empty() || rule.reason.is_empty())
        {
            return Err(CapabilityCompileError::EmptyIdentifier);
        }
        let mut rules = layers
            .into_iter()
            .enumerate()
            .flat_map(|(layer, rules)| rules.into_iter().map(move |rule| (layer, rule)))
            .collect::<Vec<_>>();
        for (_, rule) in &rules {
            validate_mutation_path(rule.action.path())?;
            validate_condition(&rule.when)?;
            if let RuleAction::ClampNumber { minimum, maximum, .. } = rule.action
                && minimum.zip(maximum).is_some_and(|(min, max)| min > max)
            {
                return Err(CapabilityCompileError::EmptyRange);
            }
        }
        rules.sort_by(|(left_layer, left), (right_layer, right)| {
            (left.phase, left_layer, &left.id).cmp(&(right.phase, right_layer, &right.id))
        });
        Ok(Self {
            id,
            rules: rules.into_iter().map(|(_, rule)| rule).collect::<Vec<_>>().into(),
        })
    }

    /// Artifact identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Apply this RuleSet to one administrator-supplied Messages sample without
    /// applying Group enforcement or model capabilities.
    ///
    /// This is intentionally a dry run: the adjusted body is represented by a
    /// digest and the ordinary `AppliedChange` hashes, so management telemetry
    /// and idempotency records never retain prompt content.
    ///
    /// # Errors
    ///
    /// Returns a stable policy error for an invalid Messages shape, a condition
    /// expansion failure, or a conflicting mutation.
    pub fn simulate(&self, mut request: Value, context: &PolicyContext) -> Result<RuleSimulation, PolicyError> {
        let object = request.as_object().ok_or(PolicyError::InvalidStructure)?;
        let model = object
            .get("model")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(Box::<str>::from)
            .ok_or(PolicyError::InvalidStructure)?;
        if !object.get("messages").is_some_and(Value::is_array)
            || object.get("max_tokens").is_none_or(|value| value.as_u64().is_none())
        {
            return Err(PolicyError::InvalidStructure);
        }
        let stream = match object.get("stream") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err(PolicyError::InvalidStructure),
        };
        let evaluation = context.evaluation(&model, stream);
        let mut changes = Vec::new();
        apply_rules(self, &mut request, &evaluation, &mut changes)?;
        let adjusted = serde_json::to_vec(&request).map_err(|_| PolicyError::Serializer)?;
        Ok(RuleSimulation {
            adjusted_request_digest: Digest::of(&adjusted),
            changes,
        })
    }
}

/// Request-scoped facts available to conditions and portability selection.
#[derive(Clone, Debug)]
pub struct PolicyContext {
    pub client_class: ClientClass,
    pub client_os: ClientOs,
    pub protocol_headers: std::collections::BTreeMap<Box<str>, Value>,
    pub affinity_credential: Option<CredentialId>,
}

impl PolicyContext {
    fn evaluation(&self, model: &str, stream: bool) -> EvaluationContext {
        let mut request = std::collections::BTreeMap::new();
        request.insert(
            Box::<str>::from("client_class"),
            Value::String(
                match self.client_class {
                    ClientClass::ClaudeCodeCli => "claude_code_cli",
                    ClientClass::NonClaudeCodeCli => "non_claude_code_cli",
                }
                .to_owned(),
            ),
        );
        request.insert(Box::<str>::from("model"), Value::String(model.to_owned()));
        request.insert(
            Box::<str>::from("client_os"),
            Value::String(self.client_os.as_str().to_owned()),
        );
        request.insert(Box::<str>::from("stream"), Value::Bool(stream));
        EvaluationContext {
            headers: self.protocol_headers.clone(),
            request,
        }
    }
}

/// Policy processing failures mapped at the Edge into stable Anthropic-style errors.
#[derive(Clone, Debug, Error)]
pub enum PolicyError {
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("invalid request structure")]
    InvalidStructure,
    #[error("model unavailable")]
    ModelUnavailable,
    #[error("request capability violation")]
    Capability(Vec<CapabilityDiagnostic>),
    #[error("CAPABILITY_PATH_EXPANSION_LIMIT")]
    CapabilityPathExpansionLimit,
    #[error("CAPABILITY_RUNTIME_CONFLICT")]
    CapabilityRuntimeConflict,
    #[error("deterministic serializer failed")]
    Serializer,
}

/// Complete policy snapshot frozen for a request.
#[derive(Clone, Debug)]
pub struct RequestPolicy {
    pub schema_mode: SchemaMode,
    pub capabilities: CapabilityCatalog,
    pub enforcement: Enforcement,
    pub ruleset: Option<CompiledRuleSet>,
    pub snapshots: Arc<RequestSnapshotSet>,
}

impl RequestPolicy {
    /// Build a conservative base Messages policy for exact published model IDs.
    ///
    /// # Errors
    ///
    /// Returns a compile error only when the generated invariant rules are invalid.
    pub fn base_for_models(
        model_ids: impl IntoIterator<Item = impl Into<Box<str>>>,
        snapshots: Arc<RequestSnapshotSet>,
    ) -> Result<Self, CapabilityCompileError> {
        let mut models = Vec::new();
        for model_id in model_ids {
            let model_id = model_id.into();
            let rules = vec![
                capability_rule("model", "body:/model", JsonType::String),
                capability_rule("max_tokens", "body:/max_tokens", JsonType::Integer),
                capability_rule("messages", "body:/messages", JsonType::Array),
                allowed_rule("stream", "body:/stream", &[JsonType::Boolean]),
                allowed_rule("system", "body:/system", &[JsonType::String, JsonType::Array]),
            ];
            models.push(CompiledCapabilitySnapshot::compile(
                format!("capability:{model_id}:base"),
                model_id,
                rules,
            )?);
        }
        Ok(Self {
            schema_mode: SchemaMode::Compatible,
            capabilities: CapabilityCatalog::new(models)?,
            enforcement: Enforcement::default(),
            ruleset: None,
            snapshots,
        })
    }

    /// Parse, validate, explicitly adjust, revalidate, and freeze a Credential-neutral request.
    ///
    /// # Errors
    ///
    /// Returns stable client/policy errors without acquiring business resources.
    pub fn process(&self, raw_body: Arc<[u8]>, context: &PolicyContext) -> Result<GenericAdjustedRequest, PolicyError> {
        self.process_with_options(raw_body, context, true)
    }

    /// Process a count-tokens request. Unlike Messages, this endpoint does not
    /// require a `max_tokens` field, while retaining the same model, system,
    /// capability, and mutation protections.
    ///
    /// # Errors
    /// Returns client parsing, validation, or policy errors before acquiring resources.
    pub fn process_count_tokens(
        &self,
        raw_body: Arc<[u8]>,
        context: &PolicyContext,
    ) -> Result<GenericAdjustedRequest, PolicyError> {
        self.process_with_options(raw_body, context, false)
    }

    fn process_with_options(
        &self,
        raw_body: Arc<[u8]>,
        context: &PolicyContext,
        require_max_tokens: bool,
    ) -> Result<GenericAdjustedRequest, PolicyError> {
        let parsed = parse_messages_request(raw_body, self.schema_mode == SchemaMode::Strict)?;
        let (model_id, stream) = validate_base_structure(&parsed, require_max_tokens)?;
        let capability = self.capabilities.get(&model_id).ok_or(PolicyError::ModelUnavailable)?;
        let evaluation = context.evaluation(&model_id, stream);
        let precheck = capability
            .validate(&parsed.tree, &evaluation, false)
            .map_err(map_runtime_error)?;
        let precheck = filter_count_tokens_diagnostics(precheck, require_max_tokens);
        if !precheck.is_empty() {
            return Err(PolicyError::Capability(precheck));
        }

        let original_model = model_id.clone();
        let mut tree = parsed.tree.clone();
        let mut changes = Vec::new();
        if let Some(ruleset) = &self.ruleset {
            apply_rules(ruleset, &mut tree, &evaluation, &mut changes)?;
        }
        let enforcement = apply_enforcement(&self.enforcement, &mut tree, &mut changes)?;
        // Any semantic mutation causes a re-serialization. Keep the Claude
        // request's conventional top-level ordering stable in that case.
        if !changes.is_empty() {
            canonicalize_system_order(&mut tree);
        }
        if tree.get("model").and_then(Value::as_str) != Some(original_model.as_ref()) {
            return Err(PolicyError::CapabilityRuntimeConflict);
        }
        let final_diagnostics = capability
            .validate(&tree, &evaluation, true)
            .map_err(map_runtime_error)?;
        let final_diagnostics = filter_count_tokens_diagnostics(final_diagnostics, require_max_tokens);
        if !final_diagnostics.is_empty() {
            return Err(PolicyError::Capability(final_diagnostics));
        }

        let portability = classify_portability(&parsed, &tree, context.affinity_credential.clone());
        let (bytes, reused_original) = if changes.is_empty() {
            (parsed.raw_body, true)
        } else {
            (
                Arc::<[u8]>::from(serde_json::to_vec(&tree).map_err(|_| PolicyError::Serializer)?),
                false,
            )
        };
        let digest = Digest::of(&bytes);
        Ok(GenericAdjustedRequest {
            replay_body: Arc::new(RequestReplayBody::new(bytes, Arc::new(tree), reused_original)),
            body_digest: digest,
            model_id: original_model,
            stream,
            portability,
            attribution_suppressed: enforcement.attribution_suppressed,
            system_template_pending: enforcement.system_template_pending,
            change_set: changes.into(),
            snapshot_set: self.snapshots.clone(),
        })
    }
}

fn capability_rule(id: &str, path: &str, kind: JsonType) -> crate::CapabilityRule {
    crate::CapabilityRule {
        id: Box::from(id),
        path: Box::from(path),
        action: crate::CapabilityAction::Required,
        types: BTreeSet::from([kind]),
        enum_values: Vec::new(),
        minimum: if path == "body:/max_tokens" { Some(1.0) } else { None },
        maximum: None,
        exclusive_maximum_path: None,
        required_children: BTreeSet::new(),
        when: CapabilityCondition::Always,
    }
}

fn allowed_rule(id: &str, path: &str, kinds: &[JsonType]) -> crate::CapabilityRule {
    crate::CapabilityRule {
        id: Box::from(id),
        path: Box::from(path),
        action: crate::CapabilityAction::Allowed,
        types: kinds.iter().copied().collect(),
        enum_values: Vec::new(),
        minimum: None,
        maximum: None,
        exclusive_maximum_path: None,
        required_children: BTreeSet::new(),
        when: CapabilityCondition::Always,
    }
}

fn validate_base_structure(parsed: &ParsedRequest, require_max_tokens: bool) -> Result<(Box<str>, bool), PolicyError> {
    let object = parsed.tree.as_object().ok_or(PolicyError::InvalidStructure)?;
    let model = object
        .get("model")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(Box::from)
        .ok_or(PolicyError::InvalidStructure)?;
    if !object.get("messages").is_some_and(Value::is_array)
        || (require_max_tokens && object.get("max_tokens").is_none())
        || object
            .get("max_tokens")
            .is_some_and(|value| !value.is_null() && value.as_u64().is_none())
    {
        return Err(PolicyError::InvalidStructure);
    }
    let stream = match object.get("stream") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(PolicyError::InvalidStructure),
    };
    Ok((model, stream))
}

fn filter_count_tokens_diagnostics(
    diagnostics: Vec<CapabilityDiagnostic>,
    require_max_tokens: bool,
) -> Vec<CapabilityDiagnostic> {
    if require_max_tokens {
        diagnostics
    } else {
        diagnostics
            .into_iter()
            .filter(|diagnostic| diagnostic.path.as_ref() != "body:/max_tokens")
            .collect()
    }
}

fn validate_mutation_path(path: &str) -> Result<(), CapabilityCompileError> {
    let Some(pointer) = path.strip_prefix("body:") else {
        return Err(CapabilityCompileError::InvalidPath);
    };
    // Message content is immutable policy input. Besides protecting prompt
    // attribution, this keeps the client-provided first user text stable for
    // downstream billing fingerprints.
    if !pointer.starts_with('/')
        || pointer.contains('*')
        || pointer == "/model"
        || pointer.starts_with("/model/")
        || pointer == "/messages"
        || pointer.starts_with("/messages/")
    {
        return Err(CapabilityCompileError::InvalidPath);
    }
    Ok(())
}

fn apply_rules(
    ruleset: &CompiledRuleSet,
    tree: &mut Value,
    evaluation: &EvaluationContext,
    changes: &mut Vec<AppliedChange>,
) -> Result<(), PolicyError> {
    for rule in ruleset.rules.iter() {
        if !condition_matches(&rule.when, tree, evaluation).map_err(map_runtime_error)? {
            continue;
        }
        let path = rule
            .action
            .path()
            .strip_prefix("body:")
            .ok_or(PolicyError::CapabilityRuntimeConflict)?;
        let before = tree.pointer(path).cloned();
        match &rule.action {
            RuleAction::SetDefault { value, .. } if before.is_none() => set_pointer(tree, path, value.clone())?,
            RuleAction::Set { value, .. } => set_pointer(tree, path, value.clone())?,
            RuleAction::Remove { .. } => remove_pointer(tree, path)?,
            RuleAction::ClampNumber { minimum, maximum, .. } => {
                if let Some(number) = before.as_ref().and_then(Value::as_f64) {
                    let mut bounded = number;
                    if let Some(minimum) = minimum {
                        bounded = bounded.max(*minimum);
                    }
                    if let Some(maximum) = maximum {
                        bounded = bounded.min(*maximum);
                    }
                    if bounded.total_cmp(&number).is_ne() {
                        set_pointer(tree, path, json!(bounded))?;
                    }
                }
            }
            RuleAction::SetDefault { .. } => {}
        }
        let after = tree.pointer(path).cloned();
        if before != after {
            changes.push(change(
                rule.id.clone(),
                path,
                before.as_ref(),
                after.as_ref(),
                rule.reason.clone(),
                rule.risk,
            ));
        }
    }
    Ok(())
}

/// Result of applying the Group System policy at the Credential-neutral stage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EnforcementOutcome {
    attribution_suppressed: bool,
    system_template_pending: bool,
}

fn apply_enforcement(
    enforcement: &Enforcement,
    tree: &mut Value,
    changes: &mut Vec<AppliedChange>,
) -> Result<EnforcementOutcome, PolicyError> {
    let current = tree.get("system").cloned();
    if current
        .as_ref()
        .is_some_and(|value| !value.is_string() && !value.is_array())
    {
        return Err(PolicyError::InvalidStructure);
    }
    let mut outcome = EnforcementOutcome::default();
    let (next, reason) = match &enforcement.system {
        SystemPolicy::Preserve => return Ok(outcome),
        // The Claude Code billing block survives so the dispatcher can still
        // align attribution; everything the client authored is dropped.
        SystemPolicy::StripClient => (current.as_ref().and_then(strip_client_system), "system_strip_client"),
        SystemPolicy::Replace { content, .. } => {
            if is_empty_replacement(content) {
                // Empty administrator content defers to the captured static
                // template of the Archetype selected at dispatch time.
                outcome.system_template_pending = true;
                return Ok(outcome);
            }
            let mut next = current.clone().unwrap_or(Value::Null);
            replace_system_static(&mut next, content);
            (Some(next), "system_replace")
        }
        SystemPolicy::StripAll => {
            outcome.attribution_suppressed = true;
            (None, "system_strip_all")
        }
    };
    match &next {
        Some(value) => set_pointer(tree, "/system", value.clone())?,
        None => remove_pointer(tree, "/system")?,
    }
    let after = tree.get("system");
    if current.as_ref() != after {
        changes.push(change(
            Box::from("group_enforcement.system"),
            "/system",
            current.as_ref(),
            after,
            Box::from(reason),
            ChangeRisk::High,
        ));
    }
    Ok(outcome)
}

/// Keep `system` immediately before `messages` after any in-place rewrite.
pub fn canonicalize_system_order(tree: &mut Value) {
    let Some(object) = tree.as_object_mut() else {
        return;
    };
    if !object.contains_key("system") || !object.contains_key("messages") {
        return;
    }
    let original = std::mem::take(object);
    let system = original.get("system").cloned();
    let mut reordered = Map::with_capacity(original.len());
    for (key, value) in original {
        if key == "messages"
            && let Some(system) = system.clone()
        {
            reordered.insert("system".to_owned(), system);
        }
        if key != "system" {
            reordered.insert(key, value);
        }
    }
    *object = reordered;
}

fn classify_portability(
    parsed: &ParsedRequest,
    tree: &Value,
    affinity_credential: Option<CredentialId>,
) -> Portability {
    let mut reasons = BTreeSet::new();
    if !parsed.unknown_top_level.is_empty() || !parsed.unknown_content_blocks.is_empty() {
        reasons.insert(PinReason::UnknownExtension);
    }
    scan_pin_reasons(tree, &mut reasons);
    if reasons.is_empty() {
        Portability::Portable
    } else {
        Portability::Pinned {
            credential_id: affinity_credential,
            reasons: reasons.into_iter().collect(),
        }
    }
}

fn scan_pin_reasons(value: &Value, reasons: &mut BTreeSet<PinReason>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                match key.as_str() {
                    "continuation" | "continuation_token" => {
                        reasons.insert(PinReason::Continuation);
                    }
                    "file_id" | "container_id" | "batch_id" => {
                        reasons.insert(PinReason::AccountResource);
                    }
                    "credential_extension" => {
                        reasons.insert(PinReason::CredentialExtension);
                    }
                    _ => {}
                }
                scan_pin_reasons(value, reasons);
            }
        }
        Value::Array(values) => {
            for value in values {
                scan_pin_reasons(value, reasons);
            }
        }
        _ => {}
    }
}

fn set_pointer(tree: &mut Value, pointer: &str, value: Value) -> Result<(), PolicyError> {
    let (parent, leaf) = split_pointer(pointer)?;
    let parent = if parent.is_empty() {
        tree
    } else {
        tree.pointer_mut(&parent).ok_or(PolicyError::InvalidStructure)?
    };
    match parent {
        Value::Object(object) => {
            object.insert(leaf, value);
            Ok(())
        }
        Value::Array(array) => {
            let index = leaf.parse::<usize>().map_err(|_| PolicyError::InvalidStructure)?;
            let slot = array.get_mut(index).ok_or(PolicyError::InvalidStructure)?;
            *slot = value;
            Ok(())
        }
        _ => Err(PolicyError::InvalidStructure),
    }
}

fn remove_pointer(tree: &mut Value, pointer: &str) -> Result<(), PolicyError> {
    let (parent, leaf) = split_pointer(pointer)?;
    let parent = if parent.is_empty() {
        tree
    } else if let Some(value) = tree.pointer_mut(&parent) {
        value
    } else {
        return Ok(());
    };
    match parent {
        Value::Object(object) => {
            object.remove(&leaf);
            Ok(())
        }
        Value::Array(array) => {
            let index = leaf.parse::<usize>().map_err(|_| PolicyError::InvalidStructure)?;
            if index < array.len() {
                array.remove(index);
            }
            Ok(())
        }
        _ => Err(PolicyError::InvalidStructure),
    }
}

fn split_pointer(pointer: &str) -> Result<(String, String), PolicyError> {
    let index = pointer.rfind('/').ok_or(PolicyError::InvalidStructure)?;
    let parent = pointer[..index].to_owned();
    let leaf = pointer[index + 1..].replace("~1", "/").replace("~0", "~");
    if leaf.is_empty() {
        return Err(PolicyError::InvalidStructure);
    }
    Ok((parent, leaf))
}

fn change(
    rule_id: Box<str>,
    path: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    reason: Box<str>,
    risk: ChangeRisk,
) -> AppliedChange {
    AppliedChange {
        rule_id,
        path: Box::from(path),
        before_digest: value_digest(before),
        after_digest: value_digest(after),
        reason,
        risk,
    }
}

fn value_digest(value: Option<&Value>) -> Digest {
    value.map_or_else(
        || Digest::of(b"gateway:missing"),
        |value| {
            serde_json::to_vec(value)
                .map_or_else(|_| Digest::of(b"gateway:serializer-error"), |bytes| Digest::of(&bytes))
        },
    )
}

fn map_runtime_error(error: RuntimeCapabilityError) -> PolicyError {
    match error {
        RuntimeCapabilityError::PathExpansionLimit => PolicyError::CapabilityPathExpansionLimit,
        RuntimeCapabilityError::Conflict => PolicyError::CapabilityRuntimeConflict,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "test fixtures must have the asserted shape")]
mod tests {
    use std::sync::Arc;

    use gateway_domain::{ChangeRisk, ClientClass, ClientOs, Portability, RequestSnapshotSet, SnapshotVersion};
    use serde_json::{Value, json};

    use super::{
        CompiledRuleSet, Enforcement, PolicyContext, RequestPolicy, RuleAction, RuleDefinition, RulePhase, SchemaMode,
        SystemPolicy,
    };
    use crate::CapabilityCondition;

    fn snapshots() -> Arc<RequestSnapshotSet> {
        let version = || SnapshotVersion::new("v1");
        Arc::new(RequestSnapshotSet {
            access_policy: version(),
            group_config: version(),
            enforcement: version(),
            ruleset: None,
            capability: version(),
            client_profile_catalog: version(),
            price: version(),
            serializer: version(),
        })
    }

    fn context() -> PolicyContext {
        PolicyContext {
            client_class: ClientClass::NonClaudeCodeCli,
            client_os: ClientOs::Windows,
            protocol_headers: std::collections::BTreeMap::default(),
            affinity_credential: None,
        }
    }

    fn raw(extra: &str) -> Arc<[u8]> {
        Arc::from(format!(r#"{{"model":"m","max_tokens":32,"messages":[]{extra}}}"#).into_bytes())
    }

    #[test]
    fn zero_change_reuses_original_and_unknown_pins() -> Result<(), Box<dyn std::error::Error>> {
        let policy = RequestPolicy::base_for_models(["m"], snapshots())?;
        let generic = policy.process(raw(r#", "future": 1"#), &context())?;
        assert!(generic.replay_body.reused_original());
        assert!(generic.digest_is_valid());
        assert!(matches!(generic.portability, Portability::Pinned { .. }));
        Ok(())
    }

    #[test]
    fn cli_mid_conversation_system_and_cache_blocks_are_preserved() -> Result<(), Box<dyn std::error::Error>> {
        let body = serde_json::to_vec(&json!({
            "model":"claude-opus-5","max_tokens":64000,"stream":true,
            "system":[{"type":"text","text":"fixture system","cache_control":{"type":"ephemeral"}}],
            "messages":[{"role":"user","content":"fixture input"},
                {"role":"system","content":"fixture reminder"}],
            "thinking":{"type":"disabled"},"output_config":{"effort":"high"}
        }))?;
        let policy = RequestPolicy::base_for_models(["claude-opus-5"], snapshots())?;
        let generic = policy.process(Arc::from(body.clone()), &context())?;
        assert!(generic.replay_body.reused_original());
        assert_eq!(generic.replay_body.bytes(), body.as_slice());
        Ok(())
    }

    #[test]
    fn all_system_modes_have_frozen_semantics() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (SystemPolicy::Preserve, Some(json!("client")), false),
            (SystemPolicy::StripClient, None, false),
            (
                SystemPolicy::Replace {
                    platform_system_ref: Box::from("system-v1"),
                    content: json!("platform"),
                },
                Some(json!("platform")),
                false,
            ),
            (SystemPolicy::StripAll, None, true),
        ];
        for (system, expected, suppressed) in cases {
            let mut policy = RequestPolicy::base_for_models(["m"], snapshots())?;
            policy.enforcement = Enforcement { system };
            let generic = policy.process(raw(r#", "system": "client""#), &context())?;
            assert_eq!(generic.replay_body.tree().get("system"), expected.as_ref());
            assert_eq!(generic.attribution_suppressed, suppressed);
        }
        Ok(())
    }

    fn claude_code_raw() -> Arc<[u8]> {
        raw(concat!(
            r##", "system": ["##,
            r##"{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.220.a3f; cc_entrypoint=cli;"},"##,
            r##"{"type":"text","text":"You are Claude Code.\n# Tone and style\n","cache_control":{"type":"ephemeral"}},"##,
            r##"{"type":"text","text":"# Environment\n - Platform: win32\n"}"##,
            r##"]"##
        ))
    }

    #[test]
    fn strip_client_keeps_the_claude_code_billing_block() -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = RequestPolicy::base_for_models(["m"], snapshots())?;
        policy.enforcement = Enforcement {
            system: SystemPolicy::StripClient,
        };
        let generic = policy.process(claude_code_raw(), &context())?;
        let system = generic.replay_body.tree()["system"]
            .as_array()
            .cloned()
            .expect("system array");
        assert_eq!(system.len(), 1);
        assert!(
            system[0]["text"]
                .as_str()
                .is_some_and(|text| text.starts_with("x-anthropic-billing-header:"))
        );
        assert!(!generic.attribution_suppressed);
        assert!(!generic.system_template_pending);
        Ok(())
    }

    #[test]
    fn replace_swaps_the_static_segment_and_keeps_environment() -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = RequestPolicy::base_for_models(["m"], snapshots())?;
        policy.enforcement = Enforcement {
            system: SystemPolicy::Replace {
                platform_system_ref: Box::from("system-v1"),
                content: json!("platform static"),
            },
        };
        let generic = policy.process(claude_code_raw(), &context())?;
        let system = generic.replay_body.tree()["system"]
            .as_array()
            .cloned()
            .expect("system array");
        assert_eq!(system.len(), 3);
        assert_eq!(system[1]["text"], "platform static");
        assert_eq!(system[1]["cache_control"]["type"], "ephemeral");
        assert!(
            system[2]["text"]
                .as_str()
                .is_some_and(|text| text.contains("Platform: win32"))
        );
        assert_eq!(generic.change_set.len(), 1);
        let keys = generic
            .replay_body
            .tree()
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let system_at = keys.iter().position(|key| key == "system");
        let messages_at = keys.iter().position(|key| key == "messages");
        assert!(system_at < messages_at, "system must precede messages: {keys:?}");
        Ok(())
    }

    #[test]
    fn empty_replace_content_defers_to_the_archetype_template() -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = RequestPolicy::base_for_models(["m"], snapshots())?;
        policy.enforcement = Enforcement {
            system: SystemPolicy::Replace {
                platform_system_ref: Box::from("system-v1"),
                content: json!(""),
            },
        };
        let generic = policy.process(claude_code_raw(), &context())?;
        assert!(generic.system_template_pending);
        assert!(generic.replay_body.reused_original());
        assert!(generic.change_set.is_empty());
        Ok(())
    }

    #[test]
    fn ruleset_cannot_weaken_group_system_enforcement() -> Result<(), Box<dyn std::error::Error>> {
        let ruleset = CompiledRuleSet::compile(
            "key-rules",
            vec![RuleDefinition {
                id: Box::from("attempt-system-restore"),
                phase: RulePhase::System,
                action: RuleAction::Set {
                    path: Box::from("body:/system"),
                    value: json!("key-supplied-system"),
                },
                when: CapabilityCondition::Always,
                reason: Box::from("fixture"),
                risk: ChangeRisk::High,
            }],
        )?;
        let mut policy = RequestPolicy::base_for_models(["m"], snapshots())?;
        policy.ruleset = Some(ruleset);
        policy.enforcement = Enforcement {
            system: SystemPolicy::StripAll,
        };
        let generic = policy.process(raw(r#", "system": "client""#), &context())?;
        assert!(generic.replay_body.tree().get("system").is_none());
        assert!(generic.attribution_suppressed);
        Ok(())
    }

    #[test]
    fn rules_are_deterministic_and_model_is_not_a_valid_target() -> Result<(), Box<dyn std::error::Error>> {
        let definition = RuleDefinition {
            id: Box::from("default-temperature"),
            phase: RulePhase::Default,
            action: RuleAction::SetDefault {
                path: Box::from("body:/temperature"),
                value: json!(0.2),
            },
            when: CapabilityCondition::Always,
            reason: Box::from("configured_default"),
            risk: ChangeRisk::Low,
        };
        let ruleset = CompiledRuleSet::compile("rules-v1", vec![definition])?;
        let mut policy = RequestPolicy::base_for_models(["m"], snapshots())?;
        policy.ruleset = Some(ruleset);
        let first = policy.process(raw(""), &context())?;
        let second = policy.process(raw(""), &context())?;
        assert_eq!(first.replay_body.bytes(), second.replay_body.bytes());
        assert_eq!(first.model_id.as_ref(), "m");

        let invalid = RuleDefinition {
            id: Box::from("rewrite-model"),
            phase: RulePhase::Default,
            action: RuleAction::Set {
                path: Box::from("body:/model"),
                value: Value::String("other".to_owned()),
            },
            when: CapabilityCondition::Always,
            reason: Box::from("bad"),
            risk: ChangeRisk::High,
        };
        assert!(CompiledRuleSet::compile("bad", vec![invalid]).is_err());

        for path in ["body:/messages", "body:/messages/0", "body:/messages/0/content/0/text"] {
            let invalid = RuleDefinition {
                id: Box::from("rewrite-message"),
                phase: RulePhase::Default,
                action: RuleAction::Remove { path: Box::from(path) },
                when: CapabilityCondition::Always,
                reason: Box::from("bad"),
                risk: ChangeRisk::High,
            };
            assert!(
                CompiledRuleSet::compile("bad-message", vec![invalid]).is_err(),
                "path {path}"
            );
        }
        Ok(())
    }

    #[test]
    fn ruleset_simulation_returns_only_digest_and_change_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let ruleset = CompiledRuleSet::compile(
            "rules-v1",
            vec![RuleDefinition {
                id: Box::from("default-temperature"),
                phase: RulePhase::Default,
                action: RuleAction::SetDefault {
                    path: Box::from("body:/temperature"),
                    value: json!(0.2),
                },
                when: CapabilityCondition::Always,
                reason: Box::from("configured_default"),
                risk: ChangeRisk::Low,
            }],
        )?;
        let sample = json!({"model":"m","max_tokens":32,"messages":[]});
        let result = ruleset.simulate(sample, &context())?;
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path.as_ref(), "/temperature");
        assert_ne!(result.changes[0].before_digest, result.changes[0].after_digest);
        Ok(())
    }

    #[test]
    fn layered_rules_preserve_group_then_key_precedence() -> Result<(), Box<dyn std::error::Error>> {
        let rule = |id: &'static str, value: i64| RuleDefinition {
            id: Box::from(id),
            phase: RulePhase::Default,
            action: RuleAction::Set {
                path: Box::from("body:/temperature"),
                value: json!(value),
            },
            when: CapabilityCondition::Always,
            reason: Box::from("layered_override"),
            risk: ChangeRisk::Low,
        };
        let ruleset = CompiledRuleSet::compile_layers(
            "effective-rules",
            vec![vec![rule("z-group", 1)], vec![rule("a-key", 2)]],
        )?;
        let mut policy = RequestPolicy::base_for_models(["m"], snapshots())?;
        policy.ruleset = Some(ruleset);
        let generic = policy.process(raw(""), &context())?;
        assert_eq!(generic.replay_body.tree()["temperature"], json!(2));
        Ok(())
    }

    #[test]
    fn strict_mode_rejects_unknown() -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = RequestPolicy::base_for_models(["m"], snapshots())?;
        policy.schema_mode = SchemaMode::Strict;
        assert!(policy.process(raw(",\"future\":1"), &context()).is_err());
        Ok(())
    }
}
