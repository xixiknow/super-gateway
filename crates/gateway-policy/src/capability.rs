//! Data-driven model capability compilation and deterministic validation.
#![allow(missing_docs, clippy::doc_markdown)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const MAX_CONDITION_DEPTH: usize = 8;
const MAX_CONDITION_NODES: usize = 128;
const MAX_DIRECT_CHILDREN: usize = 32;
const MAX_WILDCARDS: usize = 3;
const MAX_PATH_EXPANSIONS: usize = 1_024;
const REQUEST_FACTS: &[&str] = &["client_class", "model", "stream", "traffic_class"];

/// Capability presence action. Capability validates; it never mutates requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAction {
    /// A field must be present; nullability remains a type decision.
    Required,
    /// A field may be present subject to constraints.
    Allowed,
    /// A field must be absent.
    Forbidden,
}

/// Strict JSON value types. Integer is a subset of the shared numeric domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonType {
    Null,
    Boolean,
    Integer,
    Number,
    String,
    Array,
    Object,
}

/// How wildcard results are reduced for a condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// At least one expansion must match.
    AnyMatch,
    /// At least one expansion must exist and every expansion must match.
    AllMatch,
}

/// Bounded, typed condition tree shared by Capability and RuleSet definitions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CapabilityCondition {
    Always,
    All {
        conditions: Vec<CapabilityCondition>,
    },
    Any {
        conditions: Vec<CapabilityCondition>,
    },
    Not {
        condition: Box<CapabilityCondition>,
    },
    Present {
        path: Box<str>,
        mode: MatchMode,
    },
    Equals {
        path: Box<str>,
        value: Value,
        mode: MatchMode,
    },
    In {
        path: Box<str>,
        values: Vec<Value>,
        mode: MatchMode,
    },
}

/// One published model capability rule.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRule {
    pub id: Box<str>,
    pub path: Box<str>,
    pub action: CapabilityAction,
    #[serde(default)]
    pub types: BTreeSet<JsonType>,
    #[serde(default)]
    pub enum_values: Vec<Value>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    #[serde(default)]
    pub required_children: BTreeSet<Box<str>>,
    pub when: CapabilityCondition,
}

/// Context values visible to published conditions.
#[derive(Clone, Debug, Default)]
pub struct EvaluationContext {
    /// Lowercase protocol header values approved for policy inspection.
    pub headers: BTreeMap<Box<str>, Value>,
    /// Allowlisted request facts such as client class and stream.
    pub request: BTreeMap<Box<str>, Value>,
}

/// Compile-time failures prevent an artifact from becoming eligible.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CapabilityCompileError {
    #[error("capability identifier/model/rule identifier is empty")]
    EmptyIdentifier,
    #[error("invalid capability path")]
    InvalidPath,
    #[error("capability condition exceeds bounded complexity")]
    ConditionLimit,
    #[error("capability numeric range is empty")]
    EmptyRange,
    #[error("capability rules conflict")]
    Conflict,
}

/// Runtime errors distinguish client path expansion from a quarantinable artifact conflict.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RuntimeCapabilityError {
    #[error("CAPABILITY_PATH_EXPANSION_LIMIT")]
    PathExpansionLimit,
    #[error("CAPABILITY_RUNTIME_CONFLICT")]
    Conflict,
}

/// Stable, privacy-safe validation diagnostic.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CapabilityDiagnostic {
    pub path: Box<str>,
    pub code: Box<str>,
}

/// Immutable, compiled Capability artifact for one exact model ID.
#[derive(Clone, Debug)]
pub struct CompiledCapabilitySnapshot {
    id: Box<str>,
    model_id: Box<str>,
    rules: ArcRules,
}

type ArcRules = std::sync::Arc<[CapabilityRule]>;

impl CompiledCapabilitySnapshot {
    /// Validate and compile a published model capability without order semantics.
    ///
    /// # Errors
    ///
    /// Returns a bounded compile error when identifiers, paths, conditions, ranges, or
    /// unconditional rule intersections are invalid.
    pub fn compile(
        id: impl Into<Box<str>>,
        model_id: impl Into<Box<str>>,
        mut rules: Vec<CapabilityRule>,
    ) -> Result<Self, CapabilityCompileError> {
        let id = id.into();
        let model_id = model_id.into();
        if id.is_empty() || model_id.is_empty() || rules.iter().any(|rule| rule.id.is_empty()) {
            return Err(CapabilityCompileError::EmptyIdentifier);
        }
        for rule in &rules {
            validate_path(&rule.path)?;
            validate_condition(&rule.when)?;
            if rule.minimum.zip(rule.maximum).is_some_and(|(min, max)| min > max) {
                return Err(CapabilityCompileError::EmptyRange);
            }
            if !rule.enum_values.iter().all(is_scalar) {
                return Err(CapabilityCompileError::Conflict);
            }
        }
        rules.sort_by(|left, right| left.id.cmp(&right.id));
        validate_unconditional_intersections(&rules)?;
        Ok(Self {
            id,
            model_id,
            rules: rules.into(),
        })
    }

    /// Artifact identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Exact model identifier. No aliases are accepted.
    #[must_use]
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// Validate a tree against the effective conditional intersections.
    ///
    /// `final_pass=false` defers only missing-required diagnostics so explicit defaults may run.
    ///
    /// # Errors
    ///
    /// Returns expansion-limit or runtime-conflict errors; ordinary client mistakes are diagnostics.
    pub fn validate(
        &self,
        tree: &Value,
        context: &EvaluationContext,
        final_pass: bool,
    ) -> Result<Vec<CapabilityDiagnostic>, RuntimeCapabilityError> {
        let mut active = BTreeMap::<&str, Vec<&CapabilityRule>>::new();
        for rule in self.rules.iter() {
            if condition_matches(&rule.when, tree, context)? {
                active.entry(&rule.path).or_default().push(rule);
            }
        }
        let mut diagnostics = Vec::new();
        for (path, rules) in active {
            let constraints = merge_rules(&rules).map_err(|()| RuntimeCapabilityError::Conflict)?;
            let values = expand_path(path, tree, context)?;
            if values.is_empty() {
                if final_pass && constraints.action == CapabilityAction::Required {
                    diagnostics.push(diagnostic(path, "required"));
                }
                continue;
            }
            if constraints.action == CapabilityAction::Forbidden {
                diagnostics.push(diagnostic(path, "forbidden"));
                continue;
            }
            for value in values {
                if !constraints.types.is_empty() && !constraints.types.iter().any(|kind| type_matches(*kind, value)) {
                    diagnostics.push(diagnostic(path, "invalid_type"));
                    continue;
                }
                if !constraints.enum_values.is_empty()
                    && !constraints
                        .enum_values
                        .iter()
                        .any(|allowed| strict_equal(allowed, value))
                {
                    diagnostics.push(diagnostic(path, "invalid_enum"));
                }
                if let Some(number) = value.as_f64()
                    && (constraints.minimum.is_some_and(|min| number < min)
                        || constraints.maximum.is_some_and(|max| number > max))
                {
                    diagnostics.push(diagnostic(path, "out_of_range"));
                }
                if let Some(object) = value.as_object() {
                    for child in &constraints.required_children {
                        if !object.contains_key(child.as_ref()) {
                            diagnostics.push(diagnostic(path, "required_child"));
                            break;
                        }
                    }
                }
            }
        }
        diagnostics.sort_unstable();
        diagnostics.dedup();
        Ok(diagnostics)
    }
}

/// Exact-model lookup catalog frozen in the request snapshot.
#[derive(Clone, Debug, Default)]
pub struct CapabilityCatalog {
    models: BTreeMap<Box<str>, std::sync::Arc<CompiledCapabilitySnapshot>>,
}

impl CapabilityCatalog {
    /// Build a catalog and reject duplicate exact model IDs.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityCompileError::Conflict`] for duplicates.
    pub fn new(snapshots: Vec<CompiledCapabilitySnapshot>) -> Result<Self, CapabilityCompileError> {
        let mut models = BTreeMap::new();
        for snapshot in snapshots {
            let model = snapshot.model_id.clone();
            if models.insert(model, std::sync::Arc::new(snapshot)).is_some() {
                return Err(CapabilityCompileError::Conflict);
            }
        }
        Ok(Self { models })
    }

    /// Resolve only the exact client model string.
    #[must_use]
    pub fn get(&self, model_id: &str) -> Option<&std::sync::Arc<CompiledCapabilitySnapshot>> {
        self.models.get(model_id)
    }
}

#[derive(Clone)]
struct EffectiveConstraints {
    action: CapabilityAction,
    types: BTreeSet<JsonType>,
    enum_values: Vec<Value>,
    minimum: Option<f64>,
    maximum: Option<f64>,
    required_children: BTreeSet<Box<str>>,
}

fn validate_unconditional_intersections(rules: &[CapabilityRule]) -> Result<(), CapabilityCompileError> {
    let mut groups = BTreeMap::<&str, Vec<&CapabilityRule>>::new();
    for rule in rules {
        if matches!(rule.when, CapabilityCondition::Always) {
            groups.entry(&rule.path).or_default().push(rule);
        }
    }
    for group in groups.values() {
        merge_rules(group).map_err(|()| CapabilityCompileError::Conflict)?;
    }
    Ok(())
}

fn merge_rules(rules: &[&CapabilityRule]) -> Result<EffectiveConstraints, ()> {
    let mut action = CapabilityAction::Allowed;
    let mut types: Option<BTreeSet<JsonType>> = None;
    let mut enum_values: Option<Vec<Value>> = None;
    let mut minimum: Option<f64> = None;
    let mut maximum: Option<f64> = None;
    let mut required_children = BTreeSet::new();
    for rule in rules {
        action = merge_action(action, rule.action)?;
        if !rule.types.is_empty() {
            types = Some(match types {
                None => rule.types.clone(),
                Some(current) => current.intersection(&rule.types).copied().collect(),
            });
        }
        if !rule.enum_values.is_empty() {
            enum_values = Some(match enum_values {
                None => rule.enum_values.clone(),
                Some(current) => current
                    .into_iter()
                    .filter(|candidate| rule.enum_values.iter().any(|value| strict_equal(candidate, value)))
                    .collect(),
            });
        }
        minimum = match (minimum, rule.minimum) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (left, right) => left.or(right),
        };
        maximum = match (maximum, rule.maximum) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        };
        required_children.extend(rule.required_children.iter().cloned());
    }
    let types = types.unwrap_or_default();
    let enum_values = enum_values.unwrap_or_default();
    if rules.iter().any(|rule| !rule.types.is_empty()) && types.is_empty()
        || rules.iter().any(|rule| !rule.enum_values.is_empty()) && enum_values.is_empty()
        || minimum.zip(maximum).is_some_and(|(min, max)| min > max)
    {
        return Err(());
    }
    Ok(EffectiveConstraints {
        action,
        types,
        enum_values,
        minimum,
        maximum,
        required_children,
    })
}

fn merge_action(left: CapabilityAction, right: CapabilityAction) -> Result<CapabilityAction, ()> {
    match (left, right) {
        (CapabilityAction::Forbidden, CapabilityAction::Forbidden) => Ok(CapabilityAction::Forbidden),
        (CapabilityAction::Forbidden, _) | (_, CapabilityAction::Forbidden) => Err(()),
        (CapabilityAction::Required, _) | (_, CapabilityAction::Required) => Ok(CapabilityAction::Required),
        _ => Ok(CapabilityAction::Allowed),
    }
}

fn validate_path(path: &str) -> Result<(), CapabilityCompileError> {
    if let Some(pointer) = path.strip_prefix("body:") {
        if !pointer.starts_with('/') || pointer.split('/').filter(|segment| *segment == "*").count() > MAX_WILDCARDS {
            return Err(CapabilityCompileError::InvalidPath);
        }
        return Ok(());
    }
    if let Some(header) = path.strip_prefix("header:") {
        if header.is_empty() || header != header.to_ascii_lowercase() || !header.is_ascii() {
            return Err(CapabilityCompileError::InvalidPath);
        }
        return Ok(());
    }
    if path
        .strip_prefix("request:")
        .is_some_and(|name| REQUEST_FACTS.contains(&name))
    {
        Ok(())
    } else {
        Err(CapabilityCompileError::InvalidPath)
    }
}

pub(crate) fn validate_condition(condition: &CapabilityCondition) -> Result<(), CapabilityCompileError> {
    fn walk(condition: &CapabilityCondition, depth: usize, nodes: &mut usize) -> Result<(), CapabilityCompileError> {
        *nodes += 1;
        if depth > MAX_CONDITION_DEPTH || *nodes > MAX_CONDITION_NODES {
            return Err(CapabilityCompileError::ConditionLimit);
        }
        match condition {
            CapabilityCondition::Always => Ok(()),
            CapabilityCondition::All { conditions } | CapabilityCondition::Any { conditions } => {
                if conditions.len() > MAX_DIRECT_CHILDREN {
                    return Err(CapabilityCompileError::ConditionLimit);
                }
                for child in conditions {
                    walk(child, depth + 1, nodes)?;
                }
                Ok(())
            }
            CapabilityCondition::Not { condition } => walk(condition, depth + 1, nodes),
            CapabilityCondition::Present { path, .. } => validate_path(path),
            CapabilityCondition::Equals { path, value, .. } => {
                validate_path(path)?;
                if is_scalar(value) {
                    Ok(())
                } else {
                    Err(CapabilityCompileError::Conflict)
                }
            }
            CapabilityCondition::In { path, values, .. } => {
                validate_path(path)?;
                if values.iter().all(is_scalar) {
                    Ok(())
                } else {
                    Err(CapabilityCompileError::Conflict)
                }
            }
        }
    }
    walk(condition, 1, &mut 0)
}

pub(crate) fn condition_matches(
    condition: &CapabilityCondition,
    tree: &Value,
    context: &EvaluationContext,
) -> Result<bool, RuntimeCapabilityError> {
    match condition {
        CapabilityCondition::Always => Ok(true),
        CapabilityCondition::All { conditions } => {
            for child in conditions {
                if !condition_matches(child, tree, context)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        CapabilityCondition::Any { conditions } => {
            for child in conditions {
                if condition_matches(child, tree, context)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        CapabilityCondition::Not { condition } => Ok(!condition_matches(condition, tree, context)?),
        CapabilityCondition::Present { path, mode } => {
            let values = expand_path(path, tree, context)?;
            Ok(reduce(values.iter().map(|_| true), *mode))
        }
        CapabilityCondition::Equals { path, value, mode } => {
            let values = expand_path(path, tree, context)?;
            Ok(reduce(
                values.iter().map(|candidate| strict_equal(candidate, value)),
                *mode,
            ))
        }
        CapabilityCondition::In {
            path,
            values: expected,
            mode,
        } => {
            let values = expand_path(path, tree, context)?;
            Ok(reduce(
                values
                    .iter()
                    .map(|candidate| expected.iter().any(|value| strict_equal(candidate, value))),
                *mode,
            ))
        }
    }
}

fn reduce(matches: impl Iterator<Item = bool>, mode: MatchMode) -> bool {
    let values = matches.collect::<Vec<_>>();
    !values.is_empty()
        && match mode {
            MatchMode::AnyMatch => values.into_iter().any(|value| value),
            MatchMode::AllMatch => values.into_iter().all(|value| value),
        }
}

fn expand_path<'a>(
    path: &str,
    tree: &'a Value,
    context: &'a EvaluationContext,
) -> Result<Vec<&'a Value>, RuntimeCapabilityError> {
    if let Some(pointer) = path.strip_prefix("body:") {
        let mut values = vec![tree];
        for raw_segment in pointer.split('/').skip(1) {
            let segment = raw_segment.replace("~1", "/").replace("~0", "~");
            let mut next = Vec::new();
            for value in values {
                if segment == "*" {
                    if let Some(items) = value.as_array() {
                        next.extend(items);
                    }
                } else if let Some(child) = value.get(&segment) {
                    next.push(child);
                }
                if next.len() > MAX_PATH_EXPANSIONS {
                    return Err(RuntimeCapabilityError::PathExpansionLimit);
                }
            }
            values = next;
        }
        Ok(values)
    } else if let Some(name) = path.strip_prefix("header:") {
        Ok(context.headers.get(name).into_iter().collect())
    } else if let Some(name) = path.strip_prefix("request:") {
        Ok(context.request.get(name).into_iter().collect())
    } else {
        Ok(Vec::new())
    }
}

fn type_matches(kind: JsonType, value: &Value) -> bool {
    match kind {
        JsonType::Null => value.is_null(),
        JsonType::Boolean => value.is_boolean(),
        JsonType::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
        JsonType::Number => value.is_number(),
        JsonType::String => value.is_string(),
        JsonType::Array => value.is_array(),
        JsonType::Object => value.is_object(),
    }
}

fn strict_equal(left: &Value, right: &Value) -> bool {
    if left.is_number() && right.is_number() {
        left.as_f64() == right.as_f64()
    } else {
        std::mem::discriminant(left) == std::mem::discriminant(right) && left == right
    }
}

fn is_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

fn diagnostic(path: &str, code: &'static str) -> CapabilityDiagnostic {
    CapabilityDiagnostic {
        path: Box::from(path),
        code: Box::from(code),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::{
        CapabilityAction, CapabilityCondition, CapabilityRule, CompiledCapabilitySnapshot, EvaluationContext, JsonType,
    };

    fn rule(id: &str, path: &str, action: CapabilityAction, types: &[JsonType]) -> CapabilityRule {
        CapabilityRule {
            id: Box::from(id),
            path: Box::from(path),
            action,
            types: types.iter().copied().collect::<BTreeSet<_>>(),
            enum_values: Vec::new(),
            minimum: None,
            maximum: None,
            required_children: BTreeSet::new(),
            when: CapabilityCondition::Always,
        }
    }

    #[test]
    fn required_is_presence_and_nullability_is_type() -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = CompiledCapabilitySnapshot::compile(
            "cap-v1",
            "model-a",
            vec![rule(
                "thinking",
                "body:/thinking",
                CapabilityAction::Required,
                &[JsonType::Object],
            )],
        )?;
        let missing = snapshot.validate(&json!({}), &EvaluationContext::default(), true)?;
        let null = snapshot.validate(&json!({"thinking": null}), &EvaluationContext::default(), true)?;
        assert_eq!(missing[0].code.as_ref(), "required");
        assert_eq!(null[0].code.as_ref(), "invalid_type");
        Ok(())
    }

    #[test]
    fn conflicting_unconditional_rules_fail_compile() {
        let result = CompiledCapabilitySnapshot::compile(
            "cap-v1",
            "model-a",
            vec![
                rule("a", "body:/thinking", CapabilityAction::Allowed, &[JsonType::Object]),
                rule("b", "body:/thinking", CapabilityAction::Forbidden, &[]),
            ],
        );
        assert!(result.is_err());
    }

    #[test]
    fn wildcard_expansion_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = CompiledCapabilitySnapshot::compile(
            "cap-v1",
            "model-a",
            vec![rule(
                "text",
                "body:/messages/*/content/*/text",
                CapabilityAction::Allowed,
                &[JsonType::String],
            )],
        )?;
        let body = json!({"messages": (0..1025).map(|_| json!({"content":[{"text":"x"}]})).collect::<Vec<_>>()});
        assert!(snapshot.validate(&body, &EvaluationContext::default(), true).is_err());
        Ok(())
    }
}
