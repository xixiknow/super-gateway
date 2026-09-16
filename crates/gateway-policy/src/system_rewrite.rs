//! Segment-aware structural rewrites of the `system` value.
//!
//! The policy engine (Group four-mode enforcement) and the dispatcher (captured
//! Archetype template fallback) share these helpers so both stages agree on the
//! same rules:
//!
//! - When the Claude Code static/dynamic boundary is resolved, only the static
//!   segment is replaced. The billing block stays at `system[0]` and the dynamic
//!   segment (`# Environment`, memory, session guidance) keeps its runtime
//!   values, which a captured template can never freeze.
//! - When the boundary is unresolved (non-Claude clients, string `system`,
//!   trimmed request variants) the whole value is replaced.
//! - Cache breakpoints are re-laid on the rewritten value and never exceed the
//!   number the client sent, so the request stays within the upstream budget the
//!   client already satisfied.
#![allow(missing_docs)]

use std::ops::Range;

use serde_json::{Value, json};

use crate::system_segments::{Boundary, Flag, parse};

/// Whether a `replace` payload is empty and therefore defers to the selected
/// Archetype's captured static template.
#[must_use]
pub fn is_empty_replacement(content: &Value) -> bool {
    match content {
        Value::Null => true,
        Value::String(text) => text.trim().is_empty(),
        Value::Array(blocks) => blocks.is_empty(),
        _ => false,
    }
}

/// Which part of the value a replacement touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemRewrite {
    /// Billing and dynamic blocks were kept; only the static segment changed.
    StaticSegment,
    /// No Claude Code boundary was found, so the whole value was replaced.
    Whole,
}

/// Replace the client's static System segment with platform content.
///
/// `replacement` is a string or a block array (captured templates carry the
/// original `cache_control` annotations of each block).
pub fn replace_system_static(system: &mut Value, replacement: &Value) -> SystemRewrite {
    let segments = parse(system);
    let budget = segments.cache_control_points.len();
    if let (Value::Array(blocks), Boundary::Resolved { dynamic_start, .. }) = (&*system, segments.boundary) {
        let start = usize::from(segments.billing.is_some() || segments.flags.contains(&Flag::BillingMalformed));
        let dynamic_start = dynamic_start.min(blocks.len()).max(start);
        let mut replacement_blocks = as_blocks(replacement);
        // Keep the client's "static prefix is cacheable" behaviour when the
        // template itself carries no breakpoint.
        if count_points(&replacement_blocks) == 0
            && let Some(inherited) = last_cache_control(&blocks[start..dynamic_start])
            && let Some(last) = replacement_blocks.last_mut().and_then(Value::as_object_mut)
        {
            last.insert("cache_control".to_owned(), inherited);
        }
        let mut next = Vec::with_capacity(start + replacement_blocks.len() + blocks.len() - dynamic_start);
        next.extend_from_slice(&blocks[..start]);
        let replaced = start..start + replacement_blocks.len();
        next.extend(replacement_blocks);
        next.extend_from_slice(&blocks[dynamic_start..]);
        enforce_breakpoint_budget(&mut next, budget, replaced);
        *system = Value::Array(next);
        return SystemRewrite::StaticSegment;
    }

    let mut next = match (&*system, replacement) {
        (Value::Array(_), Value::String(text)) => json!([{"type":"text","text":text}]),
        _ => replacement.clone(),
    };
    transfer_cache_controls(Some(&*system), &mut next);
    if let Value::Array(blocks) = &mut next {
        let len = blocks.len();
        enforce_breakpoint_budget(blocks, budget, 0..len);
    }
    *system = next;
    SystemRewrite::Whole
}

/// `strip_client`: drop the client's System but keep a Claude Code billing
/// block so attribution can still be aligned downstream. Returns `None` when
/// nothing should remain.
#[must_use]
pub fn strip_client_system(system: &Value) -> Option<Value> {
    let segments = parse(system);
    let has_billing = segments.billing.is_some() || segments.flags.contains(&Flag::BillingMalformed);
    match system {
        Value::Array(blocks) if has_billing && !blocks.is_empty() => {
            let mut billing = blocks[0].clone();
            if let Some(object) = billing.as_object_mut() {
                object.remove("cache_control");
            }
            Some(Value::Array(vec![billing]))
        }
        _ => None,
    }
}

fn as_blocks(replacement: &Value) -> Vec<Value> {
    match replacement {
        Value::String(text) => vec![json!({"type":"text","text":text})],
        Value::Array(blocks) => blocks.clone(),
        _ => Vec::new(),
    }
}

fn has_point(block: &Value) -> bool {
    block
        .as_object()
        .and_then(|object| object.get("cache_control"))
        .is_some_and(|value| !value.is_null())
}

fn count_points(blocks: &[Value]) -> usize {
    blocks.iter().filter(|block| has_point(block)).count()
}

fn last_cache_control(blocks: &[Value]) -> Option<Value> {
    blocks
        .iter()
        .rev()
        .find(|block| has_point(block))
        .and_then(|block| block.get("cache_control").cloned())
}

/// Drop breakpoints until the value carries at most `budget`, preferring to
/// remove those on freshly inserted blocks and keeping the trailing ones,
/// which cache the longest prefix.
fn enforce_breakpoint_budget(blocks: &mut [Value], budget: usize, inserted: Range<usize>) {
    let mut excess = count_points(blocks).saturating_sub(budget);
    if excess == 0 {
        return;
    }
    let candidates = inserted
        .clone()
        .filter(|index| *index < blocks.len())
        .chain((0..blocks.len()).filter(|index| !inserted.contains(index)))
        .collect::<Vec<_>>();
    for index in candidates {
        if excess == 0 {
            break;
        }
        if let Some(object) = blocks[index].as_object_mut()
            && object.get("cache_control").is_some_and(|value| !value.is_null())
        {
            object.remove("cache_control");
            excess -= 1;
        }
    }
}

/// Carry client breakpoints onto the corresponding blocks of a whole
/// replacement so the relative cache layout survives the swap.
pub(crate) fn transfer_cache_controls(current: Option<&Value>, replacement: &mut Value) {
    let (Some(Value::Array(source)), Value::Array(target)) = (current, replacement) else {
        return;
    };
    if target.is_empty() {
        return;
    }
    let source_len = source.len();
    let target_len = target.len();
    let mut used = std::collections::BTreeSet::new();
    for (source_index, cache) in source.iter().enumerate().filter_map(|(index, block)| {
        let object = block.as_object()?;
        let cache = object.get("cache_control")?;
        (!cache.is_null()).then(|| (index, cache.clone()))
    }) {
        let mapped = if source_len == 1 || target_len == 1 {
            0
        } else {
            // Keep the breakpoint at the same relative location in the
            // replacement array instead of packing all controls at the front.
            (source_index * (target_len - 1) + (source_len - 1) / 2) / (source_len - 1)
        };
        let mut candidates = (0..target_len)
            .map(|index| (index.abs_diff(mapped), index))
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        let Some((_, target_index)) = candidates.into_iter().find(|(_, index)| !used.contains(index)) else {
            continue;
        };
        let Some(object) = target[target_index].as_object_mut() else {
            continue;
        };
        if object.get("cache_control").is_some_and(|value| !value.is_null()) {
            continue;
        }
        object.insert("cache_control".to_owned(), cache);
        used.insert(target_index);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "test fixtures must have the asserted shape")]
mod tests {
    use serde_json::json;

    use super::{SystemRewrite, is_empty_replacement, replace_system_static, strip_client_system};

    fn claude_code_system() -> serde_json::Value {
        json!([
            {"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.220.a3f; cc_entrypoint=cli;"},
            {"type":"text","text":"You are Claude Code.\n# Tone and style\n","cache_control":{"type":"ephemeral","ttl":"1h"}},
            {"type":"text","text":"Communicating clearly\n"},
            {"type":"text","text":"# Environment\n - Platform: win32\n","cache_control":{"type":"ephemeral"}}
        ])
    }

    fn points(system: &serde_json::Value) -> Vec<usize> {
        system
            .as_array()
            .map(|blocks| {
                blocks
                    .iter()
                    .enumerate()
                    .filter(|(_, block)| block.get("cache_control").is_some_and(|value| !value.is_null()))
                    .map(|(index, _)| index)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn empty_replacement_detection_covers_string_array_and_null() {
        assert!(is_empty_replacement(&json!(null)));
        assert!(is_empty_replacement(&json!("   ")));
        assert!(is_empty_replacement(&json!([])));
        assert!(!is_empty_replacement(&json!("platform")));
        assert!(!is_empty_replacement(&json!([{"type":"text","text":"x"}])));
    }

    #[test]
    fn replace_swaps_only_the_static_segment_and_inherits_its_breakpoint() {
        let mut system = claude_code_system();
        let rewrite = replace_system_static(&mut system, &json!("platform static"));
        assert_eq!(rewrite, SystemRewrite::StaticSegment);
        let blocks = system.as_array().expect("array");
        assert_eq!(blocks.len(), 4);
        assert!(
            blocks[0]["text"]
                .as_str()
                .is_some_and(|text| text.starts_with("x-anthropic-billing-header:"))
        );
        assert_eq!(blocks[1]["text"], "platform static");
        assert_eq!(blocks[1]["cache_control"]["ttl"], "1h");
        assert_eq!(blocks[2]["text"], "Communicating clearly\n");
        assert!(
            blocks[3]["text"]
                .as_str()
                .is_some_and(|text| text.contains("Platform: win32"))
        );
        assert_eq!(points(&system), vec![1, 3]);
    }

    #[test]
    fn replace_keeps_template_breakpoints_within_the_client_budget() {
        let mut system = claude_code_system();
        let template = json!([
            {"type":"text","text":"a","cache_control":{"type":"ephemeral"}},
            {"type":"text","text":"b","cache_control":{"type":"ephemeral"}},
            {"type":"text","text":"c","cache_control":{"type":"ephemeral"}}
        ]);
        replace_system_static(&mut system, &template);
        // Client sent two breakpoints; the dynamic one is kept, the template
        // keeps its trailing one only.
        assert_eq!(points(&system), vec![3, 5]);
        assert_eq!(system[3]["text"], "c");
    }

    #[test]
    fn unresolved_boundary_replaces_the_whole_value() {
        let mut system = json!([{"type":"text","text":"custom","cache_control":{"type":"ephemeral"}}]);
        let rewrite = replace_system_static(&mut system, &json!("platform"));
        assert_eq!(rewrite, SystemRewrite::Whole);
        assert_eq!(
            system,
            json!([{"type":"text","text":"platform","cache_control":{"type":"ephemeral"}}])
        );

        let mut text = json!("client");
        assert_eq!(
            replace_system_static(&mut text, &json!("platform")),
            SystemRewrite::Whole
        );
        assert_eq!(text, json!("platform"));

        let mut absent = serde_json::Value::Null;
        replace_system_static(&mut absent, &json!("platform"));
        assert_eq!(absent, json!("platform"));
    }

    #[test]
    fn strip_client_keeps_only_the_billing_block() {
        let stripped = strip_client_system(&claude_code_system()).expect("billing kept");
        assert_eq!(stripped.as_array().map(Vec::len), Some(1));
        assert!(
            stripped[0]["text"]
                .as_str()
                .is_some_and(|text| text.starts_with("x-anthropic-billing-header:"))
        );
        assert!(stripped[0].get("cache_control").is_none());
        assert!(strip_client_system(&json!("client")).is_none());
        assert!(strip_client_system(&json!([{"type":"text","text":"custom"}])).is_none());
    }
}
