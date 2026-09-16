//! Claude Code billing/attribution block helpers.
#![allow(missing_docs, clippy::doc_markdown)]

use gateway_domain::Digest;
use serde_json::{Value, json};
use thiserror::Error;

const FP3_SALT: &str = "59cf53e54c78";

/// Whether the client version emits the optional `cch` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CchPolicy {
    Omit,
    Zero00,
}

/// Select the known attribution variant for a Claude Code client version.
#[must_use]
pub fn cch_policy_for_version(client_version: &str) -> CchPolicy {
    if client_version == "2.1.220" {
        CchPolicy::Zero00
    } else {
        CchPolicy::Omit
    }
}

/// Result of ensuring a billing block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BillingAction {
    Preserved,
    Rewritten,
    Inserted,
}

/// Stable errors returned by billing block manipulation.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BillingError {
    #[error("system must be an array or string")]
    InvalidSystem,
    #[error("target client version is empty")]
    EmptyVersion,
}

/// Calculate the three hexadecimal fingerprint characters used by `cc_version`.
///
/// Character offsets are Unicode scalar offsets, matching the CLI implementation;
/// missing characters are represented by `0`.
#[must_use]
pub fn fp3(first_user_text: &str, client_version: &str) -> Box<str> {
    let chars = first_user_text.chars().collect::<Vec<_>>();
    let suffix = [
        chars.get(4).copied().unwrap_or('0'),
        chars.get(7).copied().unwrap_or('0'),
        chars.get(20).copied().unwrap_or('0'),
    ];
    let mut input = String::from(FP3_SALT);
    for character in suffix {
        input.push(character);
    }
    input.push_str(client_version);
    Digest::of(input.as_bytes()).as_str()[..3].into()
}

/// Render the canonical attribution block text.
///
/// # Errors
/// Returns `EmptyVersion` if the client version is blank.
pub fn render_billing_block(
    client_version: &str,
    fingerprint: &str,
    cch_policy: CchPolicy,
) -> Result<Box<str>, BillingError> {
    if client_version.trim().is_empty() {
        return Err(BillingError::EmptyVersion);
    }
    let mut rendered =
        format!("x-anthropic-billing-header: cc_version={client_version}.{fingerprint}; cc_entrypoint=cli;");
    if matches!(cch_policy, CchPolicy::Zero00) {
        rendered.push_str(" cch=00000;");
    }
    Ok(rendered.into_boxed_str())
}

/// Find the first text block in the first user message.
#[must_use]
pub fn first_user_text(body: &Value) -> Option<&str> {
    body.get("messages")?
        .as_array()?
        .iter()
        .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))
        .and_then(|message| message.get("content"))
        .and_then(|content| {
            content.as_array().and_then(|blocks| {
                blocks.iter().find_map(|block| {
                    (block.get("type").and_then(Value::as_str) == Some("text"))
                        .then(|| block.get("text").and_then(Value::as_str))
                        .flatten()
                })
            })
        })
}

/// Ensure that `system[0]` contains a billing block for the selected version.
/// Existing blocks for the selected version are preserved byte-for-byte.
///
/// # Errors
/// Returns an error if the target version is blank or the system value has an unsupported type.
pub fn ensure_billing_block(
    system: &mut Value,
    target_version: &str,
    first_user_text: &str,
    cch_policy: CchPolicy,
) -> Result<BillingAction, BillingError> {
    if target_version.trim().is_empty() {
        return Err(BillingError::EmptyVersion);
    }
    let fingerprint = fp3(first_user_text, target_version);
    let rendered = render_billing_block(target_version, &fingerprint, cch_policy)?;
    if matches!(system, Value::String(_) | Value::Null) {
        let previous = std::mem::replace(system, Value::Null);
        match previous {
            Value::Null => {
                *system = json!([{"type":"text", "text": rendered.as_ref()}]);
                return Ok(BillingAction::Inserted);
            }
            Value::String(text) => {
                if looks_like_billing_header(&text) {
                    if billing_version(&text) == Some(target_version) {
                        *system = Value::String(text);
                        return Ok(BillingAction::Preserved);
                    }
                    let replacement = if billing_version(&text).is_some() {
                        rewrite_version_and_fp3(&text, target_version, &fingerprint)
                    } else {
                        rendered.to_string()
                    };
                    *system = Value::String(replacement);
                    return Ok(BillingAction::Rewritten);
                }
                *system = json!([
                    {"type":"text", "text": rendered.as_ref()},
                    {"type":"text", "text": text}
                ]);
                return Ok(BillingAction::Inserted);
            }
            _ => return Err(BillingError::InvalidSystem),
        }
    }
    let Value::Array(values) = system else {
        return Err(BillingError::InvalidSystem);
    };

    if let Some(first) = values.first_mut()
        && let Some(text) = first.get("text").and_then(Value::as_str)
        && looks_like_billing_header(text)
    {
        if billing_version(text) == Some(target_version) {
            // Billing is a text attribution block, never a cache
            // breakpoint. Remove a malformed client-side marker while
            // preserving every other field on the block.
            if let Some(object) = first.as_object_mut()
                && object.get("cache_control").is_some_and(|value| !value.is_null())
            {
                object.remove("cache_control");
                return Ok(BillingAction::Rewritten);
            }
            return Ok(BillingAction::Preserved);
        }
        let replacement = if billing_version(text).is_some() {
            rewrite_version_and_fp3(text, target_version, &fingerprint)
        } else {
            rendered.to_string()
        };
        if let Some(slot) = first.get_mut("text") {
            *slot = Value::String(replacement);
            if let Some(object) = first.as_object_mut() {
                object.remove("cache_control");
            }
            return Ok(BillingAction::Rewritten);
        }
    }

    values.insert(0, json!({"type":"text", "text": rendered.as_ref()}));
    Ok(BillingAction::Inserted)
}

fn looks_like_billing_header(text: &str) -> bool {
    text.trim_start().starts_with("x-anthropic-billing-header:")
}

fn billing_version(text: &str) -> Option<&str> {
    let payload = text.trim_start().strip_prefix("x-anthropic-billing-header:")?;
    let value = payload
        .split(';')
        .find_map(|part| part.trim().strip_prefix("cc_version="))?;
    value.rsplit_once('.').map(|(version, _)| version)
}

fn rewrite_version_and_fp3(text: &str, target_version: &str, fingerprint: &str) -> String {
    let Some(prefix_start) = text.find("cc_version=") else {
        return text.to_owned();
    };
    let value_start = prefix_start + "cc_version=".len();
    let value_end = text[value_start..]
        .find(';')
        .map_or(text.len(), |offset| value_start + offset);
    let mut result = String::with_capacity(text.len() + target_version.len());
    result.push_str(&text[..value_start]);
    result.push_str(target_version);
    result.push('.');
    result.push_str(fingerprint);
    result.push_str(&text[value_end..]);
    result
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "test fixtures must have the asserted shape")]
mod tests {
    use serde_json::json;

    use super::{BillingAction, CchPolicy, ensure_billing_block, first_user_text, fp3, render_billing_block};

    #[test]
    fn fp3_is_three_lower_hex_characters_and_is_deterministic() {
        let first = fp3("<system-reminder>hello</system-reminder>", "2.1.220");
        assert_eq!(first.len(), 3);
        assert!(
            first
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        );
        assert_eq!(first, fp3("<system-reminder>hello</system-reminder>", "2.1.220"));
    }

    #[test]
    fn first_text_in_first_user_message_includes_reminder() {
        let body = json!({"messages":[{"role":"user","content":[{"type":"text","text":"reminder"}]}]});
        assert_eq!(first_user_text(&body), Some("reminder"));
    }

    #[test]
    fn ensure_preserves_matching_block_and_rewrites_mismatched_version() {
        let mut system = json!([{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.220.abc; cc_entrypoint=cli; extra=1;"}]);
        assert_eq!(
            ensure_billing_block(&mut system, "2.1.220", "hello", CchPolicy::Omit),
            Ok(BillingAction::Preserved)
        );
        let original = system.clone();
        assert_eq!(
            ensure_billing_block(&mut system, "2.1.241", "hello", CchPolicy::Omit),
            Ok(BillingAction::Rewritten)
        );
        assert_ne!(system, original);
        assert!(
            system[0]["text"]
                .as_str()
                .is_some_and(|text| text.contains("cc_version=2.1.241."))
        );
    }

    #[test]
    fn ensure_inserts_missing_block_and_can_emit_cch() {
        let mut system = json!([{"type":"text","text":"identity"}]);
        assert_eq!(
            ensure_billing_block(&mut system, "2.1.220", "hello", CchPolicy::Zero00),
            Ok(BillingAction::Inserted)
        );
        assert!(
            system[0]["text"]
                .as_str()
                .is_some_and(|text| text.contains("cch=00000;"))
        );
    }

    #[test]
    fn renders_without_cch_by_default() {
        let value = render_billing_block("2.1.220", "abc", CchPolicy::Omit).expect("render");
        assert_eq!(
            value.as_ref(),
            "x-anthropic-billing-header: cc_version=2.1.220.abc; cc_entrypoint=cli;"
        );
    }

    #[test]
    fn string_system_with_billing_header_is_rewritten_in_place() {
        let mut system = json!("x-anthropic-billing-header: cc_version=2.1.220.abc; cc_entrypoint=cli;");
        assert_eq!(
            ensure_billing_block(&mut system, "2.1.241", "hello", CchPolicy::Omit),
            Ok(BillingAction::Rewritten)
        );
        assert!(system.is_string());
        assert!(
            system
                .as_str()
                .is_some_and(|text| text.contains("cc_version=2.1.241.") && !text.contains("2.1.220."))
        );
    }

    #[test]
    fn malformed_billing_prefix_is_replaced_instead_of_inserting_a_second_block() {
        let mut system = json!([{"type":"text","text":"x-anthropic-billing-header: garbage"}]);
        assert_eq!(
            ensure_billing_block(&mut system, "2.1.241", "hello", CchPolicy::Omit),
            Ok(BillingAction::Rewritten)
        );
        assert_eq!(system.as_array().map(Vec::len), Some(1));
        assert!(
            system[0]["text"]
                .as_str()
                .is_some_and(|text| text.starts_with("x-anthropic-billing-header: cc_version=2.1.241."))
        );
    }
}
