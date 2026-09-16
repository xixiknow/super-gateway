//! Heuristic segmentation of Claude Code `system` content.
//!
//! Claude Code does not send an explicit boundary marker in the API request,
//! so this module deliberately reports an unresolved boundary instead of
//! guessing when the stable headings are absent.
#![allow(missing_docs)]

use std::{collections::BTreeMap, ops::Range};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Operating systems represented by Claude Code's client and environment data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Windows,
    Macos,
    Linux,
}

/// A diagnostic produced while parsing a request variant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flag {
    BoundaryUnresolved,
    UnknownVersion,
    SystemAsString,
    BillingMalformed,
}

/// Parsed Claude Code attribution information.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Billing {
    /// Complete `cc_version` value, including the three-character suffix.
    pub cc_version: Box<str>,
    /// Semantic Claude Code version extracted from `cc_version`.
    pub client_version: Box<str>,
    /// Three-character content suffix, when present.
    pub fp3: Box<str>,
    /// Billing entrypoint, normally `cli`.
    pub cc_entrypoint: Box<str>,
    /// Optional cache-hash field emitted by some client versions.
    pub cch: Option<Box<str>>,
}

/// A system section identified after the static prompt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicSection {
    pub index: usize,
    pub kind: Box<str>,
}

/// The result of the static/dynamic boundary heuristic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Boundary {
    Resolved { static_end: usize, dynamic_start: usize },
    Unresolved,
}

/// A field extracted from the environment block, with a byte range into its
/// containing text block. The range excludes the field label and line ending.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentField {
    pub value: Box<str>,
    pub byte_range: Range<usize>,
}

/// Values exposed by the `# Environment` section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentBlock {
    pub index: usize,
    pub primary_working_directory: Option<EnvironmentField>,
    pub is_git_repository: Option<EnvironmentField>,
    pub platform: Option<EnvironmentField>,
    pub shell: Option<EnvironmentField>,
    pub os_version: Option<EnvironmentField>,
    pub model: Option<EnvironmentField>,
    pub platform_normalized: Option<OsFamily>,
}

/// Structured, lossless-enough view of the system array.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemSegments {
    pub billing: Option<Billing>,
    pub static_blocks: Vec<usize>,
    pub boundary: Boundary,
    pub dynamic: Vec<DynamicSection>,
    pub environment: Option<EnvironmentBlock>,
    pub cache_control_points: Vec<usize>,
    pub flags: Vec<Flag>,
}

/// Parse a Claude Code system value. Missing, non-text, or otherwise unusual
/// blocks are retained in the index space but simply do not match heuristics.
#[must_use]
pub fn parse(system: &Value) -> SystemSegments {
    let mut flags = Vec::new();
    let blocks = match system {
        Value::String(text) => {
            flags.push(Flag::SystemAsString);
            vec![Block {
                text: Some(text.as_str()),
                cache_control: false,
            }]
        }
        Value::Array(values) => values.iter().map(block).collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    let texts = blocks.iter().map(|item| item.text).collect::<Vec<_>>();
    let billing = texts.first().and_then(|text| (*text).and_then(parse_billing));
    if texts
        .first()
        .and_then(|text| *text)
        .is_some_and(|text| text.trim_start().starts_with("x-anthropic-billing-header:") && billing.is_none())
    {
        flags.push(Flag::BillingMalformed);
    }
    if let Some(item) = billing.as_ref()
        && !is_known_version(&item.client_version)
    {
        flags.push(Flag::UnknownVersion);
    }

    let cache_control_points = blocks
        .iter()
        .enumerate()
        .filter_map(|(index, item)| item.cache_control.then_some(index))
        .collect::<Vec<_>>();
    let static_end = texts
        .iter()
        .enumerate()
        .filter_map(|(index, text)| text.filter(|value| value.contains("# Tone and style")).map(|_| index))
        .next_back();
    let dynamic_start_candidate = static_end.and_then(|end| {
        texts.iter().enumerate().skip(end + 1).find_map(|(index, text)| {
            let text = (*text)?.trim_start();
            is_dynamic_heading(text).then_some(index)
        })
    });
    let boundary = if let (Some(static_end), Some(dynamic_start_candidate)) = (static_end, dynamic_start_candidate) {
        let mut dynamic_start = dynamic_start_candidate;
        let points = cache_control_points
            .iter()
            .copied()
            .filter(|point| *point > static_end && *point < dynamic_start)
            .collect::<Vec<_>>();
        if points.len() == 1 {
            dynamic_start = (points[0] + 1).min(blocks.len());
        }
        Boundary::Resolved {
            static_end,
            dynamic_start,
        }
    } else {
        flags.push(Flag::BoundaryUnresolved);
        Boundary::Unresolved
    };

    let static_blocks = match boundary {
        Boundary::Resolved { static_end, .. } => {
            let start = usize::from(billing.is_some());
            (start..=static_end).collect()
        }
        Boundary::Unresolved => Vec::new(),
    };
    let dynamic = match boundary {
        Boundary::Resolved { dynamic_start, .. } => texts
            .iter()
            .enumerate()
            .skip(dynamic_start)
            .filter_map(|(index, text)| {
                let text = (*text)?.trim_start();
                is_dynamic_heading(text).then(|| DynamicSection {
                    index,
                    kind: dynamic_kind(text),
                })
            })
            .collect(),
        Boundary::Unresolved => Vec::new(),
    };
    let environment = texts.iter().enumerate().find_map(|(index, text)| {
        text.filter(|value| has_environment_heading(value))
            .map(|value| parse_environment(index, value))
    });

    SystemSegments {
        billing,
        static_blocks,
        boundary,
        dynamic,
        environment,
        cache_control_points,
        flags,
    }
}

struct Block<'a> {
    text: Option<&'a str>,
    cache_control: bool,
}

fn block(value: &Value) -> Block<'_> {
    let Some(object) = value.as_object() else {
        return Block {
            text: value.as_str(),
            cache_control: false,
        };
    };
    Block {
        text: object.get("text").and_then(Value::as_str),
        cache_control: object.get("cache_control").is_some_and(|value| !value.is_null()),
    }
}

fn parse_billing(text: &str) -> Option<Billing> {
    let text = text.trim_start();
    let payload = text.strip_prefix("x-anthropic-billing-header:")?;
    let mut values = BTreeMap::new();
    for field in payload.split(';') {
        let field = field.trim();
        if field.is_empty() {
            continue;
        }
        let (key, value) = field.split_once('=')?;
        values.insert(key, value);
    }
    let cc_version = values.get("cc_version")?.to_owned();
    let (client_version, fp3) = cc_version.rsplit_once('.')?;
    if !is_version(client_version) || !is_fp3(fp3) {
        return None;
    }
    Some(Billing {
        cc_version: cc_version.to_owned().into_boxed_str(),
        client_version: client_version.into(),
        fp3: fp3.into(),
        cc_entrypoint: values.get("cc_entrypoint")?.to_string().into_boxed_str(),
        cch: values.get("cch").map(|value| (*value).to_owned().into_boxed_str()),
    })
}

fn is_version(version: &str) -> bool {
    let mut components = version.split('.');
    components.clone().count() == 3
        && components.all(|component| !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_fp3(fp3: &str) -> bool {
    fp3.len() == 3
        && fp3
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_known_version(version: &str) -> bool {
    matches!(version, "2.1.220" | "2.1.241")
}

fn is_dynamic_heading(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.starts_with("communicating")
        || lower.starts_with("pronouns")
        || lower.starts_with("session_guidance")
        || lower.starts_with("# environment")
        || lower.starts_with("session guidance")
}

fn dynamic_kind(text: &str) -> Box<str> {
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("# environment") {
        "environment".into()
    } else if lower.starts_with("pronouns") {
        "pronouns".into()
    } else if lower.starts_with("session_guidance") || lower.starts_with("session guidance") {
        "session_guidance".into()
    } else {
        "communicating".into()
    }
}

fn parse_environment(index: usize, text: &str) -> EnvironmentBlock {
    let primary_working_directory = field(text, "Primary working directory:");
    let is_git_repository = field(text, "Is a git repository:");
    let platform = field(text, "Platform:");
    let shell = field(text, "Shell:");
    let os_version = field(text, "OS Version:");
    let model = field(text, "The exact model ID is").map(|mut value| {
        let trimmed = value.value.trim_end_matches('.').to_owned();
        let start = value.byte_range.start;
        value.value = trimmed.into_boxed_str();
        value.byte_range = start..start + value.value.len();
        value
    });
    let platform_normalized = platform.as_ref().and_then(|field| normalize_os(&field.value));
    EnvironmentBlock {
        index,
        primary_working_directory,
        is_git_repository,
        platform,
        shell,
        os_version,
        model,
        platform_normalized,
    }
}

fn has_environment_heading(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim().eq_ignore_ascii_case("# environment"))
}

fn field(text: &str, label: &str) -> Option<EnvironmentField> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let indent = line.len() - line.trim_start().len();
        let rest = &line[indent..];
        let (content, bullet) = rest
            .strip_prefix("- ")
            .map(|content| (content, 2usize))
            .or_else(|| rest.strip_prefix("* ").map(|content| (content, 2usize)))
            .unwrap_or((rest, 0));
        if let Some(after) = content.strip_prefix(label) {
            let without_eol = after.trim_end_matches(['\r', '\n']);
            let leading = without_eol.len() - without_eol.trim_start().len();
            let value = without_eol.trim();
            let value_start = offset + indent + bullet + label.len() + leading;
            let value_end = value_start + value.len();
            if value_start <= value_end && value_end <= text.len() {
                return Some(EnvironmentField {
                    value: value.into(),
                    byte_range: value_start..value_end,
                });
            }
        }
        offset += line.len();
    }
    None
}

fn normalize_os(value: &str) -> Option<OsFamily> {
    match value.trim().to_ascii_lowercase().as_str() {
        "win32" | "windows" => Some(OsFamily::Windows),
        "darwin" | "macos" | "mac os" => Some(OsFamily::Macos),
        "linux" => Some(OsFamily::Linux),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Boundary, Flag, OsFamily, parse};

    #[test]
    fn parses_billing_and_environment() {
        let value = json!([
            {"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.220.a3f; cc_entrypoint=cli; cch=00000;"},
            {"type":"text","text":"You are Claude.\n# Tone and style\n"},
            {"type":"text","text":"Communicating clearly\n"},
            {"type":"text","text":"# Environment\n - Primary working directory: C:\\repo\n - Is a git repository: Yes\n - Platform: win32\n - Shell: PowerShell\n - OS Version: Windows 11\n - The exact model ID is claude-sonnet-4-5.\n"}
        ]);
        let parsed = parse(&value);
        assert_eq!(
            parsed.billing.as_ref().map(|value| value.client_version.as_ref()),
            Some("2.1.220")
        );
        assert_eq!(
            parsed.billing.as_ref().and_then(|value| value.cch.as_deref()),
            Some("00000")
        );
        assert_eq!(
            parsed.boundary,
            Boundary::Resolved {
                static_end: 1,
                dynamic_start: 2
            }
        );
        assert_eq!(parsed.static_blocks, vec![1]);
        assert_eq!(
            parsed.environment.as_ref().and_then(|value| value.platform_normalized),
            Some(OsFamily::Windows)
        );
        assert_eq!(
            parsed
                .environment
                .as_ref()
                .and_then(|value| value.shell.as_ref())
                .map(|value| value.value.as_ref()),
            Some("PowerShell")
        );
    }

    #[test]
    fn environment_fields_are_matched_on_their_own_line() {
        let value = json!([
            {"type":"text","text":"# Environment\nDo not confuse Platform: linux in prose\n - Platform: win32\n - Shell: PowerShell\n"}
        ]);
        let parsed = parse(&value);
        assert_eq!(
            parsed
                .environment
                .as_ref()
                .and_then(|block| block.platform.as_ref())
                .map(|field| field.value.as_ref()),
            Some("win32")
        );
        assert_eq!(
            parsed.environment.as_ref().and_then(|block| block.platform_normalized),
            Some(OsFamily::Windows)
        );
    }

    #[test]
    fn string_system_is_safe_and_unresolved() {
        let parsed = parse(&json!("short system"));
        assert_eq!(parsed.boundary, Boundary::Unresolved);
        assert!(parsed.flags.contains(&Flag::SystemAsString));
        assert!(parsed.flags.contains(&Flag::BoundaryUnresolved));
    }

    #[test]
    fn unknown_version_is_flagged_without_failing() {
        let parsed = parse(
            &json!([{"type":"text","text":"x-anthropic-billing-header: cc_version=9.9.9.abc; cc_entrypoint=cli;"}]),
        );
        assert!(parsed.billing.is_some());
        assert!(parsed.flags.contains(&Flag::UnknownVersion));
    }
}
