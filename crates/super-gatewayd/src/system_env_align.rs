//! Precise southbound alignment of Claude Code's environment system block.

use gateway_policy::{EnvironmentField, OsFamily, parse_system_segments};
use serde_json::Value;
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub(crate) struct EnvironmentTarget<'a> {
    pub(crate) os_family: OsFamily,
    pub(crate) shell: Option<&'a str>,
    pub(crate) os_version: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum EnvironmentAlignError {
    #[error("environment replacement contains a line break")]
    InvalidReplacement,
    #[error("environment field range is invalid")]
    InvalidRange,
}

pub(crate) fn align_system_environment(
    system: &mut Value,
    target: EnvironmentTarget<'_>,
) -> Result<bool, EnvironmentAlignError> {
    if [target.shell, target.os_version]
        .into_iter()
        .flatten()
        .any(|value| value.contains(['\r', '\n']))
    {
        return Err(EnvironmentAlignError::InvalidReplacement);
    }
    let segments = parse_system_segments(system);
    let Some(environment) = segments.environment else {
        return Ok(false);
    };
    let text = match system {
        Value::String(text) if environment.index == 0 => text,
        Value::Array(blocks) => {
            let Some(block) = blocks.get_mut(environment.index) else {
                return Err(EnvironmentAlignError::InvalidRange);
            };
            block_text_mut(block).ok_or(EnvironmentAlignError::InvalidRange)?
        }
        _ => return Err(EnvironmentAlignError::InvalidRange),
    };

    let platform = match target.os_family {
        OsFamily::Windows => "win32",
        OsFamily::Macos => "darwin",
        OsFamily::Linux => "linux",
    };
    let mut edits = Vec::with_capacity(3);
    push_edit(&mut edits, environment.platform.as_ref(), Some(platform));
    push_edit(&mut edits, environment.shell.as_ref(), target.shell);
    push_edit(&mut edits, environment.os_version.as_ref(), target.os_version);
    edits.sort_unstable_by_key(|edit| std::cmp::Reverse(edit.0.start));

    let mut changed = false;
    for (range, replacement) in edits {
        let Some(current) = text.get(range.clone()) else {
            return Err(EnvironmentAlignError::InvalidRange);
        };
        if current != replacement {
            text.replace_range(range, replacement);
            changed = true;
        }
    }
    Ok(changed)
}

fn block_text_mut(block: &mut Value) -> Option<&mut String> {
    match block {
        Value::String(text) => Some(text),
        Value::Object(object) => object.get_mut("text").and_then(|value| match value {
            Value::String(text) => Some(text),
            _ => None,
        }),
        _ => None,
    }
}

fn push_edit<'a>(
    edits: &mut Vec<(std::ops::Range<usize>, &'a str)>,
    field: Option<&EnvironmentField>,
    replacement: Option<&'a str>,
) {
    if let (Some(field), Some(replacement)) = (field, replacement) {
        edits.push((field.byte_range.clone(), replacement));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "environment fixtures must contain text blocks")]
mod tests {
    use gateway_policy::OsFamily;
    use serde_json::json;

    use super::{EnvironmentAlignError, EnvironmentTarget, align_system_environment};

    #[test]
    fn aligns_only_environment_os_fields_and_preserves_cache_metadata() {
        let mut system = json!([{
            "type":"text",
            "text":"# Environment\r\n - Primary working directory: C:\\工作区\r\n - Is a git repository: Yes\r\n - Platform: win32\r\n - Shell: PowerShell\r\n - OS Version: Windows 11\r\n",
            "cache_control":{"type":"ephemeral","ttl":"1h"}
        }]);
        let cache = system[0]["cache_control"].clone();

        assert_eq!(
            align_system_environment(
                &mut system,
                EnvironmentTarget {
                    os_family: OsFamily::Macos,
                    shell: Some("zsh"),
                    os_version: Some("Darwin 25.0"),
                },
            ),
            Ok(true)
        );
        let text = system[0]["text"].as_str().expect("text");
        assert!(text.contains("Primary working directory: C:\\工作区"));
        assert!(text.contains("Is a git repository: Yes"));
        assert!(text.contains("Platform: darwin"));
        assert!(text.contains("Shell: zsh"));
        assert!(text.contains("OS Version: Darwin 25.0"));
        assert_eq!(system[0]["cache_control"], cache);
    }

    #[test]
    fn supports_string_system_and_missing_environment() {
        let target = EnvironmentTarget {
            os_family: OsFamily::Linux,
            shell: Some("bash"),
            os_version: Some("Linux 6.12"),
        };
        let mut system = json!("# Environment\nPlatform: win32\nShell: PowerShell\nOS Version: Windows 11");
        assert_eq!(align_system_environment(&mut system, target), Ok(true));
        assert!(system.as_str().is_some_and(|text| text.contains("Platform: linux")));

        let mut short = json!([{"type":"text","text":"short system"}]);
        assert_eq!(align_system_environment(&mut short, target), Ok(false));
    }

    #[test]
    fn rejects_multiline_replacements() {
        let mut system = json!("# Environment\nPlatform: linux\nShell: bash\nOS Version: Linux");
        assert_eq!(
            align_system_environment(
                &mut system,
                EnvironmentTarget {
                    os_family: OsFamily::Linux,
                    shell: Some("bash\nInjected: value"),
                    os_version: Some("Linux"),
                },
            ),
            Err(EnvironmentAlignError::InvalidReplacement)
        );
    }

    #[test]
    fn aligns_available_fields_for_legacy_archetypes() {
        let mut system = json!("# Environment\nPlatform: win32\nShell: PowerShell\nOS Version: Windows 11");
        assert_eq!(
            align_system_environment(
                &mut system,
                EnvironmentTarget {
                    os_family: OsFamily::Macos,
                    shell: None,
                    os_version: None,
                },
            ),
            Ok(true)
        );
        assert_eq!(
            system,
            json!("# Environment\nPlatform: darwin\nShell: PowerShell\nOS Version: Windows 11")
        );
    }
}
