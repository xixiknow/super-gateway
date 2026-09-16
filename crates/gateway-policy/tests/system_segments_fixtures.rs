#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    reason = "fixture assertions report malformed samples and mode failures"
)]

use std::sync::Arc;

use gateway_domain::{ClientClass, ClientOs, RequestSnapshotSet, SnapshotVersion};
use gateway_policy::{
    Boundary, Enforcement, OsFamily, PolicyContext, RequestPolicy, SystemPolicy, parse_system_segments,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Fixture {
    source: String,
    headers: Value,
    body: Value,
}

const FIXTURES: &[&str] = &[
    include_str!("fixtures/claude-code/main-conversation.json"),
    include_str!("fixtures/claude-code/count-tokens.json"),
    include_str!("fixtures/claude-code/side-query.json"),
    include_str!("fixtures/claude-code/compaction.json"),
    include_str!("fixtures/claude-code/subagent.json"),
    include_str!("fixtures/claude-code/no-environment.json"),
    include_str!("fixtures/claude-code/no-billing.json"),
    include_str!("fixtures/claude-code/system-as-string.json"),
];

#[test]
fn all_claude_code_variants_parse_and_segment_without_panics() {
    for raw in FIXTURES {
        let fixture: Fixture = serde_json::from_str(raw).expect("fixture JSON");
        assert!(!fixture.source.is_empty());
        assert!(fixture.headers.is_object());
        let system = fixture.body.get("system").cloned().unwrap_or(Value::Null);
        let parsed = parse_system_segments(&system);
        if fixture.body.get("system").is_some_and(Value::is_string) {
            assert!(
                parsed
                    .flags
                    .iter()
                    .any(|flag| matches!(flag, gateway_policy::Flag::SystemAsString))
            );
            assert_eq!(parsed.boundary, Boundary::Unresolved);
        }
    }
}

#[test]
fn main_fixture_exposes_expected_environment_and_boundary() {
    let fixture: Fixture = serde_json::from_str(FIXTURES[0]).expect("fixture JSON");
    let parsed = parse_system_segments(fixture.body.get("system").expect("system"));
    assert!(matches!(parsed.boundary, Boundary::Resolved { .. }));
    assert_eq!(
        parsed
            .environment
            .as_ref()
            .and_then(|environment| environment.platform_normalized),
        Some(OsFamily::Windows)
    );
    assert_eq!(
        parsed.billing.as_ref().map(|billing| billing.client_version.as_ref()),
        Some("2.1.220")
    );
}

#[test]
fn count_tokens_fixture_has_no_max_tokens_requirement() {
    let fixture: Fixture = serde_json::from_str(FIXTURES[1]).expect("fixture JSON");
    assert!(fixture.body.get("max_tokens").is_none());
    assert!(fixture.body.get("messages").is_some_and(Value::is_array));
}

#[test]
fn fixture_bytes_are_owned_for_policy_callers() {
    let fixture: Fixture = serde_json::from_str(FIXTURES[0]).expect("fixture JSON");
    let bytes: Arc<[u8]> = Arc::from(serde_json::to_vec(&fixture.body).expect("serialize fixture"));
    assert!(!bytes.is_empty());
}

fn count_breakpoints(value: Option<&Value>) -> usize {
    value.and_then(Value::as_array).map_or(0, |blocks| {
        blocks
            .iter()
            .filter(|block| block.get("cache_control").is_some_and(|value| !value.is_null()))
            .count()
    })
}

fn policy_for(model: &str, system: SystemPolicy) -> RequestPolicy {
    let version = || SnapshotVersion::new("fixture");
    let snapshots = Arc::new(RequestSnapshotSet {
        access_policy: version(),
        group_config: version(),
        enforcement: version(),
        ruleset: None,
        capability: version(),
        client_profile_catalog: version(),
        price: version(),
        serializer: version(),
    });
    let mut policy = RequestPolicy::base_for_models([model], snapshots).expect("base policy");
    policy.enforcement = Enforcement { system };
    policy
}

/// Four modes × every captured request variant: no variant may be rejected,
/// breakpoints never grow, and `system` keeps preceding `messages` whenever the
/// body is re-serialized.
#[test]
fn all_variants_pass_every_system_mode_within_the_breakpoint_budget() {
    let context = PolicyContext {
        client_class: ClientClass::ClaudeCodeCli,
        client_os: ClientOs::Windows,
        protocol_headers: std::collections::BTreeMap::default(),
        affinity_credential: None,
    };
    let modes = [
        SystemPolicy::Preserve,
        SystemPolicy::StripClient,
        SystemPolicy::Replace {
            platform_system_ref: Box::from("platform-static-v1"),
            content: json!([
                {"type":"text","text":"platform identity"},
                {"type":"text","text":"platform tools"}
            ]),
        },
        SystemPolicy::Replace {
            platform_system_ref: Box::from("archetype-template"),
            content: json!(""),
        },
        SystemPolicy::StripAll,
    ];
    for raw in FIXTURES {
        let fixture: Fixture = serde_json::from_str(raw).expect("fixture JSON");
        let model = fixture.body["model"].as_str().expect("model");
        let bytes: Arc<[u8]> = Arc::from(serde_json::to_vec(&fixture.body).expect("serialize fixture"));
        let original_points = count_breakpoints(fixture.body.get("system"));
        let count_tokens = fixture.body.get("max_tokens").is_none();
        for mode in &modes {
            let policy = policy_for(model, mode.clone());
            let generic = if count_tokens {
                policy.process_count_tokens(bytes.clone(), &context)
            } else {
                policy.process(bytes.clone(), &context)
            }
            .unwrap_or_else(|error| panic!("{}: mode {mode:?} rejected: {error:?}", fixture.source));
            let tree = generic.replay_body.tree();
            assert!(
                count_breakpoints(tree.get("system")) <= original_points,
                "{}: mode {mode:?} grew breakpoints",
                fixture.source
            );
            let keys = tree
                .as_object()
                .map(|object| object.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            if let (Some(system_at), Some(messages_at)) = (
                keys.iter().position(|key| key == "system"),
                keys.iter().position(|key| key == "messages"),
            ) {
                assert!(system_at < messages_at, "{}: {mode:?} keys {keys:?}", fixture.source);
            }
            match mode {
                SystemPolicy::Preserve => assert!(generic.replay_body.reused_original()),
                SystemPolicy::StripAll => {
                    assert!(tree.get("system").is_none());
                    assert!(generic.attribution_suppressed);
                }
                SystemPolicy::StripClient => {
                    let segments = parse_system_segments(fixture.body.get("system").unwrap_or(&Value::Null));
                    let has_billing =
                        segments.billing.is_some() || segments.flags.contains(&gateway_policy::Flag::BillingMalformed);
                    assert_eq!(
                        tree.get("system").and_then(Value::as_array).map(Vec::len),
                        has_billing.then_some(1),
                        "{}: strip_client keeps exactly the billing block",
                        fixture.source
                    );
                }
                SystemPolicy::Replace { content, .. } if content == &json!("") => {
                    assert!(generic.system_template_pending);
                    assert!(generic.replay_body.reused_original());
                }
                SystemPolicy::Replace { .. } => {
                    let system = tree.get("system").and_then(Value::as_array).expect("replaced system");
                    assert!(system.iter().any(|block| block["text"] == "platform identity"));
                    if let Boundary::Resolved { .. } =
                        parse_system_segments(fixture.body.get("system").unwrap_or(&Value::Null)).boundary
                    {
                        let original = fixture.body["system"].as_array().expect("array");
                        assert_eq!(system.last(), original.last(), "{}: dynamic tail kept", fixture.source);
                    }
                }
            }
        }
    }
}
