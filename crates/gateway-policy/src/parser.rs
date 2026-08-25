//! Lossless-enough JSON parsing: exact bytes plus an unambiguous semantic tree.

use std::{collections::BTreeMap, fmt, sync::Arc};

use gateway_domain::{Digest, FieldPresence};
use serde::{Deserialize, Deserializer, de};
use serde_json::{Map, Number, Value};
use thiserror::Error;

const KNOWN_TOP_LEVEL: &[&str] = &[
    "model",
    "max_tokens",
    "messages",
    "system",
    "stream",
    "temperature",
    "top_p",
    "top_k",
    "stop_sequences",
    "tools",
    "tool_choice",
    "thinking",
    "metadata",
    "output_config",
    "context_management",
];

const KNOWN_CONTENT_TYPES: &[&str] = &[
    "text",
    "image",
    "document",
    "tool_use",
    "tool_result",
    "server_tool_use",
    "web_search_tool_result",
    "thinking",
    "redacted_thinking",
];

/// Known fields projected without discarding the original semantic tree.
#[derive(Clone, Debug, PartialEq)]
pub struct KnownMessagesProjection {
    /// Model when it is a string.
    pub model: Option<Box<str>>,
    /// Stream mode when it is a boolean.
    pub stream: Option<bool>,
    /// Exact known field values, including explicit null.
    pub fields: BTreeMap<Box<str>, Value>,
}

/// A parsed request retaining exact bytes, presence, unknowns, and the full tree.
#[derive(Clone)]
pub struct ParsedRequest {
    /// Digest of exact northbound bytes.
    pub raw_digest: Digest,
    /// Exact northbound bytes, scoped to the request task.
    pub raw_body: Arc<[u8]>,
    /// Complete unambiguous JSON tree.
    pub tree: Value,
    /// Projection used by policy and routing.
    pub known: KnownMessagesProjection,
    /// Unknown top-level JSON pointers.
    pub unknown_top_level: Vec<Box<str>>,
    /// Unknown content-block JSON pointers.
    pub unknown_content_blocks: Vec<Box<str>>,
    /// Presence for every recognized top-level field.
    pub presence_map: BTreeMap<Box<str>, FieldPresence>,
}

impl fmt::Debug for ParsedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedRequest")
            .field("raw_digest", &self.raw_digest)
            .field("raw_len", &self.raw_body.len())
            .field("known", &self.known)
            .field("unknown_top_level", &self.unknown_top_level)
            .field("unknown_content_blocks", &self.unknown_content_blocks)
            .field("presence_map", &self.presence_map)
            .finish_non_exhaustive()
    }
}

/// Stable parser failures mapped to the public generic invalid-body error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// Bytes are not valid UTF-8 JSON.
    #[error("invalid JSON")]
    InvalidJson,
    /// The root must be an object.
    #[error("request root is not an object")]
    RootNotObject,
    /// Duplicate object members create parser ambiguity.
    #[error("duplicate JSON object key")]
    DuplicateKey,
    /// Strict mode rejects an unknown field/block.
    #[error("unknown request extension at {0}")]
    UnknownExtension(Box<str>),
}

/// Parse exact request bytes, rejecting duplicate keys at every object depth.
///
/// # Errors
///
/// Returns a stable [`ParseError`] for ambiguous or invalid JSON and for strict-mode unknowns.
pub fn parse_messages_request(raw_body: Arc<[u8]>, strict: bool) -> Result<ParsedRequest, ParseError> {
    let mut deserializer = serde_json::Deserializer::from_slice(&raw_body);
    let unique = UniqueValue::deserialize(&mut deserializer).map_err(|error| map_json_error(&error))?;
    deserializer.end().map_err(|_| ParseError::InvalidJson)?;
    let tree = unique.0;
    let object = tree.as_object().ok_or(ParseError::RootNotObject)?;

    let mut presence_map = BTreeMap::new();
    let mut fields = BTreeMap::new();
    for name in KNOWN_TOP_LEVEL {
        let presence = match object.get(*name) {
            None => FieldPresence::Missing,
            Some(Value::Null) => {
                fields.insert(Box::<str>::from(*name), Value::Null);
                FieldPresence::Null
            }
            Some(value) => {
                fields.insert(Box::<str>::from(*name), value.clone());
                FieldPresence::Value
            }
        };
        presence_map.insert(Box::<str>::from(*name), presence);
    }

    let mut unknown_top_level = object
        .keys()
        .filter(|key| !KNOWN_TOP_LEVEL.contains(&key.as_str()))
        .map(|key| format!("/{}", escape_pointer(key)).into_boxed_str())
        .collect::<Vec<_>>();
    unknown_top_level.sort_unstable();
    let mut unknown_content_blocks = Vec::new();
    collect_unknown_content_blocks(object.get("messages"), true, &mut unknown_content_blocks);
    collect_unknown_content_blocks(object.get("system"), false, &mut unknown_content_blocks);
    unknown_content_blocks.sort_unstable();

    if strict && let Some(path) = unknown_top_level.first().or_else(|| unknown_content_blocks.first()) {
        return Err(ParseError::UnknownExtension(path.clone()));
    }

    Ok(ParsedRequest {
        raw_digest: Digest::of(&raw_body),
        raw_body,
        known: KnownMessagesProjection {
            model: object.get("model").and_then(Value::as_str).map(Box::from),
            stream: object.get("stream").and_then(Value::as_bool),
            fields,
        },
        tree,
        unknown_top_level,
        unknown_content_blocks,
        presence_map,
    })
}

fn collect_unknown_content_blocks(value: Option<&Value>, messages: bool, output: &mut Vec<Box<str>>) {
    let Some(value) = value else { return };
    if messages {
        let Some(items) = value.as_array() else { return };
        for (message_index, message) in items.iter().enumerate() {
            let Some(content) = message.get("content").and_then(Value::as_array) else {
                continue;
            };
            for (content_index, block) in content.iter().enumerate() {
                if unknown_block(block) {
                    output.push(format!("/messages/{message_index}/content/{content_index}").into_boxed_str());
                }
            }
        }
    } else if let Some(system) = value.as_array() {
        for (index, block) in system.iter().enumerate() {
            if unknown_block(block) {
                output.push(format!("/system/{index}").into_boxed_str());
            }
        }
    }
}

fn unknown_block(block: &Value) -> bool {
    block
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| !KNOWN_CONTENT_TYPES.contains(&kind))
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn map_json_error(error: &serde_json::Error) -> ParseError {
    if error.to_string().contains("duplicate object key") {
        ParseError::DuplicateKey
    } else {
        ParseError::InvalidJson
    }
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> de::Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unambiguous JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let value = map.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gateway_domain::FieldPresence;

    use super::{ParseError, parse_messages_request};

    #[test]
    fn preserves_presence_unknowns_and_original_bytes() -> Result<(), ParseError> {
        let raw =
            Arc::<[u8]>::from(br#"{ "model":"m", "max_tokens":null, "messages":[], "future":{"x":1} }"#.as_slice());
        let parsed = parse_messages_request(raw.clone(), false)?;
        assert_eq!(parsed.raw_body.as_ref(), raw.as_ref());
        assert_eq!(parsed.presence_map["max_tokens"], FieldPresence::Null);
        assert_eq!(parsed.presence_map["stream"], FieldPresence::Missing);
        assert_eq!(parsed.unknown_top_level, [Box::<str>::from("/future")]);
        Ok(())
    }

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        let raw = Arc::<[u8]>::from(br#"{"model":"a","model":"b","messages":[]}"#.as_slice());
        assert!(matches!(
            parse_messages_request(raw, false),
            Err(ParseError::DuplicateKey)
        ));
    }

    #[test]
    fn strict_mode_rejects_first_sorted_unknown() {
        let raw = Arc::<[u8]>::from(br#"{"model":"a","messages":[],"z":1,"a":2}"#.as_slice());
        assert!(matches!(
            parse_messages_request(raw, true),
            Err(ParseError::UnknownExtension(path)) if path.as_ref() == "/a"
        ));
    }

    #[test]
    fn bounded_mutation_corpus_never_panics_or_accepts_ambiguous_objects() {
        let seed = br#"{"model":"m","max_tokens":32,"messages":[]}"#;
        for case in 0..2_048_usize {
            let mut bytes = seed.to_vec();
            let index = case % bytes.len();
            let mutation = case.wrapping_mul(73).wrapping_add(41).to_le_bytes()[0];
            bytes[index] ^= mutation;
            let result = parse_messages_request(Arc::from(bytes), false);
            if let Ok(parsed) = result {
                assert!(parsed.tree.is_object());
                assert_eq!(parsed.raw_digest, gateway_domain::Digest::of(&parsed.raw_body));
            }
        }
        let duplicate = Arc::<[u8]>::from(br#"{"x":{"a":1,"a":2}}"#.as_slice());
        assert!(matches!(
            parse_messages_request(duplicate, false),
            Err(ParseError::DuplicateKey)
        ));
    }
}
