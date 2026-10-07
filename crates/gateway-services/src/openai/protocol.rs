//! Explicit Chat/Responses conversion; unknown content is rejected rather than dropped.

use super::OpenAiError;
use gateway_domain::{OpenAiAuthKind, OpenAiEndpoint};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Group reasoning policy. Default preserves the client's value.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReasoningPolicy {
    /// Optional maximum from the model's ordered supported-effort list.
    pub maximum: Option<String>,
    /// Explicit opt-in to lowering a requested effort; otherwise reject.
    #[serde(default)]
    pub downgrade: bool,
}

impl ReasoningPolicy {
    /// Apply an explicit ceiling against model capabilities, never lexical ordering.
    ///
    /// # Errors
    /// Rejects unsupported values or requests above a rejecting ceiling.
    pub fn apply(&self, body: &mut Value, supported: &[&str]) -> Result<(), OpenAiError> {
        let chat = body.get("reasoning_effort").is_some();
        let Some(requested) = body
            .pointer("/reasoning/effort")
            .or_else(|| body.get("reasoning_effort"))
            .and_then(Value::as_str)
        else {
            return Ok(());
        };
        let rank = supported
            .iter()
            .position(|effort| *effort == requested)
            .ok_or(OpenAiError::InvalidRequest)?;
        let Some(maximum) = self.maximum.as_deref() else {
            return Ok(());
        };
        let ceiling = supported
            .iter()
            .position(|effort| *effort == maximum)
            .ok_or(OpenAiError::InvalidRequest)?;
        if rank > ceiling {
            if !self.downgrade {
                return Err(OpenAiError::ReasoningLimit);
            }
            if chat {
                body["reasoning_effort"] = json!(maximum);
            } else {
                body["reasoning"]["effort"] = json!(maximum);
            }
        }
        Ok(())
    }
}

/// Prepare the body for the selected account, preserving continuation and tool items.
///
/// # Errors
/// Invalid request shapes are rejected before acquiring upstream resources.
pub fn prepare(body: &Value, endpoint: OpenAiEndpoint, auth: OpenAiAuthKind) -> Result<Value, OpenAiError> {
    if !body.is_object() || body.get("model").and_then(Value::as_str).is_none_or(str::is_empty) {
        return Err(OpenAiError::InvalidRequest);
    }
    let mut result = if endpoint == OpenAiEndpoint::ChatCompletions && auth == OpenAiAuthKind::Oauth {
        chat_to_responses(body)?
    } else {
        body.clone()
    };
    let map = result.as_object_mut().ok_or(OpenAiError::InvalidRequest)?;
    if endpoint == OpenAiEndpoint::Compact {
        map.remove("stream");
        map.remove("store");
    } else if auth == OpenAiAuthKind::Oauth {
        if let Some(Value::String(text)) = map.get("input") {
            map.insert(
                "input".into(),
                json!([{"role":"user","content":[{"type":"input_text","text":text}]}]),
            );
        }
        map.insert("store".into(), json!(false));
        map.insert("stream".into(), json!(true));
        map.entry("instructions").or_insert_with(|| json!(""));
    }
    Ok(result)
}

/// Validate capabilities explicitly advertised by the published Codex directory.
/// Unknown capabilities stay upstream-authoritative for official API-key models.
/// # Errors
/// Rejects unsupported input modalities and reasoning levels without dropping input.
pub fn validate_capabilities(body: &Value, metadata: Option<&Value>) -> Result<(), OpenAiError> {
    let Some(metadata) = metadata else {
        return Ok(());
    };
    if let Some(efforts) = metadata.get("supported_reasoning_levels").and_then(Value::as_array)
        && let Some(effort) = body
            .pointer("/reasoning/effort")
            .or_else(|| body.get("reasoning_effort"))
            .and_then(Value::as_str)
        && !efforts
            .iter()
            .any(|value| value.get("effort").and_then(Value::as_str) == Some(effort))
    {
        return Err(OpenAiError::InvalidRequest);
    }
    if let Some(modalities) = metadata.get("input_modalities").and_then(Value::as_array) {
        fn contains_image(value: &Value) -> bool {
            match value {
                Value::Object(fields) => {
                    fields
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| matches!(kind, "input_image" | "image_url"))
                        || fields.values().any(contains_image)
                }
                Value::Array(values) => values.iter().any(contains_image),
                _ => false,
            }
        }
        if !modalities.iter().any(|v| v.as_str() == Some("image")) && contains_image(body) {
            return Err(OpenAiError::InvalidRequest);
        }
    }
    Ok(())
}

/// Convert messages, multimodal content, function declarations and tool results.
///
/// # Errors
/// Rejects unsupported message parts, multiple choices, and malformed tool calls.
#[allow(
    clippy::too_many_lines,
    reason = "conversion keeps message and tool ordering explicit"
)]
pub fn chat_to_responses(body: &Value) -> Result<Value, OpenAiError> {
    if body.get("n").is_some_and(|n| n.as_u64() != Some(1)) {
        return Err(OpenAiError::InvalidRequest);
    }
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .ok_or(OpenAiError::InvalidRequest)?;
    let mut input = Vec::new();
    for message in messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .ok_or(OpenAiError::InvalidRequest)?;
        if role == "tool" {
            input.push(
                json!({"type":"function_call_output", "call_id": required_str(message, "tool_call_id")?,
                "output": required_str(message, "content")?}),
            );
            continue;
        }
        if !["system", "developer", "user", "assistant"].contains(&role) {
            return Err(OpenAiError::InvalidRequest);
        }
        if let Some(content) = message.get("content").filter(|v| !v.is_null()) {
            let parts = match content {
                Value::String(text) => vec![json!({"type": if role == "assistant" {"output_text"} else {"input_text"}, "text":text})],
                Value::Array(parts) => parts.iter().map(|part| match part.get("type").and_then(Value::as_str) {
                    Some("text") => Ok(json!({"type": if role == "assistant" {"output_text"} else {"input_text"}, "text":required_str(part, "text")?})),
                    Some("image_url") if role == "user" => {
                        let image = part.get("image_url").ok_or(OpenAiError::InvalidRequest)?;
                        let mut item = json!({"type":"input_image", "image_url":required_str(image, "url")?});
                        if let Some(detail) = image.get("detail") { item["detail"] = detail.clone(); }
                        Ok(item)
                    }
                    _ => Err(OpenAiError::InvalidRequest),
                }).collect::<Result<Vec<_>, _>>()?,
                _ => return Err(OpenAiError::InvalidRequest),
            };
            input.push(json!({"role":role, "content":parts}));
        }
        if let Some(calls) = message.get("tool_calls") {
            for call in calls.as_array().ok_or(OpenAiError::InvalidRequest)? {
                if call.get("type").and_then(Value::as_str) != Some("function") {
                    return Err(OpenAiError::InvalidRequest);
                }
                let function = call.get("function").ok_or(OpenAiError::InvalidRequest)?;
                input.push(json!({"type":"function_call", "call_id":required_str(call, "id")?,
                    "name":required_str(function, "name")?, "arguments":required_str(function, "arguments")?}));
            }
        }
    }
    let mut result = body.clone();
    let map = result.as_object_mut().ok_or(OpenAiError::InvalidRequest)?;
    for field in [
        "messages",
        "n",
        "stream_options",
        "reasoning_effort",
        "max_tokens",
        "max_completion_tokens",
        "response_format",
    ] {
        map.remove(field);
    }
    map.insert("input".into(), json!(input));
    if let Some(effort) = body.get("reasoning_effort") {
        result["reasoning"] = json!({"effort":effort});
    }
    if let Some(limit) = body.get("max_completion_tokens").or_else(|| body.get("max_tokens")) {
        result["max_output_tokens"] = limit.clone();
    }
    if let Some(tools) = body.get("tools") {
        result["tools"] = Value::Array(
            tools
                .as_array()
                .ok_or(OpenAiError::InvalidRequest)?
                .iter()
                .map(|tool| {
                    if tool.get("type").and_then(Value::as_str) != Some("function") {
                        return Err(OpenAiError::InvalidRequest);
                    }
                    let mut function = tool
                        .get("function")
                        .filter(|v| v.is_object())
                        .cloned()
                        .ok_or(OpenAiError::InvalidRequest)?;
                    function["type"] = json!("function");
                    Ok(function)
                })
                .collect::<Result<_, _>>()?,
        );
    }
    if let Some(choice) = body.get("tool_choice").filter(|v| v.is_object()) {
        result["tool_choice"] = json!({"type":"function", "name":choice.pointer("/function/name").and_then(Value::as_str).ok_or(OpenAiError::InvalidRequest)?});
    }
    if let Some(format) = body.get("response_format") {
        let format = if format.get("type").and_then(Value::as_str) == Some("json_schema") {
            let mut schema = format
                .get("json_schema")
                .filter(|v| v.is_object())
                .cloned()
                .ok_or(OpenAiError::InvalidRequest)?;
            schema["type"] = json!("json_schema");
            schema
        } else {
            format.clone()
        };
        result["text"] = json!({"format":format});
    }
    Ok(result)
}

/// Convert a completed Responses object to a single Chat completion.
///
/// # Errors
/// Rejects malformed output rather than silently returning an empty completion.
pub fn responses_to_chat(response: &Value) -> Result<Value, OpenAiError> {
    if response.get("status").and_then(Value::as_str) == Some("failed") {
        return Err(OpenAiError::InvalidRequest);
    }
    let output = response
        .get("output")
        .and_then(Value::as_array)
        .ok_or(OpenAiError::InvalidRequest)?;
    let mut text = String::new();
    let mut calls = Vec::new();
    for item in output {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => {
                for part in item
                    .get("content")
                    .and_then(Value::as_array)
                    .ok_or(OpenAiError::InvalidRequest)?
                {
                    match part.get("type").and_then(Value::as_str) {
                        Some("output_text") => text.push_str(required_str(part, "text")?),
                        _ => return Err(OpenAiError::InvalidRequest),
                    }
                }
            }
            Some("function_call") => calls.push(json!({"id":required_str(item, "call_id")?, "type":"function",
                "function":{"name":required_str(item, "name")?, "arguments":required_str(item, "arguments")?}})),
            Some("reasoning") => {}
            _ => return Err(OpenAiError::InvalidRequest),
        }
    }
    let mut message = json!({"role":"assistant", "content": if text.is_empty() {Value::Null} else {json!(text)}});
    let finish = if response.get("status").and_then(Value::as_str) == Some("incomplete") {
        "length"
    } else if calls.is_empty() {
        "stop"
    } else {
        "tool_calls"
    };
    if !calls.is_empty() {
        message["tool_calls"] = json!(calls);
    }
    let mut result = json!({"id":required_str(response, "id")?, "object":"chat.completion",
        "created":response.get("created_at").cloned().unwrap_or(json!(0)), "model":required_str(response, "model")?,
        "choices":[{"index":0,"message":message,"finish_reason":finish}]});
    if let Some(usage) = response.get("usage").filter(|v| !v.is_null()) {
        result["usage"] = json!({"prompt_tokens":usage.get("input_tokens"), "completion_tokens":usage.get("output_tokens"),
            "total_tokens":usage.get("total_tokens"), "prompt_tokens_details":usage.get("input_tokens_details"),
            "completion_tokens_details":usage.get("output_tokens_details")});
    }
    Ok(result)
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, OpenAiError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(OpenAiError::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_round_trip_and_compact_preserve_context() -> Result<(), OpenAiError> {
        let body = json!({"model":"model", "messages":[
            {"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
            {"role":"tool","tool_call_id":"call_1","content":"result"}], "previous_response_id":"resp_1"});
        let prepared = prepare(&body, OpenAiEndpoint::ChatCompletions, OpenAiAuthKind::Oauth)?;
        assert_eq!(prepared["input"][1]["call_id"], "call_1");
        assert_eq!(prepared["previous_response_id"], "resp_1");
        assert_eq!(prepared["stream"], true);
        let compact = prepare(&prepared, OpenAiEndpoint::Compact, OpenAiAuthKind::Oauth)?;
        assert!(compact.get("stream").is_none());
        assert!(compact.get("store").is_none());
        Ok(())
    }

    #[test]
    fn reasoning_defaults_to_rejection() {
        let mut body = json!({"reasoning":{"effort":"high"}});
        let policy = ReasoningPolicy {
            maximum: Some("low".into()),
            downgrade: false,
        };
        assert_eq!(
            policy.apply(&mut body, &["low", "medium", "high"]),
            Err(OpenAiError::ReasoningLimit)
        );
        assert_eq!(body["reasoning"]["effort"], "high");
    }
}
