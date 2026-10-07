//! Bounded SSE decoding and `OpenAI` token accounting independent of byte relay.

use super::OpenAiError;
use gateway_domain::{TokenCounts, UsageCompleteness};
use serde_json::Value;

/// Raw token totals and non-additive details.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenAiUsage {
    /// Total input includes cached input.
    pub input: Option<u64>,
    /// Total output includes reasoning output.
    pub output: Option<u64>,
    /// Input subset charged at cache-read prices.
    pub cached: Option<u64>,
    /// Output subset for reporting only, not an extra cost bucket.
    pub reasoning: Option<u64>,
}

impl OpenAiUsage {
    /// Parse both Responses and Chat usage with checked subset relationships.
    ///
    /// # Errors
    /// Rejects invalid counts and contradictory token subsets.
    pub fn parse(value: &Value) -> Result<Self, OpenAiError> {
        let usage = Self {
            input: count(value.get("input_tokens").or_else(|| value.get("prompt_tokens")))?,
            output: count(value.get("output_tokens").or_else(|| value.get("completion_tokens")))?,
            cached: count(
                value
                    .pointer("/input_tokens_details/cached_tokens")
                    .or_else(|| value.pointer("/prompt_tokens_details/cached_tokens")),
            )?,
            reasoning: count(
                value
                    .pointer("/output_tokens_details/reasoning_tokens")
                    .or_else(|| value.pointer("/completion_tokens_details/reasoning_tokens")),
            )?,
        };
        if usage
            .input
            .zip(usage.cached)
            .is_some_and(|(total, subset)| subset > total)
            || usage
                .output
                .zip(usage.reasoning)
                .is_some_and(|(total, subset)| subset > total)
        {
            return Err(OpenAiError::InvalidUsage);
        }
        Ok(usage)
    }

    /// Convert to existing mutually exclusive cost buckets without charging reasoning twice.
    #[must_use]
    pub fn cost_counts(self) -> TokenCounts {
        TokenCounts {
            input_tokens: self.input.map(|total| total.saturating_sub(self.cached.unwrap_or(0))),
            output_tokens: self.output,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: self.cached,
        }
    }
}

fn count(value: Option<&Value>) -> Result<Option<u64>, OpenAiError> {
    value
        .filter(|v| !v.is_null())
        .map(|v| v.as_u64().ok_or(OpenAiError::InvalidUsage))
        .transpose()
}

/// One response observer. A duplicate terminal event never produces a second completion.
#[derive(Debug, Default)]
pub struct ResponseObserver {
    /// First nonempty text, reasoning, or tool-argument output.
    pub first_content_at: Option<std::time::Instant>,
    /// Last valid usage snapshot.
    pub usage: OpenAiUsage,
    /// Actual response model, when observed.
    pub model: Option<String>,
    /// Upstream response identifier for continuation ownership.
    pub response_id: Option<String>,
    /// completed, failed or incomplete; missing means a truncated stream.
    pub terminal: Option<String>,
}

impl ResponseObserver {
    /// Observe a JSON event. Returns true exactly once, on the first terminal event.
    ///
    /// # Errors
    /// Contradictory usage is reported to the caller.
    pub fn observe(&mut self, event: &Value) -> Result<bool, OpenAiError> {
        if self.terminal.is_some() {
            return Ok(false);
        }
        if self.first_content_at.is_none() && has_output_content(event) {
            self.first_content_at = Some(std::time::Instant::now());
        }
        let response = event.get("response").unwrap_or(event);
        if let Some(id) = response.get("id").and_then(Value::as_str) {
            self.response_id = Some(id.to_owned());
        }
        if let Some(model) = response.get("model").and_then(Value::as_str) {
            self.model = Some(model.to_owned());
        }
        if let Some(value) = response.get("usage").filter(|v| !v.is_null()) {
            let incoming = OpenAiUsage::parse(value)?;
            // Some upstream terminal events contain zero placeholders after a valid snapshot.
            if incoming.input != Some(0) || incoming.output != Some(0) || self.usage == OpenAiUsage::default() {
                self.usage = incoming;
            }
        }
        if let Some(kind @ ("response.completed" | "response.failed" | "response.incomplete")) =
            event.get("type").and_then(Value::as_str)
        {
            self.terminal = Some(kind.to_owned());
            return Ok(true);
        }
        Ok(false)
    }

    /// Usage completeness is independent of success or failure.
    #[must_use]
    pub fn completeness(&self) -> UsageCompleteness {
        if self.usage == OpenAiUsage::default() {
            UsageCompleteness::Unknown
        } else if self.terminal.is_some() && self.usage.input.is_some() && self.usage.output.is_some() {
            UsageCompleteness::Complete
        } else {
            UsageCompleteness::Partial
        }
    }
}

fn has_output_content(event: &Value) -> bool {
    let nonempty = |value: Option<&Value>| value.and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    if matches!(
        event.get("type").and_then(Value::as_str),
        Some(
            "response.output_text.delta"
                | "response.reasoning_text.delta"
                | "response.reasoning_summary_text.delta"
                | "response.function_call_arguments.delta"
                | "response.custom_tool_call_input.delta"
                | "response.refusal.delta"
        )
    ) && nonempty(event.get("delta"))
    {
        return true;
    }
    event.get("choices").and_then(Value::as_array).is_some_and(|choices| {
        choices.iter().any(|choice| {
            let delta = choice.get("delta").or_else(|| choice.get("message"));
            delta.is_some_and(|d| {
                nonempty(d.get("content"))
                    || nonempty(d.get("refusal"))
                    || nonempty(d.get("reasoning_content"))
                    || nonempty(d.get("reasoning"))
                    || nonempty(d.pointer("/function_call/arguments"))
                    || d.get("tool_calls")
                        .and_then(Value::as_array)
                        .is_some_and(|tools| tools.iter().any(|t| nonempty(t.pointer("/function/arguments"))))
            })
        })
    })
}

/// Incremental SSE decoder with a strict maximum buffered event size.
#[derive(Debug)]
pub struct SseDecoder {
    pending: Vec<u8>,
    limit: usize,
    done: bool,
}

impl SseDecoder {
    /// Set the maximum event size; response bytes remain owned by the relay.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            pending: Vec::new(),
            limit,
            done: false,
        }
    }

    /// Feed arbitrary byte chunks, including split UTF-8 and CRLF boundaries.
    ///
    /// # Errors
    /// Oversized or malformed JSON data events are rejected.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Value>, OpenAiError> {
        let mut events = Vec::new();
        for byte in bytes {
            if self.pending.len() >= self.limit {
                return Err(OpenAiError::EventTooLarge);
            }
            self.pending.push(*byte);
            if self.pending.ends_with(b"\n\n") || self.pending.ends_with(b"\r\n\r\n") {
                let text = std::str::from_utf8(&self.pending).map_err(|_| OpenAiError::InvalidRequest)?;
                let data = text
                    .lines()
                    .filter_map(|line| line.strip_prefix("data:").map(|v| v.strip_prefix(' ').unwrap_or(v)))
                    .collect::<Vec<_>>()
                    .join("\n");
                if data.trim() == "[DONE]" {
                    self.done = true;
                } else if !data.is_empty() {
                    events.push(serde_json::from_str(&data).map_err(|_| OpenAiError::InvalidRequest)?);
                }
                self.pending.clear();
            }
        }
        Ok(events)
    }

    /// Whether the network ended inside an unfinished event.
    #[must_use]
    pub fn has_partial_event(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Whether an actual Chat Completions end marker was received.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn first_content_tracks_responses_and_chat_without_metadata() -> Result<(), OpenAiError> {
        for output in [
            json!({"type":"response.output_text.delta","delta":"hello"}),
            json!({"type":"response.reasoning_summary_text.delta","delta":"thinking"}),
            json!({"type":"response.function_call_arguments.delta","delta":"{"}),
            json!({"type":"response.custom_tool_call_input.delta","delta":"custom input"}),
            json!({"type":"response.refusal.delta","delta":"refusal text"}),
            json!({"choices":[{"delta":{"content":"hello"}}]}),
            json!({"choices":[{"delta":{"refusal":"refusal text"}}]}),
            json!({"choices":[{"delta":{"reasoning_content":"thinking"}}]}),
            json!({"choices":[{"delta":{"tool_calls":[{"function":{"arguments":"{"}}]}}]}),
        ] {
            let mut observer = ResponseObserver::default();
            for empty in [
                json!({"type":"response.created"}),
                json!({"type":"response.output_text.delta","delta":""}),
                json!({"choices":[{"delta":{"role":"assistant","content":""}}]}),
            ] {
                observer.observe(&empty)?;
            }
            assert!(observer.first_content_at.is_none());
            observer.observe(&output)?;
            let first = observer.first_content_at;
            assert!(first.is_some());
            observer.observe(&output)?;
            assert_eq!(observer.first_content_at, first);
        }
        Ok(())
    }

    #[test]
    fn cache_and_reasoning_are_subsets() -> Result<(), OpenAiError> {
        let usage = OpenAiUsage::parse(&json!({"input_tokens":100,"output_tokens":40,
            "input_tokens_details":{"cached_tokens":60},"output_tokens_details":{"reasoning_tokens":30}}))?;
        assert_eq!(usage.cost_counts().input_tokens, Some(40));
        assert_eq!(usage.cost_counts().output_tokens, Some(40));
        assert_eq!(usage.cost_counts().cache_read_input_tokens, Some(60));
        assert_eq!(
            OpenAiUsage::parse(&json!({"input_tokens":1,"input_tokens_details":{"cached_tokens":2}})),
            Err(OpenAiError::InvalidUsage)
        );
        Ok(())
    }

    #[test]
    fn fragmented_failure_usage_is_recorded_once() -> Result<(), OpenAiError> {
        let event =
            json!({"type":"response.failed","response":{"id":"r1","usage":{"input_tokens":7,"output_tokens":3}}});
        let wire = format!("data: {event}\r\n\r\n");
        let mut decoder = SseDecoder::new(4096);
        let mut observer = ResponseObserver::default();
        let mut completed = 0;
        for byte in wire.as_bytes() {
            for event in decoder.push(&[*byte])? {
                completed += usize::from(observer.observe(&event)?);
            }
        }
        assert_eq!(completed, 1);
        assert!(!observer.observe(&event)?);
        assert_eq!(observer.completeness(), UsageCompleteness::Complete);
        assert!(!decoder.has_partial_event());
        Ok(())
    }
}
