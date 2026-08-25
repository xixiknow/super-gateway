//! Side-channel usage observation and exact cost calculation.
#![allow(missing_docs, clippy::large_enum_variant, clippy::struct_excessive_bools)]

use std::io::{self, Write as _};

use flate2::write::GzDecoder;
use gateway_domain::{
    CostEstimate, PriceSnapshot, TokenCounts, UsageCompleteness, UsageObservation, UsageObservationError, UsageSource,
};
use serde_json::Value;

const MAX_SSE_OBSERVER_BUFFER: usize = 256 * 1024;
const MAX_USAGE_OBJECT_BYTES: usize = 64 * 1024;
const MAX_USAGE_DECODED_BYTES: usize = 2 * 1024 * 1024 * 1024;
const PICO_USD_PER_USD: u128 = 1_000_000_000_000;
const TOKENS_PER_MILLION: u128 = 1_000_000;

/// Parses complete SSE events beside the byte relay. Input bytes are never mutated or returned from this type.
#[derive(Clone, Debug, Default)]
pub struct UsageObserver {
    line_buffer: Vec<u8>,
    event_data: Vec<u8>,
    non_stream_scanner: JsonUsageScanner,
    counts: TokenCounts,
    saw_usage: bool,
    saw_message_stop: bool,
    observer_overflowed: bool,
    decoded_bytes_seen: u64,
    committed_event_ordinal: u64,
    committed_content_event_ordinal: u64,
    committed_decoded_end_offset: u64,
    output_content_bytes: u64,
    output_content_seen: bool,
    output_gap: bool,
    ignore_next_lf: bool,
    last_event_type: Option<Box<str>>,
}

/// Last fully committed SSE boundary and its versioned output estimate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseUsageEvidence {
    pub complete_event_ordinal: u64,
    pub content_event_ordinal: u64,
    pub decoded_end_offset: u64,
    pub last_event_type: Option<Box<str>>,
    pub output_tokens_estimate: Option<u64>,
    pub gap: bool,
}

/// Official observation plus cancellation-safe side-channel evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedResponseUsage {
    pub official: UsageObservation,
    pub sse: Option<SseUsageEvidence>,
    pub upstream_bytes_received: u64,
}

/// Observes identity or gzip-encoded upstream bytes without changing the relay.
pub struct EncodedUsageObserver {
    inner: EncodedUsageObserverInner,
    upstream_bytes_received: u64,
}

enum EncodedUsageObserverInner {
    Identity(UsageSink),
    Gzip {
        decoder: GzDecoder<UsageSink>,
        failed: bool,
    },
    Unsupported {
        streaming: bool,
    },
}

#[derive(Clone)]
struct UsageSink {
    observer: UsageObserver,
    streaming: bool,
    decoded_bytes: usize,
}

impl UsageSink {
    fn new(streaming: bool) -> Self {
        Self {
            observer: UsageObserver::default(),
            streaming,
            decoded_bytes: 0,
        }
    }

    fn finish(self, body_complete: bool) -> ObservedResponseUsage {
        if self.streaming {
            self.observer.finish_observed(body_complete)
        } else {
            self.observer.finish_non_stream_observed(body_complete)
        }
    }
}

impl io::Write for UsageSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_USAGE_DECODED_BYTES)
            .ok_or_else(|| io::Error::other("usage decode limit exceeded"))?;
        if self.streaming {
            self.observer.observe_sse_bytes(bytes);
        } else {
            self.observer.observe_non_stream_bytes(bytes);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl EncodedUsageObserver {
    #[must_use]
    pub fn new(content_encoding: Option<&str>, streaming: bool) -> Self {
        let sink = UsageSink::new(streaming);
        let inner = match content_encoding.map(str::trim) {
            None | Some("" | "identity") => EncodedUsageObserverInner::Identity(sink),
            Some(encoding) if encoding.eq_ignore_ascii_case("gzip") => EncodedUsageObserverInner::Gzip {
                decoder: GzDecoder::new(sink),
                failed: false,
            },
            Some(_) => EncodedUsageObserverInner::Unsupported { streaming },
        };
        Self {
            inner,
            upstream_bytes_received: 0,
        }
    }

    pub fn observe(&mut self, bytes: &[u8]) {
        self.upstream_bytes_received = self
            .upstream_bytes_received
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        match &mut self.inner {
            EncodedUsageObserverInner::Identity(sink) => {
                let _ = sink.write_all(bytes);
            }
            EncodedUsageObserverInner::Gzip { decoder, failed } if !*failed => {
                if decoder.write_all(bytes).is_err() {
                    *failed = true;
                }
            }
            EncodedUsageObserverInner::Gzip { .. } | EncodedUsageObserverInner::Unsupported { .. } => {}
        }
    }

    #[must_use]
    pub fn finish(self, body_complete: bool) -> ObservedResponseUsage {
        let mut observed = match self.inner {
            EncodedUsageObserverInner::Identity(sink) => sink.finish(body_complete),
            EncodedUsageObserverInner::Gzip { decoder, failed } => {
                let streaming = decoder.get_ref().streaming;
                if failed {
                    unreachable_observed(streaming)
                } else if body_complete {
                    decoder
                        .finish()
                        .map_or_else(|_| unreachable_observed(streaming), |sink| sink.finish(true))
                } else {
                    decoder.get_ref().clone().finish(false)
                }
            }
            EncodedUsageObserverInner::Unsupported { streaming } => unreachable_observed(streaming),
        };
        observed.upstream_bytes_received = self.upstream_bytes_received;
        observed
    }
}

impl UsageObserver {
    /// Observe an arbitrary SSE byte fragment.
    pub fn observe_sse_bytes(&mut self, bytes: &[u8]) {
        if self.observer_overflowed {
            return;
        }
        for &byte in bytes {
            self.decoded_bytes_seen = self.decoded_bytes_seen.saturating_add(1);
            if self.ignore_next_lf {
                self.ignore_next_lf = false;
                if byte == b'\n' {
                    continue;
                }
            }
            if matches!(byte, b'\n' | b'\r') {
                let line = std::mem::take(&mut self.line_buffer);
                self.observe_sse_line(&line);
                self.ignore_next_lf = byte == b'\r';
            } else if self.line_buffer.len() < MAX_SSE_OBSERVER_BUFFER {
                self.line_buffer.push(byte);
            } else {
                self.mark_observer_gap();
                return;
            }
        }
    }

    /// Observe a fully received non-stream response.
    pub fn observe_non_stream_body(&mut self, body: &[u8]) {
        if let Ok(value) = serde_json::from_slice::<Value>(body) {
            self.observe_json(&value);
            if self.saw_usage {
                self.saw_message_stop = true;
            }
        }
    }

    /// Accumulate a bounded non-stream body for parsing after the full response arrives.
    /// Larger bodies safely degrade usage to `unknown` instead of affecting delivery.
    pub fn observe_non_stream_bytes(&mut self, bytes: &[u8]) {
        let captures = self.non_stream_scanner.scan(bytes);
        self.observer_overflowed |= self.non_stream_scanner.overflowed;
        for capture in captures {
            if let Ok(usage) = serde_json::from_slice::<Value>(&capture) {
                self.merge_usage(&usage);
            }
        }
    }

    /// Finish a bounded non-stream observation.
    #[must_use]
    pub fn finish_non_stream(mut self, body_complete: bool) -> UsageObservation {
        if body_complete && self.saw_usage {
            self.saw_message_stop = true;
        }
        self.finish(body_complete)
    }

    fn finish_non_stream_observed(mut self, body_complete: bool) -> ObservedResponseUsage {
        if body_complete && self.saw_usage {
            self.saw_message_stop = true;
        }
        ObservedResponseUsage {
            official: self.finish(body_complete),
            sse: None,
            upstream_bytes_received: 0,
        }
    }

    /// Return the best official observation without inventing missing fields.
    #[must_use]
    pub fn finish(self, _body_complete: bool) -> UsageObservation {
        let completeness = if !self.saw_usage {
            UsageCompleteness::Unknown
        } else if self.saw_message_stop {
            UsageCompleteness::Complete
        } else {
            UsageCompleteness::Partial
        };
        let counts = if completeness == UsageCompleteness::Unknown {
            TokenCounts::default()
        } else {
            self.counts
        };
        UsageObservation::new(UsageSource::Official, completeness, counts, None).unwrap_or_else(|_| {
            UsageObservation::new(
                UsageSource::Official,
                UsageCompleteness::Unknown,
                TokenCounts::default(),
                None,
            )
            .unwrap_or_else(|_| unreachable_usage())
        })
    }

    fn finish_observed(self, body_complete: bool) -> ObservedResponseUsage {
        let evidence = SseUsageEvidence {
            complete_event_ordinal: self.committed_event_ordinal,
            content_event_ordinal: self.committed_content_event_ordinal,
            decoded_end_offset: self.committed_decoded_end_offset,
            last_event_type: self.last_event_type.clone(),
            output_tokens_estimate: (self.output_content_seen && !self.output_gap)
                .then(|| self.output_content_bytes.saturating_add(3) / 4),
            gap: self.output_gap || self.observer_overflowed,
        };
        ObservedResponseUsage {
            official: self.finish(body_complete),
            sse: Some(evidence),
            upstream_bytes_received: 0,
        }
    }

    fn observe_sse_line(&mut self, line: &[u8]) {
        if line.is_empty() {
            if !self.event_data.is_empty() {
                let data = std::mem::take(&mut self.event_data);
                self.committed_event_ordinal = self.committed_event_ordinal.saturating_add(1);
                self.committed_decoded_end_offset = self.decoded_bytes_seen;
                if data.as_slice() != b"[DONE]" {
                    match serde_json::from_slice::<Value>(&data) {
                        Ok(value) => {
                            self.observe_output_content(&value);
                            self.observe_json(&value);
                            self.last_event_type = value
                                .get("type")
                                .and_then(Value::as_str)
                                .map(|value| value.to_owned().into_boxed_str());
                        }
                        Err(_) => self.output_gap = true,
                    }
                }
            }
            return;
        }
        if let Some(data) = line.strip_prefix(b"data:") {
            let data = data.strip_prefix(b" ").unwrap_or(data);
            if !self.event_data.is_empty() {
                if self.event_data.len() >= MAX_SSE_OBSERVER_BUFFER {
                    self.mark_observer_gap();
                    return;
                }
                self.event_data.push(b'\n');
            }
            if self.event_data.len().saturating_add(data.len()) > MAX_SSE_OBSERVER_BUFFER {
                self.mark_observer_gap();
                return;
            }
            self.event_data.extend_from_slice(data);
        }
    }

    fn observe_output_content(&mut self, value: &Value) {
        let event_type = value.get("type").and_then(Value::as_str);
        let fragments: &[&str] = match event_type {
            Some("content_block_start") => match value.pointer("/content_block/type").and_then(Value::as_str) {
                Some("text") => &["/content_block/text"],
                Some("thinking") => &["/content_block/thinking"],
                Some(
                    "tool_use"
                    | "server_tool_use"
                    | "web_search_tool_result"
                    | "code_execution_tool_result"
                    | "bash_code_execution_tool_result"
                    | "text_editor_code_execution_tool_result",
                ) => &[],
                _ => {
                    self.output_gap = true;
                    self.committed_content_event_ordinal = self.committed_content_event_ordinal.saturating_add(1);
                    return;
                }
            },
            Some("content_block_delta") => match value.pointer("/delta/type").and_then(Value::as_str) {
                Some("text_delta") => &["/delta/text"],
                Some("thinking_delta") => &["/delta/thinking"],
                Some("input_json_delta") => &["/delta/partial_json"],
                Some("signature_delta" | "citations_delta") => &[],
                Some(_) | None => {
                    self.output_gap = true;
                    self.committed_content_event_ordinal = self.committed_content_event_ordinal.saturating_add(1);
                    return;
                }
            },
            Some(value) if value.starts_with("content_block_") => {
                self.output_gap = true;
                self.committed_content_event_ordinal = self.committed_content_event_ordinal.saturating_add(1);
                return;
            }
            _ => return,
        };
        self.committed_content_event_ordinal = self.committed_content_event_ordinal.saturating_add(1);
        for pointer in fragments {
            let Some(fragment) = value.pointer(pointer).and_then(Value::as_str) else {
                self.output_gap = true;
                continue;
            };
            self.output_content_seen = true;
            match self.output_content_bytes.checked_add(fragment.len() as u64) {
                Some(total) => self.output_content_bytes = total,
                None => self.output_gap = true,
            }
        }
    }

    fn mark_observer_gap(&mut self) {
        self.observer_overflowed = true;
        self.output_gap = true;
        self.line_buffer.clear();
        self.event_data.clear();
    }

    fn observe_json(&mut self, value: &Value) {
        if value.get("type").and_then(Value::as_str) == Some("message_stop") {
            self.saw_message_stop = true;
        }
        if let Some(usage) = value.get("usage") {
            self.merge_usage(usage);
        }
        if let Some(usage) = value.pointer("/message/usage") {
            self.merge_usage(usage);
        }
        if let Some(usage) = value.pointer("/delta/usage") {
            self.merge_usage(usage);
        }
    }

    fn merge_usage(&mut self, usage: &Value) {
        let Some(object) = usage.as_object() else {
            return;
        };
        let mut observed = false;
        merge_u64(object.get("input_tokens"), &mut self.counts.input_tokens, &mut observed);
        merge_u64(
            object.get("output_tokens"),
            &mut self.counts.output_tokens,
            &mut observed,
        );
        merge_u64(
            object.get("cache_creation_input_tokens"),
            &mut self.counts.cache_creation_input_tokens,
            &mut observed,
        );
        merge_u64(
            object.get("cache_read_input_tokens"),
            &mut self.counts.cache_read_input_tokens,
            &mut observed,
        );
        self.saw_usage |= observed;
    }
}

#[derive(Clone, Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct JsonUsageScanner {
    in_string: bool,
    escaped: bool,
    string_bytes: Vec<u8>,
    candidate_key: Option<Vec<u8>>,
    awaiting_usage_value: bool,
    capture: Option<JsonObjectCapture>,
    overflowed: bool,
}

impl JsonUsageScanner {
    fn scan(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut completed = Vec::new();
        for &byte in bytes {
            if let Some(capture) = self.capture.as_mut() {
                if capture.push(byte)
                    && let Some(capture) = self.capture.take()
                {
                    self.overflowed |= capture.overflowed;
                    if !capture.overflowed {
                        completed.push(capture.bytes);
                    }
                }
                continue;
            }
            if self.in_string {
                if self.escaped {
                    self.escaped = false;
                    self.string_bytes.push(byte);
                } else if byte == b'\\' {
                    self.escaped = true;
                } else if byte == b'"' {
                    self.in_string = false;
                    self.candidate_key = Some(std::mem::take(&mut self.string_bytes));
                } else if self.string_bytes.len() < 128 {
                    self.string_bytes.push(byte);
                }
                continue;
            }
            if self.awaiting_usage_value {
                if byte.is_ascii_whitespace() {
                    continue;
                }
                self.awaiting_usage_value = false;
                if byte == b'{' {
                    self.capture = Some(JsonObjectCapture::new());
                }
                continue;
            }
            match byte {
                b'"' => {
                    self.in_string = true;
                    self.escaped = false;
                    self.string_bytes.clear();
                }
                b':' => {
                    self.awaiting_usage_value = self.candidate_key.as_deref() == Some(b"usage".as_slice());
                    self.candidate_key = None;
                }
                byte if byte.is_ascii_whitespace() => {}
                _ => self.candidate_key = None,
            }
        }
        if self.capture.as_ref().is_some_and(|capture| capture.overflowed) {
            self.overflowed = true;
        }
        completed
    }
}

#[derive(Clone, Debug)]
struct JsonObjectCapture {
    bytes: Vec<u8>,
    depth: usize,
    in_string: bool,
    escaped: bool,
    overflowed: bool,
}

impl JsonObjectCapture {
    fn new() -> Self {
        Self {
            bytes: vec![b'{'],
            depth: 1,
            in_string: false,
            escaped: false,
            overflowed: false,
        }
    }

    fn push(&mut self, byte: u8) -> bool {
        if self.bytes.len() < MAX_USAGE_OBJECT_BYTES {
            self.bytes.push(byte);
        } else {
            self.overflowed = true;
        }
        if self.in_string {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.in_string = false;
            }
            return false;
        }
        match byte {
            b'"' => self.in_string = true,
            b'{' => self.depth = self.depth.saturating_add(1),
            b'}' => self.depth = self.depth.saturating_sub(1),
            _ => {}
        }
        self.depth == 0
    }
}

fn merge_u64(value: Option<&Value>, target: &mut Option<u64>, observed: &mut bool) {
    if let Some(value) = value.and_then(Value::as_u64) {
        *target = Some(value);
        *observed = true;
    }
}

fn unreachable_usage() -> UsageObservation {
    UsageObservation {
        source: UsageSource::Official,
        completeness: UsageCompleteness::Unknown,
        counts: TokenCounts::default(),
        algorithm_version: None,
    }
}

fn unreachable_observed(streaming: bool) -> ObservedResponseUsage {
    ObservedResponseUsage {
        official: unreachable_usage(),
        sse: streaming.then_some(SseUsageEvidence {
            complete_event_ordinal: 0,
            content_event_ordinal: 0,
            decoded_end_offset: 0,
            last_event_type: None,
            output_tokens_estimate: None,
            gap: true,
        }),
        upstream_bytes_received: 0,
    }
}

/// Choose a single final accounting basis without discarding other observations.
#[must_use]
pub fn select_final_basis(observations: &[UsageObservation]) -> Option<&UsageObservation> {
    observations.iter().max_by_key(|observation| basis_rank(observation))
}

fn basis_rank(observation: &UsageObservation) -> (u8, u8, u8) {
    let source = match observation.source {
        UsageSource::Official => 4,
        UsageSource::ConsoleCount => 3,
        UsageSource::LocalEstimate => 2,
        UsageSource::CancelEstimate => 1,
    };
    let completeness = match observation.completeness {
        UsageCompleteness::Complete => 3,
        UsageCompleteness::Partial => 2,
        UsageCompleteness::Unknown => 1,
    };
    let known = u8::from(observation.completeness != UsageCompleteness::Unknown);
    (known, source, completeness)
}

/// Calculate exact pico-USD from the fields that are known in the selected basis.
///
/// # Errors
///
/// Returns overflow when hostile counts or prices exceed the fixed integer domain.
pub fn calculate_cost(
    usage: &UsageObservation,
    price: PriceSnapshot,
    algorithm_version: impl Into<Box<str>>,
) -> Result<CostEstimate, CostError> {
    let mut total = 0_u128;
    let mut known = false;
    for (count, rate) in [
        (usage.counts.input_tokens, price.input_per_million_pico_usd),
        (usage.counts.output_tokens, price.output_per_million_pico_usd),
        (
            usage.counts.cache_creation_input_tokens,
            price.cache_creation_per_million_pico_usd,
        ),
        (
            usage.counts.cache_read_input_tokens,
            price.cache_read_per_million_pico_usd,
        ),
    ] {
        if let Some(count) = count {
            known = true;
            let numerator = u128::from(count).checked_mul(rate).ok_or(CostError::Overflow)?;
            let rounded = numerator
                .checked_add(TOKENS_PER_MILLION / 2)
                .ok_or(CostError::Overflow)?
                / TOKENS_PER_MILLION;
            total = total.checked_add(rounded).ok_or(CostError::Overflow)?;
        }
    }
    Ok(CostEstimate {
        amount_usd: known.then(|| format_pico_usd(total).into_boxed_str()),
        usage_completeness: usage.completeness,
        algorithm_version: algorithm_version.into(),
    })
}

fn format_pico_usd(value: u128) -> String {
    let whole = value / PICO_USD_PER_USD;
    let fractional = value % PICO_USD_PER_USD;
    format!("{whole}.{fractional:012}")
}

/// Exact cost calculation failure.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CostError {
    #[error("cost calculation overflow")]
    Overflow,
}

impl From<UsageObservationError> for CostError {
    fn from(_value: UsageObservationError) -> Self {
        Self::Overflow
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::similar_names)]
mod tests {
    use std::io::Write as _;

    use flate2::{Compression, write::GzEncoder};
    use gateway_domain::{PriceSnapshot, TokenCounts, UsageCompleteness, UsageObservation, UsageSource};

    use super::{EncodedUsageObserver, UsageObserver, calculate_cost, select_final_basis};

    #[test]
    fn arbitrary_sse_chunks_are_observed_without_reassembly_assumptions() {
        let wire = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        for split in 1..wire.len() {
            let mut observer = UsageObserver::default();
            observer.observe_sse_bytes(&wire[..split]);
            observer.observe_sse_bytes(&wire[split..]);
            let usage = observer.finish(true);
            assert_eq!(usage.completeness, UsageCompleteness::Complete);
            assert_eq!(usage.counts.input_tokens, Some(11));
            assert_eq!(usage.counts.output_tokens, Some(7));
        }
    }

    #[test]
    fn cancellation_estimate_stops_at_last_complete_sse_event() {
        let complete = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"abcdefgh\"}}\n\n";
        let partial = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"must-not-count\"}";
        let mut wire = complete.to_vec();
        wire.extend_from_slice(partial);
        for split in 1..wire.len() {
            let mut observer = EncodedUsageObserver::new(None, true);
            observer.observe(&wire[..split]);
            observer.observe(&wire[split..]);
            let observed = observer.finish(false);
            let evidence = observed.sse.expect("stream evidence");
            assert_eq!(evidence.complete_event_ordinal, 1);
            assert_eq!(evidence.content_event_ordinal, 1);
            assert_eq!(evidence.output_tokens_estimate, Some(2));
            assert_eq!(evidence.last_event_type.as_deref(), Some("content_block_delta"));
            assert!(!evidence.gap);
            assert!(evidence.decoded_end_offset < wire.len() as u64);
        }
    }

    #[test]
    fn cancellation_estimate_marks_unknown_content_delta_as_a_gap() {
        let wire =
            b"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"future_delta\",\"value\":\"opaque\"}}\n\n";
        let mut observer = EncodedUsageObserver::new(None, true);
        observer.observe(wire);
        let evidence = observer.finish(false).sse.expect("stream evidence");
        assert_eq!(evidence.complete_event_ordinal, 1);
        assert_eq!(evidence.content_event_ordinal, 1);
        assert!(evidence.gap);
        assert_eq!(evidence.output_tokens_estimate, None);
    }

    #[test]
    fn cancellation_estimate_marks_missing_known_delta_payload_as_a_gap() {
        let wire = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"abcdefgh\"}}\n\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\"}}\n\n";
        let mut observer = EncodedUsageObserver::new(None, true);
        observer.observe(wire);
        let evidence = observer.finish(false).sse.expect("stream evidence");
        assert_eq!(evidence.complete_event_ordinal, 2);
        assert_eq!(evidence.content_event_ordinal, 2);
        assert!(evidence.gap);
        assert_eq!(evidence.output_tokens_estimate, None);
    }

    #[test]
    fn signature_and_citation_deltas_do_not_invent_output_text() {
        let wire = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"signature_delta\",\"signature\":\"opaque\"}}\n\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"citations_delta\",\"citation\":{\"type\":\"char_location\"}}}\n\n";
        let mut observer = EncodedUsageObserver::new(None, true);
        observer.observe(wire);
        let evidence = observer.finish(false).sse.expect("stream evidence");
        assert_eq!(evidence.complete_event_ordinal, 2);
        assert_eq!(evidence.content_event_ordinal, 2);
        assert!(!evidence.gap);
        assert_eq!(evidence.output_tokens_estimate, None);
    }

    #[test]
    fn committed_message_stop_is_complete_even_if_transport_eof_has_not_arrived() {
        let wire = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\r\n\r\ndata: {\"type\":\"message_stop\"}\r\r";
        let mut observer = EncodedUsageObserver::new(None, true);
        observer.observe(wire);
        let observed = observer.finish(false);
        assert_eq!(observed.official.completeness, UsageCompleteness::Complete);
        assert_eq!(observed.official.counts.output_tokens, Some(3));
        assert_eq!(observed.sse.expect("stream evidence").complete_event_ordinal, 2);
    }

    #[test]
    fn official_partial_beats_complete_estimate_and_cost_is_decimal_string() -> Result<(), Box<dyn std::error::Error>> {
        let official = UsageObservation::new(
            UsageSource::Official,
            UsageCompleteness::Partial,
            TokenCounts {
                input_tokens: Some(1_000_000),
                ..TokenCounts::default()
            },
            None,
        )?;
        let estimate = UsageObservation::new(
            UsageSource::LocalEstimate,
            UsageCompleteness::Complete,
            TokenCounts {
                input_tokens: Some(2_000_000),
                ..TokenCounts::default()
            },
            Some("local-v1".into()),
        )?;
        assert_eq!(select_final_basis(&[estimate, official.clone()]), Some(&official));
        let cost = calculate_cost(
            &official,
            PriceSnapshot {
                input_per_million_pico_usd: 3_000_000_000_000,
                output_per_million_pico_usd: 15_000_000_000_000,
                cache_creation_per_million_pico_usd: 0,
                cache_read_per_million_pico_usd: 0,
            },
            "price-v1",
        )?;
        assert_eq!(cost.amount_usd.as_deref(), Some("3.000000000000"));
        Ok(())
    }

    #[test]
    fn known_cancel_estimate_beats_unknown_official_observation() -> Result<(), Box<dyn std::error::Error>> {
        let official = UsageObservation::new(
            UsageSource::Official,
            UsageCompleteness::Unknown,
            TokenCounts::default(),
            None,
        )?;
        let cancel = UsageObservation::new(
            UsageSource::CancelEstimate,
            UsageCompleteness::Partial,
            TokenCounts {
                input_tokens: Some(7),
                output_tokens: Some(3),
                ..TokenCounts::default()
            },
            Some("cancel-boundary-v1".into()),
        )?;
        assert_eq!(select_final_basis(&[official, cancel.clone()]), Some(&cancel));
        Ok(())
    }

    #[test]
    fn non_stream_usage_scanner_is_chunk_independent_and_bounded() {
        let mut observer = UsageObserver::default();
        observer.observe_non_stream_bytes(b"{\"type\":\"message\",\"content\":\"");
        for _ in 0..1_000 {
            observer.observe_non_stream_bytes(br"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        }
        observer.observe_non_stream_bytes(b"\",\"usage\":{\"input_tokens\":17,\"output_tokens\":9}}");
        let usage = observer.finish_non_stream(true);
        assert_eq!(usage.completeness, UsageCompleteness::Complete);
        assert_eq!(usage.counts.input_tokens, Some(17));
        assert_eq!(usage.counts.output_tokens, Some(9));
    }

    #[test]
    fn gzip_usage_is_decoded_only_for_the_side_channel() -> Result<(), Box<dyn std::error::Error>> {
        let body = br#"{"type":"message","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":23,"output_tokens":5}}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(body)?;
        let compressed = encoder.finish()?;
        for chunk_size in 1..=17 {
            let mut observer = EncodedUsageObserver::new(Some("gzip"), false);
            for chunk in compressed.chunks(chunk_size) {
                observer.observe(chunk);
            }
            let usage = observer.finish(true);
            assert_eq!(usage.official.completeness, UsageCompleteness::Complete);
            assert_eq!(usage.official.counts.input_tokens, Some(23));
            assert_eq!(usage.official.counts.output_tokens, Some(5));
        }
        let mut corrupt = EncodedUsageObserver::new(Some("gzip"), false);
        corrupt.observe(b"not-gzip");
        assert_eq!(corrupt.finish(true).official.completeness, UsageCompleteness::Unknown);
        Ok(())
    }
}
