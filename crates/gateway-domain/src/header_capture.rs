//! Bounded, redacted header snapshots shared by ingress and transport adapters.
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// The captured protocol exchange, distinct from synthetic SSE adapter headers.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeaderTransport {
    /// HTTP request or response.
    Http,
    /// WebSocket connection handshake, shared by subsequent turns.
    WebsocketHandshake,
}

/// One header; repeated names are deliberately retained.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedHeader {
    /// Normalized field name.
    pub name: String,
    /// Display value, with secrets replaced before leaving the adapter.
    pub value: String,
    /// Whether the value was removed by the redactor.
    pub redacted: bool,
}

/// A diagnostic snapshot, not a wire-level recording of casing or order.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderSnapshot {
    /// Header entries in the order supplied by the protocol adapter.
    pub entries: Vec<CapturedHeader>,
    /// Capture time as Unix milliseconds, independent of display timezone.
    pub captured_at_ms: u64,
    /// Protocol exchange represented by this snapshot.
    pub transport: HeaderTransport,
    /// True when the handshake belongs to a reused connection.
    pub reused: bool,
    /// Transport attempt ordinal; ingress snapshots have no attempt.
    pub attempt_ordinal: Option<u32>,
    /// True when the 128-field / 64 KiB diagnostic budget was exceeded.
    pub truncated: bool,
}

impl std::fmt::Debug for HeaderSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderSnapshot")
            .field("header_count", &self.entries.len())
            .field("transport", &self.transport)
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

impl HeaderSnapshot {
    /// Redact before copying values into a bounded snapshot. Secret values are
    /// never decoded, partially revealed, hashed, or retained by this function.
    #[must_use]
    pub fn capture<'a>(transport: HeaderTransport, headers: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        let mut snapshot = Self {
            entries: Vec::new(),
            captured_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            transport,
            reused: false,
            attempt_ordinal: None,
            truncated: false,
        };
        let mut remaining = 64 * 1024_usize;
        for (name, bytes) in headers {
            if snapshot.entries.len() == 128 || name.len() >= remaining {
                snapshot.truncated = true;
                break;
            }
            let name = name.to_ascii_lowercase();
            let redacted = sensitive_header(&name);
            let value = if redacted {
                "[REDACTED]".to_owned()
            } else {
                let limit = remaining.saturating_sub(name.len()).min(16 * 1024);
                snapshot.truncated |= bytes.len() > limit;
                let mut value = String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]).into_owned();
                let mut keep = value.len().min(limit);
                while !value.is_char_boundary(keep) {
                    keep -= 1;
                }
                snapshot.truncated |= keep < value.len();
                value.truncate(keep);
                value
            };
            if name.len() + value.len() > remaining {
                snapshot.truncated = true;
                break;
            }
            remaining = remaining.saturating_sub(name.len() + value.len());
            snapshot.entries.push(CapturedHeader { name, value, redacted });
        }
        snapshot
    }
}

fn sensitive_header(name: &str) -> bool {
    [
        "authorization",
        "cookie",
        "api-key",
        "api_key",
        "apikey",
        "token",
        "secret",
        "session",
        "account-id",
        "account_id",
        "device",
        "fingerprint",
        "profile-seed",
        "session-hmac",
        "sec-websocket-key",
    ]
    .iter()
    .any(|part| name.contains(part))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secrets_and_retains_repeated_diagnostic_fields() {
        let snapshot = HeaderSnapshot::capture(
            HeaderTransport::Http,
            [
                ("Authorization", b"Bearer secret".as_slice()),
                ("Cookie", b"session=secret"),
                ("x-api-key", b"secret"),
                ("chatgpt-account-id", b"private-id"),
                ("session_id", b"private-session"),
                ("x-request-id", b"request-1"),
                ("x-trace", b"first"),
                ("x-trace", b"second"),
            ],
        );
        assert!(
            snapshot.entries[..5]
                .iter()
                .all(|h| h.redacted && h.value == "[REDACTED]")
        );
        assert_eq!(snapshot.entries[5].value, "request-1");
        assert_eq!(snapshot.entries[6].name, snapshot.entries[7].name);
        assert!(!snapshot.truncated);
    }

    #[test]
    fn bounds_field_count_and_values() {
        let bytes = vec![b'x'; 100_000];
        let snapshot = HeaderSnapshot::capture(
            HeaderTransport::Http,
            std::iter::repeat_n(("x-field", bytes.as_slice()), 200),
        );
        assert!(snapshot.truncated);
        assert!(snapshot.entries.len() <= 128);
        assert!(
            snapshot
                .entries
                .iter()
                .map(|h| h.name.len() + h.value.len())
                .sum::<usize>()
                <= 64 * 1024
        );
    }
}
