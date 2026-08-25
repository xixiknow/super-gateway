//! Evidence-versioned parsing for subscription quota observations.
//!
//! Anthropic's public API documents the standard request/token rate-limit
//! headers. The 5h/7d headers below are therefore treated as captured,
//! versioned evidence and fail closed to an unknown quota projection when a
//! recognized window is ambiguous or malformed.

use bytes::Bytes;
use sha2::{Digest as _, Sha256};

/// Parser/evidence version persisted beside every accepted observation.
pub const SUBSCRIPTION_QUOTA_PARSER_VERSION: &str = "captured-unified-v1";

/// Subscription usage window represented by the captured header family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionQuotaWindow {
    /// Rolling five-hour subscription window.
    FiveHour,
    /// Rolling seven-day subscription window.
    SevenDay,
}

impl SubscriptionQuotaWindow {
    /// Durable database code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FiveHour => "five_hour",
            Self::SevenDay => "seven_day",
        }
    }
}

/// One strictly parsed quota window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionQuotaObservation {
    /// Window represented by this observation.
    pub window: SubscriptionQuotaWindow,
    /// Utilization in billionths, `0..=1_000_000_000`.
    pub utilization_nanos: u32,
    /// Captured reset timestamp as Unix seconds.
    pub reset_epoch_seconds: u64,
    /// Digest of the exact normalized header name/value pairs.
    pub header_digest: [u8; 32],
}

/// Partial parse result. A rejected window never suppresses an independent,
/// valid window, but is surfaced for compatibility telemetry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionQuotaParse {
    /// Independently valid windows.
    pub observations: Vec<SubscriptionQuotaObservation>,
    /// Recognized windows rejected due to ambiguity or malformed values.
    pub rejected_windows: u8,
}

/// Parse the captured subscription quota header family without floating point.
#[must_use]
pub fn parse_subscription_quota_headers(headers: &[(Box<str>, Bytes)]) -> SubscriptionQuotaParse {
    let mut parsed = SubscriptionQuotaParse::default();
    for (window, prefix) in [
        (SubscriptionQuotaWindow::FiveHour, "anthropic-ratelimit-unified-5h"),
        (SubscriptionQuotaWindow::SevenDay, "anthropic-ratelimit-unified-7d"),
    ] {
        let utilization_name = format!("{prefix}-utilization");
        let reset_name = format!("{prefix}-reset");
        let utilization = matching_values(headers, &utilization_name);
        let reset = matching_values(headers, &reset_name);
        if utilization.is_empty() && reset.is_empty() {
            continue;
        }
        if utilization.len() != 1 || reset.len() != 1 {
            parsed.rejected_windows = parsed.rejected_windows.saturating_add(1);
            continue;
        }
        let Some(utilization_text) = strict_header_text(utilization[0]) else {
            parsed.rejected_windows = parsed.rejected_windows.saturating_add(1);
            continue;
        };
        let Some(reset_text) = strict_header_text(reset[0]) else {
            parsed.rejected_windows = parsed.rejected_windows.saturating_add(1);
            continue;
        };
        let Some(utilization_nanos) = parse_utilization_nanos(utilization_text) else {
            parsed.rejected_windows = parsed.rejected_windows.saturating_add(1);
            continue;
        };
        let Some(reset_epoch_seconds) = reset_text.parse::<u64>().ok() else {
            parsed.rejected_windows = parsed.rejected_windows.saturating_add(1);
            continue;
        };
        let mut digest = Sha256::new();
        digest.update(utilization_name.as_bytes());
        digest.update([0]);
        digest.update(utilization_text.as_bytes());
        digest.update([0]);
        digest.update(reset_name.as_bytes());
        digest.update([0]);
        digest.update(reset_text.as_bytes());
        parsed.observations.push(SubscriptionQuotaObservation {
            window,
            utilization_nanos,
            reset_epoch_seconds,
            header_digest: digest.finalize().into(),
        });
    }
    parsed
}

fn matching_values<'a>(headers: &'a [(Box<str>, Bytes)], name: &str) -> Vec<&'a Bytes> {
    headers
        .iter()
        .filter_map(|(candidate, value)| candidate.eq_ignore_ascii_case(name).then_some(value))
        .collect()
}

fn strict_header_text(value: &Bytes) -> Option<&str> {
    std::str::from_utf8(value)
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 64 && !value.contains(','))
}

fn parse_utilization_nanos(value: &str) -> Option<u32> {
    let (whole, fractional) = value.split_once('.').map_or((value, ""), |parts| parts);
    if !matches!(whole, "0" | "1")
        || fractional.len() > 9
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        || (whole == "1" && fractional.bytes().any(|byte| byte != b'0'))
    {
        return None;
    }
    if whole == "1" {
        return Some(1_000_000_000);
    }
    let fraction = if fractional.is_empty() {
        0
    } else {
        fractional
            .parse::<u32>()
            .ok()?
            .checked_mul(10_u32.pow(u32::try_from(9 - fractional.len()).ok()?))?
    };
    Some(fraction)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{SubscriptionQuotaWindow, parse_subscription_quota_headers};

    #[test]
    fn valid_windows_are_exact_and_independent() {
        let headers = vec![
            (
                Box::from("anthropic-ratelimit-unified-5h-utilization"),
                Bytes::from_static(b"0.95"),
            ),
            (
                Box::from("anthropic-ratelimit-unified-5h-reset"),
                Bytes::from_static(b"1770000000"),
            ),
            (
                Box::from("anthropic-ratelimit-unified-7d-utilization"),
                Bytes::from_static(b"0.125000001"),
            ),
            (
                Box::from("anthropic-ratelimit-unified-7d-reset"),
                Bytes::from_static(b"1770000100"),
            ),
        ];
        let parsed = parse_subscription_quota_headers(&headers);
        assert_eq!(parsed.rejected_windows, 0);
        assert_eq!(parsed.observations.len(), 2);
        assert_eq!(parsed.observations[0].window, SubscriptionQuotaWindow::FiveHour);
        assert_eq!(parsed.observations[0].utilization_nanos, 950_000_000);
        assert_eq!(parsed.observations[1].utilization_nanos, 125_000_001);
    }

    #[test]
    fn duplicate_or_malformed_window_never_advances_it() {
        let headers = vec![
            (
                Box::from("anthropic-ratelimit-unified-5h-utilization"),
                Bytes::from_static(b"0.9"),
            ),
            (
                Box::from("Anthropic-RateLimit-Unified-5h-Utilization"),
                Bytes::from_static(b"0.8"),
            ),
            (
                Box::from("anthropic-ratelimit-unified-5h-reset"),
                Bytes::from_static(b"1770000000"),
            ),
            (
                Box::from("anthropic-ratelimit-unified-7d-utilization"),
                Bytes::from_static(b"1.1"),
            ),
            (
                Box::from("anthropic-ratelimit-unified-7d-reset"),
                Bytes::from_static(b"1770000100"),
            ),
        ];
        let parsed = parse_subscription_quota_headers(&headers);
        assert!(parsed.observations.is_empty());
        assert_eq!(parsed.rejected_windows, 2);
    }
}
