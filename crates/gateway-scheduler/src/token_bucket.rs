//! Deterministic integer token buckets.

use std::time::Duration;

use serde::{Deserialize, Serialize};

const SCALE: u128 = 1_000_000;
const NANOS_PER_MINUTE: u128 = 60_000_000_000;

/// Token-bucket rate and burst.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketConfig {
    /// Whole requests replenished per minute.
    pub requests_per_minute: u32,
    /// Maximum whole request tokens.
    pub burst: u32,
}

impl BucketConfig {
    /// Credential default: 60 RPM with burst 10.
    pub const CREDENTIAL_DEFAULT: Self = Self {
        requests_per_minute: 60,
        burst: 10,
    };
}

/// Integer micro-token bucket with deterministic refill and retry-after.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    config: BucketConfig,
    available: u128,
    remainder: u128,
    last_refill: Duration,
}

impl TokenBucket {
    /// Create a full bucket at a monotonic instant.
    #[must_use]
    pub fn full(config: BucketConfig, now: Duration) -> Self {
        Self {
            config,
            available: u128::from(config.burst) * SCALE,
            remainder: 0,
            last_refill: now,
        }
    }

    /// Consume one request token when available.
    pub fn try_consume(&mut self, now: Duration) -> bool {
        self.refill(now);
        if self.available < SCALE {
            return false;
        }
        self.available -= SCALE;
        true
    }

    /// Earliest wait for one token, rounded up to one millisecond.
    #[must_use]
    pub fn retry_after(&mut self, now: Duration) -> Duration {
        self.refill(now);
        if self.available >= SCALE {
            return Duration::ZERO;
        }
        if self.config.requests_per_minute == 0 {
            return Duration::from_mins(1);
        }
        let missing = SCALE - self.available;
        let numerator = missing * NANOS_PER_MINUTE;
        let denominator = u128::from(self.config.requests_per_minute) * SCALE;
        let nanos = numerator.div_ceil(denominator).max(1);
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }

    /// Current whole-token floor, exposed for reference-model assertions.
    #[must_use]
    pub fn available_tokens(&mut self, now: Duration) -> u32 {
        self.refill(now);
        u32::try_from(self.available / SCALE).unwrap_or(u32::MAX)
    }

    /// Check one-token availability without consuming it.
    pub(crate) fn try_consume_preview(&mut self, now: Duration) -> bool {
        self.refill(now);
        self.available >= SCALE
    }

    /// Replace the rate without manufacturing a fresh burst. Accrued capacity
    /// is first settled under the old rate and then clamped to the new burst.
    pub(crate) fn reconfigure(&mut self, config: BucketConfig, now: Duration) {
        self.refill(now);
        self.config = config;
        self.available = self.available.min(u128::from(config.burst) * SCALE);
        self.remainder = 0;
    }

    fn refill(&mut self, now: Duration) {
        let elapsed = now.saturating_sub(self.last_refill);
        if elapsed.is_zero() {
            return;
        }
        let elapsed_nanos = elapsed.as_nanos();
        let numerator = elapsed_nanos * u128::from(self.config.requests_per_minute) * SCALE + self.remainder;
        let added = numerator / NANOS_PER_MINUTE;
        self.remainder = numerator % NANOS_PER_MINUTE;
        self.available = (self.available + added).min(u128::from(self.config.burst) * SCALE);
        self.last_refill = now;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{BucketConfig, TokenBucket};

    #[test]
    fn retry_after_is_exact_and_refill_has_no_float_drift() {
        let mut bucket = TokenBucket::full(
            BucketConfig {
                requests_per_minute: 2,
                burst: 2,
            },
            Duration::ZERO,
        );
        assert!(bucket.try_consume(Duration::ZERO));
        assert!(bucket.try_consume(Duration::ZERO));
        assert!(!bucket.try_consume(Duration::ZERO));
        assert_eq!(bucket.retry_after(Duration::ZERO), Duration::from_secs(30));
        assert!(bucket.try_consume(Duration::from_secs(30)));
    }

    #[test]
    fn sub_millisecond_observations_do_not_discard_refill_time() {
        let mut bucket = TokenBucket::full(
            BucketConfig {
                requests_per_minute: 60,
                burst: 1,
            },
            Duration::ZERO,
        );
        assert!(bucket.try_consume(Duration::ZERO));
        for step in 1..2_000_u64 {
            assert!(!bucket.try_consume(Duration::from_micros(step * 500)));
        }
        assert!(bucket.try_consume(Duration::from_secs(1)));
    }

    #[test]
    fn reconfigure_clamps_without_refilling_to_the_new_burst() {
        let mut bucket = TokenBucket::full(
            BucketConfig {
                requests_per_minute: 60,
                burst: 10,
            },
            Duration::ZERO,
        );
        for _ in 0..8 {
            assert!(bucket.try_consume(Duration::ZERO));
        }
        bucket.reconfigure(
            BucketConfig {
                requests_per_minute: 120,
                burst: 20,
            },
            Duration::ZERO,
        );
        assert_eq!(bucket.available_tokens(Duration::ZERO), 2);

        bucket.reconfigure(
            BucketConfig {
                requests_per_minute: 120,
                burst: 1,
            },
            Duration::ZERO,
        );
        assert_eq!(bucket.available_tokens(Duration::ZERO), 1);
    }
}
