//! UTC and monotonic time abstractions.

use std::time::{Duration, Instant, SystemTime};

/// A paired UTC and monotonic observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimePoint {
    /// Wall-clock time used for persisted timestamps.
    pub utc: SystemTime,
    /// Monotonic duration from the clock's private origin.
    pub monotonic: Duration,
}

/// Clock used by deterministic state machines.
pub trait Clock: Send + Sync + 'static {
    /// Return paired wall-clock and monotonic time.
    fn now(&self) -> TimePoint;
}

/// Production clock backed by the operating system.
#[derive(Debug)]
pub struct SystemClock {
    origin_utc: SystemTime,
    origin_monotonic: Instant,
}

impl SystemClock {
    /// Create a clock with a single paired origin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin_utc: SystemTime::now(),
            origin_monotonic: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> TimePoint {
        let monotonic = self.origin_monotonic.elapsed();
        TimePoint {
            utc: self.origin_utc + monotonic,
            monotonic,
        }
    }
}
