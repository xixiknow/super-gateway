//! Deterministic paired UTC and monotonic clock.

use std::{
    sync::{Mutex, MutexGuard},
    time::{Duration, SystemTime},
};

use gateway_domain::{Clock, TimePoint};

/// Manually advanced clock for state-machine and timeout tests.
#[derive(Debug)]
pub struct ManualClock {
    current: Mutex<TimePoint>,
}

impl ManualClock {
    /// Create a clock at a caller-supplied paired origin.
    #[must_use]
    pub fn new(origin: TimePoint) -> Self {
        Self {
            current: Mutex::new(origin),
        }
    }

    /// Advance UTC and monotonic time by the same duration.
    pub fn advance(&self, duration: Duration) {
        let mut current = self.lock();
        current.utc += duration;
        current.monotonic += duration;
    }

    /// Advance only persistent UTC, simulating an operating-system clock jump.
    pub fn advance_utc(&self, duration: Duration) {
        self.lock().utc += duration;
    }

    /// Move only persistent UTC backwards without touching monotonic deadlines.
    pub fn rewind_utc(&self, duration: Duration) {
        let mut current = self.lock();
        current.utc = current.utc.checked_sub(duration).unwrap_or(SystemTime::UNIX_EPOCH);
    }

    /// Advance only monotonic runtime time.
    pub fn advance_monotonic(&self, duration: Duration) {
        self.lock().monotonic += duration;
    }

    /// Simulate process restart: UTC persists while the private monotonic origin resets.
    pub fn restart_monotonic(&self) {
        self.lock().monotonic = Duration::ZERO;
    }

    fn lock(&self) -> MutexGuard<'_, TimePoint> {
        self.current.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Clock for ManualClock {
    fn now(&self) -> TimePoint {
        *self.lock()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use gateway_domain::{Clock, TimePoint};

    use super::ManualClock;

    #[test]
    fn advances_both_time_domains() {
        let clock = ManualClock::new(TimePoint {
            utc: SystemTime::UNIX_EPOCH,
            monotonic: Duration::ZERO,
        });
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.now().monotonic, Duration::from_secs(5));
        assert_eq!(clock.now().utc, SystemTime::UNIX_EPOCH + Duration::from_secs(5));
    }

    #[test]
    fn wall_clock_jump_and_restart_are_independent() {
        let clock = ManualClock::new(TimePoint {
            utc: SystemTime::UNIX_EPOCH,
            monotonic: Duration::from_secs(8),
        });
        clock.advance_utc(Duration::from_secs(4));
        assert_eq!(clock.now().monotonic, Duration::from_secs(8));
        clock.restart_monotonic();
        assert_eq!(clock.now().monotonic, Duration::ZERO);
        assert_eq!(clock.now().utc, SystemTime::UNIX_EPOCH + Duration::from_secs(4));
    }
}
