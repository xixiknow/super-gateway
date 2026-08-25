//! Deterministic typed-ID source.

use std::sync::atomic::{AtomicU64, Ordering};

use uuid::Uuid;

/// Stable, thread-safe sequence with an explicit fixture prefix.
#[derive(Debug)]
pub struct DeterministicIdGenerator {
    prefix: Box<str>,
    next: AtomicU64,
}

impl DeterministicIdGenerator {
    /// Create a generator whose first emitted sequence is `start`.
    #[must_use]
    pub fn new(prefix: impl Into<Box<str>>, start: u64) -> Self {
        Self {
            prefix: prefix.into(),
            next: AtomicU64::new(start),
        }
    }

    /// Generate the next stable identifier.
    #[must_use]
    pub fn next(&self) -> String {
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);
        format!("{}_{sequence:016x}", self.prefix)
    }

    /// Generate a stable UUID fixture using a deterministic prefix namespace and sequence.
    #[must_use]
    pub fn next_uuid(&self) -> Uuid {
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);
        let namespace = self
            .prefix
            .as_bytes()
            .iter()
            .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
            });
        Uuid::from_u128((u128::from(namespace) << 64) | u128::from(sequence))
    }
}

#[cfg(test)]
mod tests {
    use super::DeterministicIdGenerator;

    #[test]
    fn uuid_sequence_is_stable_and_unique() {
        let first = DeterministicIdGenerator::new("credential", 7);
        let second = DeterministicIdGenerator::new("credential", 7);
        let first_id = first.next_uuid();
        assert_eq!(first_id, second.next_uuid());
        assert_ne!(first_id, first.next_uuid());
    }
}
