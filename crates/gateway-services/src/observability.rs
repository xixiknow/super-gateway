//! Low-cardinality R7 data-plane metrics and typed timeline facts.
#![allow(missing_docs)]

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use gateway_domain::DeliveryOutcome;

/// Stable timeline stages. Identifiers belong in traces/database rows, never metric labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelineStage {
    Accepted,
    Validated,
    Queued,
    Reserved,
    Submitted,
    ResponseCommitted,
    Finished,
}

/// Snapshot exposed to the authenticated operations plane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataPlaneMetricSnapshot {
    pub accepted: u64,
    pub response_committed: u64,
    pub completed: u64,
    pub client_disconnected: u64,
    pub client_write_timeout: u64,
    pub upstream_body_error: u64,
    pub buffer_rejected: u64,
    pub cancelled_before_commit: u64,
    pub delivered_bytes: u64,
    pub unknown_usage: u64,
    pub partial_usage: u64,
    pub complete_usage: u64,
}

/// Process-local instrumentation. Durable request facts are persisted separately.
#[derive(Clone, Debug, Default)]
pub struct DataPlaneObservability {
    inner: Arc<MetricAtoms>,
}

#[derive(Debug, Default)]
struct MetricAtoms {
    accepted: AtomicU64,
    response_committed: AtomicU64,
    completed: AtomicU64,
    client_disconnected: AtomicU64,
    client_write_timeout: AtomicU64,
    upstream_body_error: AtomicU64,
    buffer_rejected: AtomicU64,
    cancelled_before_commit: AtomicU64,
    delivered_bytes: AtomicU64,
    unknown_usage: AtomicU64,
    partial_usage: AtomicU64,
    complete_usage: AtomicU64,
}

impl DataPlaneObservability {
    pub fn accepted(&self) {
        self.inner.accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn response_committed(&self) {
        self.inner.response_committed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn delivery_finished(&self, outcome: DeliveryOutcome, bytes: u64) {
        self.inner.delivered_bytes.fetch_add(bytes, Ordering::Relaxed);
        let counter = match outcome {
            DeliveryOutcome::Complete => &self.inner.completed,
            DeliveryOutcome::ClientDisconnected => &self.inner.client_disconnected,
            DeliveryOutcome::ClientWriteTimeout => &self.inner.client_write_timeout,
            DeliveryOutcome::UpstreamBodyError => &self.inner.upstream_body_error,
            DeliveryOutcome::BufferRejected => &self.inner.buffer_rejected,
            DeliveryOutcome::CancelledBeforeCommit => &self.inner.cancelled_before_commit,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn usage_observed(&self, completeness: gateway_domain::UsageCompleteness) {
        let counter = match completeness {
            gateway_domain::UsageCompleteness::Unknown => &self.inner.unknown_usage,
            gateway_domain::UsageCompleteness::Partial => &self.inner.partial_usage,
            gateway_domain::UsageCompleteness::Complete => &self.inner.complete_usage,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> DataPlaneMetricSnapshot {
        DataPlaneMetricSnapshot {
            accepted: self.inner.accepted.load(Ordering::Relaxed),
            response_committed: self.inner.response_committed.load(Ordering::Relaxed),
            completed: self.inner.completed.load(Ordering::Relaxed),
            client_disconnected: self.inner.client_disconnected.load(Ordering::Relaxed),
            client_write_timeout: self.inner.client_write_timeout.load(Ordering::Relaxed),
            upstream_body_error: self.inner.upstream_body_error.load(Ordering::Relaxed),
            buffer_rejected: self.inner.buffer_rejected.load(Ordering::Relaxed),
            cancelled_before_commit: self.inner.cancelled_before_commit.load(Ordering::Relaxed),
            delivered_bytes: self.inner.delivered_bytes.load(Ordering::Relaxed),
            unknown_usage: self.inner.unknown_usage.load(Ordering::Relaxed),
            partial_usage: self.inner.partial_usage.load(Ordering::Relaxed),
            complete_usage: self.inner.complete_usage.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use gateway_domain::{DeliveryOutcome, UsageCompleteness};

    use super::DataPlaneObservability;

    #[test]
    fn delivery_and_usage_dimensions_are_bounded_and_monotonic() {
        let metrics = DataPlaneObservability::default();
        metrics.accepted();
        metrics.response_committed();
        metrics.delivery_finished(DeliveryOutcome::Complete, 17);
        metrics.usage_observed(UsageCompleteness::Partial);
        assert_eq!(metrics.snapshot().accepted, 1);
        assert_eq!(metrics.snapshot().completed, 1);
        assert_eq!(metrics.snapshot().delivered_bytes, 17);
        assert_eq!(metrics.snapshot().partial_usage, 1);
    }
}
