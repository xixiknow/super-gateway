#![forbid(unsafe_code)]
//! Single-owner Group scheduling, fairness, eligibility, lease, retry, and resource accounting.

mod actor;
mod attempt;
mod engine;
mod fair_queue;
mod retry;
mod token_bucket;
mod types;

pub use actor::{ActorError, GroupCommand, GroupExecutor, GroupExecutorHandle};
pub use attempt::{
    AttemptPhase, AttemptState, AttemptStateError, CancelDisposition, TransportCancelAction, UpstreamProtocol,
    UsageKnowledge,
};
pub use engine::SchedulerEngine;
pub use retry::{ConnectionAttemptBudget, RetryContext, RetryDecision, RetryErrorClass, RetryStrategy, decide_retry};
pub use token_bucket::{BucketConfig, TokenBucket};
pub use types::{
    AdmissionDecision, AffinityKey, CredentialAuthUpdate, CredentialConfig, CredentialCooldownUpdate,
    CredentialFenceResult, CredentialLease, CredentialQuotaUpdate, CredentialRemoveResult, CredentialState,
    EligibilityClass, ExecutorIdentity, GroupConfig, LeaseRelease, OwnerGeneration, QueueResolution, QueueTicket,
    Rejection, RejectionKind, ResourceAction, ResourceEvent, ResourceKind, RetryCredentialTarget, RetryLeaseDecision,
    RetryLeaseRequest, RuntimeLifecycle, ScheduleEntry, SchedulerError, SchedulerSnapshot, SessionCapacityConfig,
    TicketState,
};
