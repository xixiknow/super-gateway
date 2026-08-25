#![forbid(unsafe_code)]
//! Pure domain types shared by the gateway adapters.

mod clock;
mod credential;
mod error;
mod ids;
mod readiness;
mod request;
mod response;
mod secret;
mod transport;

pub use clock::{Clock, SystemClock, TimePoint};
pub use credential::{
    AnthropicAccountUuid, ArchetypeCandidate, AttachmentState, AuthKind, AuthState, BrowserChallenge,
    BrowserStrategyState, CanonicalCredentialStatus, CapacityState, ConflictClass, ContinuityChange, CredentialBlocker,
    CredentialLifecycle, CredentialPurpose, CredentialState, EgressBindingSnapshot, EgressDecision, EgressMode,
    EgressPolicy, Enrollment, EnrollmentAction, EnrollmentAuthMethod, EnrollmentMode, EnrollmentNextAction,
    EnrollmentState, EpochSet, MaintenanceKind, MaintenanceOperation, MaintenanceState, MaintenanceTrigger,
    ManagementClass, PlanAdapter, PlanFreshness, ProxyCandidate, ProxyHealth, ProxyLifecycle, ProxyStability,
    RefreshPolicy, SubmittedAuthMaterial, TransportState, choose_archetype, choose_egress,
};
pub use error::{DomainError, DomainResult};
pub use ids::{
    AgentId, ArchetypeVersionId, AttemptPlanId, AuthVersionId, AutoReauthStrategyId, BrowserMaterialVersionId,
    ConnectionAttemptId, CredentialId, CredentialProfileId, DeviceIdentityId, EgressBindingId, EnrollmentId, GroupId,
    LeaseId, MaintenanceOperationId, PlatformKeyId, ProxyEndpointId, RequestId, SecretId, SessionId, TicketId,
    TransportBundleId, TypedId, UserId,
};
pub use readiness::{ApplicationLifecycle, InternalReadiness, PublicReadiness, ReadinessBlocker};
pub use request::{
    AppliedChange, ChangeRisk, ClientClass, Digest, FieldPresence, GenericAdjustedRequest, PinReason, Portability,
    RequestReplayBody, RequestSnapshotSet, SnapshotVersion, TrafficClass,
};
pub use response::{
    BufferTier, ClientCommitState, CostEstimate, DeliveryOutcome, PriceSnapshot, RequestPhase, ResponseMode,
    TokenCounts, UsageCompleteness, UsageObservation, UsageObservationError, UsageSource,
};
pub use secret::{SecretBytes, SecretValue};
pub use transport::{
    AttemptDeadlines, AttemptIdentitySnapshot, EgressRouteSnapshot, FinalUpstreamRequest, HttpProtocol,
    ProxyCredentials, Socks5DnsMode, TransportAttemptSnapshot, UpstreamHeader,
};

/// Version of the test/runtime interfaces introduced by R1.
pub const RUNTIME_ABI_VERSION: &str = "r1-v1";
