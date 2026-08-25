#![forbid(unsafe_code)]
//! `PostgreSQL` adapters, forward-only migrations and transactional persistence ports.

mod backup;
mod credential;
mod egress_rebind;
mod export;
mod group_migration;
mod model_discovery;
mod postgres;
mod proxy;
mod telemetry;
mod upgrade;

pub use credential::{
    AuthCandidateCommit, AuthCandidateRecord, AuthCasPrecondition, BrowserCasPrecondition, BrowserMaterialCandidate,
    BrowserReauthCommit, CredentialEnrollmentCreate, CredentialGroupMigrationBegin, CredentialLifecycleCommand,
    CredentialProfileProvision, CredentialR5Snapshot, DeviceIdentityRebuild, DurableJobFence, EgressAllocation,
    EgressAllocationRequest, EnrollmentRecord, MaintenanceFailureUpdate, MaintenanceOperationCreate,
    MaintenanceOperationRecord, ManagedBrowserStrategyCreate, OAuthCallbackClaim, PlanMappingActivation,
    PlanMappingActivationCommit, PlanMappingArtifactCreate, PlanMappingRecomputeCommit, PlanObservationCommit,
    PlanObservationFence, ProfileCohortUpgrade, ProfileContinuityCommit,
};
pub use egress_rebind::EgressRebindCommit;
pub use export::{UsageExportArtifactCommit, UsageExportDataRow, UsageExportDownload, UsageExportWork};
pub use group_migration::{CredentialGroupMigrationCommit, CredentialGroupMigrationWork};
pub use model_discovery::{DiscoveredModel, ModelDiscoveryCommit};
pub use postgres::{
    AuditOutboxRecord, AuditVerificationReport, BootstrapAdminRecord, BootstrapOutcome, CURRENT_SCHEMA_VERSION,
    GroupOwnerClaim, JobLease, MINIMUM_SCHEMA_VERSION, MigrationReport, OutboxLease, PgStorage, RuntimeRolePolicy,
    SchedulerResourceEventRecord, SecretRewrapCandidate, embedded_migration_count,
};
pub use proxy::ProxyProbeCommit;
pub use telemetry::{
    CancelEstimateEvidencePersist, CostPersist, DeliveryComplete, DeliveryStart, PriceBasis, QuotaCurrentProjection,
    QuotaObservationPersist, RequestCreate, RequestLifecycleComplete, SubmissionIntentArm, UsagePersist,
};
use thiserror::Error;
pub use upgrade::{UpgradeGateCommit, UpgradePreflightCommit, UpgradePreflightWork};

/// Runtime-visible database/schema compatibility state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StorageState {
    /// Connection and migration checks are pending.
    #[default]
    Starting,
    /// Runtime database and schema range are compatible.
    Ready,
    /// Connection or schema compatibility is outside the serving contract.
    Unavailable,
}

/// Read-only storage health port used by the composition root.
pub trait StorageHealth: Send + Sync + 'static {
    /// Return current database/schema state without exposing a connection.
    fn state(&self) -> StorageState;
}

/// Fail-closed storage adapter used before `PostgreSQL` is connected.
#[derive(Debug, Default)]
pub struct UnconfiguredStorage;

impl StorageHealth for UnconfiguredStorage {
    fn state(&self) -> StorageState {
        StorageState::Unavailable
    }
}

/// Stable storage adapter errors.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Runtime database configuration is absent or unreadable.
    #[error("database configuration unavailable")]
    ConfigurationUnavailable,
    /// The database connection failed.
    #[error("database connection failed")]
    ConnectionFailed,
    /// A forward migration failed.
    #[error("database migration failed")]
    MigrationFailed,
    /// The database schema is outside this binary's supported range or has a failed migration.
    #[error("database schema is incompatible")]
    SchemaIncompatible,
    /// The serving process connected with a role outside its least-privilege contract.
    #[error("database runtime role is invalid")]
    RuntimeRoleInvalid,
    /// Empty-database bootstrap variables are incomplete.
    #[error("empty database requires bootstrap administrator credentials")]
    BootstrapRequired,
    /// An atomic persistence operation failed.
    #[error("database transaction failed")]
    TransactionFailed,
    /// An optimistic concurrency precondition failed.
    #[error("storage revision conflict")]
    RevisionConflict,
    /// A transaction-scoped capacity limit was reached.
    #[error("storage capacity limit reached")]
    CapacityExceeded,
    /// A verified account already belongs to another Credential, including an archived one.
    #[error("credential account already exists")]
    AccountConflict,
    /// Candidate authentication material belongs to a different account.
    #[error("credential account mismatch")]
    AccountMismatch,
    /// No stable Egress can currently be reserved under the Group policy.
    #[error("credential egress is unavailable")]
    EgressUnavailable,
    /// The aggregate is in a lifecycle state that rejects this command.
    #[error("credential lifecycle command rejected")]
    InvalidLifecycle,
    /// Audit chain, daily seal, or Deletion Ledger verification failed.
    #[error("storage integrity verification failed")]
    IntegrityViolation,
}
pub use backup::{BackupRunCommit, RestoreDrillCommit, RestoreOperationWork, RestoreValidationCommit};
