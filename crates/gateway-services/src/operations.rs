//! Durable operation policy shared by Credential maintenance and later background workers.
#![allow(missing_docs)]

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Operations service ABI version after the R5 restart-safe job contract.
pub const ABI_VERSION: &str = "operations-service-r5-v1";

/// Default database lease for one durable worker generation.
pub const DEFAULT_JOB_LEASE: Duration = Duration::from_mins(1);
/// Heartbeats are emitted three times per default lease.
pub const DEFAULT_JOB_HEARTBEAT: Duration = Duration::from_secs(20);

/// Retry class returned by a durable job adapter after one bounded attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobAttemptDecision {
    /// Atomically mark the job successful.
    Succeeded {
        /// Stable, non-secret completion code.
        outcome_code: String,
    },
    /// Persist a non-secret checkpoint and schedule a later generation.
    Retry {
        /// Stable, sanitized transient error code.
        error_code: String,
        /// Durable UTC delay before a later generation is claimable.
        retry_after_seconds: u32,
        /// Optional non-secret resume position.
        checkpoint: Option<serde_json::Value>,
    },
    /// Persist a terminal sanitized error code.
    DeadLetter {
        /// Stable, sanitized terminal error code.
        error_code: String,
        /// Optional non-secret final checkpoint for diagnosis.
        checkpoint: Option<serde_json::Value>,
    },
}

/// Generation-fenced input for one Credential Enrollment durable-job attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialEnrollmentJobAttempt {
    pub enrollment_id: Uuid,
    pub credential_id: Uuid,
    pub job_id: Uuid,
    pub job_generation: i64,
}

/// Restart-safe execution port for one Credential Enrollment durable-job attempt.
#[async_trait]
pub trait CredentialEnrollmentJobExecutor: Send + Sync + 'static {
    /// Advance one enrollment as far as possible without exposing secret material
    /// in the durable job payload or decision checkpoint.
    async fn execute(&self, attempt: CredentialEnrollmentJobAttempt) -> JobAttemptDecision;
}

/// Input for one environment-owned backup or isolated-restore attempt.  It
/// contains references and verified manifest data, never repository secrets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupOperationRequest {
    pub operation_id: Uuid,
    pub kind: BackupOperationKind,
    pub backup_run_id: Option<Uuid>,
    pub recovery_point: Option<String>,
    pub manifest: Option<serde_json::Value>,
    pub manifest_sha256_hex: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupOperationKind {
    BackupCreate,
    ManifestValidation,
    FullRestoreDrill,
}

/// Sanitized result returned by the external backup adapter.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackupOperationResult {
    Backup {
        manifest: serde_json::Value,
        manifest_sha256_hex: String,
        database_system_id: String,
        timeline: i64,
        lsn_start: String,
        lsn_end: String,
        wal_archived_at: String,
        watermarks: serde_json::Value,
        backup_key_version: i64,
        repository_ref: String,
        bytes_written: i64,
    },
    Validation {
        manifest_sha256_hex: String,
        checks: serde_json::Value,
        lineage: serde_json::Value,
    },
    Drill {
        manifest_sha256_hex: String,
        isolated_environment_id: String,
        db_recovered: bool,
        object_replayed: bool,
        ledger_replayed: bool,
        checks: serde_json::Value,
        lineage: serde_json::Value,
        rpo_seconds: i64,
        rto_seconds: i64,
        serving_simulated: bool,
        destroyed: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackupOperationFailure {
    Transient(String),
    Terminal(String),
}

/// Adapter boundary for base-backup/WAL tooling.  The gateway owns leases,
/// authorization and evidence; the adapter owns the environment-specific tool.
#[async_trait]
pub trait BackupOperationsExecutor: Send + Sync + 'static {
    async fn execute(&self, request: BackupOperationRequest) -> Result<BackupOperationResult, BackupOperationFailure>;
}

/// Frozen R5 retry policy for authentication maintenance jobs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaintenanceJobPolicy {
    lease: Duration,
    heartbeat: Duration,
    retry_schedule: [Duration; 4],
}

impl Default for MaintenanceJobPolicy {
    fn default() -> Self {
        Self {
            lease: DEFAULT_JOB_LEASE,
            heartbeat: DEFAULT_JOB_HEARTBEAT,
            retry_schedule: [
                Duration::from_secs(30),
                Duration::from_mins(2),
                Duration::from_mins(10),
                Duration::from_mins(30),
            ],
        }
    }
}

impl MaintenanceJobPolicy {
    /// Validate a custom policy before it reaches a storage adapter.
    pub fn new(lease: Duration, heartbeat: Duration, retry_schedule: [Duration; 4]) -> Option<Self> {
        if lease.is_zero()
            || heartbeat.is_zero()
            || heartbeat >= lease
            || retry_schedule.iter().any(Duration::is_zero)
            || !retry_schedule.windows(2).all(|pair| pair[0] <= pair[1])
        {
            return None;
        }
        Some(Self {
            lease,
            heartbeat,
            retry_schedule,
        })
    }

    /// Database lease duration.
    #[must_use]
    pub const fn lease(&self) -> Duration {
        self.lease
    }

    /// Heartbeat interval.
    #[must_use]
    pub const fn heartbeat(&self) -> Duration {
        self.heartbeat
    }

    /// Bounded retry delay. Attempts after the fourth use the final 30-minute delay.
    #[must_use]
    pub fn retry_delay(&self, completed_attempts: u32) -> Duration {
        let index = completed_attempts.saturating_sub(1) as usize;
        self.retry_schedule[index.min(self.retry_schedule.len() - 1)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r5_job_defaults_and_retry_bounds_are_frozen() {
        let policy = MaintenanceJobPolicy::default();
        assert_eq!(policy.lease(), Duration::from_mins(1));
        assert_eq!(policy.heartbeat(), Duration::from_secs(20));
        assert_eq!(policy.retry_delay(1), Duration::from_secs(30));
        assert_eq!(policy.retry_delay(2), Duration::from_mins(2));
        assert_eq!(policy.retry_delay(3), Duration::from_mins(10));
        assert_eq!(policy.retry_delay(4), Duration::from_mins(30));
        assert_eq!(policy.retry_delay(u32::MAX), Duration::from_mins(30));
    }

    #[test]
    fn invalid_heartbeat_and_decreasing_retry_schedule_are_rejected() {
        assert!(
            MaintenanceJobPolicy::new(
                Duration::from_mins(1),
                Duration::from_mins(1),
                [
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    Duration::from_secs(3),
                    Duration::from_secs(4),
                ],
            )
            .is_none()
        );
        assert!(
            MaintenanceJobPolicy::new(
                Duration::from_mins(1),
                Duration::from_secs(20),
                [
                    Duration::from_secs(1),
                    Duration::from_secs(3),
                    Duration::from_secs(2),
                    Duration::from_secs(4),
                ],
            )
            .is_none()
        );
    }
}
