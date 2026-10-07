//! `SQLx` `PostgreSQL` implementation and startup contracts.

#![allow(
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    reason = "adapter methods share one sanitized error taxonomy; integrity verification mirrors the frozen algorithm"
)]

use std::{
    borrow::Cow,
    str::FromStr,
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

use gateway_domain::{SecretBytes, SecretValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::{
    PgPool, Postgres, Row, Transaction,
    migrate::MigrateDatabase as _,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use uuid::Uuid;
use zeroize::Zeroize as _;

use crate::{StorageError, StorageHealth, StorageState};

/// First schema version accepted by this binary.
pub const MINIMUM_SCHEMA_VERSION: i64 = 20_260_824_000_100;
/// Latest schema version understood by this binary.
pub const CURRENT_SCHEMA_VERSION: i64 = 20_260_929_000_400;
const BOOTSTRAP_ADVISORY_LOCK: i64 = 0x4757_4254_5354_5250;
const BUSINESS_KEY_ADVISORY_LOCK: i64 = 0x4757_4255_534b_4559;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

// Keep released migration checksums stable for databases which already applied them.
// SQLx executes this compatibility wrapper, the original SQL and its history insert
// in one transaction under its migration lock. Failure rolls back the trigger DDL too.
//
// Version 20_260_901_000_100 backfills a NOT NULL column into an existing table.
// That migration was written before the immutable-content trigger was added, so it
// fails on a live database because the trigger fires on the UPDATE used by the backfill.
// Rather than re-checksum the already-shipped migration (which would break databases
// that applied it before this wrapper existed), we wrap it: disable the trigger, run
// the original SQL unchanged, then re-enable. The wrapper runs inside SQLx's own
// migration transaction, so any failure rolls back the trigger DDL change as well.
// Only this one version needs the workaround; future migrations should avoid the
// pattern by using a deferred constraint or a separate migration step.
fn upgrade_migrator() -> sqlx::migrate::Migrator {
    let mut migrator = sqlx::migrate!();
    let migrations = migrator.migrations.to_mut();
    for migration in migrations {
        if migration.version == 20_260_901_000_100 {
            migration.sql = Cow::Owned(format!(
                "SET CONSTRAINTS ALL IMMEDIATE;\n\
                 ALTER TABLE gateway.group_config DISABLE TRIGGER group_config_content_immutable;\n{}\n\
                 ALTER TABLE gateway.group_config ENABLE TRIGGER group_config_content_immutable;",
                migration.sql
            ));
        }
    }
    migrator
}

/// Number of migrations embedded in this exact binary.
#[must_use]
pub fn embedded_migration_count() -> i64 {
    i64::try_from(MIGRATOR.iter().count()).unwrap_or(i64::MAX)
}

/// Whether a connection must prove that it uses the dedicated runtime role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeRolePolicy {
    /// Production serving contract.
    Enforce,
    /// Explicit local mode may use its isolated cluster superuser.
    AllowPrivilegedLocal,
    /// Integration harness may use a privileged disposable role.
    AllowPrivilegedTest,
}

/// Result of a migration run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Highest successful timestamp migration version.
    pub current_version: i64,
    /// Number of successful migrations known to `SQLx`.
    pub applied_count: i64,
}

/// Persisted result of claiming one active Credential Group for an executor generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupOwnerClaim {
    /// Claimed Group.
    pub group_id: Uuid,
    /// Executor identity stored in the fencing row.
    pub executor_id: String,
    /// Newly incremented owner generation.
    pub owner_generation: i64,
    /// Group revision after the claim.
    pub group_revision: i64,
}

/// Append-only scheduler resource event accepted by the storage adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerResourceEventRecord {
    /// Event identity.
    pub event_id: Uuid,
    /// Persisted request UUID.
    pub request_id: Uuid,
    /// Stable resource kind code.
    pub resource_kind_code: String,
    /// Optional non-secret resource token identity.
    pub resource_token_id: Option<String>,
    /// `acquire`, `release`, or `forced_release`.
    pub action_code: String,
    /// Request portability class.
    pub portability_code: String,
    /// Owner generation which emitted the event.
    pub owner_generation: i64,
    /// Per-request monotonic event sequence.
    pub event_sequence: i64,
    /// Optional terminal/release reason.
    pub release_reason_code: Option<String>,
}

/// Already-hashed administrator material passed into the atomic bootstrap transaction.
pub struct BootstrapAdminRecord {
    /// Application-generated `UUIDv7`.
    pub user_id: Uuid,
    /// Application-generated `UUIDv7`.
    pub password_credential_id: Uuid,
    /// Display-preserving username.
    pub username: String,
    /// Case-folded lookup form.
    pub username_normalized: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// Optional email.
    pub email: Option<String>,
    /// Optional normalized email.
    pub email_normalized: Option<String>,
    /// Argon2id PHC string; never logged or serialized.
    pub password_phc: SecretValue,
}

impl std::fmt::Debug for BootstrapAdminRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BootstrapAdminRecord")
            .field("user_id", &self.user_id)
            .field("password_credential_id", &self.password_credential_id)
            .field("username", &self.username)
            .field("password_phc", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Idempotent empty-database bootstrap result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// This process created the first administrator.
    Created,
    /// At least one user already existed; environment bootstrap values were ignored.
    ExistingUser,
}

/// Connected `PostgreSQL` runtime adapter.
#[derive(Debug)]
pub struct PgStorage {
    pub(crate) pool: PgPool,
    state: AtomicU8,
}

impl PgStorage {
    /// Create a missing local database and apply every migration embedded in this binary.
    ///
    /// The supplied connection must be able to connect to the `PostgreSQL` maintenance database
    /// and create the target database. Production deployments should continue to use the
    /// dedicated `migrate` command with a pre-provisioned database.
    pub async fn provision_and_migrate(database_url: &SecretValue) -> Result<MigrationReport, StorageError> {
        let exists = Postgres::database_exists(database_url.expose())
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "database provisioning check failed");
                StorageError::DatabaseProvisioningFailed
            })?;
        if !exists && let Err(error) = Postgres::create_database(database_url.expose()).await {
            let appeared_concurrently = Postgres::database_exists(database_url.expose()).await.unwrap_or(false);
            if !appeared_concurrently {
                tracing::error!(error = %error, "database creation failed");
                return Err(StorageError::DatabaseProvisioningFailed);
            }
        }
        Self::migrate(database_url).await
    }

    /// Connect using a plaintext DSN exposed only at this final adapter boundary.
    pub async fn connect(database_url: &SecretValue, role_policy: RuntimeRolePolicy) -> Result<Self, StorageError> {
        let options =
            PgConnectOptions::from_str(database_url.expose()).map_err(|_| StorageError::ConfigurationUnavailable)?;
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(20)
            .acquire_timeout(Duration::from_secs(10))
            .idle_timeout(Duration::from_mins(5))
            .connect_with(options)
            .await
            .map_err(|_| StorageError::ConnectionFailed)?;
        let storage = Self {
            pool,
            state: AtomicU8::new(0),
        };
        storage.validate_role(role_policy).await?;
        storage.validate_schema().await?;
        storage.state.store(1, Ordering::Release);
        Ok(storage)
    }

    /// Run embedded forward-only migrations with the dedicated migration connection.
    pub async fn migrate(database_url: &SecretValue) -> Result<MigrationReport, StorageError> {
        let options =
            PgConnectOptions::from_str(database_url.expose()).map_err(|_| StorageError::ConfigurationUnavailable)?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(30))
            .connect_with(options)
            .await
            .map_err(|_| StorageError::ConnectionFailed)?;
        upgrade_migrator().run(&pool).await.map_err(|error| {
            tracing::error!(error = %error, "database migration failed");
            StorageError::MigrationFailed
        })?;
        let report = read_migration_report(&pool).await?;
        pool.close().await;
        Ok(report)
    }

    /// Return a cloned pool for repository adapters.
    #[must_use]
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    /// Return stable Bundle payload IDs referenced by active Credential Profiles.
    ///
    /// # Errors
    ///
    /// Returns a sanitized storage error when the active snapshot cannot be read or contains a malformed Bundle.
    pub async fn active_transport_bundle_ids(&self) -> Result<Vec<String>, StorageError> {
        let rows = sqlx::query(
            "SELECT DISTINCT bundle.manifest #>> '{payload,bundle_id}' AS bundle_id \
             FROM gateway.anthropic_credential credential \
             JOIN gateway.credential_profile profile ON profile.credential_id = credential.id \
             JOIN catalog.archetype_bundle_binding binding \
               ON binding.archetype_version_id = profile.archetype_version_id AND binding.state_code = 'active' \
             JOIN catalog.transport_bundle bundle ON bundle.id = binding.transport_bundle_id \
             WHERE credential.lifecycle_state_code = 'active' AND profile.lifecycle_code = 'active' \
               AND bundle.lifecycle_code IN ('canary','active') AND bundle.runtime_state_code = 'loadable'",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        rows.into_iter()
            .map(|row| {
                row.try_get::<Option<String>, _>("bundle_id")
                    .map_err(|_| StorageError::SchemaIncompatible)?
                    .filter(|value| !value.is_empty())
                    .ok_or(StorageError::SchemaIncompatible)
            })
            .collect()
    }

    /// Flip a transport bundle into runtime quarantine: only the orthogonal
    /// `runtime_state_code` dial moves, so the R6 lifecycle CHECK (which forbids a
    /// `quarantined` lifecycle value) is never violated. Returns the bundle's
    /// `artifact_version` when the state transition happened, `None` when the bundle
    /// was already quarantined.
    ///
    /// # Errors
    ///
    /// Returns a sanitized storage error when the quarantine update cannot be applied.
    pub async fn quarantine_transport_bundle_runtime(
        executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
        bundle_id: Uuid,
    ) -> Result<Option<i64>, StorageError> {
        sqlx::query_scalar(
            "UPDATE catalog.transport_bundle SET runtime_state_code='quarantined' \
             WHERE id=$1 AND runtime_state_code<>'quarantined' RETURNING artifact_version",
        )
        .bind(bundle_id)
        .fetch_optional(executor)
        .await
        .map_err(|_| StorageError::TransactionFailed)
    }

    /// Verify `SQLx` migration success/count/range without performing DDL.
    pub async fn validate_schema(&self) -> Result<MigrationReport, StorageError> {
        validate_embedded_migration_checksums(&self.pool).await?;
        let report = read_migration_report(&self.pool).await?;
        let embedded_count = i64::try_from(MIGRATOR.iter().count()).map_err(|_| StorageError::SchemaIncompatible)?;
        if report.current_version < CURRENT_SCHEMA_VERSION || report.applied_count < embedded_count {
            self.state.store(2, Ordering::Release);
            return Err(StorageError::SchemaIncompatible);
        }
        Ok(report)
    }

    /// Bootstrap the first `PlatformAdmin` under a transaction-scoped advisory lock.
    pub async fn bootstrap_admin(
        &self,
        candidate: Option<BootstrapAdminRecord>,
    ) -> Result<BootstrapOutcome, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(|_| StorageError::TransactionFailed)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(BOOTSTRAP_ADVISORY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM iam.user_account")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
        if count > 0 {
            transaction
                .commit()
                .await
                .map_err(|_| StorageError::TransactionFailed)?;
            return Ok(BootstrapOutcome::ExistingUser);
        }
        let candidate = candidate.ok_or(StorageError::BootstrapRequired)?;
        insert_bootstrap_admin(&mut transaction, &candidate).await?;
        transaction
            .commit()
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
        Ok(BootstrapOutcome::Created)
    }

    /// Ensure the database Business `KeyProvider` has one valid active 32-byte version.
    pub async fn ensure_database_business_key(&self) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(|_| StorageError::TransactionFailed)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(BUSINESS_KEY_ADVISORY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
        let active: Option<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT key_version,key_material,checksum FROM security.business_key_material \
             WHERE state_code='active' AND provider_code='database' FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        if let Some((_version, material, checksum)) = active {
            let calculated: [u8; 32] = Sha256::digest(&material).into();
            if material.len() != 32 || checksum.as_slice() != calculated {
                return Err(StorageError::TransactionFailed);
            }
        } else {
            let mut material = vec![0_u8; 32];
            getrandom::fill(&mut material).map_err(|_| StorageError::TransactionFailed)?;
            let checksum: [u8; 32] = Sha256::digest(&material).into();
            sqlx::query(
                "INSERT INTO security.business_key_material \
                 (key_version,provider_code,key_material,state_code,checksum,created_at,activated_at) \
                 VALUES (1,'database',$1,'active',$2,clock_timestamp(),clock_timestamp())",
            )
            .bind(&material)
            .bind(checksum.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
            material.zeroize();
        }
        transaction.commit().await.map_err(|_| StorageError::TransactionFailed)
    }

    /// Load a database-provider key version into a zeroizing container.
    pub async fn load_database_business_key(&self, key_version: i64) -> Result<SecretBytes, StorageError> {
        let material: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT key_material FROM security.business_key_material \
             WHERE key_version=$1 AND provider_code='database' AND state_code IN ('active','decrypt_only')",
        )
        .bind(key_version)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        let material = material.ok_or(StorageError::ConfigurationUnavailable)?;
        if material.len() != 32 {
            return Err(StorageError::IntegrityViolation);
        }
        Ok(SecretBytes::new(material))
    }

    /// Atomically activate a new database-provider key while retaining the prior version for reads.
    pub async fn rotate_database_business_key(&self) -> Result<i64, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(|_| StorageError::TransactionFailed)?;
        let (_, next) = self.activate_database_business_key_in(&mut transaction, None).await?;
        transaction
            .commit()
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
        Ok(next)
    }

    /// Activate a new database Business Key inside a caller-owned transaction.
    ///
    /// The optional expected version is a management CAS fence. The old key remains
    /// `decrypt_only`; retirement is a separate restore-gated operation.
    pub async fn activate_database_business_key_in(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        expected_old_version: Option<i64>,
    ) -> Result<(i64, i64), StorageError> {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(BUSINESS_KEY_ADVISORY_LOCK)
            .execute(&mut **transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
        let current: i64 = sqlx::query_scalar(
            "SELECT key_version FROM security.business_key_material \
             WHERE state_code='active' AND provider_code='database' FOR UPDATE",
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        if expected_old_version.is_some_and(|expected| expected != current) {
            return Err(StorageError::RevisionConflict);
        }
        let next = current.checked_add(1).ok_or(StorageError::TransactionFailed)?;
        let mut material = vec![0_u8; 32];
        getrandom::fill(&mut material).map_err(|_| StorageError::TransactionFailed)?;
        let checksum: [u8; 32] = Sha256::digest(&material).into();
        sqlx::query(
            "UPDATE security.business_key_material SET state_code='decrypt_only',retired_at=NULL \
             WHERE key_version=$1 AND provider_code='database' AND state_code='active'",
        )
        .bind(current)
        .execute(&mut **transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        sqlx::query(
            "INSERT INTO security.business_key_material \
             (key_version,provider_code,key_material,state_code,checksum,created_at,activated_at) \
             VALUES ($1,'database',$2,'active',$3,clock_timestamp(),clock_timestamp())",
        )
        .bind(next)
        .bind(&material)
        .bind(checksum.as_slice())
        .execute(&mut **transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        material.zeroize();
        Ok((current, next))
    }

    /// Count live Business Secret and encrypted export rows that still depend
    /// on a key version.
    pub async fn count_live_business_key_references(&self, key_version: i64) -> Result<i64, StorageError> {
        sqlx::query_scalar(
            "SELECT \
               (SELECT count(*) FROM security.encrypted_secret \
                WHERE provider_role_code='business' AND key_version=$1 AND destroyed_at IS NULL) \
               + \
               (SELECT count(*) FROM ops.export_job \
                WHERE key_version=$1 AND wrapped_dek IS NOT NULL)",
        )
        .bind(key_version)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| StorageError::TransactionFailed)
    }

    /// Restore-gated, generation-fenced Business Key retirement or destruction.
    /// The key mutation and Job terminal state commit atomically.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_database_business_key_lifecycle(
        &self,
        job_id: Uuid,
        generation: i64,
        key_version: i64,
        target_state: &str,
        rotation_job_id: Uuid,
        backup_run_id: Uuid,
        restore_drill_id: Uuid,
    ) -> Result<(), StorageError> {
        let expected_state = match target_state {
            "retired" => "decrypt_only",
            "destroyed" => "retired",
            _ => return Err(StorageError::InvalidLifecycle),
        };
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let leased: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ops.durable_job \
             WHERE id=$1 AND kind_code='business_key_lifecycle' AND state_code='leased' AND lease_generation=$2 \
               AND (payload->>'key_version')::bigint=$3 AND payload->>'target_state'=$4 \
               AND payload->>'rotation_job_id'=$5::text AND payload->>'backup_run_id'=$6::text \
               AND payload->>'restore_drill_id'=$7::text FOR UPDATE)",
        )
        .bind(job_id)
        .bind(generation)
        .bind(key_version)
        .bind(target_state)
        .bind(rotation_job_id)
        .bind(backup_run_id)
        .bind(restore_drill_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if !leased {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(BUSINESS_KEY_ADVISORY_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        let _checksum: Vec<u8> = sqlx::query_scalar(
            "SELECT target.checksum \
             FROM security.business_key_material target \
             JOIN ops.durable_job rotation ON rotation.id=$3 \
             JOIN ops.backup_run backup ON backup.id=$4 \
             JOIN ops.restore_drill drill ON drill.id=$5 AND drill.backup_run_id=backup.id \
             JOIN security.business_key_material active ON active.provider_code='database' AND active.state_code='active' \
             WHERE target.key_version=$1 AND target.provider_code='database' AND target.state_code=$2 \
               AND rotation.kind_code='business_key_rotation' AND rotation.state_code='succeeded' \
               AND (rotation.payload->>'old_key_version')::bigint=target.key_version \
               AND COALESCE((rotation.checkpoint->>'remaining_old_references')::bigint,-1)=0 \
               AND backup.state_code='succeeded' AND backup.kind_code='base_backup' \
               AND backup.completed_at >= CASE WHEN $6='retired' THEN rotation.completed_at ELSE target.retired_at END \
               AND drill.state_code='succeeded' AND drill.kind_code='full_restore_drill' \
               AND drill.completed_at>=backup.completed_at \
               AND drill.checks #> '{business_key,active_version}'=to_jsonb(active.key_version) \
               AND COALESCE(drill.checks #> '{business_key,excluded_versions}','[]'::jsonb) \
                   @> jsonb_build_array(target.key_version) \
               AND drill.checks #> '{business_key,live_reference_count}'='0'::jsonb \
               AND drill.checks #> '{business_key,decrypt_probe}'='true'::jsonb \
             FOR UPDATE OF target",
        )
        .bind(key_version)
        .bind(expected_state)
        .bind(rotation_job_id)
        .bind(backup_run_id)
        .bind(restore_drill_id)
        .bind(target_state)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::InvalidLifecycle)?;
        let references: i64 = sqlx::query_scalar(
            "SELECT \
               (SELECT count(*) FROM security.encrypted_secret \
                WHERE provider_role_code='business' AND key_version=$1 AND destroyed_at IS NULL) \
               + (SELECT count(*) FROM ops.export_job WHERE key_version=$1 AND wrapped_dek IS NOT NULL)",
        )
        .bind(key_version)
        .fetch_one(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if references != 0 {
            return Err(StorageError::InvalidLifecycle);
        }
        if target_state == "destroyed" {
            sqlx::query(
                "UPDATE security.business_key_material SET state_code='destroyed',key_material=NULL, \
                   destroyed_at=clock_timestamp() \
                 WHERE key_version=$1 AND provider_code='database' AND state_code='retired'",
            )
            .bind(key_version)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        } else {
            sqlx::query(
                "UPDATE security.business_key_material SET state_code='retired',retired_at=clock_timestamp() \
                 WHERE key_version=$1 AND provider_code='database' AND state_code='decrypt_only'",
            )
            .bind(key_version)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        }
        let completed = sqlx::query(
            "UPDATE ops.durable_job SET state_code='succeeded',lease_owner=NULL,lease_expires_at=NULL, \
               checkpoint=jsonb_build_object('schema_version',1,'phase','complete','target_state',$3), \
               updated_at=clock_timestamp(),completed_at=clock_timestamp() \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
        )
        .bind(job_id)
        .bind(generation)
        .bind(target_state)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if completed.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,'leased','succeeded',$3,$4,$5,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(generation)
        .bind(format!("business_key_{target_state}"))
        .bind(json!({"key_version":key_version,"target_state":target_state}))
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)
    }

    /// Bind one Credential to a Proxy using the frozen Credential → Egress → Proxy lock order.
    pub async fn bind_proxy_egress(
        &self,
        credential_id: Uuid,
        expected_credential_revision: i64,
        binding_id: Uuid,
        proxy_id: Uuid,
    ) -> Result<i64, StorageError> {
        let mut transaction = self.pool.begin().await.map_err(|_| StorageError::TransactionFailed)?;
        let revision: i64 =
            sqlx::query_scalar("SELECT revision FROM gateway.anthropic_credential WHERE id=$1 FOR UPDATE")
                .bind(credential_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| StorageError::TransactionFailed)?;
        if revision != expected_credential_revision {
            return Err(StorageError::RevisionConflict);
        }
        let existing = sqlx::query(
            "SELECT id,egress_epoch,proxy_id FROM gateway.credential_egress_binding WHERE credential_id=$1 FOR UPDATE",
        )
        .bind(credential_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        let proxy = sqlx::query(
            "SELECT max_active_bindings,lifecycle_code,health_code,stability_code \
             FROM gateway.proxy_endpoint WHERE id=$1 FOR UPDATE",
        )
        .bind(proxy_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        let max_bindings: i32 = proxy
            .try_get("max_active_bindings")
            .map_err(|_| StorageError::TransactionFailed)?;
        let lifecycle: String = proxy
            .try_get("lifecycle_code")
            .map_err(|_| StorageError::TransactionFailed)?;
        let health: String = proxy
            .try_get("health_code")
            .map_err(|_| StorageError::TransactionFailed)?;
        let stability: String = proxy
            .try_get("stability_code")
            .map_err(|_| StorageError::TransactionFailed)?;
        if lifecycle != "active" || health != "healthy" || stability != "static" {
            return Err(StorageError::CapacityExceeded);
        }
        let active_bindings: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM gateway.credential_egress_binding \
             WHERE proxy_id=$1 AND lifecycle_code IN ('pending','active','transport_unavailable','rebinding') \
               AND credential_id<>$2",
        )
        .bind(proxy_id)
        .bind(credential_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        if active_bindings >= i64::from(max_bindings) {
            return Err(StorageError::CapacityExceeded);
        }
        let next_epoch = if existing.is_empty() {
            sqlx::query(
                "INSERT INTO gateway.credential_egress_binding \
                 (id,credential_id,mode_code,proxy_id,stability_code,lifecycle_code,egress_epoch,revision,created_at,updated_at) \
                 VALUES ($1,$2,'proxy',$3,'pending','pending',1,1,clock_timestamp(),clock_timestamp())",
            )
            .bind(binding_id)
            .bind(credential_id)
            .bind(proxy_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
            let next_revision: i64 = sqlx::query_scalar(
                "UPDATE gateway.anthropic_credential SET revision=revision+1,updated_at=clock_timestamp() \
                 WHERE id=$1 RETURNING revision",
            )
            .bind(credential_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
            super::credential::append_credential_event(
                &mut transaction,
                credential_id,
                None,
                None,
                "egress_reserved",
                next_revision,
                json!({"binding_id": binding_id, "proxy_id": proxy_id, "egress_epoch": 1}),
            )
            .await?;
            1
        } else {
            let already_bound = existing
                .iter()
                .all(|row| row.try_get::<Option<Uuid>, _>("proxy_id").ok().flatten() == Some(proxy_id));
            let current_epoch = existing
                .iter()
                .filter_map(|row| row.try_get::<i64, _>("egress_epoch").ok())
                .max()
                .ok_or(StorageError::TransactionFailed)?;
            if already_bound {
                transaction
                    .commit()
                    .await
                    .map_err(|_| StorageError::TransactionFailed)?;
                return Ok(current_epoch);
            }
            let existing_id: Uuid = existing[0].try_get("id").map_err(|_| StorageError::TransactionFailed)?;
            let next = current_epoch.checked_add(1).ok_or(StorageError::TransactionFailed)?;
            sqlx::query(
                "UPDATE gateway.credential_egress_binding SET mode_code='proxy',proxy_id=$2, \
                   stability_code='pending',lifecycle_code='rebinding',egress_epoch=$3,revision=revision+1, \
                   rebound_at=clock_timestamp(),updated_at=clock_timestamp() \
                 WHERE credential_id=$1",
            )
            .bind(credential_id)
            .bind(proxy_id)
            .bind(next)
            .execute(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
            let profiles = sqlx::query(
                "UPDATE gateway.credential_profile SET profile_epoch=profile_epoch+1,revision=revision+1, \
                 updated_at=clock_timestamp() WHERE credential_id=$1 \
                 RETURNING id,archetype_version_id,profile_epoch",
            )
            .bind(credential_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
            for profile in profiles {
                let profile_id: Uuid = profile.try_get("id").map_err(|_| StorageError::TransactionFailed)?;
                let archetype_id: Uuid = profile
                    .try_get("archetype_version_id")
                    .map_err(|_| StorageError::TransactionFailed)?;
                let profile_epoch: i64 = profile
                    .try_get("profile_epoch")
                    .map_err(|_| StorageError::TransactionFailed)?;
                sqlx::query(
                    "INSERT INTO gateway.credential_profile_change \
                     (id,credential_profile_id,credential_id,from_archetype_version_id,to_archetype_version_id, \
                      from_profile_epoch,to_profile_epoch,change_kind_code,from_egress_epoch,to_egress_epoch, \
                      reason_code,cohort_code,changed_at) \
                     VALUES ($1,$2,$3,$4,$4,$5,$6,'egress_rebind',$7,$8,'explicit_rebind','explicit',clock_timestamp())",
                )
                .bind(Uuid::now_v7())
                .bind(profile_id)
                .bind(credential_id)
                .bind(archetype_id)
                .bind(profile_epoch - 1)
                .bind(profile_epoch)
                .bind(current_epoch)
                .bind(next)
                .execute(&mut *transaction)
                .await
                .map_err(|_| StorageError::TransactionFailed)?;
            }
            let next_revision: i64 = sqlx::query_scalar(
                "UPDATE gateway.anthropic_credential SET revision=revision+1,transport_state_code='transport_unavailable', \
                 scheduling_state_code='transport_unavailable',updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
            )
            .bind(credential_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
            super::credential::append_credential_event(
                &mut transaction,
                credential_id,
                None,
                None,
                "egress_rebound",
                next_revision,
                json!({"binding_id": existing_id, "proxy_id": proxy_id, "egress_epoch": next}),
            )
            .await?;
            next
        };
        transaction
            .commit()
            .await
            .map_err(|_| StorageError::TransactionFailed)?;
        Ok(next_epoch)
    }

    /// Atomically claim an active Group and increment its durable fencing generation.
    /// A live owner cannot be displaced before its short lease expires.
    pub async fn claim_group_owner(&self, group_id: Uuid, executor_id: &str) -> Result<GroupOwnerClaim, StorageError> {
        if executor_id.is_empty() || executor_id.len() > 255 {
            return Err(StorageError::TransactionFailed);
        }
        let row = sqlx::query(
            "UPDATE gateway.credential_group \
             SET owner_executor_id=$2,owner_generation=owner_generation+1, \
                 owner_lease_expires_at=clock_timestamp()+interval '30 seconds',updated_at=clock_timestamp() \
             WHERE id=$1 AND status_code='active' \
               AND (owner_executor_id IS NULL OR owner_executor_id=$2 \
                    OR (owner_lease_expires_at IS NOT NULL AND owner_lease_expires_at<=clock_timestamp())) \
             RETURNING owner_generation,revision",
        )
        .bind(group_id)
        .bind(executor_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| StorageError::TransactionFailed)?
        .ok_or(StorageError::RevisionConflict)?;
        Ok(GroupOwnerClaim {
            group_id,
            executor_id: executor_id.to_owned(),
            owner_generation: row
                .try_get("owner_generation")
                .map_err(|_| StorageError::TransactionFailed)?,
            group_revision: row.try_get("revision").map_err(|_| StorageError::TransactionFailed)?,
        })
    }

    /// Renew the exact owner generation. A stale process receives a revision conflict.
    ///
    /// The lease column is the only write. `updated_at` stays put so a heartbeat is
    /// not a group edit, and `lock_timeout` keeps a busy group row from pinning a
    /// pooled connection behind a management transaction.
    pub async fn heartbeat_group_owner(
        &self,
        group_id: Uuid,
        executor_id: &str,
        owner_generation: i64,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(|_| StorageError::TransactionFailed)?;
        if let Err(error) = sqlx::query("SET LOCAL lock_timeout = '250ms'")
            .execute(&mut *transaction)
            .await
        {
            let _ = transaction.rollback().await;
            return Err(transaction_error(error));
        }
        let affected = sqlx::query(
            "UPDATE gateway.credential_group \
             SET owner_lease_expires_at=clock_timestamp()+interval '30 seconds' \
             WHERE id=$1 AND owner_executor_id=$2 AND owner_generation=$3 AND status_code='active'",
        )
        .bind(group_id)
        .bind(executor_id)
        .bind(owner_generation)
        .execute(&mut *transaction)
        .await;
        let affected = match affected {
            Ok(result) => result.rows_affected(),
            Err(error) => {
                let _ = transaction.rollback().await;
                // 55P03: the group row is locked by a management transaction. Retry
                // on the next interval instead of treating the wait as a failure.
                let locked = error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .is_some_and(|code| code == "55P03");
                if locked {
                    return Err(StorageError::TransactionFailed);
                }
                return Err(transaction_error(error));
            }
        };
        transaction.commit().await.map_err(transaction_error)?;
        if affected != 1 {
            return Err(StorageError::RevisionConflict);
        }
        Ok(())
    }

    /// Clear ownership only when the exact executor generation still owns the Group.
    pub async fn release_group_owner(
        &self,
        group_id: Uuid,
        executor_id: &str,
        owner_generation: i64,
    ) -> Result<(), StorageError> {
        let affected = sqlx::query(
            "UPDATE gateway.credential_group \
             SET owner_executor_id=NULL,owner_lease_expires_at=NULL,updated_at=clock_timestamp() \
             WHERE id=$1 AND owner_executor_id=$2 AND owner_generation=$3",
        )
        .bind(group_id)
        .bind(executor_id)
        .bind(owner_generation)
        .execute(&self.pool)
        .await
        .map_err(|_| StorageError::TransactionFailed)?
        .rows_affected();
        if affected != 1 {
            return Err(StorageError::RevisionConflict);
        }
        Ok(())
    }

    /// Persist one generation-fenced resource transition. Uniqueness rejects duplicate release.
    pub async fn append_scheduler_resource_event(
        &self,
        record: &SchedulerResourceEventRecord,
    ) -> Result<(), StorageError> {
        self.append_scheduler_resource_events(std::slice::from_ref(record))
            .await
    }

    /// Atomically persist one actor-ledger prefix. Stable event IDs make a
    /// retry after an uncertain commit idempotent without masking a different
    /// duplicate resource transition.
    pub async fn append_scheduler_resource_events(
        &self,
        records: &[SchedulerResourceEventRecord],
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        for record in records {
            if record.owner_generation < 1 || record.event_sequence < 1 {
                return Err(StorageError::TransactionFailed);
            }
            sqlx::query(
            "INSERT INTO telemetry.request_resource_event \
             (id,request_month,request_id,resource_kind_code,resource_token_id,action_code,portability_code, \
              owner_generation,event_sequence,release_reason_code,observed_at) \
             VALUES ($1,(SELECT request_month FROM telemetry.request_record WHERE request_id=$2),$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(record.event_id)
        .bind(record.request_id)
        .bind(&record.resource_kind_code)
        .bind(&record.resource_token_id)
        .bind(&record.action_code)
        .bind(&record.portability_code)
        .bind(record.owner_generation)
        .bind(record.event_sequence)
        .bind(&record.release_reason_code)
        .execute(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        }
        transaction.commit().await.map_err(transaction_error)?;
        Ok(())
    }

    /// Mark active platform keys whose configured expiration has passed.
    pub async fn expire_platform_keys(&self, limit: i64) -> Result<u64, StorageError> {
        if limit < 1 {
            return Ok(0);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let rows = sqlx::query(
            "UPDATE iam.platform_key SET status_code='expired',revision=revision+1,updated_at=clock_timestamp() \
             WHERE id IN (SELECT id FROM iam.platform_key \
                          WHERE status_code='active' AND expires_at IS NOT NULL \
                            AND expires_at<=clock_timestamp() ORDER BY expires_at,id FOR UPDATE SKIP LOCKED LIMIT $1) \
             RETURNING id,revision",
        )
        .bind(limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)?;
        u64::try_from(rows.len()).map_err(|_| StorageError::TransactionFailed)
    }

    /// Claim runnable durable jobs with `SKIP LOCKED` and a generation fence.
    pub async fn claim_jobs(
        &self,
        worker_id: &str,
        limit: i64,
        lease_seconds: i32,
    ) -> Result<Vec<JobLease>, StorageError> {
        if limit < 1 || lease_seconds < 1 {
            return Err(StorageError::TransactionFailed);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let exhausted = sqlx::query(
            "UPDATE ops.durable_job SET state_code='dead_letter',lease_owner=NULL,lease_expires_at=NULL, \
               last_error_code=COALESCE(last_error_code,'lease_expired'),updated_at=clock_timestamp(), \
               completed_at=clock_timestamp() \
             WHERE state_code='leased' AND lease_expires_at < clock_timestamp() AND attempt_count >= max_attempts \
             RETURNING id,lease_generation",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        for row in exhausted {
            let exhausted_job_id: Uuid = row.try_get("id").map_err(transaction_error)?;
            let exhausted_generation: i64 = row.try_get("lease_generation").map_err(transaction_error)?;
            sqlx::query(
                "INSERT INTO ops.durable_job_history \
                 (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
                 VALUES ($1,$2,'leased','dead_letter',$3,'lease_expired',jsonb_build_object('reason','max_attempts'),clock_timestamp())",
            )
            .bind(Uuid::now_v7())
            .bind(exhausted_job_id)
            .bind(exhausted_generation)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        }
        let rows = sqlx::query(
            "WITH candidates AS ( \
               SELECT id FROM ops.durable_job \
               WHERE ((state_code IN ('scheduled','retry_wait') AND run_after <= clock_timestamp()) \
                      OR (state_code='leased' AND lease_expires_at < clock_timestamp())) \
                 AND attempt_count < max_attempts \
               ORDER BY run_after,created_at FOR UPDATE SKIP LOCKED LIMIT $1 \
             ) \
             UPDATE ops.durable_job j SET state_code='leased',lease_owner=$2, \
               lease_generation=j.lease_generation+1,lease_expires_at=clock_timestamp()+($3 * interval '1 second'), \
               attempt_count=j.attempt_count+1,updated_at=clock_timestamp() \
             FROM candidates c WHERE j.id=c.id \
             RETURNING j.id,j.kind_code,j.payload,j.checkpoint,j.lease_generation,j.attempt_count,j.max_attempts",
        )
        .bind(limit)
        .bind(worker_id)
        .bind(lease_seconds)
        .fetch_all(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        let leases = rows
            .into_iter()
            .map(|row| {
                Ok(JobLease {
                    job_id: row.try_get("id").map_err(|_| StorageError::TransactionFailed)?,
                    kind: row.try_get("kind_code").map_err(|_| StorageError::TransactionFailed)?,
                    payload: row.try_get("payload").map_err(|_| StorageError::TransactionFailed)?,
                    checkpoint: row.try_get("checkpoint").map_err(|_| StorageError::TransactionFailed)?,
                    generation: row
                        .try_get("lease_generation")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    attempt: row
                        .try_get("attempt_count")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    max_attempts: row
                        .try_get("max_attempts")
                        .map_err(|_| StorageError::TransactionFailed)?,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        transaction.commit().await.map_err(transaction_error)?;
        Ok(leases)
    }

    /// Extend a durable job lease and atomically persist its non-secret restart checkpoint.
    pub async fn heartbeat_job(
        &self,
        job_id: Uuid,
        generation: i64,
        worker_id: &str,
        lease_seconds: i32,
        checkpoint: Option<&serde_json::Value>,
    ) -> Result<(), StorageError> {
        if lease_seconds < 1 {
            return Err(StorageError::TransactionFailed);
        }
        let result = sqlx::query(
            "UPDATE ops.durable_job SET lease_expires_at=clock_timestamp()+($4 * interval '1 second'), \
               checkpoint=COALESCE($5,checkpoint),updated_at=clock_timestamp() \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2 AND lease_owner=$3 \
               AND lease_expires_at >= clock_timestamp()",
        )
        .bind(job_id)
        .bind(generation)
        .bind(worker_id)
        .bind(lease_seconds)
        .bind(checkpoint)
        .execute(&self.pool)
        .await
        .map_err(transaction_error)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        Ok(())
    }

    /// Release a current lease into a persisted retry deadline and checkpoint.
    pub async fn retry_job(
        &self,
        job_id: Uuid,
        generation: i64,
        retry_after_seconds: i32,
        error_code: &str,
        checkpoint: Option<&serde_json::Value>,
    ) -> Result<(), StorageError> {
        if retry_after_seconds < 0 || error_code.trim().is_empty() {
            return Err(StorageError::TransactionFailed);
        }
        self.finish_job_attempt(
            job_id,
            generation,
            "retry_wait",
            error_code,
            checkpoint,
            Some(retry_after_seconds),
        )
        .await
    }

    /// Permanently fail the current job generation and prevent another claim.
    pub async fn dead_letter_job(
        &self,
        job_id: Uuid,
        generation: i64,
        error_code: &str,
        checkpoint: Option<&serde_json::Value>,
    ) -> Result<(), StorageError> {
        if error_code.trim().is_empty() {
            return Err(StorageError::TransactionFailed);
        }
        self.finish_job_attempt(job_id, generation, "dead_letter", error_code, checkpoint, None)
            .await
    }

    /// Cancel a queued durable job before a worker has leased it.
    pub async fn cancel_job(&self, job_id: Uuid, expected_generation: Option<i64>) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let row = sqlx::query(
            "UPDATE ops.durable_job SET state_code='cancelled',lease_owner=NULL,lease_expires_at=NULL, \
               updated_at=clock_timestamp(),completed_at=clock_timestamp() \
             WHERE id=$1 AND state_code IN ('scheduled','retry_wait') \
               AND ($2 IS NULL OR lease_generation=$2) \
             RETURNING lease_generation",
        )
        .bind(job_id)
        .bind(expected_generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::RevisionConflict)?;
        let generation: i64 = row.try_get("lease_generation").map_err(transaction_error)?;
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,to_state_code,lease_generation,outcome_code,occurred_at) \
             VALUES ($1,$2,'cancelled',$3,'cancelled',clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(generation)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)
    }

    /// Commit a durable job result only for the current lease generation.
    pub async fn complete_job(&self, job_id: Uuid, generation: i64, outcome: &str) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(|_| StorageError::TransactionFailed)?;
        let result = sqlx::query(
            "UPDATE ops.durable_job SET state_code='succeeded',lease_owner=NULL,lease_expires_at=NULL, \
               updated_at=clock_timestamp(),completed_at=clock_timestamp() \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
        )
        .bind(job_id)
        .bind(generation)
        .execute(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,occurred_at) \
             VALUES ($1,$2,'leased','succeeded',$3,$4,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(generation)
        .bind(outcome)
        .execute(&mut *transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        transaction.commit().await.map_err(|_| StorageError::TransactionFailed)
    }

    /// Atomically finish one notification delivery attempt and its owning Job.
    #[allow(clippy::too_many_arguments)]
    pub async fn finish_notification_delivery_attempt(
        &self,
        delivery_id: Uuid,
        destination_id: Uuid,
        job_id: Uuid,
        generation: i64,
        attempt: i32,
        delivery_state: &str,
        outcome_code: &str,
        retry_after_seconds: Option<i32>,
    ) -> Result<(), StorageError> {
        let job_state = match delivery_state {
            "delivered" => "succeeded",
            "retry_wait" => "retry_wait",
            "failed" => "dead_letter",
            _ => return Err(StorageError::InvalidLifecycle),
        };
        let retry_after_seconds = retry_after_seconds.unwrap_or_default();
        if attempt < 1 || outcome_code.is_empty() || (delivery_state == "retry_wait" && retry_after_seconds < 1) {
            return Err(StorageError::TransactionFailed);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let delivery = sqlx::query(
            "UPDATE ops.notification_delivery SET state_code=$3,response_code=$4, \
               next_attempt_at=CASE WHEN $3='retry_wait' THEN clock_timestamp()+make_interval(secs=>$5) ELSE NULL END, \
               delivered_at=CASE WHEN $3='delivered' THEN clock_timestamp() ELSE delivered_at END, \
               last_outcome=jsonb_build_object('code',$4::text),attempt_count=GREATEST(attempt_count,$6), \
               attempt_ordinal=GREATEST(attempt_ordinal,$6),updated_at=clock_timestamp() \
             WHERE id=$1 AND destination_id=$2 AND state_code IN ('pending','retry_wait')",
        )
        .bind(delivery_id)
        .bind(destination_id)
        .bind(delivery_state)
        .bind(outcome_code)
        .bind(retry_after_seconds)
        .bind(attempt)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if delivery.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        let job = sqlx::query(
            "UPDATE ops.durable_job SET state_code=$3,lease_owner=NULL,lease_expires_at=NULL, \
               run_after=CASE WHEN $3='retry_wait' THEN clock_timestamp()+make_interval(secs=>$5) ELSE run_after END, \
               last_error_code=CASE WHEN $3='succeeded' THEN NULL ELSE $4 END,updated_at=clock_timestamp(), \
               completed_at=CASE WHEN $3 IN ('succeeded','dead_letter') THEN clock_timestamp() ELSE NULL END \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
        )
        .bind(job_id)
        .bind(generation)
        .bind(job_state)
        .bind(outcome_code)
        .bind(retry_after_seconds)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if job.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,'leased',$3,$4,$5,jsonb_build_object('delivery_id',$6::text),clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(job_state)
        .bind(generation)
        .bind(outcome_code)
        .bind(delivery_id)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)
    }

    async fn finish_job_attempt(
        &self,
        job_id: Uuid,
        generation: i64,
        target_state: &str,
        outcome: &str,
        checkpoint: Option<&serde_json::Value>,
        retry_after_seconds: Option<i32>,
    ) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let result = sqlx::query(
            "UPDATE ops.durable_job SET state_code=$3,lease_owner=NULL,lease_expires_at=NULL, \
               run_after=CASE WHEN $3='retry_wait' THEN clock_timestamp()+($6 * interval '1 second') ELSE run_after END, \
               checkpoint=COALESCE($5,checkpoint),last_error_code=$4,updated_at=clock_timestamp(), \
               completed_at=CASE WHEN $3='dead_letter' THEN clock_timestamp() ELSE NULL END \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
        )
        .bind(job_id)
        .bind(generation)
        .bind(target_state)
        .bind(outcome)
        .bind(checkpoint)
        .bind(retry_after_seconds.unwrap_or_default())
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,'leased',$3,$4,$5,jsonb_build_object('checkpoint_persisted',$6),clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(target_state)
        .bind(generation)
        .bind(outcome)
        .bind(checkpoint.is_some())
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)
    }

    /// Claim pending Outbox rows for at-least-once delivery.
    pub async fn claim_outbox(
        &self,
        worker_id: &str,
        limit: i64,
        lease_seconds: i32,
    ) -> Result<Vec<OutboxLease>, StorageError> {
        if limit < 1 || lease_seconds < 1 {
            return Err(StorageError::TransactionFailed);
        }
        let rows = sqlx::query(
            "WITH candidates AS ( \
               SELECT id FROM ops.outbox_message \
               WHERE (state_code='pending' AND available_at <= clock_timestamp()) \
                  OR (state_code='leased' AND lease_expires_at < clock_timestamp()) \
               ORDER BY available_at,created_at FOR UPDATE SKIP LOCKED LIMIT $1 \
             ) \
             UPDATE ops.outbox_message o SET state_code='leased',lease_owner=$2, \
               lease_generation=o.lease_generation+1,lease_expires_at=clock_timestamp()+($3 * interval '1 second'), \
               attempt_count=o.attempt_count+1 \
             FROM candidates c WHERE o.id=c.id \
             RETURNING o.id,o.event_id,o.topic_code,o.aggregate_id,o.aggregate_revision, \
                       o.payload_schema_version,o.payload,o.lease_generation,o.attempt_count",
        )
        .bind(limit)
        .bind(worker_id)
        .bind(lease_seconds)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        rows.into_iter()
            .map(|row| {
                Ok(OutboxLease {
                    message_id: row.try_get("id").map_err(|_| StorageError::TransactionFailed)?,
                    event_id: row.try_get("event_id").map_err(|_| StorageError::TransactionFailed)?,
                    topic: row.try_get("topic_code").map_err(|_| StorageError::TransactionFailed)?,
                    aggregate_id: row
                        .try_get("aggregate_id")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    aggregate_revision: row
                        .try_get("aggregate_revision")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    payload_schema_version: row
                        .try_get("payload_schema_version")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    payload: row.try_get("payload").map_err(|_| StorageError::TransactionFailed)?,
                    generation: row
                        .try_get("lease_generation")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    attempt: row
                        .try_get("attempt_count")
                        .map_err(|_| StorageError::TransactionFailed)?,
                })
            })
            .collect()
    }

    /// Mark an Outbox row published using its lease generation fence.
    pub async fn publish_outbox(&self, message_id: Uuid, generation: i64) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE ops.outbox_message SET state_code='published',lease_owner=NULL,lease_expires_at=NULL, \
               published_at=clock_timestamp() WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
        )
        .bind(message_id)
        .bind(generation)
        .execute(&self.pool)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        Ok(())
    }

    /// Return an unsupported/transient Outbox delivery to a bounded backoff,
    /// or dead-letter it after the caller's terminal attempt.
    pub async fn retry_outbox(
        &self,
        message_id: Uuid,
        generation: i64,
        retry_after_seconds: i32,
        dead_letter: bool,
        reason: &str,
    ) -> Result<(), StorageError> {
        if retry_after_seconds < 1 || reason.is_empty() {
            return Err(StorageError::TransactionFailed);
        }
        let state = if dead_letter { "dead_letter" } else { "pending" };
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let updated = sqlx::query(
            "UPDATE ops.outbox_message SET state_code=$3,lease_owner=NULL,lease_expires_at=NULL, \
               available_at=CASE WHEN $3='pending' THEN clock_timestamp()+($4*interval '1 second') ELSE available_at END \
             WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
        )
        .bind(message_id)
        .bind(generation)
        .bind(state)
        .bind(retry_after_seconds)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if updated.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "INSERT INTO ops.outbox_history \
             (id,outbox_message_id,state_code,lease_generation,detail,occurred_at) \
             VALUES ($1,$2,$3,$4,jsonb_build_object('reason_code',$5),clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(message_id)
        .bind(state)
        .bind(generation)
        .bind(reason)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        transaction.commit().await.map_err(transaction_error)
    }

    /// Atomically fan one exact Alert/Recovery event into administrator inboxes
    /// and matching external destinations, then acknowledge the Outbox lease.
    pub async fn publish_alert_event(&self, message: &OutboxLease, phase: &str) -> Result<(), StorageError> {
        if !matches!(phase, "alert" | "recovery") || message.payload_schema_version != 1 {
            return Err(StorageError::TransactionFailed);
        }
        let mut transaction = self.pool.begin().await.map_err(transaction_error)?;
        let alert = sqlx::query(
            "SELECT id,fingerprint,severity_code,type_code,state_code,group_id,summary,revision \
             FROM ops.alert WHERE id=$1 FOR SHARE",
        )
        .bind(message.aggregate_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(transaction_error)?
        .ok_or(StorageError::TransactionFailed)?;
        let alert_id: Uuid = alert.try_get("id").map_err(transaction_error)?;
        let fingerprint: String = alert.try_get("fingerprint").map_err(transaction_error)?;
        let severity: String = alert.try_get("severity_code").map_err(transaction_error)?;
        let alert_type: String = alert.try_get("type_code").map_err(transaction_error)?;
        let state: String = alert.try_get("state_code").map_err(transaction_error)?;
        let group_id: Option<Uuid> = alert.try_get("group_id").map_err(transaction_error)?;
        let current_revision: i64 = alert.try_get("revision").map_err(transaction_error)?;
        if current_revision < message.aggregate_revision
            || !matches!(severity.as_str(), "info" | "warning" | "critical")
            || (phase == "recovery" && state != "resolved")
        {
            return Err(StorageError::RevisionConflict);
        }
        let summary = message
            .payload
            .get("summary")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 4096)
            .map_or_else(
                || {
                    alert
                        .try_get::<String, _>("summary")
                        .unwrap_or_else(|_| "Gateway alert".to_owned())
                },
                str::to_owned,
            );
        let title = if phase == "recovery" {
            format!("Super Gateway 恢复：{alert_type}")
        } else {
            format!("Super Gateway 告警：{alert_type}")
        };
        let users = sqlx::query(
            "SELECT id FROM iam.user_account WHERE role_code='platform_admin' AND status_code='active' ORDER BY id",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        for user in users {
            let user_id: Uuid = user.try_get("id").map_err(transaction_error)?;
            sqlx::query(
                "INSERT INTO ops.notification_inbox \
                 (id,user_id,source_event_id,alert_id,severity_code,title,summary,created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp()) \
                 ON CONFLICT (user_id,source_event_id) WHERE source_event_id IS NOT NULL DO NOTHING",
            )
            .bind(Uuid::now_v7())
            .bind(user_id)
            .bind(message.event_id)
            .bind(alert_id)
            .bind(&severity)
            .bind(&title)
            .bind(&summary)
            .execute(&mut *transaction)
            .await
            .map_err(transaction_error)?;
        }
        let silenced = if phase == "alert" {
            let patterns = sqlx::query_scalar::<_, String>(
                "SELECT fingerprint_pattern FROM ops.alert_silence \
                 WHERE starts_at<=clock_timestamp() AND expires_at>clock_timestamp() ORDER BY id",
            )
            .fetch_all(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            patterns.iter().any(|pattern| alert_glob_matches(pattern, &fingerprint))
        } else {
            false
        };
        if !silenced && (phase == "recovery" || matches!(state.as_str(), "open" | "acknowledged" | "silenced")) {
            let destinations = sqlx::query(
                "SELECT id,revision,configuration FROM ops.notification_destination \
                 WHERE kind_code='serverchan3' AND state_code='active' ORDER BY id FOR SHARE",
            )
            .fetch_all(&mut *transaction)
            .await
            .map_err(transaction_error)?;
            for destination in destinations {
                let destination_id: Uuid = destination.try_get("id").map_err(transaction_error)?;
                let destination_revision: i64 = destination.try_get("revision").map_err(transaction_error)?;
                let configuration: serde_json::Value =
                    destination.try_get("configuration").map_err(transaction_error)?;
                if !notification_destination_matches(&configuration, &severity, &alert_type, group_id, phase) {
                    continue;
                }
                if phase == "recovery" {
                    let raised_delivered: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM ops.notification_delivery \
                         WHERE alert_id=$1 AND destination_id=$2 AND delivery_kind_code='alert' \
                           AND state_code='delivered')",
                    )
                    .bind(alert_id)
                    .bind(destination_id)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(transaction_error)?;
                    if !raised_delivered {
                        continue;
                    }
                }
                let delivery_id = Uuid::now_v7();
                let dedupe_key = format!("alert:{alert_id}:{phase}");
                let delivery_payload = json!({
                    "schema_version":1,"phase":phase,"title":title,"summary":summary,
                    "severity":severity,"alert_type":alert_type,"fingerprint":fingerprint,
                    "group_id":group_id,"tags":format!("super-gateway|{severity}|{phase}")
                });
                let inserted: Option<Uuid> = sqlx::query_scalar(
                    "INSERT INTO ops.notification_delivery \
                     (id,alert_id,destination_id,attempt_ordinal,state_code,created_at,delivery_kind_code, \
                      dedupe_key,payload,attempt_count,updated_at) \
                     VALUES ($1,$2,$3,1,'pending',clock_timestamp(),$4,$5,$6,0,clock_timestamp()) \
                     ON CONFLICT (destination_id,dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING RETURNING id",
                )
                .bind(delivery_id)
                .bind(alert_id)
                .bind(destination_id)
                .bind(phase)
                .bind(&dedupe_key)
                .bind(&delivery_payload)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(transaction_error)?;
                if inserted.is_none() {
                    continue;
                }
                let job_id = Uuid::now_v7();
                sqlx::query(
                    "INSERT INTO ops.durable_job \
                     (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after, \
                      lease_generation,attempt_count,max_attempts,created_at,updated_at) \
                     VALUES ($1,'notification_delivery_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,5,clock_timestamp(),clock_timestamp())",
                )
                .bind(job_id)
                .bind(format!("notification:{destination_id}:{dedupe_key}"))
                .bind(json!({
                    "delivery_id":delivery_id,"destination_id":destination_id,
                    "destination_revision":destination_revision
                }))
                .execute(&mut *transaction)
                .await
                .map_err(transaction_error)?;
                sqlx::query(
                    "INSERT INTO ops.durable_job_history \
                     (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
                     VALUES ($1,$2,NULL,'scheduled',0,'notification_scheduled',$3,clock_timestamp())",
                )
                .bind(Uuid::now_v7())
                .bind(job_id)
                .bind(json!({"delivery_id":delivery_id,"phase":phase}))
                .execute(&mut *transaction)
                .await
                .map_err(transaction_error)?;
            }
        }
        let published = sqlx::query(
            "UPDATE ops.outbox_message SET state_code='published',lease_owner=NULL,lease_expires_at=NULL, \
               published_at=clock_timestamp() WHERE id=$1 AND state_code='leased' AND lease_generation=$2",
        )
        .bind(message.message_id)
        .bind(message.generation)
        .execute(&mut *transaction)
        .await
        .map_err(transaction_error)?;
        if published.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        transaction.commit().await.map_err(transaction_error)
    }

    /// Read one ordered, restart-safe batch of business Secret DEKs still wrapped by an old key version.
    pub async fn load_secret_rewrap_batch(
        &self,
        old_key_version: i64,
        after_secret_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<SecretRewrapCandidate>, StorageError> {
        if limit < 1 {
            return Err(StorageError::TransactionFailed);
        }
        let rows = sqlx::query(
            "SELECT id,secret_kind_code,provider_role_code,owner_type_code,owner_id,purpose_code, \
                    aad_schema_version,key_version,wrapped_dek \
             FROM security.encrypted_secret \
             WHERE provider_role_code='business' AND key_version=$1 AND destroyed_at IS NULL \
               AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT $3",
        )
        .bind(old_key_version)
        .bind(after_secret_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        rows.into_iter()
            .map(|row| {
                let aad_schema_version: i32 = row
                    .try_get("aad_schema_version")
                    .map_err(|_| StorageError::TransactionFailed)?;
                Ok(SecretRewrapCandidate {
                    secret_id: row.try_get("id").map_err(|_| StorageError::TransactionFailed)?,
                    secret_kind: row
                        .try_get("secret_kind_code")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    provider_role: row
                        .try_get("provider_role_code")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    owner_type: row
                        .try_get("owner_type_code")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    owner_id: row.try_get("owner_id").map_err(|_| StorageError::TransactionFailed)?,
                    purpose: row
                        .try_get("purpose_code")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    aad_schema_version: u32::try_from(aad_schema_version)
                        .map_err(|_| StorageError::IntegrityViolation)?,
                    key_version: row
                        .try_get("key_version")
                        .map_err(|_| StorageError::TransactionFailed)?,
                    wrapped_dek: SecretBytes::new(
                        row.try_get("wrapped_dek")
                            .map_err(|_| StorageError::TransactionFailed)?,
                    ),
                })
            })
            .collect()
    }

    /// CAS-commit a rewrapped DEK; a concurrent winner is reported as a revision conflict.
    pub async fn commit_rewrapped_dek(
        &self,
        secret_id: Uuid,
        expected_key_version: i64,
        new_key_version: i64,
        wrapped_dek: &SecretBytes,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE security.encrypted_secret SET wrapped_dek=$3,key_version=$2 \
             WHERE id=$1 AND key_version=$4 AND provider_role_code='business' AND destroyed_at IS NULL",
        )
        .bind(secret_id)
        .bind(new_key_version)
        .bind(wrapped_dek.expose())
        .bind(expected_key_version)
        .execute(&self.pool)
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        Ok(())
    }

    async fn validate_role(&self, policy: RuntimeRolePolicy) -> Result<(), StorageError> {
        if policy != RuntimeRolePolicy::Enforce {
            return Ok(());
        }
        let role: String = sqlx::query_scalar("SELECT current_user")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| StorageError::ConnectionFailed)?;
        if role != "gateway_runtime" {
            return Err(StorageError::RuntimeRoleInvalid);
        }
        Ok(())
    }
}

async fn validate_embedded_migration_checksums(pool: &PgPool) -> Result<(), StorageError> {
    let applied = sqlx::query("SELECT version,checksum FROM _sqlx_migrations WHERE success ORDER BY version")
        .fetch_all(pool)
        .await
        .map_err(|_| StorageError::SchemaIncompatible)?;
    let embedded_count = MIGRATOR.iter().count();
    if applied.len() < embedded_count {
        return Err(StorageError::SchemaIncompatible);
    }
    for (row, expected) in applied.iter().take(embedded_count).zip(MIGRATOR.iter()) {
        let version: i64 = row.try_get("version").map_err(|_| StorageError::SchemaIncompatible)?;
        let checksum: Vec<u8> = row.try_get("checksum").map_err(|_| StorageError::SchemaIncompatible)?;
        if version != expected.version || checksum.as_slice() != expected.checksum.as_ref() {
            return Err(StorageError::SchemaIncompatible);
        }
    }
    for row in applied.iter().skip(embedded_count) {
        let version: i64 = row.try_get("version").map_err(|_| StorageError::SchemaIncompatible)?;
        if version <= CURRENT_SCHEMA_VERSION {
            return Err(StorageError::SchemaIncompatible);
        }
    }
    Ok(())
}

impl StorageHealth for PgStorage {
    fn state(&self) -> StorageState {
        match self.state.load(Ordering::Acquire) {
            1 => StorageState::Ready,
            2 => StorageState::Unavailable,
            _ => StorageState::Starting,
        }
    }
}

async fn read_migration_report(pool: &PgPool) -> Result<MigrationReport, StorageError> {
    let row = sqlx::query(
        "SELECT COALESCE(max(version) FILTER (WHERE success), 0) AS current_version, \
                count(*) FILTER (WHERE success) AS applied_count, \
                COALESCE(bool_and(success), false) AS all_success \
         FROM _sqlx_migrations",
    )
    .fetch_one(pool)
    .await
    .map_err(|_| StorageError::SchemaIncompatible)?;
    let all_success: bool = row
        .try_get("all_success")
        .map_err(|_| StorageError::SchemaIncompatible)?;
    if !all_success {
        return Err(StorageError::SchemaIncompatible);
    }
    Ok(MigrationReport {
        current_version: row
            .try_get("current_version")
            .map_err(|_| StorageError::SchemaIncompatible)?,
        applied_count: row
            .try_get("applied_count")
            .map_err(|_| StorageError::SchemaIncompatible)?,
    })
}

async fn insert_bootstrap_admin(
    transaction: &mut Transaction<'_, Postgres>,
    candidate: &BootstrapAdminRecord,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO iam.user_account \
         (id,username,username_normalized,display_name,email,email_normalized,role_code,status_code,password_credential_id,revision,created_at,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,'platform_admin','mfa_pending',$7,1,clock_timestamp(),clock_timestamp())",
    )
    .bind(candidate.user_id)
    .bind(&candidate.username)
    .bind(&candidate.username_normalized)
    .bind(&candidate.display_name)
    .bind(&candidate.email)
    .bind(&candidate.email_normalized)
    .bind(candidate.password_credential_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| StorageError::TransactionFailed)?;
    sqlx::query(
        "INSERT INTO iam.password_credential \
         (id,user_id,password_phc,parameters_version,created_at,last_changed_at,force_change) \
         VALUES ($1,$2,$3,1,clock_timestamp(),clock_timestamp(),true)",
    )
    .bind(candidate.password_credential_id)
    .bind(candidate.user_id)
    .bind(candidate.password_phc.expose())
    .execute(&mut **transaction)
    .await
    .map_err(|_| StorageError::TransactionFailed)?;
    Ok(())
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the function is passed directly to Result::map_err"
)]
fn alert_glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut previous = vec![false; value.len().saturating_add(1)];
    previous[0] = true;
    for token in pattern {
        let mut current = vec![false; value.len().saturating_add(1)];
        if *token == b'*' {
            current[0] = previous[0];
            for index in 1..=value.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=value.len() {
                current[index] = previous[index - 1] && value[index - 1] == *token;
            }
        }
        previous = current;
    }
    previous[value.len()]
}

fn notification_destination_matches(
    configuration: &serde_json::Value,
    severity: &str,
    alert_type: &str,
    group_id: Option<Uuid>,
    phase: &str,
) -> bool {
    let Some(configuration) = configuration.as_object() else {
        return false;
    };
    if configuration
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .and_then(|provider| provider.get("kind"))
        .and_then(serde_json::Value::as_str)
        != Some("serverchan3")
    {
        return false;
    }
    let Some(severities) = configuration.get("severities").and_then(serde_json::Value::as_array) else {
        return false;
    };
    if !severities.iter().any(|candidate| candidate.as_str() == Some(severity)) {
        return false;
    }
    let Some(alert_types) = configuration.get("alert_types").and_then(serde_json::Value::as_array) else {
        return false;
    };
    if !alert_types.is_empty()
        && !alert_types
            .iter()
            .any(|candidate| candidate.as_str() == Some(alert_type))
    {
        return false;
    }
    let Some(group_ids) = configuration.get("group_ids").and_then(serde_json::Value::as_array) else {
        return false;
    };
    if !group_ids.is_empty()
        && group_id.is_none_or(|group_id| {
            let group_id = group_id.to_string();
            !group_ids
                .iter()
                .any(|candidate| candidate.as_str() == Some(group_id.as_str()))
        })
    {
        return false;
    }
    phase != "recovery"
        || configuration
            .get("send_recovery")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
}

#[allow(clippy::needless_pass_by_value)]
fn transaction_error(error: sqlx::Error) -> StorageError {
    tracing::error!(error = %error, "sanitized PostgreSQL operation failed");
    StorageError::TransactionFailed
}

/// Generation-fenced durable job lease.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JobLease {
    /// Job identity.
    pub job_id: Uuid,
    /// Closed job kind code.
    pub kind: String,
    /// Versioned non-secret job payload.
    pub payload: serde_json::Value,
    /// Last durable restart checkpoint, when one was committed by the previous generation.
    pub checkpoint: Option<serde_json::Value>,
    /// Lease generation; stale workers must not commit with an older value.
    pub generation: i64,
    /// One-based execution attempt count after this claim.
    pub attempt: i32,
    /// Maximum execution attempts before the job is moved to dead letter.
    pub max_attempts: i32,
}

/// Generation-fenced Outbox delivery lease.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutboxLease {
    /// Outbox row identity.
    pub message_id: Uuid,
    /// Stable event identity used by consumers for idempotency.
    pub event_id: Uuid,
    /// Topic code.
    pub topic: String,
    /// Aggregate identity bound by the producer transaction.
    pub aggregate_id: Uuid,
    /// Aggregate revision bound by the producer transaction.
    pub aggregate_revision: i64,
    /// Payload schema version.
    pub payload_schema_version: i64,
    /// Redacted versioned payload.
    pub payload: serde_json::Value,
    /// Lease generation.
    pub generation: i64,
    /// One-based attempt count after this claim.
    pub attempt: i32,
}

/// Minimal encrypted-secret projection used by a resumable DEK rewrap job.
pub struct SecretRewrapCandidate {
    /// Secret identity and ordering checkpoint.
    pub secret_id: Uuid,
    /// Persisted secret kind.
    pub secret_kind: String,
    /// Provider purpose domain.
    pub provider_role: String,
    /// Aggregate owner type.
    pub owner_type: String,
    /// Aggregate owner identity.
    pub owner_id: String,
    /// Narrow use-site purpose.
    pub purpose: String,
    /// Payload/wrap AAD schema version.
    pub aad_schema_version: u32,
    /// Current wrapping key version.
    pub key_version: i64,
    /// Wrapped DEK bytes; formatting is redacted.
    pub wrapped_dek: SecretBytes,
}

impl std::fmt::Debug for SecretRewrapCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretRewrapCandidate")
            .field("secret_id", &self.secret_id)
            .field("key_version", &self.key_version)
            .field("wrapped_dek", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
