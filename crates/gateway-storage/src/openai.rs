//! Version-fenced `OpenAI` credential maintenance persistence.

use crate::{PgStorage, StorageError};
use sqlx::Row as _;
use uuid::Uuid;

/// Successful refresh inputs contain encrypted secret references only.
#[derive(Debug)]
pub struct OpenAiRefreshCommit {
    /// Account whose refresh is being completed.
    pub account_id: Uuid,
    /// Frozen token version before the network call.
    pub expected_token_version: i64,
    /// Verified workspace identity from the provider.
    pub verified_identity: String,
    /// Newly persisted encrypted access token.
    pub access_secret_id: Uuid,
    /// Omitted when the provider did not rotate the refresh token.
    pub refresh_secret_id: Option<Uuid>,
    /// Newly persisted encrypted ID token, when supplied.
    pub id_token_secret_id: Option<Uuid>,
    /// Token expiry as Unix seconds.
    pub expires_at: Option<i64>,
}

impl PgStorage {
    /// Claim a single account refresh before doing network I/O.
    ///
    /// # Errors
    /// Returns a revision conflict for concurrent refresh or non-refreshable material.
    pub async fn claim_openai_refresh(&self, id: Uuid, expected_version: i64) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE gateway.openai_account SET auth_state_code='refreshing',updated_at=clock_timestamp() \
             WHERE id=$1 AND token_version=$2 AND auth_kind_code='oauth' AND refresh_secret_id IS NOT NULL \
             AND auth_state_code IN ('healthy','manual_update')",
        )
        .bind(id)
        .bind(expected_version)
        .execute(&self.pool())
        .await
        .map_err(|_| StorageError::TransactionFailed)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        Ok(())
    }

    /// Commit a refresh using both token-version and workspace-identity fences.
    /// Secret insertion and this update can share the caller's transaction.
    ///
    /// # Errors
    /// Returns a conflict for stale work and an identity mismatch for a changed account.
    pub async fn commit_openai_refresh_in(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        command: &OpenAiRefreshCommit,
    ) -> Result<(), StorageError> {
        let row = sqlx::query(
            "SELECT account_id,token_version,auth_state_code FROM gateway.openai_account WHERE id=$1 FOR UPDATE",
        )
        .bind(command.account_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| StorageError::TransactionFailed)?
        .ok_or(StorageError::RevisionConflict)?;
        if row
            .try_get::<String, _>("account_id")
            .map_err(|_| StorageError::TransactionFailed)?
            != command.verified_identity
        {
            return Err(StorageError::AccountMismatch);
        }
        if row
            .try_get::<i64, _>("token_version")
            .map_err(|_| StorageError::TransactionFailed)?
            != command.expected_token_version
            || row
                .try_get::<String, _>("auth_state_code")
                .map_err(|_| StorageError::TransactionFailed)?
                != "refreshing"
        {
            return Err(StorageError::RevisionConflict);
        }
        sqlx::query(
            "UPDATE gateway.openai_account SET access_secret_id=$2,refresh_secret_id=COALESCE($3,refresh_secret_id), \
             id_token_secret_id=COALESCE($4,id_token_secret_id),expires_at=to_timestamp($5::bigint::double precision), \
             token_version=token_version+1,revision=revision+1,auth_state_code='healthy',cooldown_until=NULL,updated_at=clock_timestamp() WHERE id=$1",
        ).bind(command.account_id).bind(command.access_secret_id).bind(command.refresh_secret_id)
            .bind(command.id_token_secret_id).bind(command.expires_at)
            .execute(&mut **transaction).await.map_err(|_| StorageError::TransactionFailed)?;
        Ok(())
    }

    /// Release failed refresh claims without accepting stale worker results.
    ///
    /// # Errors
    /// Returns a conflict if another operation already replaced the credentials.
    pub async fn fail_openai_refresh(&self, id: Uuid, version: i64, permanent: bool) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE gateway.openai_account SET auth_state_code=CASE WHEN $3 THEN 'needs_reauth' ELSE 'healthy' END, \
             cooldown_until=CASE WHEN $3 THEN NULL ELSE clock_timestamp()+interval '30 seconds' END, \
             revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 AND token_version=$2 AND auth_state_code='refreshing'",
        ).bind(id).bind(version).bind(permanent).execute(&self.pool()).await.map_err(|_| StorageError::TransactionFailed)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::RevisionConflict);
        }
        Ok(())
    }
}
