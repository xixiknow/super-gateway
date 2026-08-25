//! Credential enrollment and maintenance orchestration.
#![allow(missing_docs, clippy::missing_errors_doc, clippy::struct_excessive_bools)]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use gateway_domain::{
    AnthropicAccountUuid, AuthKind, BrowserChallenge, ConflictClass, CredentialId, EgressBindingSnapshot,
    MaintenanceTrigger, PlanAdapter, PlanFreshness, Portability, SecretId,
};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::{Mutex, Notify};

/// Credential service ABI version frozen by R5.
pub const ABI_VERSION: &str = "credential-service-r5-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthOperationSnapshot {
    pub credential_id: CredentialId,
    pub account_uuid: Option<AnthropicAccountUuid>,
    pub auth_kind: AuthKind,
    pub credential_revision: u64,
    pub token_version: u64,
    pub egress: EgressBindingSnapshot,
    pub operation_id: Box<str>,
    pub operation_generation: u64,
    pub joined_existing: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCandidate {
    pub access_secret_id: Option<SecretId>,
    pub refresh_secret_id: Option<SecretId>,
    pub console_secret_id: Option<SecretId>,
    pub verified_account_uuid: Option<AnthropicAccountUuid>,
    pub expires_after: Option<Duration>,
    pub adapter_code: Box<str>,
    pub adapter_version: Box<str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCommit {
    pub token_version: u64,
    pub credential_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthMaintenanceOutcome {
    pub operation_id: Box<str>,
    pub commit: AuthCommit,
    pub shared: bool,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CredentialServiceError {
    #[error("credential persistence conflict")]
    Conflict,
    #[error("credential egress temporarily unavailable")]
    WaitingEgress,
    #[error("credential maintenance rate limited")]
    RateLimited(Duration),
    #[error("credential maintenance transient failure")]
    Transient,
    #[error("credential authentication is invalid")]
    InvalidAuthentication,
    #[error("credential account identity mismatch")]
    AccountMismatch,
    #[error("credential requires administrator recovery")]
    ManualRecoveryRequired(BrowserChallenge),
    #[error("credential maintenance worker timed out")]
    WorkerTimeout,
    #[error("credential adapter evidence is not production active")]
    EvidencePending,
}

#[async_trait]
pub trait AuthMaintenanceRepository: Send + Sync + 'static {
    async fn begin_or_join(
        &self,
        credential_id: &CredentialId,
        trigger: MaintenanceTrigger,
    ) -> Result<AuthOperationSnapshot, CredentialServiceError>;

    async fn await_persisted_operation(
        &self,
        operation: &AuthOperationSnapshot,
    ) -> Result<AuthCommit, CredentialServiceError>;

    async fn commit_candidate(
        &self,
        operation: &AuthOperationSnapshot,
        candidate: &AuthCandidate,
    ) -> Result<AuthCommit, CredentialServiceError>;

    async fn mark_failure(
        &self,
        operation: &AuthOperationSnapshot,
        error: &CredentialServiceError,
    ) -> Result<(), CredentialServiceError>;
}

#[async_trait]
pub trait AuthMaintenanceAdapter: Send + Sync + 'static {
    async fn execute(&self, operation: &AuthOperationSnapshot) -> Result<AuthCandidate, CredentialServiceError>;
}

#[async_trait]
pub trait CredentialMaintainer: Send + Sync + 'static {
    async fn maintain(
        self: Arc<Self>,
        credential_id: CredentialId,
        trigger: MaintenanceTrigger,
    ) -> Result<AuthMaintenanceOutcome, CredentialServiceError>;
}

type FlightKey = (CredentialId, ConflictClass);
type SharedResult = Result<AuthMaintenanceOutcome, CredentialServiceError>;

#[derive(Debug, Default)]
struct Flight {
    result: Mutex<Option<SharedResult>>,
    notify: Notify,
}

impl Flight {
    async fn wait(&self) -> SharedResult {
        loop {
            let notified = self.notify.notified();
            if let Some(result) = self.result.lock().await.clone() {
                return result;
            }
            notified.await;
        }
    }

    async fn finish(&self, result: SharedResult) {
        *self.result.lock().await = Some(result);
        self.notify.notify_waiters();
    }
}

pub struct MaintenanceCoordinator<R, A> {
    repository: Arc<R>,
    adapter: Arc<A>,
    flights: Mutex<BTreeMap<FlightKey, Arc<Flight>>>,
    worker_timeout: Duration,
}

impl<R, A> std::fmt::Debug for MaintenanceCoordinator<R, A> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MaintenanceCoordinator")
            .field("worker_timeout", &self.worker_timeout)
            .finish_non_exhaustive()
    }
}

impl<R, A> MaintenanceCoordinator<R, A>
where
    R: AuthMaintenanceRepository,
    A: AuthMaintenanceAdapter,
{
    #[must_use]
    pub fn new(repository: Arc<R>, adapter: Arc<A>, worker_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            repository,
            adapter,
            flights: Mutex::new(BTreeMap::new()),
            worker_timeout,
        })
    }

    pub async fn maintain(self: &Arc<Self>, credential_id: CredentialId, trigger: MaintenanceTrigger) -> SharedResult {
        let key = (credential_id, ConflictClass::AuthMaterialWrite);
        let (flight, leader) = {
            let mut flights = self.flights.lock().await;
            if let Some(existing) = flights.get(&key) {
                (Arc::clone(existing), false)
            } else {
                let created = Arc::new(Flight::default());
                flights.insert(key.clone(), Arc::clone(&created));
                (created, true)
            }
        };
        if leader {
            let coordinator = Arc::clone(self);
            let worker_flight = Arc::clone(&flight);
            tokio::spawn(async move {
                let result =
                    tokio::time::timeout(coordinator.worker_timeout, coordinator.execute_worker(&key.0, trigger))
                        .await
                        .unwrap_or(Err(CredentialServiceError::WorkerTimeout));
                worker_flight.finish(result).await;
                let mut flights = coordinator.flights.lock().await;
                if flights
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &worker_flight))
                {
                    flights.remove(&key);
                }
            });
        }
        let mut result = flight.wait().await;
        if !leader && let Ok(outcome) = &mut result {
            outcome.shared = true;
        }
        result
    }

    async fn execute_worker(&self, credential_id: &CredentialId, trigger: MaintenanceTrigger) -> SharedResult {
        let operation = self.repository.begin_or_join(credential_id, trigger).await?;
        if operation.joined_existing {
            let commit = self.repository.await_persisted_operation(&operation).await?;
            return Ok(AuthMaintenanceOutcome {
                operation_id: operation.operation_id,
                commit,
                shared: true,
            });
        }
        let candidate = match self.adapter.execute(&operation).await {
            Ok(candidate) => candidate,
            Err(error) => {
                self.repository.mark_failure(&operation, &error).await?;
                return Err(error);
            }
        };
        if candidate.verified_account_uuid != operation.account_uuid
            && !(operation.auth_kind == AuthKind::ConsoleApiKey
                && candidate.verified_account_uuid.is_none()
                && operation.account_uuid.is_none())
        {
            let error = CredentialServiceError::AccountMismatch;
            self.repository.mark_failure(&operation, &error).await?;
            return Err(error);
        }
        let commit = self.repository.commit_candidate(&operation, &candidate).await?;
        Ok(AuthMaintenanceOutcome {
            operation_id: operation.operation_id,
            commit,
            shared: false,
        })
    }
}

#[async_trait]
impl<R, A> CredentialMaintainer for MaintenanceCoordinator<R, A>
where
    R: AuthMaintenanceRepository,
    A: AuthMaintenanceAdapter,
{
    async fn maintain(
        self: Arc<Self>,
        credential_id: CredentialId,
        trigger: MaintenanceTrigger,
    ) -> Result<AuthMaintenanceOutcome, CredentialServiceError> {
        MaintenanceCoordinator::maintain(&self, credential_id, trigger).await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayDecision {
    ReplaySameCredential,
    SwitchCredential,
    StopAuthenticationLoop,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BrowserContextKey {
    pub credential_id: CredentialId,
    pub strategy_id: Box<str>,
    pub egress_binding_id: gateway_domain::EgressBindingId,
    pub egress_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrowserAuthorizationResult {
    Authorized { account_uuid: AnthropicAccountUuid },
    Challenge(BrowserChallenge),
}

pub fn validate_browser_authorization(
    expected_account: AnthropicAccountUuid,
    result: &BrowserAuthorizationResult,
) -> Result<(), CredentialServiceError> {
    match result {
        BrowserAuthorizationResult::Authorized { account_uuid } if *account_uuid == expected_account => Ok(()),
        BrowserAuthorizationResult::Authorized { .. } => Err(CredentialServiceError::AccountMismatch),
        BrowserAuthorizationResult::Challenge(challenge) => {
            Err(CredentialServiceError::ManualRecoveryRequired(*challenge))
        }
    }
}

#[must_use]
pub fn decide_after_unauthorized(messages_attempt: u8, portability: &Portability) -> ReplayDecision {
    match messages_attempt {
        1 => ReplayDecision::ReplaySameCredential,
        2 if matches!(portability, Portability::Portable) => ReplayDecision::SwitchCredential,
        _ => ReplayDecision::StopAuthenticationLoop,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PlanProjection {
    pub adapter: PlanAdapter,
    pub freshness: PlanFreshness,
    pub normalized_plan: Box<str>,
    pub raw_redacted: Option<Value>,
    pub last_success_age: Option<Duration>,
    pub last_refresh_failed: bool,
    pub warning: Option<Box<str>>,
}

impl PlanProjection {
    #[must_use]
    pub fn not_applicable() -> Self {
        Self {
            adapter: PlanAdapter::NotApplicable,
            freshness: PlanFreshness::NotApplicable,
            normalized_plan: "api_payg".into(),
            raw_redacted: None,
            last_success_age: None,
            last_refresh_failed: false,
            warning: None,
        }
    }

    #[must_use]
    pub fn success(adapter: PlanAdapter, normalized_plan: impl Into<Box<str>>, raw_redacted: Value) -> Self {
        Self {
            adapter,
            freshness: PlanFreshness::Fresh,
            normalized_plan: normalized_plan.into(),
            raw_redacted: Some(raw_redacted),
            last_success_age: Some(Duration::ZERO),
            last_refresh_failed: false,
            warning: None,
        }
    }

    pub fn refresh_failed(&mut self, elapsed_since_success: Duration, category: impl Into<Box<str>>) {
        self.last_success_age = Some(elapsed_since_success);
        self.last_refresh_failed = true;
        self.warning = Some(category.into());
        self.freshness = if elapsed_since_success <= Duration::from_hours(48) {
            PlanFreshness::Fresh
        } else {
            PlanFreshness::Stale
        };
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulingIdentityProjection {
    pub credential_id: CredentialId,
    pub token_version: u64,
    pub profile_epoch: u64,
    pub egress_epoch: u64,
    pub plan_digest: Option<Box<str>>,
}

impl SchedulingIdentityProjection {
    #[must_use]
    pub fn routing_identity(&self) -> (&CredentialId, u64, u64, u64) {
        (
            &self.credential_id,
            self.token_version,
            self.profile_epoch,
            self.egress_epoch,
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    reason = "fixture construction converts impossible typed-ID failures into test failures"
)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use gateway_domain::{DomainResult, EgressMode};
    use tokio::sync::Barrier;

    use super::*;

    fn typed<T>(value: DomainResult<T>) -> T {
        value.unwrap_or_else(|error| std::panic::panic_any(error))
    }

    #[derive(Debug, Default)]
    struct FakeRepository {
        begins: AtomicUsize,
        commits: AtomicUsize,
    }

    #[async_trait]
    impl AuthMaintenanceRepository for FakeRepository {
        async fn begin_or_join(
            &self,
            credential_id: &CredentialId,
            _trigger: MaintenanceTrigger,
        ) -> Result<AuthOperationSnapshot, CredentialServiceError> {
            self.begins.fetch_add(1, Ordering::SeqCst);
            Ok(AuthOperationSnapshot {
                credential_id: credential_id.clone(),
                account_uuid: Some(AnthropicAccountUuid::new(uuid::Uuid::from_u128(1))),
                auth_kind: AuthKind::OauthSubscription,
                credential_revision: 7,
                token_version: 3,
                egress: EgressBindingSnapshot {
                    binding_id: typed(gateway_domain::EgressBindingId::new("egress_1")),
                    mode: EgressMode::Direct,
                    proxy_id: None,
                    egress_epoch: 1,
                },
                operation_id: "operation_1".into(),
                operation_generation: 1,
                joined_existing: false,
            })
        }

        async fn await_persisted_operation(
            &self,
            _operation: &AuthOperationSnapshot,
        ) -> Result<AuthCommit, CredentialServiceError> {
            Err(CredentialServiceError::Conflict)
        }

        async fn commit_candidate(
            &self,
            _operation: &AuthOperationSnapshot,
            _candidate: &AuthCandidate,
        ) -> Result<AuthCommit, CredentialServiceError> {
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(AuthCommit {
                token_version: 4,
                credential_revision: 8,
            })
        }

        async fn mark_failure(
            &self,
            _operation: &AuthOperationSnapshot,
            _error: &CredentialServiceError,
        ) -> Result<(), CredentialServiceError> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FakeAdapter {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl AuthMaintenanceAdapter for FakeAdapter {
        async fn execute(&self, _operation: &AuthOperationSnapshot) -> Result<AuthCandidate, CredentialServiceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(AuthCandidate {
                access_secret_id: Some(typed(SecretId::new("access_2"))),
                refresh_secret_id: Some(typed(SecretId::new("refresh_2"))),
                console_secret_id: None,
                verified_account_uuid: Some(AnthropicAccountUuid::new(uuid::Uuid::from_u128(1))),
                expires_after: Some(Duration::from_hours(1)),
                adapter_code: "oauth_refresh".into(),
                adapter_version: "fixture-v1".into(),
            })
        }
    }

    #[tokio::test]
    async fn twenty_simultaneous_unauthorized_requests_share_one_refresh() {
        let repository = Arc::new(FakeRepository::default());
        let adapter = Arc::new(FakeAdapter::default());
        let coordinator =
            MaintenanceCoordinator::new(Arc::clone(&repository), Arc::clone(&adapter), Duration::from_secs(2));
        let barrier = Arc::new(Barrier::new(20));
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let coordinator = Arc::clone(&coordinator);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                coordinator
                    .maintain(
                        typed(CredentialId::new("credential_1")),
                        MaintenanceTrigger::Upstream401,
                    )
                    .await
            }));
        }
        for task in tasks {
            let result = task.await;
            assert!(matches!(result, Ok(Ok(ref outcome)) if outcome.commit.token_version == 4));
        }
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
        assert_eq!(repository.begins.load(Ordering::SeqCst), 1);
        assert_eq!(repository.commits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unauthorized_replay_has_a_hard_three_attempt_fence() {
        assert_eq!(
            decide_after_unauthorized(1, &Portability::Portable),
            ReplayDecision::ReplaySameCredential
        );
        assert_eq!(
            decide_after_unauthorized(2, &Portability::Portable),
            ReplayDecision::SwitchCredential
        );
        assert_eq!(
            decide_after_unauthorized(
                2,
                &Portability::Pinned {
                    credential_id: None,
                    reasons: Vec::new(),
                }
            ),
            ReplayDecision::StopAuthenticationLoop
        );
        assert_eq!(
            decide_after_unauthorized(3, &Portability::Portable),
            ReplayDecision::StopAuthenticationLoop
        );
    }

    #[test]
    fn plan_failure_preserves_the_last_success_and_only_changes_display_state() {
        let mut projection =
            PlanProjection::success(PlanAdapter::OauthProfile, "max", serde_json::json!({"plan": "max"}));
        let before_plan = projection.normalized_plan.clone();
        projection.refresh_failed(Duration::from_hours(49), "upstream_schema_changed");
        assert_eq!(projection.normalized_plan, before_plan);
        assert_eq!(projection.freshness, PlanFreshness::Stale);
        assert!(projection.last_refresh_failed);
    }

    #[test]
    fn plan_is_excluded_from_the_routing_identity() {
        let mut projection = SchedulingIdentityProjection {
            credential_id: typed(CredentialId::new("credential_1")),
            token_version: 1,
            profile_epoch: 2,
            egress_epoch: 3,
            plan_digest: Some("plan_a".into()),
        };
        let before = projection.routing_identity();
        let before = (before.0.clone(), before.1, before.2, before.3);
        projection.plan_digest = Some("plan_b".into());
        assert_eq!(projection.routing_identity(), (&before.0, before.1, before.2, before.3));
    }

    #[test]
    fn browser_context_and_challenges_are_credential_scoped() {
        let expected = AnthropicAccountUuid::new(uuid::Uuid::from_u128(1));
        assert_eq!(
            validate_browser_authorization(expected, &BrowserAuthorizationResult::Challenge(BrowserChallenge::Otp)),
            Err(CredentialServiceError::ManualRecoveryRequired(BrowserChallenge::Otp))
        );
        assert_eq!(
            validate_browser_authorization(
                expected,
                &BrowserAuthorizationResult::Authorized {
                    account_uuid: AnthropicAccountUuid::new(uuid::Uuid::from_u128(2))
                }
            ),
            Err(CredentialServiceError::AccountMismatch)
        );
        let first = BrowserContextKey {
            credential_id: typed(CredentialId::new("credential_1")),
            strategy_id: "browser_1".into(),
            egress_binding_id: typed(gateway_domain::EgressBindingId::new("egress_1")),
            egress_epoch: 1,
        };
        let second = BrowserContextKey {
            credential_id: typed(CredentialId::new("credential_2")),
            strategy_id: "browser_2".into(),
            egress_binding_id: typed(gateway_domain::EgressBindingId::new("egress_2")),
            egress_epoch: 1,
        };
        assert_ne!(first, second);
    }
}
