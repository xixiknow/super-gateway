//! Credential lifecycle, identity, egress, maintenance, and PLAN value objects.
#![allow(missing_docs, clippy::struct_excessive_bools)]

use std::{cmp::Ordering, time::Duration};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ArchetypeVersionId, CredentialId, DomainError, DomainResult, EgressBindingId, EnrollmentId, GroupId,
    MaintenanceOperationId, ProxyEndpointId, SecretId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AnthropicAccountUuid(Uuid);

impl AnthropicAccountUuid {
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> Uuid {
        self.0
    }
}

macro_rules! snake_enum {
    ($(#[$meta:meta])* $visibility:vis enum $name:ident { $($variant:ident),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        $visibility enum $name { $($variant),+ }
    };
}

snake_enum!(
    pub enum AuthKind {
        OauthSubscription,
        SetupTokenSubscription,
        ConsoleApiKey,
    }
);
snake_enum!(
    pub enum CredentialPurpose {
        Business,
        VerificationOnly,
        CountTokens,
    }
);
snake_enum!(
    pub enum CredentialLifecycle {
        PendingVerify,
        PendingProfile,
        PendingEgress,
        PendingReauthStrategy,
        Active,
        Disabled,
        Revoked,
        Archived,
    }
);
snake_enum!(
    pub enum AttachmentState {
        Attached,
        Draining,
        Detached,
        Attaching,
    }
);
snake_enum!(
    pub enum AuthState {
        Healthy,
        Expiring,
        Refreshing,
        ReauthRetrying,
        ReauthWaitingEgress,
        ManualRecoveryRequired,
        NeedsAdminReauth,
        AuthBroken,
    }
);
snake_enum!(
    pub enum CapacityState {
        Available,
        Limited,
        Cooldown,
        HalfOpen,
    }
);
snake_enum!(
    pub enum TransportState {
        Ready,
        TransportUnavailable,
    }
);
snake_enum!(
    pub enum ManagementClass {
        FullyManaged,
        NonManaged,
        PendingReauthStrategy,
        ManualRecoveryRequired,
    }
);
snake_enum!(
    pub enum EgressPolicy {
        Auto,
        ProxyRequired,
        Direct,
    }
);
snake_enum!(
    pub enum EgressMode {
        Direct,
        Proxy,
    }
);
snake_enum!(
    pub enum ProxyLifecycle {
        Active,
        Draining,
        Disabled,
        Archived,
    }
);
snake_enum!(
    pub enum ProxyHealth {
        Unknown,
        Probing,
        Healthy,
        UnhealthyDns,
        UnhealthyConnect,
        UnhealthyAuth,
        UnhealthyTunnel,
        UnhealthyTlsPassthrough,
    }
);
snake_enum!(
    pub enum ProxyStability {
        Static,
        Dynamic,
    }
);
snake_enum!(
    pub enum EnrollmentMode {
        Create,
        Recover,
    }
);
snake_enum!(
    pub enum EnrollmentAuthMethod {
        OauthPkce,
        SetupToken,
        ExistingOauth,
        BrowserSessionImport,
        ConsoleApiKey,
    }
);
snake_enum!(
    pub enum EnrollmentState {
        Created,
        ResolvingEgress,
        AwaitingUserAction,
        ExchangingMaterial,
        VerifyingAccount,
        Deduplicating,
        RecoveringExisting,
        ProvisioningIdentity,
        ConfiguringReauth,
        ActivationCheck,
        Succeeded,
        Failed,
        Cancelled,
        Expired,
    }
);
snake_enum!(
    pub enum EnrollmentNextAction {
        WaitForEgress,
        OpenAuthorizationUrl,
        SubmitSetupMaterial,
        SubmitExistingOauthMaterial,
        CompleteOauthCallback,
        CompleteBrowserLogin,
        Retry,
        ManualRecovery,
        None,
    }
);
snake_enum!(
    pub enum MaintenanceKind {
        Verify,
        Refresh,
        Reauthenticate,
        ManualRecovery,
        AuthMethodMigration,
        PlanCollect,
        BrowserHealth,
    }
);
snake_enum!(
    pub enum MaintenanceTrigger {
        Enrollment,
        Scheduled,
        ExpiryGuard,
        Upstream401,
        Admin,
        ManualRecovery,
        StrategyHealth,
    }
);
snake_enum!(
    pub enum ConflictClass {
        AuthMaterialWrite,
        PlanCollect,
        BrowserHealth,
    }
);
snake_enum!(
    pub enum MaintenanceState {
        Planned,
        Leased,
        Running,
        VerifyingAccount,
        Committing,
        WaitingBackoff,
        WaitingEgress,
        NeedsAttention,
        Succeeded,
        Failed,
        Cancelled,
        Expired,
    }
);
snake_enum!(
    pub enum BrowserStrategyState {
        Pending,
        Healthy,
        Degraded,
        Invalid,
        Disabled,
    }
);
snake_enum!(
    pub enum BrowserChallenge {
        Login,
        Otp,
        AccountChooser,
        Passkey,
        Totp,
        Sso,
    }
);
snake_enum!(
    pub enum PlanAdapter {
        OauthProfile,
        ClaudeCliBootstrap,
        NotApplicable,
    }
);
snake_enum!(
    pub enum PlanFreshness {
        Fresh,
        Stale,
        Unknown,
        NotApplicable,
    }
);
snake_enum!(
    pub enum ContinuityChange {
        Refresh,
        SameAccountRecovery,
        GroupMigration,
        Cohort,
        EgressRebind,
        DeviceRebuild,
    }
);
snake_enum!(
    pub enum CanonicalCredentialStatus {
        Archived,
        Revoked,
        Disabled,
        Pending,
        Draining,
        Detached,
        Attaching,
        ManualRecoveryRequired,
        NeedsAdminReauth,
        AuthBroken,
        Refreshing,
        ReauthRetrying,
        ReauthWaitingEgress,
        TransportUnavailable,
        Cooldown,
        HalfOpen,
        Limited,
        Active,
    }
);
snake_enum!(
    pub enum CredentialBlocker {
        Lifecycle,
        Attachment,
        Authentication,
        Management,
        Profile,
        Egress,
        Transport,
        Purpose,
    }
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochSet {
    pub revision: u64,
    pub token_version: u64,
    pub profile_epoch: u64,
    pub device_epoch: u64,
    pub egress_epoch: u64,
}

impl EpochSet {
    /// Apply one frozen continuity transition.
    ///
    /// # Errors
    ///
    /// Returns an invalid-value error when a version or epoch overflows.
    pub fn apply(&mut self, change: ContinuityChange) -> DomainResult<()> {
        match change {
            ContinuityChange::Refresh | ContinuityChange::SameAccountRecovery => {
                self.token_version = increment(self.token_version)?;
            }
            ContinuityChange::GroupMigration => {}
            ContinuityChange::Cohort => self.profile_epoch = increment(self.profile_epoch)?,
            ContinuityChange::EgressRebind => {
                self.profile_epoch = increment(self.profile_epoch)?;
                self.egress_epoch = increment(self.egress_epoch)?;
            }
            ContinuityChange::DeviceRebuild => {
                self.profile_epoch = increment(self.profile_epoch)?;
                self.device_epoch = increment(self.device_epoch)?;
            }
        }
        self.revision = increment(self.revision)?;
        Ok(())
    }
}

fn increment(value: u64) -> DomainResult<u64> {
    value.checked_add(1).ok_or(DomainError::InvalidValue)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialState {
    pub lifecycle: CredentialLifecycle,
    pub attachment: AttachmentState,
    pub auth: AuthState,
    pub capacity: CapacityState,
    pub transport: TransportState,
    pub management_class: ManagementClass,
    pub profile_ready: bool,
    pub egress_ready: bool,
    pub purpose_compatible: bool,
}

impl CredentialState {
    #[must_use]
    pub fn canonical_status(&self) -> CanonicalCredentialStatus {
        match self.lifecycle {
            CredentialLifecycle::Archived => return CanonicalCredentialStatus::Archived,
            CredentialLifecycle::Revoked => return CanonicalCredentialStatus::Revoked,
            CredentialLifecycle::Disabled => return CanonicalCredentialStatus::Disabled,
            CredentialLifecycle::PendingVerify
            | CredentialLifecycle::PendingProfile
            | CredentialLifecycle::PendingEgress
            | CredentialLifecycle::PendingReauthStrategy => return CanonicalCredentialStatus::Pending,
            CredentialLifecycle::Active => {}
        }
        match self.attachment {
            AttachmentState::Draining => return CanonicalCredentialStatus::Draining,
            AttachmentState::Detached => return CanonicalCredentialStatus::Detached,
            AttachmentState::Attaching => return CanonicalCredentialStatus::Attaching,
            AttachmentState::Attached => {}
        }
        match self.auth {
            AuthState::ManualRecoveryRequired => return CanonicalCredentialStatus::ManualRecoveryRequired,
            AuthState::NeedsAdminReauth => return CanonicalCredentialStatus::NeedsAdminReauth,
            AuthState::AuthBroken => return CanonicalCredentialStatus::AuthBroken,
            AuthState::Refreshing => return CanonicalCredentialStatus::Refreshing,
            AuthState::ReauthRetrying => return CanonicalCredentialStatus::ReauthRetrying,
            AuthState::ReauthWaitingEgress => return CanonicalCredentialStatus::ReauthWaitingEgress,
            AuthState::Healthy | AuthState::Expiring => {}
        }
        if self.transport == TransportState::TransportUnavailable || !self.egress_ready || !self.profile_ready {
            return CanonicalCredentialStatus::TransportUnavailable;
        }
        match self.capacity {
            CapacityState::Cooldown => CanonicalCredentialStatus::Cooldown,
            CapacityState::HalfOpen => CanonicalCredentialStatus::HalfOpen,
            CapacityState::Limited => CanonicalCredentialStatus::Limited,
            CapacityState::Available => CanonicalCredentialStatus::Active,
        }
    }

    #[must_use]
    pub fn blockers(&self) -> Vec<CredentialBlocker> {
        let mut result = Vec::new();
        if self.lifecycle != CredentialLifecycle::Active {
            result.push(CredentialBlocker::Lifecycle);
        }
        if self.attachment != AttachmentState::Attached {
            result.push(CredentialBlocker::Attachment);
        }
        if !matches!(self.auth, AuthState::Healthy | AuthState::Expiring) {
            result.push(CredentialBlocker::Authentication);
        }
        if matches!(
            self.management_class,
            ManagementClass::PendingReauthStrategy | ManagementClass::ManualRecoveryRequired
        ) {
            result.push(CredentialBlocker::Management);
        }
        if !self.profile_ready {
            result.push(CredentialBlocker::Profile);
        }
        if !self.egress_ready {
            result.push(CredentialBlocker::Egress);
        }
        if self.transport != TransportState::Ready {
            result.push(CredentialBlocker::Transport);
        }
        if !self.purpose_compatible {
            result.push(CredentialBlocker::Purpose);
        }
        result
    }

    #[must_use]
    pub fn is_schedulable(&self) -> bool {
        self.blockers().is_empty() && self.capacity != CapacityState::Cooldown
    }

    /// # Errors
    ///
    /// Returns an invalid-transition error while any activation blocker remains.
    pub fn activate(&mut self) -> DomainResult<()> {
        if !matches!(
            self.lifecycle,
            CredentialLifecycle::PendingVerify
                | CredentialLifecycle::PendingProfile
                | CredentialLifecycle::PendingEgress
                | CredentialLifecycle::PendingReauthStrategy
                | CredentialLifecycle::Disabled
        ) {
            return Err(DomainError::InvalidStateTransition);
        }
        let previous = self.lifecycle;
        self.lifecycle = CredentialLifecycle::Active;
        if !self.blockers().is_empty() {
            self.lifecycle = previous;
            return Err(DomainError::InvalidStateTransition);
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an invalid-transition error unless the Credential is active.
    pub fn disable(&mut self) -> DomainResult<()> {
        if self.lifecycle != CredentialLifecycle::Active {
            return Err(DomainError::InvalidStateTransition);
        }
        self.lifecycle = CredentialLifecycle::Disabled;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an invalid-transition error for an already revoked or archived Credential.
    pub fn revoke(&mut self) -> DomainResult<()> {
        if matches!(
            self.lifecycle,
            CredentialLifecycle::Revoked | CredentialLifecycle::Archived
        ) {
            return Err(DomainError::InvalidStateTransition);
        }
        self.lifecycle = CredentialLifecycle::Revoked;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an invalid-transition error unless the Credential is drained and archivable.
    pub fn archive(&mut self, active_leases: u32, active_operations: u32) -> DomainResult<()> {
        if !matches!(
            self.lifecycle,
            CredentialLifecycle::Disabled | CredentialLifecycle::Revoked
        ) || active_leases != 0
            || active_operations != 0
            || self.attachment == AttachmentState::Draining
        {
            return Err(DomainError::InvalidStateTransition);
        }
        self.lifecycle = CredentialLifecycle::Archived;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressBindingSnapshot {
    pub binding_id: EgressBindingId,
    pub mode: EgressMode,
    pub proxy_id: Option<ProxyEndpointId>,
    pub egress_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyCandidate {
    pub id: ProxyEndpointId,
    pub lifecycle: ProxyLifecycle,
    pub health: ProxyHealth,
    pub stability: ProxyStability,
    pub active_bindings: u32,
    pub max_active_bindings: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressDecision {
    Direct,
    Proxy(ProxyEndpointId),
    WaitForEgress,
}

#[must_use]
pub fn choose_egress(policy: EgressPolicy, proxies: &[ProxyCandidate]) -> EgressDecision {
    if policy == EgressPolicy::Direct {
        return EgressDecision::Direct;
    }
    let selected = proxies
        .iter()
        .filter(|proxy| {
            proxy.lifecycle == ProxyLifecycle::Active
                && proxy.health == ProxyHealth::Healthy
                && proxy.stability == ProxyStability::Static
                && proxy.active_bindings < proxy.max_active_bindings
                && proxy.max_active_bindings > 0
        })
        .min_by(|left, right| proxy_load_order(left, right));
    match selected {
        Some(proxy) => EgressDecision::Proxy(proxy.id.clone()),
        None if policy == EgressPolicy::Auto => EgressDecision::Direct,
        None => EgressDecision::WaitForEgress,
    }
}

fn proxy_load_order(left: &ProxyCandidate, right: &ProxyCandidate) -> Ordering {
    let left_cross = u64::from(left.active_bindings) * u64::from(right.max_active_bindings);
    let right_cross = u64::from(right.active_bindings) * u64::from(left.max_active_bindings);
    left_cross.cmp(&right_cross).then_with(|| left.id.cmp(&right.id))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchetypeCandidate {
    pub id: ArchetypeVersionId,
    pub compatible: bool,
    pub active: bool,
    pub bundle_active: bool,
    pub allocated_credentials: u32,
    pub max_credentials: u32,
    pub allocation_weight: u32,
}

#[must_use]
pub fn choose_archetype(candidates: &[ArchetypeCandidate], seed: u64) -> Option<ArchetypeVersionId> {
    let eligible: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            candidate.compatible
                && candidate.active
                && candidate.bundle_active
                && candidate.allocated_credentials < candidate.max_credentials
                && candidate.allocation_weight > 0
        })
        .collect();
    let total = eligible.iter().fold(0_u64, |sum, candidate| {
        sum.saturating_add(u64::from(candidate.allocation_weight))
    });
    if total == 0 {
        return None;
    }
    let mut point = seed % total;
    for candidate in eligible {
        let weight = u64::from(candidate.allocation_weight);
        if point < weight {
            return Some(candidate.id.clone());
        }
        point -= weight;
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub id: EnrollmentId,
    pub mode: EnrollmentMode,
    pub target_group_id: GroupId,
    pub auth_method: EnrollmentAuthMethod,
    pub pending_credential_id: Option<CredentialId>,
    pub recovery_credential_id: Option<CredentialId>,
    pub expected_credential_revision: Option<u64>,
    pub state: EnrollmentState,
    pub next_action: EnrollmentNextAction,
    pub egress_snapshot: Option<EgressBindingSnapshot>,
    pub identified_account_uuid: Option<AnthropicAccountUuid>,
    pub material_secret_refs: Vec<SecretId>,
    pub attempt_count: u32,
    pub expires_after: Duration,
    pub revision: u64,
}

impl Enrollment {
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            EnrollmentState::Succeeded
                | EnrollmentState::Failed
                | EnrollmentState::Cancelled
                | EnrollmentState::Expired
        )
    }

    /// # Errors
    ///
    /// Returns a terminal-state or invalid-transition error for an edge outside the frozen graph.
    pub fn transition(&mut self, state: EnrollmentState, next_action: EnrollmentNextAction) -> DomainResult<()> {
        if self.is_terminal() {
            return Err(DomainError::TerminalState);
        }
        if !valid_enrollment_transition(self.state, state, self.mode) {
            return Err(DomainError::InvalidStateTransition);
        }
        if matches!(
            state,
            EnrollmentState::Succeeded
                | EnrollmentState::Failed
                | EnrollmentState::Cancelled
                | EnrollmentState::Expired
        ) && next_action != EnrollmentNextAction::None
        {
            return Err(DomainError::InvalidStateTransition);
        }
        self.state = state;
        self.next_action = next_action;
        self.revision = increment(self.revision)?;
        Ok(())
    }
}

fn valid_enrollment_transition(from: EnrollmentState, to: EnrollmentState, mode: EnrollmentMode) -> bool {
    if matches!(
        to,
        EnrollmentState::Failed | EnrollmentState::Cancelled | EnrollmentState::Expired
    ) {
        return true;
    }
    matches!(
        (from, to),
        (EnrollmentState::Created, EnrollmentState::ResolvingEgress)
            | (EnrollmentState::ResolvingEgress, EnrollmentState::AwaitingUserAction)
            | (EnrollmentState::AwaitingUserAction, EnrollmentState::ExchangingMaterial)
            | (EnrollmentState::ExchangingMaterial, EnrollmentState::VerifyingAccount)
            | (EnrollmentState::VerifyingAccount, EnrollmentState::Deduplicating)
            | (EnrollmentState::Deduplicating, EnrollmentState::ProvisioningIdentity)
            | (
                EnrollmentState::ProvisioningIdentity,
                EnrollmentState::ConfiguringReauth
            )
            | (EnrollmentState::ConfiguringReauth, EnrollmentState::ActivationCheck)
            | (EnrollmentState::ActivationCheck, EnrollmentState::Succeeded)
    ) || (mode == EnrollmentMode::Recover
        && matches!(
            (from, to),
            (EnrollmentState::Deduplicating, EnrollmentState::RecoveringExisting)
                | (EnrollmentState::RecoveringExisting, EnrollmentState::ConfiguringReauth)
        ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollmentAction {
    Advance {
        state: EnrollmentState,
        next_action: EnrollmentNextAction,
    },
    Fail,
    Cancel,
    Expire,
}

#[derive(Debug)]
pub enum SubmittedAuthMaterial {
    OauthTokens {
        access: SecretId,
        refresh: Option<SecretId>,
        expires_after: Option<Duration>,
    },
    BrowserSessionImport {
        cookie_jar: SecretId,
        web_storage: Option<SecretId>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceOperation {
    pub id: MaintenanceOperationId,
    pub credential_id: CredentialId,
    pub kind: MaintenanceKind,
    pub trigger: MaintenanceTrigger,
    pub conflict_class: ConflictClass,
    pub state: MaintenanceState,
    pub expected_revision: u64,
    pub expected_token_version: u64,
    pub expected_egress: EgressBindingSnapshot,
    pub generation: u64,
    pub attempt_count: u32,
}

impl MaintenanceOperation {
    /// # Errors
    ///
    /// Returns a terminal-state or invalid-transition error for an edge outside the frozen graph.
    pub fn transition(&mut self, next: MaintenanceState) -> DomainResult<()> {
        if self.is_terminal() {
            return Err(DomainError::TerminalState);
        }
        if !valid_maintenance_transition(self.state, next) {
            return Err(DomainError::InvalidStateTransition);
        }
        self.state = next;
        Ok(())
    }

    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            MaintenanceState::Succeeded
                | MaintenanceState::Failed
                | MaintenanceState::Cancelled
                | MaintenanceState::Expired
        )
    }
}

fn valid_maintenance_transition(from: MaintenanceState, to: MaintenanceState) -> bool {
    if matches!(
        to,
        MaintenanceState::Failed | MaintenanceState::Cancelled | MaintenanceState::Expired
    ) {
        return true;
    }
    matches!(
        (from, to),
        (
            MaintenanceState::Planned
                | MaintenanceState::WaitingBackoff
                | MaintenanceState::WaitingEgress
                | MaintenanceState::NeedsAttention,
            MaintenanceState::Leased
        ) | (MaintenanceState::Leased, MaintenanceState::Running)
            | (
                MaintenanceState::Running,
                MaintenanceState::VerifyingAccount
                    | MaintenanceState::WaitingBackoff
                    | MaintenanceState::WaitingEgress
                    | MaintenanceState::NeedsAttention
            )
            | (
                MaintenanceState::VerifyingAccount,
                MaintenanceState::Committing | MaintenanceState::NeedsAttention
            )
            | (MaintenanceState::Committing, MaintenanceState::Succeeded)
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshPolicy {
    pub guard_ratio_basis_points: u16,
    pub minimum_guard: Duration,
    pub maximum_guard: Duration,
    pub maximum_jitter: Duration,
}

impl Default for RefreshPolicy {
    fn default() -> Self {
        Self {
            guard_ratio_basis_points: 1_000,
            minimum_guard: Duration::from_mins(5),
            maximum_guard: Duration::from_hours(4),
            maximum_jitter: Duration::from_secs(30),
        }
    }
}

impl RefreshPolicy {
    /// # Errors
    ///
    /// Returns an invalid-value error for invalid bounds, excessive jitter, or arithmetic overflow.
    pub fn refresh_after(self, lifetime: Duration, jitter: Duration) -> DomainResult<Duration> {
        if self.guard_ratio_basis_points > 10_000
            || self.minimum_guard > self.maximum_guard
            || jitter > self.maximum_jitter
        {
            return Err(DomainError::InvalidValue);
        }
        let ratio_guard = lifetime
            .checked_mul(u32::from(self.guard_ratio_basis_points))
            .ok_or(DomainError::InvalidValue)?
            / 10_000;
        let guard = ratio_guard.clamp(self.minimum_guard.min(lifetime), self.maximum_guard.min(lifetime));
        Ok(lifetime.saturating_sub(guard).saturating_add(jitter).min(lifetime))
    }
}

impl AuthKind {
    #[must_use]
    pub const fn plan_adapter(self) -> PlanAdapter {
        match self {
            Self::OauthSubscription => PlanAdapter::OauthProfile,
            Self::SetupTokenSubscription => PlanAdapter::ClaudeCliBootstrap,
            Self::ConsoleApiKey => PlanAdapter::NotApplicable,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    reason = "fixture construction converts impossible typed-ID failures into test failures"
)]
mod tests {
    use super::*;

    fn typed<T>(value: DomainResult<T>) -> T {
        value.unwrap_or_else(|error| std::panic::panic_any(error))
    }

    #[test]
    fn proxy_selection_is_ratio_then_stable_id() {
        let candidates = vec![
            ProxyCandidate {
                id: typed(ProxyEndpointId::new("proxy_b")),
                lifecycle: ProxyLifecycle::Active,
                health: ProxyHealth::Healthy,
                stability: ProxyStability::Static,
                active_bindings: 2,
                max_active_bindings: 5,
            },
            ProxyCandidate {
                id: typed(ProxyEndpointId::new("proxy_a")),
                lifecycle: ProxyLifecycle::Active,
                health: ProxyHealth::Healthy,
                stability: ProxyStability::Static,
                active_bindings: 1,
                max_active_bindings: 5,
            },
        ];
        assert_eq!(
            choose_egress(EgressPolicy::Auto, &candidates),
            EgressDecision::Proxy(typed(ProxyEndpointId::new("proxy_a")))
        );
    }

    #[test]
    fn proxy_required_waits_while_auto_has_stable_direct_fallback() {
        assert_eq!(
            choose_egress(EgressPolicy::ProxyRequired, &[]),
            EgressDecision::WaitForEgress
        );
        assert_eq!(choose_egress(EgressPolicy::Auto, &[]), EgressDecision::Direct);
    }

    #[test]
    fn dynamic_proxy_is_never_selected_for_fixed_egress() {
        let dynamic = ProxyCandidate {
            id: typed(ProxyEndpointId::new("dynamic_proxy")),
            lifecycle: ProxyLifecycle::Active,
            health: ProxyHealth::Healthy,
            stability: ProxyStability::Dynamic,
            active_bindings: 0,
            max_active_bindings: 5,
        };
        assert_eq!(
            choose_egress(EgressPolicy::Auto, std::slice::from_ref(&dynamic)),
            EgressDecision::Direct
        );
        assert_eq!(
            choose_egress(EgressPolicy::ProxyRequired, &[dynamic]),
            EgressDecision::WaitForEgress
        );
    }

    #[test]
    fn refresh_default_for_one_hour_is_fifty_four_minutes_without_jitter() {
        let result = RefreshPolicy::default().refresh_after(Duration::from_hours(1), Duration::ZERO);
        assert_eq!(result, Ok(Duration::from_mins(54)));
    }

    #[test]
    fn continuity_matrix_changes_only_contract_epochs() {
        let original = EpochSet {
            revision: 1,
            token_version: 1,
            profile_epoch: 1,
            device_epoch: 1,
            egress_epoch: 1,
        };
        let mut egress = original;
        assert!(egress.apply(ContinuityChange::EgressRebind).is_ok());
        assert_eq!(egress.profile_epoch, 2);
        assert_eq!(egress.device_epoch, 1);
        assert_eq!(egress.egress_epoch, 2);
        let mut cohort = original;
        assert!(cohort.apply(ContinuityChange::Cohort).is_ok());
        assert_eq!(cohort.profile_epoch, 2);
        assert_eq!(cohort.device_epoch, 1);
        assert_eq!(cohort.egress_epoch, 1);
    }

    #[test]
    fn terminal_enrollment_is_immutable() {
        let mut enrollment = Enrollment {
            id: typed(EnrollmentId::new("enrollment_1")),
            mode: EnrollmentMode::Create,
            target_group_id: typed(GroupId::new("group_1")),
            auth_method: EnrollmentAuthMethod::OauthPkce,
            pending_credential_id: None,
            recovery_credential_id: None,
            expected_credential_revision: None,
            state: EnrollmentState::Failed,
            next_action: EnrollmentNextAction::None,
            egress_snapshot: None,
            identified_account_uuid: None,
            material_secret_refs: Vec::new(),
            attempt_count: 0,
            expires_after: Duration::from_mins(30),
            revision: 2,
        };
        assert_eq!(
            enrollment.transition(EnrollmentState::Succeeded, EnrollmentNextAction::None),
            Err(DomainError::TerminalState)
        );
    }

    #[test]
    fn plan_adapter_never_falls_back_across_auth_kinds() {
        assert_eq!(AuthKind::OauthSubscription.plan_adapter(), PlanAdapter::OauthProfile);
        assert_eq!(
            AuthKind::SetupTokenSubscription.plan_adapter(),
            PlanAdapter::ClaudeCliBootstrap
        );
        assert_eq!(AuthKind::ConsoleApiKey.plan_adapter(), PlanAdapter::NotApplicable);
    }
}
