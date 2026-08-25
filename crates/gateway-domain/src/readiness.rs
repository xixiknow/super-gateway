//! Internal readiness evaluation and privacy-safe public projection.

use serde::{Deserialize, Serialize};

/// Process lifecycle used by readiness and drain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationLifecycle {
    /// Configuration and dependencies are loading.
    #[default]
    Starting,
    /// The process can accept new data-plane traffic.
    Serving,
    /// New traffic is rejected while in-flight work drains.
    Draining,
    /// Final flush and process shutdown.
    ShuttingDown,
}

/// Stable internal readiness blocker codes. These never enter public probe bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessBlocker {
    /// Static configuration or secret references are incomplete.
    StaticConfiguration,
    /// `PostgreSQL` or the compatible migration range is unavailable.
    DatabaseOrSchema,
    /// Bootstrap is required for an empty database.
    Bootstrap,
    /// Business encryption key material is unavailable.
    BusinessKeyProvider,
    /// Audit integrity or deletion ledger startup verification failed.
    AuditIntegrity,
    /// Active immutable configuration is unavailable.
    ActiveConfiguration,
    /// Transport core is unavailable.
    TransportCore,
    /// A Bundle required by an active `Credential` is unavailable.
    RequiredBundle,
    /// Content audit key/store is required by an active full-encrypted scope.
    ContentAudit,
    /// The process lifecycle is not serving.
    Lifecycle,
}

/// Full internal readiness state used by the management plane and local diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "readiness deliberately preserves one independent flag per hard prerequisite"
)]
pub struct InternalReadiness {
    /// Application lifecycle.
    pub lifecycle: ApplicationLifecycle,
    /// Static configuration and required paths were validated.
    pub static_configuration_ready: bool,
    /// `PostgreSQL` and migration compatibility passed.
    pub database_schema_ready: bool,
    /// Empty-database bootstrap or existing-user detection completed.
    pub bootstrap_ready: bool,
    /// Business key provider is ready.
    pub business_key_provider_ready: bool,
    /// Startup audit chain and deletion ledger verification passed.
    pub audit_integrity_ready: bool,
    /// Required immutable active configuration is loaded.
    pub active_configuration_ready: bool,
    /// Transport core can create matching engines.
    pub transport_core_ready: bool,
    /// All Bundles referenced by active `Credentials` are available.
    pub required_bundles_ready: bool,
    /// Content audit dependencies are ready when a full-encrypted scope exists.
    pub content_audit_ready: bool,
}

impl Default for InternalReadiness {
    fn default() -> Self {
        Self {
            lifecycle: ApplicationLifecycle::Starting,
            static_configuration_ready: false,
            database_schema_ready: false,
            bootstrap_ready: false,
            business_key_provider_ready: false,
            audit_integrity_ready: false,
            active_configuration_ready: false,
            transport_core_ready: false,
            required_bundles_ready: false,
            content_audit_ready: true,
        }
    }
}

impl InternalReadiness {
    /// Return the privacy-safe public readiness state.
    #[must_use]
    pub fn public(&self) -> PublicReadiness {
        if self.blockers().is_empty() {
            PublicReadiness::Ready
        } else {
            PublicReadiness::NotReady
        }
    }

    /// Return stable blocker codes for the management plane and local logs.
    #[must_use]
    pub fn blockers(&self) -> Vec<ReadinessBlocker> {
        let mut blockers = Vec::with_capacity(10);
        if self.lifecycle != ApplicationLifecycle::Serving {
            blockers.push(ReadinessBlocker::Lifecycle);
        }
        for (ready, blocker) in [
            (self.static_configuration_ready, ReadinessBlocker::StaticConfiguration),
            (self.database_schema_ready, ReadinessBlocker::DatabaseOrSchema),
            (self.bootstrap_ready, ReadinessBlocker::Bootstrap),
            (self.business_key_provider_ready, ReadinessBlocker::BusinessKeyProvider),
            (self.audit_integrity_ready, ReadinessBlocker::AuditIntegrity),
            (self.active_configuration_ready, ReadinessBlocker::ActiveConfiguration),
            (self.transport_core_ready, ReadinessBlocker::TransportCore),
            (self.required_bundles_ready, ReadinessBlocker::RequiredBundle),
            (self.content_audit_ready, ReadinessBlocker::ContentAudit),
        ] {
            if !ready {
                blockers.push(blocker);
            }
        }
        blockers
    }
}

/// Public `/readyz` projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicReadiness {
    /// The instance can accept new data-plane traffic.
    Ready,
    /// The instance remains alive but is outside the serving contract.
    NotReady,
}

#[cfg(test)]
mod tests {
    use super::{ApplicationLifecycle, InternalReadiness, PublicReadiness};

    #[test]
    fn all_hard_prerequisites_are_required() {
        let mut state = InternalReadiness {
            lifecycle: ApplicationLifecycle::Serving,
            static_configuration_ready: true,
            database_schema_ready: true,
            bootstrap_ready: true,
            business_key_provider_ready: true,
            audit_integrity_ready: true,
            active_configuration_ready: true,
            transport_core_ready: true,
            required_bundles_ready: true,
            content_audit_ready: true,
        };
        assert_eq!(state.public(), PublicReadiness::Ready);
        state.database_schema_ready = false;
        assert_eq!(state.public(), PublicReadiness::NotReady);
    }

    #[test]
    fn public_projection_has_no_blockers() {
        let json = serde_json::to_string(&PublicReadiness::NotReady);
        assert!(json.is_ok());
        assert_eq!(json.ok().as_deref(), Some("\"not_ready\""));
    }
}
