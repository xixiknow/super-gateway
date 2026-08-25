#![forbid(unsafe_code)]
//! Application services shared by data, control and background paths.

pub mod content_audit;
pub mod credential;
pub mod credential_enrollment;
pub mod credential_enrollment_postgres;
pub mod credential_postgres;
pub mod credential_provider;
pub mod export;
pub mod model_discovery;
pub mod observability;
pub mod operations;
pub mod plan;
pub mod quota;
pub mod response;
pub mod scheduler;
pub mod security;
pub mod usage;

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use gateway_domain::{ApplicationLifecycle, InternalReadiness, PublicReadiness};

/// Thread-safe readiness coordinator. Internal details never enter public probe bodies.
#[derive(Clone, Debug, Default)]
pub struct ReadinessCoordinator {
    inner: Arc<RwLock<InternalReadiness>>,
}

impl ReadinessCoordinator {
    /// Create a coordinator from an initial full state.
    #[must_use]
    pub fn new(initial: InternalReadiness) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    /// Read the privacy-safe public projection.
    #[must_use]
    pub fn public(&self) -> PublicReadiness {
        self.read().public()
    }

    /// Return a snapshot for the authenticated management plane.
    #[must_use]
    pub fn internal_snapshot(&self) -> InternalReadiness {
        self.read().clone()
    }

    /// Apply an atomic update to the complete readiness state.
    pub fn update(&self, update: impl FnOnce(&mut InternalReadiness)) {
        update(&mut self.write());
    }

    /// Publish the serving lifecycle after every startup dependency and listener is ready.
    pub fn begin_serving(&self) {
        self.update(|state| state.lifecycle = ApplicationLifecycle::Serving);
    }

    /// Begin draining before listeners stop accepting new Messages.
    pub fn begin_drain(&self) {
        self.update(|state| state.lifecycle = ApplicationLifecycle::Draining);
    }

    /// Publish the final shutdown lifecycle after draining has completed.
    pub fn begin_shutdown(&self) {
        self.update(|state| state.lifecycle = ApplicationLifecycle::ShuttingDown);
    }

    fn read(&self) -> RwLockReadGuard<'_, InternalReadiness> {
        self.inner.read().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, InternalReadiness> {
        self.inner.write().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
