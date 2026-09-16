#![forbid(unsafe_code)]
//! Axum protocol adapters for the data and management listeners.

mod data;
mod edge;
mod management;
mod probes;

pub use data::{
    AccessGrant, AccessResolver, AllowAllSpendAuthorizer, ClientOsSessionCache, DataPlaneState, DenyAllAccessResolver,
    DispatchEndpoint, DispatchError, DispatchRequest, EndpointPermission, InMemoryAccessResolver,
    ManagementRuntimeBridge, ManagementRuntimeSnapshot, MessageDispatcher, ModelCatalog, ModelRecord, RateLimit,
    SpendAuthorizer, SpendDecision, StaticModelCatalog, UnavailableDispatcher, UpstreamResponse,
    VersionedDigestAccessResolver,
};
pub use edge::{BusinessRateLimiter, KeyConcurrencyLimiter, TrustedProxyConfig, data_plane_router};
pub use management::{
    ManagementBackend, ManagementBackendError, ManagementBackendResponse, ManagementContractError, ManagementDownload,
    ManagementPrincipal, ManagementRequest, ManagementRole, ManagementState, UnavailableManagementBackend,
    management_router,
};
pub use probes::{ProbeRateLimit, ProbeRateLimiter, ProbeState};
