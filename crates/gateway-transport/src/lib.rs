#![forbid(unsafe_code)]
//! Process-local production transport boundary and verified Bundle runtime.

mod attempt;
mod bundle;
mod egress;
mod engine;
mod error;
mod event;
mod h1;
mod pool;
mod port;
#[cfg(feature = "boring-backend")]
mod production;
#[cfg(feature = "boring-backend")]
mod provider_http;
#[cfg(feature = "boring-backend")]
mod tls;

pub use attempt::{ConnectionAttemptMachine, ConnectionAttemptState};
pub use bundle::{
    ApplicationProfile, BundleCanonicalization, BundleConnectionPolicy, BundleEvidenceGate, BundleLifecycle,
    BundleLoadContext, BundleLoadError, BundleRuntimeState, BundleSignature, BundleTrustStore, EngineBuild,
    HeaderTemplate, Http1Profile, Http2Profile, SignedBundleEnvelope, TlsProfile, TransportBundlePayload, TrustKey,
    TrustKeyStatus, VerifiedBundle,
};
pub use egress::{AsyncIo, BoxedIo, EgressDialer};
pub use engine::{
    ActivationGeneration, CatalogActivation, CompiledApplicationProfile, CompiledTransportEngine, EngineCatalog,
    EngineCatalogHandle, EngineCompileError, EngineKey, PreparedCatalogActivation,
};
pub use error::{
    AttributionDomain, ConnectionDisposition, FailureScope, HealthEffect, RetrySafety, TransportError,
    TransportErrorCode, TransportPhase,
};
pub use event::{InMemoryEventSink, MonotonicEventSink, TransportEvent, TransportEventKind, TransportEventSink};
pub use h1::{H1Framing, ParsedResponseHead, encode_request, parse_response_head};
pub use pool::{ConnectionPoolCatalog, PoolEntry, PoolKey, PoolShardKey};
pub use port::{
    NoopTransportCore, RawResponseBody, RawUpstreamResponse, TransportAttempt, TransportCore, TransportCoreState,
};
#[cfg(feature = "boring-backend")]
pub use production::ProductionTransportCore;
#[cfg(feature = "boring-backend")]
pub use provider_http::{
    ProviderHttpsClient, ProviderHttpsHeader, ProviderHttpsRequest, ProviderHttpsResponse, ProviderHttpsTimeouts,
};
#[cfg(feature = "boring-backend")]
pub use tls::{BoringTlsConnector, TlsConnection, TlsObservation};
