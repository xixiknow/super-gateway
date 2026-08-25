//! Deterministic Bundle compiler and atomically published immutable Engine Catalog.

use std::{collections::BTreeMap, sync::Arc};

use arc_swap::ArcSwap;
use gateway_domain::{HttpProtocol, TransportBundleId};
use thiserror::Error;

use crate::{ApplicationProfile, HeaderTemplate, Http1Profile, Http2Profile, TlsProfile, VerifiedBundle};

/// Monotonic catalog publication generation. A→B→A always produces a new value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActivationGeneration(pub(crate) u64);

impl ActivationGeneration {
    /// Initial generation.
    pub const INITIAL: Self = Self(1);

    /// Numeric value for persistence/telemetry.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, EngineCompileError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(EngineCompileError::GenerationOverflow)
    }
}

/// Complete immutable engine cache key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EngineKey {
    /// Stable Bundle ID.
    pub bundle_id: TransportBundleId,
    /// Artifact version.
    pub bundle_version: u64,
    /// Canonical payload hash.
    pub bundle_hash: Box<str>,
    /// Semantic runtime ABI.
    pub engine_abi: Box<str>,
    /// Backend implementation ID.
    pub backend_id: Box<str>,
    /// Protocol selected by the discriminated Bundle.
    pub protocol: HttpProtocol,
}

/// Protocol-specific compiled controls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompiledApplicationProfile {
    /// Ordered HTTP/1.1 controls.
    H1(Http1Profile),
    /// HTTP/2 controls, activation-gated by evidence.
    H2(Http2Profile),
}

/// Immutable compiled logical transport engine.
#[derive(Clone, Debug)]
pub struct CompiledTransportEngine {
    /// Full engine identity.
    pub key: EngineKey,
    /// Source Archetype version.
    pub source_archetype_version_id: Box<str>,
    /// Evidence cohort.
    pub capture_cohort: Box<str>,
    /// Fixed authority.
    pub authority: Box<str>,
    /// TLS controls.
    pub tls: TlsProfile,
    /// Protocol controls.
    pub application: CompiledApplicationProfile,
    /// Ordered application header templates.
    pub headers: Arc<[HeaderTemplate]>,
    /// Evidence hashes bound by the signed payload.
    pub evidence_hashes: Arc<[Box<str>]>,
}

/// Deterministic compiler rejection.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EngineCompileError {
    /// Bundle ID cannot be represented by the bounded domain ID type.
    #[error("bundle id is invalid")]
    InvalidBundleId,
    /// Compiled profile failed a deterministic self-test.
    #[error("compiled engine self-test failed")]
    SelfTest,
    /// Catalog contains a duplicate `EngineKey`.
    #[error("engine catalog contains a duplicate key")]
    DuplicateKey,
    /// Empty catalogs are never published as ready.
    #[error("engine catalog is empty")]
    EmptyCatalog,
    /// Activation generation overflowed.
    #[error("engine activation generation overflow")]
    GenerationOverflow,
}

impl CompiledTransportEngine {
    /// Deterministically compile an already-verified Bundle.
    ///
    /// # Errors
    ///
    /// Returns [`EngineCompileError`] when the immutable engine fails its local self-test.
    pub fn compile(bundle: VerifiedBundle) -> Result<Self, EngineCompileError> {
        let bundle_id = TransportBundleId::new(bundle.payload.bundle_id.clone())
            .map_err(|_| EngineCompileError::InvalidBundleId)?;
        let (protocol, authority, tls, application, headers) = match bundle.payload.application {
            ApplicationProfile::H1 {
                authority, tls, http1, ..
            } => {
                let headers: Arc<[HeaderTemplate]> = http1.header_order.clone().into();
                (
                    HttpProtocol::H1,
                    authority,
                    tls,
                    CompiledApplicationProfile::H1(http1),
                    headers,
                )
            }
            ApplicationProfile::H2 {
                authority, tls, http2, ..
            } => {
                let headers: Arc<[HeaderTemplate]> = http2.header_order.clone().into();
                (
                    HttpProtocol::H2,
                    authority,
                    tls,
                    CompiledApplicationProfile::H2(http2),
                    headers,
                )
            }
        };
        let engine = Self {
            key: EngineKey {
                bundle_id,
                bundle_version: bundle.payload.artifact_version,
                bundle_hash: bundle.canonical_hash,
                engine_abi: bundle.payload.engine_abi_version,
                backend_id: bundle.payload.backend_id,
                protocol,
            },
            source_archetype_version_id: bundle.payload.source_archetype_version_id,
            capture_cohort: bundle.payload.capture_cohort,
            authority,
            tls,
            application,
            headers,
            evidence_hashes: bundle.payload.evidence_hashes.into(),
        };
        engine.self_test()?;
        Ok(engine)
    }

    fn self_test(&self) -> Result<(), EngineCompileError> {
        if self.authority.as_ref() != "api.anthropic.com"
            || self.key.bundle_version == 0
            || self.evidence_hashes.is_empty()
            || self.headers.iter().any(|header| {
                header.name.is_empty()
                    || header
                        .name
                        .as_bytes()
                        .iter()
                        .any(|byte| !byte.is_ascii() || matches!(byte, b'\r' | b'\n'))
                    || header.value_template.contains(['\r', '\n'])
            })
        {
            return Err(EngineCompileError::SelfTest);
        }
        Ok(())
    }
}

/// Immutable catalog held by every in-flight Attempt through an `Arc`.
#[derive(Clone, Debug)]
pub struct EngineCatalog {
    generation: ActivationGeneration,
    entries: BTreeMap<EngineKey, Arc<CompiledTransportEngine>>,
}

impl EngineCatalog {
    /// Build a complete catalog before publication.
    ///
    /// # Errors
    ///
    /// Rejects empty catalogs and duplicate keys.
    pub fn build(
        generation: ActivationGeneration,
        engines: impl IntoIterator<Item = CompiledTransportEngine>,
    ) -> Result<Self, EngineCompileError> {
        let mut entries = BTreeMap::new();
        for engine in engines {
            let key = engine.key.clone();
            if entries.insert(key, Arc::new(engine)).is_some() {
                return Err(EngineCompileError::DuplicateKey);
            }
        }
        if entries.is_empty() {
            return Err(EngineCompileError::EmptyCatalog);
        }
        Ok(Self { generation, entries })
    }

    /// Publication generation.
    #[must_use]
    pub fn generation(&self) -> ActivationGeneration {
        self.generation
    }

    /// Resolve one immutable engine.
    #[must_use]
    pub fn get(&self, key: &EngineKey) -> Option<Arc<CompiledTransportEngine>> {
        self.entries.get(key).cloned()
    }

    /// Resolve the exact active Bundle projection for one Archetype without
    /// allowing a caller to fall back to another OS/cohort.
    #[must_use]
    pub fn find_exact(
        &self,
        source_archetype_version_id: &str,
        bundle_id: &str,
        bundle_version: u64,
        bundle_hash: &str,
    ) -> Option<Arc<CompiledTransportEngine>> {
        self.entries.values().find_map(|engine| {
            (engine.source_archetype_version_id.as_ref() == source_archetype_version_id
                && engine.key.bundle_id.as_str() == bundle_id
                && engine.key.bundle_version == bundle_version
                && engine.key.bundle_hash.as_ref() == bundle_hash)
                .then(|| engine.clone())
        })
    }

    /// Number of engines.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the catalog has no engines.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether at least one compiled engine belongs to the stable Bundle ID.
    #[must_use]
    pub fn contains_bundle_id(&self, bundle_id: &str) -> bool {
        self.entries.keys().any(|key| key.bundle_id.as_str() == bundle_id)
    }
}

/// Facts returned after one atomic catalog publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogActivation {
    /// Previously visible generation.
    pub previous: ActivationGeneration,
    /// Newly visible generation.
    pub current: ActivationGeneration,
}

/// Fully built replacement catalog awaiting the commit-side publication fence.
#[derive(Debug)]
pub struct PreparedCatalogActivation {
    catalog: Arc<EngineCatalog>,
    activation: CatalogActivation,
}

/// Atomic catalog holder; in-flight callers retain the old snapshot.
#[derive(Debug)]
pub struct EngineCatalogHandle {
    current: ArcSwap<EngineCatalog>,
}

impl EngineCatalogHandle {
    /// Create a holder from a non-empty initial catalog.
    #[must_use]
    pub fn new(initial: EngineCatalog) -> Self {
        Self {
            current: ArcSwap::from_pointee(initial),
        }
    }

    /// Load one consistent immutable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<EngineCatalog> {
        self.current.load_full()
    }

    /// Build a replacement catalog without changing the visible snapshot.
    ///
    /// # Errors
    ///
    /// Leaves the current catalog untouched if compilation fails. Callers must
    /// serialize staging through publication so two prepared generations cannot
    /// be published out of order.
    pub fn stage(
        &self,
        engines: impl IntoIterator<Item = CompiledTransportEngine>,
    ) -> Result<PreparedCatalogActivation, EngineCompileError> {
        let previous_catalog = self.snapshot();
        let next_generation = previous_catalog.generation.next()?;
        let next = EngineCatalog::build(next_generation, engines)?;
        Ok(PreparedCatalogActivation {
            catalog: Arc::new(next),
            activation: CatalogActivation {
                previous: previous_catalog.generation,
                current: next_generation,
            },
        })
    }

    /// Publish a replacement whose complete validation happened before the
    /// surrounding durable activation committed. This operation is infallible.
    #[must_use]
    pub fn publish(&self, prepared: PreparedCatalogActivation) -> CatalogActivation {
        self.current.store(prepared.catalog);
        prepared.activation
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use gateway_domain::{HttpProtocol, TransportBundleId};

    use super::{
        ActivationGeneration, CompiledApplicationProfile, CompiledTransportEngine, EngineCatalog, EngineCatalogHandle,
        EngineKey,
    };
    use crate::{Http1Profile, TlsProfile};

    fn engine(hash: &str) -> CompiledTransportEngine {
        CompiledTransportEngine {
            key: EngineKey {
                bundle_id: TransportBundleId::new("bundle_1").expect("valid fixture bundle"),
                bundle_version: 1,
                bundle_hash: hash.into(),
                engine_abi: "1.0".into(),
                backend_id: "fixture".into(),
                protocol: HttpProtocol::H1,
            },
            source_archetype_version_id: "archetype_1".into(),
            capture_cohort: "fixture".into(),
            authority: "api.anthropic.com".into(),
            tls: TlsProfile {
                client_hello_profile: "fixture".into(),
                alpn: vec!["http/1.1".into()],
                cipher_suite_ids: Vec::new(),
                supported_group_ids: Vec::new(),
                key_share_group_ids: Vec::new(),
                extension_order: Vec::new(),
                grease_enabled: false,
                permute_extensions: false,
                session_resumption: false,
            },
            application: CompiledApplicationProfile::H1(Http1Profile {
                request_line_form: "origin".into(),
                header_order: Vec::new(),
                framing: "content-length".into(),
            }),
            headers: Arc::from([]),
            evidence_hashes: Arc::from([]),
        }
    }

    #[test]
    fn stage_is_invisible_until_publish_and_a_to_b_to_a_advances() {
        let handle = EngineCatalogHandle::new(
            EngineCatalog::build(ActivationGeneration::INITIAL, [engine("a")]).expect("initial catalog"),
        );
        let staged_b = handle.stage([engine("b")]).expect("stage b");
        assert_eq!(handle.snapshot().generation(), ActivationGeneration::INITIAL);
        assert!(
            handle
                .snapshot()
                .find_exact("archetype_1", "bundle_1", 1, "a")
                .is_some()
        );
        let activation_b = handle.publish(staged_b);
        assert_eq!(activation_b.current.get(), 2);
        assert!(
            handle
                .snapshot()
                .find_exact("archetype_1", "bundle_1", 1, "b")
                .is_some()
        );

        let staged_a = handle.stage([engine("a")]).expect("stage a again");
        let activation_a = handle.publish(staged_a);
        assert_eq!(activation_a.current.get(), 3);
        assert!(
            handle
                .snapshot()
                .find_exact("archetype_1", "bundle_1", 1, "a")
                .is_some()
        );
    }

    #[test]
    fn exact_lookup_includes_bundle_hash() {
        let catalog = EngineCatalog::build(ActivationGeneration::INITIAL, [engine("aaaaaaaa"), engine("bbbbbbbb")])
            .expect("catalog with distinct full keys");
        assert_eq!(
            catalog
                .find_exact("archetype_1", "bundle_1", 1, "bbbbbbbb")
                .expect("second hash")
                .key
                .bundle_hash
                .as_ref(),
            "bbbbbbbb"
        );
        assert!(catalog.find_exact("archetype_1", "bundle_1", 1, "missing").is_none());
    }
}
