//! Exact nine-field Credential-isolated connection pool catalog.

use std::{collections::BTreeMap, sync::Mutex};

use gateway_domain::{CredentialId, EgressBindingId, HttpProtocol, TransportBundleId};

use crate::ActivationGeneration;

/// Semantic connection/session-cache isolation key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolKey {
    /// Credential owns the socket, H2 state and TLS ticket scope.
    pub credential_id: CredentialId,
    /// Profile/Archetype migration epoch.
    pub profile_epoch: u64,
    /// Stable Bundle identity.
    pub bundle_id: TransportBundleId,
    /// Bundle artifact version.
    pub bundle_version: u64,
    /// Fixed Egress Binding identity.
    pub egress_binding_id: EgressBindingId,
    /// Egress rebind epoch.
    pub egress_epoch: u64,
    /// Origin authority.
    pub authority: Box<str>,
    /// TLS server name.
    pub sni: Box<str>,
    /// Negotiated application protocol.
    pub protocol: HttpProtocol,
}

/// Actual shard key includes publication generation, preventing A→B→A reuse.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolShardKey {
    /// Nine semantic isolation fields.
    pub pool: PoolKey,
    /// Engine activation generation.
    pub activation_generation: ActivationGeneration,
}

/// One connection-like resource eligible for an exact shard.
#[derive(Debug)]
pub struct PoolEntry<T> {
    /// Opaque protocol connection/resource.
    pub resource: T,
    /// Generation in which it was created.
    pub activation_generation: ActivationGeneration,
}

/// Small process-local pool catalog. Protocol engines own resource close/drain semantics.
#[derive(Debug, Default)]
pub struct ConnectionPoolCatalog<T> {
    state: Mutex<PoolState<T>>,
}

#[derive(Debug, Default)]
struct PoolState<T> {
    shards: BTreeMap<PoolShardKey, Vec<PoolEntry<T>>>,
    minimum_profile_epochs: BTreeMap<CredentialId, u64>,
    retired_through: Option<ActivationGeneration>,
}

impl<T> ConnectionPoolCatalog<T> {
    /// Create an empty pool catalog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(PoolState {
                shards: BTreeMap::new(),
                minimum_profile_epochs: BTreeMap::new(),
                retired_through: None,
            }),
        }
    }

    /// Return a resource only to its exact `PoolKey` and activation generation.
    ///
    /// Poisoned internal state fails closed and returns the entry to the caller for disposal.
    ///
    /// # Errors
    ///
    /// Returns the original entry when the generation differs or internal state is poisoned.
    pub fn checkin(&self, key: PoolShardKey, entry: PoolEntry<T>) -> Result<(), PoolEntry<T>> {
        if entry.activation_generation != key.activation_generation {
            return Err(entry);
        }
        let Ok(mut state) = self.state.lock() else {
            return Err(entry);
        };
        if state
            .retired_through
            .is_some_and(|retired| key.activation_generation <= retired)
        {
            return Err(entry);
        }
        if state
            .minimum_profile_epochs
            .get(&key.pool.credential_id)
            .is_some_and(|minimum| key.pool.profile_epoch < *minimum)
        {
            return Err(entry);
        }
        state.shards.entry(key).or_default().push(entry);
        Ok(())
    }

    /// Borrow one resource from the exact shard only.
    #[must_use]
    pub fn checkout(&self, key: &PoolShardKey) -> Option<PoolEntry<T>> {
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        let entry = state.shards.get_mut(key).and_then(Vec::pop);
        if state.shards.get(key).is_some_and(Vec::is_empty) {
            state.shards.remove(key);
        }
        entry
    }

    /// Remove a single exact shard before protocol resources are closed/drained.
    #[must_use]
    pub fn drain_key(&self, key: &PoolShardKey) -> Vec<PoolEntry<T>> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        state.shards.remove(key).unwrap_or_default()
    }

    /// Retire a generation and all older generations. Late check-ins at or
    /// below the watermark are rejected after this call.
    #[must_use]
    pub fn drain_generation(&self, generation: ActivationGeneration) -> Vec<PoolEntry<T>> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        state.retired_through = Some(
            state
                .retired_through
                .map_or(generation, |retired| retired.max(generation)),
        );
        let retired = state.retired_through.unwrap_or(generation);
        let keys: Vec<_> = state
            .shards
            .keys()
            .filter(|key| key.activation_generation <= retired)
            .cloned()
            .collect();
        let mut drained = Vec::new();
        for key in keys {
            if let Some(mut entries) = state.shards.remove(&key) {
                drained.append(&mut entries);
            }
        }
        drained
    }

    /// Advance the minimum reusable Profile epoch for one Credential and
    /// atomically drain all older shards. A connection checked in after this
    /// call is rejected when it belongs to an obsolete epoch.
    #[must_use]
    pub fn advance_credential_profile_epoch(
        &self,
        credential_id: &CredentialId,
        minimum_profile_epoch: u64,
    ) -> Vec<PoolEntry<T>> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        let minimum = state
            .minimum_profile_epochs
            .entry(credential_id.clone())
            .or_insert(minimum_profile_epoch);
        *minimum = (*minimum).max(minimum_profile_epoch);
        let floor = *minimum;
        let keys = state
            .shards
            .keys()
            .filter(|key| key.pool.credential_id == *credential_id && key.pool.profile_epoch < floor)
            .cloned()
            .collect::<Vec<_>>();
        let mut drained = Vec::new();
        for key in keys {
            if let Some(mut entries) = state.shards.remove(&key) {
                drained.append(&mut entries);
            }
        }
        drained
    }

    /// Current pooled resource count, or zero after mutex poison.
    #[must_use]
    pub fn resource_count(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.shards.values().map(Vec::len).sum())
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use gateway_domain::{CredentialId, EgressBindingId, HttpProtocol, TransportBundleId};

    use super::{ConnectionPoolCatalog, PoolEntry, PoolKey, PoolShardKey};
    use crate::ActivationGeneration;

    fn id<T>(value: Result<T, gateway_domain::DomainError>) -> T {
        match value {
            Ok(value) => value,
            Err(error) => std::panic::panic_any(error),
        }
    }

    fn key() -> PoolKey {
        PoolKey {
            credential_id: id(CredentialId::new("credential_1")),
            profile_epoch: 1,
            bundle_id: id(TransportBundleId::new("bundle_1")),
            bundle_version: 1,
            egress_binding_id: id(EgressBindingId::new("egress_1")),
            egress_epoch: 1,
            authority: "api.anthropic.com".into(),
            sni: "api.anthropic.com".into(),
            protocol: HttpProtocol::H1,
        }
    }

    #[test]
    fn every_pool_field_and_generation_isolated() {
        let original = key();
        let mut variants = Vec::new();
        let mut value = original.clone();
        value.credential_id = id(CredentialId::new("credential_2"));
        variants.push(value);
        let mut value = original.clone();
        value.profile_epoch += 1;
        variants.push(value);
        let mut value = original.clone();
        value.bundle_id = id(TransportBundleId::new("bundle_2"));
        variants.push(value);
        let mut value = original.clone();
        value.bundle_version += 1;
        variants.push(value);
        let mut value = original.clone();
        value.egress_binding_id = id(EgressBindingId::new("egress_2"));
        variants.push(value);
        let mut value = original.clone();
        value.egress_epoch += 1;
        variants.push(value);
        let mut value = original.clone();
        value.authority = "other.anthropic.com".into();
        variants.push(value);
        let mut value = original.clone();
        value.sni = "other.anthropic.com".into();
        variants.push(value);
        let mut value = original.clone();
        value.protocol = HttpProtocol::H2;
        variants.push(value);

        let pools = ConnectionPoolCatalog::new();
        let shard = PoolShardKey {
            pool: original,
            activation_generation: ActivationGeneration::INITIAL,
        };
        assert!(
            pools
                .checkin(
                    shard.clone(),
                    PoolEntry {
                        resource: 7_u8,
                        activation_generation: ActivationGeneration::INITIAL
                    }
                )
                .is_ok()
        );
        for variant in variants {
            assert!(
                pools
                    .checkout(&PoolShardKey {
                        pool: variant,
                        activation_generation: ActivationGeneration::INITIAL
                    })
                    .is_none()
            );
        }
        assert!(
            pools
                .checkout(&PoolShardKey {
                    pool: shard.pool.clone(),
                    activation_generation: ActivationGeneration(2)
                })
                .is_none()
        );
        assert_eq!(pools.checkout(&shard).map(|entry| entry.resource), Some(7));
    }

    #[test]
    fn profile_epoch_floor_drains_and_rejects_late_checkin() {
        let pools = ConnectionPoolCatalog::new();
        let old_key = PoolShardKey {
            pool: key(),
            activation_generation: ActivationGeneration::INITIAL,
        };
        let credential_id = old_key.pool.credential_id.clone();
        assert!(
            pools
                .checkin(
                    old_key.clone(),
                    PoolEntry {
                        resource: 1_u8,
                        activation_generation: ActivationGeneration::INITIAL,
                    },
                )
                .is_ok()
        );
        assert_eq!(pools.advance_credential_profile_epoch(&credential_id, 2).len(), 1);
        assert!(
            pools
                .checkin(
                    old_key,
                    PoolEntry {
                        resource: 2_u8,
                        activation_generation: ActivationGeneration::INITIAL,
                    },
                )
                .is_err()
        );
        let mut new_pool = key();
        new_pool.profile_epoch = 2;
        assert!(
            pools
                .checkin(
                    PoolShardKey {
                        pool: new_pool,
                        activation_generation: ActivationGeneration::INITIAL,
                    },
                    PoolEntry {
                        resource: 3_u8,
                        activation_generation: ActivationGeneration::INITIAL,
                    },
                )
                .is_ok()
        );
        assert_eq!(pools.resource_count(), 1);
    }

    #[test]
    fn generation_watermark_drains_old_idle_and_rejects_late_checkin() {
        let pools = ConnectionPoolCatalog::new();
        let old_key = PoolShardKey {
            pool: key(),
            activation_generation: ActivationGeneration::INITIAL,
        };
        assert!(
            pools
                .checkin(
                    old_key.clone(),
                    PoolEntry {
                        resource: 1_u8,
                        activation_generation: ActivationGeneration::INITIAL,
                    },
                )
                .is_ok()
        );
        assert_eq!(pools.drain_generation(ActivationGeneration::INITIAL).len(), 1);
        assert!(
            pools
                .checkin(
                    old_key,
                    PoolEntry {
                        resource: 2_u8,
                        activation_generation: ActivationGeneration::INITIAL,
                    },
                )
                .is_err()
        );
        let current_key = PoolShardKey {
            pool: key(),
            activation_generation: ActivationGeneration(2),
        };
        assert!(
            pools
                .checkin(
                    current_key,
                    PoolEntry {
                        resource: 3_u8,
                        activation_generation: ActivationGeneration(2),
                    },
                )
                .is_ok()
        );
        assert_eq!(pools.resource_count(), 1);
    }
}
