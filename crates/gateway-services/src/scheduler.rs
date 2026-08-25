//! Process-local supervision for single-owner Group scheduler actors.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use gateway_domain::GroupId;
use gateway_scheduler::{GroupExecutor, GroupExecutorHandle, OwnerGeneration, SchedulerEngine};
use tokio::task::JoinHandle;

/// Owns the process-local set of Group actors; database owner generations remain authoritative.
#[derive(Clone, Debug, Default)]
pub struct SchedulerSupervisor {
    handles: Arc<RwLock<BTreeMap<GroupId, GroupExecutorHandle>>>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl SchedulerSupervisor {
    /// Spawn and publish one Group actor. Existing Group IDs are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::DuplicateGroup`] when this process already owns the Group runtime.
    pub fn register(&self, group_id: GroupId, engine: SchedulerEngine) -> Result<GroupExecutorHandle, SupervisorError> {
        let mut handles = write(&self.handles);
        if handles.contains_key(&group_id) {
            return Err(SupervisorError::DuplicateGroup);
        }
        let executor = GroupExecutor::spawn(engine, 1_024);
        let handle = executor.handle.clone();
        handles.insert(group_id, handle.clone());
        lock(&self.tasks).push(executor.task);
        Ok(handle)
    }

    /// Return the current owner actor for a Group.
    #[must_use]
    pub fn handle(&self, group_id: &GroupId) -> Option<GroupExecutorHandle> {
        read(&self.handles).get(group_id).cloned()
    }

    /// Remove a stopped Group actor from the process-local registry so a
    /// later owner generation can be registered after Group reactivation.
    #[must_use]
    pub fn unregister(&self, group_id: &GroupId) -> Option<GroupExecutorHandle> {
        write(&self.handles).remove(group_id)
    }

    /// Fence new admissions on every registered Group and return all queued resolutions.
    pub async fn begin_drain(
        &self,
        generations: &BTreeMap<GroupId, OwnerGeneration>,
        now: Duration,
    ) -> Vec<gateway_scheduler::QueueResolution> {
        let actors = read(&self.handles)
            .iter()
            .filter_map(|(group_id, handle)| {
                generations
                    .get(group_id)
                    .map(|generation| (handle.clone(), *generation))
            })
            .collect::<Vec<_>>();
        let mut resolutions = Vec::new();
        for (handle, generation) in actors {
            if let Ok(mut group_resolutions) = handle.begin_drain(generation, now).await {
                resolutions.append(&mut group_resolutions);
            }
        }
        resolutions
    }

    /// Number of published Group owners.
    #[must_use]
    pub fn group_count(&self) -> usize {
        read(&self.handles).len()
    }
}

/// Supervisor registration failure.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum SupervisorError {
    /// A Group already has a process-local owner actor.
    #[error("group scheduler is already registered")]
    DuplicateGroup,
}

fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use gateway_domain::GroupId;
    use gateway_scheduler::{ExecutorIdentity, GroupConfig, OwnerGeneration, SchedulerEngine};

    use super::{SchedulerSupervisor, SupervisorError};

    fn engine(group_id: GroupId, generation: u64) -> Result<SchedulerEngine, Box<dyn std::error::Error>> {
        let generation = OwnerGeneration::new(generation)?;
        Ok(SchedulerEngine::new(
            ExecutorIdentity {
                group_id,
                owner_partition: "test".into(),
                executor_id: "executor_test".into(),
                generation,
            },
            GroupConfig::default(),
            Vec::new(),
            Duration::ZERO,
        )?)
    }

    #[tokio::test]
    async fn stopped_group_can_be_unregistered_and_reactivated_with_a_new_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let supervisor = SchedulerSupervisor::default();
        let group_id = GroupId::new("group_dynamic")?;
        let first = supervisor.register(group_id.clone(), engine(group_id.clone(), 1)?)?;
        assert_eq!(supervisor.group_count(), 1);
        assert!(matches!(
            supervisor.register(group_id.clone(), engine(group_id.clone(), 2)?),
            Err(SupervisorError::DuplicateGroup)
        ));
        drop(first);
        assert!(supervisor.unregister(&group_id).is_some());
        assert_eq!(supervisor.group_count(), 0);
        let second = supervisor.register(group_id.clone(), engine(group_id, 2)?)?;
        assert_eq!(supervisor.group_count(), 1);
        drop(second);
        Ok(())
    }
}
