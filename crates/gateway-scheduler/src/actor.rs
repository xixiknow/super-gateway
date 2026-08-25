//! Tokio actor that gives each Credential Group one mutation order.
#![allow(missing_docs, clippy::missing_errors_doc)]

use std::time::Duration;

use gateway_domain::{CredentialId, LeaseId, RequestId};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use crate::{
    AdmissionDecision, CredentialAuthUpdate, CredentialConfig, CredentialCooldownUpdate, CredentialFenceResult,
    CredentialQuotaUpdate, CredentialRemoveResult, GroupConfig, LeaseRelease, OwnerGeneration, QueueResolution,
    ResourceEvent, RetryLeaseDecision, RetryLeaseRequest, ScheduleEntry, SchedulerEngine, SchedulerError,
    SchedulerSnapshot,
};

/// Serialized commands accepted by one Group owner.
#[derive(Debug)]
pub enum GroupCommand {
    Admit {
        generation: OwnerGeneration,
        entry: ScheduleEntry,
        now: Duration,
        reply: oneshot::Sender<Result<AdmissionDecision, SchedulerError>>,
    },
    Cancel {
        generation: OwnerGeneration,
        request_id: RequestId,
        now: Duration,
        reply: oneshot::Sender<Result<AdmissionDecision, SchedulerError>>,
    },
    ReleaseLease {
        generation: OwnerGeneration,
        lease_id: LeaseId,
        now: Duration,
        reply: oneshot::Sender<Result<(LeaseRelease, Vec<QueueResolution>), SchedulerError>>,
    },
    ReplaceLease {
        generation: OwnerGeneration,
        request: RetryLeaseRequest,
        now: Duration,
        reply: oneshot::Sender<Result<RetryLeaseDecision, SchedulerError>>,
    },
    ObserveCredentialCooldown {
        generation: OwnerGeneration,
        update: CredentialCooldownUpdate,
        now: Duration,
        reply: oneshot::Sender<(bool, Vec<QueueResolution>)>,
    },
    ObserveCredentialAuth {
        generation: OwnerGeneration,
        update: CredentialAuthUpdate,
        now: Duration,
        reply: oneshot::Sender<(bool, Vec<QueueResolution>)>,
    },
    ObserveCredentialQuota {
        generation: OwnerGeneration,
        update: CredentialQuotaUpdate,
        now: Duration,
        reply: oneshot::Sender<(bool, Vec<QueueResolution>)>,
    },
    SetCredentialFence {
        generation: OwnerGeneration,
        credential_id: CredentialId,
        fenced: bool,
        now: Duration,
        reply: oneshot::Sender<(CredentialFenceResult, Vec<QueueResolution>)>,
    },
    RemoveFencedCredential {
        generation: OwnerGeneration,
        credential_id: CredentialId,
        now: Duration,
        reply: oneshot::Sender<(CredentialRemoveResult, Vec<QueueResolution>)>,
    },
    ReconfigureGroup {
        generation: OwnerGeneration,
        config: GroupConfig,
        now: Duration,
        reply: oneshot::Sender<Result<Vec<QueueResolution>, SchedulerError>>,
    },
    ReconfigureCredential {
        generation: OwnerGeneration,
        config: CredentialConfig,
        now: Duration,
        reply: oneshot::Sender<Result<(bool, Vec<QueueResolution>), SchedulerError>>,
    },
    ConfirmTransportCancel {
        generation: OwnerGeneration,
        request_id: RequestId,
        now: Duration,
        reply: oneshot::Sender<Result<LeaseRelease, SchedulerError>>,
    },
    CompleteRequest {
        generation: OwnerGeneration,
        request_id: RequestId,
        now: Duration,
        reply: oneshot::Sender<Result<Vec<QueueResolution>, SchedulerError>>,
    },
    Tick {
        generation: OwnerGeneration,
        now: Duration,
        reply: oneshot::Sender<Vec<QueueResolution>>,
    },
    BeginDrain {
        generation: OwnerGeneration,
        now: Duration,
        reply: oneshot::Sender<Vec<QueueResolution>>,
    },
    Snapshot {
        reply: oneshot::Sender<SchedulerSnapshot>,
    },
    ResourceEvents {
        reply: oneshot::Sender<Vec<ResourceEvent>>,
    },
    AcknowledgeResourceEvents {
        through_sequence: u64,
        reply: oneshot::Sender<()>,
    },
}

/// Cloneable ingress for one Group actor.
#[derive(Clone, Debug)]
pub struct GroupExecutorHandle {
    sender: mpsc::Sender<GroupCommand>,
}

impl GroupExecutorHandle {
    /// Admit a request.
    pub async fn admit(
        &self,
        generation: OwnerGeneration,
        entry: ScheduleEntry,
        now: Duration,
    ) -> Result<AdmissionDecision, ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::Admit {
                generation,
                entry,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response
            .await
            .map_err(|_| ActorError::Closed)?
            .map_err(ActorError::Scheduler)
    }

    /// Cancel queued or leased work.
    pub async fn cancel(
        &self,
        generation: OwnerGeneration,
        request_id: RequestId,
        now: Duration,
    ) -> Result<AdmissionDecision, ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::Cancel {
                generation,
                request_id,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response
            .await
            .map_err(|_| ActorError::Closed)?
            .map_err(ActorError::Scheduler)
    }

    /// Release an exact Lease token.
    pub async fn release_lease(
        &self,
        generation: OwnerGeneration,
        lease_id: LeaseId,
        now: Duration,
    ) -> Result<(LeaseRelease, Vec<QueueResolution>), ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::ReleaseLease {
                generation,
                lease_id,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response
            .await
            .map_err(|_| ActorError::Closed)?
            .map_err(ActorError::Scheduler)
    }

    /// Atomically replace the current Credential Lease without reacquiring the
    /// Group permit or consuming Group/Platform-Key admission budget again.
    pub async fn replace_lease(
        &self,
        generation: OwnerGeneration,
        request: RetryLeaseRequest,
        now: Duration,
    ) -> Result<RetryLeaseDecision, ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::ReplaceLease {
                generation,
                request,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response
            .await
            .map_err(|_| ActorError::Closed)?
            .map_err(ActorError::Scheduler)
    }

    /// Project a durable cooldown change and immediately reconsider queued work.
    pub async fn observe_credential_cooldown(
        &self,
        generation: OwnerGeneration,
        update: CredentialCooldownUpdate,
        now: Duration,
    ) -> Result<(bool, Vec<QueueResolution>), ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::ObserveCredentialCooldown {
                generation,
                update,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response.await.map_err(|_| ActorError::Closed)
    }

    /// Project a durable token/authentication generation into the owning actor.
    pub async fn observe_credential_auth(
        &self,
        generation: OwnerGeneration,
        update: CredentialAuthUpdate,
        now: Duration,
    ) -> Result<(bool, Vec<QueueResolution>), ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::ObserveCredentialAuth {
                generation,
                update,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response.await.map_err(|_| ActorError::Closed)
    }

    /// Project durable quota pressure and immediately reconsider queued work.
    pub async fn observe_credential_quota(
        &self,
        generation: OwnerGeneration,
        update: CredentialQuotaUpdate,
        now: Duration,
    ) -> Result<(bool, Vec<QueueResolution>), ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::ObserveCredentialQuota {
                generation,
                update,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response.await.map_err(|_| ActorError::Closed)
    }

    /// Fence or unfence one Credential and reconsider queued work atomically.
    pub async fn set_credential_fence(
        &self,
        generation: OwnerGeneration,
        credential_id: CredentialId,
        fenced: bool,
        now: Duration,
    ) -> Result<(CredentialFenceResult, Vec<QueueResolution>), ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::SetCredentialFence {
                generation,
                credential_id,
                fenced,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response.await.map_err(|_| ActorError::Closed)
    }

    /// Remove a previously fenced Credential when its in-flight Lease count is zero.
    pub async fn remove_fenced_credential(
        &self,
        generation: OwnerGeneration,
        credential_id: CredentialId,
        now: Duration,
    ) -> Result<(CredentialRemoveResult, Vec<QueueResolution>), ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::RemoveFencedCredential {
                generation,
                credential_id,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response.await.map_err(|_| ActorError::Closed)
    }

    /// Publish one exact Group Config generation into the scheduler actor.
    pub async fn reconfigure_group(
        &self,
        generation: OwnerGeneration,
        config: GroupConfig,
        now: Duration,
    ) -> Result<Vec<QueueResolution>, ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::ReconfigureGroup {
                generation,
                config,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response
            .await
            .map_err(|_| ActorError::Closed)?
            .map_err(ActorError::Scheduler)
    }

    /// Publish one immutable Credential scheduling-config generation.
    pub async fn reconfigure_credential(
        &self,
        generation: OwnerGeneration,
        config: CredentialConfig,
        now: Duration,
    ) -> Result<(bool, Vec<QueueResolution>), ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::ReconfigureCredential {
                generation,
                config,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response
            .await
            .map_err(|_| ActorError::Closed)?
            .map_err(ActorError::Scheduler)
    }

    /// Confirm upstream transport cancellation after its stream/socket is no longer reusable by the request.
    pub async fn confirm_transport_cancel(
        &self,
        generation: OwnerGeneration,
        request_id: RequestId,
        now: Duration,
    ) -> Result<LeaseRelease, ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::ConfirmTransportCancel {
                generation,
                request_id,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response
            .await
            .map_err(|_| ActorError::Closed)?
            .map_err(ActorError::Scheduler)
    }

    /// Complete client delivery and release the Group request permit.
    pub async fn complete_request(
        &self,
        generation: OwnerGeneration,
        request_id: RequestId,
        now: Duration,
    ) -> Result<Vec<QueueResolution>, ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::CompleteRequest {
                generation,
                request_id,
                now,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response
            .await
            .map_err(|_| ActorError::Closed)?
            .map_err(ActorError::Scheduler)
    }

    /// Run expiry and work-conserving grant processing.
    pub async fn tick(&self, generation: OwnerGeneration, now: Duration) -> Result<Vec<QueueResolution>, ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::Tick { generation, now, reply })
            .await
            .map_err(|_| ActorError::Closed)?;
        response.await.map_err(|_| ActorError::Closed)
    }

    /// Fence new work and reject queued work while active Leases drain.
    pub async fn begin_drain(
        &self,
        generation: OwnerGeneration,
        now: Duration,
    ) -> Result<Vec<QueueResolution>, ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::BeginDrain { generation, now, reply })
            .await
            .map_err(|_| ActorError::Closed)?;
        response.await.map_err(|_| ActorError::Closed)
    }

    /// Read a normalized actor snapshot.
    pub async fn snapshot(&self) -> Result<SchedulerSnapshot, ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::Snapshot { reply })
            .await
            .map_err(|_| ActorError::Closed)?;
        response.await.map_err(|_| ActorError::Closed)
    }

    /// Read the unacknowledged resource-ledger suffix without removing it.
    pub async fn resource_events(&self) -> Result<Vec<ResourceEvent>, ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::ResourceEvents { reply })
            .await
            .map_err(|_| ActorError::Closed)?;
        response.await.map_err(|_| ActorError::Closed)
    }

    /// Remove only the resource-ledger prefix already committed durably.
    pub async fn acknowledge_resource_events(&self, through_sequence: u64) -> Result<(), ActorError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(GroupCommand::AcknowledgeResourceEvents {
                through_sequence,
                reply,
            })
            .await
            .map_err(|_| ActorError::Closed)?;
        response.await.map_err(|_| ActorError::Closed)
    }
}

/// Actor endpoint and task lifecycle.
#[derive(Debug)]
pub struct GroupExecutor {
    /// Cloneable command handle.
    pub handle: GroupExecutorHandle,
    /// Actor task, completed after all handles are dropped.
    pub task: JoinHandle<()>,
}

impl GroupExecutor {
    /// Spawn one scheduler engine with a bounded mailbox.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn spawn(mut engine: SchedulerEngine, mailbox_capacity: usize) -> Self {
        let (sender, mut receiver) = mpsc::channel(mailbox_capacity.max(1));
        let task = tokio::spawn(async move {
            while let Some(command) = receiver.recv().await {
                match command {
                    GroupCommand::Admit {
                        generation,
                        entry,
                        now,
                        reply,
                    } => handle_admit(&mut engine, generation, entry, now, reply),
                    GroupCommand::Cancel {
                        generation,
                        request_id,
                        now,
                        reply,
                    } => {
                        let _ = reply.send(engine.cancel(generation, &request_id, now));
                    }
                    GroupCommand::ReleaseLease {
                        generation,
                        lease_id,
                        now,
                        reply,
                    } => {
                        let result = engine
                            .release_lease(generation, &lease_id, now)
                            .map(|released| (released, engine.pump(generation, now)));
                        if let Err(Ok((_, resolutions))) = reply.send(result) {
                            abandon_resolutions(&mut engine, resolutions, now);
                        }
                    }
                    GroupCommand::ReplaceLease {
                        generation,
                        request,
                        now,
                        reply,
                    } => {
                        let result = engine.replace_lease(generation, request, now);
                        if let Err(Ok(RetryLeaseDecision::Granted(lease))) = reply.send(result) {
                            let request_id = lease.request_id.clone();
                            let _ = engine.release_lease(generation, &lease.id, now);
                            if let Ok(resolutions) = engine.complete_request(generation, &request_id, now) {
                                abandon_resolutions(&mut engine, resolutions, now);
                            }
                        }
                    }
                    GroupCommand::ObserveCredentialCooldown {
                        generation,
                        update,
                        now,
                        reply,
                    } => handle_observe_cooldown(&mut engine, generation, &update, now, reply),
                    GroupCommand::ObserveCredentialAuth {
                        generation,
                        update,
                        now,
                        reply,
                    } => handle_observe_auth(&mut engine, generation, &update, now, reply),
                    GroupCommand::ObserveCredentialQuota {
                        generation,
                        update,
                        now,
                        reply,
                    } => handle_observe_quota(&mut engine, generation, &update, now, reply),
                    GroupCommand::SetCredentialFence {
                        generation,
                        credential_id,
                        fenced,
                        now,
                        reply,
                    } => {
                        let result = engine.set_credential_fence(generation, &credential_id, fenced);
                        let resolutions = engine.pump(generation, now);
                        if let Err((_, resolutions)) = reply.send((result, resolutions)) {
                            abandon_resolutions(&mut engine, resolutions, now);
                        }
                    }
                    GroupCommand::RemoveFencedCredential {
                        generation,
                        credential_id,
                        now,
                        reply,
                    } => {
                        let result = engine.remove_fenced_credential(generation, &credential_id);
                        let resolutions = engine.pump(generation, now);
                        if let Err((_, resolutions)) = reply.send((result, resolutions)) {
                            abandon_resolutions(&mut engine, resolutions, now);
                        }
                    }
                    GroupCommand::ReconfigureGroup {
                        generation,
                        config,
                        now,
                        reply,
                    } => {
                        let result = engine.reconfigure(generation, config, now).map(|mut resolutions| {
                            resolutions.extend(engine.pump(generation, now));
                            resolutions
                        });
                        if let Err(Ok(resolutions)) = reply.send(result) {
                            abandon_resolutions(&mut engine, resolutions, now);
                        }
                    }
                    GroupCommand::ReconfigureCredential {
                        generation,
                        config,
                        now,
                        reply,
                    } => {
                        let result = engine.reconfigure_credential(generation, config, now).map(|applied| {
                            let resolutions = engine.pump(generation, now);
                            (applied, resolutions)
                        });
                        if let Err(Ok((_, resolutions))) = reply.send(result) {
                            abandon_resolutions(&mut engine, resolutions, now);
                        }
                    }
                    GroupCommand::ConfirmTransportCancel {
                        generation,
                        request_id,
                        now,
                        reply,
                    } => {
                        let _ = reply.send(engine.confirm_transport_cancel(generation, &request_id, now));
                    }
                    GroupCommand::CompleteRequest {
                        generation,
                        request_id,
                        now,
                        reply,
                    } => {
                        let result = engine.complete_request(generation, &request_id, now);
                        if let Err(Ok(resolutions)) = reply.send(result) {
                            abandon_resolutions(&mut engine, resolutions, now);
                        }
                    }
                    GroupCommand::Tick { generation, now, reply } => {
                        if reply.is_closed() {
                            continue;
                        }
                        let resolutions = engine.pump(generation, now);
                        if let Err(resolutions) = reply.send(resolutions) {
                            abandon_resolutions(&mut engine, resolutions, now);
                        }
                    }
                    GroupCommand::BeginDrain { generation, now, reply } => {
                        let _ = reply.send(engine.disable(generation, now));
                    }
                    GroupCommand::Snapshot { reply } => {
                        let _ = reply.send(engine.snapshot());
                    }
                    GroupCommand::ResourceEvents { reply } => {
                        let _ = reply.send(engine.resource_events().to_vec());
                    }
                    GroupCommand::AcknowledgeResourceEvents {
                        through_sequence,
                        reply,
                    } => {
                        engine.acknowledge_resource_events(through_sequence);
                        let _ = reply.send(());
                    }
                }
            }
        });
        Self {
            handle: GroupExecutorHandle { sender },
            task,
        }
    }
}

fn handle_observe_auth(
    engine: &mut SchedulerEngine,
    generation: OwnerGeneration,
    update: &CredentialAuthUpdate,
    now: Duration,
    reply: oneshot::Sender<(bool, Vec<QueueResolution>)>,
) {
    let applied = engine.observe_credential_auth(generation, update);
    let resolutions = if applied {
        engine.pump(generation, now)
    } else {
        Vec::new()
    };
    if let Err((_, resolutions)) = reply.send((applied, resolutions)) {
        abandon_resolutions(engine, resolutions, now);
    }
}

fn handle_observe_cooldown(
    engine: &mut SchedulerEngine,
    generation: OwnerGeneration,
    update: &CredentialCooldownUpdate,
    now: Duration,
    reply: oneshot::Sender<(bool, Vec<QueueResolution>)>,
) {
    let applied = engine.observe_credential_cooldown(generation, update);
    let resolutions = if applied {
        engine.pump(generation, now)
    } else {
        Vec::new()
    };
    if let Err((_, resolutions)) = reply.send((applied, resolutions)) {
        abandon_resolutions(engine, resolutions, now);
    }
}

fn handle_observe_quota(
    engine: &mut SchedulerEngine,
    generation: OwnerGeneration,
    update: &CredentialQuotaUpdate,
    now: Duration,
    reply: oneshot::Sender<(bool, Vec<QueueResolution>)>,
) {
    let applied = engine.observe_credential_quota(generation, update);
    let resolutions = if applied {
        engine.pump(generation, now)
    } else {
        Vec::new()
    };
    if let Err((_, resolutions)) = reply.send((applied, resolutions)) {
        abandon_resolutions(engine, resolutions, now);
    }
}

fn handle_admit(
    engine: &mut SchedulerEngine,
    generation: OwnerGeneration,
    entry: ScheduleEntry,
    now: Duration,
    reply: oneshot::Sender<Result<AdmissionDecision, SchedulerError>>,
) {
    if reply.is_closed() {
        return;
    }
    let result = engine.admit(generation, entry, now);
    if let Err(Ok(decision)) = reply.send(result) {
        engine.abandon_admission(decision, now);
    }
}

fn abandon_resolutions(engine: &mut SchedulerEngine, resolutions: Vec<QueueResolution>, now: Duration) {
    for resolution in resolutions {
        engine.abandon_admission(resolution.decision, now);
    }
}

/// Actor transport or scheduler failure.
#[derive(Debug, thiserror::Error)]
pub enum ActorError {
    #[error("group executor closed")]
    Closed,
    #[error(transparent)]
    Scheduler(#[from] SchedulerError),
}
