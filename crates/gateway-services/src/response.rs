//! Transparent client-response preparation with bounded buffering and backpressure.
#![allow(missing_docs, clippy::too_many_arguments)]

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use async_trait::async_trait;
use bytes::Bytes;
use gateway_domain::{BufferTier, ResponseMode, SecretBytes};
use gateway_transport::{RawResponseBody, RawUpstreamResponse, TransportError};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

use crate::usage::{EncodedUsageObserver, ObservedResponseUsage, UsageObserver};

const ENCRYPTED_FRAME_PLAINTEXT: usize = 64 * 1024;
const AES_GCM_NONCE_LEN: usize = 12;
const AES_GCM_TAG_LEN: usize = 16;

/// R7 response limits. Defaults are product decisions, not implementation hints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseConfig {
    pub memory_threshold_bytes: usize,
    pub max_non_stream_bytes: usize,
    pub max_large_responses: usize,
    pub large_response_queue_capacity: usize,
    pub reservation_wait: Duration,
    pub stream_inflight_bytes: usize,
    pub client_write_idle: Duration,
    pub non_stream_total: Duration,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            memory_threshold_bytes: 8 * 1024 * 1024,
            max_non_stream_bytes: 64 * 1024 * 1024,
            max_large_responses: 32,
            large_response_queue_capacity: 64,
            reservation_wait: Duration::from_secs(30),
            stream_inflight_bytes: 1024 * 1024,
            client_write_idle: Duration::from_mins(2),
            non_stream_total: Duration::from_mins(5),
        }
    }
}

/// Prepared response body item.
pub type PreparedBodyItem = Result<Bytes, ResponseError>;

/// Non-blocking plaintext observer used by optional encrypted response audit.
/// Implementations must return immediately and must never affect relay bytes.
pub trait ResponseSideWriter: Send + 'static {
    fn observe(&mut self, bytes: &Bytes);
    fn finish(&mut self, complete: bool);
}

/// Producer-side response termination, shared with the client body adapter.
#[derive(Clone, Debug, Default)]
pub struct PreparedDeliveryState(Arc<AtomicU8>);

impl PreparedDeliveryState {
    fn finish(&self, state: ProducerTermination) {
        let _ = self
            .0
            .compare_exchange(0, state as u8, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Resolve the terminal observed when the prepared body channel reaches EOF.
    #[must_use]
    pub fn eof_outcome(&self) -> gateway_domain::DeliveryOutcome {
        match self.0.load(Ordering::Acquire) {
            value if value == ProducerTermination::Complete as u8 => gateway_domain::DeliveryOutcome::Complete,
            value if value == ProducerTermination::ClientWriteTimeout as u8 => {
                gateway_domain::DeliveryOutcome::ClientWriteTimeout
            }
            value if value == ProducerTermination::Cancelled as u8 => {
                gateway_domain::DeliveryOutcome::ClientDisconnected
            }
            _ => gateway_domain::DeliveryOutcome::UpstreamBodyError,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum ProducerTermination {
    Complete = 1,
    ClientWriteTimeout = 2,
    UpstreamBodyError = 3,
    Cancelled = 4,
}

/// Response ready for the API adapter. Header privacy is intentionally applied later.
pub struct PreparedClientResponse {
    pub status: u16,
    pub headers: Vec<(Box<str>, Bytes)>,
    pub mode: ResponseMode,
    pub buffer_tier: Option<BufferTier>,
    pub body: mpsc::Receiver<PreparedBodyItem>,
    /// Completes independently from delivery and carries no invented token fields.
    pub usage: oneshot::Receiver<ObservedResponseUsage>,
    /// Producer terminal fact used when EOF alone is ambiguous.
    pub delivery_state: PreparedDeliveryState,
    /// Request/Lease/Delivery terminal callback owned by the upper data-plane task.
    pub completion: Option<Arc<dyn DeliveryCompletion>>,
    /// Cancels the upstream relay when the client body is dropped.
    pub cancellation: CancellationToken,
    /// Opaque logical response-byte reservation held through client delivery.
    pub admission: Option<ResponseReservation>,
}

impl std::fmt::Debug for PreparedClientResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedClientResponse")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("mode", &self.mode)
            .field("buffer_tier", &self.buffer_tier)
            .field("has_completion", &self.completion.is_some())
            .finish_non_exhaustive()
    }
}

impl PreparedClientResponse {
    /// Build a fully buffered fixture/adapter response without bypassing the streaming API boundary.
    #[must_use]
    pub fn from_bytes(status: u16, headers: Vec<(Box<str>, Bytes)>, body: Bytes) -> Self {
        let mut observer = UsageObserver::default();
        observer.observe_non_stream_body(&body);
        let (usage_sender, usage_receiver) = oneshot::channel();
        let _ = usage_sender.send(ObservedResponseUsage {
            official: observer.finish(true),
            sse: None,
            upstream_bytes_received: u64::try_from(body.len()).unwrap_or(u64::MAX),
        });
        let (sender, receiver) = mpsc::channel(1);
        let _ = sender.try_send(Ok(body));
        let delivery_state = PreparedDeliveryState::default();
        delivery_state.finish(ProducerTermination::Complete);
        Self {
            status,
            headers,
            mode: ResponseMode::NonStreaming,
            buffer_tier: Some(BufferTier::Memory),
            body: receiver,
            usage: usage_receiver,
            delivery_state,
            completion: None,
            cancellation: CancellationToken::new(),
            admission: None,
        }
    }
}

/// Bounded process-wide admission for responses that cross the memory threshold.
#[derive(Clone, Debug)]
pub struct ReservationPool {
    permits: Arc<Semaphore>,
    capacity: usize,
    waiting: Arc<AtomicUsize>,
    queue_capacity: usize,
    wait_timeout: Duration,
}

impl ReservationPool {
    /// Build a reservation pool.
    ///
    /// # Errors
    ///
    /// Rejects zero permit counts and queue sizes that cannot be represented safely.
    pub fn new(permits: usize, queue_capacity: usize, wait_timeout: Duration) -> Result<Self, ResponseError> {
        if permits == 0 || wait_timeout.is_zero() {
            return Err(ResponseError::InvalidConfiguration);
        }
        Ok(Self {
            permits: Arc::new(Semaphore::new(permits)),
            capacity: permits,
            waiting: Arc::new(AtomicUsize::new(0)),
            queue_capacity,
            wait_timeout,
        })
    }

    async fn acquire(&self, cancellation: &CancellationToken) -> Result<ResponseReservation, ResponseError> {
        self.acquire_with_timeout(cancellation, self.wait_timeout).await
    }

    async fn acquire_with_timeout(
        &self,
        cancellation: &CancellationToken,
        wait_timeout: Duration,
    ) -> Result<ResponseReservation, ResponseError> {
        if let Ok(permit) = self.permits.clone().try_acquire_owned() {
            return Ok(ResponseReservation { _permit: permit });
        }
        if wait_timeout.is_zero() {
            return Err(ResponseError::ReservationTimeout);
        }
        let previous = self.waiting.fetch_add(1, Ordering::AcqRel);
        if previous >= self.queue_capacity {
            self.waiting.fetch_sub(1, Ordering::AcqRel);
            return Err(ResponseError::ReservationQueueFull);
        }
        let acquire = self.permits.clone().acquire_owned();
        let result = tokio::select! {
            () = cancellation.cancelled() => Err(ResponseError::Cancelled),
            timed = tokio::time::timeout(wait_timeout.min(self.wait_timeout), acquire) => match timed {
                Ok(Ok(permit)) => Ok(ResponseReservation { _permit: permit }),
                Ok(Err(_)) => Err(ResponseError::ReservationClosed),
                Err(_) => Err(ResponseError::ReservationTimeout),
            }
        };
        self.waiting.fetch_sub(1, Ordering::AcqRel);
        result
    }

    /// Current active large-response count.
    #[must_use]
    pub fn active(&self) -> usize {
        self.capacity.saturating_sub(self.permits.available_permits())
    }

    /// Current bounded waiter count.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.waiting.load(Ordering::Acquire)
    }
}

pub struct ResponseReservation {
    _permit: OwnedSemaphorePermit,
}

/// Transparent response pipeline.
#[derive(Clone, Debug)]
pub struct ResponsePipeline {
    config: ResponseConfig,
    reservations: ReservationPool,
    spill_directory: Arc<PathBuf>,
    spill_key: Arc<SecretBytes>,
}

impl ResponsePipeline {
    /// Construct the response pipeline with a process-local encrypted spill key.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits or a key that is not 256 bits.
    pub fn new(
        config: ResponseConfig,
        spill_directory: PathBuf,
        spill_key: Arc<SecretBytes>,
    ) -> Result<Self, ResponseError> {
        if config.memory_threshold_bytes == 0
            || config.max_non_stream_bytes < config.memory_threshold_bytes
            || config.stream_inflight_bytes == 0
            || config.client_write_idle.is_zero()
            || config.non_stream_total.is_zero()
            || spill_key.expose().len() != 32
        {
            return Err(ResponseError::InvalidConfiguration);
        }
        let reservations = ReservationPool::new(
            config.max_large_responses,
            config.large_response_queue_capacity,
            config.reservation_wait,
        )?;
        Ok(Self {
            config,
            reservations,
            spill_directory: Arc::new(spill_directory),
            spill_key,
        })
    }

    /// Remove stale encrypted spill files before readiness.
    ///
    /// # Errors
    ///
    /// Returns an I/O classification if the directory cannot be created, scanned or cleaned.
    pub async fn sweep_orphans(&self) -> Result<usize, ResponseError> {
        fs::create_dir_all(self.spill_directory.as_ref())
            .await
            .map_err(|_| ResponseError::SpillIo)?;
        let mut entries = fs::read_dir(self.spill_directory.as_ref())
            .await
            .map_err(|_| ResponseError::SpillIo)?;
        let mut removed = 0_usize;
        while let Some(entry) = entries.next_entry().await.map_err(|_| ResponseError::SpillIo)? {
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "r7spill") && path.is_file() {
                fs::remove_file(path).await.map_err(|_| ResponseError::SpillIo)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    /// Convert raw Transport output into a client-deliverable response.
    ///
    /// # Errors
    ///
    /// Non-stream responses fail before commit on size, reservation, transport-body or spill errors.
    pub async fn prepare(
        &self,
        response: RawUpstreamResponse,
        cancellation: CancellationToken,
    ) -> Result<PreparedClientResponse, ResponseError> {
        self.prepare_with_side_writer(response, cancellation, None).await
    }

    /// Prepare a response while copying upstream body chunks to a synchronous,
    /// non-blocking side writer. Side-writer failures are intentionally outside
    /// this method's error channel.
    ///
    /// # Errors
    ///
    /// Returns the same bounded relay, transport-body and spill errors as
    /// [`Self::prepare`]; side-writer failures are never returned here.
    pub async fn prepare_with_side_writer(
        &self,
        response: RawUpstreamResponse,
        cancellation: CancellationToken,
        side_writer: Option<Box<dyn ResponseSideWriter>>,
    ) -> Result<PreparedClientResponse, ResponseError> {
        self.prepare_with_side_writer_and_reservation(response, cancellation, side_writer, None)
            .await
    }

    /// Reserve one 64 MiB logical non-stream response slot before taking a Credential Lease.
    ///
    /// # Errors
    ///
    /// Returns a bounded queue, timeout, cancellation, or closed-pool classification.
    pub async fn reserve_non_stream(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<ResponseReservation, ResponseError> {
        self.reservations.acquire(cancellation).await
    }

    /// Reserve one non-stream slot while consuming only the caller's remaining
    /// request-scoped pre-upstream budget.
    ///
    /// # Errors
    ///
    /// Returns a bounded queue, caller-budget timeout, cancellation, or
    /// closed-pool classification.
    pub async fn reserve_non_stream_for(
        &self,
        cancellation: &CancellationToken,
        remaining: Duration,
    ) -> Result<ResponseReservation, ResponseError> {
        self.reservations.acquire_with_timeout(cancellation, remaining).await
    }

    /// Production entry that consumes a pre-upstream non-stream reservation.
    ///
    /// # Errors
    ///
    /// Returns bounded relay, transport-body, size, cancellation, or encrypted-spill failures.
    pub async fn prepare_with_side_writer_and_reservation(
        &self,
        response: RawUpstreamResponse,
        cancellation: CancellationToken,
        side_writer: Option<Box<dyn ResponseSideWriter>>,
        reservation: Option<ResponseReservation>,
    ) -> Result<PreparedClientResponse, ResponseError> {
        let RawUpstreamResponse {
            status,
            headers,
            content_encoding,
            body,
            ..
        } = response;
        match body {
            RawResponseBody::Sse(upstream) => {
                Ok(self.prepare_streaming(status, headers, content_encoding, upstream, cancellation, side_writer))
            }
            RawResponseBody::NonStream(upstream) => {
                self.prepare_non_stream(
                    status,
                    headers,
                    content_encoding,
                    upstream,
                    cancellation,
                    side_writer,
                    reservation,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_streaming(
        &self,
        status: u16,
        headers: Vec<(Box<str>, Bytes)>,
        content_encoding: Option<Box<str>>,
        mut upstream: mpsc::Receiver<Result<Bytes, TransportError>>,
        cancellation: CancellationToken,
        mut side_writer: Option<Box<dyn ResponseSideWriter>>,
    ) -> PreparedClientResponse {
        let (sender, receiver) = mpsc::channel(64);
        let (usage_sender, usage_receiver) = oneshot::channel();
        let byte_budget = Arc::new(Semaphore::new(self.config.stream_inflight_bytes));
        let write_idle = self.config.client_write_idle;
        let task_cancellation = cancellation.clone();
        let delivery_state = PreparedDeliveryState::default();
        let task_delivery_state = delivery_state.clone();
        tokio::spawn(async move {
            let mut observer = EncodedUsageObserver::new(content_encoding.as_deref(), true);
            let mut body_complete = false;
            while let Some(item) = tokio::select! {
                () = task_cancellation.cancelled() => {
                    task_delivery_state.finish(ProducerTermination::Cancelled);
                    if let Some(writer) = side_writer.as_mut() { writer.finish(false); }
                    let _ = usage_sender.send(observer.finish(false));
                    return;
                },
                item = upstream.recv() => item,
            } {
                match item {
                    Ok(bytes) => {
                        if let Some(writer) = side_writer.as_mut() {
                            writer.observe(&bytes);
                        }
                        observer.observe(&bytes);
                        for chunk in split_bytes(bytes, byte_budget.available_permits().max(1)) {
                            let Ok(permits) = u32::try_from(chunk.len()) else {
                                let _ = sender.send(Err(ResponseError::BackpressureInvariant)).await;
                                task_delivery_state.finish(ProducerTermination::UpstreamBodyError);
                                task_cancellation.cancel();
                                if let Some(writer) = side_writer.as_mut() {
                                    writer.finish(false);
                                }
                                let _ = usage_sender.send(observer.finish(false));
                                return;
                            };
                            let permit = tokio::select! {
                                () = task_cancellation.cancelled() => {
                                    task_delivery_state.finish(ProducerTermination::Cancelled);
                                    if let Some(writer) = side_writer.as_mut() { writer.finish(false); }
                                    let _ = usage_sender.send(observer.finish(false));
                                    return;
                                },
                                timed = tokio::time::timeout(
                                    write_idle,
                                    byte_budget.clone().acquire_many_owned(permits),
                                ) => match timed {
                                    Ok(Ok(value)) => value,
                                    Ok(Err(_)) => {
                                        task_delivery_state.finish(ProducerTermination::UpstreamBodyError);
                                        if let Some(writer) = side_writer.as_mut() { writer.finish(false); }
                                        let _ = usage_sender.send(observer.finish(false));
                                        return;
                                    }
                                    Err(_) => {
                                        task_cancellation.cancel();
                                        task_delivery_state.finish(ProducerTermination::ClientWriteTimeout);
                                        if let Some(writer) = side_writer.as_mut() { writer.finish(false); }
                                        let _ = usage_sender.send(observer.finish(false));
                                        return;
                                    }
                                },
                            };
                            let budgeted = Bytes::from_owner(BudgetedBytes {
                                bytes: chunk,
                                _permit: permit,
                            });
                            match tokio::time::timeout(write_idle, sender.send(Ok(budgeted))).await {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => {
                                    task_cancellation.cancel();
                                    task_delivery_state.finish(ProducerTermination::Cancelled);
                                    if let Some(writer) = side_writer.as_mut() {
                                        writer.finish(false);
                                    }
                                    let _ = usage_sender.send(observer.finish(false));
                                    return;
                                }
                                Err(_) => {
                                    task_cancellation.cancel();
                                    task_delivery_state.finish(ProducerTermination::ClientWriteTimeout);
                                    if let Some(writer) = side_writer.as_mut() {
                                        writer.finish(false);
                                    }
                                    let _ = usage_sender.send(observer.finish(false));
                                    return;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        task_delivery_state.finish(ProducerTermination::UpstreamBodyError);
                        let _ = sender.send(Err(ResponseError::Transport(error))).await;
                        if let Some(writer) = side_writer.as_mut() {
                            writer.finish(false);
                        }
                        let _ = usage_sender.send(observer.finish(false));
                        return;
                    }
                }
            }
            if task_cancellation.is_cancelled() {
                task_delivery_state.finish(ProducerTermination::Cancelled);
            } else {
                body_complete = true;
                task_delivery_state.finish(ProducerTermination::Complete);
            }
            if let Some(writer) = side_writer.as_mut() {
                writer.finish(body_complete);
            }
            let _ = usage_sender.send(observer.finish(body_complete));
        });
        PreparedClientResponse {
            status,
            headers,
            mode: ResponseMode::Streaming,
            buffer_tier: None,
            body: receiver,
            usage: usage_receiver,
            delivery_state,
            completion: None,
            cancellation,
            admission: None,
        }
    }

    async fn prepare_non_stream(
        &self,
        status: u16,
        headers: Vec<(Box<str>, Bytes)>,
        content_encoding: Option<Box<str>>,
        mut upstream: mpsc::Receiver<Result<Bytes, TransportError>>,
        cancellation: CancellationToken,
        mut side_writer: Option<Box<dyn ResponseSideWriter>>,
        mut reservation: Option<ResponseReservation>,
    ) -> Result<PreparedClientResponse, ResponseError> {
        let mut memory = Vec::new();
        let mut spill: Option<SpillWriter> = None;
        let mut total = 0_usize;
        let mut observer = EncodedUsageObserver::new(content_encoding.as_deref(), false);
        let total_timeout = tokio::time::sleep(self.config.non_stream_total);
        tokio::pin!(total_timeout);
        while let Some(item) = tokio::select! {
            () = cancellation.cancelled() => {
                finish_side_writer(&mut side_writer, false);
                return Err(ResponseError::Cancelled);
            },
            () = &mut total_timeout => {
                cancellation.cancel();
                finish_side_writer(&mut side_writer, false);
                return Err(ResponseError::ResponseTotalTimeout);
            },
            item = upstream.recv() => item,
        } {
            let bytes = match item {
                Ok(bytes) => bytes,
                Err(error) => {
                    finish_side_writer(&mut side_writer, false);
                    return Err(ResponseError::Transport(error));
                }
            };
            if let Some(writer) = side_writer.as_mut() {
                writer.observe(&bytes);
            }
            observer.observe(&bytes);
            total = total.checked_add(bytes.len()).ok_or(ResponseError::ResponseTooLarge)?;
            if total > self.config.max_non_stream_bytes {
                cancellation.cancel();
                finish_side_writer(&mut side_writer, false);
                return Err(ResponseError::ResponseTooLarge);
            }
            if spill.is_none() && total <= self.config.memory_threshold_bytes {
                memory.extend_from_slice(&bytes);
                continue;
            }
            if spill.is_none() {
                let reservation = match reservation.take() {
                    Some(reservation) => reservation,
                    None => self.reservations.acquire(&cancellation).await?,
                };
                let mut writer =
                    SpillWriter::create(self.spill_directory.as_ref(), self.spill_key.clone(), reservation).await?;
                writer.write_plaintext(&memory).await?;
                memory.clear();
                spill = Some(writer);
            }
            if let Some(writer) = spill.as_mut() {
                writer.write_plaintext(&bytes).await?;
            }
        }
        finish_side_writer(&mut side_writer, true);

        let (sender, receiver) = mpsc::channel(64);
        let (usage_sender, usage_receiver) = oneshot::channel();
        let _ = usage_sender.send(observer.finish(true));
        let delivery_state = PreparedDeliveryState::default();
        let tier = if let Some(writer) = spill {
            let file = writer.finish().await?;
            let task_cancellation = cancellation.clone();
            let write_idle = self.config.client_write_idle;
            let task_delivery_state = delivery_state.clone();
            tokio::spawn(async move {
                match relay_spill(file, &sender, task_cancellation, write_idle).await {
                    Ok(()) => task_delivery_state.finish(ProducerTermination::Complete),
                    Err(ResponseError::ClientWriteTimeout) => {
                        task_delivery_state.finish(ProducerTermination::ClientWriteTimeout);
                        let _ = sender.try_send(Err(ResponseError::ClientWriteTimeout));
                    }
                    Err(ResponseError::Cancelled | ResponseError::ClientDisconnected) => {
                        task_delivery_state.finish(ProducerTermination::Cancelled);
                    }
                    Err(error) => {
                        task_delivery_state.finish(ProducerTermination::UpstreamBodyError);
                        let _ = sender.try_send(Err(error));
                    }
                }
            });
            BufferTier::EncryptedSpill
        } else {
            let _ = sender.try_send(Ok(Bytes::from(memory)));
            delivery_state.finish(ProducerTermination::Complete);
            BufferTier::Memory
        };
        Ok(PreparedClientResponse {
            status,
            headers,
            mode: ResponseMode::NonStreaming,
            buffer_tier: Some(tier),
            body: receiver,
            usage: usage_receiver,
            delivery_state,
            completion: None,
            cancellation,
            admission: if tier == BufferTier::Memory { reservation } else { None },
        })
    }
}

fn finish_side_writer(side_writer: &mut Option<Box<dyn ResponseSideWriter>>, complete: bool) {
    if let Some(writer) = side_writer.as_mut() {
        writer.finish(complete);
    }
}

struct BudgetedBytes {
    bytes: Bytes,
    _permit: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for BudgetedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn split_bytes(mut bytes: Bytes, maximum: usize) -> Vec<Bytes> {
    let maximum = maximum.max(1);
    let mut output = Vec::new();
    while bytes.len() > maximum {
        output.push(bytes.split_to(maximum));
    }
    if !bytes.is_empty() {
        output.push(bytes);
    }
    output
}

struct SpillWriter {
    file: File,
    path: PathBuf,
    aad: Box<[u8]>,
    key: Arc<SecretBytes>,
    reservation: Option<ResponseReservation>,
    finalized: bool,
}

impl SpillWriter {
    async fn create(
        directory: &Path,
        key: Arc<SecretBytes>,
        reservation: ResponseReservation,
    ) -> Result<Self, ResponseError> {
        fs::create_dir_all(directory)
            .await
            .map_err(|_| ResponseError::SpillIo)?;
        let file_id = uuid::Uuid::now_v7().simple().to_string();
        let path = directory.join(format!("{file_id}.r7spill"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(|_| ResponseError::SpillIo)?;
        Ok(Self {
            file,
            path,
            aad: format!("super-gateway-response-spill-v1:{file_id}")
                .into_bytes()
                .into_boxed_slice(),
            key,
            reservation: Some(reservation),
            finalized: false,
        })
    }

    async fn write_plaintext(&mut self, bytes: &[u8]) -> Result<(), ResponseError> {
        let cipher = Aes256Gcm::new_from_slice(self.key.expose()).map_err(|_| ResponseError::SpillCrypto)?;
        for chunk in bytes.chunks(ENCRYPTED_FRAME_PLAINTEXT) {
            let mut nonce = [0_u8; AES_GCM_NONCE_LEN];
            getrandom::fill(&mut nonce).map_err(|_| ResponseError::SpillCrypto)?;
            let ciphertext = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: chunk,
                        aad: &self.aad,
                    },
                )
                .map_err(|_| ResponseError::SpillCrypto)?;
            let length = u32::try_from(ciphertext.len()).map_err(|_| ResponseError::SpillCrypto)?;
            self.file.write_u32(length).await.map_err(|_| ResponseError::SpillIo)?;
            self.file.write_all(&nonce).await.map_err(|_| ResponseError::SpillIo)?;
            self.file
                .write_all(&ciphertext)
                .await
                .map_err(|_| ResponseError::SpillIo)?;
        }
        Ok(())
    }

    async fn finish(mut self) -> Result<SpillFile, ResponseError> {
        self.file.flush().await.map_err(|_| ResponseError::SpillIo)?;
        self.file.sync_data().await.map_err(|_| ResponseError::SpillIo)?;
        self.finalized = true;
        Ok(SpillFile {
            path: self.path.clone(),
            aad: self.aad.clone(),
            key: self.key.clone(),
            _reservation: self.reservation.take().ok_or(ResponseError::SpillIo)?,
        })
    }
}

impl Drop for SpillWriter {
    fn drop(&mut self) {
        if !self.finalized {
            let path = self.path.clone();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = fs::remove_file(path).await;
                });
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

struct SpillFile {
    path: PathBuf,
    aad: Box<[u8]>,
    key: Arc<SecretBytes>,
    _reservation: ResponseReservation,
}

async fn relay_spill(
    spill: SpillFile,
    sender: &mpsc::Sender<PreparedBodyItem>,
    cancellation: CancellationToken,
    write_idle: Duration,
) -> Result<(), ResponseError> {
    let result = relay_spill_inner(&spill, sender, &cancellation, write_idle).await;
    let cleanup = fs::remove_file(&spill.path)
        .await
        .map_err(|_| ResponseError::SpillCleanup);
    result.and(cleanup)
}

async fn relay_spill_inner(
    spill: &SpillFile,
    sender: &mpsc::Sender<PreparedBodyItem>,
    cancellation: &CancellationToken,
    write_idle: Duration,
) -> Result<(), ResponseError> {
    let mut file = File::open(&spill.path).await.map_err(|_| ResponseError::SpillIo)?;
    let cipher = Aes256Gcm::new_from_slice(spill.key.expose()).map_err(|_| ResponseError::SpillCrypto)?;
    loop {
        let length = match file.read_u32().await {
            Ok(value) => usize::try_from(value).map_err(|_| ResponseError::SpillFormat)?,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(_) => return Err(ResponseError::SpillIo),
        };
        if length > ENCRYPTED_FRAME_PLAINTEXT + AES_GCM_TAG_LEN {
            return Err(ResponseError::SpillFormat);
        }
        let mut nonce = [0_u8; AES_GCM_NONCE_LEN];
        file.read_exact(&mut nonce).await.map_err(|_| ResponseError::SpillIo)?;
        let mut ciphertext = vec![0_u8; length];
        file.read_exact(&mut ciphertext)
            .await
            .map_err(|_| ResponseError::SpillIo)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &spill.aad,
                },
            )
            .map_err(|_| ResponseError::SpillCrypto)?;
        tokio::select! {
            () = cancellation.cancelled() => return Err(ResponseError::Cancelled),
            result = tokio::time::timeout(write_idle, sender.send(Ok(Bytes::from(plaintext)))) => match result {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(ResponseError::ClientDisconnected),
                Err(_) => return Err(ResponseError::ClientWriteTimeout),
            }
        }
    }
}

/// Response preparation and delivery failure.
#[derive(Debug, thiserror::Error)]
pub enum ResponseError {
    #[error("response configuration is invalid")]
    InvalidConfiguration,
    #[error("upstream response exceeds the configured limit")]
    ResponseTooLarge,
    #[error("non-stream response exceeded its total preparation deadline")]
    ResponseTotalTimeout,
    #[error("large-response reservation queue is full")]
    ReservationQueueFull,
    #[error("large-response reservation timed out")]
    ReservationTimeout,
    #[error("large-response reservation pool is closed")]
    ReservationClosed,
    #[error("response was cancelled")]
    Cancelled,
    #[error("client disconnected")]
    ClientDisconnected,
    #[error("client write idle timeout")]
    ClientWriteTimeout,
    #[error("stream backpressure invariant failed")]
    BackpressureInvariant,
    #[error("encrypted spill I/O failed")]
    SpillIo,
    #[error("encrypted spill cryptography failed")]
    SpillCrypto,
    #[error("encrypted spill framing is invalid")]
    SpillFormat,
    #[error("encrypted spill cleanup failed")]
    SpillCleanup,
    #[error("transport response body failed: {0}")]
    Transport(#[source] TransportError),
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{
        io::Write as _,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use bytes::Bytes;
    use flate2::{Compression, write::GzEncoder};
    use gateway_domain::{BufferTier, HttpProtocol, SecretBytes};
    use gateway_transport::{RawResponseBody, RawUpstreamResponse};
    use tokio::{fs, sync::mpsc};
    use tokio_util::sync::CancellationToken;

    use super::{ReservationPool, ResponseConfig, ResponseError, ResponsePipeline, ResponseSideWriter};

    struct CapturingSideWriter {
        body: Arc<Mutex<Vec<u8>>>,
        terminal: Arc<Mutex<Option<bool>>>,
    }

    impl ResponseSideWriter for CapturingSideWriter {
        fn observe(&mut self, bytes: &Bytes) {
            self.body
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(bytes);
        }

        fn finish(&mut self, complete: bool) {
            *self.terminal.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(complete);
        }
    }

    fn test_pipeline(
        directory: std::path::PathBuf,
        threshold: usize,
        maximum: usize,
    ) -> Result<ResponsePipeline, ResponseError> {
        ResponsePipeline::new(
            ResponseConfig {
                memory_threshold_bytes: threshold,
                max_non_stream_bytes: maximum,
                max_large_responses: 1,
                large_response_queue_capacity: 1,
                reservation_wait: Duration::from_secs(1),
                stream_inflight_bytes: 16,
                client_write_idle: Duration::from_secs(1),
                non_stream_total: Duration::from_mins(5),
            },
            directory,
            Arc::new(SecretBytes::new(vec![9_u8; 32])),
        )
    }

    fn raw_non_stream(chunks: &[&'static [u8]]) -> RawUpstreamResponse {
        let (sender, receiver) = mpsc::channel(chunks.len().max(1));
        for chunk in chunks {
            let _ = sender.try_send(Ok(Bytes::from_static(chunk)));
        }
        RawUpstreamResponse {
            status: 200,
            headers: Vec::new(),
            content_encoding: None,
            protocol: HttpProtocol::H1,
            body: RawResponseBody::NonStream(receiver),
        }
    }

    fn raw_stream(chunks: &[&'static [u8]]) -> RawUpstreamResponse {
        let (sender, receiver) = mpsc::channel(chunks.len().max(1));
        for chunk in chunks {
            let _ = sender.try_send(Ok(Bytes::from_static(chunk)));
        }
        RawUpstreamResponse {
            status: 200,
            headers: Vec::new(),
            content_encoding: None,
            protocol: HttpProtocol::H1,
            body: RawResponseBody::Sse(receiver),
        }
    }

    #[tokio::test]
    async fn sse_arbitrary_chunks_are_byte_exact_and_usage_is_side_channel_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("gateway-r7-{}", uuid::Uuid::now_v7()));
        let pipeline = test_pipeline(directory, 8, 64)?;
        let chunks = [
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7}}}\n\n"
                .as_slice(),
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\n\n"
                .as_slice(),
            b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".as_slice(),
        ];
        let expected = chunks.concat();
        let mut prepared = pipeline.prepare(raw_stream(&chunks), CancellationToken::new()).await?;
        let mut actual = Vec::new();
        while let Some(item) = prepared.body.recv().await {
            actual.extend_from_slice(&item?);
        }
        assert_eq!(actual, expected);
        let usage = prepared.usage.await?;
        assert_eq!(usage.official.completeness, gateway_domain::UsageCompleteness::Complete);
        assert_eq!(usage.official.counts.input_tokens, Some(7));
        assert_eq!(usage.official.counts.output_tokens, Some(3));
        assert_eq!(usage.upstream_bytes_received, expected.len() as u64);
        assert_eq!(
            prepared.delivery_state.eof_outcome(),
            gateway_domain::DeliveryOutcome::Complete
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_stream_usage_stops_at_the_last_complete_sse_event() -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("gateway-r7-cancel-{}", uuid::Uuid::now_v7()));
        let pipeline = test_pipeline(directory, 1_024, 4_096)?;
        let complete = Bytes::from_static(
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"abcdefgh\"}}\n\n",
        );
        let partial = Bytes::from_static(
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"must-not-count\"}",
        );
        let (sender, receiver) = mpsc::channel(4);
        let cancellation = CancellationToken::new();
        let response = RawUpstreamResponse {
            status: 200,
            headers: Vec::new(),
            content_encoding: None,
            protocol: HttpProtocol::H1,
            body: RawResponseBody::Sse(receiver),
        };
        let mut prepared = pipeline.prepare(response, cancellation.clone()).await?;
        sender.send(Ok(complete.clone())).await?;
        sender.send(Ok(partial.clone())).await?;
        let expected = [complete.as_ref(), partial.as_ref()].concat();
        let mut relayed = Vec::new();
        while relayed.len() < expected.len() {
            let chunk = prepared.body.recv().await.transpose()?.expect("relayed chunk");
            relayed.extend_from_slice(&chunk);
        }
        assert_eq!(relayed, expected);
        cancellation.cancel();
        drop(sender);
        let observed = prepared.usage.await?;
        let evidence = observed.sse.expect("stream evidence");
        assert_eq!(
            observed.official.completeness,
            gateway_domain::UsageCompleteness::Unknown
        );
        assert_eq!(observed.upstream_bytes_received, expected.len() as u64);
        assert_eq!(evidence.complete_event_ordinal, 1);
        assert_eq!(evidence.content_event_ordinal, 1);
        assert_eq!(evidence.output_tokens_estimate, Some(2));
        assert!(!evidence.gap);
        assert_eq!(
            prepared.delivery_state.eof_outcome(),
            gateway_domain::DeliveryOutcome::ClientDisconnected
        );
        Ok(())
    }

    #[tokio::test]
    async fn gzip_body_is_relayed_exactly_while_usage_observes_plaintext() -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = br#"{"type":"message","content":[],"usage":{"input_tokens":29,"output_tokens":13}}"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(plaintext)?;
        let compressed = encoder.finish()?;
        let (sender, receiver) = mpsc::channel(64);
        for chunk in compressed.chunks(3) {
            sender.send(Ok(Bytes::copy_from_slice(chunk))).await?;
        }
        drop(sender);
        let response = RawUpstreamResponse {
            status: 200,
            headers: vec![("content-encoding".into(), Bytes::from_static(b"gzip"))],
            content_encoding: Some("gzip".into()),
            protocol: HttpProtocol::H1,
            body: RawResponseBody::NonStream(receiver),
        };
        let directory = std::env::temp_dir().join(format!("gateway-r7-gzip-{}", uuid::Uuid::now_v7()));
        let pipeline = test_pipeline(directory, 1_024, 1_024)?;
        let mut prepared = pipeline.prepare(response, CancellationToken::new()).await?;
        let mut relayed = Vec::new();
        while let Some(item) = prepared.body.recv().await {
            relayed.extend_from_slice(&item?);
        }
        assert_eq!(relayed, compressed);
        let usage = prepared.usage.await?;
        assert_eq!(usage.official.completeness, gateway_domain::UsageCompleteness::Complete);
        assert_eq!(usage.official.counts.input_tokens, Some(29));
        assert_eq!(usage.official.counts.output_tokens, Some(13));
        assert_eq!(usage.upstream_bytes_received, compressed.len() as u64);
        Ok(())
    }

    #[tokio::test]
    async fn stream_idle_timeout_includes_waiting_for_the_byte_budget() -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("gateway-r7-backpressure-{}", uuid::Uuid::now_v7()));
        let pipeline = ResponsePipeline::new(
            ResponseConfig {
                memory_threshold_bytes: 8,
                max_non_stream_bytes: 64,
                max_large_responses: 1,
                large_response_queue_capacity: 1,
                reservation_wait: Duration::from_secs(1),
                stream_inflight_bytes: 4,
                client_write_idle: Duration::from_millis(25),
                non_stream_total: Duration::from_mins(5),
            },
            directory,
            Arc::new(SecretBytes::new(vec![8_u8; 32])),
        )?;
        let mut prepared = pipeline
            .prepare(raw_stream(&[b"1234", b"5678"]), CancellationToken::new())
            .await?;
        tokio::time::sleep(Duration::from_millis(75)).await;
        assert_eq!(
            prepared.body.recv().await.transpose()?,
            Some(Bytes::from_static(b"1234"))
        );
        assert!(prepared.body.recv().await.is_none());
        assert_eq!(
            prepared.delivery_state.eof_outcome(),
            gateway_domain::DeliveryOutcome::ClientWriteTimeout
        );
        let usage = prepared.usage.await?;
        assert_ne!(usage.official.completeness, gateway_domain::UsageCompleteness::Complete);
        Ok(())
    }

    #[tokio::test]
    async fn response_side_writer_observes_exact_upstream_bytes_without_changing_relay()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("gateway-r9-side-{}", uuid::Uuid::now_v7()));
        let pipeline = test_pipeline(directory, 8, 64)?;
        let body = Arc::new(Mutex::new(Vec::new()));
        let terminal = Arc::new(Mutex::new(None));
        let writer = CapturingSideWriter {
            body: body.clone(),
            terminal: terminal.clone(),
        };
        let chunks = [b"event: ping\n".as_slice(), b"data: {\"ok\":true}\n\n".as_slice()];
        let expected = chunks.concat();
        let mut prepared = pipeline
            .prepare_with_side_writer(raw_stream(&chunks), CancellationToken::new(), Some(Box::new(writer)))
            .await?;
        let mut relayed = Vec::new();
        while let Some(item) = prepared.body.recv().await {
            relayed.extend_from_slice(&item?);
        }
        assert_eq!(relayed, expected);
        assert_eq!(
            *body.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            expected
        );
        assert_eq!(
            *terminal.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(true)
        );
        Ok(())
    }

    #[tokio::test]
    async fn threshold_stays_memory_and_threshold_plus_one_uses_encrypted_spill()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("gateway-r7-{}", uuid::Uuid::now_v7()));
        let pipeline = test_pipeline(directory.clone(), 8, 64)?;
        let memory = pipeline
            .prepare(raw_non_stream(&[b"12345678"]), CancellationToken::new())
            .await?;
        assert_eq!(memory.buffer_tier, Some(BufferTier::Memory));

        let mut spill = pipeline
            .prepare(raw_non_stream(&[b"12345678", b"9"]), CancellationToken::new())
            .await?;
        assert_eq!(spill.buffer_tier, Some(BufferTier::EncryptedSpill));
        let mut joined = Vec::new();
        while let Some(item) = spill.body.recv().await {
            joined.extend_from_slice(&item?);
        }
        assert_eq!(joined, b"123456789");
        assert!(pipeline.sweep_orphans().await? == 0);
        fs::remove_dir_all(directory).await?;
        Ok(())
    }

    #[tokio::test]
    async fn maximum_plus_one_is_rejected_before_commit() -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("gateway-r7-{}", uuid::Uuid::now_v7()));
        let pipeline = test_pipeline(directory, 4, 8)?;
        let result = pipeline
            .prepare(raw_non_stream(&[b"123456789"]), CancellationToken::new())
            .await;
        assert!(matches!(result, Err(ResponseError::ResponseTooLarge)));
        Ok(())
    }

    #[tokio::test]
    async fn non_stream_preparation_has_a_configurable_total_deadline() -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("gateway-r7-total-{}", uuid::Uuid::now_v7()));
        let pipeline = ResponsePipeline::new(
            ResponseConfig {
                memory_threshold_bytes: 8,
                max_non_stream_bytes: 64,
                max_large_responses: 1,
                large_response_queue_capacity: 1,
                reservation_wait: Duration::from_secs(1),
                stream_inflight_bytes: 16,
                client_write_idle: Duration::from_secs(1),
                non_stream_total: Duration::from_millis(25),
            },
            directory,
            Arc::new(SecretBytes::new(vec![7_u8; 32])),
        )?;
        let (_sender, receiver) = mpsc::channel(1);
        let response = RawUpstreamResponse {
            status: 200,
            headers: Vec::new(),
            content_encoding: None,
            protocol: HttpProtocol::H1,
            body: RawResponseBody::NonStream(receiver),
        };
        let result = pipeline.prepare(response, CancellationToken::new()).await;
        assert!(matches!(result, Err(ResponseError::ResponseTotalTimeout)));
        Ok(())
    }

    #[tokio::test]
    async fn pre_upstream_non_stream_reservation_is_held_through_memory_delivery()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("gateway-r7-admission-{}", uuid::Uuid::now_v7()));
        let pipeline = test_pipeline(directory, 8, 64)?;
        let cancellation = CancellationToken::new();
        let reservation = pipeline.reserve_non_stream(&cancellation).await?;
        assert_eq!(pipeline.reservations.active(), 1);
        let prepared = pipeline
            .prepare_with_side_writer_and_reservation(raw_non_stream(&[b"1234"]), cancellation, None, Some(reservation))
            .await?;
        assert_eq!(pipeline.reservations.active(), 1);
        drop(prepared);
        assert_eq!(pipeline.reservations.active(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn reservation_wait_consumes_only_the_callers_remaining_budget() -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("gateway-r7-shared-deadline-{}", uuid::Uuid::now_v7()));
        let pipeline = test_pipeline(directory, 8, 64)?;
        let cancellation = CancellationToken::new();
        let _active = pipeline.reserve_non_stream(&cancellation).await?;
        let started = tokio::time::Instant::now();
        let result = pipeline
            .reserve_non_stream_for(&cancellation, Duration::from_millis(20))
            .await;
        assert!(matches!(result, Err(ResponseError::ReservationTimeout)));
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    #[tokio::test]
    async fn thirty_two_reservations_and_sixty_four_waiters_are_hard_bounds() -> Result<(), Box<dyn std::error::Error>>
    {
        let pool = ReservationPool::new(32, 64, Duration::from_mins(1))?;
        let root_cancellation = CancellationToken::new();
        let mut active = Vec::new();
        for _ in 0..32 {
            active.push(pool.acquire(&root_cancellation).await?);
        }
        assert_eq!(pool.active(), 32);

        let mut waiter_cancellations = Vec::new();
        let mut waiter_tasks = Vec::new();
        for _ in 0..64 {
            let cancellation = CancellationToken::new();
            waiter_cancellations.push(cancellation.clone());
            let waiter_pool = pool.clone();
            waiter_tasks.push(tokio::spawn(async move { waiter_pool.acquire(&cancellation).await }));
        }
        while pool.waiting() < 64 {
            tokio::task::yield_now().await;
        }
        let overflow = pool.acquire(&CancellationToken::new()).await;
        assert!(matches!(overflow, Err(ResponseError::ReservationQueueFull)));

        for cancellation in waiter_cancellations {
            cancellation.cancel();
        }
        for task in waiter_tasks {
            assert!(matches!(task.await?, Err(ResponseError::Cancelled)));
        }
        drop(active);
        assert_eq!(pool.active(), 0);
        assert_eq!(pool.waiting(), 0);
        Ok(())
    }
}

/// Client-delivery terminal report. It is emitted exactly once by the API body adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryReport {
    pub outcome: gateway_domain::DeliveryOutcome,
    pub bytes_delivered: u64,
}

/// Commit/terminal hook used to persist delivery and release request-owned resources.
#[async_trait]
pub trait DeliveryCompletion: Send + Sync + 'static {
    /// Persist the response commit fence before Axum returns headers.
    async fn committed(&self) -> Result<(), DeliveryCompletionError>;
    /// Persist the independently observed usage fact. Delivery may still be in progress.
    async fn usage_observed(&self, _usage: ObservedResponseUsage) {}
    /// Persist the terminal and release Group/Credential resources.
    async fn completed(&self, report: DeliveryReport);
}

/// A pre-commit completion hook failed.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("client response commit hook failed")]
pub struct DeliveryCompletionError;
