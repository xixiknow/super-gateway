//! Production H1 Transport Core composed from signed engines, exact pools, Egress and `BoringSSL`.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use gateway_domain::{CredentialId, EgressRouteSnapshot, HttpProtocol};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::{
    AttributionDomain, BoringTlsConnector, ConnectionDisposition, ConnectionPoolCatalog, EgressDialer,
    EngineCatalogHandle, FailureScope, H1Framing, HealthEffect, PoolEntry, PoolKey, PoolShardKey, RawResponseBody,
    RawUpstreamResponse, RetrySafety, TlsConnection, TransportAttempt, TransportCore, TransportCoreState,
    TransportError, TransportErrorCode, TransportEvent, TransportEventKind, TransportEventSink, TransportPhase,
    encode_request, parse_response_head,
};

/// `BoringSSL`-backed process-local Transport implementation.
#[derive(Debug)]
pub struct ProductionTransportCore {
    engines: Arc<EngineCatalogHandle>,
    pools: Arc<ConnectionPoolCatalog<TlsConnection>>,
    egress: EgressDialer,
    tls: BoringTlsConnector,
}

impl ProductionTransportCore {
    /// Construct a serving core from an already verified, non-empty catalog.
    #[must_use]
    pub fn new(engines: Arc<EngineCatalogHandle>) -> Self {
        Self {
            engines,
            pools: Arc::new(ConnectionPoolCatalog::new()),
            egress: EgressDialer,
            tls: BoringTlsConnector,
        }
    }

    /// Current exact-key pooled connection count.
    #[must_use]
    pub fn pooled_connection_count(&self) -> usize {
        self.pools.resource_count()
    }

    /// Drain all connections created by an obsolete Catalog generation.
    #[must_use]
    pub fn drain_generation(&self, generation: crate::ActivationGeneration) -> usize {
        self.pools.drain_generation(generation).len()
    }
}

#[async_trait]
impl TransportCore for ProductionTransportCore {
    fn state(&self) -> TransportCoreState {
        if self.engines.snapshot().is_empty() {
            TransportCoreState::Unavailable
        } else {
            TransportCoreState::Ready
        }
    }

    fn advance_credential_profile_epoch(&self, credential_id: &CredentialId, minimum_profile_epoch: u64) -> usize {
        self.pools
            .advance_credential_profile_epoch(credential_id, minimum_profile_epoch)
            .len()
    }

    fn drain_generation(&self, generation: crate::ActivationGeneration) -> usize {
        self.drain_generation(generation)
    }

    #[allow(clippy::too_many_lines)]
    async fn execute(
        &self,
        attempt: TransportAttempt,
        sink: Arc<dyn TransportEventSink>,
    ) -> Result<RawUpstreamResponse, TransportError> {
        validate_attempt(&attempt)?;
        if attempt.engine.key.protocol != HttpProtocol::H1 {
            return Err(TransportError::engine_unavailable(
                "h2_bundle_activation_disabled_without_wire_evidence",
            ));
        }
        let pool_key = PoolKey {
            credential_id: attempt.snapshot.identity.credential_id.clone(),
            profile_epoch: attempt.snapshot.identity.profile_epoch,
            bundle_id: attempt.snapshot.identity.bundle_id.clone(),
            bundle_version: attempt.snapshot.identity.bundle_version,
            egress_binding_id: attempt.snapshot.identity.egress_binding_id.clone(),
            egress_epoch: attempt.snapshot.identity.egress_epoch,
            authority: attempt.snapshot.request.authority.clone(),
            sni: attempt.snapshot.request.authority.clone(),
            protocol: HttpProtocol::H1,
        };
        let shard = PoolShardKey {
            pool: pool_key,
            activation_generation: attempt.activation_generation,
        };
        let emitter = Arc::new(EventEmitter::new(&attempt, sink));
        let proxied = !matches!(attempt.snapshot.egress, EgressRouteSnapshot::Direct);
        let mut connection = if let Some(entry) = self.pools.checkout(&shard) {
            entry.resource
        } else {
            let connect_deadline = tokio::time::Instant::now() + attempt.snapshot.deadlines.connect;
            let io = self
                .egress
                .dial(
                    &attempt.snapshot.egress,
                    &attempt.snapshot.request.authority,
                    443,
                    remaining_until(connect_deadline, TransportPhase::TcpConnect, 0)?,
                    &attempt.cancellation,
                )
                .await?;
            self.tls
                .connect(
                    io,
                    &attempt.snapshot.request.authority,
                    &attempt.engine.tls,
                    remaining_until(connect_deadline, TransportPhase::TlsHandshake, 0)?,
                    &attempt.cancellation,
                    proxied,
                )
                .await?
        };
        emitter.emit(TransportEventKind::ConnectionReady, 0, 0, false, None, None)?;
        let encoded = encode_request(&attempt.snapshot.request)?;
        let mut written = 0_usize;
        let first_write = await_io(
            attempt.snapshot.deadlines.upstream_total,
            &attempt.cancellation,
            connection.stream.write(&encoded),
            TransportPhase::RequestUpload,
            0,
        )
        .await?;
        if first_write == 0 {
            return Err(io_error(TransportPhase::RequestUpload, 0, "upstream_write_zero"));
        }
        written += first_write;
        // The non-stream upstream total budget starts exactly when the first
        // request byte is written. Every later upload/header/body await in this
        // Transport attempt consumes this same absolute deadline.
        let upstream_deadline = tokio::time::Instant::now() + attempt.snapshot.deadlines.upstream_total;
        emitter.emit(
            TransportEventKind::FirstUpstreamRequestByte,
            usize_to_u64(written),
            0,
            false,
            None,
            None,
        )?;
        if written < encoded.len() {
            await_io(
                remaining_until(upstream_deadline, TransportPhase::RequestUpload, usize_to_u64(written))?,
                &attempt.cancellation,
                connection.stream.write_all(&encoded[written..]),
                TransportPhase::RequestUpload,
                usize_to_u64(written),
            )
            .await?;
            written = encoded.len();
        }
        emitter.emit(
            TransportEventKind::RequestBodyComplete,
            usize_to_u64(written),
            0,
            true,
            None,
            None,
        )?;
        let (head, initial_body) = read_head(
            &mut connection,
            &attempt.cancellation,
            if attempt.snapshot.request.stream {
                None
            } else {
                Some(upstream_deadline)
            },
            attempt.snapshot.deadlines.stream_idle,
            usize_to_u64(written),
        )
        .await?;
        emitter.emit(
            TransportEventKind::ResponseHeaders,
            usize_to_u64(written),
            0,
            true,
            None,
            None,
        )?;
        let content_encoding = head
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
            .map(|(_, value)| String::from_utf8_lossy(value).into_owned().into_boxed_str());
        let status = head.status;
        let headers = head.headers;
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let pools = self.pools.clone();
        let cancellation = attempt.cancellation.clone();
        let deadlines = attempt.snapshot.deadlines;
        let stream_response = attempt.snapshot.request.stream;
        tokio::spawn(async move {
            relay_body(
                connection,
                head.framing,
                initial_body,
                sender,
                pools,
                shard,
                emitter,
                cancellation,
                upstream_deadline,
                deadlines.stream_idle,
                usize_to_u64(written),
                stream_response,
            )
            .await;
        });
        let body = if stream_response {
            RawResponseBody::Sse(receiver)
        } else {
            RawResponseBody::NonStream(receiver)
        };
        Ok(RawUpstreamResponse {
            status,
            headers,
            content_encoding,
            protocol: HttpProtocol::H1,
            body,
        })
    }
}

fn validate_attempt(attempt: &TransportAttempt) -> Result<(), TransportError> {
    let identity = &attempt.snapshot.identity;
    let request = &attempt.snapshot.request;
    if attempt.ordinal == 0
        || attempt.ordinal > 3
        || identity.bundle_id != attempt.engine.key.bundle_id
        || identity.bundle_version != attempt.engine.key.bundle_version
        || identity.bundle_hash.as_str() != attempt.engine.key.bundle_hash.as_ref()
        || request.scheme.as_ref() != "https"
        || request.authority.as_ref() != "api.anthropic.com"
        || attempt.engine.authority != request.authority
    {
        let mut error = TransportError::engine_unavailable("transport_attempt_snapshot_mismatch");
        error.code = TransportErrorCode::InternalInvariant;
        return Err(error);
    }
    Ok(())
}

async fn read_head(
    connection: &mut TlsConnection,
    cancellation: &tokio_util::sync::CancellationToken,
    total_deadline: Option<tokio::time::Instant>,
    idle_timeout: Duration,
    request_bytes: u64,
) -> Result<(crate::ParsedResponseHead, Vec<u8>), TransportError> {
    let mut buffer = Vec::with_capacity(4096);
    loop {
        if buffer.len() >= 64 * 1024 {
            return Err(h1_body_error("h1_response_head_too_large", request_bytes));
        }
        let mut chunk = [0_u8; 4096];
        let timeout = match total_deadline {
            Some(deadline) => remaining_until(deadline, TransportPhase::ResponseHeaders, request_bytes)?,
            None => idle_timeout,
        };
        let read = await_io(
            timeout,
            cancellation,
            connection.stream.read(&mut chunk),
            TransportPhase::ResponseHeaders,
            request_bytes,
        )
        .await?;
        if read == 0 {
            return Err(h1_body_error("h1_response_head_eof", request_bytes));
        }
        buffer.extend_from_slice(&chunk[..read]);
        match parse_response_head(&buffer, "POST") {
            Ok(head) => {
                let initial = buffer.split_off(head.consumed);
                return Ok((head, initial));
            }
            Err(error) if error.diagnostic.as_ref() == "h1_response_head_incomplete" => {}
            Err(error) => return Err(error),
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn relay_body(
    mut connection: TlsConnection,
    framing: H1Framing,
    initial_body: Vec<u8>,
    sender: tokio::sync::mpsc::Sender<Result<Bytes, TransportError>>,
    pools: Arc<ConnectionPoolCatalog<TlsConnection>>,
    shard: PoolShardKey,
    emitter: Arc<EventEmitter>,
    cancellation: tokio_util::sync::CancellationToken,
    total_deadline: tokio::time::Instant,
    idle_timeout: Duration,
    request_bytes: u64,
    streaming: bool,
) {
    let result = match framing {
        H1Framing::NoBody => {
            if initial_body.is_empty() {
                Ok(true)
            } else {
                Err(h1_body_error("h1_residual_response", request_bytes))
            }
        }
        H1Framing::ContentLength(length) => {
            relay_content_length(
                &mut connection,
                length,
                initial_body,
                &sender,
                &emitter,
                &cancellation,
                total_deadline,
                idle_timeout,
                request_bytes,
                streaming,
            )
            .await
        }
        H1Framing::Chunked => {
            relay_chunked(
                &mut connection,
                initial_body,
                &sender,
                &emitter,
                &cancellation,
                total_deadline,
                idle_timeout,
                request_bytes,
                streaming,
            )
            .await
        }
        H1Framing::CloseDelimited => relay_close_delimited(
            &mut connection,
            initial_body,
            &sender,
            &emitter,
            &cancellation,
            total_deadline,
            idle_timeout,
            request_bytes,
            streaming,
        )
        .await
        .map(|()| false),
    };
    match result {
        Ok(reusable) => {
            let _ = emitter.emit(
                TransportEventKind::ResponseComplete,
                request_bytes,
                emitter.response_bytes.load(Ordering::Acquire),
                true,
                None,
                None,
            );
            let disposition = if reusable {
                ConnectionDisposition::Reusable
            } else {
                ConnectionDisposition::CloseConnection
            };
            let _ = emitter.emit(
                TransportEventKind::ConnectionDisposition,
                request_bytes,
                emitter.response_bytes.load(Ordering::Acquire),
                true,
                Some(disposition),
                None,
            );
            if reusable {
                let generation = shard.activation_generation;
                let _ = pools.checkin(
                    shard,
                    PoolEntry {
                        resource: connection,
                        activation_generation: generation,
                    },
                );
            }
        }
        Err(error) => {
            let disposition = error.connection_disposition;
            let diagnostic = error.diagnostic.clone();
            if error.code == TransportErrorCode::Cancelled {
                let _ = emitter.emit(
                    TransportEventKind::CancelRequested,
                    request_bytes,
                    emitter.response_bytes.load(Ordering::Acquire),
                    true,
                    None,
                    Some("cancel_requested".into()),
                );
                let _ = emitter.emit(
                    TransportEventKind::CancelConfirmed,
                    request_bytes,
                    emitter.response_bytes.load(Ordering::Acquire),
                    true,
                    None,
                    Some("cancel_confirmed".into()),
                );
            }
            let _ = sender.try_send(Err(error));
            let _ = emitter.emit(
                TransportEventKind::ConnectionDisposition,
                request_bytes,
                emitter.response_bytes.load(Ordering::Acquire),
                true,
                Some(disposition),
                Some(diagnostic),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_content_length(
    connection: &mut TlsConnection,
    length: u64,
    initial: Vec<u8>,
    sender: &tokio::sync::mpsc::Sender<Result<Bytes, TransportError>>,
    emitter: &EventEmitter,
    cancellation: &tokio_util::sync::CancellationToken,
    total_deadline: tokio::time::Instant,
    idle_timeout: Duration,
    request_bytes: u64,
    streaming: bool,
) -> Result<bool, TransportError> {
    if usize_to_u64(initial.len()) > length {
        return Err(h1_body_error("h1_residual_response", request_bytes));
    }
    let mut remaining = length;
    if !initial.is_empty() {
        remaining -= usize_to_u64(initial.len());
        send_body(sender, emitter, Bytes::from(initial), request_bytes).await?;
    }
    let mut buffer = vec![0_u8; 16 * 1024];
    while remaining > 0 {
        let limit = buffer.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = read_body(
            connection,
            &mut buffer[..limit],
            cancellation,
            total_deadline,
            idle_timeout,
            request_bytes,
            streaming,
        )
        .await?;
        if read == 0 {
            return Err(h1_body_error("h1_body_eof", request_bytes));
        }
        remaining -= usize_to_u64(read);
        send_body(sender, emitter, Bytes::copy_from_slice(&buffer[..read]), request_bytes).await?;
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn relay_close_delimited(
    connection: &mut TlsConnection,
    initial: Vec<u8>,
    sender: &tokio::sync::mpsc::Sender<Result<Bytes, TransportError>>,
    emitter: &EventEmitter,
    cancellation: &tokio_util::sync::CancellationToken,
    total_deadline: tokio::time::Instant,
    idle_timeout: Duration,
    request_bytes: u64,
    streaming: bool,
) -> Result<(), TransportError> {
    if !initial.is_empty() {
        send_body(sender, emitter, Bytes::from(initial), request_bytes).await?;
    }
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let read = read_body(
            connection,
            &mut buffer,
            cancellation,
            total_deadline,
            idle_timeout,
            request_bytes,
            streaming,
        )
        .await?;
        if read == 0 {
            return Ok(());
        }
        send_body(sender, emitter, Bytes::copy_from_slice(&buffer[..read]), request_bytes).await?;
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_chunked(
    connection: &mut TlsConnection,
    initial: Vec<u8>,
    sender: &tokio::sync::mpsc::Sender<Result<Bytes, TransportError>>,
    emitter: &EventEmitter,
    cancellation: &tokio_util::sync::CancellationToken,
    total_deadline: tokio::time::Instant,
    idle_timeout: Duration,
    request_bytes: u64,
    streaming: bool,
) -> Result<bool, TransportError> {
    let mut decoder = ChunkDecoder::default();
    let mut incoming = initial;
    loop {
        let payload_chunks = decoder.feed(&incoming).map_err(|mut error| {
            error.upstream_request_bytes_written = request_bytes;
            error.upstream_submission_complete = true;
            error
        })?;
        for chunk in payload_chunks {
            send_body(sender, emitter, chunk, request_bytes).await?;
        }
        if decoder.complete {
            return if decoder.buffer.is_empty() {
                Ok(true)
            } else {
                Err(h1_body_error("h1_residual_response", request_bytes))
            };
        }
        incoming.resize(16 * 1024, 0);
        let read = read_body(
            connection,
            &mut incoming,
            cancellation,
            total_deadline,
            idle_timeout,
            request_bytes,
            streaming,
        )
        .await?;
        if read == 0 {
            return Err(h1_body_error("h1_chunked_eof", request_bytes));
        }
        incoming.truncate(read);
    }
}

async fn read_body(
    connection: &mut TlsConnection,
    buffer: &mut [u8],
    cancellation: &tokio_util::sync::CancellationToken,
    total_deadline: tokio::time::Instant,
    idle_timeout: Duration,
    request_bytes: u64,
    streaming: bool,
) -> Result<usize, TransportError> {
    let timeout = if streaming {
        idle_timeout
    } else {
        total_deadline.saturating_duration_since(tokio::time::Instant::now())
    };
    if timeout.is_zero() {
        return Err(timeout_error(TransportPhase::ResponseBody, request_bytes));
    }
    await_io(
        timeout,
        cancellation,
        connection.stream.read(buffer),
        TransportPhase::ResponseBody,
        request_bytes,
    )
    .await
}

async fn send_body(
    sender: &tokio::sync::mpsc::Sender<Result<Bytes, TransportError>>,
    emitter: &EventEmitter,
    bytes: Bytes,
    request_bytes: u64,
) -> Result<(), TransportError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let length = usize_to_u64(bytes.len());
    let previous = emitter.response_bytes.fetch_add(length, Ordering::AcqRel);
    if previous == 0 {
        emitter.emit(
            TransportEventKind::FirstResponseBodyByte,
            request_bytes,
            length,
            true,
            None,
            None,
        )?;
    }
    sender
        .send(Ok(bytes))
        .await
        .map_err(|_| cancelled_after_submission(request_bytes))
}

async fn await_io<T>(
    timeout: Duration,
    cancellation: &tokio_util::sync::CancellationToken,
    operation: impl std::future::Future<Output = std::io::Result<T>>,
    phase: TransportPhase,
    request_bytes: u64,
) -> Result<T, TransportError> {
    tokio::select! {
        () = cancellation.cancelled() => Err(cancelled_after_submission(request_bytes)),
        result = tokio::time::timeout(timeout, operation) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(io_error(phase, request_bytes, "upstream_io")),
            Err(_) => Err(timeout_error(phase, request_bytes)),
        }
    }
}

fn remaining_until(
    deadline: tokio::time::Instant,
    phase: TransportPhase,
    request_bytes: u64,
) -> Result<Duration, TransportError> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        Err(timeout_error(phase, request_bytes))
    } else {
        Ok(remaining)
    }
}

#[derive(Debug, Default)]
struct ChunkDecoder {
    buffer: Vec<u8>,
    remaining: Option<usize>,
    expect_data_crlf: bool,
    trailers: bool,
    complete: bool,
}

impl ChunkDecoder {
    fn feed(&mut self, incoming: &[u8]) -> Result<Vec<Bytes>, TransportError> {
        self.buffer.extend_from_slice(incoming);
        let mut output = Vec::new();
        loop {
            if self.complete {
                break;
            }
            if self.trailers {
                if self.buffer.starts_with(b"\r\n") {
                    self.buffer.drain(..2);
                    self.complete = true;
                } else if let Some(end) = find_bytes(&self.buffer, b"\r\n\r\n") {
                    self.buffer.drain(..end + 4);
                    self.complete = true;
                }
                break;
            }
            if self.expect_data_crlf {
                if self.buffer.len() < 2 {
                    break;
                }
                if !self.buffer.starts_with(b"\r\n") {
                    return Err(h1_body_error("h1_chunk_terminator", 0));
                }
                self.buffer.drain(..2);
                self.expect_data_crlf = false;
                self.remaining = None;
                continue;
            }
            if let Some(remaining) = self.remaining.as_mut() {
                if *remaining == 0 {
                    self.expect_data_crlf = true;
                    continue;
                }
                if self.buffer.is_empty() {
                    break;
                }
                let take = (*remaining).min(self.buffer.len());
                let chunk = Bytes::from(self.buffer.drain(..take).collect::<Vec<_>>());
                *remaining -= take;
                output.push(chunk);
                continue;
            }
            let Some(line_end) = find_bytes(&self.buffer, b"\r\n") else {
                if self.buffer.len() > 1024 {
                    return Err(h1_body_error("h1_chunk_size_too_large", 0));
                }
                break;
            };
            let line = std::str::from_utf8(&self.buffer[..line_end]).map_err(|_| h1_body_error("h1_chunk_size", 0))?;
            let size_text = line.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size_text, 16).map_err(|_| h1_body_error("h1_chunk_size", 0))?;
            self.buffer.drain(..line_end + 2);
            if size == 0 {
                self.trailers = true;
            } else {
                self.remaining = Some(size);
            }
        }
        Ok(output)
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

struct EventEmitter {
    request_id: gateway_domain::RequestId,
    attempt_plan_id: gateway_domain::AttemptPlanId,
    connection_attempt_id: gateway_domain::ConnectionAttemptId,
    sink: Arc<dyn TransportEventSink>,
    sequence: AtomicU64,
    response_bytes: AtomicU64,
    started: Instant,
}

impl EventEmitter {
    fn new(attempt: &TransportAttempt, sink: Arc<dyn TransportEventSink>) -> Self {
        Self {
            request_id: attempt.snapshot.request_id.clone(),
            attempt_plan_id: attempt.snapshot.attempt_plan_id.clone(),
            connection_attempt_id: attempt.connection_attempt_id.clone(),
            sink,
            sequence: AtomicU64::new(0),
            response_bytes: AtomicU64::new(0),
            started: Instant::now(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        kind: TransportEventKind,
        request_bytes_written: u64,
        response_bytes_read: u64,
        upstream_submission_complete: bool,
        disposition: Option<ConnectionDisposition>,
        diagnostic_code: Option<Box<str>>,
    ) -> Result<(), TransportError> {
        self.sink.emit(TransportEvent {
            request_id: self.request_id.clone(),
            attempt_plan_id: self.attempt_plan_id.clone(),
            connection_attempt_id: self.connection_attempt_id.clone(),
            sequence: self.sequence.fetch_add(1, Ordering::AcqRel).saturating_add(1),
            monotonic_ns: u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX),
            kind,
            request_bytes_written,
            response_bytes_read,
            upstream_submission_complete,
            connection_disposition: disposition,
            diagnostic_code,
        })
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn io_error(phase: TransportPhase, request_bytes: u64, diagnostic: &'static str) -> TransportError {
    TransportError {
        code: TransportErrorCode::TcpConnectFailure,
        phase,
        attribution_domain: AttributionDomain::AnthropicIncident,
        failure_scope: FailureScope::Connection,
        retry_safety: if request_bytes == 0 {
            RetrySafety::SafeBeforeSubmission
        } else {
            RetrySafety::CommitUnknown
        },
        upstream_request_bytes_written: request_bytes,
        upstream_submission_complete: false,
        connection_disposition: ConnectionDisposition::Evict,
        health_effect: HealthEffect::TransientFailure,
        diagnostic: diagnostic.into(),
    }
}

fn timeout_error(phase: TransportPhase, request_bytes: u64) -> TransportError {
    let mut error = io_error(phase, request_bytes, "upstream_timeout");
    error.code = TransportErrorCode::Timeout;
    error
}

fn h1_body_error(diagnostic: &'static str, request_bytes: u64) -> TransportError {
    TransportError {
        code: TransportErrorCode::H1Framing,
        phase: TransportPhase::ResponseBody,
        attribution_domain: AttributionDomain::BundleRuntime,
        failure_scope: FailureScope::Connection,
        retry_safety: RetrySafety::UnsafeSubmitted,
        upstream_request_bytes_written: request_bytes,
        upstream_submission_complete: true,
        connection_disposition: ConnectionDisposition::Evict,
        health_effect: HealthEffect::QuarantineBundle,
        diagnostic: diagnostic.into(),
    }
}

fn cancelled_after_submission(request_bytes: u64) -> TransportError {
    TransportError {
        code: TransportErrorCode::Cancelled,
        phase: TransportPhase::Cancel,
        attribution_domain: AttributionDomain::Cancellation,
        failure_scope: FailureScope::Attempt,
        retry_safety: if request_bytes == 0 {
            RetrySafety::SafeBeforeSubmission
        } else {
            RetrySafety::UnsafeSubmitted
        },
        upstream_request_bytes_written: request_bytes,
        upstream_submission_complete: request_bytes > 0,
        connection_disposition: ConnectionDisposition::Evict,
        health_effect: HealthEffect::None,
        diagnostic: "cancelled_transport".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{ChunkDecoder, remaining_until};
    use crate::{TransportErrorCode, TransportPhase};

    #[test]
    fn chunk_decoder_streams_payload_without_wire_framing() {
        let mut decoder = ChunkDecoder::default();
        let first = decoder.feed(b"4\r\nWiki\r\n5\r\nped").unwrap_or_default();
        let second = decoder.feed(b"ia\r\n0\r\n\r\n").unwrap_or_default();
        let joined: Vec<u8> = first
            .into_iter()
            .chain(second)
            .flat_map(|bytes| bytes.to_vec())
            .collect();
        assert_eq!(joined, b"Wikipedia");
        assert!(decoder.complete);
        assert!(decoder.buffer.is_empty());
    }

    #[test]
    fn expired_absolute_deadline_is_not_restarted_for_the_next_phase() {
        let result = remaining_until(tokio::time::Instant::now(), TransportPhase::ResponseHeaders, 1);
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.code, TransportErrorCode::Timeout);
            assert_eq!(error.phase, TransportPhase::ResponseHeaders);
        }
    }
}
