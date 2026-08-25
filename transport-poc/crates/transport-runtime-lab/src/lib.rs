#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolKey {
    pub credential_id: String,
    pub profile_epoch: u64,
    pub archetype_bundle_version: u32,
    pub egress_binding_id: String,
    pub egress_epoch: u64,
    pub destination_authority: String,
    pub negotiated_protocol: String,
}

#[derive(Debug)]
pub struct IsolatedPool<T> {
    idle_by_key: HashMap<PoolKey, Vec<T>>,
    max_idle_per_key: usize,
}

impl<T> IsolatedPool<T> {
    /// Creates an idle pool with a strict per-key capacity.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeLabError::InvalidConfiguration`] for zero capacity.
    pub fn new(max_idle_per_key: usize) -> Result<Self, RuntimeLabError> {
        if max_idle_per_key == 0 {
            return Err(RuntimeLabError::InvalidConfiguration);
        }
        Ok(Self {
            idle_by_key: HashMap::new(),
            max_idle_per_key,
        })
    }

    pub fn check_out(&mut self, key: &PoolKey) -> Option<T> {
        self.idle_by_key.get_mut(key).and_then(Vec::pop)
    }

    pub fn check_in(&mut self, key: PoolKey, connection: T) -> bool {
        let idle = self.idle_by_key.entry(key).or_default();
        if idle.len() >= self.max_idle_per_key {
            return false;
        }
        idle.push(connection);
        true
    }

    pub fn idle_for(&self, key: &PoolKey) -> usize {
        self.idle_by_key.get(key).map_or(0, Vec::len)
    }

    pub fn evict_key(&mut self, key: &PoolKey) -> usize {
        self.idle_by_key.remove(key).map_or(0, |items| items.len())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    Http1,
    Http2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionStage {
    BeforeConnection,
    Uploading,
    EndStreamSubmitted,
    ResponseCommitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationDecision {
    pub request_bytes: RequestByteState,
    pub stream_action: StreamCancellationAction,
    pub connection_action: ConnectionCancellationAction,
    pub response_bytes: ResponseByteAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestByteState {
    Zero,
    Possible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamCancellationAction {
    None,
    ResetH2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionCancellationAction {
    Keep,
    Evict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseByteAction {
    None,
    PreserveEmitted,
}

pub const fn cancellation_decision(
    protocol: UpstreamProtocol,
    stage: SubmissionStage,
) -> CancellationDecision {
    match (protocol, stage) {
        (_, SubmissionStage::BeforeConnection) => CancellationDecision {
            request_bytes: RequestByteState::Zero,
            stream_action: StreamCancellationAction::None,
            connection_action: ConnectionCancellationAction::Keep,
            response_bytes: ResponseByteAction::None,
        },
        (
            UpstreamProtocol::Http2,
            SubmissionStage::Uploading | SubmissionStage::EndStreamSubmitted,
        ) => CancellationDecision {
            request_bytes: RequestByteState::Possible,
            stream_action: StreamCancellationAction::ResetH2,
            connection_action: ConnectionCancellationAction::Keep,
            response_bytes: ResponseByteAction::None,
        },
        (UpstreamProtocol::Http2, SubmissionStage::ResponseCommitted) => CancellationDecision {
            request_bytes: RequestByteState::Possible,
            stream_action: StreamCancellationAction::ResetH2,
            connection_action: ConnectionCancellationAction::Keep,
            response_bytes: ResponseByteAction::PreserveEmitted,
        },
        (
            UpstreamProtocol::Http1,
            SubmissionStage::Uploading | SubmissionStage::EndStreamSubmitted,
        ) => CancellationDecision {
            request_bytes: RequestByteState::Possible,
            stream_action: StreamCancellationAction::None,
            connection_action: ConnectionCancellationAction::Evict,
            response_bytes: ResponseByteAction::None,
        },
        (UpstreamProtocol::Http1, SubmissionStage::ResponseCommitted) => CancellationDecision {
            request_bytes: RequestByteState::Possible,
            stream_action: StreamCancellationAction::None,
            connection_action: ConnectionCancellationAction::Evict,
            response_bytes: ResponseByteAction::PreserveEmitted,
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayCompletion {
    EndOfStream,
    Cancelled,
    IdleTimeout,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayObservation {
    pub completion: RelayCompletion,
    pub bytes_forwarded: u64,
    pub read_chunks: u64,
    pub first_byte_elapsed_micros: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptDeadlines {
    pub non_stream_response_seconds: u64,
    pub stream_idle_seconds: u64,
}

impl Default for AttemptDeadlines {
    fn default() -> Self {
        Self {
            non_stream_response_seconds: 300,
            stream_idle_seconds: 30,
        }
    }
}

/// Relays upstream SSE bytes without parsing or appending a platform event.
///
/// # Errors
///
/// Returns [`RuntimeLabError`] for invalid timeout, I/O failure, or counter
/// overflow.
pub async fn relay_sse_bytes<R, W>(
    reader: &mut R,
    writer: &mut W,
    idle_timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<RelayObservation, RuntimeLabError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if idle_timeout.is_zero() {
        return Err(RuntimeLabError::InvalidConfiguration);
    }
    let started = tokio::time::Instant::now();
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut bytes_forwarded = 0_u64;
    let mut read_chunks = 0_u64;
    let mut first_byte_elapsed_micros = None;
    loop {
        let read_result = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                writer.flush().await.map_err(RuntimeLabError::Io)?;
                return Ok(RelayObservation {
                    completion: RelayCompletion::Cancelled,
                    bytes_forwarded,
                    read_chunks,
                    first_byte_elapsed_micros,
                });
            }
            result = tokio::time::timeout(idle_timeout, reader.read(&mut buffer)) => result,
        };
        let count = if let Ok(result) = read_result {
            result.map_err(RuntimeLabError::Io)?
        } else {
            writer.flush().await.map_err(RuntimeLabError::Io)?;
            return Ok(RelayObservation {
                completion: RelayCompletion::IdleTimeout,
                bytes_forwarded,
                read_chunks,
                first_byte_elapsed_micros,
            });
        };
        if count == 0 {
            writer.flush().await.map_err(RuntimeLabError::Io)?;
            return Ok(RelayObservation {
                completion: RelayCompletion::EndOfStream,
                bytes_forwarded,
                read_chunks,
                first_byte_elapsed_micros,
            });
        }
        writer
            .write_all(&buffer[..count])
            .await
            .map_err(RuntimeLabError::Io)?;
        bytes_forwarded = bytes_forwarded
            .checked_add(u64::try_from(count).map_err(|_| RuntimeLabError::CounterOverflow)?)
            .ok_or(RuntimeLabError::CounterOverflow)?;
        read_chunks = read_chunks
            .checked_add(1)
            .ok_or(RuntimeLabError::CounterOverflow)?;
        if first_byte_elapsed_micros.is_none() {
            first_byte_elapsed_micros =
                Some(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
        }
    }
}

#[derive(Debug, Error)]
pub enum RuntimeLabError {
    #[error("runtime lab configuration is invalid")]
    InvalidConfiguration,
    #[error("runtime lab counter overflowed")]
    CounterOverflow,
    #[error("runtime lab I/O failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("runtime lab task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("runtime lab output bytes drifted")]
    ByteDrift,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MockLoadReport {
    pub sse_connections_requested: usize,
    pub sse_connections_completed: usize,
    pub peak_sse_connections: usize,
    pub short_requests_completed: usize,
    pub elapsed_micros: u64,
    pub measured_requests_per_second: f64,
    pub unfinished_tasks: usize,
    pub rss_before_kib: Option<u64>,
    pub rss_after_kib: Option<u64>,
}

/// Runs an in-memory mocked-endpoint load scenario with simultaneous SSE
/// relays followed by short byte-transparent request relays.
///
/// # Errors
///
/// Returns [`RuntimeLabError`] for zero inputs, task failure, I/O failure, or
/// any byte drift.
pub async fn run_mock_load(
    sse_connections: usize,
    short_requests: usize,
) -> Result<MockLoadReport, RuntimeLabError> {
    if sse_connections == 0 || short_requests == 0 {
        return Err(RuntimeLabError::InvalidConfiguration);
    }
    let rss_before_kib = linux_rss_kib().await;
    let barrier = Arc::new(tokio::sync::Barrier::new(sse_connections + 1));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..sse_connections {
        let barrier = Arc::clone(&barrier);
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        tasks.spawn(async move {
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(current, Ordering::SeqCst);
            barrier.wait().await;
            let result = relay_fixture(b"event: message\ndata: fixture\n\n").await;
            active.fetch_sub(1, Ordering::SeqCst);
            result
        });
    }
    barrier.wait().await;
    let started = tokio::time::Instant::now();
    let mut sse_connections_completed = 0_usize;
    while let Some(result) = tasks.join_next().await {
        result??;
        sse_connections_completed += 1;
    }
    for _ in 0..short_requests {
        tasks.spawn(relay_fixture(b"{\"type\":\"message\",\"fixture\":true}"));
    }
    let mut short_requests_completed = 0_usize;
    while let Some(result) = tasks.join_next().await {
        result??;
        short_requests_completed += 1;
    }
    let elapsed = started.elapsed();
    let elapsed_seconds = elapsed.as_secs_f64();
    let completed_for_rate =
        u32::try_from(short_requests_completed).map_err(|_| RuntimeLabError::CounterOverflow)?;
    let measured_requests_per_second = if elapsed_seconds == 0.0 {
        f64::INFINITY
    } else {
        f64::from(completed_for_rate) / elapsed_seconds
    };
    tokio::task::yield_now().await;
    let rss_after_kib = linux_rss_kib().await;
    Ok(MockLoadReport {
        sse_connections_requested: sse_connections,
        sse_connections_completed,
        peak_sse_connections: peak.load(Ordering::SeqCst),
        short_requests_completed,
        elapsed_micros: u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
        measured_requests_per_second,
        unfinished_tasks: tasks.len(),
        rss_before_kib,
        rss_after_kib,
    })
}

async fn relay_fixture(payload: &'static [u8]) -> Result<(), RuntimeLabError> {
    let capacity = payload.len().max(64);
    let (mut source_writer, mut source_reader) = tokio::io::duplex(capacity);
    let (mut sink_writer, mut sink_reader) = tokio::io::duplex(capacity);
    source_writer
        .write_all(payload)
        .await
        .map_err(RuntimeLabError::Io)?;
    source_writer
        .shutdown()
        .await
        .map_err(RuntimeLabError::Io)?;
    let cancellation = CancellationToken::new();
    relay_sse_bytes(
        &mut source_reader,
        &mut sink_writer,
        Duration::from_secs(1),
        &cancellation,
    )
    .await?;
    sink_writer.shutdown().await.map_err(RuntimeLabError::Io)?;
    let mut output = Vec::with_capacity(payload.len());
    sink_reader
        .read_to_end(&mut output)
        .await
        .map_err(RuntimeLabError::Io)?;
    if output != payload {
        return Err(RuntimeLabError::ByteDrift);
    }
    Ok(())
}

async fn linux_rss_kib() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let status = tokio::fs::read_to_string("/proc/self/status").await.ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmRSS:")?
            .split_ascii_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn key(credential: &str, profile_epoch: u64, egress: &str) -> PoolKey {
        PoolKey {
            credential_id: credential.to_owned(),
            profile_epoch,
            archetype_bundle_version: 3,
            egress_binding_id: egress.to_owned(),
            egress_epoch: 2,
            destination_authority: "api.anthropic.com".to_owned(),
            negotiated_protocol: "h2".to_owned(),
        }
    }

    #[test]
    fn pool_reuses_only_an_exact_isolation_key() {
        let a = key("credential-a", 1, "egress-a");
        let other_credential = key("credential-b", 1, "egress-a");
        let other_epoch = key("credential-a", 2, "egress-a");
        let other_egress = key("credential-a", 1, "egress-b");
        let mut pool = IsolatedPool::new(2).expect("pool");
        assert!(pool.check_in(a.clone(), "connection-a"));
        assert_eq!(pool.check_out(&other_credential), None);
        assert_eq!(pool.check_out(&other_epoch), None);
        assert_eq!(pool.check_out(&other_egress), None);
        assert_eq!(pool.check_out(&a), Some("connection-a"));
    }

    #[test]
    fn cancellation_matrix_preserves_h2_connection_and_evicts_h1() {
        let h2 = cancellation_decision(UpstreamProtocol::Http2, SubmissionStage::ResponseCommitted);
        assert_eq!(h2.stream_action, StreamCancellationAction::ResetH2);
        assert_eq!(h2.connection_action, ConnectionCancellationAction::Keep);
        assert_eq!(h2.response_bytes, ResponseByteAction::PreserveEmitted);
        let h1 = cancellation_decision(UpstreamProtocol::Http1, SubmissionStage::ResponseCommitted);
        assert_eq!(h1.stream_action, StreamCancellationAction::None);
        assert_eq!(h1.connection_action, ConnectionCancellationAction::Evict);
    }

    #[tokio::test]
    async fn sse_relay_is_byte_transparent() {
        let (mut source_writer, mut source_reader) = tokio::io::duplex(1024);
        let (mut sink_writer, mut sink_reader) = tokio::io::duplex(1024);
        let payload = b"event: message\r\ndata: {\"x\":1}\r\n\r\n: ping\n\n";
        let producer = tokio::spawn(async move {
            source_writer
                .write_all(&payload[..7])
                .await
                .expect("chunk 1");
            source_writer
                .write_all(&payload[7..])
                .await
                .expect("chunk 2");
            source_writer.shutdown().await.expect("source close");
        });
        let cancellation = CancellationToken::new();
        let observation = relay_sse_bytes(
            &mut source_reader,
            &mut sink_writer,
            Duration::from_secs(1),
            &cancellation,
        )
        .await
        .expect("relay");
        sink_writer.shutdown().await.expect("sink close");
        let mut output = vec![];
        sink_reader
            .read_to_end(&mut output)
            .await
            .expect("sink read");
        producer.await.expect("producer");
        assert_eq!(output, payload);
        assert_eq!(observation.completion, RelayCompletion::EndOfStream);
        assert_eq!(observation.bytes_forwarded, payload.len() as u64);
    }

    #[tokio::test]
    async fn sse_cancellation_appends_no_error_bytes() {
        let (mut source_writer, mut source_reader) = tokio::io::duplex(1024);
        let (mut sink_writer, mut sink_reader) = tokio::io::duplex(1024);
        let cancellation = CancellationToken::new();
        source_writer
            .write_all(b"data: already-committed\n\n")
            .await
            .expect("source write");
        let child = cancellation.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            child.cancel();
        });
        let observation = relay_sse_bytes(
            &mut source_reader,
            &mut sink_writer,
            Duration::from_secs(1),
            &cancellation,
        )
        .await
        .expect("relay");
        sink_writer.shutdown().await.expect("sink close");
        let mut output = vec![];
        sink_reader
            .read_to_end(&mut output)
            .await
            .expect("sink read");
        cancel_task.await.expect("cancel task");
        assert_eq!(output, b"data: already-committed\n\n");
        assert_eq!(observation.completion, RelayCompletion::Cancelled);
    }

    #[tokio::test]
    async fn h2_reset_is_stream_local() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.expect("server h2");
            let (_, mut responder_a) = connection
                .accept()
                .await
                .expect("request a")
                .expect("request a valid");
            let (_, mut responder_b) = connection
                .accept()
                .await
                .expect("request b")
                .expect("request b valid");
            let response = http::Response::builder()
                .status(200)
                .body(())
                .expect("response");
            let mut stream_a = responder_a
                .send_response(response, false)
                .expect("response a");
            let response = http::Response::builder()
                .status(200)
                .body(())
                .expect("response");
            let mut stream_b = responder_b
                .send_response(response, false)
                .expect("response b");
            stream_b
                .send_data(Bytes::from_static(b"stream-b-complete"), true)
                .expect("data b");
            let reason = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    tokio::select! {
                        reset = poll_fn(|context| stream_a.poll_reset(context)) => break reset,
                        next = connection.accept() => {
                            assert!(next.is_some(), "connection closed before stream reset");
                        }
                    }
                }
            })
            .await
            .expect("reset timeout")
            .expect("stream a reset");
            assert_eq!(reason, h2::Reason::CANCEL);
        });
        let (mut sender, connection) = h2::client::handshake(client_io).await.expect("client h2");
        let client_task = tokio::spawn(async move { connection.await.expect("client connection") });
        sender = sender.ready().await.expect("ready a");
        let request = http::Request::builder()
            .uri("https://capture.invalid/a")
            .body(())
            .expect("request a");
        let (response_a, mut request_stream_a) =
            sender.send_request(request, true).expect("send a");
        sender = sender.ready().await.expect("ready b");
        let request = http::Request::builder()
            .uri("https://capture.invalid/b")
            .body(())
            .expect("request b");
        let (response_b, _) = sender.send_request(request, true).expect("send b");
        let response_a = response_a.await.expect("response a");
        let response_b = response_b.await.expect("response b");
        let body_a = response_a.into_body();
        request_stream_a.send_reset(h2::Reason::CANCEL);
        drop(body_a);
        let mut body_b = response_b.into_body();
        let data = body_b
            .data()
            .await
            .expect("body b frame")
            .expect("body b valid");
        assert_eq!(data, Bytes::from_static(b"stream-b-complete"));
        assert!(body_b.data().await.is_none());
        drop(sender);
        server_task.await.expect("server task");
        client_task.await.expect("client task");
    }
}
