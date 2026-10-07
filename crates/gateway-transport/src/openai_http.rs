//! Standard streaming HTTP over the configured fixed egress for official `OpenAI` endpoints.
use crate::OpenAiConnection;
use crate::{BoringTlsConnector, EgressDialer};
use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use gateway_domain::{EgressRouteSnapshot, HeaderSnapshot, HeaderTransport, SecretBytes};
use http_body_util::{BodyExt as _, Full};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// One isolated connection; no identity or proxy configuration is shared with another account.
pub struct OpenAiHttpRequest {
    /// Optional bounded diagnostics sink. At most two redacted snapshots per execution.
    pub header_capture: Option<mpsc::Sender<OpenAiHeaderEvent>>,
    /// Allow one additional TCP/TLS connection attempt before inference bytes are written.
    pub retry_connect: bool,
    /// Application bytes accepted by the TLS stream; zero proves no inference submission.
    pub written: Arc<AtomicU64>,
    /// Official hostname.
    pub host: &'static str,
    /// Origin-form request path.
    pub path: &'static str,
    /// Validated identity and protocol headers.
    pub headers: http::HeaderMap,
    /// Serialized request JSON.
    pub body: SecretBytes,
    /// Fixed direct or proxy exit.
    pub egress: EgressRouteSnapshot,
    /// Connection/handshake timeout.
    pub connect_timeout: Duration,
    /// Per-read timeout (also bounds response headers).
    pub idle_timeout: Duration,
    /// Request lifetime cancellation.
    pub cancellation: CancellationToken,
}
/// Diagnostic events emitted only after the adapter has prepared actual headers.
#[derive(Debug)]
pub enum OpenAiHeaderEvent {
    /// Final request or connection handshake headers.
    Request(HeaderSnapshot),
    /// Original upstream response or handshake response headers.
    Response(HeaderSnapshot),
}

fn snapshot(headers: &http::HeaderMap, transport: HeaderTransport) -> HeaderSnapshot {
    HeaderSnapshot::capture(transport, headers.iter().map(|(k, v)| (k.as_str(), v.as_bytes())))
}

fn emit(sink: Option<&mpsc::Sender<OpenAiHeaderEvent>>, event: OpenAiHeaderEvent) {
    if let Some(sink) = sink {
        let _ = sink.try_send(event);
    }
}
/// Response preserves upstream payload bytes and backpressure.
pub struct OpenAiHttpResponse {
    /// Original status.
    pub status: u16,
    /// Original headers.
    pub headers: http::HeaderMap,
    /// Body chunks; a failure terminates the stream without a fabricated terminal event.
    pub body: mpsc::Receiver<Result<Bytes, &'static str>>,
}

/// Execute a serial response turn on a permanently account-bound WebSocket.
/// # Errors
/// Identity changes, handshake failures and upstream frame errors are never replayed.
#[allow(clippy::too_many_lines)]
pub async fn execute_openai_websocket(
    request: OpenAiHttpRequest,
    connection: Arc<tokio::sync::Mutex<OpenAiConnection>>,
    account: String,
    version: u64,
) -> Result<OpenAiHttpResponse, &'static str> {
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest as _};
    let mut connection = connection.lock_owned().await;
    if connection.account.as_ref().is_some_and(|id| id != &account)
        || connection.token_version.is_some_and(|v| v != version)
    {
        return Err("connection_identity_changed");
    }
    connection.account = Some(account);
    connection.token_version = Some(version);
    let reused = connection.socket.is_some();
    if connection.socket.is_none() {
        let io = connect_official(&request).await?;
        let mut handshake = format!("wss://{}{}", request.host, request.path)
            .into_client_request()
            .map_err(|_| "request")?;
        handshake.headers_mut().extend(request.headers);
        if request.host == "chatgpt.com" {
            handshake.headers_mut().insert(
                "openai-beta",
                http::HeaderValue::from_static("responses_websockets=2026-02-06"),
            );
        }
        let outgoing = snapshot(handshake.headers(), HeaderTransport::WebsocketHandshake);
        emit(
            request.header_capture.as_ref(),
            OpenAiHeaderEvent::Request(outgoing.clone()),
        );
        connection.request_headers = Some(outgoing);
        connection.response_headers = None;
        let handshake_result = tokio::time::timeout(
            request.connect_timeout,
            tokio_tungstenite::client_async(
                handshake,
                Box::new(CountingIo {
                    io: Box::new(io),
                    written: connection.written.clone(),
                }) as crate::BoxedIo,
            ),
        )
        .await
        .map_err(|_| "timeout")?;
        let (socket, response) = match handshake_result {
            Ok(result) => result,
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                emit(
                    request.header_capture.as_ref(),
                    OpenAiHeaderEvent::Response(snapshot(response.headers(), HeaderTransport::WebsocketHandshake)),
                );
                return Err("websocket_handshake");
            }
            Err(_) => return Err("websocket_handshake"),
        };
        connection.response_headers = Some(snapshot(response.headers(), HeaderTransport::WebsocketHandshake));
        connection.socket = Some(socket);
    }
    if reused && let Some(mut headers) = connection.request_headers.clone() {
        headers.reused = true;
        emit(request.header_capture.as_ref(), OpenAiHeaderEvent::Request(headers));
    }
    if let Some(mut headers) = connection.response_headers.clone() {
        headers.reused = reused;
        emit(request.header_capture.as_ref(), OpenAiHeaderEvent::Response(headers));
    }
    let mut body: serde_json::Value = serde_json::from_slice(request.body.expose()).map_err(|_| "body")?;
    let map = body.as_object_mut().ok_or("body")?;
    map.remove("stream");
    map.remove("background");
    map.insert("type".into(), serde_json::json!("response.create"));
    connection.written.store(0, Ordering::Release);
    let socket = connection.socket.as_mut().ok_or("socket")?;
    let sent = tokio::time::timeout(
        request.connect_timeout,
        socket.send(Message::Text(body.to_string().into())),
    )
    .await;
    request
        .written
        .store(connection.written.load(Ordering::Acquire), Ordering::Release);
    if !matches!(sent, Ok(Ok(()))) {
        connection.socket.take();
        return Err(if sent.is_err() { "write_timeout" } else { "write" });
    }
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let mut complete = false;
        while let Some(socket) = connection.socket.as_mut() {
            let frame = tokio::select! {()=request.cancellation.cancelled()=>break,frame=tokio::time::timeout(request.idle_timeout,socket.next())=>frame};
            let text = match frame {
                Ok(Some(Ok(Message::Text(text)))) => text,
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                _ => break,
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                break;
            };
            let terminal = matches!(
                value.get("type").and_then(serde_json::Value::as_str),
                Some("response.completed" | "response.failed" | "response.incomplete")
            );
            let sent = tokio::select! {()=request.cancellation.cancelled()=>false,result=tokio::time::timeout(request.idle_timeout,tx.send(Ok(Bytes::from(format!("data: {text}\n\n")))))=>matches!(result,Ok(Ok(())))};
            if !sent {
                break;
            }
            if terminal {
                complete = true;
                break;
            }
        }
        if !complete {
            connection.socket.take();
            let _ = tx.try_send(Err("websocket_disconnected"));
        }
    });
    let mut headers = http::HeaderMap::new();
    headers.insert("content-type", http::HeaderValue::from_static("text/event-stream"));
    Ok(OpenAiHttpResponse {
        status: 200,
        headers,
        body: rx,
    })
}
fn prepare_http_request(
    headers: http::HeaderMap,
    host: &'static str,
    path: &'static str,
    body: &[u8],
) -> Result<http::Request<Full<Bytes>>, &'static str> {
    let mut upstream = http::Request::builder()
        .method("POST")
        .uri(path)
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|_| "request")?;
    *upstream.headers_mut() = headers;
    upstream
        .headers_mut()
        .insert("host", http::HeaderValue::from_static(host));
    upstream
        .headers_mut()
        .insert("content-type", http::HeaderValue::from_static("application/json"));
    upstream
        .headers_mut()
        .insert("accept-encoding", http::HeaderValue::from_static("identity"));
    upstream
        .headers_mut()
        .insert("content-length", http::HeaderValue::from(body.len()));
    Ok(upstream)
}

/// Perform a single request. Callers must not replay after starting this operation.
/// # Errors
/// Returns a redacted failure stage; secrets and upstream response bodies never enter errors.
pub async fn execute_openai_http(request: OpenAiHttpRequest) -> Result<OpenAiHttpResponse, &'static str> {
    if !matches!(
        (request.host, request.path),
        (
            "api.openai.com",
            "/v1/responses" | "/v1/chat/completions" | "/v1/responses/compact"
        ) | (
            "chatgpt.com",
            "/backend-api/codex/responses" | "/backend-api/codex/responses/compact"
        )
    ) {
        return Err("invalid_endpoint");
    }
    let io = connect_official(&request).await?;
    let io = CountingIo {
        io: Box::new(io),
        written: request.written.clone(),
    };
    let (mut sender, connection) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
        .await
        .map_err(|_| "handshake")?;
    let cancel = request.cancellation.clone();
    tokio::spawn(async move {
        tokio::select! { () = cancel.cancelled() => {}, _ = connection => {} }
    });
    let upstream = prepare_http_request(request.headers, request.host, request.path, request.body.expose())?;
    emit(
        request.header_capture.as_ref(),
        OpenAiHeaderEvent::Request(snapshot(upstream.headers(), HeaderTransport::Http)),
    );
    let response = tokio::select! {
        () = request.cancellation.cancelled() => return Err("cancelled"),
        result = tokio::time::timeout(request.idle_timeout,sender.send_request(upstream)) => result.map_err(|_| "headers_timeout")?.map_err(|_| "request")?,
    };
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    emit(
        request.header_capture.as_ref(),
        OpenAiHeaderEvent::Response(snapshot(&headers, HeaderTransport::Http)),
    );
    let mut body = response.into_body();
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                () = request.cancellation.cancelled() => break,
                result = tokio::time::timeout(request.idle_timeout,body.frame()) => result,
            };
            let chunk = match frame {
                Ok(Some(Ok(frame))) => {
                    let Ok(bytes) = frame.into_data() else {
                        continue;
                    };
                    Ok(bytes)
                }
                Ok(None) => break,
                _ => Err("upstream_body"),
            };
            let failed = chunk.is_err();
            tokio::select! { () = request.cancellation.cancelled() => break,
                result = tokio::time::timeout(request.idle_timeout,tx.send(chunk)) => { if !matches!(result,Ok(Ok(()))) {break;} }
            }
            if failed {
                break;
            }
        }
    });
    Ok(OpenAiHttpResponse {
        status,
        headers,
        body: rx,
    })
}

async fn connect_official(request: &OpenAiHttpRequest) -> Result<crate::BoxedIo, &'static str> {
    let proxied = !matches!(request.egress, EgressRouteSnapshot::Direct);
    let mut failure = "connect";
    for _ in 0..if request.retry_connect { 2 } else { 1 } {
        if request.cancellation.is_cancelled() {
            return Err("cancelled");
        }
        let Ok(io) = EgressDialer
            .dial_provider(
                &request.egress,
                request.host,
                443,
                request.connect_timeout,
                &request.cancellation,
            )
            .await
        else {
            failure = "connect";
            continue;
        };
        match BoringTlsConnector
            .connect_provider(
                io,
                request.host,
                request.connect_timeout,
                &request.cancellation,
                proxied,
            )
            .await
        {
            Ok(io) => return Ok(Box::new(io)),
            Err(_) => failure = "tls",
        }
    }
    Err(failure)
}

struct CountingIo {
    io: crate::BoxedIo,
    written: Arc<AtomicU64>,
}
impl AsyncRead for CountingIo {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for CountingIo {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(size)) = &result {
            self.written.fetch_add(*size as u64, Ordering::AcqRel);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn http_capture_uses_the_complete_prepared_headers() -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", http::HeaderValue::from_static("Bearer fixture-secret"));
        headers.append("x-trace", http::HeaderValue::from_static("first"));
        headers.append("x-trace", http::HeaderValue::from_static("second"));
        let prepared = prepare_http_request(headers, "api.openai.com", "/v1/responses", b"{}")?;
        let captured = snapshot(prepared.headers(), HeaderTransport::Http);
        for (name, value) in [
            ("host", "api.openai.com"),
            ("content-type", "application/json"),
            ("accept-encoding", "identity"),
            ("content-length", "2"),
            ("authorization", "[REDACTED]"),
        ] {
            assert!(captured.entries.iter().any(|h| h.name == name && h.value == value));
        }
        assert_eq!(captured.entries.iter().filter(|h| h.name == "x-trace").count(), 2);
        Ok(())
    }

    use super::*;
    use tokio_tungstenite::{
        WebSocketStream,
        tungstenite::{Message, protocol::Role},
    };

    fn request(cancel: CancellationToken) -> OpenAiHttpRequest {
        OpenAiHttpRequest {
            header_capture: None,
            retry_connect: false,
            written: Arc::new(AtomicU64::new(0)),
            host: "api.openai.com",
            path: "/v1/responses",
            headers: http::HeaderMap::new(),
            body: SecretBytes::new(br#"{"model":"fixture","input":"hello","stream":true}"#.to_vec()),
            egress: EgressRouteSnapshot::Direct,
            connect_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            cancellation: cancel,
        }
    }

    #[tokio::test]
    async fn websocket_serial_turns_keep_one_account_and_release_on_cancel() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server) = tokio::io::duplex(16384);
        let client = WebSocketStream::from_raw_socket(Box::new(client) as crate::BoxedIo, Role::Client, None).await;
        let mut server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let connection = Arc::new(tokio::sync::Mutex::new(OpenAiConnection {
            socket: Some(client),
            request_headers: Some(HeaderSnapshot::capture(
                HeaderTransport::WebsocketHandshake,
                [("authorization", b"Bearer fixture-secret".as_slice())],
            )),
            response_headers: Some(HeaderSnapshot::capture(
                HeaderTransport::WebsocketHandshake,
                [("upgrade", b"websocket".as_slice())],
            )),
            ..Default::default()
        }));
        let fixture = tokio::spawn(async move {
            for _ in 0..2 {
                let Some(Ok(Message::Text(text))) = server.next().await else {
                    return false;
                };
                let Ok(body) = serde_json::from_str::<serde_json::Value>(&text) else {
                    return false;
                };
                if body["type"] != "response.create" || body.get("stream").is_some() {
                    return false;
                }
                if server
                    .send(Message::Text(
                        r#"{"type":"response.completed","response":{"id":"fixture"}}"#.into(),
                    ))
                    .await
                    .is_err()
                {
                    return false;
                }
            }
            server.next().await.is_some()
        });
        for _ in 0..2 {
            let (tx, mut rx) = mpsc::channel(2);
            let mut input = request(CancellationToken::new());
            input.header_capture = Some(tx);
            let mut response = execute_openai_websocket(input, connection.clone(), "account".into(), 1).await?;
            let OpenAiHeaderEvent::Request(outgoing) = rx.try_recv()? else {
                return Err("expected outgoing headers".into());
            };
            assert!(outgoing.reused);
            assert_eq!(outgoing.entries[0].value, "[REDACTED]");
            let OpenAiHeaderEvent::Response(incoming) = rx.try_recv()? else {
                return Err("expected response headers".into());
            };
            assert!(incoming.reused);
            assert_eq!(incoming.entries[0].name, "upgrade");
            assert_eq!(incoming.transport, HeaderTransport::WebsocketHandshake);
            assert!(response.body.recv().await.ok_or("chunk")??.starts_with(b"data: "));
            assert!(response.body.recv().await.is_none());
        }
        assert!(
            execute_openai_websocket(request(CancellationToken::new()), connection.clone(), "other".into(), 1)
                .await
                .is_err()
        );
        let cancel = CancellationToken::new();
        let mut response =
            execute_openai_websocket(request(cancel.clone()), connection.clone(), "account".into(), 1).await?;
        cancel.cancel();
        while response.body.recv().await.is_some() {}
        assert!(connection.lock().await.socket.is_none());
        assert!(fixture.await?);
        Ok(())
    }

    #[tokio::test]
    async fn byte_counter_counts_only_successful_writes() -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let (client, _server) = tokio::io::duplex(64);
        let written = Arc::new(AtomicU64::new(0));
        let mut io = CountingIo {
            io: Box::new(client),
            written: written.clone(),
        };
        assert_eq!(written.load(Ordering::Acquire), 0);
        io.write_all(b"hello").await?;
        assert_eq!(written.load(Ordering::Acquire), 5);
        Ok(())
    }
}
