//! Bounded HTTPS client for versioned Credential provider endpoints.

use std::time::Duration;

use gateway_domain::{EgressRouteSnapshot, SecretBytes, SecretValue};
use http::Method;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_boring::SslStream;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    AttributionDomain, BoringTlsConnector, BoxedIo, ConnectionDisposition, EgressDialer, FailureScope, H1Framing,
    HealthEffect, RetrySafety, TransportError, TransportErrorCode, TransportPhase, parse_response_head,
};

const RESPONSE_HEAD_LIMIT: usize = 64 * 1024;
const MAX_RESPONSE_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
/// Independent bounded phases for Credential-provider HTTPS calls.
pub struct ProviderHttpsTimeouts {
    /// TCP/proxy connection budget.
    pub connect: Duration,
    /// TLS handshake budget.
    pub tls: Duration,
    /// Complete request upload budget.
    pub write: Duration,
    /// Response header and body budget.
    pub response: Duration,
}

impl Default for ProviderHttpsTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(15),
            tls: Duration::from_secs(15),
            write: Duration::from_secs(15),
            response: Duration::from_secs(30),
        }
    }
}

/// Secret-bearing provider request that follows a Credential's selected Egress.
pub struct ProviderHttpsRequest {
    /// HTTP method. Provider calls are intentionally limited to GET and POST.
    pub method: Method,
    /// Verified provider DNS name.
    pub host: Box<str>,
    /// Verified provider TCP port.
    pub port: u16,
    /// Exact HTTP Host header.
    pub host_header: Box<str>,
    /// Absolute path and optional query. Some providers place credentials in
    /// this component, so it remains redacted and zeroized until rendering.
    pub path_and_query: SecretValue,
    /// Explicit bounded provider headers. Header names and values are validated.
    pub headers: Vec<ProviderHttpsHeader>,
    /// Zeroizing request body.
    pub body: SecretBytes,
    /// Maximum accepted response body bytes.
    pub response_limit: usize,
    /// Direct or fixed proxy route.
    pub egress: EgressRouteSnapshot,
    /// Request cancellation fence.
    pub cancellation: CancellationToken,
}

/// Secret-bearing provider request header.
pub struct ProviderHttpsHeader {
    /// Lowercase allowlisted header name.
    pub name: &'static str,
    /// Header value, kept in zeroizing memory.
    pub value: SecretBytes,
}

/// Bounded provider response with secret body material.
pub struct ProviderHttpsResponse {
    /// HTTP status code.
    pub status: u16,
    /// Optional raw single Retry-After value.
    pub retry_after: Option<Box<[u8]>>,
    /// Zeroizing response body.
    pub body: SecretBytes,
}

#[derive(Clone, Copy, Debug, Default)]
/// Stateless provider HTTPS client using the production Egress and TLS stack.
pub struct ProviderHttpsClient {
    dialer: EgressDialer,
    tls: BoringTlsConnector,
    timeouts: ProviderHttpsTimeouts,
}

impl ProviderHttpsClient {
    /// Construct a client with explicit phase budgets.
    #[must_use]
    pub const fn new(timeouts: ProviderHttpsTimeouts) -> Self {
        Self {
            dialer: EgressDialer,
            tls: BoringTlsConnector,
            timeouts,
        }
    }

    /// Execute one bounded provider request.
    ///
    /// # Errors
    ///
    /// Returns a structured transport error for invalid input, Egress/TLS/I/O
    /// failure, timeout, cancellation, ambiguous framing, or size overflow.
    pub async fn execute(&self, request: ProviderHttpsRequest) -> Result<ProviderHttpsResponse, TransportError> {
        validate_request(&request)?;
        let proxied = !matches!(request.egress, EgressRouteSnapshot::Direct);
        let io = self
            .dialer
            .dial_provider(
                &request.egress,
                &request.host,
                request.port,
                self.timeouts.connect,
                &request.cancellation,
            )
            .await?;
        let mut stream = self
            .tls
            .connect_provider(io, &request.host, self.timeouts.tls, &request.cancellation, proxied)
            .await?;
        let rendered = render_request(&request);
        await_io(
            self.timeouts.write,
            &request.cancellation,
            stream.write_all(&rendered),
            TransportPhase::RequestUpload,
            false,
        )
        .await?;
        let (head, initial) = read_head(
            &mut stream,
            request.method.as_str(),
            &request.cancellation,
            self.timeouts.response,
        )
        .await?;
        let retry_after = head
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
            .map(|(_, value)| Box::<[u8]>::from(value.as_ref()))
            .collect::<Vec<_>>();
        let retry_after = if retry_after.len() == 1 {
            retry_after.into_iter().next()
        } else {
            None
        };
        let body = read_body(
            &mut stream,
            head.framing,
            initial,
            request.response_limit,
            self.timeouts.response,
            &request.cancellation,
        )
        .await?;
        Ok(ProviderHttpsResponse {
            status: head.status,
            retry_after,
            body: SecretBytes::new(body),
        })
    }
}

fn validate_request(request: &ProviderHttpsRequest) -> Result<(), TransportError> {
    if request.host.is_empty()
        || request.port == 0
        || request.host_header.is_empty()
        || request
            .host_header
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '\r' | '\n' | '/' | '\\' | '@'))
        || !request.path_and_query.expose().starts_with('/')
        || request.path_and_query.expose().contains(['\r', '\n', ' '])
        || !matches!(request.method, Method::GET | Method::POST)
        || (request.method == Method::GET && !request.body.is_empty())
        || (request.method == Method::POST && request.body.is_empty())
        || request.headers.len() > 8
        || request.headers.iter().any(|header| {
            !matches!(
                header.name,
                "authorization"
                    | "content-type"
                    | "cache-control"
                    | "anthropic-beta"
                    | "anthropic-version"
                    | "user-agent"
                    | "x-api-key"
            ) || header.value.expose().is_empty()
                || header.value.expose().contains(&b'\r')
                || header.value.expose().contains(&b'\n')
        })
        || request.response_limit == 0
        || request.response_limit > MAX_RESPONSE_LIMIT
    {
        return Err(provider_error(
            TransportErrorCode::InternalInvariant,
            TransportPhase::RequestUpload,
            false,
            "provider_request_invalid",
        ));
    }
    Ok(())
}

fn render_request(request: &ProviderHttpsRequest) -> Zeroizing<Vec<u8>> {
    let mut rendered = Zeroizing::new(Vec::with_capacity(request.body.expose().len() + 512));
    rendered.extend_from_slice(request.method.as_str().as_bytes());
    rendered.push(b' ');
    rendered.extend_from_slice(request.path_and_query.expose().as_bytes());
    rendered.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    rendered.extend_from_slice(request.host_header.as_bytes());
    rendered.extend_from_slice(b"\r\n");
    for header in &request.headers {
        rendered.extend_from_slice(header.name.as_bytes());
        rendered.extend_from_slice(b": ");
        rendered.extend_from_slice(header.value.expose());
        rendered.extend_from_slice(b"\r\n");
    }
    rendered.extend_from_slice(
        b"Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: ",
    );
    rendered.extend_from_slice(request.body.expose().len().to_string().as_bytes());
    rendered.extend_from_slice(b"\r\n\r\n");
    rendered.extend_from_slice(request.body.expose());
    rendered
}

async fn read_head(
    stream: &mut SslStream<BoxedIo>,
    request_method: &str,
    cancellation: &CancellationToken,
    timeout: Duration,
) -> Result<(crate::ParsedResponseHead, Vec<u8>), TransportError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buffer = Zeroizing::new(Vec::with_capacity(4096));
    loop {
        if buffer.len() >= RESPONSE_HEAD_LIMIT {
            return Err(provider_error(
                TransportErrorCode::H1Framing,
                TransportPhase::ResponseHeaders,
                true,
                "provider_response_head_too_large",
            ));
        }
        let mut chunk = [0_u8; 4096];
        let read = await_until(
            deadline,
            cancellation,
            stream.read(&mut chunk),
            TransportPhase::ResponseHeaders,
        )
        .await?;
        if read == 0 {
            return Err(provider_error(
                TransportErrorCode::H1Framing,
                TransportPhase::ResponseHeaders,
                true,
                "provider_response_head_eof",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        match parse_response_head(&buffer, request_method) {
            Ok(head) => {
                let initial = buffer.split_off(head.consumed);
                return Ok((head, initial));
            }
            Err(error) if error.diagnostic.as_ref() == "h1_response_head_incomplete" => {}
            Err(_) => {
                return Err(provider_error(
                    TransportErrorCode::H1Framing,
                    TransportPhase::ResponseHeaders,
                    true,
                    "provider_response_head_malformed",
                ));
            }
        }
    }
}

async fn read_body(
    stream: &mut SslStream<BoxedIo>,
    framing: H1Framing,
    initial: Vec<u8>,
    limit: usize,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, TransportError> {
    let deadline = tokio::time::Instant::now() + timeout;
    match framing {
        H1Framing::NoBody => {
            if initial.is_empty() {
                Ok(Vec::new())
            } else {
                Err(body_error("provider_response_residual_body"))
            }
        }
        H1Framing::ContentLength(length) => {
            let expected = usize::try_from(length).map_err(|_| body_error("provider_response_too_large"))?;
            if expected > limit || initial.len() > expected {
                return Err(body_error("provider_response_too_large"));
            }
            let mut body = Zeroizing::new(initial);
            let additional = expected.saturating_sub(body.len());
            body.reserve(additional);
            while body.len() < expected {
                let remaining = expected - body.len();
                let mut chunk = vec![0_u8; remaining.min(16 * 1024)];
                let read = await_until(
                    deadline,
                    cancellation,
                    stream.read(&mut chunk),
                    TransportPhase::ResponseBody,
                )
                .await?;
                if read == 0 {
                    return Err(body_error("provider_response_body_eof"));
                }
                body.extend_from_slice(&chunk[..read]);
            }
            Ok(std::mem::take(&mut *body))
        }
        H1Framing::CloseDelimited => {
            let mut body = Zeroizing::new(initial);
            ensure_limit(body.len(), limit)?;
            loop {
                let mut chunk = Zeroizing::new(vec![0_u8; 16 * 1024]);
                let read = await_until(
                    deadline,
                    cancellation,
                    stream.read(&mut chunk),
                    TransportPhase::ResponseBody,
                )
                .await?;
                if read == 0 {
                    return Ok(std::mem::take(&mut *body));
                }
                ensure_limit(body.len().saturating_add(read), limit)?;
                body.extend_from_slice(&chunk[..read]);
            }
        }
        H1Framing::Chunked => read_chunked(stream, initial, limit, deadline, cancellation).await,
    }
}

async fn read_chunked(
    stream: &mut SslStream<BoxedIo>,
    initial: Vec<u8>,
    limit: usize,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, TransportError> {
    let mut incoming = Zeroizing::new(initial);
    let mut body = Zeroizing::new(Vec::new());
    loop {
        let line_end = loop {
            if let Some(position) = find_bytes(&incoming, b"\r\n") {
                break position;
            }
            if incoming.len() > 1024 {
                return Err(body_error("provider_chunk_size_too_large"));
            }
            read_more(stream, &mut incoming, deadline, cancellation).await?;
        };
        let line = std::str::from_utf8(&incoming[..line_end]).map_err(|_| body_error("provider_chunk_size"))?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| body_error("provider_chunk_size"))?;
        incoming.drain(..line_end + 2);
        if size == 0 {
            loop {
                if incoming.starts_with(b"\r\n") {
                    return Ok(std::mem::take(&mut *body));
                }
                if find_bytes(&incoming, b"\r\n\r\n").is_some() {
                    return Ok(std::mem::take(&mut *body));
                }
                if incoming.len() > RESPONSE_HEAD_LIMIT {
                    return Err(body_error("provider_chunk_trailers_too_large"));
                }
                read_more(stream, &mut incoming, deadline, cancellation).await?;
            }
        }
        ensure_limit(body.len().saturating_add(size), limit)?;
        while incoming.len() < size + 2 {
            read_more(stream, &mut incoming, deadline, cancellation).await?;
        }
        if &incoming[size..size + 2] != b"\r\n" {
            return Err(body_error("provider_chunk_terminator"));
        }
        body.extend_from_slice(&incoming[..size]);
        incoming.drain(..size + 2);
    }
}

async fn read_more(
    stream: &mut SslStream<BoxedIo>,
    incoming: &mut Vec<u8>,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<(), TransportError> {
    let mut chunk = Zeroizing::new(vec![0_u8; 16 * 1024]);
    let read = await_until(
        deadline,
        cancellation,
        stream.read(&mut chunk),
        TransportPhase::ResponseBody,
    )
    .await?;
    if read == 0 {
        return Err(body_error("provider_chunked_eof"));
    }
    incoming.extend_from_slice(&chunk[..read]);
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn ensure_limit(length: usize, limit: usize) -> Result<(), TransportError> {
    if length > limit {
        Err(body_error("provider_response_too_large"))
    } else {
        Ok(())
    }
}

async fn await_io<T>(
    timeout: Duration,
    cancellation: &CancellationToken,
    operation: impl std::future::Future<Output = std::io::Result<T>>,
    phase: TransportPhase,
    submitted: bool,
) -> Result<T, TransportError> {
    tokio::select! {
        () = cancellation.cancelled() => Err(provider_error(TransportErrorCode::Cancelled, TransportPhase::Cancel, submitted, "provider_request_cancelled")),
        result = tokio::time::timeout(timeout, operation) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(provider_error(TransportErrorCode::TcpConnectFailure, phase, submitted, "provider_io")),
            Err(_) => Err(provider_error(TransportErrorCode::Timeout, phase, submitted, "provider_timeout")),
        }
    }
}

async fn await_until<T>(
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    operation: impl std::future::Future<Output = std::io::Result<T>>,
    phase: TransportPhase,
) -> Result<T, TransportError> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(provider_error(
            TransportErrorCode::Timeout,
            phase,
            true,
            "provider_timeout",
        ));
    }
    await_io(remaining, cancellation, operation, phase, true).await
}

fn body_error(diagnostic: &'static str) -> TransportError {
    provider_error(
        TransportErrorCode::H1Framing,
        TransportPhase::ResponseBody,
        true,
        diagnostic,
    )
}

fn provider_error(
    code: TransportErrorCode,
    phase: TransportPhase,
    submitted: bool,
    diagnostic: &'static str,
) -> TransportError {
    TransportError {
        code,
        phase,
        attribution_domain: if code == TransportErrorCode::Cancelled {
            AttributionDomain::Cancellation
        } else {
            AttributionDomain::LocalRuntime
        },
        failure_scope: FailureScope::Connection,
        retry_safety: if submitted {
            RetrySafety::UnsafeSubmitted
        } else {
            RetrySafety::SafeBeforeSubmission
        },
        upstream_request_bytes_written: u64::from(submitted),
        upstream_submission_complete: submitted,
        connection_disposition: ConnectionDisposition::CloseConnection,
        health_effect: if code == TransportErrorCode::Cancelled {
            HealthEffect::None
        } else {
            HealthEffect::TransientFailure
        },
        diagnostic: diagnostic.into(),
    }
}

#[cfg(test)]
mod tests {
    use gateway_domain::{EgressRouteSnapshot, SecretBytes, SecretValue};
    use http::Method;
    use tokio_util::sync::CancellationToken;

    use super::{ProviderHttpsHeader, ProviderHttpsRequest, validate_request};

    fn request() -> ProviderHttpsRequest {
        ProviderHttpsRequest {
            method: Method::POST,
            host: "provider.fixture".into(),
            port: 443,
            host_header: "provider.fixture".into(),
            path_and_query: SecretValue::new("/oauth/token".to_owned()),
            headers: vec![ProviderHttpsHeader {
                name: "content-type",
                value: SecretBytes::new(b"application/x-www-form-urlencoded".to_vec()),
            }],
            body: SecretBytes::new(b"grant_type=refresh_token".to_vec()),
            response_limit: 64 * 1024,
            egress: EgressRouteSnapshot::Direct,
            cancellation: CancellationToken::new(),
        }
    }

    #[test]
    fn request_validation_rejects_header_injection_and_unbounded_responses() {
        assert!(validate_request(&request()).is_ok());
        let mut invalid = request();
        invalid.host_header = "provider.fixture\r\nX-Evil: one".into();
        assert!(validate_request(&invalid).is_err());
        let mut invalid = request();
        invalid.response_limit = 1024 * 1024 + 1;
        assert!(validate_request(&invalid).is_err());
        let mut invalid = request();
        invalid.headers.push(ProviderHttpsHeader {
            name: "authorization",
            value: SecretBytes::new(b"Bearer fixture\r\nX-Evil: one".to_vec()),
        });
        assert!(validate_request(&invalid).is_err());
        let valid_get = ProviderHttpsRequest {
            method: Method::GET,
            host: "api.anthropic.com".into(),
            port: 443,
            host_header: "api.anthropic.com".into(),
            path_and_query: SecretValue::new("/api/oauth/profile".to_owned()),
            headers: vec![ProviderHttpsHeader {
                name: "authorization",
                value: SecretBytes::new(b"Bearer fixture".to_vec()),
            }],
            body: SecretBytes::new(Vec::new()),
            response_limit: 64 * 1024,
            egress: EgressRouteSnapshot::Direct,
            cancellation: CancellationToken::new(),
        };
        assert!(validate_request(&valid_get).is_ok());
    }
}
