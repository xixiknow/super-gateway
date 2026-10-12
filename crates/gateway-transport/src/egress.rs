//! Direct, HTTP CONNECT, HTTPS CONNECT and SOCKS5 TLS pass-through TCP establishment.

use std::{io, net::IpAddr, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gateway_domain::{EgressRouteSnapshot, ProxyCredentials, ProxyHop, Socks5DnsMode};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, lookup_host},
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    AttributionDomain, ConnectionDisposition, FailureScope, HealthEffect, RetrySafety, TransportError,
    TransportErrorCode, TransportPhase,
};

/// Async byte stream used by TLS after direct/proxy establishment.
pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Type-erased TCP or tunnel stream.
pub type BoxedIo = Box<dyn AsyncIo>;

/// Stateless Egress dialer. Route identity and secret material come from the frozen attempt snapshot.
#[derive(Clone, Copy, Debug, Default)]
pub struct EgressDialer;

impl EgressDialer {
    /// Open a direct or TLS pass-through proxy path to the fixed Anthropic authority.
    ///
    /// # Errors
    ///
    /// Rejects non-Anthropic targets, malformed proxy configuration, cancellation, deadline and protocol failures.
    pub async fn dial(
        &self,
        route: &EgressRouteSnapshot,
        target_host: &str,
        target_port: u16,
        deadline: Duration,
        cancellation: &CancellationToken,
    ) -> Result<BoxedIo, TransportError> {
        if target_host != "api.anthropic.com" || target_port != 443 || deadline.is_zero() {
            return Err(egress_error(EgressFailure::InvalidConfig, false));
        }
        self.dial_validated(route, target_host, target_port, deadline, cancellation)
            .await
    }

    /// Open a direct or TLS pass-through path to an evidence-gated HTTPS provider endpoint.
    ///
    /// # Errors
    ///
    /// Rejects malformed targets, proxy configuration, cancellation, deadline and tunnel failures.
    pub async fn dial_provider(
        &self,
        route: &EgressRouteSnapshot,
        target_host: &str,
        target_port: u16,
        deadline: Duration,
        cancellation: &CancellationToken,
    ) -> Result<BoxedIo, TransportError> {
        validate_target(target_host, target_port).map_err(|error| egress_error(error, route.is_proxied()))?;
        if deadline.is_zero() {
            return Err(egress_error(EgressFailure::InvalidConfig, route.is_proxied()));
        }
        self.dial_validated(route, target_host, target_port, deadline, cancellation)
            .await
    }

    async fn dial_validated(
        &self,
        route: &EgressRouteSnapshot,
        target_host: &str,
        target_port: u16,
        deadline: Duration,
        cancellation: &CancellationToken,
    ) -> Result<BoxedIo, TransportError> {
        tokio::select! {
            () = cancellation.cancelled() => Err(cancelled()),
            result = tokio::time::timeout(deadline, dial_inner(route, target_host, target_port, deadline)) => {
                match result {
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(error)) => Err(egress_error(error, route.is_proxied())),
                    Err(_) => Err(egress_error(EgressFailure::Timeout, route.is_proxied())),
                }
            }
        }
    }
}

async fn dial_inner(
    route: &EgressRouteSnapshot,
    target_host: &str,
    target_port: u16,
    deadline: Duration,
) -> Result<BoxedIo, EgressFailure> {
    match route {
        EgressRouteSnapshot::Direct => Ok(Box::new(
            TcpStream::connect((target_host, target_port))
                .await
                .map_err(EgressFailure::Io)?,
        )),
        EgressRouteSnapshot::HttpConnect {
            host,
            port,
            credentials,
        } => dial_http_connect(host, *port, credentials.as_deref(), target_host, target_port).await,
        EgressRouteSnapshot::HttpsConnect {
            host,
            port,
            credentials,
        } => dial_https_connect(host, *port, credentials.as_deref(), target_host, target_port).await,
        EgressRouteSnapshot::Socks5 {
            host,
            port,
            dns,
            credentials,
        } => dial_socks5(host, *port, *dns, credentials.as_deref(), target_host, target_port).await,
        EgressRouteSnapshot::WithRelay { primary, relay } => {
            // The direct path is tried first; the relay chain is the fallback
            // for unreachable-class failures only (TCP/DNS/timeout), never for
            // rejected authentication or proxy protocol errors.
            let primary = primary.as_ref();
            let direct = tokio::time::timeout(deadline / 2, async {
                match primary {
                    ProxyHop::HttpConnect {
                        host,
                        port,
                        credentials,
                    } => dial_http_connect(host, *port, credentials.as_deref(), target_host, target_port).await,
                    ProxyHop::HttpsConnect {
                        host,
                        port,
                        credentials,
                    } => dial_https_connect(host, *port, credentials.as_deref(), target_host, target_port).await,
                    ProxyHop::Socks5 {
                        host,
                        port,
                        dns,
                        credentials,
                    } => dial_socks5(host, *port, *dns, credentials.as_deref(), target_host, target_port).await,
                }
            })
            .await;
            match direct {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(failure)) if relay_eligible(&failure) => {
                    dial_via_relay(relay, primary, target_host, target_port).await
                }
                Ok(Err(failure)) => Err(failure),
                Err(_elapsed) => dial_via_relay(relay, primary, target_host, target_port).await,
            }
        }
    }
}

/// Whether the direct attempt failed in a way a relay could plausibly fix.
/// Authentication rejections and proxy protocol errors are never retried
/// through the relay because the primary endpoint was clearly reachable.
fn relay_eligible(failure: &EgressFailure) -> bool {
    matches!(
        failure,
        EgressFailure::Io(_) | EgressFailure::Timeout | EgressFailure::DnsEmpty
    )
}

async fn dial_via_relay(
    relay: &ProxyHop,
    primary: &ProxyHop,
    target_host: &str,
    target_port: u16,
) -> Result<BoxedIo, EgressFailure> {
    let (primary_host, primary_port) = primary.endpoint();
    let mut io: BoxedIo = match relay {
        ProxyHop::HttpConnect {
            host,
            port,
            credentials,
        } => {
            validate_endpoint(host, *port)?;
            let mut stream = TcpStream::connect((host.as_ref(), *port))
                .await
                .map_err(EgressFailure::Io)?;
            http_connect(&mut stream, primary_host, primary_port, credentials.as_deref()).await?;
            Box::new(stream)
        }
        ProxyHop::HttpsConnect {
            host,
            port,
            credentials,
        } => {
            validate_endpoint(host, *port)?;
            let stream = TcpStream::connect((host.as_ref(), *port))
                .await
                .map_err(EgressFailure::Io)?;
            let mut stream = proxy_tls(Box::new(stream), host).await?;
            http_connect(&mut stream, primary_host, primary_port, credentials.as_deref()).await?;
            stream
        }
        ProxyHop::Socks5 {
            host,
            port,
            dns,
            credentials,
        } => {
            validate_endpoint(host, *port)?;
            let mut stream = TcpStream::connect((host.as_ref(), *port))
                .await
                .map_err(EgressFailure::Io)?;
            socks5_connect(&mut stream, primary_host, primary_port, *dns, credentials.as_deref()).await?;
            Box::new(stream)
        }
    };
    if matches!(primary, ProxyHop::HttpsConnect { .. }) {
        io = proxy_tls(io, primary_host).await?;
    }
    match primary {
        ProxyHop::HttpConnect { credentials, .. } | ProxyHop::HttpsConnect { credentials, .. } => {
            http_connect(io.as_mut(), target_host, target_port, credentials.as_deref()).await?;
        }
        ProxyHop::Socks5 { dns, credentials, .. } => {
            socks5_connect(io.as_mut(), target_host, target_port, *dns, credentials.as_deref()).await?;
        }
    }
    Ok(io)
}

async fn dial_http_connect(
    host: &str,
    port: u16,
    credentials: Option<&ProxyCredentials>,
    target_host: &str,
    target_port: u16,
) -> Result<BoxedIo, EgressFailure> {
    validate_endpoint(host, port)?;
    let mut stream = TcpStream::connect((host, port)).await.map_err(EgressFailure::Io)?;
    http_connect(&mut stream, target_host, target_port, credentials).await?;
    Ok(Box::new(stream))
}

async fn dial_https_connect(
    host: &str,
    port: u16,
    credentials: Option<&ProxyCredentials>,
    target_host: &str,
    target_port: u16,
) -> Result<BoxedIo, EgressFailure> {
    validate_endpoint(host, port)?;
    let stream = TcpStream::connect((host, port)).await.map_err(EgressFailure::Io)?;
    let mut stream = proxy_tls(Box::new(stream), host).await?;
    http_connect(&mut stream, target_host, target_port, credentials).await?;
    Ok(stream)
}

async fn dial_socks5(
    host: &str,
    port: u16,
    dns: Socks5DnsMode,
    credentials: Option<&ProxyCredentials>,
    target_host: &str,
    target_port: u16,
) -> Result<BoxedIo, EgressFailure> {
    validate_endpoint(host, port)?;
    let mut stream = TcpStream::connect((host, port)).await.map_err(EgressFailure::Io)?;
    socks5_connect(&mut stream, target_host, target_port, dns, credentials).await?;
    Ok(Box::new(stream))
}

#[cfg(feature = "boring-backend")]
async fn proxy_tls(io: BoxedIo, proxy_host: &str) -> Result<BoxedIo, EgressFailure> {
    crate::tls::connect_proxy_tls(io, proxy_host)
        .await
        .map(|stream| Box::new(stream) as BoxedIo)
        .map_err(|failure| match failure {
            crate::tls::ProxyTlsFailure::Configuration => EgressFailure::InvalidConfig,
            crate::tls::ProxyTlsFailure::Handshake => EgressFailure::ProxyTlsHandshake,
            crate::tls::ProxyTlsFailure::Certificate => EgressFailure::ProxyTlsCertificate,
        })
}

#[cfg(not(feature = "boring-backend"))]
async fn proxy_tls(_io: BoxedIo, _proxy_host: &str) -> Result<BoxedIo, EgressFailure> {
    Err(EgressFailure::InvalidConfig)
}

fn validate_endpoint(host: &str, port: u16) -> Result<(), EgressFailure> {
    if host.is_empty()
        || port == 0
        || host
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '/' | '\\' | '@'))
    {
        return Err(EgressFailure::InvalidConfig);
    }
    Ok(())
}

fn validate_target(host: &str, port: u16) -> Result<(), EgressFailure> {
    validate_endpoint(host, port)?;
    if host.len() > usize::from(u8::MAX)
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || host.chars().any(|character| matches!(character, '[' | ']'))
    {
        return Err(EgressFailure::InvalidConfig);
    }
    Ok(())
}

async fn http_connect<S: AsyncIo + ?Sized>(
    stream: &mut S,
    host: &str,
    port: u16,
    credentials: Option<&ProxyCredentials>,
) -> Result<(), EgressFailure> {
    let authority = format_authority(host, port);
    let mut request = Zeroizing::new(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"));
    if let Some(credentials) = credentials {
        let raw = Zeroizing::new(format!(
            "{}:{}",
            credentials.username.expose(),
            credentials.password.expose()
        ));
        let encoded = Zeroizing::new(STANDARD.encode(raw.as_bytes()));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&encoded);
        request.push_str("\r\n");
    }
    request.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    stream.write_all(request.as_bytes()).await.map_err(EgressFailure::Io)?;
    let response = read_http_head(stream, 16 * 1024).await?;
    let status = parse_http_status(&response)?;
    match status {
        200 => Ok(()),
        407 => Err(EgressFailure::AuthenticationRejected),
        _ => Err(EgressFailure::HttpStatus),
    }
}

async fn read_http_head<S: AsyncIo + ?Sized>(stream: &mut S, limit: usize) -> Result<Vec<u8>, EgressFailure> {
    let mut response = Vec::with_capacity(512);
    while response.len() < limit {
        let byte = stream.read_u8().await.map_err(EgressFailure::Io)?;
        response.push(byte);
        if response.ends_with(b"\r\n\r\n") {
            return Ok(response);
        }
    }
    Err(EgressFailure::MalformedResponse)
}

fn parse_http_status(response: &[u8]) -> Result<u16, EgressFailure> {
    let line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(EgressFailure::MalformedResponse)?;
    let line = std::str::from_utf8(&response[..line_end]).map_err(|_| EgressFailure::MalformedResponse)?;
    let mut parts = line.split_ascii_whitespace();
    let version = parts.next().ok_or(EgressFailure::MalformedResponse)?;
    let status = parts
        .next()
        .ok_or(EgressFailure::MalformedResponse)?
        .parse::<u16>()
        .map_err(|_| EgressFailure::MalformedResponse)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(EgressFailure::MalformedResponse);
    }
    Ok(status)
}

async fn socks5_connect<S: AsyncIo + ?Sized>(
    stream: &mut S,
    host: &str,
    port: u16,
    dns: Socks5DnsMode,
    credentials: Option<&ProxyCredentials>,
) -> Result<(), EgressFailure> {
    let methods: &[u8] = if credentials.is_some() { &[0, 2] } else { &[0] };
    stream
        .write_all(&[
            5,
            u8::try_from(methods.len()).map_err(|_| EgressFailure::InvalidConfig)?,
        ])
        .await
        .map_err(EgressFailure::Io)?;
    stream.write_all(methods).await.map_err(EgressFailure::Io)?;
    let mut selection = [0_u8; 2];
    stream.read_exact(&mut selection).await.map_err(EgressFailure::Io)?;
    if selection[0] != 5 || selection[1] == 0xff {
        return Err(EgressFailure::AuthenticationRejected);
    }
    match selection[1] {
        0 => {}
        2 => authenticate_socks5(stream, credentials.ok_or(EgressFailure::AuthenticationRejected)?).await?,
        _ => return Err(EgressFailure::MalformedResponse),
    }
    let mut request = Zeroizing::new(vec![5, 1, 0]);
    append_socks5_address(&mut request, host, port, dns).await?;
    stream.write_all(&request).await.map_err(EgressFailure::Io)?;
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await.map_err(EgressFailure::Io)?;
    if head[0] != 5 || head[2] != 0 {
        return Err(EgressFailure::MalformedResponse);
    }
    if head[1] != 0 {
        return Err(EgressFailure::Socks5Reply);
    }
    consume_socks5_address(stream, head[3]).await
}

async fn authenticate_socks5<S: AsyncIo + ?Sized>(
    stream: &mut S,
    credentials: &ProxyCredentials,
) -> Result<(), EgressFailure> {
    let username = credentials.username.expose().as_bytes();
    let password = credentials.password.expose().as_bytes();
    if username.is_empty() || username.len() > usize::from(u8::MAX) || password.len() > usize::from(u8::MAX) {
        return Err(EgressFailure::InvalidConfig);
    }
    let mut request = Zeroizing::new(vec![
        1,
        u8::try_from(username.len()).map_err(|_| EgressFailure::InvalidConfig)?,
    ]);
    request.extend_from_slice(username);
    request.push(u8::try_from(password.len()).map_err(|_| EgressFailure::InvalidConfig)?);
    request.extend_from_slice(password);
    stream.write_all(&request).await.map_err(EgressFailure::Io)?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await.map_err(EgressFailure::Io)?;
    if response != [1, 0] {
        return Err(EgressFailure::AuthenticationRejected);
    }
    Ok(())
}

async fn append_socks5_address(
    request: &mut Vec<u8>,
    host: &str,
    port: u16,
    dns: Socks5DnsMode,
) -> Result<(), EgressFailure> {
    match dns {
        Socks5DnsMode::Remote => {
            validate_target(host, port)?;
            request.push(3);
            request.push(u8::try_from(host.len()).map_err(|_| EgressFailure::InvalidConfig)?);
            request.extend_from_slice(host.as_bytes());
        }
        Socks5DnsMode::Local => {
            let address = lookup_host((host, port))
                .await
                .map_err(EgressFailure::Io)?
                .next()
                .ok_or(EgressFailure::DnsEmpty)?
                .ip();
            match address {
                IpAddr::V4(address) => {
                    request.push(1);
                    request.extend_from_slice(&address.octets());
                }
                IpAddr::V6(address) => {
                    request.push(4);
                    request.extend_from_slice(&address.octets());
                }
            }
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

async fn consume_socks5_address<S: AsyncIo + ?Sized>(stream: &mut S, kind: u8) -> Result<(), EgressFailure> {
    let address_bytes = match kind {
        1 => 4,
        4 => 16,
        3 => usize::from(stream.read_u8().await.map_err(EgressFailure::Io)?),
        _ => return Err(EgressFailure::MalformedResponse),
    };
    let mut remainder = vec![0_u8; address_bytes + 2];
    stream.read_exact(&mut remainder).await.map_err(EgressFailure::Io)?;
    Ok(())
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Debug)]
enum EgressFailure {
    Timeout,
    InvalidConfig,
    AuthenticationRejected,
    HttpStatus,
    MalformedResponse,
    Socks5Reply,
    DnsEmpty,
    ProxyTlsHandshake,
    ProxyTlsCertificate,
    Io(io::Error),
}

fn egress_error(failure: EgressFailure, proxy: bool) -> TransportError {
    let (code, diagnostic, health_effect) = match failure {
        EgressFailure::AuthenticationRejected => (
            TransportErrorCode::ProxyAuthentication,
            "proxy_authentication",
            HealthEffect::QuarantineEgress,
        ),
        EgressFailure::MalformedResponse | EgressFailure::HttpStatus | EgressFailure::Socks5Reply => (
            TransportErrorCode::ProxyProtocol,
            "proxy_protocol",
            HealthEffect::TransientFailure,
        ),
        EgressFailure::ProxyTlsHandshake => (
            TransportErrorCode::TlsHandshake,
            "proxy_tls_handshake",
            HealthEffect::TransientFailure,
        ),
        EgressFailure::ProxyTlsCertificate => (
            TransportErrorCode::TlsCertificate,
            "proxy_tls_certificate",
            HealthEffect::QuarantineEgress,
        ),
        EgressFailure::DnsEmpty => (
            TransportErrorCode::ResolverFailure,
            "egress_dns_empty",
            HealthEffect::TransientFailure,
        ),
        EgressFailure::Timeout => (
            TransportErrorCode::Timeout,
            "egress_timeout",
            HealthEffect::TransientFailure,
        ),
        EgressFailure::InvalidConfig => (
            TransportErrorCode::InternalInvariant,
            "egress_configuration",
            HealthEffect::QuarantineEgress,
        ),
        EgressFailure::Io(error) => {
            let _ = error.kind();
            (
                TransportErrorCode::TcpConnectFailure,
                "egress_io",
                HealthEffect::TransientFailure,
            )
        }
    };
    TransportError {
        code,
        phase: if proxy {
            TransportPhase::ProxyTunnel
        } else {
            TransportPhase::TcpConnect
        },
        attribution_domain: if proxy {
            AttributionDomain::Proxy
        } else {
            AttributionDomain::DirectEgress
        },
        failure_scope: FailureScope::Egress,
        retry_safety: RetrySafety::SafeBeforeSubmission,
        upstream_request_bytes_written: 0,
        upstream_submission_complete: false,
        connection_disposition: ConnectionDisposition::CloseConnection,
        health_effect,
        diagnostic: diagnostic.into(),
    }
}

fn cancelled() -> TransportError {
    TransportError {
        code: TransportErrorCode::Cancelled,
        phase: TransportPhase::TcpConnect,
        attribution_domain: AttributionDomain::Cancellation,
        failure_scope: FailureScope::Attempt,
        retry_safety: RetrySafety::SafeBeforeSubmission,
        upstream_request_bytes_written: 0,
        upstream_submission_complete: false,
        connection_disposition: ConnectionDisposition::CloseConnection,
        health_effect: HealthEffect::None,
        diagnostic: "cancelled_egress".into(),
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::sync::Arc;

    use gateway_domain::{EgressRouteSnapshot, ProxyCredentials, SecretValue};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };
    use tokio_util::sync::CancellationToken;

    use super::EgressDialer;

    #[tokio::test]
    async fn connect_auth_is_sent_only_to_proxy_and_tunnel_bytes_remain_raw() {
        let proxy = match TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(proxy) => proxy,
            Err(error) => std::panic::panic_any(error),
        };
        let address = match proxy.local_addr() {
            Ok(address) => address,
            Err(error) => std::panic::panic_any(error),
        };
        let server = tokio::spawn(async move {
            let (mut stream, _) = match proxy.accept().await {
                Ok(value) => value,
                Err(error) => std::panic::panic_any(error),
            };
            let head = super::read_http_head(&mut stream, 16 * 1024).await.unwrap_or_default();
            assert!(String::from_utf8_lossy(&head).contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
            assert!(
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_ok()
            );
            let mut payload = [0_u8; 4];
            assert!(stream.read_exact(&mut payload).await.is_ok());
            assert_eq!(&payload, b"ping");
        });
        let route = EgressRouteSnapshot::HttpConnect {
            host: address.ip().to_string().into_boxed_str(),
            port: address.port(),
            credentials: Some(Arc::new(ProxyCredentials {
                username: SecretValue::new("user".to_owned()),
                password: SecretValue::new("pass".to_owned()),
            })),
        };
        let stream = EgressDialer
            .dial(
                &route,
                "api.anthropic.com",
                443,
                std::time::Duration::from_secs(2),
                &CancellationToken::new(),
            )
            .await;
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(error) => std::panic::panic_any(error),
        };
        assert!(stream.write_all(b"ping").await.is_ok());
        assert!(server.await.is_ok());
    }

    #[cfg(feature = "boring-backend")]
    #[tokio::test]
    async fn https_proxy_never_sends_connect_before_proxy_tls() {
        let proxy = match TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(proxy) => proxy,
            Err(error) => std::panic::panic_any(error),
        };
        let address = match proxy.local_addr() {
            Ok(address) => address,
            Err(error) => std::panic::panic_any(error),
        };
        let server = tokio::spawn(async move {
            let (mut stream, _) = match proxy.accept().await {
                Ok(value) => value,
                Err(error) => std::panic::panic_any(error),
            };
            let mut hello = [0_u8; 5];
            assert!(stream.read_exact(&mut hello).await.is_ok());
            // A TLS handshake record, never a plaintext CONNECT carrying credentials.
            assert_eq!(hello[0], 0x16);
            assert!(!hello.starts_with(b"CONNE"));
            assert!(stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await.is_ok());
        });
        let route = EgressRouteSnapshot::HttpsConnect {
            host: "localhost".into(),
            port: address.port(),
            credentials: Some(Arc::new(ProxyCredentials {
                username: SecretValue::new("user".to_owned()),
                password: SecretValue::new("pass".to_owned()),
            })),
        };
        let Err(error) = EgressDialer
            .dial(
                &route,
                "api.anthropic.com",
                443,
                std::time::Duration::from_secs(5),
                &CancellationToken::new(),
            )
            .await
        else {
            std::panic::panic_any("plaintext proxy must not complete an HTTPS proxy handshake");
        };
        assert_eq!(error.code, crate::TransportErrorCode::TlsHandshake);
        assert_eq!(error.diagnostic.as_ref(), "proxy_tls_handshake");
        assert!(server.await.is_ok());
    }

    #[tokio::test]
    async fn direct_failure_falls_back_to_relay_chain() {
        // 主代理端口拒绝所有连接,模拟直连不可达;中继为 SOCKS5 服务器,
        // 拨号器应自动经中继建立到主代理的隧道并完成第二跳 CONNECT。
        let primary = match TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(primary) => primary,
            Err(error) => std::panic::panic_any(error),
        };
        let primary_address = match primary.local_addr() {
            Ok(address) => address,
            Err(error) => std::panic::panic_any(error),
        };
        let relay = match TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(relay) => relay,
            Err(error) => std::panic::panic_any(error),
        };
        let relay_address = match relay.local_addr() {
            Ok(address) => address,
            Err(error) => std::panic::panic_any(error),
        };
        // 中继期望对端发起 CONNECT primary_address:port,完成后允许第二跳写入。
        let relay_server = tokio::spawn(async move {
            let (mut stream, _) = match relay.accept().await {
                Ok(value) => value,
                Err(error) => std::panic::panic_any(error),
            };
            let head = super::read_http_head(&mut stream, 16 * 1024).await.unwrap_or_default();
            let request = String::from_utf8_lossy(&head);
            let authority = format!("{primary_address}");
            assert!(
                request.starts_with(&format!("CONNECT {authority} ")),
                "relay must receive CONNECT to the primary endpoint, got {request}"
            );
            assert!(
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_ok()
            );
            // 第二跳:主代理在隧道内发起 SOCKS5 握手到 api.anthropic.com:443。
            let mut greeting = [0_u8; 3];
            assert!(stream.read_exact(&mut greeting).await.is_ok());
            assert_eq!(&greeting, &[5, 1, 0]);
            let mut destination = [0_u8; 24];
            assert!(stream.read_exact(&mut destination).await.is_ok());
            assert_eq!(&destination[..7], &[5, 1, 0, 3, 16]);
            assert_eq!(&destination[7..23], b"api.anthropic.com");
            assert!(stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_ok());
            let mut payload = [0_u8; 4];
            assert!(stream.read_exact(&mut payload).await.is_ok());
            assert_eq!(&payload, b"pong");
        });
        let _primary_guard = primary; // 保持主端口监听以稳定拒绝连接
        let route = EgressRouteSnapshot::WithRelay {
            primary: Box::new(
                ProxyHop::from_row(
                    "http_connect",
                    format!("127.0.0.1").into_boxed_str(),
                    primary_address.port(),
                    None,
                )
                .unwrap_or_else(|| std::process::abort()),
            ),
            relay: Box::new(
                ProxyHop::from_row("socks5", "127.0.0.1".into(), relay_address.port(), None)
                    .unwrap_or_else(|| std::process::abort()),
            ),
        };
        let stream = EgressDialer
            .dial(
                &route,
                "api.anthropic.com",
                443,
                std::time::Duration::from_secs(5),
                &CancellationToken::new(),
            )
            .await;
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(error) => std::panic::panic_any(error),
        };
        assert!(stream.write_all(b"pong").await.is_ok());
        assert!(relay_server.await.is_ok());
    }
}
