use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{fmt, io, net::IpAddr, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, lookup_host},
};

use crate::boring_backend::DialEndpoint;

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub type BoxedIo = Box<dyn AsyncIo>;

#[derive(Clone, PartialEq, Eq)]
pub struct ProxyCredentials {
    username: String,
    password: String,
}

impl ProxyCredentials {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }

    fn valid_for_socks5(&self) -> bool {
        !self.username.is_empty()
            && self.username.len() <= u8::MAX.into()
            && self.password.len() <= u8::MAX.into()
    }
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProxyCredentials([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socks5Dns {
    Local,
    Remote,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyRoute {
    HttpConnect {
        endpoint: DialEndpoint,
        credentials: Option<ProxyCredentials>,
    },
    Socks5 {
        endpoint: DialEndpoint,
        dns: Socks5Dns,
        credentials: Option<ProxyCredentials>,
    },
}

impl ProxyRoute {
    pub fn is_valid(&self) -> bool {
        let (endpoint, credentials, socks5) = match self {
            Self::HttpConnect {
                endpoint,
                credentials,
            } => (endpoint, credentials, false),
            Self::Socks5 {
                endpoint,
                credentials,
                ..
            } => (endpoint, credentials, true),
        };
        !endpoint.host.is_empty()
            && endpoint.port != 0
            && !endpoint.host.contains(|character: char| {
                character.is_whitespace() || matches!(character, '/' | '\\' | '@')
            })
            && (!socks5
                || credentials
                    .as_ref()
                    .is_none_or(ProxyCredentials::valid_for_socks5))
    }

    fn endpoint(&self) -> &DialEndpoint {
        match self {
            Self::HttpConnect { endpoint, .. } | Self::Socks5 { endpoint, .. } => endpoint,
        }
    }
}

#[derive(Debug, Error)]
pub enum EgressError {
    #[error("egress operation timed out")]
    Timeout,
    #[error("egress configuration is invalid")]
    InvalidConfig,
    #[error("proxy authentication was rejected")]
    AuthenticationRejected,
    #[error("HTTP CONNECT proxy rejected tunnel with status {0}")]
    HttpStatus(u16),
    #[error("proxy returned a malformed protocol response")]
    MalformedResponse,
    #[error("SOCKS5 proxy rejected tunnel with code {0}")]
    Socks5Reply(u8),
    #[error("egress DNS lookup returned no address")]
    DnsEmpty,
    #[error("egress I/O failed: {0}")]
    Io(#[source] io::Error),
}

impl EgressError {
    pub const fn stage(&self) -> &'static str {
        match self {
            Self::Timeout => "egress_timeout",
            Self::InvalidConfig => "egress_configuration",
            Self::AuthenticationRejected => "proxy_authentication",
            Self::HttpStatus(_) | Self::Socks5Reply(_) => "proxy_rejected",
            Self::MalformedResponse => "proxy_protocol",
            Self::DnsEmpty => "egress_dns",
            Self::Io(_) => "egress_io",
        }
    }
}

pub async fn open_egress(
    target_host: &str,
    target_port: u16,
    dial_override: Option<&DialEndpoint>,
    proxy: Option<&ProxyRoute>,
    timeout: Duration,
) -> Result<(BoxedIo, String), EgressError> {
    if target_host.is_empty() || target_port == 0 || timeout.is_zero() {
        return Err(EgressError::InvalidConfig);
    }
    tokio::time::timeout(
        timeout,
        open_inner(target_host, target_port, dial_override, proxy),
    )
    .await
    .map_err(|_| EgressError::Timeout)?
}

async fn open_inner(
    target_host: &str,
    target_port: u16,
    dial_override: Option<&DialEndpoint>,
    proxy: Option<&ProxyRoute>,
) -> Result<(BoxedIo, String), EgressError> {
    let endpoint = if let Some(proxy) = proxy {
        proxy.endpoint()
    } else if let Some(override_endpoint) = dial_override {
        override_endpoint
    } else {
        let stream = TcpStream::connect((target_host, target_port))
            .await
            .map_err(EgressError::Io)?;
        let family = network_family(&stream)?;
        return Ok((Box::new(stream), family));
    };
    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .map_err(EgressError::Io)?;
    let family = network_family(&stream)?;
    if let Some(proxy) = proxy {
        match proxy {
            ProxyRoute::HttpConnect { credentials, .. } => {
                http_connect(&mut stream, target_host, target_port, credentials.as_ref()).await?;
            }
            ProxyRoute::Socks5 {
                dns, credentials, ..
            } => {
                socks5_connect(
                    &mut stream,
                    target_host,
                    target_port,
                    *dns,
                    credentials.as_ref(),
                )
                .await?;
            }
        }
    }
    Ok((Box::new(stream), family))
}

fn network_family(stream: &TcpStream) -> Result<String, EgressError> {
    let peer = stream.peer_addr().map_err(EgressError::Io)?;
    Ok(if peer.is_ipv4() { "ipv4" } else { "ipv6" }.to_owned())
}

async fn http_connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    credentials: Option<&ProxyCredentials>,
) -> Result<(), EgressError> {
    let authority = format_authority(host, port);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(credentials) = credentials {
        let encoded = STANDARD.encode(format!("{}:{}", credentials.username, credentials.password));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&encoded);
        request.push_str("\r\n");
    }
    request.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(EgressError::Io)?;
    let response = read_http_head(stream, 16 * 1024).await?;
    let status = parse_http_status(&response)?;
    if status == 407 {
        return Err(EgressError::AuthenticationRejected);
    }
    if status != 200 {
        return Err(EgressError::HttpStatus(status));
    }
    Ok(())
}

async fn read_http_head(stream: &mut TcpStream, limit: usize) -> Result<Vec<u8>, EgressError> {
    let mut response = Vec::with_capacity(512);
    while response.len() < limit {
        let byte = stream.read_u8().await.map_err(EgressError::Io)?;
        response.push(byte);
        if response.ends_with(b"\r\n\r\n") {
            return Ok(response);
        }
    }
    Err(EgressError::MalformedResponse)
}

fn parse_http_status(response: &[u8]) -> Result<u16, EgressError> {
    let line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(EgressError::MalformedResponse)?;
    let line =
        std::str::from_utf8(&response[..line_end]).map_err(|_| EgressError::MalformedResponse)?;
    let mut parts = line.split_ascii_whitespace();
    let version = parts.next().ok_or(EgressError::MalformedResponse)?;
    let status = parts
        .next()
        .ok_or(EgressError::MalformedResponse)?
        .parse::<u16>()
        .map_err(|_| EgressError::MalformedResponse)?;
    if !version.starts_with("HTTP/1.") {
        return Err(EgressError::MalformedResponse);
    }
    Ok(status)
}

async fn socks5_connect(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    dns: Socks5Dns,
    credentials: Option<&ProxyCredentials>,
) -> Result<(), EgressError> {
    let methods: &[u8] = if credentials.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let method_count = u8::try_from(methods.len()).map_err(|_| EgressError::InvalidConfig)?;
    stream
        .write_all(&[0x05, method_count])
        .await
        .map_err(EgressError::Io)?;
    stream.write_all(methods).await.map_err(EgressError::Io)?;
    let mut selection = [0_u8; 2];
    stream
        .read_exact(&mut selection)
        .await
        .map_err(EgressError::Io)?;
    if selection[0] != 0x05 || selection[1] == 0xff {
        return Err(EgressError::AuthenticationRejected);
    }
    match selection[1] {
        0x00 => {}
        0x02 => {
            authenticate_socks5(
                stream,
                credentials.ok_or(EgressError::AuthenticationRejected)?,
            )
            .await?;
        }
        _ => return Err(EgressError::MalformedResponse),
    }
    let mut request = vec![0x05, 0x01, 0x00];
    append_socks5_address(&mut request, host, port, dns).await?;
    stream.write_all(&request).await.map_err(EgressError::Io)?;
    let mut head = [0_u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(EgressError::Io)?;
    if head[0] != 0x05 || head[2] != 0x00 {
        return Err(EgressError::MalformedResponse);
    }
    if head[1] != 0x00 {
        return Err(EgressError::Socks5Reply(head[1]));
    }
    consume_socks5_address(stream, head[3]).await?;
    Ok(())
}

async fn authenticate_socks5(
    stream: &mut TcpStream,
    credentials: &ProxyCredentials,
) -> Result<(), EgressError> {
    if !credentials.valid_for_socks5() {
        return Err(EgressError::InvalidConfig);
    }
    let username_length =
        u8::try_from(credentials.username.len()).map_err(|_| EgressError::InvalidConfig)?;
    let password_length =
        u8::try_from(credentials.password.len()).map_err(|_| EgressError::InvalidConfig)?;
    let mut request = vec![0x01, username_length];
    request.extend_from_slice(credentials.username.as_bytes());
    request.push(password_length);
    request.extend_from_slice(credentials.password.as_bytes());
    stream.write_all(&request).await.map_err(EgressError::Io)?;
    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .await
        .map_err(EgressError::Io)?;
    if response != [0x01, 0x00] {
        return Err(EgressError::AuthenticationRejected);
    }
    Ok(())
}

async fn append_socks5_address(
    request: &mut Vec<u8>,
    host: &str,
    port: u16,
    dns: Socks5Dns,
) -> Result<(), EgressError> {
    match dns {
        Socks5Dns::Remote => {
            let length = u8::try_from(host.len()).map_err(|_| EgressError::InvalidConfig)?;
            request.push(0x03);
            request.push(length);
            request.extend_from_slice(host.as_bytes());
        }
        Socks5Dns::Local => {
            let address = lookup_host((host, port))
                .await
                .map_err(EgressError::Io)?
                .next()
                .ok_or(EgressError::DnsEmpty)?
                .ip();
            match address {
                IpAddr::V4(address) => {
                    request.push(0x01);
                    request.extend_from_slice(&address.octets());
                }
                IpAddr::V6(address) => {
                    request.push(0x04);
                    request.extend_from_slice(&address.octets());
                }
            }
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

async fn consume_socks5_address(stream: &mut TcpStream, kind: u8) -> Result<(), EgressError> {
    let address_bytes = match kind {
        0x01 => 4,
        0x04 => 16,
        0x03 => usize::from(stream.read_u8().await.map_err(EgressError::Io)?),
        _ => return Err(EgressError::MalformedResponse),
    };
    let mut remainder = vec![0_u8; address_bytes + 2];
    stream
        .read_exact(&mut remainder)
        .await
        .map_err(EgressError::Io)?;
    Ok(())
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn credentials_debug_is_redacted() {
        let credentials = ProxyCredentials::new("user".to_owned(), "secret".to_owned());
        let output = format!("{credentials:?}");
        assert!(!output.contains("user"));
        assert!(!output.contains("secret"));
    }

    #[test]
    fn formats_ipv6_connect_authority() {
        assert_eq!(format_authority("::1", 443), "[::1]:443");
    }

    #[tokio::test]
    async fn http_connect_auth_stays_outside_tunnel() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target address");
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("target accept");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.expect("target read");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.expect("target write");
        });
        let proxy = TcpListener::bind(("127.0.0.1", 0)).await.expect("proxy");
        let proxy_addr = proxy.local_addr().expect("proxy address");
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy.accept().await.expect("proxy accept");
            let head = read_http_head(&mut client, 16 * 1024)
                .await
                .expect("CONNECT head");
            let text = String::from_utf8(head).expect("ASCII CONNECT");
            assert!(text.starts_with("CONNECT 127.0.0.1:"));
            assert!(text.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            let mut upstream = TcpStream::connect(target_addr).await.expect("upstream");
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .expect("CONNECT response");
            tokio::io::copy_bidirectional(&mut client, &mut upstream)
                .await
                .expect("tunnel copy");
        });
        let route = ProxyRoute::HttpConnect {
            endpoint: DialEndpoint {
                host: proxy_addr.ip().to_string(),
                port: proxy_addr.port(),
            },
            credentials: Some(ProxyCredentials::new("user".to_owned(), "pass".to_owned())),
        };
        let (mut tunnel, _) = open_egress(
            "127.0.0.1",
            target_addr.port(),
            None,
            Some(&route),
            Duration::from_secs(2),
        )
        .await
        .expect("open CONNECT");
        tunnel.write_all(b"ping").await.expect("tunnel write");
        let mut response = [0_u8; 4];
        tunnel.read_exact(&mut response).await.expect("tunnel read");
        assert_eq!(&response, b"pong");
        drop(tunnel);
        proxy_task.await.expect("proxy task");
        target_task.await.expect("target task");
    }

    #[tokio::test]
    async fn http_connect_auth_rejection_has_dedicated_stage() {
        let proxy = TcpListener::bind(("127.0.0.1", 0)).await.expect("proxy");
        let proxy_addr = proxy.local_addr().expect("proxy address");
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy.accept().await.expect("proxy accept");
            let _ = read_http_head(&mut client, 16 * 1024)
                .await
                .expect("CONNECT head");
            client
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .expect("reject CONNECT");
        });
        let route = ProxyRoute::HttpConnect {
            endpoint: DialEndpoint {
                host: proxy_addr.ip().to_string(),
                port: proxy_addr.port(),
            },
            credentials: None,
        };
        let result = open_egress(
            "example.invalid",
            443,
            None,
            Some(&route),
            Duration::from_secs(2),
        )
        .await;
        let Err(error) = result else {
            panic!("407 must fail");
        };
        assert!(matches!(error, EgressError::AuthenticationRejected));
        assert_eq!(error.stage(), "proxy_authentication");
        proxy_task.await.expect("proxy task");
    }

    #[tokio::test]
    async fn socks5_supports_local_and_remote_dns_tunnels() {
        for dns in [Socks5Dns::Local, Socks5Dns::Remote] {
            run_socks5_echo(dns).await;
        }
    }

    async fn run_socks5_echo(dns: Socks5Dns) {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target address");
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("target accept");
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.expect("target read");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.expect("target write");
        });
        let proxy = TcpListener::bind(("127.0.0.1", 0)).await.expect("proxy");
        let proxy_addr = proxy.local_addr().expect("proxy address");
        let proxy_task = tokio::spawn(async move {
            let (mut client, _) = proxy.accept().await.expect("proxy accept");
            let mut greeting = [0_u8; 2];
            client.read_exact(&mut greeting).await.expect("greeting");
            let mut methods = vec![0_u8; usize::from(greeting[1])];
            client.read_exact(&mut methods).await.expect("methods");
            client.write_all(&[0x05, 0x00]).await.expect("method");
            let mut head = [0_u8; 4];
            client.read_exact(&mut head).await.expect("request head");
            let expected_atyp = if dns == Socks5Dns::Local { 0x01 } else { 0x03 };
            assert_eq!(head[3], expected_atyp);
            consume_socks5_address(&mut client, head[3])
                .await
                .expect("request address");
            let mut upstream = TcpStream::connect(target_addr).await.expect("upstream");
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .expect("SOCKS response");
            tokio::io::copy_bidirectional(&mut client, &mut upstream)
                .await
                .expect("SOCKS tunnel");
        });
        let route = ProxyRoute::Socks5 {
            endpoint: DialEndpoint {
                host: proxy_addr.ip().to_string(),
                port: proxy_addr.port(),
            },
            dns,
            credentials: None,
        };
        let (mut tunnel, _) = open_egress(
            "127.0.0.1",
            target_addr.port(),
            None,
            Some(&route),
            Duration::from_secs(2),
        )
        .await
        .expect("open SOCKS5");
        tunnel.write_all(b"ping").await.expect("tunnel write");
        let mut response = [0_u8; 4];
        tunnel.read_exact(&mut response).await.expect("tunnel read");
        assert_eq!(&response, b"pong");
        drop(tunnel);
        proxy_task.await.expect("proxy task");
        target_task.await.expect("target task");
    }
}
