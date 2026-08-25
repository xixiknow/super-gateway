#![forbid(unsafe_code)]

use capture_schema::{TlsAttributeObservation, TlsExtensionObservation};
use std::{fmt, net::SocketAddr, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
const CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 1;
const TLS_RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsTapConfig {
    pub listen: SocketAddr,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub max_capture_bytes: usize,
    pub session_timeout: Duration,
}

#[derive(Debug)]
pub struct TlsTapListener {
    listener: TcpListener,
    config: TlsTapConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectTlsTapConfig {
    pub listen: SocketAddr,
    pub allowed_host: String,
    pub allowed_port: u16,
    pub max_connect_header_bytes: usize,
    pub max_capture_bytes: usize,
    pub session_timeout: Duration,
    pub upstream_http_proxy: Option<UpstreamHttpProxy>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamHttpProxy {
    pub host: String,
    pub port: u16,
    pub authorization: Option<String>,
}

impl fmt::Debug for UpstreamHttpProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamHttpProxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug)]
pub struct ConnectTlsTapListener {
    listener: TcpListener,
    config: ConnectTlsTapConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedClientHello {
    pub record_version: u16,
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<TlsExtensionObservation>,
    pub alpn: Vec<String>,
    pub client_hello_len: u32,
    pub record_lengths: Vec<u32>,
}

impl TlsTapListener {
    /// Binds a one-shot pass-through tap.
    ///
    /// # Errors
    ///
    /// Returns [`TlsTapError`] when the listener configuration or bind fails.
    pub async fn bind(config: TlsTapConfig) -> Result<Self, TlsTapError> {
        validate_config(&config)?;
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(TlsTapError::Io)?;
        Ok(Self { listener, config })
    }

    /// Returns the actual listener address, including an ephemeral port.
    ///
    /// # Errors
    ///
    /// Returns [`TlsTapError`] when the socket address cannot be read.
    pub fn local_addr(&self) -> Result<SocketAddr, TlsTapError> {
        self.listener.local_addr().map_err(TlsTapError::Io)
    }

    /// Proxies exactly one TCP connection and returns only the bounded
    /// client-to-server prefix needed to parse `ClientHello`.
    ///
    /// # Errors
    ///
    /// Returns [`TlsTapError`] for accept/connect/forwarding failure or timeout.
    pub async fn capture_one(self) -> Result<Vec<u8>, TlsTapError> {
        let timeout = self.config.session_timeout;
        tokio::time::timeout(timeout, Box::pin(self.capture_one_inner()))
            .await
            .map_err(|_| TlsTapError::Timeout)?
    }

    async fn capture_one_inner(self) -> Result<Vec<u8>, TlsTapError> {
        let (client, _) = self.listener.accept().await.map_err(TlsTapError::Io)?;
        let upstream = TcpStream::connect((
            self.config.upstream_host.as_str(),
            self.config.upstream_port,
        ))
        .await
        .map_err(TlsTapError::Io)?;
        Box::pin(forward_and_capture(
            client,
            upstream,
            self.config.max_capture_bytes,
        ))
        .await
    }
}

impl ConnectTlsTapListener {
    /// Binds a one-shot HTTP CONNECT proxy that permits exactly one configured
    /// upstream authority and captures the tunneled TLS `ClientHello` prefix.
    ///
    /// # Errors
    ///
    /// Returns [`TlsTapError`] when configuration or listener binding fails.
    pub async fn bind(config: ConnectTlsTapConfig) -> Result<Self, TlsTapError> {
        validate_connect_config(&config)?;
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(TlsTapError::Io)?;
        Ok(Self { listener, config })
    }

    /// Returns the actual listener address.
    ///
    /// # Errors
    ///
    /// Returns [`TlsTapError`] when socket metadata lookup fails.
    pub fn local_addr(&self) -> Result<SocketAddr, TlsTapError> {
        self.listener.local_addr().map_err(TlsTapError::Io)
    }

    /// Accepts one CONNECT tunnel, verifies its authority, and captures the
    /// tunneled TLS prefix while forwarding all bytes unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`TlsTapError`] for timeout, invalid CONNECT, unexpected target,
    /// upstream connection failure, or bidirectional forwarding failure.
    pub async fn capture_one(self) -> Result<Vec<u8>, TlsTapError> {
        self.capture_allowed(0).await
    }

    /// Rejects a bounded number of unrelated CONNECT targets before capturing
    /// the configured upstream. This lets a real CLI finish harmless startup
    /// telemetry without letting the tap become an open proxy.
    ///
    /// # Errors
    ///
    /// Returns [`TlsTapError`] for timeout, malformed CONNECT requests, too many
    /// rejected targets, upstream connection failure, or forwarding failure.
    pub async fn capture_allowed(
        self,
        max_rejected_tunnels: usize,
    ) -> Result<Vec<u8>, TlsTapError> {
        let timeout = self.config.session_timeout;
        tokio::time::timeout(
            timeout,
            Box::pin(self.capture_one_inner(max_rejected_tunnels)),
        )
        .await
        .map_err(|_| TlsTapError::Timeout)?
    }

    async fn capture_one_inner(self, max_rejected_tunnels: usize) -> Result<Vec<u8>, TlsTapError> {
        let mut rejected_tunnels = 0_usize;
        loop {
            let (mut client, _) = self.listener.accept().await.map_err(TlsTapError::Io)?;
            let head = read_connect_head(&mut client, self.config.max_connect_header_bytes).await?;
            let (host, port) = parse_connect_authority(&head)?;
            if !host.eq_ignore_ascii_case(&self.config.allowed_host)
                || port != self.config.allowed_port
            {
                client
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                    .await
                    .map_err(TlsTapError::Io)?;
                if rejected_tunnels >= max_rejected_tunnels {
                    return Err(TlsTapError::UnexpectedConnectAuthority { host, port });
                }
                rejected_tunnels += 1;
                continue;
            }
            let upstream = connect_allowed_upstream(&self.config).await?;
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .map_err(TlsTapError::Io)?;
            return Box::pin(forward_and_capture(
                client,
                upstream,
                self.config.max_capture_bytes,
            ))
            .await;
        }
    }
}

async fn connect_allowed_upstream(config: &ConnectTlsTapConfig) -> Result<TcpStream, TlsTapError> {
    let Some(proxy) = &config.upstream_http_proxy else {
        return TcpStream::connect((config.allowed_host.as_str(), config.allowed_port))
            .await
            .map_err(TlsTapError::Io);
    };
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(TlsTapError::Io)?;
    let authority = format_authority(&config.allowed_host, config.allowed_port);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(authorization) = &proxy.authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    request.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(TlsTapError::Io)?;
    let response = read_connect_head(&mut stream, config.max_connect_header_bytes).await?;
    let status = parse_connect_response_status(&response)?;
    if status != 200 {
        return Err(TlsTapError::UpstreamProxyStatus(status));
    }
    Ok(stream)
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn parse_connect_response_status(head: &[u8]) -> Result<u16, TlsTapError> {
    let line_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(TlsTapError::InvalidUpstreamProxyResponse)?;
    let line = std::str::from_utf8(&head[..line_end])
        .map_err(|_| TlsTapError::InvalidUpstreamProxyResponse)?;
    let mut parts = line.split_ascii_whitespace();
    let version = parts
        .next()
        .ok_or(TlsTapError::InvalidUpstreamProxyResponse)?;
    if !version.starts_with("HTTP/1.") {
        return Err(TlsTapError::InvalidUpstreamProxyResponse);
    }
    parts
        .next()
        .ok_or(TlsTapError::InvalidUpstreamProxyResponse)?
        .parse()
        .map_err(|_| TlsTapError::InvalidUpstreamProxyResponse)
}

async fn forward_and_capture(
    client: TcpStream,
    upstream: TcpStream,
    max_capture_bytes: usize,
) -> Result<Vec<u8>, TlsTapError> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let client_to_upstream = async move {
        let mut captured = Vec::with_capacity(max_capture_bytes.min(16 * 1024));
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = match client_read.read(&mut buffer).await {
                Ok(read) => read,
                Err(error) if !captured.is_empty() && is_terminal_tunnel_error(&error) => {
                    return Ok::<_, TlsTapError>(captured);
                }
                Err(error) => return Err(TlsTapError::Io(error)),
            };
            if read == 0 {
                if let Err(error) = upstream_write.shutdown().await
                    && !is_terminal_tunnel_error(&error)
                {
                    return Err(TlsTapError::Io(error));
                }
                return Ok::<_, TlsTapError>(captured);
            }
            if captured.len() < max_capture_bytes {
                let remaining = max_capture_bytes - captured.len();
                captured.extend_from_slice(&buffer[..read.min(remaining)]);
            }
            if let Err(error) = upstream_write.write_all(&buffer[..read]).await {
                if !captured.is_empty() && is_terminal_tunnel_error(&error) {
                    return Ok(captured);
                }
                return Err(TlsTapError::Io(error));
            }
        }
    };
    let upstream_to_client = async move {
        if let Err(error) = tokio::io::copy(&mut upstream_read, &mut client_write).await
            && !is_terminal_tunnel_error(&error)
        {
            return Err(TlsTapError::Io(error));
        }
        if let Err(error) = client_write.shutdown().await
            && !is_terminal_tunnel_error(&error)
        {
            return Err(TlsTapError::Io(error));
        }
        Ok(())
    };
    let (captured, reverse) = tokio::join!(client_to_upstream, upstream_to_client);
    reverse?;
    captured
}

fn is_terminal_tunnel_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
}

async fn read_connect_head(
    client: &mut TcpStream,
    max_header_bytes: usize,
) -> Result<Vec<u8>, TlsTapError> {
    let mut head = Vec::with_capacity(max_header_bytes.min(1024));
    while head.len() < max_header_bytes {
        let byte = client.read_u8().await.map_err(TlsTapError::Io)?;
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    Err(TlsTapError::ConnectHeaderTooLarge)
}

fn parse_connect_authority(head: &[u8]) -> Result<(String, u16), TlsTapError> {
    let line_end = head
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(TlsTapError::InvalidConnectRequest)?;
    let line =
        std::str::from_utf8(&head[..line_end]).map_err(|_| TlsTapError::InvalidConnectRequest)?;
    let mut parts = line.split_ascii_whitespace();
    if parts.next() != Some("CONNECT") {
        return Err(TlsTapError::InvalidConnectRequest);
    }
    let authority = parts.next().ok_or(TlsTapError::InvalidConnectRequest)?;
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(TlsTapError::InvalidConnectRequest);
    }
    let (host, port) = split_authority(authority)?;
    Ok((host.to_owned(), port))
}

fn split_authority(authority: &str) -> Result<(&str, u16), TlsTapError> {
    if authority.contains(['/', '\\', '@']) {
        return Err(TlsTapError::InvalidConnectRequest);
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or(TlsTapError::InvalidConnectRequest)?;
        let host = &bracketed[..end];
        let port = bracketed[end + 1..]
            .strip_prefix(':')
            .ok_or(TlsTapError::InvalidConnectRequest)?;
        (host, port)
    } else {
        authority
            .rsplit_once(':')
            .ok_or(TlsTapError::InvalidConnectRequest)?
    };
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return Err(TlsTapError::InvalidConnectRequest);
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| TlsTapError::InvalidConnectRequest)?;
    if port == 0 {
        return Err(TlsTapError::InvalidConnectRequest);
    }
    Ok((host, port))
}

/// Parses the first TLS `ClientHello` without retaining randoms, keys, tickets,
/// hostnames, or other dynamic secret-bearing values.
///
/// # Errors
///
/// Returns [`TlsTapError`] when TLS records or `ClientHello` vectors are
/// truncated, malformed, or use unsupported framing.
pub fn parse_client_hello(input: &[u8]) -> Result<ParsedClientHello, TlsTapError> {
    let (handshake, record_version, record_lengths) = collect_handshake(input)?;
    if handshake.first().copied() != Some(CLIENT_HELLO_HANDSHAKE_TYPE) {
        return Err(TlsTapError::NotClientHello);
    }
    let declared_len = read_u24(&handshake[1..HANDSHAKE_HEADER_LEN])?;
    let message_len = HANDSHAKE_HEADER_LEN
        .checked_add(declared_len)
        .ok_or(TlsTapError::Malformed("ClientHello length overflow"))?;
    let message = handshake
        .get(..message_len)
        .ok_or(TlsTapError::Truncated("ClientHello message"))?;
    let mut cursor = Cursor::new(&message[HANDSHAKE_HEADER_LEN..]);
    let legacy_version = cursor.u16("legacy_version")?;
    cursor.take(32, "client_random")?;
    let session_id_len = usize::from(cursor.u8("session_id_length")?);
    cursor.take(session_id_len, "session_id")?;
    let cipher_bytes = usize::from(cursor.u16("cipher_suites_length")?);
    if cipher_bytes == 0 || cipher_bytes % 2 != 0 {
        return Err(TlsTapError::Malformed("cipher suite vector"));
    }
    let cipher_suites = cursor
        .take(cipher_bytes, "cipher_suites")?
        .chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .collect();
    let compression_len = usize::from(cursor.u8("compression_methods_length")?);
    cursor.take(compression_len, "compression_methods")?;
    let extensions_len = usize::from(cursor.u16("extensions_length")?);
    let extension_bytes = cursor.take(extensions_len, "extensions")?;
    if cursor.remaining() != 0 {
        return Err(TlsTapError::Malformed("trailing ClientHello bytes"));
    }
    let (extensions, alpn) = parse_extensions(extension_bytes)?;
    Ok(ParsedClientHello {
        record_version,
        legacy_version,
        cipher_suites,
        extensions,
        alpn,
        client_hello_len: u32::try_from(message_len)
            .map_err(|_| TlsTapError::Malformed("ClientHello too large"))?,
        record_lengths,
    })
}

fn validate_config(config: &TlsTapConfig) -> Result<(), TlsTapError> {
    if config.upstream_host.is_empty()
        || config.upstream_port == 0
        || config.max_capture_bytes < 512
        || config.session_timeout.is_zero()
    {
        return Err(TlsTapError::InvalidConfig);
    }
    Ok(())
}

fn validate_connect_config(config: &ConnectTlsTapConfig) -> Result<(), TlsTapError> {
    if config.allowed_host.is_empty()
        || config.allowed_host.contains(['/', '\\', '@'])
        || config.allowed_host.chars().any(char::is_whitespace)
        || config.allowed_port == 0
        || config.max_connect_header_bytes < 128
        || config.max_capture_bytes < 512
        || config.session_timeout.is_zero()
    {
        return Err(TlsTapError::InvalidConfig);
    }
    if let Some(proxy) = &config.upstream_http_proxy
        && (proxy.host.is_empty()
            || proxy.host.contains(['/', '\\', '@'])
            || proxy.host.chars().any(char::is_whitespace)
            || proxy.port == 0
            || proxy
                .authorization
                .as_ref()
                .is_some_and(|value| value.contains(['\r', '\n'])))
    {
        return Err(TlsTapError::InvalidConfig);
    }
    Ok(())
}

fn collect_handshake(input: &[u8]) -> Result<(Vec<u8>, u16, Vec<u32>), TlsTapError> {
    let mut offset = 0;
    let mut handshake = vec![];
    let mut record_version = None;
    let mut record_lengths = vec![];
    let mut expected_handshake_len = None;
    while offset < input.len() {
        let header = input
            .get(offset..offset + TLS_RECORD_HEADER_LEN)
            .ok_or(TlsTapError::Truncated("TLS record header"))?;
        let content_type = header[0];
        let version = u16::from_be_bytes([header[1], header[2]]);
        let payload_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let end = offset
            .checked_add(TLS_RECORD_HEADER_LEN + payload_len)
            .ok_or(TlsTapError::Malformed("TLS record length overflow"))?;
        let payload = input
            .get(offset + TLS_RECORD_HEADER_LEN..end)
            .ok_or(TlsTapError::Truncated("TLS record payload"))?;
        if content_type != TLS_HANDSHAKE_CONTENT_TYPE && handshake.is_empty() {
            return Err(TlsTapError::NotClientHello);
        }
        if content_type == TLS_HANDSHAKE_CONTENT_TYPE {
            record_version.get_or_insert(version);
            record_lengths.push(
                u32::try_from(TLS_RECORD_HEADER_LEN + payload_len)
                    .map_err(|_| TlsTapError::Malformed("TLS record too large"))?,
            );
            handshake.extend_from_slice(payload);
            if expected_handshake_len.is_none() && handshake.len() >= HANDSHAKE_HEADER_LEN {
                expected_handshake_len =
                    Some(HANDSHAKE_HEADER_LEN + read_u24(&handshake[1..HANDSHAKE_HEADER_LEN])?);
            }
            if expected_handshake_len.is_some_and(|expected| handshake.len() >= expected) {
                break;
            }
        }
        offset = end;
    }
    let expected = expected_handshake_len.ok_or(TlsTapError::Truncated("handshake header"))?;
    if handshake.len() < expected {
        return Err(TlsTapError::Truncated("ClientHello across TLS records"));
    }
    Ok((
        handshake,
        record_version.ok_or(TlsTapError::NotClientHello)?,
        record_lengths,
    ))
}

fn parse_extensions(
    input: &[u8],
) -> Result<(Vec<TlsExtensionObservation>, Vec<String>), TlsTapError> {
    let mut cursor = Cursor::new(input);
    let mut extensions = vec![];
    let mut alpn = vec![];
    while cursor.remaining() > 0 {
        let extension_type = cursor.u16("extension_type")?;
        let length = usize::from(cursor.u16("extension_length")?);
        let data = cursor.take(length, "extension_data")?;
        let position = u16::try_from(extensions.len())
            .map_err(|_| TlsTapError::Malformed("too many TLS extensions"))?;
        let (name, attributes) = extension_shape(extension_type, data, &mut alpn)?;
        extensions.push(TlsExtensionObservation {
            extension_type,
            name,
            position,
            encoded_len: u32::try_from(length)
                .map_err(|_| TlsTapError::Malformed("TLS extension too large"))?,
            attributes,
        });
    }
    Ok((extensions, alpn))
}

fn extension_shape(
    extension_type: u16,
    data: &[u8],
    alpn: &mut Vec<String>,
) -> Result<(String, Vec<TlsAttributeObservation>), TlsTapError> {
    let mut attributes = vec![];
    let name = match extension_type {
        0 => {
            let hostname_len = parse_server_name_length(data)?;
            attributes.push(TlsAttributeObservation {
                name: "hostname".to_owned(),
                value: "x".repeat(hostname_len),
                dynamic: true,
            });
            "server_name"
        }
        10 => {
            attributes.push(static_vector_attribute(
                "groups",
                parse_u16_vector(data, 2)?,
            ));
            "supported_groups"
        }
        13 => {
            attributes.push(static_vector_attribute(
                "signature_algorithms",
                parse_u16_vector(data, 2)?,
            ));
            "signature_algorithms"
        }
        16 => {
            *alpn = parse_alpn(data)?;
            "application_layer_protocol_negotiation"
        }
        21 => {
            attributes.push(TlsAttributeObservation {
                name: "padding_length".to_owned(),
                value: data.len().to_string(),
                dynamic: false,
            });
            "padding"
        }
        43 => {
            attributes.push(static_vector_attribute(
                "versions",
                parse_u16_vector(data, 1)?,
            ));
            "supported_versions"
        }
        51 => {
            attributes.push(TlsAttributeObservation {
                name: "key_share_shape".to_owned(),
                value: parse_key_share_shape(data)?,
                dynamic: false,
            });
            "key_share"
        }
        11 => "ec_point_formats",
        23 => "extended_master_secret",
        35 => "session_ticket",
        45 => "psk_key_exchange_modes",
        65_281 => "renegotiation_info",
        value if is_grease(value) => "grease",
        _ => "unknown",
    };
    Ok((name.to_owned(), attributes))
}

fn parse_server_name_length(data: &[u8]) -> Result<usize, TlsTapError> {
    let mut cursor = Cursor::new(data);
    let list_len = usize::from(cursor.u16("server_name list length")?);
    let names = cursor.take(list_len, "server_name list")?;
    if cursor.remaining() != 0 {
        return Err(TlsTapError::Malformed("trailing server_name bytes"));
    }
    let mut names = Cursor::new(names);
    while names.remaining() > 0 {
        let name_type = names.u8("server_name type")?;
        let name_len = usize::from(names.u16("server_name length")?);
        names.take(name_len, "server_name value")?;
        if name_type == 0 {
            return Ok(name_len);
        }
    }
    Err(TlsTapError::Malformed("server_name has no hostname"))
}

fn parse_u16_vector(data: &[u8], prefix_len: usize) -> Result<String, TlsTapError> {
    if data.len() < prefix_len {
        return Err(TlsTapError::Truncated("u16 vector length"));
    }
    let declared = match prefix_len {
        1 => usize::from(data[0]),
        2 => usize::from(u16::from_be_bytes([data[0], data[1]])),
        _ => return Err(TlsTapError::Malformed("vector prefix width")),
    };
    let values = data
        .get(prefix_len..prefix_len + declared)
        .ok_or(TlsTapError::Truncated("u16 vector"))?;
    if values.len() % 2 != 0 || prefix_len + declared != data.len() {
        return Err(TlsTapError::Malformed("u16 vector"));
    }
    Ok(values
        .chunks_exact(2)
        .map(|pair| format!("0x{:04x}", u16::from_be_bytes([pair[0], pair[1]])))
        .collect::<Vec<_>>()
        .join(","))
}

fn parse_alpn(data: &[u8]) -> Result<Vec<String>, TlsTapError> {
    let mut cursor = Cursor::new(data);
    let declared = usize::from(cursor.u16("ALPN list length")?);
    let values = cursor.take(declared, "ALPN list")?;
    if cursor.remaining() != 0 {
        return Err(TlsTapError::Malformed("trailing ALPN bytes"));
    }
    let mut protocols = vec![];
    let mut values = Cursor::new(values);
    while values.remaining() > 0 {
        let length = usize::from(values.u8("ALPN protocol length")?);
        let value = values.take(length, "ALPN protocol")?;
        protocols.push(
            std::str::from_utf8(value)
                .map_err(|_| TlsTapError::Malformed("non-UTF8 ALPN"))?
                .to_owned(),
        );
    }
    Ok(protocols)
}

fn parse_key_share_shape(data: &[u8]) -> Result<String, TlsTapError> {
    let mut cursor = Cursor::new(data);
    let declared = usize::from(cursor.u16("key_share list length")?);
    let encoded_shares = cursor.take(declared, "key_share list")?;
    if cursor.remaining() != 0 {
        return Err(TlsTapError::Malformed("trailing key_share bytes"));
    }
    let mut share_cursor = Cursor::new(encoded_shares);
    let mut descriptors = vec![];
    while share_cursor.remaining() > 0 {
        let group = share_cursor.u16("key_share group")?;
        let length = usize::from(share_cursor.u16("key_share length")?);
        share_cursor.take(length, "key_share bytes")?;
        descriptors.push(format!("0x{group:04x}:{length}"));
    }
    Ok(descriptors.join(","))
}

fn static_vector_attribute(name: &str, value: String) -> TlsAttributeObservation {
    TlsAttributeObservation {
        name: name.to_owned(),
        value,
        dynamic: false,
    }
}

fn read_u24(input: &[u8]) -> Result<usize, TlsTapError> {
    let bytes: [u8; 3] = input
        .try_into()
        .map_err(|_| TlsTapError::Truncated("u24"))?;
    Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0x00ff
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], TlsTapError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(TlsTapError::Malformed("cursor overflow"))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(TlsTapError::Truncated(field))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, TlsTapError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, TlsTapError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[derive(Debug, Error)]
pub enum TlsTapError {
    #[error("TLS tap configuration is invalid")]
    InvalidConfig,
    #[error("TLS tap timed out")]
    Timeout,
    #[error("expected a TLS ClientHello")]
    NotClientHello,
    #[error("HTTP CONNECT request is invalid")]
    InvalidConnectRequest,
    #[error("HTTP CONNECT authority {host}:{port} is outside the configured capture target")]
    UnexpectedConnectAuthority { host: String, port: u16 },
    #[error("HTTP CONNECT request headers exceed the configured limit")]
    ConnectHeaderTooLarge,
    #[error("upstream HTTP proxy returned status {0}")]
    UpstreamProxyStatus(u16),
    #[error("upstream HTTP proxy returned an invalid CONNECT response")]
    InvalidUpstreamProxyResponse,
    #[error("TLS input is truncated at {0}")]
    Truncated(&'static str),
    #[error("TLS input is malformed: {0}")]
    Malformed(&'static str),
    #[error("TLS tap I/O failed: {0}")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_terminal_tunnel_close_errors() {
        for kind in [
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::NotConnected,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            assert!(is_terminal_tunnel_error(&std::io::Error::from(kind)));
        }
        assert!(!is_terminal_tunnel_error(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
    }

    fn client_hello() -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend([7_u8; 32]);
        body.push(0);
        body.extend([0, 4, 0x13, 1, 0x13, 2]);
        body.extend([1, 0]);
        let extensions = [0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2'];
        body.extend(
            u16::try_from(extensions.len())
                .expect("extension length")
                .to_be_bytes(),
        );
        body.extend(extensions);
        let mut handshake = vec![1];
        let len = body.len();
        handshake.extend([
            u8::try_from((len >> 16) & 0xff).expect("length byte"),
            u8::try_from((len >> 8) & 0xff).expect("length byte"),
            u8::try_from(len & 0xff).expect("length byte"),
        ]);
        handshake.extend(body);
        let mut record = vec![22, 0x03, 0x01];
        record.extend(
            u16::try_from(handshake.len())
                .expect("record length")
                .to_be_bytes(),
        );
        record.extend(handshake);
        record
    }

    #[test]
    fn parses_secret_free_client_hello_shape() {
        let parsed = parse_client_hello(&client_hello()).expect("parse ClientHello");
        assert_eq!(parsed.record_version, 0x0301);
        assert_eq!(parsed.legacy_version, 0x0303);
        assert_eq!(parsed.cipher_suites, vec![0x1301, 0x1302]);
        assert_eq!(parsed.alpn, vec!["h2"]);
        assert_eq!(parsed.extensions[0].extension_type, 16);
    }

    #[test]
    fn rejects_truncated_record() {
        let mut record = client_hello();
        record.pop();
        assert!(matches!(
            parse_client_hello(&record),
            Err(TlsTapError::Truncated(_))
        ));
    }

    #[tokio::test]
    async fn pass_through_tap_forwards_and_captures_client_prefix() {
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("accept upstream");
            let mut received = vec![];
            stream
                .read_to_end(&mut received)
                .await
                .expect("read upstream");
            received
        });
        let tap = TlsTapListener::bind(TlsTapConfig {
            listen: "127.0.0.1:0".parse().expect("tap address"),
            upstream_host: "127.0.0.1".to_owned(),
            upstream_port: upstream_addr.port(),
            max_capture_bytes: 4096,
            session_timeout: Duration::from_secs(5),
        })
        .await
        .expect("bind tap");
        let tap_addr = tap.local_addr().expect("tap address");
        let tap_task = tokio::spawn(tap.capture_one());
        let payload = client_hello();
        let mut client = TcpStream::connect(tap_addr).await.expect("connect tap");
        client.write_all(&payload).await.expect("write payload");
        client.shutdown().await.expect("shutdown client");
        let captured = tap_task.await.expect("join tap").expect("capture tap");
        let forwarded = server.await.expect("join server");
        assert_eq!(captured, payload);
        assert_eq!(forwarded, payload);
    }

    #[tokio::test]
    async fn connect_tap_forwards_only_after_allowed_connect() {
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("accept upstream");
            let mut received = vec![];
            stream
                .read_to_end(&mut received)
                .await
                .expect("read upstream");
            received
        });
        let tap = ConnectTlsTapListener::bind(ConnectTlsTapConfig {
            listen: "127.0.0.1:0".parse().expect("tap address"),
            allowed_host: "127.0.0.1".to_owned(),
            allowed_port: upstream_addr.port(),
            max_connect_header_bytes: 4096,
            max_capture_bytes: 4096,
            session_timeout: Duration::from_secs(5),
            upstream_http_proxy: None,
        })
        .await
        .expect("bind CONNECT tap");
        let tap_addr = tap.local_addr().expect("tap address");
        let tap_task = tokio::spawn(tap.capture_one());
        let mut client = TcpStream::connect(tap_addr).await.expect("connect tap");
        client
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: fixture\r\n\r\n",
                    upstream_addr.port()
                )
                .as_bytes(),
            )
            .await
            .expect("write CONNECT");
        let response = read_connect_head(&mut client, 4096)
            .await
            .expect("CONNECT response");
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let payload = client_hello();
        client.write_all(&payload).await.expect("write ClientHello");
        client.shutdown().await.expect("shutdown client");
        let captured = tap_task.await.expect("join tap").expect("capture tap");
        let forwarded = server.await.expect("join server");
        assert_eq!(captured, payload);
        assert_eq!(forwarded, payload);
    }

    #[tokio::test]
    async fn connect_tap_can_reject_unrelated_target_then_capture_allowed_target() {
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("accept upstream");
            let mut received = vec![];
            stream
                .read_to_end(&mut received)
                .await
                .expect("read upstream");
            received
        });
        let tap = ConnectTlsTapListener::bind(ConnectTlsTapConfig {
            listen: "127.0.0.1:0".parse().expect("tap address"),
            allowed_host: "127.0.0.1".to_owned(),
            allowed_port: upstream_addr.port(),
            max_connect_header_bytes: 4096,
            max_capture_bytes: 4096,
            session_timeout: Duration::from_secs(5),
            upstream_http_proxy: None,
        })
        .await
        .expect("bind CONNECT tap");
        let tap_addr = tap.local_addr().expect("tap address");
        let tap_task = tokio::spawn(tap.capture_allowed(1));

        let mut unrelated = TcpStream::connect(tap_addr)
            .await
            .expect("connect unrelated target");
        unrelated
            .write_all(b"CONNECT telemetry.invalid:443 HTTP/1.1\r\nHost: fixture\r\n\r\n")
            .await
            .expect("write unrelated CONNECT");
        let denied = read_connect_head(&mut unrelated, 4096)
            .await
            .expect("denied response");
        assert!(denied.starts_with(b"HTTP/1.1 403"));

        let mut client = TcpStream::connect(tap_addr).await.expect("connect tap");
        client
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: fixture\r\n\r\n",
                    upstream_addr.port()
                )
                .as_bytes(),
            )
            .await
            .expect("write CONNECT");
        let response = read_connect_head(&mut client, 4096)
            .await
            .expect("CONNECT response");
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let payload = client_hello();
        client.write_all(&payload).await.expect("write ClientHello");
        client.shutdown().await.expect("shutdown client");

        let captured = tap_task.await.expect("join tap").expect("capture tap");
        let forwarded = server.await.expect("join server");
        assert_eq!(captured, payload);
        assert_eq!(forwarded, payload);
    }

    #[tokio::test]
    async fn connect_tap_can_chain_through_an_upstream_http_proxy() {
        let proxy = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture proxy");
        let proxy_addr = proxy.local_addr().expect("fixture proxy address");
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.expect("accept fixture proxy");
            let head = read_connect_head(&mut stream, 4096)
                .await
                .expect("read chained CONNECT");
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .expect("write chained CONNECT response");
            let mut payload = vec![];
            stream
                .read_to_end(&mut payload)
                .await
                .expect("read chained payload");
            (head, payload)
        });
        let tap = ConnectTlsTapListener::bind(ConnectTlsTapConfig {
            listen: "127.0.0.1:0".parse().expect("tap address"),
            allowed_host: "api.anthropic.com".to_owned(),
            allowed_port: 443,
            max_connect_header_bytes: 4096,
            max_capture_bytes: 4096,
            session_timeout: Duration::from_secs(5),
            upstream_http_proxy: Some(UpstreamHttpProxy {
                host: "127.0.0.1".to_owned(),
                port: proxy_addr.port(),
                authorization: Some("Basic fixture-secret".to_owned()),
            }),
        })
        .await
        .expect("bind chained tap");
        let tap_addr = tap.local_addr().expect("tap address");
        let tap_task = tokio::spawn(tap.capture_one());
        let mut client = TcpStream::connect(tap_addr).await.expect("connect tap");
        client
            .write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
            .await
            .expect("write local CONNECT");
        let response = read_connect_head(&mut client, 4096)
            .await
            .expect("local CONNECT response");
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let payload = client_hello();
        client.write_all(&payload).await.expect("write ClientHello");
        client.shutdown().await.expect("shutdown client");
        let captured = tap_task.await.expect("join tap").expect("capture tap");
        let (head, forwarded) = proxy_task.await.expect("join fixture proxy");
        let head = String::from_utf8(head).expect("UTF-8 CONNECT head");
        assert!(head.starts_with("CONNECT api.anthropic.com:443 HTTP/1.1\r\n"));
        assert!(head.contains("Proxy-Authorization: Basic fixture-secret\r\n"));
        assert_eq!(captured, payload);
        assert_eq!(forwarded, payload);
    }

    #[test]
    fn connect_parser_supports_ipv6_and_rejects_userinfo() {
        assert_eq!(
            parse_connect_authority(b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n").expect("IPv6 CONNECT"),
            ("::1".to_owned(), 443)
        );
        assert!(matches!(
            parse_connect_authority(b"CONNECT user@host:443 HTTP/1.1\r\n\r\n"),
            Err(TlsTapError::InvalidConnectRequest)
        ));
    }
}
