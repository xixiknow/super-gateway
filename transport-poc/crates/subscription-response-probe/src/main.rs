#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslConnector, SslMethod},
    x509::{
        X509, X509Name,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use clap::Parser;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
};
use uuid::Uuid;

const ANTHROPIC_HOST: &str = "api.anthropic.com";
const ANTHROPIC_PORT: u16 = 443;
const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;
const DIAGNOSTIC_PREFIX_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Run a privacy-safe real-subscription response Header probe")]
struct Cli {
    #[arg(long, default_value = "claude")]
    claude_bin: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    execute_paid_request: bool,
    #[arg(long, default_value = "Reply with exactly: ok")]
    prompt: String,
    #[arg(long, default_value = "claude-opus-4-6")]
    model: String,
    #[arg(long, default_value_t = 45)]
    timeout_seconds: u64,
}

struct RelayServer {
    listener: TcpListener,
    acceptor: SslAcceptor,
    ca_pem: Vec<u8>,
    timeout: Duration,
    upstream_proxy: Option<HttpProxy>,
}

impl fmt::Debug for RelayServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayServer")
            .field("listener", &self.listener)
            .field("timeout", &self.timeout)
            .field("upstream_proxy", &self.upstream_proxy)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct HttpProxy {
    host: String,
    port: u16,
    authorization: Option<String>,
}

impl fmt::Debug for HttpProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

#[derive(Debug)]
struct RequestHead {
    method: String,
    path: String,
    version: String,
    headers: Vec<(String, String)>,
    body_framing: BodyFraming,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
}

#[derive(Debug)]
struct ResponseHead {
    version: String,
    status_code: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

#[derive(Debug, Serialize)]
struct ProbeReport {
    schema_version: u32,
    probe_id: Uuid,
    probe_kind: &'static str,
    evidence_scope: &'static str,
    observed_at: String,
    environment: EnvironmentReport,
    route: RouteReport,
    request: RequestReport,
    response: ResponseReport,
    claude: ClaudeReport,
    privacy: PrivacyReport,
}

#[derive(Debug, Serialize)]
struct EnvironmentReport {
    os: &'static str,
    arch: &'static str,
    claude_code_version: String,
}

#[derive(Debug, Serialize)]
struct RouteReport {
    local_tls_termination: bool,
    upstream_certificate_verified: bool,
    upstream_alpn: String,
    chained_http_connect_proxy: bool,
    skipped_background_requests: usize,
    native_trust_root_count: usize,
}

#[derive(Debug, Serialize)]
struct RequestReport {
    method: String,
    path: String,
    version: String,
    header_names_in_order: Vec<String>,
    authorization_present: bool,
    authorization_scheme: Option<String>,
    body_framing: &'static str,
    body_bytes: usize,
}

#[derive(Debug, Serialize)]
struct ResponseReport {
    version: String,
    status_code: u16,
    reason: String,
    headers_in_order: Vec<SafeHeader>,
}

#[derive(Debug, Serialize)]
struct SafeHeader {
    wire_name: String,
    canonical_name: String,
    value_bytes: usize,
    value_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_sha256: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct ClaudeReport {
    exit_code: Option<i32>,
    timed_out: bool,
    stdout_bytes: usize,
    stderr_bytes: usize,
    init_events: usize,
    assistant_events: usize,
    result_success_events: usize,
    result_error_events: usize,
    api_retry_events: usize,
    rate_limit_events: usize,
    stream_event_types: BTreeMap<String, usize>,
    assistant_models: BTreeMap<String, usize>,
    usage_input_tokens: u64,
    usage_output_tokens: u64,
    usage_cache_creation_input_tokens: u64,
    usage_cache_read_input_tokens: u64,
}

#[derive(Debug, Serialize)]
struct PrivacyReport {
    dispositions: Vec<PrivacyDisposition>,
}

#[derive(Debug, Serialize)]
struct PrivacyDisposition {
    data_class: &'static str,
    persistence: &'static str,
}

#[derive(Debug)]
struct ChildOutput {
    exit_code: Option<i32>,
    timed_out: bool,
    stdout_bytes: usize,
    stderr_bytes: usize,
    stdout_prefix: Vec<u8>,
}

#[derive(Debug)]
struct RelayedExchange {
    request: RequestHead,
    request_body_bytes: usize,
    response: ResponseHead,
    upstream_alpn: String,
    skipped_background_requests: usize,
    native_trust_root_count: usize,
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(
        cli.execute_paid_request,
        "real-subscription probe requires --execute-paid-request"
    );
    ensure!(cli.timeout_seconds > 0, "timeout-seconds must be positive");
    ensure!(!cli.prompt.is_empty(), "prompt must not be empty");
    let timeout = Duration::from_secs(cli.timeout_seconds);
    let claude_version = claude_version(&cli.claude_bin, timeout).await?;
    let upstream_proxy = inherited_http_proxy()?;
    let chained_http_connect_proxy = upstream_proxy.is_some();
    let relay = RelayServer::bind(timeout, upstream_proxy).await?;
    let relay_addr = relay.listener.local_addr().context("read relay address")?;
    let temp = tempfile::tempdir().context("create probe workspace")?;
    let ca_path = temp.path().join("response-probe-ca.pem");
    tokio::fs::write(&ca_path, &relay.ca_pem)
        .await
        .context("write ephemeral response-probe CA")?;
    let base_url = format!("https://127.0.0.1:{}", relay_addr.port());
    let settings_path = temp.path().join("response-probe-settings.json");
    write_settings(&settings_path, &base_url, &ca_path).await?;

    let relay_task = tokio::spawn(relay.relay_one());
    let child = run_claude(
        &cli.claude_bin,
        &cli.prompt,
        &cli.model,
        temp.path(),
        &settings_path,
        &base_url,
        &ca_path,
        timeout,
    )
    .await?;
    let exchange = relay_task.await.context("join response relay")??;
    let mut claude = summarize_claude(&child.stdout_prefix);
    claude.exit_code = child.exit_code;
    claude.timed_out = child.timed_out;
    claude.stdout_bytes = child.stdout_bytes;
    claude.stderr_bytes = child.stderr_bytes;
    ensure!(
        !claude.timed_out
            && claude.exit_code == Some(0)
            && claude.assistant_events > 0
            && claude.result_success_events > 0
            && claude.result_error_events == 0
            && claude.api_retry_events == 0,
        "Claude Code did not complete a retry-free successful exchange"
    );
    ensure!(
        (200..300).contains(&exchange.response.status_code),
        "upstream Messages response was not successful"
    );

    let report = ProbeReport {
        schema_version: 1,
        probe_id: Uuid::new_v4(),
        probe_kind: "real_subscription_response_headers",
        evidence_scope: "semantic_response_only_not_transport_fingerprint",
        observed_at: observed_at(),
        environment: EnvironmentReport {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            claude_code_version: claude_version,
        },
        route: RouteReport {
            local_tls_termination: true,
            upstream_certificate_verified: true,
            upstream_alpn: exchange.upstream_alpn,
            chained_http_connect_proxy,
            skipped_background_requests: exchange.skipped_background_requests,
            native_trust_root_count: exchange.native_trust_root_count,
        },
        request: request_report(&exchange.request, exchange.request_body_bytes),
        response: response_report(exchange.response),
        claude,
        privacy: PrivacyReport {
            dispositions: vec![
                PrivacyDisposition {
                    data_class: "request_headers",
                    persistence: "names_only_plus_authorization_presence_and_scheme",
                },
                PrivacyDisposition {
                    data_class: "response_headers",
                    persistence: "safe_allowlist_values_otherwise_shape_or_hash",
                },
                PrivacyDisposition {
                    data_class: "request_body",
                    persistence: "none",
                },
                PrivacyDisposition {
                    data_class: "response_body",
                    persistence: "none",
                },
                PrivacyDisposition {
                    data_class: "prompt_or_completion",
                    persistence: "none",
                },
                PrivacyDisposition {
                    data_class: "credentials",
                    persistence: "none",
                },
            ],
        },
    };
    persist_report(&cli.output, &report)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

impl RelayServer {
    async fn bind(timeout: Duration, upstream_proxy: Option<HttpProxy>) -> Result<Self> {
        let (certificate, key) = ephemeral_certificate("127.0.0.1")?;
        let ca_pem = certificate.to_pem().context("encode probe CA")?;
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        acceptor.set_certificate(&certificate)?;
        acceptor.set_private_key(&key)?;
        acceptor.check_private_key()?;
        acceptor.set_alpn_select_callback(|_, client| {
            boring::ssl::select_next_proto(b"\x08http/1.1", client)
                .ok_or(boring::ssl::AlpnError::NOACK)
        });
        let listener =
            TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
        Ok(Self {
            listener,
            acceptor: acceptor.build(),
            ca_pem,
            timeout,
            upstream_proxy,
        })
    }

    async fn relay_one(self) -> Result<RelayedExchange> {
        let timeout = self.timeout;
        tokio::time::timeout(timeout, self.relay_one_inner())
            .await
            .map_err(|_| anyhow!("response relay timed out"))?
    }

    async fn relay_one_inner(self) -> Result<RelayedExchange> {
        let mut skipped_background_requests = 0_usize;
        for _ in 0..8 {
            let (tcp, _) = self.listener.accept().await?;
            let mut inbound = tokio_boring::accept(&self.acceptor, tcp)
                .await
                .context("accept local Claude TLS")?;
            let (request_head_bytes, mut buffered_body) = read_head(&mut inbound).await?;
            let request = parse_request_head(&request_head_bytes)?;
            read_request_body(&mut inbound, &request.body_framing, &mut buffered_body).await?;
            if request.method != "POST" || !request.path.starts_with("/v1/messages") {
                inbound
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await?;
                inbound.flush().await?;
                let _ = inbound.shutdown().await;
                skipped_background_requests = skipped_background_requests.saturating_add(1);
                continue;
            }

            let request_body_bytes = buffered_body.len();
            let tcp = open_upstream(self.upstream_proxy.as_ref()).await?;
            let (mut connector, native_trust_root_count) = native_tls_connector()?;
            connector.set_alpn_protos(b"\x08http/1.1")?;
            let config = connector.build().configure()?;
            let mut upstream = tokio_boring::connect(config, ANTHROPIC_HOST, tcp)
                .await
                .context("connect verified Anthropic TLS")?;
            let upstream_alpn = upstream.ssl().selected_alpn_protocol().map_or_else(
                || "none".to_owned(),
                |value| String::from_utf8_lossy(value).into_owned(),
            );
            ensure!(
                upstream_alpn == "http/1.1",
                "Anthropic selected an unexpected upstream ALPN"
            );
            let forwarded_head = build_upstream_request_head(&request);
            upstream.write_all(&forwarded_head).await?;
            upstream.write_all(&buffered_body).await?;
            upstream.flush().await?;

            let (response_head_bytes, response_prefix) = read_head(&mut upstream).await?;
            let response = parse_response_head(&response_head_bytes)?;
            inbound.write_all(&response_head_bytes).await?;
            inbound.write_all(&response_prefix).await?;
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let read = upstream.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                inbound.write_all(&buffer[..read]).await?;
            }
            inbound.flush().await?;
            let _ = inbound.shutdown().await;
            return Ok(RelayedExchange {
                request,
                request_body_bytes,
                response,
                upstream_alpn,
                skipped_background_requests,
                native_trust_root_count,
            });
        }
        bail!("Messages request was not observed")
    }
}

fn native_tls_connector() -> Result<(boring::ssl::SslConnectorBuilder, usize)> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    let native = rustls_native_certs::load_native_certs();
    ensure!(
        native.errors.is_empty(),
        "one or more native trust roots failed to load"
    );
    let mut added = 0_usize;
    for certificate in native.certs {
        let certificate =
            X509::from_der(certificate.as_ref()).context("parse native trust root as X.509 DER")?;
        if builder.cert_store_mut().add_cert(certificate).is_ok() {
            added = added.saturating_add(1);
        }
    }
    ensure!(added > 0, "native trust store contains no usable roots");
    Ok((builder, added))
}

async fn read_head<S>(stream: &mut S) -> Result<(Vec<u8>, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer).await?;
        ensure!(read > 0, "connection ended before HTTP head");
        bytes.extend_from_slice(&buffer[..read]);
        ensure!(
            bytes.len() <= MAX_HEAD_BYTES,
            "HTTP head exceeds probe limit"
        );
        if let Some(end) = find_head_end(&bytes) {
            let remainder = bytes.split_off(end);
            return Ok((bytes, remainder));
        }
    }
}

fn find_head_end(input: &[u8]) -> Option<usize> {
    input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn parse_request_head(input: &[u8]) -> Result<RequestHead> {
    let text = std::str::from_utf8(input).context("request head is not UTF-8")?;
    let mut lines = text.trim_end_matches("\r\n\r\n").split("\r\n");
    let start = lines
        .next()
        .ok_or_else(|| anyhow!("missing request line"))?;
    let mut parts = start.splitn(3, ' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let version = parts.next().unwrap_or_default().to_owned();
    ensure!(
        !method.is_empty() && path.starts_with('/') && version == "HTTP/1.1",
        "malformed request line"
    );
    let headers = parse_headers(lines)?;
    let body_framing = body_framing(&headers)?;
    Ok(RequestHead {
        method,
        path,
        version,
        headers,
        body_framing,
    })
}

async fn read_request_body<S>(
    stream: &mut S,
    framing: &BodyFraming,
    bytes: &mut Vec<u8>,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    loop {
        ensure!(
            bytes.len() <= MAX_REQUEST_BODY_BYTES,
            "probe request body exceeds capture limit"
        );
        let complete = match framing {
            BodyFraming::None => {
                ensure!(bytes.is_empty(), "bodyless request contained body bytes");
                true
            }
            BodyFraming::ContentLength(expected) => {
                ensure!(
                    *expected <= MAX_REQUEST_BODY_BYTES,
                    "probe request body exceeds capture limit"
                );
                ensure!(
                    bytes.len() <= *expected,
                    "local request contained trailing bytes"
                );
                bytes.len() == *expected
            }
            BodyFraming::Chunked => complete_chunked_len(bytes)?.is_some(),
        };
        if complete {
            break;
        }
        let mut buffer = vec![0_u8; 64 * 1024];
        let read = stream.read(&mut buffer).await?;
        ensure!(read > 0, "local request body ended early");
        bytes.extend_from_slice(&buffer[..read]);
    }
    if let BodyFraming::Chunked = framing {
        let end = complete_chunked_len(bytes)?
            .ok_or_else(|| anyhow!("chunked request body ended early"))?;
        ensure!(end == bytes.len(), "local request contained trailing bytes");
    }
    Ok(())
}

fn parse_response_head(input: &[u8]) -> Result<ResponseHead> {
    let text = std::str::from_utf8(input).context("response head is not UTF-8")?;
    let mut lines = text.trim_end_matches("\r\n\r\n").split("\r\n");
    let start = lines
        .next()
        .ok_or_else(|| anyhow!("missing response line"))?;
    let mut parts = start.splitn(3, ' ');
    let version = parts.next().unwrap_or_default().to_owned();
    let status_code = parts
        .next()
        .ok_or_else(|| anyhow!("missing response status"))?
        .parse::<u16>()
        .context("parse response status")?;
    let reason = parts.next().unwrap_or_default().to_owned();
    ensure!(
        version.starts_with("HTTP/1."),
        "unexpected response version"
    );
    Ok(ResponseHead {
        version,
        status_code,
        reason,
        headers: parse_headers(lines)?,
    })
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Vec<(String, String)>> {
    lines
        .map(|line| {
            ensure!(
                !line.starts_with([' ', '\t']),
                "folded HTTP headers are outside this probe contract"
            );
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| anyhow!("malformed HTTP header"))?;
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
                "malformed HTTP header name"
            );
            ensure!(
                !value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)),
                "malformed HTTP header value"
            );
            Ok((name.to_owned(), value.trim().to_owned()))
        })
        .collect()
}

fn body_framing(headers: &[(String, String)]) -> Result<BodyFraming> {
    let values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.parse::<usize>().context("parse content-length"))
        .collect::<Result<Vec<_>>>()?;
    let transfer_encodings = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    ensure!(
        values.len() <= 1 && transfer_encodings.len() <= 1,
        "request body framing is ambiguous"
    );
    match (values.first(), transfer_encodings.first()) {
        (Some(_), Some(_)) => bail!("request has conflicting body framing"),
        (Some(length), None) => Ok(BodyFraming::ContentLength(*length)),
        (None, Some(value)) if value == "chunked" => Ok(BodyFraming::Chunked),
        (None, None) => Ok(BodyFraming::None),
        _ => bail!("request body framing is unsupported"),
    }
}

fn complete_chunked_len(input: &[u8]) -> Result<Option<usize>> {
    let mut cursor = 0_usize;
    loop {
        let Some(line_end) = find_crlf(input, cursor) else {
            return Ok(None);
        };
        let size_text = std::str::from_utf8(&input[cursor..line_end])
            .context("chunk size is not UTF-8")?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        ensure!(!size_text.is_empty(), "chunk size is empty");
        let size = usize::from_str_radix(size_text, 16).context("parse chunk size")?;
        cursor = line_end + 2;
        if size == 0 {
            loop {
                let Some(trailer_end) = find_crlf(input, cursor) else {
                    return Ok(None);
                };
                if trailer_end == cursor {
                    return Ok(Some(cursor + 2));
                }
                let trailer = &input[cursor..trailer_end];
                ensure!(trailer.contains(&b':'), "malformed chunk trailer");
                cursor = trailer_end + 2;
            }
        }
        let Some(data_end) = cursor.checked_add(size) else {
            bail!("chunk size overflow");
        };
        let Some(terminator_end) = data_end.checked_add(2) else {
            bail!("chunk size overflow");
        };
        if input.len() < terminator_end {
            return Ok(None);
        }
        ensure!(
            &input[data_end..data_end + 2] == b"\r\n",
            "chunk data terminator is malformed"
        );
        cursor = data_end + 2;
    }
}

fn find_crlf(input: &[u8], start: usize) -> Option<usize> {
    input
        .get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

fn build_upstream_request_head(request: &RequestHead) -> Vec<u8> {
    let mut output = format!(
        "{} {} {}\r\n",
        request.method, request.path, request.version
    );
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        output.push_str(name);
        output.push_str(": ");
        output.push_str(value);
        output.push_str("\r\n");
    }
    output.push_str("Host: api.anthropic.com\r\nConnection: close\r\n\r\n");
    output.into_bytes()
}

async fn open_upstream(proxy: Option<&HttpProxy>) -> Result<TcpStream> {
    let Some(proxy) = proxy else {
        return TcpStream::connect((ANTHROPIC_HOST, ANTHROPIC_PORT))
            .await
            .context("connect Anthropic TCP");
    };
    let mut tcp = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .context("connect inherited HTTP proxy")?;
    let authority = format!("{ANTHROPIC_HOST}:{ANTHROPIC_PORT}");
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(authorization) = &proxy.authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    tcp.write_all(request.as_bytes()).await?;
    tcp.flush().await?;
    let (head, remainder) = read_head(&mut tcp).await?;
    ensure!(
        remainder.is_empty(),
        "proxy CONNECT returned unexpected tunnel bytes"
    );
    let status = parse_response_head(&head)?.status_code;
    ensure!(status == 200, "inherited HTTP proxy rejected CONNECT");
    Ok(tcp)
}

fn inherited_http_proxy() -> Result<Option<HttpProxy>> {
    for name in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"] {
        let Some(value) = std::env::var_os(name) else {
            continue;
        };
        let value = value.to_string_lossy();
        if !value.trim().is_empty() {
            return parse_http_proxy(&value).map(Some);
        }
    }
    Ok(None)
}

fn parse_http_proxy(value: &str) -> Result<HttpProxy> {
    let authority = value
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("inherited proxy must use http scheme"))?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    ensure!(
        !authority.is_empty()
            && !authority.contains(['/', '\\', '?', '#'])
            && !authority.chars().any(char::is_whitespace),
        "inherited proxy URL contains an unsupported component"
    );
    let (userinfo, endpoint) = authority
        .rsplit_once('@')
        .map_or((None, authority), |(left, right)| (Some(left), right));
    let (host, port) = parse_proxy_endpoint(endpoint)?;
    let authorization = userinfo
        .map(|value| {
            let (username, password) = value.split_once(':').unwrap_or((value, ""));
            ensure!(!username.is_empty(), "proxy username is empty");
            let username = percent_encoding::percent_decode_str(username)
                .decode_utf8()
                .context("decode proxy username")?;
            let password = percent_encoding::percent_decode_str(password)
                .decode_utf8()
                .context("decode proxy password")?;
            Ok::<_, anyhow::Error>(format!(
                "Basic {}",
                STANDARD.encode(format!("{username}:{password}"))
            ))
        })
        .transpose()?;
    Ok(HttpProxy {
        host,
        port,
        authorization,
    })
}

fn parse_proxy_endpoint(endpoint: &str) -> Result<(String, u16)> {
    if let Some(bracketed) = endpoint.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| anyhow!("proxy IPv6 host is malformed"))?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            80
        } else {
            suffix
                .strip_prefix(':')
                .ok_or_else(|| anyhow!("proxy IPv6 port is malformed"))?
                .parse::<u16>()?
        };
        ensure!(!host.is_empty() && port > 0, "proxy endpoint is empty");
        return Ok((host.to_owned(), port));
    }
    ensure!(
        endpoint.matches(':').count() <= 1,
        "proxy IPv6 host requires brackets"
    );
    let (host, port) = endpoint.rsplit_once(':').map_or_else(
        || Ok::<_, anyhow::Error>((endpoint, 80)),
        |(host, port)| Ok((host, port.parse::<u16>()?)),
    )?;
    ensure!(!host.is_empty() && port > 0, "proxy endpoint is empty");
    Ok((host.to_owned(), port))
}

async fn write_settings(path: &Path, base_url: &str, ca_path: &Path) -> Result<()> {
    let settings = serde_json::json!({
        "env": {
            "ANTHROPIC_BASE_URL": base_url,
            "NODE_EXTRA_CA_CERTS": ca_path,
            "SSL_CERT_FILE": ca_path,
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "DISABLE_AUTOUPDATER": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
        }
    });
    tokio::fs::write(path, serde_json::to_vec(&settings)?)
        .await
        .context("write response-probe settings")
}

#[allow(clippy::too_many_arguments)]
async fn run_claude(
    claude_bin: &Path,
    prompt: &str,
    model: &str,
    working_dir: &Path,
    settings_path: &Path,
    base_url: &str,
    ca_path: &Path,
    timeout: Duration,
) -> Result<ChildOutput> {
    let mut command = Command::new(claude_bin);
    command
        .arg("-p")
        .arg(prompt)
        .arg("--model")
        .arg(model)
        .arg("--output-format")
        .arg("stream-json")
        .arg("--include-partial-messages")
        .arg("--verbose")
        .arg("--no-session-persistence")
        .arg("--safe-mode")
        .arg("--tools")
        .arg("")
        .arg("--prompt-suggestions")
        .arg("false")
        .arg("--settings")
        .arg(settings_path)
        .current_dir(working_dir)
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("ANTHROPIC_AUTH_TOKEN")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("https_proxy")
        .env_remove("http_proxy")
        .env_remove("all_proxy")
        .env("ANTHROPIC_BASE_URL", base_url)
        .env("NODE_EXTRA_CA_CERTS", ca_path)
        .env("SSL_CERT_FILE", ca_path)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .env("DISABLE_AUTOUPDATER", "1")
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().context("spawn Claude Code")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("missing stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("missing stderr"))?;
    let stdout_task = tokio::spawn(drain_output(stdout, true));
    let stderr_task = tokio::spawn(drain_output(stderr, false));
    let (status, timed_out) = if let Ok(status) = tokio::time::timeout(timeout, child.wait()).await
    {
        (status?, false)
    } else {
        let _ = child.kill().await;
        (child.wait().await?, true)
    };
    let (stdout_bytes, stdout_prefix) = stdout_task.await.context("join stdout")??;
    let (stderr_bytes, _) = stderr_task.await.context("join stderr")??;
    Ok(ChildOutput {
        exit_code: (!timed_out).then(|| status.code()).flatten(),
        timed_out,
        stdout_bytes,
        stderr_bytes,
        stdout_prefix,
    })
}

async fn drain_output<R>(mut reader: R, keep_prefix: bool) -> Result<(usize, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut total = 0_usize;
    let mut prefix = Vec::new();
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        if keep_prefix && prefix.len() < DIAGNOSTIC_PREFIX_LIMIT {
            let remaining = DIAGNOSTIC_PREFIX_LIMIT - prefix.len();
            prefix.extend_from_slice(&buffer[..read.min(remaining)]);
        }
    }
    Ok((total, prefix))
}

fn summarize_claude(output: &[u8]) -> ClaudeReport {
    let mut report = ClaudeReport::default();
    for line in output.split(|byte| *byte == b'\n') {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        match value.get("type").and_then(serde_json::Value::as_str) {
            Some("system")
                if value.get("subtype").and_then(serde_json::Value::as_str) == Some("init") =>
            {
                report.init_events += 1;
            }
            Some("system")
                if value.get("subtype").and_then(serde_json::Value::as_str)
                    == Some("api_retry") =>
            {
                report.api_retry_events += 1;
            }
            Some("assistant") => {
                report.assistant_events += 1;
                if let Some(model) = value
                    .get("message")
                    .and_then(|message| message.get("model"))
                    .and_then(serde_json::Value::as_str)
                {
                    *report.assistant_models.entry(model.to_owned()).or_default() += 1;
                }
            }
            Some("result") => {
                let is_error = value
                    .get("is_error")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true);
                if is_error {
                    report.result_error_events += 1;
                } else {
                    report.result_success_events += 1;
                }
                if let Some(usage) = value.get("usage") {
                    report.usage_input_tokens = json_u64(usage, "input_tokens");
                    report.usage_output_tokens = json_u64(usage, "output_tokens");
                    report.usage_cache_creation_input_tokens =
                        json_u64(usage, "cache_creation_input_tokens");
                    report.usage_cache_read_input_tokens =
                        json_u64(usage, "cache_read_input_tokens");
                }
            }
            Some("rate_limit_event") => report.rate_limit_events += 1,
            Some("stream_event") => {
                let event_type = value
                    .get("event")
                    .and_then(|event| event.get("type"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("missing");
                *report
                    .stream_event_types
                    .entry(event_type.to_owned())
                    .or_default() += 1;
            }
            _ => {}
        }
    }
    report
}

fn json_u64(value: &serde_json::Value, field: &str) -> u64 {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default()
}

fn request_report(request: &RequestHead, body_bytes: usize) -> RequestReport {
    let authorization = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"));
    RequestReport {
        method: request.method.clone(),
        path: request.path.clone(),
        version: request.version.clone(),
        header_names_in_order: request
            .headers
            .iter()
            .map(|(name, _)| name.clone())
            .collect(),
        authorization_present: authorization.is_some(),
        authorization_scheme: authorization.map(|(_, value)| {
            value
                .split_ascii_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_ascii_lowercase()
        }),
        body_framing: match request.body_framing {
            BodyFraming::None => "none",
            BodyFraming::ContentLength(_) => "content_length",
            BodyFraming::Chunked => "chunked",
        },
        body_bytes,
    }
}

fn response_report(response: ResponseHead) -> ResponseReport {
    ResponseReport {
        version: response.version,
        status_code: response.status_code,
        reason: response.reason,
        headers_in_order: response
            .headers
            .into_iter()
            .map(|(name, value)| safe_response_header(name, &value))
            .collect(),
    }
}

fn safe_response_header(wire_name: String, value: &str) -> SafeHeader {
    let canonical_name = wire_name.to_ascii_lowercase();
    let exact_safe = canonical_name == "retry-after"
        || canonical_name.starts_with("anthropic-ratelimit-")
        || canonical_name.starts_with("x-ratelimit-")
        || matches!(
            canonical_name.as_str(),
            "content-type"
                | "content-encoding"
                | "transfer-encoding"
                | "connection"
                | "cache-control"
        );
    let hashed = matches!(canonical_name.as_str(), "request-id" | "x-request-id");
    SafeHeader {
        wire_name,
        canonical_name,
        value_bytes: value.len(),
        value_kind: if exact_safe {
            "allowlisted_exact"
        } else if hashed {
            "sha256"
        } else {
            "shape_only"
        },
        safe_value: exact_safe.then(|| value.to_owned()),
        value_sha256: hashed.then(|| hex::encode(Sha256::digest(value.as_bytes()))),
    }
}

async fn claude_version(claude_bin: &Path, timeout: Duration) -> Result<String> {
    let output = tokio::time::timeout(
        timeout.min(Duration::from_secs(10)),
        Command::new(claude_bin).arg("--version").output(),
    )
    .await
    .map_err(|_| anyhow!("Claude Code version probe timed out"))??;
    ensure!(output.status.success(), "Claude Code version probe failed");
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    ensure!(!version.is_empty(), "Claude Code version was empty");
    Ok(version)
}

fn ephemeral_certificate(authority: &str) -> Result<(X509, PKey<Private>)> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, authority)?;
    let name = name.build();
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_subject_name(&name)?;
    certificate.set_issuer_name(&name)?;
    certificate.set_pubkey(&key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(1)?;
    certificate.set_not_before(&not_before)?;
    certificate.set_not_after(&not_after)?;
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    certificate.set_serial_number(&serial)?;
    let mut san = SubjectAlternativeName::new();
    san.ip(authority);
    for extension in [
        BasicConstraints::new().critical().ca().build()?,
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .key_cert_sign()
            .build()?,
        ExtendedKeyUsage::new().server_auth().build()?,
        san.build(&certificate.x509v3_context(None, None))?,
    ] {
        certificate.append_extension(&extension)?;
    }
    certificate.sign(&key, MessageDigest::sha256())?;
    Ok((certificate.build(), key))
}

fn persist_report(path: &Path, report: &ProbeReport) -> Result<()> {
    if path.exists() {
        bail!("probe output already exists: {}", path.display());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temp = NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temp, report)?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("persist probe report {}", path.display()))?;
    Ok(())
}

fn observed_at() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("unix-ms:{millis}")
}

#[cfg(test)]
mod tests {
    use super::{
        BodyFraming, RequestHead, build_upstream_request_head, complete_chunked_len,
        parse_http_proxy, parse_response_head, safe_response_header,
    };

    #[test]
    fn rewrites_host_and_forces_connection_close() {
        let request = RequestHead {
            method: "POST".to_owned(),
            path: "/v1/messages?beta=true".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: vec![
                ("Host".to_owned(), "127.0.0.1:1234".to_owned()),
                ("Authorization".to_owned(), "Bearer secret".to_owned()),
                ("Connection".to_owned(), "keep-alive".to_owned()),
                ("Content-Length".to_owned(), "2".to_owned()),
            ],
            body_framing: BodyFraming::ContentLength(2),
        };
        let rendered = String::from_utf8(build_upstream_request_head(&request)).expect("UTF-8");
        assert!(rendered.contains("Host: api.anthropic.com\r\n"));
        assert!(rendered.contains("Connection: close\r\n"));
        assert!(!rendered.contains("127.0.0.1:1234"));
        assert_eq!(rendered.matches("Authorization:").count(), 1);
    }

    #[test]
    fn response_header_policy_hashes_request_id_and_keeps_rate_limit() {
        let request_id = safe_response_header("request-id".to_owned(), "req-secret");
        assert_eq!(request_id.value_kind, "sha256");
        assert!(request_id.safe_value.is_none());
        assert!(request_id.value_sha256.is_some());
        let limit = safe_response_header(
            "anthropic-ratelimit-unified-tokens-limit".to_owned(),
            "20000",
        );
        assert_eq!(limit.safe_value.as_deref(), Some("20000"));
    }

    #[test]
    fn proxy_credentials_are_decoded_and_redacted_from_debug() {
        let proxy = parse_http_proxy("http://user:p%40ss@127.0.0.1:7890").expect("proxy");
        assert_eq!(proxy.authorization.as_deref(), Some("Basic dXNlcjpwQHNz"));
        let debug = format!("{proxy:?}");
        assert!(!debug.contains("dXNlcjpwQHNz"));
        assert!(!debug.contains("p@ss"));
    }

    #[test]
    fn parses_ordered_response_headers() {
        let response = parse_response_head(
            b"HTTP/1.1 200 OK\r\nrequest-id: req_fixture\r\nretry-after: 3\r\n\r\n",
        )
        .expect("response");
        assert_eq!(response.status_code, 200);
        assert_eq!(response.headers[0].0, "request-id");
        assert_eq!(response.headers[1].0, "retry-after");
    }

    #[test]
    fn recognizes_complete_chunked_body_with_trailer() {
        assert_eq!(
            complete_chunked_len(b"4\r\ntest\r\n0\r\nx-fixture: yes\r\n\r\n").expect("chunked"),
            Some(30)
        );
        assert_eq!(
            complete_chunked_len(b"4\r\ntes").expect("partial chunked"),
            None
        );
    }
}
