#![forbid(unsafe_code)]

use capture_schema::{Http2FrameDetail, Http2FrameType, Http2Setting};
use thiserror::Error;

pub const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedH2Frame {
    pub sequence: u64,
    pub stream_id: u32,
    pub frame_type: Http2FrameType,
    pub flags: Vec<String>,
    pub length: u32,
    pub detail: Http2FrameDetail,
}

/// Parses complete client-originated HTTP/2 frames after the connection
/// preface, preserving their wire order and SETTINGS entry order.
///
/// # Errors
///
/// Returns [`ControlledCaptureError`] when the preface or frame encoding is
/// incomplete or malformed.
pub fn parse_client_frames(input: &[u8]) -> Result<Vec<CapturedH2Frame>, ControlledCaptureError> {
    let mut remaining = input
        .strip_prefix(H2_CLIENT_PREFACE)
        .ok_or(ControlledCaptureError::InvalidPreface)?;
    let mut frames = vec![];
    let mut sequence = 0_u64;
    while !remaining.is_empty() {
        let header = remaining
            .get(..9)
            .ok_or(ControlledCaptureError::Truncated("HTTP/2 frame header"))?;
        let length =
            (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        let end = 9_usize
            .checked_add(length)
            .ok_or(ControlledCaptureError::Malformed("HTTP/2 frame length"))?;
        let payload = remaining
            .get(9..end)
            .ok_or(ControlledCaptureError::Truncated("HTTP/2 frame payload"))?;
        let frame_code = header[3];
        let flag_bits = header[4];
        let stream_id =
            u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
        sequence = sequence
            .checked_add(1)
            .ok_or(ControlledCaptureError::Malformed("frame sequence overflow"))?;
        let (frame_type, flags, detail) = parse_frame(frame_code, flag_bits, stream_id, payload)?;
        frames.push(CapturedH2Frame {
            sequence,
            stream_id,
            frame_type,
            flags,
            length: u32::try_from(length)
                .map_err(|_| ControlledCaptureError::Malformed("frame too large"))?,
            detail,
        });
        remaining = &remaining[end..];
    }
    Ok(frames)
}

fn parse_frame(
    frame_code: u8,
    flag_bits: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<(Http2FrameType, Vec<String>, Http2FrameDetail), ControlledCaptureError> {
    match frame_code {
        0 => Ok((
            Http2FrameType::Data,
            common_flags(flag_bits, true),
            Http2FrameDetail::Data {
                content_sha256: None,
            },
        )),
        1 => Ok((
            Http2FrameType::Headers,
            header_flags(flag_bits),
            Http2FrameDetail::Headers { headers: vec![] },
        )),
        2 => {
            let bytes: [u8; 5] = payload
                .try_into()
                .map_err(|_| ControlledCaptureError::Malformed("PRIORITY payload"))?;
            let raw_dependency = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Ok((
                Http2FrameType::Priority,
                unknown_flags(flag_bits),
                Http2FrameDetail::Priority {
                    exclusive: raw_dependency & 0x8000_0000 != 0,
                    dependency: raw_dependency & 0x7fff_ffff,
                    weight: u16::from(bytes[4]) + 1,
                },
            ))
        }
        3 => Ok((
            Http2FrameType::RstStream,
            unknown_flags(flag_bits),
            Http2FrameDetail::RstStream {
                error_code: payload_u32(payload, "RST_STREAM")?,
            },
        )),
        4 => Ok((
            Http2FrameType::Settings,
            settings_flags(flag_bits),
            Http2FrameDetail::Settings {
                entries: parse_settings(payload, flag_bits)?,
            },
        )),
        6 => Ok((
            Http2FrameType::Ping,
            ping_flags(flag_bits),
            Http2FrameDetail::Ping {
                ack: flag_bits & 0x1 != 0,
                opaque_sha256: None,
            },
        )),
        7 => {
            if payload.len() < 8 {
                return Err(ControlledCaptureError::Truncated("GOAWAY payload"));
            }
            Ok((
                Http2FrameType::GoAway,
                unknown_flags(flag_bits),
                Http2FrameDetail::GoAway {
                    last_stream_id: u32::from_be_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]) & 0x7fff_ffff,
                    error_code: u32::from_be_bytes([
                        payload[4], payload[5], payload[6], payload[7],
                    ]),
                },
            ))
        }
        8 => Ok((
            Http2FrameType::WindowUpdate,
            unknown_flags(flag_bits),
            Http2FrameDetail::WindowUpdate {
                increment: payload_u32(payload, "WINDOW_UPDATE")? & 0x7fff_ffff,
            },
        )),
        9 => Ok((
            Http2FrameType::Continuation,
            end_headers_flags(flag_bits),
            Http2FrameDetail::Empty,
        )),
        16 => Ok((
            Http2FrameType::PriorityUpdate,
            unknown_flags(flag_bits),
            Http2FrameDetail::Other {
                summary: format!("priority_update:{}B:stream={stream_id}", payload.len()),
            },
        )),
        code => Ok((
            Http2FrameType::Other,
            unknown_flags(flag_bits),
            Http2FrameDetail::Other {
                summary: format!("type=0x{code:02x}:{}B", payload.len()),
            },
        )),
    }
}

fn parse_settings(
    payload: &[u8],
    flag_bits: u8,
) -> Result<Vec<Http2Setting>, ControlledCaptureError> {
    if flag_bits & 0x1 != 0 {
        if payload.is_empty() {
            return Ok(vec![]);
        }
        return Err(ControlledCaptureError::Malformed(
            "SETTINGS ACK has a payload",
        ));
    }
    if !payload.len().is_multiple_of(6) {
        return Err(ControlledCaptureError::Malformed("SETTINGS payload"));
    }
    Ok(payload
        .chunks_exact(6)
        .map(|entry| Http2Setting {
            id: u16::from_be_bytes([entry[0], entry[1]]),
            value: u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]),
        })
        .collect())
}

fn payload_u32(payload: &[u8], frame: &'static str) -> Result<u32, ControlledCaptureError> {
    let bytes: [u8; 4] = payload
        .try_into()
        .map_err(|_| ControlledCaptureError::Malformed(frame))?;
    Ok(u32::from_be_bytes(bytes))
}

fn common_flags(bits: u8, end_stream: bool) -> Vec<String> {
    let mut flags = vec![];
    if end_stream && bits & 0x1 != 0 {
        flags.push("end_stream".to_owned());
    }
    if bits & 0x8 != 0 {
        flags.push("padded".to_owned());
    }
    flags
}

fn header_flags(bits: u8) -> Vec<String> {
    let mut flags = common_flags(bits, true);
    if bits & 0x4 != 0 {
        flags.push("end_headers".to_owned());
    }
    if bits & 0x20 != 0 {
        flags.push("priority".to_owned());
    }
    flags
}

fn end_headers_flags(bits: u8) -> Vec<String> {
    (bits & 0x4 != 0)
        .then(|| "end_headers".to_owned())
        .into_iter()
        .collect()
}

fn settings_flags(bits: u8) -> Vec<String> {
    (bits & 0x1 != 0)
        .then(|| "ack".to_owned())
        .into_iter()
        .collect()
}

fn ping_flags(bits: u8) -> Vec<String> {
    settings_flags(bits)
}

fn unknown_flags(bits: u8) -> Vec<String> {
    if bits == 0 {
        vec![]
    } else {
        vec![format!("0x{bits:02x}")]
    }
}

#[cfg(feature = "boring-backend")]
mod server {
    use super::{
        CapturedH2Frame, ControlledCaptureError, Http2FrameDetail, Http2FrameType,
        parse_client_frames,
    };
    use boring::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        rsa::Rsa,
        ssl::{self, SslAcceptor, SslMethod},
        x509::{
            X509, X509Name,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        },
    };
    use bytes::Bytes;
    use capture_schema::{CancellationStage, HeaderObservation, ProtocolAction};
    use http::{Request, Response, header};
    use serde_json::{Value, json};
    use std::{
        io,
        net::{IpAddr, SocketAddr},
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
        net::TcpListener,
    };

    pub struct ControlledH2Server {
        listener: TcpListener,
        acceptor: SslAcceptor,
        ca_pem: Vec<u8>,
        timeout: Duration,
        max_capture_bytes: usize,
        response_mode: ControlledResponseMode,
    }

    impl std::fmt::Debug for ControlledH2Server {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("ControlledH2Server")
                .field("listener", &self.listener)
                .field("timeout", &self.timeout)
                .field("max_capture_bytes", &self.max_capture_bytes)
                .field("response_mode", &self.response_mode)
                .finish_non_exhaustive()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ControlledH2Result {
        pub frames: Vec<CapturedH2Frame>,
        pub http1_request: Option<Http1RequestObservation>,
        pub decoded_headers: Vec<HeaderObservation>,
        pub request_summary: Option<ClaudeRequestSummary>,
        pub response_sse_chunk_lengths: Vec<u32>,
        pub negotiated_alpn: String,
        pub decrypted_client_bytes: usize,
        pub skipped_background_requests: usize,
        pub cancellation: Option<ControlledCancellationObservation>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ControlledCancellationObservation {
        pub stage: CancellationStage,
        pub protocol_action: ProtocolAction,
        pub peer_close_observed: bool,
        pub other_streams_affected: bool,
        pub response_bytes_sent: u32,
    }

    type Http1ResponseResult = (
        Option<ClaudeRequestSummary>,
        Vec<u32>,
        Option<ControlledCancellationObservation>,
    );

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Http1RequestObservation {
        pub method: String,
        pub path: String,
        pub version: String,
        pub headers: Vec<HeaderObservation>,
        pub body_bytes: u32,
    }

    #[derive(Clone, PartialEq, Eq)]
    pub enum ControlledResponseMode {
        NoContent,
        ClaudeMessages {
            expected_authorization: String,
            max_request_body_bytes: usize,
        },
        ClaudeMessagesCancellation {
            expected_authorization: String,
            max_request_body_bytes: usize,
            observation_timeout: Duration,
        },
    }

    impl std::fmt::Debug for ControlledResponseMode {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NoContent => formatter.write_str("NoContent"),
                Self::ClaudeMessages {
                    max_request_body_bytes,
                    ..
                } => formatter
                    .debug_struct("ClaudeMessages")
                    .field("expected_authorization", &"[redacted]")
                    .field("max_request_body_bytes", max_request_body_bytes)
                    .finish(),
                Self::ClaudeMessagesCancellation {
                    max_request_body_bytes,
                    observation_timeout,
                    ..
                } => formatter
                    .debug_struct("ClaudeMessagesCancellation")
                    .field("expected_authorization", &"[redacted]")
                    .field("max_request_body_bytes", max_request_body_bytes)
                    .field("observation_timeout", observation_timeout)
                    .finish(),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ClaudeRequestSummary {
        pub request_path: String,
        pub body_bytes: usize,
        pub stream_requested: bool,
        pub synthetic_authorization_matched: bool,
        pub authorization_header_names: Vec<String>,
        pub top_level_field_names: Vec<String>,
        pub message_count: usize,
        pub tool_count: usize,
        pub thinking_type: Option<String>,
        pub output_config_field_names: Vec<String>,
        pub output_format_type: Option<String>,
        pub output_schema_type: Option<String>,
        pub output_schema_property_names: Vec<String>,
        pub output_schema_required: Vec<String>,
    }

    impl ControlledH2Server {
        /// Binds an ephemeral, in-memory-CA TLS/H2 endpoint for one probe.
        ///
        /// # Errors
        ///
        /// Returns [`ControlledCaptureError`] for certificate, acceptor, or
        /// listener setup failure.
        pub async fn bind(
            listen: SocketAddr,
            authority: &str,
            timeout: Duration,
            max_capture_bytes: usize,
        ) -> Result<Self, ControlledCaptureError> {
            Self::bind_with_mode(
                listen,
                authority,
                timeout,
                max_capture_bytes,
                ControlledResponseMode::NoContent,
            )
            .await
        }

        /// Binds a one-shot endpoint that returns a synthetic Claude Messages
        /// response and verifies that only the configured synthetic credential
        /// reached the capture service.
        ///
        /// # Errors
        ///
        /// Returns [`ControlledCaptureError`] for invalid configuration or
        /// listener/certificate setup failure.
        pub async fn bind_claude_messages(
            listen: SocketAddr,
            authority: &str,
            timeout: Duration,
            max_capture_bytes: usize,
            expected_authorization: String,
            max_request_body_bytes: usize,
        ) -> Result<Self, ControlledCaptureError> {
            if expected_authorization.is_empty() || max_request_body_bytes < 1024 {
                return Err(ControlledCaptureError::InvalidConfig);
            }
            Self::bind_with_mode(
                listen,
                authority,
                timeout,
                max_capture_bytes,
                ControlledResponseMode::ClaudeMessages {
                    expected_authorization,
                    max_request_body_bytes,
                },
            )
            .await
        }

        /// Binds a one-shot HTTP/1.1 endpoint that emits one partial SSE chunk,
        /// keeps the response open, and observes whether the client closes the
        /// connection after cancelling the in-flight response.
        ///
        /// # Errors
        ///
        /// Returns [`ControlledCaptureError`] for invalid configuration or
        /// listener/certificate setup failure.
        pub async fn bind_claude_messages_cancellation(
            listen: SocketAddr,
            authority: &str,
            timeout: Duration,
            max_capture_bytes: usize,
            expected_authorization: String,
            max_request_body_bytes: usize,
            observation_timeout: Duration,
        ) -> Result<Self, ControlledCaptureError> {
            if expected_authorization.is_empty()
                || max_request_body_bytes < 1024
                || observation_timeout.is_zero()
            {
                return Err(ControlledCaptureError::InvalidConfig);
            }
            Self::bind_with_mode(
                listen,
                authority,
                timeout,
                max_capture_bytes,
                ControlledResponseMode::ClaudeMessagesCancellation {
                    expected_authorization,
                    max_request_body_bytes,
                    observation_timeout,
                },
            )
            .await
        }

        async fn bind_with_mode(
            listen: SocketAddr,
            authority: &str,
            timeout: Duration,
            max_capture_bytes: usize,
            response_mode: ControlledResponseMode,
        ) -> Result<Self, ControlledCaptureError> {
            if authority.is_empty() || timeout.is_zero() || max_capture_bytes < 1024 {
                return Err(ControlledCaptureError::InvalidConfig);
            }
            let (certificate, key) = ephemeral_certificate(authority)?;
            let ca_pem = certificate
                .to_pem()
                .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
            let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())
                .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
            acceptor
                .set_certificate(&certificate)
                .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
            acceptor
                .set_private_key(&key)
                .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
            acceptor
                .check_private_key()
                .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
            acceptor.set_alpn_select_callback(|_, client| {
                ssl::select_next_proto(b"\x02h2\x08http/1.1", client).ok_or(ssl::AlpnError::NOACK)
            });
            let listener = TcpListener::bind(listen)
                .await
                .map_err(ControlledCaptureError::Io)?;
            Ok(Self {
                listener,
                acceptor: acceptor.build(),
                ca_pem,
                timeout,
                max_capture_bytes,
                response_mode,
            })
        }

        /// Returns the bound endpoint address.
        ///
        /// # Errors
        ///
        /// Returns [`ControlledCaptureError`] when socket metadata fails.
        pub fn local_addr(&self) -> Result<SocketAddr, ControlledCaptureError> {
            self.listener
                .local_addr()
                .map_err(ControlledCaptureError::Io)
        }

        pub fn ca_pem(&self) -> &[u8] {
            &self.ca_pem
        }

        /// Accepts one TLS/H2 connection and returns parsed client frames.
        ///
        /// # Errors
        ///
        /// Returns [`ControlledCaptureError`] on timeout, TLS/H2 failure,
        /// capture overflow, or malformed client bytes.
        pub async fn capture_one(self) -> Result<ControlledH2Result, ControlledCaptureError> {
            let timeout = self.timeout;
            tokio::time::timeout(timeout, Box::pin(self.capture_one_inner()))
                .await
                .map_err(|_| ControlledCaptureError::Timeout)?
        }

        async fn capture_one_inner(self) -> Result<ControlledH2Result, ControlledCaptureError> {
            let mut skipped_background_requests = 0_usize;
            for _ in 0..8 {
                let (tcp, _) = self
                    .listener
                    .accept()
                    .await
                    .map_err(ControlledCaptureError::Io)?;
                let tls = tokio_boring::accept(&self.acceptor, tcp)
                    .await
                    .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
                let mut result = match tls.ssl().selected_alpn_protocol() {
                    Some(b"h2") => {
                        capture_h2(tls, self.max_capture_bytes, &self.response_mode).await
                    }
                    Some(b"http/1.1") | None => {
                        capture_http1(tls, self.max_capture_bytes, &self.response_mode).await
                    }
                    Some(protocol) => Err(ControlledCaptureError::Tls(format!(
                        "unsupported negotiated ALPN {}",
                        String::from_utf8_lossy(protocol)
                    ))),
                }?;
                let Some(summary) = result.request_summary.as_ref() else {
                    continue;
                };
                if summary.body_bytes == 0 || !is_messages_path(&summary.request_path) {
                    continue;
                }
                if is_conversation_title_request(summary) {
                    skipped_background_requests = skipped_background_requests.saturating_add(1);
                    continue;
                }
                result.skipped_background_requests = skipped_background_requests;
                return Ok(result);
            }
            Err(ControlledCaptureError::MessagesRequestNotObserved)
        }
    }

    async fn capture_h2<S>(
        tls: S,
        max_capture_bytes: usize,
        response_mode: &ControlledResponseMode,
    ) -> Result<ControlledH2Result, ControlledCaptureError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let recording = RecordingIo {
            inner: tls,
            captured: Arc::clone(&captured),
            max_capture_bytes,
        };
        let mut connection = h2::server::handshake(recording)
            .await
            .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
        let (mut request, mut responder) = match connection.accept().await {
            Some(Ok((request, responder))) => (request, responder),
            Some(Err(error)) => return Err(ControlledCaptureError::H2(error.to_string())),
            None => {
                return Err(ControlledCaptureError::H2(
                    "client closed before sending a request".to_owned(),
                ));
            }
        };
        let decoded_headers = decoded_request_headers(&request)?;
        let (request_summary, response_sse_chunk_lengths) = handle_request(
            &mut connection,
            &mut request,
            &mut responder,
            response_mode,
            &decoded_headers,
        )
        .await?;
        let _ = tokio::time::timeout(Duration::from_millis(250), connection.accept()).await;
        drop(connection);
        let bytes = captured
            .lock()
            .map_err(|_| ControlledCaptureError::CapturePoisoned)?
            .clone();
        let mut frames = parse_client_frames(&bytes)?;
        if let Some(frame) = frames
            .iter_mut()
            .find(|frame| frame.frame_type == Http2FrameType::Headers)
        {
            frame.detail = Http2FrameDetail::Headers {
                headers: decoded_headers.clone(),
            };
        }
        Ok(ControlledH2Result {
            frames,
            http1_request: None,
            decoded_headers,
            request_summary,
            response_sse_chunk_lengths,
            negotiated_alpn: "h2".to_owned(),
            decrypted_client_bytes: bytes.len(),
            skipped_background_requests: 0,
            cancellation: None,
        })
    }

    async fn capture_http1<S>(
        mut tls: S,
        max_capture_bytes: usize,
        response_mode: &ControlledResponseMode,
    ) -> Result<ControlledH2Result, ControlledCaptureError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut bytes = Vec::new();
        let mut buffer = vec![0_u8; 16 * 1024].into_boxed_slice();
        let header_end = loop {
            if let Some(position) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break position + 4;
            }
            let read = tls
                .read(&mut buffer)
                .await
                .map_err(ControlledCaptureError::Io)?;
            if read == 0 {
                return Err(ControlledCaptureError::Http1(
                    "client closed before sending complete headers".to_owned(),
                ));
            }
            if bytes.len().saturating_add(read) > max_capture_bytes {
                return Err(ControlledCaptureError::RequestBodyTooLarge);
            }
            bytes.extend_from_slice(&buffer[..read]);
        };
        let (method, path, version, headers) = parse_http1_head(&bytes[..header_end])?;
        let content_length = http1_content_length(&headers)?;
        let body_end = header_end
            .checked_add(content_length)
            .ok_or(ControlledCaptureError::RequestBodyTooLarge)?;
        if body_end > max_capture_bytes {
            return Err(ControlledCaptureError::RequestBodyTooLarge);
        }
        while bytes.len() < body_end {
            let read = tls
                .read(&mut buffer)
                .await
                .map_err(ControlledCaptureError::Io)?;
            if read == 0 {
                return Err(ControlledCaptureError::Http1(
                    "client closed before sending complete body".to_owned(),
                ));
            }
            if bytes.len().saturating_add(read) > max_capture_bytes {
                return Err(ControlledCaptureError::RequestBodyTooLarge);
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        let body = &bytes[header_end..body_end];
        let (request_summary, response_sse_chunk_lengths, cancellation) =
            send_http1_claude_response(&mut tls, response_mode, &path, &headers, body).await?;
        if cancellation.is_none()
            && let Err(error) = tls.shutdown().await
            && !is_terminal_tls_close(&error)
        {
            return Err(ControlledCaptureError::Io(error));
        }
        let body_bytes =
            u32::try_from(body.len()).map_err(|_| ControlledCaptureError::RequestBodyTooLarge)?;
        Ok(ControlledH2Result {
            frames: vec![],
            http1_request: Some(Http1RequestObservation {
                method,
                path,
                version,
                headers: headers.clone(),
                body_bytes,
            }),
            decoded_headers: headers,
            request_summary,
            response_sse_chunk_lengths,
            negotiated_alpn: "http/1.1".to_owned(),
            decrypted_client_bytes: body_end,
            skipped_background_requests: 0,
            cancellation,
        })
    }

    fn parse_http1_head(
        head: &[u8],
    ) -> Result<(String, String, String, Vec<HeaderObservation>), ControlledCaptureError> {
        let text = std::str::from_utf8(head)
            .map_err(|_| ControlledCaptureError::Http1("headers are not UTF-8".to_owned()))?;
        let mut lines = text.split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| ControlledCaptureError::Http1("missing request line".to_owned()))?;
        let mut request_parts = request_line.split_ascii_whitespace();
        let method = request_parts
            .next()
            .ok_or_else(|| ControlledCaptureError::Http1("missing method".to_owned()))?;
        let path = request_parts
            .next()
            .ok_or_else(|| ControlledCaptureError::Http1("missing request target".to_owned()))?;
        let version = request_parts
            .next()
            .ok_or_else(|| ControlledCaptureError::Http1("missing version".to_owned()))?;
        if request_parts.next().is_some() {
            return Err(ControlledCaptureError::Http1(
                "invalid request line".to_owned(),
            ));
        }
        let headers = lines
            .take_while(|line| !line.is_empty())
            .map(|line| {
                let (name, value) = line.split_once(':').ok_or_else(|| {
                    ControlledCaptureError::Http1("invalid header line".to_owned())
                })?;
                if name.is_empty() {
                    return Err(ControlledCaptureError::Http1(
                        "empty header name".to_owned(),
                    ));
                }
                Ok(HeaderObservation {
                    name: name.to_owned(),
                    value: value.trim().to_owned(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            method.to_owned(),
            path.to_owned(),
            version.to_owned(),
            headers,
        ))
    }

    pub(super) fn is_terminal_tls_close(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::NotConnected
                | io::ErrorKind::UnexpectedEof
        )
    }

    fn http1_content_length(
        headers: &[HeaderObservation],
    ) -> Result<usize, ControlledCaptureError> {
        if headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("transfer-encoding")
                && !header.value.eq_ignore_ascii_case("identity")
        }) {
            return Err(ControlledCaptureError::Http1(
                "chunked request bodies are not supported by the capture fixture".to_owned(),
            ));
        }
        headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-length"))
            .map_or(Ok(0), |header| {
                header
                    .value
                    .parse::<usize>()
                    .map_err(|_| ControlledCaptureError::Http1("invalid content-length".to_owned()))
            })
    }

    async fn send_http1_claude_response<S>(
        stream: &mut S,
        response_mode: &ControlledResponseMode,
        request_path: &str,
        headers: &[HeaderObservation],
        body: &[u8],
    ) -> Result<Http1ResponseResult, ControlledCaptureError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (expected_authorization, max_request_body_bytes, observation_timeout) =
            match response_mode {
                ControlledResponseMode::NoContent => {
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await
                        .map_err(ControlledCaptureError::Io)?;
                    return Ok((None, vec![], None));
                }
                ControlledResponseMode::ClaudeMessages {
                    expected_authorization,
                    max_request_body_bytes,
                } => (expected_authorization, max_request_body_bytes, None),
                ControlledResponseMode::ClaudeMessagesCancellation {
                    expected_authorization,
                    max_request_body_bytes,
                    observation_timeout,
                } => (
                    expected_authorization,
                    max_request_body_bytes,
                    Some(*observation_timeout),
                ),
            };
        if let Some(observation_timeout) = observation_timeout {
            return send_http1_cancellation_response(
                stream,
                request_path,
                headers,
                body,
                expected_authorization,
                *max_request_body_bytes,
                observation_timeout,
            )
            .await;
        }
        send_http1_complete_response(
            stream,
            request_path,
            headers,
            body,
            expected_authorization,
            *max_request_body_bytes,
        )
        .await
    }

    async fn send_http1_complete_response<S>(
        stream: &mut S,
        request_path: &str,
        headers: &[HeaderObservation],
        body: &[u8],
        expected_authorization: &str,
        max_request_body_bytes: usize,
    ) -> Result<Http1ResponseResult, ControlledCaptureError>
    where
        S: AsyncWrite + Unpin,
    {
        if body.len() > max_request_body_bytes {
            return Err(ControlledCaptureError::RequestBodyTooLarge);
        }
        let synthetic_authorization_matched =
            authorization_matches(headers, expected_authorization);
        let request_json = serde_json::from_slice::<Value>(body).ok();
        let request_shape = request_json.as_ref().map(request_shape_summary);
        let stream_requested = request_json
            .as_ref()
            .and_then(|value| value.get("stream"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let payload = http1_response_payload(
            request_json.as_ref(),
            synthetic_authorization_matched,
            stream_requested,
        )?;
        let streaming = payload.content_type == "text/event-stream";
        let framing = if streaming {
            "Transfer-Encoding: chunked\r\nCache-Control: no-cache\r\nConnection: keep-alive"
                .to_owned()
        } else {
            format!(
                "Content-Length: {}\r\nConnection: close",
                payload.body.len()
            )
        };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{framing}\r\nrequest-id: req_01CaptureFixture000000000000\r\n\r\n",
            status = payload.status,
            reason = payload.reason,
            content_type = payload.content_type,
        );
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(ControlledCaptureError::Io)?;
        if streaming {
            stream
                .write_all(format!("{:x}\r\n", payload.body.len()).as_bytes())
                .await
                .map_err(ControlledCaptureError::Io)?;
            stream
                .write_all(&payload.body)
                .await
                .map_err(ControlledCaptureError::Io)?;
            stream
                .write_all(b"\r\n0\r\n\r\n")
                .await
                .map_err(ControlledCaptureError::Io)?;
        } else {
            stream
                .write_all(&payload.body)
                .await
                .map_err(ControlledCaptureError::Io)?;
        }
        let authorization_header_names = headers
            .iter()
            .filter(|item| {
                matches!(
                    item.name.to_ascii_lowercase().as_str(),
                    "authorization" | "x-api-key"
                )
            })
            .map(|item| item.name.to_ascii_lowercase())
            .collect();
        Ok((
            Some(claude_request_summary(
                request_path.to_owned(),
                body.len(),
                stream_requested,
                synthetic_authorization_matched,
                authorization_header_names,
                request_shape,
            )),
            payload.sse_chunk_lengths,
            None,
        ))
    }

    async fn send_http1_cancellation_response<S>(
        stream: &mut S,
        request_path: &str,
        headers: &[HeaderObservation],
        body: &[u8],
        expected_authorization: &str,
        max_request_body_bytes: usize,
        observation_timeout: Duration,
    ) -> Result<Http1ResponseResult, ControlledCaptureError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if body.len() > max_request_body_bytes {
            return Err(ControlledCaptureError::RequestBodyTooLarge);
        }
        let synthetic_authorization_matched =
            authorization_matches(headers, expected_authorization);
        let request_json = serde_json::from_slice::<Value>(body).ok();
        let request_shape = request_json.as_ref().map(request_shape_summary);
        let stream_requested = request_json
            .as_ref()
            .and_then(|value| value.get("stream"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !synthetic_authorization_matched || !stream_requested {
            return Err(ControlledCaptureError::InvalidConfig);
        }
        let first_event = b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nrequest-id: req_01CaptureFixture000000000000\r\n\r\n";
        stream
            .write_all(head)
            .await
            .map_err(ControlledCaptureError::Io)?;
        stream
            .write_all(format!("{:x}\r\n", first_event.len()).as_bytes())
            .await
            .map_err(ControlledCaptureError::Io)?;
        stream
            .write_all(first_event)
            .await
            .map_err(ControlledCaptureError::Io)?;
        stream
            .write_all(b"\r\n")
            .await
            .map_err(ControlledCaptureError::Io)?;
        stream.flush().await.map_err(ControlledCaptureError::Io)?;

        let mut byte = [0_u8; 1];
        let peer_close_observed =
            match tokio::time::timeout(observation_timeout, stream.read(&mut byte)).await {
                Ok(Ok(0) | Err(_)) => true,
                Ok(Ok(_)) | Err(_) => false,
            };
        if !peer_close_observed {
            return Err(ControlledCaptureError::CancellationNotObserved);
        }
        let response_bytes_sent = u32::try_from(first_event.len())
            .map_err(|_| ControlledCaptureError::Malformed("SSE event too large"))?;
        Ok((
            Some(claude_request_summary(
                request_path.to_owned(),
                body.len(),
                stream_requested,
                synthetic_authorization_matched,
                headers
                    .iter()
                    .filter(|item| {
                        matches!(
                            item.name.to_ascii_lowercase().as_str(),
                            "authorization" | "x-api-key"
                        )
                    })
                    .map(|item| item.name.to_ascii_lowercase())
                    .collect(),
                request_shape,
            )),
            vec![response_bytes_sent],
            Some(ControlledCancellationObservation {
                stage: CancellationStage::ResponseStreaming,
                protocol_action: ProtocolAction::CloseConnection,
                peer_close_observed,
                other_streams_affected: false,
                response_bytes_sent,
            }),
        ))
    }

    struct Http1ResponsePayload {
        status: u16,
        reason: &'static str,
        content_type: &'static str,
        body: Vec<u8>,
        sse_chunk_lengths: Vec<u32>,
    }

    fn http1_response_payload(
        request: Option<&Value>,
        authorized: bool,
        stream: bool,
    ) -> Result<Http1ResponsePayload, ControlledCaptureError> {
        if !authorized {
            let body = serde_json::to_vec(&json!({
                "type": "error",
                "error": {"type": "authentication_error", "message": "invalid capture credential"}
            }))
            .map_err(|error| ControlledCaptureError::Json(error.to_string()))?;
            return Ok(Http1ResponsePayload {
                status: 401,
                reason: "Unauthorized",
                content_type: "application/json",
                body,
                sse_chunk_lengths: vec![],
            });
        }
        let Some(request) = request else {
            let body = serde_json::to_vec(&json!({
                "type": "error",
                "error": {"type": "invalid_request_error", "message": "invalid JSON"}
            }))
            .map_err(|error| ControlledCaptureError::Json(error.to_string()))?;
            return Ok(Http1ResponsePayload {
                status: 400,
                reason: "Bad Request",
                content_type: "application/json",
                body,
                sse_chunk_lengths: vec![],
            });
        };
        let model = request
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("capture-model");
        let response_text = synthetic_response_text(request)?;
        if stream {
            let body = synthetic_sse(model, &response_text)?;
            let length = u32::try_from(body.len())
                .map_err(|_| ControlledCaptureError::Malformed("SSE payload too large"))?;
            Ok(Http1ResponsePayload {
                status: 200,
                reason: "OK",
                content_type: "text/event-stream",
                body,
                sse_chunk_lengths: vec![length],
            })
        } else {
            let body = serde_json::to_vec(&json!({
                "id": "msg_01CaptureFixture000000000000",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [{"type": "text", "text": response_text}],
                "container": null,
                "context_management": null,
                "stop_reason": "end_turn",
                "stop_sequence": null,
                "usage": synthetic_usage(2)
            }))
            .map_err(|error| ControlledCaptureError::Json(error.to_string()))?;
            Ok(Http1ResponsePayload {
                status: 200,
                reason: "OK",
                content_type: "application/json",
                body,
                sse_chunk_lengths: vec![],
            })
        }
    }

    async fn handle_request<T>(
        connection: &mut h2::server::Connection<T, Bytes>,
        request: &mut Request<h2::RecvStream>,
        responder: &mut h2::server::SendResponse<Bytes>,
        response_mode: &ControlledResponseMode,
        decoded_headers: &[HeaderObservation],
    ) -> Result<(Option<ClaudeRequestSummary>, Vec<u32>), ControlledCaptureError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let ControlledResponseMode::ClaudeMessages {
            expected_authorization,
            max_request_body_bytes,
        } = response_mode
        else {
            let response = Response::builder()
                .status(204)
                .body(())
                .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
            responder
                .send_response(response, true)
                .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
            return Ok((None, vec![]));
        };
        let body =
            read_request_body(connection, request.body_mut(), *max_request_body_bytes).await?;
        let request_path = request.uri().path().to_owned();
        let authorization_header_names = decoded_headers
            .iter()
            .filter(|item| {
                matches!(
                    item.name.to_ascii_lowercase().as_str(),
                    "authorization" | "x-api-key"
                )
            })
            .map(|item| item.name.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let synthetic_authorization_matched =
            authorization_matches(decoded_headers, expected_authorization);
        let request_json = serde_json::from_slice::<Value>(&body).ok();
        let request_shape = request_json.as_ref().map(request_shape_summary);
        let stream_requested = request_json
            .as_ref()
            .and_then(|value| value.get("stream"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let response_chunk_lengths = send_claude_response(
            responder,
            request_json.as_ref(),
            synthetic_authorization_matched,
        )?;
        Ok((
            Some(claude_request_summary(
                request_path,
                body.len(),
                stream_requested,
                synthetic_authorization_matched,
                authorization_header_names,
                request_shape,
            )),
            response_chunk_lengths,
        ))
    }

    async fn read_request_body<T>(
        connection: &mut h2::server::Connection<T, Bytes>,
        body: &mut h2::RecvStream,
        max_request_body_bytes: usize,
    ) -> Result<Vec<u8>, ControlledCaptureError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut collected = Vec::new();
        loop {
            tokio::select! {
                data = body.data() => {
                    let Some(data) = data else {
                        return Ok(collected);
                    };
                    let data = data.map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
                    if collected.len().saturating_add(data.len()) > max_request_body_bytes {
                        return Err(ControlledCaptureError::RequestBodyTooLarge);
                    }
                    collected.extend_from_slice(&data);
                    body.flow_control()
                        .release_capacity(data.len())
                        .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
                }
                next = connection.accept() => {
                    match next {
                        Some(Ok((_request, mut responder))) => {
                            let response = Response::builder()
                                .status(503)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(())
                                .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
                            responder
                                .send_response(response, true)
                                .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
                        }
                        Some(Err(error)) => {
                            return Err(ControlledCaptureError::H2(error.to_string()));
                        }
                        None => return Ok(collected),
                    }
                }
            }
        }
    }

    fn authorization_matches(headers: &[HeaderObservation], expected: &str) -> bool {
        headers.iter().any(|header| {
            matches!(
                header.name.to_ascii_lowercase().as_str(),
                "authorization" | "x-api-key"
            ) && (header.value == expected || header.value == format!("Bearer {expected}"))
        })
    }

    #[derive(Default)]
    struct RequestShapeSummary {
        top_level_field_names: Vec<String>,
        message_count: usize,
        tool_count: usize,
        thinking_type: Option<String>,
        output_config_field_names: Vec<String>,
        output_format_type: Option<String>,
        output_schema_type: Option<String>,
        output_schema_property_names: Vec<String>,
        output_schema_required: Vec<String>,
    }

    fn request_shape_summary(request: &Value) -> RequestShapeSummary {
        let mut top_level_field_names = request
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        top_level_field_names.sort();
        let thinking_type = request
            .get("thinking")
            .and_then(|thinking| thinking.get("type"))
            .and_then(Value::as_str)
            .filter(|value| matches!(*value, "adaptive" | "enabled" | "disabled"))
            .map(str::to_owned);
        let mut output_config_field_names = request
            .get("output_config")
            .and_then(Value::as_object)
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        output_config_field_names.sort();
        let output_format = request
            .get("output_config")
            .and_then(|config| config.get("format"));
        let output_format_type = output_format
            .and_then(|format| format.get("type"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let output_schema = output_format.and_then(|format| format.get("schema"));
        let output_schema_type = output_schema
            .and_then(|schema| schema.get("type"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut output_schema_property_names = output_schema
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .map(|properties| properties.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        output_schema_property_names.sort();
        let mut output_schema_required = output_schema
            .and_then(|schema| schema.get("required"))
            .and_then(Value::as_array)
            .map(|required| {
                required
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        output_schema_required.sort();
        RequestShapeSummary {
            message_count: request
                .get("messages")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            tool_count: request
                .get("tools")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            thinking_type,
            output_config_field_names,
            output_format_type,
            output_schema_type,
            output_schema_property_names,
            output_schema_required,
            top_level_field_names,
        }
    }

    fn claude_request_summary(
        request_path: String,
        body_bytes: usize,
        stream_requested: bool,
        synthetic_authorization_matched: bool,
        authorization_header_names: Vec<String>,
        request_shape: Option<RequestShapeSummary>,
    ) -> ClaudeRequestSummary {
        let request_shape = request_shape.unwrap_or_default();
        ClaudeRequestSummary {
            request_path,
            body_bytes,
            stream_requested,
            synthetic_authorization_matched,
            authorization_header_names,
            top_level_field_names: request_shape.top_level_field_names,
            message_count: request_shape.message_count,
            tool_count: request_shape.tool_count,
            thinking_type: request_shape.thinking_type,
            output_config_field_names: request_shape.output_config_field_names,
            output_format_type: request_shape.output_format_type,
            output_schema_type: request_shape.output_schema_type,
            output_schema_property_names: request_shape.output_schema_property_names,
            output_schema_required: request_shape.output_schema_required,
        }
    }

    fn is_messages_path(path: &str) -> bool {
        path.split('?').next() == Some("/v1/messages")
    }

    fn is_conversation_title_request(summary: &ClaudeRequestSummary) -> bool {
        summary.output_format_type.as_deref() == Some("json_schema")
            && summary.output_schema_type.as_deref() == Some("object")
            && summary.output_schema_property_names == ["title"]
            && summary.output_schema_required == ["title"]
    }

    fn send_claude_response(
        responder: &mut h2::server::SendResponse<Bytes>,
        request: Option<&Value>,
        authorized: bool,
    ) -> Result<Vec<u32>, ControlledCaptureError> {
        if !authorized {
            let body = serde_json::to_vec(&json!({
                "type": "error",
                "error": {
                    "type": "authentication_error",
                    "message": "capture endpoint requires the configured synthetic credential"
                }
            }))
            .map_err(|error| ControlledCaptureError::Json(error.to_string()))?;
            return send_json_response(responder, 401, body).map(|()| vec![]);
        }
        let Some(request) = request else {
            let body = serde_json::to_vec(&json!({
                "type": "error",
                "error": {
                    "type": "invalid_request_error",
                    "message": "capture endpoint received invalid JSON"
                }
            }))
            .map_err(|error| ControlledCaptureError::Json(error.to_string()))?;
            return send_json_response(responder, 400, body).map(|()| vec![]);
        };
        let model = request
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("capture-model");
        let stream = request
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let response_text = synthetic_response_text(request)?;
        if stream {
            let payload = synthetic_sse(model, &response_text)?;
            let length = u32::try_from(payload.len())
                .map_err(|_| ControlledCaptureError::Malformed("SSE payload too large"))?;
            let response = Response::builder()
                .status(200)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header(header::CACHE_CONTROL, "no-cache")
                .header("request-id", "req_01CaptureFixture000000000000")
                .body(())
                .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
            let mut stream = responder
                .send_response(response, false)
                .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
            stream
                .send_data(Bytes::from(payload), true)
                .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
            Ok(vec![length])
        } else {
            let body = serde_json::to_vec(&json!({
                "id": "msg_01CaptureFixture000000000000",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [{"type": "text", "text": response_text}],
                "container": null,
                "context_management": null,
                "stop_reason": "end_turn",
                "stop_sequence": null,
                "usage": synthetic_usage(2)
            }))
            .map_err(|error| ControlledCaptureError::Json(error.to_string()))?;
            send_json_response(responder, 200, body)?;
            Ok(vec![])
        }
    }

    fn send_json_response(
        responder: &mut h2::server::SendResponse<Bytes>,
        status: u16,
        body: Vec<u8>,
    ) -> Result<(), ControlledCaptureError> {
        let response = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .header("request-id", "req_01CaptureFixture000000000000")
            .body(())
            .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
        let mut stream = responder
            .send_response(response, false)
            .map_err(|error| ControlledCaptureError::H2(error.to_string()))?;
        stream
            .send_data(Bytes::from(body), true)
            .map_err(|error| ControlledCaptureError::H2(error.to_string()))
    }

    fn synthetic_sse(model: &str, response_text: &str) -> Result<Vec<u8>, ControlledCaptureError> {
        let events = [
            (
                "message_start",
                json!({
                    "type": "message_start",
                    "message": {
                        "id": "msg_01CaptureFixture000000000000",
                        "type": "message",
                        "role": "assistant",
                        "model": model,
                        "content": [],
                        "container": null,
                        "context_management": null,
                        "stop_reason": null,
                        "stop_sequence": null,
                        "usage": synthetic_usage(1)
                    }
                }),
            ),
            (
                "content_block_start",
                json!({
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""}
                }),
            ),
            (
                "content_block_delta",
                json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": response_text}
                }),
            ),
            (
                "content_block_stop",
                json!({
                    "type": "content_block_stop",
                    "index": 0
                }),
            ),
            (
                "message_delta",
                json!({
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                    "usage": synthetic_usage(2)
                }),
            ),
            ("message_stop", json!({"type": "message_stop"})),
        ];
        let mut output = Vec::new();
        for (event, data) in events {
            output.extend_from_slice(b"event: ");
            output.extend_from_slice(event.as_bytes());
            output.extend_from_slice(b"\ndata: ");
            output.extend_from_slice(
                serde_json::to_string(&data)
                    .map_err(|error| ControlledCaptureError::Json(error.to_string()))?
                    .as_bytes(),
            );
            output.extend_from_slice(b"\n\n");
        }
        Ok(output)
    }

    fn synthetic_response_text(request: &Value) -> Result<String, ControlledCaptureError> {
        let schema = request
            .get("output_config")
            .and_then(|config| config.get("format"))
            .filter(|format| format.get("type").and_then(Value::as_str) == Some("json_schema"))
            .and_then(|format| format.get("schema"));
        let Some(schema) = schema else {
            return Ok("capture complete".to_owned());
        };
        serde_json::to_string(&synthetic_schema_value(schema, 0))
            .map_err(|error| ControlledCaptureError::Json(error.to_string()))
    }

    fn synthetic_schema_value(schema: &Value, depth: usize) -> Value {
        if depth >= 8 {
            return Value::Null;
        }
        if let Some(value) = schema.get("const") {
            return value.clone();
        }
        if let Some(value) = schema
            .get("enum")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
        {
            return value.clone();
        }
        let schema_type = schema
            .get("type")
            .and_then(|value| match value {
                Value::String(value) => Some(value.as_str()),
                Value::Array(values) => values
                    .iter()
                    .filter_map(Value::as_str)
                    .find(|value| *value != "null"),
                _ => None,
            })
            .unwrap_or("object");
        match schema_type {
            "object" => {
                let properties = schema.get("properties").and_then(Value::as_object);
                let required = schema
                    .get("required")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str);
                let object = required
                    .map(|name| {
                        let value = properties
                            .and_then(|properties| properties.get(name))
                            .map_or_else(
                                || Value::String("capture complete".to_owned()),
                                |property| synthetic_schema_value(property, depth + 1),
                            );
                        (name.to_owned(), value)
                    })
                    .collect();
                Value::Object(object)
            }
            "array" => Value::Array(vec![]),
            "boolean" => Value::Bool(true),
            "integer" | "number" => Value::Number(1.into()),
            "null" => Value::Null,
            _ => Value::String("capture complete".to_owned()),
        }
    }

    fn synthetic_usage(output_tokens: u64) -> Value {
        json!({
            "input_tokens": 1,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "cache_creation": {
                "ephemeral_5m_input_tokens": 0,
                "ephemeral_1h_input_tokens": 0
            },
            "output_tokens": output_tokens,
            "output_tokens_details": {
                "thinking_tokens": 0
            },
            "service_tier": "standard",
            "server_tool_use": {
                "web_search_requests": 0,
                "web_fetch_requests": 0
            }
        })
    }

    fn decoded_request_headers(
        request: &http::Request<h2::RecvStream>,
    ) -> Result<Vec<HeaderObservation>, ControlledCaptureError> {
        let mut headers = vec![HeaderObservation {
            name: ":method".to_owned(),
            value: request.method().as_str().to_owned(),
        }];
        if let Some(authority) = request.uri().authority() {
            headers.push(HeaderObservation {
                name: ":authority".to_owned(),
                value: authority.as_str().to_owned(),
            });
        }
        for (name, value) in request.headers() {
            headers.push(HeaderObservation {
                name: name.as_str().to_owned(),
                value: value
                    .to_str()
                    .map_err(|_| ControlledCaptureError::Malformed("non-ASCII request header"))?
                    .to_owned(),
            });
        }
        Ok(headers)
    }

    fn ephemeral_certificate(
        authority: &str,
    ) -> Result<(X509, PKey<Private>), ControlledCaptureError> {
        let key = PKey::from_rsa(
            Rsa::generate(2048).map_err(|error| ControlledCaptureError::Tls(error.to_string()))?,
        )
        .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        let mut name =
            X509Name::builder().map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        name.append_entry_by_nid(Nid::COMMONNAME, authority)
            .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        let name = name.build();
        let mut certificate =
            X509::builder().map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        certificate
            .set_version(2)
            .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        certificate
            .set_subject_name(&name)
            .and_then(|()| certificate.set_issuer_name(&name))
            .and_then(|()| certificate.set_pubkey(&key))
            .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        let not_before = Asn1Time::days_from_now(0)
            .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        let not_after = Asn1Time::days_from_now(1)
            .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        certificate
            .set_not_before(&not_before)
            .and_then(|()| certificate.set_not_after(&not_after))
            .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        let mut serial =
            BigNum::new().map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        serial
            .rand(128, MsbOption::MAYBE_ZERO, false)
            .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        let serial = serial
            .to_asn1_integer()
            .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        certificate
            .set_serial_number(&serial)
            .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        let mut subject_alt_name = SubjectAlternativeName::new();
        if authority.parse::<IpAddr>().is_ok() {
            subject_alt_name.ip(authority);
        } else {
            subject_alt_name.dns(authority);
        }
        for extension in [
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?,
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .key_cert_sign()
                .build()
                .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?,
            ExtendedKeyUsage::new()
                .server_auth()
                .build()
                .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?,
            subject_alt_name
                .build(&certificate.x509v3_context(None, None))
                .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?,
        ] {
            certificate
                .append_extension(&extension)
                .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        }
        certificate
            .sign(&key, MessageDigest::sha256())
            .map_err(|error| ControlledCaptureError::Tls(error.to_string()))?;
        Ok((certificate.build(), key))
    }

    #[derive(Debug)]
    struct RecordingIo<S> {
        inner: S,
        captured: Arc<Mutex<Vec<u8>>>,
        max_capture_bytes: usize,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for RecordingIo<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buffer.filled().len();
            let result = Pin::new(&mut self.inner).poll_read(context, buffer);
            if let Poll::Ready(Ok(())) = &result {
                let new_bytes = &buffer.filled()[before..];
                let Ok(mut captured) = self.captured.lock() else {
                    return Poll::Ready(Err(io::Error::other("capture mutex poisoned")));
                };
                if captured.len().saturating_add(new_bytes.len()) > self.max_capture_bytes {
                    return Poll::Ready(Err(io::Error::other("capture byte limit exceeded")));
                }
                captured.extend_from_slice(new_bytes);
            }
            result
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for RecordingIo<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }
}

#[cfg(feature = "boring-backend")]
pub use server::{
    ClaudeRequestSummary, ControlledCancellationObservation, ControlledH2Result,
    ControlledH2Server, ControlledResponseMode, Http1RequestObservation,
};

#[derive(Debug, Error)]
pub enum ControlledCaptureError {
    #[error("controlled capture configuration is invalid")]
    InvalidConfig,
    #[error("controlled capture timed out")]
    Timeout,
    #[error("HTTP/2 client preface is invalid")]
    InvalidPreface,
    #[error("controlled H2 capture is truncated at {0}")]
    Truncated(&'static str),
    #[error("controlled H2 capture is malformed: {0}")]
    Malformed(&'static str),
    #[error("controlled H2 TLS failed: {0}")]
    Tls(String),
    #[error("controlled H2 protocol failed: {0}")]
    H2(String),
    #[error("controlled HTTP/1.1 protocol failed: {0}")]
    Http1(String),
    #[error("controlled endpoint did not observe /v1/messages within its request limit")]
    MessagesRequestNotObserved,
    #[error("controlled capture mutex is poisoned")]
    CapturePoisoned,
    #[error("controlled request body exceeds the configured limit")]
    RequestBodyTooLarge,
    #[error("controlled endpoint did not observe the expected client cancellation")]
    CancellationNotObserved,
    #[error("controlled JSON processing failed: {0}")]
    Json(String),
    #[error("controlled I/O failed: {0}")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_settings_order_and_window_update() {
        let mut bytes = H2_CLIENT_PREFACE.to_vec();
        bytes.extend([0, 0, 12, 4, 0, 0, 0, 0, 0]);
        bytes.extend([0, 1, 0, 0, 16, 0, 0, 4, 0, 1, 0, 0]);
        bytes.extend([0, 0, 4, 8, 0, 0, 0, 0, 0]);
        bytes.extend([0, 1, 0, 0]);
        let frames = parse_client_frames(&bytes).expect("parse frames");
        assert_eq!(frames.len(), 2);
        assert!(matches!(
            &frames[0].detail,
            Http2FrameDetail::Settings { entries }
                if entries.iter().map(|entry| entry.id).collect::<Vec<_>>() == vec![1, 4]
        ));
        assert!(matches!(
            frames[1].detail,
            Http2FrameDetail::WindowUpdate { increment: 65_536 }
        ));
    }

    #[test]
    fn rejects_settings_ack_payload() {
        let mut bytes = H2_CLIENT_PREFACE.to_vec();
        bytes.extend([0, 0, 6, 4, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1]);
        assert!(matches!(
            parse_client_frames(&bytes),
            Err(ControlledCaptureError::Malformed(_))
        ));
    }

    #[cfg(feature = "boring-backend")]
    #[test]
    fn accepts_terminal_tls_close_after_complete_exchange() {
        for kind in [
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::NotConnected,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            assert!(server::is_terminal_tls_close(&std::io::Error::from(kind)));
        }
        assert!(!server::is_terminal_tls_close(&std::io::Error::from(
            std::io::ErrorKind::InvalidData,
        )));
    }
}
