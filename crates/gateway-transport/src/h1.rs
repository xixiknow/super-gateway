//! Low-level ordered HTTP/1.1 request writer and strict response-head framing parser.

use bytes::Bytes;
use gateway_domain::FinalUpstreamRequest;

use crate::{
    AttributionDomain, ConnectionDisposition, FailureScope, HealthEffect, RetrySafety, TransportError,
    TransportErrorCode, TransportPhase,
};

/// Response body framing selected after strict Header validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H1Framing {
    /// HEAD, 1xx, 204 or 304 response.
    NoBody,
    /// Exact Content-Length bytes.
    ContentLength(u64),
    /// RFC chunked transfer encoding.
    Chunked,
    /// Body ends only when the peer closes; connection is never reusable.
    CloseDelimited,
}

/// Parsed response head while preserving ordered raw header values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedResponseHead {
    /// Numeric HTTP status.
    pub status: u16,
    /// Ordered headers as received; values are not decoded or normalized.
    pub headers: Vec<(Box<str>, Bytes)>,
    /// Number of response-head bytes consumed.
    pub consumed: usize,
    /// Strictly selected body framing.
    pub framing: H1Framing,
}

/// Encode the final request with exact header order/casing and Content-Length framing.
///
/// # Errors
///
/// Rejects invalid origin-form paths, header injection, unsupported methods or conflicting framing.
pub fn encode_request(request: &FinalUpstreamRequest) -> Result<Vec<u8>, TransportError> {
    if request.method.is_empty()
        || !request.method.as_bytes().iter().all(u8::is_ascii_uppercase)
        || !request.path_and_query.starts_with('/')
        || request.path_and_query.contains(['\r', '\n', ' '])
    {
        return Err(h1_error("h1_invalid_request_line"));
    }
    let body_length = request.body.len();
    let mut has_content_length = false;
    let mut rendered = Vec::with_capacity(
        request.method.len()
            + request.path_and_query.len()
            + request
                .headers
                .iter()
                .map(|header| header.name.len() + header.value.len() + 4)
                .sum::<usize>()
            + body_length
            + 64,
    );
    rendered.extend_from_slice(request.method.as_bytes());
    rendered.push(b' ');
    rendered.extend_from_slice(request.path_and_query.as_bytes());
    rendered.extend_from_slice(b" HTTP/1.1\r\n");
    for header in request.headers.iter() {
        if header.name.is_empty()
            || header.name.as_bytes().iter().any(|byte| !is_header_name_byte(*byte))
            || header.value.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
        {
            return Err(h1_error("h1_invalid_header"));
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(h1_error("h1_request_transfer_encoding_forbidden"));
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if has_content_length || header.value.as_ref() != body_length.to_string().as_bytes() {
                return Err(h1_error("h1_content_length_conflict"));
            }
            has_content_length = true;
        }
        rendered.extend_from_slice(header.name.as_bytes());
        rendered.extend_from_slice(b": ");
        rendered.extend_from_slice(&header.value);
        rendered.extend_from_slice(b"\r\n");
    }
    if !has_content_length {
        rendered.extend_from_slice(format!("Content-Length: {body_length}\r\n").as_bytes());
    }
    rendered.extend_from_slice(b"\r\n");
    rendered.extend_from_slice(&request.body);
    Ok(rendered)
}

/// Parse one complete response head and determine a non-ambiguous body boundary.
///
/// # Errors
///
/// Returns `h1_framing` for incomplete, oversized, conflicting or malformed response headers.
pub fn parse_response_head(buffer: &[u8], request_method: &str) -> Result<ParsedResponseHead, TransportError> {
    let mut raw_headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut raw_headers);
    let consumed = match response
        .parse(buffer)
        .map_err(|_| h1_error("h1_response_head_malformed"))?
    {
        httparse::Status::Complete(consumed) => consumed,
        httparse::Status::Partial => return Err(h1_error("h1_response_head_incomplete")),
    };
    let status = response.code.ok_or_else(|| h1_error("h1_status_missing"))?;
    let mut headers = Vec::with_capacity(response.headers.len());
    let mut content_length = None;
    let mut transfer_encoding = None;
    for header in response.headers.iter() {
        if header.name.eq_ignore_ascii_case("content-length") {
            let text = std::str::from_utf8(header.value).map_err(|_| h1_error("h1_content_length_invalid"))?;
            let value = text
                .trim()
                .parse::<u64>()
                .map_err(|_| h1_error("h1_content_length_invalid"))?;
            if content_length.is_some_and(|existing| existing != value) {
                return Err(h1_error("h1_content_length_ambiguous"));
            }
            content_length = Some(value);
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(h1_error("h1_transfer_encoding_ambiguous"));
            }
            transfer_encoding = Some(
                std::str::from_utf8(header.value)
                    .map_err(|_| h1_error("h1_transfer_encoding_invalid"))?
                    .trim()
                    .to_ascii_lowercase(),
            );
        }
        headers.push((header.name.into(), Bytes::copy_from_slice(header.value)));
    }
    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(h1_error("h1_framing_conflict"));
    }
    let framing =
        if request_method.eq_ignore_ascii_case("HEAD") || (100..200).contains(&status) || matches!(status, 204 | 304) {
            H1Framing::NoBody
        } else if let Some(encoding) = transfer_encoding {
            if encoding == "chunked" {
                H1Framing::Chunked
            } else {
                return Err(h1_error("h1_transfer_encoding_unsupported"));
            }
        } else if let Some(length) = content_length {
            H1Framing::ContentLength(length)
        } else {
            H1Framing::CloseDelimited
        };
    Ok(ParsedResponseHead {
        status,
        headers,
        consumed,
        framing,
    })
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn h1_error(diagnostic: &'static str) -> TransportError {
    TransportError {
        code: TransportErrorCode::H1Framing,
        phase: TransportPhase::ResponseHeaders,
        attribution_domain: AttributionDomain::BundleRuntime,
        failure_scope: FailureScope::Connection,
        retry_safety: RetrySafety::CommitUnknown,
        upstream_request_bytes_written: 0,
        upstream_submission_complete: false,
        connection_disposition: ConnectionDisposition::Evict,
        health_effect: HealthEffect::QuarantineBundle,
        diagnostic: diagnostic.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gateway_domain::{FinalUpstreamRequest, UpstreamHeader};

    use super::{H1Framing, encode_request, parse_response_head};

    #[test]
    fn writer_preserves_order_and_exact_body() {
        let request = FinalUpstreamRequest {
            method: "POST".into(),
            scheme: "https".into(),
            authority: "api.anthropic.com".into(),
            path_and_query: "/v1/messages".into(),
            headers: Arc::from([
                UpstreamHeader {
                    name: "Host".into(),
                    value: Arc::from(b"api.anthropic.com".as_slice()),
                },
                UpstreamHeader {
                    name: "X-Test".into(),
                    value: Arc::from(b"one".as_slice()),
                },
            ]),
            body: Arc::from(b"{}".as_slice()),
            stream: false,
        };
        let bytes = encode_request(&request).unwrap_or_default();
        assert_eq!(
            bytes,
            b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nX-Test: one\r\nContent-Length: 2\r\n\r\n{}"
        );
    }

    #[test]
    fn response_parser_rejects_smuggling_ambiguity() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(parse_response_head(response, "POST").is_err());
    }

    #[test]
    fn response_parser_preserves_chunked_boundary() {
        let response = b"HTTP/1.1 200 OK\r\nX-CaSe: value\r\nTransfer-Encoding: chunked\r\n\r\n";
        let parsed = parse_response_head(response, "POST");
        assert!(matches!(parsed.map(|head| head.framing), Ok(H1Framing::Chunked)));
    }
}
