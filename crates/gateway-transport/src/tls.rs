//! Certificate-validating `BoringSSL` connector for verified Bundle controls.

use std::time::{Duration, Instant};

use boring::{
    hash::MessageDigest,
    ssl::{SslConnector, SslMethod, SslVerifyMode},
};
use tokio_boring::SslStream;
use tokio_util::sync::CancellationToken;

use crate::{
    AttributionDomain, BoxedIo, ConnectionDisposition, FailureScope, HealthEffect, RetrySafety, TlsProfile,
    TransportError, TransportErrorCode, TransportPhase,
};

/// Non-secret negotiated TLS facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsObservation {
    /// Negotiated ALPN, or `none`.
    pub negotiated_alpn: Box<str>,
    /// Negotiated TLS version.
    pub tls_version: Box<str>,
    /// Negotiated cipher.
    pub cipher: Box<str>,
    /// Session reuse stays false while Bundle resumption is disabled.
    pub session_reused: bool,
    /// Peer leaf certificate SHA-256.
    pub certificate_sha256: Box<str>,
    /// Handshake duration.
    pub handshake_micros: u64,
}

/// Established `BoringSSL` stream and redacted observation.
pub struct TlsConnection {
    /// Certificate-validated stream.
    pub stream: SslStream<BoxedIo>,
    /// Negotiated non-secret properties.
    pub observation: TlsObservation,
}

impl std::fmt::Debug for TlsConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsConnection")
            .field("observation", &self.observation)
            .finish_non_exhaustive()
    }
}

/// Stateless `BoringSSL` compiler/connector.
#[derive(Clone, Copy, Debug, Default)]
pub struct BoringTlsConnector;

impl BoringTlsConnector {
    /// Apply verified Bundle controls and perform certificate/SNI/ALPN validation.
    ///
    /// # Errors
    ///
    /// Rejects unrepresentable wire controls, timeout, cancellation, certificate failures and ALPN drift.
    pub async fn connect(
        &self,
        io: BoxedIo,
        authority: &str,
        profile: &TlsProfile,
        timeout: Duration,
        cancellation: &CancellationToken,
        proxied: bool,
    ) -> Result<TlsConnection, TransportError> {
        if authority != "api.anthropic.com" || timeout.is_zero() || profile.session_resumption {
            return Err(tls_error(
                TransportErrorCode::InternalInvariant,
                "tls_configuration",
                proxied,
                HealthEffect::QuarantineBundle,
            ));
        }
        let connector = build_connector(profile, proxied)?;
        let configuration = connector.configure().map_err(|_| {
            tls_error(
                TransportErrorCode::TlsHandshake,
                "tls_configuration",
                proxied,
                HealthEffect::QuarantineBundle,
            )
        })?;
        let started = Instant::now();
        let stream = tokio::select! {
            () = cancellation.cancelled() => return Err(cancelled()),
            result = tokio::time::timeout(timeout, tokio_boring::connect(configuration, authority, io)) => {
                match result {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(_)) => return Err(tls_error(TransportErrorCode::TlsHandshake, if proxied { "unhealthy_tls_passthrough" } else { "tls_handshake" }, proxied, if proxied { HealthEffect::QuarantineEgress } else { HealthEffect::TransientFailure })),
                    Err(_) => return Err(tls_error(TransportErrorCode::Timeout, "tls_handshake_timeout", proxied, HealthEffect::TransientFailure)),
                }
            }
        };
        let ssl = stream.ssl();
        if ssl.verify_result().is_err() || ssl.peer_certificate().is_none() {
            return Err(tls_error(
                TransportErrorCode::TlsCertificate,
                if proxied {
                    "unhealthy_tls_passthrough"
                } else {
                    "tls_certificate"
                },
                proxied,
                if proxied {
                    HealthEffect::QuarantineEgress
                } else {
                    HealthEffect::TransientFailure
                },
            ));
        }
        let expected_alpn = profile.alpn.first().map(AsRef::as_ref);
        let selected_alpn = ssl.selected_alpn_protocol();
        if expected_alpn.map(str::as_bytes) != selected_alpn {
            return Err(tls_error(
                TransportErrorCode::AlpnMismatch,
                "alpn_mismatch",
                proxied,
                if proxied {
                    HealthEffect::QuarantineEgress
                } else {
                    HealthEffect::QuarantineBundle
                },
            ));
        }
        let certificate = ssl.peer_certificate().ok_or_else(|| {
            tls_error(
                TransportErrorCode::TlsCertificate,
                "tls_peer_certificate_missing",
                proxied,
                HealthEffect::TransientFailure,
            )
        })?;
        let certificate_digest = certificate.digest(MessageDigest::sha256()).map_err(|_| {
            tls_error(
                TransportErrorCode::TlsCertificate,
                "tls_certificate_digest",
                proxied,
                HealthEffect::None,
            )
        })?;
        let cipher = ssl
            .current_cipher()
            .ok_or_else(|| {
                tls_error(
                    TransportErrorCode::TlsHandshake,
                    "tls_cipher_missing",
                    proxied,
                    HealthEffect::TransientFailure,
                )
            })?
            .name();
        let observation = TlsObservation {
            negotiated_alpn: selected_alpn.map_or_else(
                || "none".into(),
                |value| String::from_utf8_lossy(value).into_owned().into_boxed_str(),
            ),
            tls_version: ssl.version_str().into(),
            cipher: cipher.into(),
            session_reused: ssl.session_reused(),
            certificate_sha256: hex_bytes(&certificate_digest).into_boxed_str(),
            handshake_micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        };
        Ok(TlsConnection { stream, observation })
    }

    /// Establish a certificate-validating HTTP/1.1 TLS stream for a versioned provider endpoint.
    ///
    /// This path intentionally does not apply a Messages transport Bundle. Provider endpoints are
    /// evidence-gated separately and are used only for Credential maintenance.
    ///
    /// # Errors
    ///
    /// Rejects invalid authorities, cancellation, timeout, certificate failures and ALPN drift.
    pub async fn connect_provider(
        &self,
        io: BoxedIo,
        authority: &str,
        timeout: Duration,
        cancellation: &CancellationToken,
        proxied: bool,
    ) -> Result<SslStream<BoxedIo>, TransportError> {
        if authority.is_empty()
            || authority.len() > 255
            || authority
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, '/' | '\\' | '@' | '[' | ']'))
            || timeout.is_zero()
        {
            return Err(tls_error(
                TransportErrorCode::InternalInvariant,
                "provider_tls_configuration",
                proxied,
                HealthEffect::None,
            ));
        }
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| {
            tls_error(
                TransportErrorCode::TlsHandshake,
                "provider_tls_connector",
                proxied,
                HealthEffect::TransientFailure,
            )
        })?;
        builder.set_verify(SslVerifyMode::PEER);
        builder.set_default_verify_paths().map_err(|_| {
            tls_error(
                TransportErrorCode::TlsCertificate,
                "provider_tls_trust_store",
                proxied,
                HealthEffect::TransientFailure,
            )
        })?;
        builder.set_alpn_protos(b"\x08http/1.1").map_err(|_| {
            tls_error(
                TransportErrorCode::TlsHandshake,
                "provider_tls_alpn",
                proxied,
                HealthEffect::None,
            )
        })?;
        let configuration = builder.build().configure().map_err(|_| {
            tls_error(
                TransportErrorCode::TlsHandshake,
                "provider_tls_configuration",
                proxied,
                HealthEffect::TransientFailure,
            )
        })?;
        let stream = tokio::select! {
            () = cancellation.cancelled() => return Err(cancelled()),
            result = tokio::time::timeout(timeout, tokio_boring::connect(configuration, authority, io)) => {
                match result {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(_)) => return Err(tls_error(TransportErrorCode::TlsHandshake, "provider_tls_handshake", proxied, HealthEffect::TransientFailure)),
                    Err(_) => return Err(tls_error(TransportErrorCode::Timeout, "provider_tls_handshake_timeout", proxied, HealthEffect::TransientFailure)),
                }
            }
        };
        let ssl = stream.ssl();
        if ssl.verify_result().is_err() || ssl.peer_certificate().is_none() {
            return Err(tls_error(
                TransportErrorCode::TlsCertificate,
                "provider_tls_certificate",
                proxied,
                HealthEffect::TransientFailure,
            ));
        }
        if ssl.selected_alpn_protocol() != Some(b"http/1.1".as_slice()) {
            return Err(tls_error(
                TransportErrorCode::AlpnMismatch,
                "provider_tls_alpn_mismatch",
                proxied,
                HealthEffect::TransientFailure,
            ));
        }
        Ok(stream)
    }
}

fn build_connector(profile: &TlsProfile, proxied: bool) -> Result<SslConnector, TransportError> {
    if profile.alpn.len() != 1
        || profile.supported_group_ids.is_empty()
        || profile.key_share_group_ids.len() > 1
        || profile.key_share_group_ids.first() != profile.supported_group_ids.first()
    {
        return Err(tls_error(
            TransportErrorCode::BundleRejected,
            "tls_profile_unrepresentable",
            proxied,
            HealthEffect::QuarantineBundle,
        ));
    }
    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| {
        tls_error(
            TransportErrorCode::TlsHandshake,
            "boringssl_connector",
            proxied,
            HealthEffect::QuarantineBundle,
        )
    })?;
    let alpn_wire = alpn_wire(&profile.alpn)?;
    builder.set_alpn_protos(&alpn_wire).map_err(|_| {
        tls_error(
            TransportErrorCode::BundleRejected,
            "tls_alpn_profile",
            proxied,
            HealthEffect::QuarantineBundle,
        )
    })?;
    let cipher_names = profile
        .cipher_suite_ids
        .iter()
        .filter(|&&id| !(0x1301..=0x1303).contains(&id))
        .map(|&id| pre_tls13_cipher_name(id).ok_or(()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|()| {
            tls_error(
                TransportErrorCode::BundleRejected,
                "tls_cipher_profile",
                proxied,
                HealthEffect::QuarantineBundle,
            )
        })?;
    if !cipher_names.is_empty() {
        builder.set_strict_cipher_list(&cipher_names.join(":")).map_err(|_| {
            tls_error(
                TransportErrorCode::BundleRejected,
                "tls_cipher_profile",
                proxied,
                HealthEffect::QuarantineBundle,
            )
        })?;
    }
    let group_names = profile
        .supported_group_ids
        .iter()
        .map(|id| tls_group_name(*id).ok_or(()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|()| {
            tls_error(
                TransportErrorCode::BundleRejected,
                "tls_group_profile",
                proxied,
                HealthEffect::QuarantineBundle,
            )
        })?;
    builder.set_curves_list(&group_names.join(":")).map_err(|_| {
        tls_error(
            TransportErrorCode::BundleRejected,
            "tls_group_profile",
            proxied,
            HealthEffect::QuarantineBundle,
        )
    })?;
    if profile.extension_order.contains(&5) {
        builder.enable_ocsp_stapling();
    }
    if profile.extension_order.contains(&18) {
        builder.enable_signed_cert_timestamps();
    }
    builder.set_grease_enabled(profile.grease_enabled);
    builder.set_permute_extensions(profile.permute_extensions);
    Ok(builder.build())
}

fn alpn_wire(protocols: &[Box<str>]) -> Result<Vec<u8>, TransportError> {
    let mut wire = Vec::new();
    for protocol in protocols {
        let length = u8::try_from(protocol.len()).map_err(|_| {
            tls_error(
                TransportErrorCode::BundleRejected,
                "tls_alpn_profile",
                false,
                HealthEffect::QuarantineBundle,
            )
        })?;
        if length == 0 {
            return Err(tls_error(
                TransportErrorCode::BundleRejected,
                "tls_alpn_profile",
                false,
                HealthEffect::QuarantineBundle,
            ));
        }
        wire.push(length);
        wire.extend_from_slice(protocol.as_bytes());
    }
    Ok(wire)
}

fn pre_tls13_cipher_name(id: u16) -> Option<&'static str> {
    match id {
        0xc02f => Some("ECDHE-RSA-AES128-GCM-SHA256"),
        0xc02b => Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
        0xc030 => Some("ECDHE-RSA-AES256-GCM-SHA384"),
        0xc02c => Some("ECDHE-ECDSA-AES256-GCM-SHA384"),
        0xcca9 => Some("ECDHE-ECDSA-CHACHA20-POLY1305"),
        0xcca8 => Some("ECDHE-RSA-CHACHA20-POLY1305"),
        0x009c => Some("AES128-GCM-SHA256"),
        0x009d => Some("AES256-GCM-SHA384"),
        _ => None,
    }
}

fn tls_group_name(id: u16) -> Option<&'static str> {
    match id {
        0x001d => Some("X25519"),
        0x0017 => Some("P-256"),
        0x0018 => Some("P-384"),
        0x0019 => Some("P-521"),
        _ => None,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn tls_error(
    code: TransportErrorCode,
    diagnostic: &'static str,
    proxied: bool,
    health: HealthEffect,
) -> TransportError {
    TransportError {
        code,
        phase: TransportPhase::TlsHandshake,
        attribution_domain: if proxied {
            AttributionDomain::Proxy
        } else {
            AttributionDomain::BundleRuntime
        },
        failure_scope: if proxied {
            FailureScope::Egress
        } else {
            FailureScope::Connection
        },
        retry_safety: RetrySafety::SafeBeforeSubmission,
        upstream_request_bytes_written: 0,
        upstream_submission_complete: false,
        connection_disposition: ConnectionDisposition::CloseConnection,
        health_effect: health,
        diagnostic: diagnostic.into(),
    }
}

fn cancelled() -> TransportError {
    TransportError {
        code: TransportErrorCode::Cancelled,
        phase: TransportPhase::TlsHandshake,
        attribution_domain: AttributionDomain::Cancellation,
        failure_scope: FailureScope::Attempt,
        retry_safety: RetrySafety::SafeBeforeSubmission,
        upstream_request_bytes_written: 0,
        upstream_submission_complete: false,
        connection_disposition: ConnectionDisposition::CloseConnection,
        health_effect: HealthEffect::None,
        diagnostic: "cancelled_tls_handshake".into(),
    }
}
