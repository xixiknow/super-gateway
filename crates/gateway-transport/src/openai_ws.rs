//! One upstream WebSocket bound to one downstream connection and account.
use crate::BoxedIo;
/// Mutable connection state is serialized by the caller for the full response turn.
#[derive(Default)]
pub struct OpenAiConnection {
    /// Redacted handshake diagnostics, retained for subsequent turns.
    pub request_headers: Option<gateway_domain::HeaderSnapshot>,
    /// Actual upgrade response, not synthetic SSE adapter headers.
    pub response_headers: Option<gateway_domain::HeaderSnapshot>,
    /// Wire-byte counter retained with the socket and reset before each serial turn.
    pub written: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Fixed account chosen by the first admitted turn.
    pub account: Option<String>,
    /// Fingerprint of token generation, fixed egress and transport settings.
    pub token_version: Option<u64>,
    /// Upstream connection retained while idle without retaining execution leases.
    pub socket: Option<tokio_tungstenite::WebSocketStream<BoxedIo>>,
}
impl std::fmt::Debug for OpenAiConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiConnection")
            .field("connected", &self.socket.is_some())
            .finish_non_exhaustive()
    }
}
