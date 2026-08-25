//! Synthetic raw HTTP upstream used by contract and relay tests.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderName, HeaderValue, Response, StatusCode},
    routing::post,
};
use bytes::Bytes;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

/// Raw response programmed by a test.
#[derive(Clone, Debug)]
pub struct SyntheticResponse {
    /// HTTP status.
    pub status: StatusCode,
    /// Ordered logical response headers.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// Body bytes, including caller-authored SSE framing when desired.
    pub body: Bytes,
}

impl SyntheticResponse {
    /// Build a JSON response.
    #[must_use]
    pub fn json(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: vec![(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/json"),
            )],
            body: body.into(),
        }
    }

    /// Build an SSE response from exact wire-visible body bytes.
    #[must_use]
    pub fn sse(body: impl Into<Bytes>) -> Self {
        Self {
            status: StatusCode::OK,
            headers: vec![(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("text/event-stream"),
            )],
            body: body.into(),
        }
    }
}

/// Running synthetic Anthropic endpoint.
pub struct SyntheticAnthropic {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<std::io::Result<()>>,
}

impl SyntheticAnthropic {
    /// Start a loopback endpoint serving the programmed response for `/v1/messages`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the loopback listener cannot bind or report
    /// its assigned address.
    pub async fn start(response: SyntheticResponse) -> std::io::Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let app = Router::new()
            .route("/v1/messages", post(messages))
            .with_state(Arc::new(response));
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _result = receiver.await;
                })
                .await
        });
        Ok(Self {
            address,
            shutdown: Some(shutdown),
            task,
        })
    }

    /// Socket address of the loopback server.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stop the server and wait for its task.
    ///
    /// # Errors
    ///
    /// Returns an error when the server task failed or terminated with an I/O
    /// error.
    pub async fn shutdown(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(shutdown) = self.shutdown.take() {
            let _result = shutdown.send(());
        }
        self.task.await??;
        Ok(())
    }
}

async fn messages(State(response): State<Arc<SyntheticResponse>>) -> Response<Body> {
    let mut outgoing = Response::new(Body::from(response.body.clone()));
    *outgoing.status_mut() = response.status;
    for (name, value) in &response.headers {
        outgoing.headers_mut().append(name, value.clone());
    }
    outgoing
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::{SyntheticAnthropic, SyntheticResponse};

    #[tokio::test]
    async fn synthetic_endpoint_starts_and_stops() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let server =
            SyntheticAnthropic::start(SyntheticResponse::json(StatusCode::OK, r#"{"type":"message"}"#)).await?;
        assert_ne!(server.address().port(), 0);
        server.shutdown().await
    }
}
