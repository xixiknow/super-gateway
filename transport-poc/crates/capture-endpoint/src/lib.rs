#![forbid(unsafe_code)]

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use capture_schema::CaptureBatch;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{io::ErrorKind, path::PathBuf, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::{fs, io::AsyncWriteExt};
use tracing::error;
use uuid::Uuid;
use wire_normalizer::{NormalizedCapture, normalize_capture, verify_normalized_capture};

pub const MAX_CAPTURE_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub enum CaptureAuth {
    Required([u8; 32]),
    DisabledLoopback,
}

impl CaptureAuth {
    pub fn required(token: &str) -> Self {
        Self::Required(token_digest(token))
    }

    fn authorize(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let Self::Required(expected) = self else {
            return Ok(());
        };
        let Some(value) = headers.get(AUTHORIZATION) else {
            return Err(ApiError::Unauthorized);
        };
        let Ok(value) = value.to_str() else {
            return Err(ApiError::Unauthorized);
        };
        let Some(token) = value.strip_prefix("Bearer ") else {
            return Err(ApiError::Unauthorized);
        };
        let supplied = token_digest(token);
        if bool::from(expected.ct_eq(&supplied)) {
            Ok(())
        } else {
            Err(ApiError::Unauthorized)
        }
    }
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[derive(Clone, Debug)]
pub struct CaptureStore {
    root: Arc<PathBuf>,
}

impl CaptureStore {
    /// Creates the normalized-evidence directory and opens the store.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the storage directory cannot be created.
    pub async fn open(root: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(&root).await?;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    async fn put(&self, capture: &NormalizedCapture) -> Result<PutOutcome, StoreError> {
        let path = self.capture_path(capture.capture_artifact_id);
        let payload = serde_json::to_vec_pretty(capture)?;
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
        {
            Ok(file) => file,
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {
                let existing = self.get(capture.capture_artifact_id).await?;
                return if existing.normalized_sha256 == capture.normalized_sha256 {
                    Ok(PutOutcome::Existing)
                } else {
                    Err(StoreError::Conflict)
                };
            }
            Err(source) => return Err(StoreError::Io(source)),
        };
        if let Err(source) = file.write_all(&payload).await {
            drop(file);
            let _ = fs::remove_file(&path).await;
            return Err(StoreError::Io(source));
        }
        file.sync_data().await?;
        Ok(PutOutcome::Stored)
    }

    async fn get(&self, capture_artifact_id: Uuid) -> Result<NormalizedCapture, StoreError> {
        let bytes = match fs::read(self.capture_path(capture_artifact_id)).await {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == ErrorKind::NotFound => {
                return Err(StoreError::NotFound);
            }
            Err(source) => return Err(StoreError::Io(source)),
        };
        let capture: NormalizedCapture = serde_json::from_slice(&bytes)?;
        verify_normalized_capture(&capture).map_err(StoreError::Integrity)?;
        Ok(capture)
    }

    fn capture_path(&self, capture_artifact_id: Uuid) -> PathBuf {
        self.root.join(format!("{capture_artifact_id}.json"))
    }
}

#[derive(Clone, Debug)]
pub struct AppState {
    auth: CaptureAuth,
    store: CaptureStore,
}

impl AppState {
    pub fn new(auth: CaptureAuth, store: CaptureStore) -> Self {
        Self { auth, store }
    }
}

pub fn app(state: AppState) -> Router {
    let protected = Router::new()
        .route("/v1/captures", post(ingest_capture))
        .route("/v1/captures/{capture_artifact_id}", get(get_capture))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));
    Router::new()
        .route("/healthz", get(health))
        .merge(protected)
        .layer(DefaultBodyLimit::max(MAX_CAPTURE_BODY_BYTES))
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn require_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    state.auth.authorize(request.headers())?;
    Ok(next.run(request).await)
}

async fn ingest_capture(
    State(state): State<AppState>,
    Json(batch): Json<CaptureBatch>,
) -> Result<(StatusCode, Json<IngestResponse>), ApiError> {
    batch.validate().map_err(|_| ApiError::InvalidCapture)?;
    let normalized = normalize_capture(&batch).map_err(|_| ApiError::InvalidCapture)?;
    let outcome = state
        .store
        .put(&normalized)
        .await
        .map_err(ApiError::store)?;
    let status = match outcome {
        PutOutcome::Stored => StatusCode::CREATED,
        PutOutcome::Existing => StatusCode::OK,
    };
    let event_count = normalized.event_count();
    Ok((
        status,
        Json(IngestResponse {
            capture_artifact_id: normalized.capture_artifact_id,
            capture_run_id: normalized.capture_run_id,
            normalized_sha256: normalized.normalized_sha256,
            event_count,
            outcome,
        }),
    ))
}

async fn get_capture(
    State(state): State<AppState>,
    Path(capture_artifact_id): Path<Uuid>,
) -> Result<Json<NormalizedCapture>, ApiError> {
    state
        .store
        .get(capture_artifact_id)
        .await
        .map(Json)
        .map_err(ApiError::store)
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum PutOutcome {
    Stored,
    Existing,
}

#[derive(Debug, Serialize)]
struct IngestResponse {
    capture_artifact_id: Uuid,
    capture_run_id: Uuid,
    normalized_sha256: String,
    event_count: usize,
    outcome: PutOutcome,
}

#[derive(Debug)]
enum StoreError {
    NotFound,
    Conflict,
    Io(std::io::Error),
    Json(serde_json::Error),
    Integrity(wire_normalizer::NormalizationError),
}

impl From<std::io::Error> for StoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    InvalidCapture,
    NotFound,
    Conflict,
    Internal,
}

impl ApiError {
    fn store(error_value: StoreError) -> Self {
        match error_value {
            StoreError::NotFound => Self::NotFound,
            StoreError::Conflict => Self::Conflict,
            StoreError::Io(source) => {
                error!(error = %source, "normalized capture store I/O failure");
                Self::Internal
            }
            StoreError::Json(source) => {
                error!(error = %source, "normalized capture store JSON failure");
                Self::Internal
            }
            StoreError::Integrity(source) => {
                error!(error = %source, "normalized capture store integrity failure");
                Self::Internal
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::InvalidCapture => (StatusCode::BAD_REQUEST, "invalid_capture"),
            Self::NotFound => (StatusCode::NOT_FOUND, "capture_not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "capture_id_conflict"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (status, Json(ErrorResponse { code })).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, header::CONTENT_TYPE},
    };
    use capture_schema::{
        CAPTURE_SCHEMA_VERSION, CaptureEvent, CaptureLane, Direction, DnsMode,
        EnvironmentDescriptor, HeaderObservation, Http2FrameDetail, Http2FrameType,
        NetworkDescriptor, NetworkPath, ScenarioDescriptor, TargetDescriptor,
    };
    use std::collections::BTreeMap;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn sample_batch() -> CaptureBatch {
        CaptureBatch {
            schema_version: CAPTURE_SCHEMA_VERSION,
            capture_artifact_id: Uuid::new_v4(),
            capture_run_id: Uuid::new_v4(),
            lane: CaptureLane::ReferenceControlledEndpoint,
            observed_at: "2026-08-22T00:00:00Z".to_owned(),
            environment: EnvironmentDescriptor {
                os_name: "linux".to_owned(),
                os_version: "fixture".to_owned(),
                os_build: None,
                arch: "x86_64".to_owned(),
                kernel: None,
                claude_code_version: "fixture".to_owned(),
                runtime_name: "bun".to_owned(),
                runtime_version: "fixture".to_owned(),
                binary_sha256: None,
                labels: BTreeMap::new(),
            },
            target: TargetDescriptor {
                authority: "capture.internal:443".to_owned(),
                official_anthropic: false,
            },
            network: NetworkDescriptor {
                path: NetworkPath::Direct,
                dns_mode: DnsMode::Local,
                proxy_software: None,
                proxy_version: None,
            },
            scenario: ScenarioDescriptor {
                id: "T01".to_owned(),
                fresh_connection: true,
                expected_protocol: "h2".to_owned(),
                concurrent_streams: 1,
                request_shape: "fixture".to_owned(),
            },
            events: vec![CaptureEvent::Http2Frame {
                connection_id: "raw-connection-id".to_owned(),
                direction: Direction::ClientToServer,
                sequence: 1,
                stream_id: 1,
                frame_type: Http2FrameType::Headers,
                flags: vec!["end_headers".to_owned()],
                length: 100,
                detail: Http2FrameDetail::Headers {
                    headers: vec![HeaderObservation {
                        name: "authorization".to_owned(),
                        value: "Bearer TOP_SECRET".to_owned(),
                    }],
                },
            }],
        }
    }

    async fn test_app(temp: &TempDir) -> Router {
        let store = CaptureStore::open(temp.path().to_path_buf())
            .await
            .expect("open store");
        app(AppState::new(CaptureAuth::required("test-token"), store))
    }

    fn post_request(batch: &CaptureBatch, token: Option<&str>) -> Request<Body> {
        let mut builder = Request::post("/v1/captures").header(CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        builder
            .body(Body::from(serde_json::to_vec(batch).expect("serialize")))
            .expect("request")
    }

    #[tokio::test]
    async fn rejects_missing_token() {
        let temp = TempDir::new().expect("temp dir");
        let response = test_app(&temp)
            .await
            .oneshot(post_request(&sample_batch(), None))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_unauthenticated_request_before_json_parsing() {
        let temp = TempDir::new().expect("temp dir");
        let request = Request::post("/v1/captures")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{not-json"))
            .expect("request");
        let response = test_app(&temp)
            .await
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stores_only_normalized_capture_and_is_idempotent() {
        let temp = TempDir::new().expect("temp dir");
        let router = test_app(&temp).await;
        let batch = sample_batch();
        let response = router
            .clone()
            .oneshot(post_request(&batch, Some("test-token")))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let stored = fs::read_to_string(
            temp.path()
                .join(format!("{}.json", batch.capture_artifact_id)),
        )
        .await
        .expect("stored capture");
        assert!(!stored.contains("TOP_SECRET"));
        assert!(!stored.contains("raw-connection-id"));
        assert!(stored.contains("conn-1"));

        let response = router
            .oneshot(post_request(&batch, Some("test-token")))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 4096).await.expect("body");
        assert!(String::from_utf8_lossy(&bytes).contains("existing"));
    }

    #[tokio::test]
    async fn retrieves_normalized_capture() {
        let temp = TempDir::new().expect("temp dir");
        let router = test_app(&temp).await;
        let batch = sample_batch();
        router
            .clone()
            .oneshot(post_request(&batch, Some("test-token")))
            .await
            .expect("ingest response");

        let request = Request::get(format!("/v1/captures/{}", batch.capture_artifact_id))
            .header(AUTHORIZATION, "Bearer test-token")
            .body(Body::empty())
            .expect("request");
        let response = router.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
