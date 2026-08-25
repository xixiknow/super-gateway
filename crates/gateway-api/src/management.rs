//! Contract-driven management listener, authentication boundary and horizontal controls.
#![allow(missing_docs, clippy::doc_markdown)]

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::{any, get},
};
use bytes::Bytes;
use gateway_domain::SecretValue;
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq as _;

const ADMIN_OPENAPI: &str = include_str!("../../../contracts/openapi/admin.openapi.json");
const SESSION_COOKIE: &str = "gateway_admin_session";
const MAX_ADMIN_BODY: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagementRole {
    PlatformAdmin,
    KeyOwner,
    Anonymous,
}

#[derive(Debug)]
pub struct ManagementPrincipal {
    pub user_id: Box<str>,
    pub session_id: Box<str>,
    pub role: ManagementRole,
    pub csrf_token: SecretValue,
    pub mfa_verified: bool,
    pub password_change_required: bool,
}

#[derive(Clone, Debug)]
pub struct ManagementRequest {
    pub operation_id: Box<str>,
    pub method: Method,
    pub path: Box<str>,
    pub query: Option<Box<str>>,
    pub path_parameters: BTreeMap<Box<str>, Box<str>>,
    pub body: Option<Value>,
    pub idempotency_key: Option<Box<str>>,
    pub if_match: Option<Box<str>>,
}

#[derive(Debug)]
pub struct ManagementBackendResponse {
    pub status: StatusCode,
    pub body: Value,
    pub etag: Option<Box<str>>,
    pub session_cookie: Option<SecretValue>,
    pub clear_session_cookie: bool,
    pub no_store: bool,
}

impl ManagementBackendResponse {
    #[must_use]
    pub fn ok(body: Value) -> Self {
        Self {
            status: StatusCode::OK,
            body,
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        }
    }
}

#[derive(Debug)]
pub struct ManagementDownload {
    pub body: Bytes,
    pub content_type: Box<str>,
    pub filename: Box<str>,
}

#[async_trait]
pub trait ManagementBackend: Send + Sync + 'static {
    async fn resolve_session(&self, token: &SecretValue)
    -> Result<Option<ManagementPrincipal>, ManagementBackendError>;

    async fn execute(
        &self,
        principal: Option<&ManagementPrincipal>,
        request: ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError>;

    async fn execute_download(
        &self,
        _principal: Option<&ManagementPrincipal>,
        _request: ManagementRequest,
    ) -> Result<ManagementDownload, ManagementBackendError> {
        Err(ManagementBackendError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManagementBackendError {
    #[error("management authentication failed")]
    Authentication,
    #[error("management authorization failed")]
    Authorization,
    #[error("management resource was not found")]
    NotFound,
    #[error("management precondition failed")]
    Precondition,
    #[error("management input is invalid")]
    InvalidInput,
    #[error("management dependency is unavailable")]
    Unavailable,
}

#[derive(Debug, Default)]
pub struct UnavailableManagementBackend;

#[async_trait]
impl ManagementBackend for UnavailableManagementBackend {
    async fn resolve_session(
        &self,
        _token: &SecretValue,
    ) -> Result<Option<ManagementPrincipal>, ManagementBackendError> {
        Ok(None)
    }

    async fn execute(
        &self,
        _principal: Option<&ManagementPrincipal>,
        _request: ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        Err(ManagementBackendError::Unavailable)
    }
}

#[derive(Clone)]
pub struct ManagementState {
    contract: Arc<ManagementContract>,
    backend: Arc<dyn ManagementBackend>,
}

impl std::fmt::Debug for ManagementState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagementState")
            .field("operation_count", &self.contract.operations.len())
            .finish_non_exhaustive()
    }
}

impl ManagementState {
    /// Compile the embedded OpenAPI route registry.
    ///
    /// # Errors
    ///
    /// Returns a contract error when the embedded artifact is malformed or contains an unsupported method/role.
    pub fn new(backend: Arc<dyn ManagementBackend>) -> Result<Self, ManagementContractError> {
        Ok(Self {
            contract: Arc::new(ManagementContract::embedded()?),
            backend,
        })
    }

    #[must_use]
    pub fn operation_count(&self) -> usize {
        self.contract.operations.len()
    }
}

/// Build the R8 management router from the embedded 196-operation contract.
pub fn management_router(state: ManagementState) -> Router {
    Router::new()
        .route("/admin/v1/{*path}", any(dispatch_management))
        .route("/admin", get(admin_index))
        .route("/admin/", get(admin_index))
        .route("/admin/{*asset}", get(admin_asset))
        .with_state(state)
}

#[derive(RustEmbed)]
#[folder = "../../web/admin-console/dist"]
struct AdminAssets;

async fn admin_index() -> Response {
    static_asset("index.html", false).unwrap_or_else(|| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "api_error",
            "Admin console unavailable.",
        )
    })
}

async fn admin_asset(axum::extract::Path(asset): axum::extract::Path<String>) -> Response {
    if asset.starts_with("v1/") {
        return error_response(StatusCode::NOT_FOUND, "not_found", "Resource not found.");
    }
    static_asset(&asset, asset.starts_with("assets/"))
        .or_else(|| static_asset("index.html", false))
        .unwrap_or_else(|| {
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "api_error",
                "Admin console unavailable.",
            )
        })
}

fn static_asset(path: &str, immutable: bool) -> Option<Response> {
    let asset = AdminAssets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut response = Response::new(Body::from(asset.data));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_str(mime.as_ref()).ok()?);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public,max-age=31536000,immutable"
        } else {
            "no-cache"
        }),
    );
    response.headers_mut().insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("same-origin"),
    );
    Some(response)
}

#[allow(clippy::too_many_lines)]
async fn dispatch_management(State(state): State<ManagementState>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(Box::from);
    let headers = request.headers().clone();
    let Some((operation, path_parameters)) = state.contract.resolve(&method, &path) else {
        return if state.contract.path_exists(&path) {
            error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "Method not allowed.",
            )
        } else {
            error_response(StatusCode::NOT_FOUND, "not_found", "Resource not found.")
        };
    };

    let raw_session = cookie_value(&headers, SESSION_COOKIE).map(SecretValue::new);
    let principal = match raw_session.as_ref() {
        Some(token) => match state.backend.resolve_session(token).await {
            Ok(value) => value,
            Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "api_error", "Service unavailable."),
        },
        None => None,
    };
    if !operation.roles.contains(&ManagementRole::Anonymous) {
        let Some(principal) = principal.as_ref() else {
            return no_store(error_response(
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "Authentication required.",
            ));
        };
        if !operation.roles.contains(&principal.role) {
            return error_response(StatusCode::NOT_FOUND, "not_found", "Resource not found.");
        }
        if !principal.mfa_verified && !partial_session_operation(&operation.operation_id) {
            return no_store(error_response(
                StatusCode::FORBIDDEN,
                "permission_error",
                "MFA verification required.",
            ));
        }
        if principal.password_change_required && !password_change_operation(&operation.operation_id) {
            return no_store(error_response(
                StatusCode::FORBIDDEN,
                "permission_error",
                "Password change required.",
            ));
        }
        if operation.csrf_required && !valid_csrf(&headers, &principal.csrf_token) {
            return error_response(StatusCode::FORBIDDEN, "permission_error", "CSRF verification failed.");
        }
    }
    if operation.csrf_required && !same_origin(&headers) {
        return error_response(StatusCode::FORBIDDEN, "permission_error", "Origin verification failed.");
    }
    let idempotency_key = header_text(&headers, "idempotency-key");
    if operation.idempotency_required && idempotency_key.is_none() {
        return error_response(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "Idempotency-Key is required.",
        );
    }
    let if_match = header_text(&headers, "if-match");
    if operation.if_match_required && if_match.is_none() {
        return error_response(
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            "If-Match is required.",
        );
    }
    let body = match to_bytes(request.into_body(), MAX_ADMIN_BODY).await {
        Ok(bytes) if bytes.is_empty() => None,
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(value) => Some(value),
            Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_request_error", "Invalid JSON body."),
        },
        Err(_) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request_error",
                "Request too large.",
            );
        }
    };
    let backend_request = ManagementRequest {
        operation_id: operation.operation_id.clone(),
        method,
        path: path.into_boxed_str(),
        query,
        path_parameters,
        body,
        idempotency_key,
        if_match,
    };
    if operation.operation_id.as_ref() == "getExportsByIdDownload" {
        match state
            .backend
            .execute_download(principal.as_ref(), backend_request)
            .await
        {
            Ok(download) => download_response(download),
            Err(error) => backend_error_response(error),
        }
    } else {
        match state.backend.execute(principal.as_ref(), backend_request).await {
            Ok(response) => backend_response(response),
            Err(error) => backend_error_response(error),
        }
    }
}

fn download_response(download: ManagementDownload) -> Response {
    let mut response = Response::new(Body::from(download.body));
    let Ok(content_type) = HeaderValue::from_str(&download.content_type) else {
        return backend_error_response(ManagementBackendError::Unavailable);
    };
    let Ok(content_disposition) = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", download.filename))
    else {
        return backend_error_response(ManagementBackendError::Unavailable);
    };
    response.headers_mut().insert(header::CONTENT_TYPE, content_type);
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, content_disposition);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn backend_response(response: ManagementBackendResponse) -> Response {
    let mut body = response.body;
    let request_id = uuid::Uuid::now_v7().to_string();
    if let Some(object) = body.as_object_mut() {
        let is_list = object.get("data").is_some_and(Value::is_array);
        let meta = object.entry("meta").or_insert_with(|| json!({}));
        let (has_more, size) = if let Some(meta) = meta.as_object_mut() {
            let has_more = meta
                .remove("has_more")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            let declared_size = meta.remove("page_size").and_then(|value| value.as_u64());
            meta.insert("request_id".to_owned(), Value::String(request_id));
            (has_more, declared_size)
        } else {
            (false, None)
        };
        if is_list && !object.contains_key("page") {
            let size = declared_list_size(object, size);
            object.insert(
                "page".to_owned(),
                json!({"size":size.max(1),"has_more":has_more,"next_cursor":null}),
            );
        }
    }
    let mut output = (response.status, axum::Json(body)).into_response();
    if let Some(etag) = response.etag
        && let Ok(value) = HeaderValue::from_str(&etag)
    {
        output.headers_mut().insert(header::ETAG, value);
    }
    if let Some(cookie) = response.session_cookie {
        let value = format!(
            "{SESSION_COOKIE}={}; Path=/admin; HttpOnly; Secure; SameSite=Strict",
            cookie.expose()
        );
        if let Ok(value) = HeaderValue::from_str(&value) {
            output.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    if response.clear_session_cookie {
        output.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_static(
                "gateway_admin_session=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
            ),
        );
    }
    if response.no_store {
        output = no_store(output);
    }
    output
}

fn declared_list_size(object: &serde_json::Map<String, Value>, declared: Option<u64>) -> u64 {
    declared
        .or_else(|| {
            object
                .get("data")
                .and_then(Value::as_array)
                .map(|items| items.len() as u64)
        })
        .unwrap_or(0)
}

fn backend_error_response(error: ManagementBackendError) -> Response {
    match error {
        ManagementBackendError::Authentication => no_store(error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "Authentication failed.",
        )),
        ManagementBackendError::Authorization => {
            error_response(StatusCode::NOT_FOUND, "not_found", "Resource not found.")
        }
        ManagementBackendError::NotFound => error_response(StatusCode::NOT_FOUND, "not_found", "Resource not found."),
        ManagementBackendError::Precondition => {
            error_response(StatusCode::CONFLICT, "conflict_error", "Resource revision conflict.")
        }
        ManagementBackendError::InvalidInput => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request_error",
            "Invalid input.",
        ),
        ManagementBackendError::Unavailable => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "api_error", "Service unavailable.")
        }
    }
}

fn error_response(status: StatusCode, kind: &'static str, message: &'static str) -> Response {
    (
        status,
        axum::Json(json!({
            "error":{"code":kind,"message":message,"field":null,"details":{}},
            "request_id":uuid::Uuid::now_v7().to_string()
        })),
    )
        .into_response()
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(candidate, value)| (candidate == name && !value.is_empty()).then(|| value.to_owned()))
}

fn header_text(headers: &HeaderMap, name: &'static str) -> Option<Box<str>> {
    let values = headers.get_all(name).iter().collect::<Vec<_>>();
    if values.len() != 1 {
        return None;
    }
    values[0]
        .to_str()
        .ok()
        .filter(|value| !value.trim().is_empty() && value.len() <= 512)
        .map(Box::from)
}

fn valid_csrf(headers: &HeaderMap, expected: &SecretValue) -> bool {
    let Some(value) = header_text(headers, "x-csrf-token") else {
        return false;
    };
    value.len() == expected.expose().len() && bool::from(value.as_bytes().ct_eq(expected.expose().as_bytes()))
}

fn same_origin(headers: &HeaderMap) -> bool {
    if header_text(headers, "sec-fetch-site").as_deref() != Some("same-origin") {
        return false;
    }
    let Some(origin) = header_text(headers, "origin") else {
        return false;
    };
    let Some(host) = header_text(headers, "host") else {
        return false;
    };
    origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .is_some_and(|authority| authority == host.as_ref())
}

fn partial_session_operation(operation_id: &str) -> bool {
    matches!(
        operation_id,
        "postAuthMfaEnrollments"
            | "postAuthMfaEnrollmentsByIdConfirm"
            | "postAuthMfaVerify"
            | "postAuthPasswordChange"
            | "deleteAuthSession"
            | "getAuthMe"
    )
}

fn password_change_operation(operation_id: &str) -> bool {
    matches!(
        operation_id,
        "postAuthPasswordChange" | "deleteAuthSession" | "getAuthMe"
    )
}

#[derive(Clone, Debug, Default)]
struct ManagementContract {
    operations: Vec<OperationSpec>,
}

type ResolvedOperation<'a> = (&'a OperationSpec, BTreeMap<Box<str>, Box<str>>);

impl ManagementContract {
    fn embedded() -> Result<Self, ManagementContractError> {
        let document: OpenApiDocument = serde_json::from_str(ADMIN_OPENAPI).map_err(|_| ManagementContractError)?;
        let mut operations = Vec::new();
        for (path, methods) in document.paths {
            for (method, operation) in methods {
                let method =
                    Method::from_bytes(method.to_ascii_uppercase().as_bytes()).map_err(|_| ManagementContractError)?;
                let roles = operation
                    .roles
                    .into_iter()
                    .map(|role| match role.as_str() {
                        "platform_admin" => Ok(ManagementRole::PlatformAdmin),
                        "key_owner" => Ok(ManagementRole::KeyOwner),
                        "anonymous" => Ok(ManagementRole::Anonymous),
                        _ => Err(ManagementContractError),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let references = operation
                    .parameters
                    .into_iter()
                    .filter_map(|parameter| parameter.reference)
                    .collect::<Vec<_>>();
                operations.push(OperationSpec {
                    method,
                    template: path.clone().into_boxed_str(),
                    operation_id: operation.operation_id,
                    roles,
                    csrf_required: references.iter().any(|value| value.ends_with("/CsrfToken")),
                    idempotency_required: references.iter().any(|value| value.ends_with("/IdempotencyKey")),
                    if_match_required: references.iter().any(|value| value.ends_with("/IfMatch")),
                });
            }
        }
        operations.sort_by(|left, right| {
            right
                .template
                .len()
                .cmp(&left.template.len())
                .then_with(|| left.method.as_str().cmp(right.method.as_str()))
        });
        Ok(Self { operations })
    }

    fn resolve(&self, method: &Method, path: &str) -> Option<ResolvedOperation<'_>> {
        self.operations.iter().find_map(|operation| {
            (operation.method == *method)
                .then(|| match_template(&operation.template, path).map(|parameters| (operation, parameters)))
                .flatten()
        })
    }

    fn path_exists(&self, path: &str) -> bool {
        self.operations
            .iter()
            .any(|operation| match_template(&operation.template, path).is_some())
    }
}

#[derive(Clone, Debug)]
struct OperationSpec {
    method: Method,
    template: Box<str>,
    operation_id: Box<str>,
    roles: Vec<ManagementRole>,
    csrf_required: bool,
    idempotency_required: bool,
    if_match_required: bool,
}

fn match_template(template: &str, path: &str) -> Option<BTreeMap<Box<str>, Box<str>>> {
    let expected = template.trim_matches('/').split('/').collect::<Vec<_>>();
    let actual = path.trim_matches('/').split('/').collect::<Vec<_>>();
    if expected.len() != actual.len() {
        return None;
    }
    let mut parameters = BTreeMap::new();
    for (expected, actual) in expected.into_iter().zip(actual) {
        if let Some(open) = expected.find('{')
            && let Some(relative_close) = expected[open + 1..].find('}')
        {
            let close = open + 1 + relative_close;
            let prefix = &expected[..open];
            let suffix = &expected[close + 1..];
            if !actual.starts_with(prefix) || !actual.ends_with(suffix) || actual.len() <= prefix.len() + suffix.len() {
                return None;
            }
            let value_end = actual.len().saturating_sub(suffix.len());
            let value = &actual[prefix.len()..value_end];
            let name = &expected[open + 1..close];
            parameters.insert(Box::from(name), Box::from(value));
        } else if expected != actual {
            return None;
        }
    }
    Some(parameters)
}

#[derive(Debug, Deserialize)]
struct OpenApiDocument {
    paths: BTreeMap<String, BTreeMap<String, OpenApiOperation>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenApiOperation {
    operation_id: Box<str>,
    #[serde(rename = "x-roles")]
    roles: Vec<String>,
    #[serde(default)]
    parameters: Vec<OpenApiParameter>,
}

#[derive(Debug, Deserialize)]
struct OpenApiParameter {
    #[serde(rename = "$ref")]
    reference: Option<String>,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("embedded management OpenAPI contract is invalid")]
pub struct ManagementContractError;

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use async_trait::async_trait;
    use axum::{body::Body, http::Request};
    use bytes::Bytes;
    use gateway_domain::SecretValue;
    use http::StatusCode;
    use http_body_util::BodyExt as _;
    use serde_json::json;
    use tower::ServiceExt as _;

    use super::{
        ManagementBackend, ManagementBackendError, ManagementBackendResponse, ManagementDownload, ManagementPrincipal,
        ManagementRequest, ManagementRole, ManagementState, management_router,
    };

    #[derive(Debug, Default)]
    struct FixtureBackend;

    #[async_trait]
    impl ManagementBackend for FixtureBackend {
        async fn resolve_session(
            &self,
            token: &SecretValue,
        ) -> Result<Option<ManagementPrincipal>, ManagementBackendError> {
            Ok((token.expose() == "session-admin").then(|| ManagementPrincipal {
                user_id: "admin-1".into(),
                session_id: "session-1".into(),
                role: ManagementRole::PlatformAdmin,
                csrf_token: SecretValue::new("csrf-admin".to_owned()),
                mfa_verified: true,
                password_change_required: false,
            }))
        }

        async fn execute(
            &self,
            _principal: Option<&ManagementPrincipal>,
            request: ManagementRequest,
        ) -> Result<ManagementBackendResponse, ManagementBackendError> {
            Ok(ManagementBackendResponse::ok(json!({
                "data": {"id": "fixture", "operation_id": request.operation_id},
                "meta": {}
            })))
        }

        async fn execute_download(
            &self,
            _principal: Option<&ManagementPrincipal>,
            _request: ManagementRequest,
        ) -> Result<ManagementDownload, ManagementBackendError> {
            Ok(ManagementDownload {
                body: Bytes::from_static(b"{\"request_id\":\"fixture\"}\n"),
                content_type: "application/x-ndjson".into(),
                filename: "usage-export-fixture.jsonl".into(),
            })
        }
    }

    #[test]
    fn embedded_contract_contains_exactly_196_operations() -> Result<(), Box<dyn std::error::Error>> {
        let state = ManagementState::new(Arc::new(FixtureBackend))?;
        assert_eq!(state.operation_count(), 196);
        let contract = state.contract;
        let (_, parameters) = contract
            .resolve(&http::Method::POST, "/admin/v1/credentials/credential-7:begin-recovery")
            .ok_or("route")?;
        assert_eq!(
            parameters,
            BTreeMap::from([(Box::from("id"), Box::from("credential-7"))])
        );
        Ok(())
    }

    #[tokio::test]
    async fn rbac_csrf_if_match_and_idempotency_are_enforced_before_backend() -> Result<(), Box<dyn std::error::Error>>
    {
        let state = ManagementState::new(Arc::new(FixtureBackend))?;
        let app = management_router(state);
        let unauthenticated = app
            .clone()
            .oneshot(Request::get("/admin/v1/users").body(Body::empty())?)
            .await?;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let missing_preconditions = app
            .clone()
            .oneshot(
                Request::post("/admin/v1/users/user-7:disable")
                    .header("cookie", "gateway_admin_session=session-admin")
                    .header("x-csrf-token", "csrf-admin")
                    .header("sec-fetch-site", "same-origin")
                    .header("origin", "https://gateway.example")
                    .header("host", "gateway.example")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(missing_preconditions.status(), StatusCode::PRECONDITION_REQUIRED);

        let accepted = app
            .oneshot(
                Request::post("/admin/v1/users/user-7:disable")
                    .header("cookie", "gateway_admin_session=session-admin")
                    .header("x-csrf-token", "csrf-admin")
                    .header("sec-fetch-site", "same-origin")
                    .header("origin", "https://gateway.example")
                    .header("host", "gateway.example")
                    .header("idempotency-key", "01HZX-R8-FIXTURE")
                    .header("if-match", "\"7\"")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(accepted.status(), StatusCode::OK);
        let body = accepted.into_body().collect().await?.to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("postUsersByIdDisable"));
        Ok(())
    }

    #[tokio::test]
    async fn embedded_admin_console_is_same_origin_and_security_hardened() -> Result<(), Box<dyn std::error::Error>> {
        let state = ManagementState::new(Arc::new(FixtureBackend))?;
        let app = management_router(state);
        let index = app
            .clone()
            .oneshot(Request::get("/admin/").body(Body::empty())?)
            .await?;
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(
            index
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/html")
        );
        assert!(index.headers().contains_key("content-security-policy"));
        assert_eq!(
            index
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        let body = index.into_body().collect().await?.to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("Claude Gateway"));

        let icons = app
            .oneshot(Request::get("/admin/public-icons.js").body(Body::empty())?)
            .await?;
        assert_eq!(icons.status(), StatusCode::OK);
        assert!(
            icons
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("javascript"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn export_download_returns_binary_with_one_shot_headers() -> Result<(), Box<dyn std::error::Error>> {
        let app = management_router(ManagementState::new(Arc::new(FixtureBackend))?);
        let response = app
            .oneshot(
                Request::get("/admin/v1/exports/0198d888-34a0-7b5d-a4cd-000000000099/download")
                    .header("cookie", "gateway_admin_session=session-admin")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/x-ndjson");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(
            response.headers()["content-disposition"],
            "attachment; filename=\"usage-export-fixture.jsonl\""
        );
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            Bytes::from_static(b"{\"request_id\":\"fixture\"}\n")
        );
        Ok(())
    }
}
