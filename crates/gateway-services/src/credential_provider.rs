//! Versioned provider boundary for subscription Credential maintenance.
#![allow(missing_docs, clippy::missing_errors_doc)]

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use gateway_domain::{AuthKind, EgressBindingSnapshot, SecretBytes, SecretValue};
use http::{Method, Uri};
use serde::Deserialize;
use zeroize::Zeroize as _;

use crate::credential::{AuthCandidate, AuthMaintenanceAdapter, AuthOperationSnapshot, CredentialServiceError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderEndpointProfile {
    pub profile_code: Box<str>,
    pub version: u64,
    pub token_endpoint: Uri,
    pub client_id: Box<str>,
    pub scopes: Vec<Box<str>>,
    pub request_encoding: ProviderRequestEncoding,
    pub max_response_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderRequestEncoding {
    ApplicationJson,
    FormUrlencoded,
}

impl ProviderEndpointProfile {
    pub fn validate(&self) -> Result<(), CredentialServiceError> {
        let authority = self
            .token_endpoint
            .authority()
            .ok_or(CredentialServiceError::EvidencePending)?;
        if self.profile_code.trim().is_empty()
            || self.version == 0
            || self.client_id.trim().is_empty()
            || self.max_response_bytes == 0
            || self.max_response_bytes > 1024 * 1024
            || self.token_endpoint.scheme_str() != Some("https")
            || authority.as_str().contains('@')
            || self.token_endpoint.path().is_empty()
            || self.scopes.iter().any(|scope| scope.trim().is_empty())
        {
            return Err(CredentialServiceError::EvidencePending);
        }
        Ok(())
    }
}

pub struct OAuthRefreshMaterial {
    pub profile: ProviderEndpointProfile,
    pub refresh_token: SecretBytes,
}

pub struct ProviderHttpRequest {
    pub method: Method,
    pub endpoint: Uri,
    pub headers: Vec<ProviderHttpHeader>,
    pub body: SecretBytes,
    pub response_limit: usize,
    pub egress: EgressBindingSnapshot,
}

pub struct ProviderHttpHeader {
    pub name: &'static str,
    pub value: SecretBytes,
}

pub struct ProviderHttpResponse {
    pub status: u16,
    pub headers: Vec<(Box<str>, Box<[u8]>)>,
    pub body: SecretBytes,
}

#[async_trait]
pub trait ProviderHttpPort: Send + Sync + 'static {
    async fn execute(&self, request: ProviderHttpRequest) -> Result<ProviderHttpResponse, CredentialServiceError>;
}

#[async_trait]
pub trait RefreshMaterialPort: Send + Sync + 'static {
    async fn load(&self, operation: &AuthOperationSnapshot) -> Result<OAuthRefreshMaterial, CredentialServiceError>;

    async fn stage_candidate(
        &self,
        operation: &AuthOperationSnapshot,
        access_token: SecretValue,
        refresh_token: SecretValue,
        expires_after: Option<Duration>,
        adapter_version: &str,
    ) -> Result<AuthCandidate, CredentialServiceError>;
}

pub struct SubscriptionOAuthRefreshAdapter<H, M> {
    http: Arc<H>,
    material: Arc<M>,
}

impl<H, M> SubscriptionOAuthRefreshAdapter<H, M>
where
    H: ProviderHttpPort,
    M: RefreshMaterialPort,
{
    #[must_use]
    pub fn new(http: Arc<H>, material: Arc<M>) -> Arc<Self> {
        Arc::new(Self { http, material })
    }
}

#[async_trait]
impl<H, M> AuthMaintenanceAdapter for SubscriptionOAuthRefreshAdapter<H, M>
where
    H: ProviderHttpPort,
    M: RefreshMaterialPort,
{
    async fn execute(&self, operation: &AuthOperationSnapshot) -> Result<AuthCandidate, CredentialServiceError> {
        if !matches!(
            operation.auth_kind,
            AuthKind::OauthSubscription | AuthKind::SetupTokenSubscription
        ) {
            return Err(CredentialServiceError::InvalidAuthentication);
        }
        let material = self.material.load(operation).await?;
        material.profile.validate()?;
        let adapter_version = format!("{}-v{}", material.profile.profile_code, material.profile.version);
        let (content_type, request_body) = match material.profile.request_encoding {
            ProviderRequestEncoding::ApplicationJson => (
                b"application/json".as_slice(),
                refresh_json(&material.profile, material.refresh_token.expose())?,
            ),
            ProviderRequestEncoding::FormUrlencoded => (
                b"application/x-www-form-urlencoded".as_slice(),
                refresh_form(&material.profile, material.refresh_token.expose()),
            ),
        };
        let response = self
            .http
            .execute(ProviderHttpRequest {
                method: Method::POST,
                endpoint: material.profile.token_endpoint.clone(),
                headers: vec![ProviderHttpHeader {
                    name: "content-type",
                    value: SecretBytes::new(content_type.to_vec()),
                }],
                body: SecretBytes::new(request_body),
                response_limit: material.profile.max_response_bytes,
                egress: operation.egress.clone(),
            })
            .await?;
        classify_status(&response)?;
        if response.body.expose().len() > material.profile.max_response_bytes {
            return Err(CredentialServiceError::Transient);
        }
        let mut document: RefreshDocument =
            serde_json::from_slice(response.body.expose()).map_err(|_| CredentialServiceError::Transient)?;
        if document.access_token.is_empty()
            || document
                .token_type
                .as_deref()
                .is_some_and(|token_type| !token_type.eq_ignore_ascii_case("bearer"))
        {
            document.zeroize();
            return Err(CredentialServiceError::InvalidAuthentication);
        }
        let effective_refresh = document
            .refresh_token
            .take()
            .unwrap_or_else(|| String::from_utf8_lossy(material.refresh_token.expose()).into_owned());
        let access = SecretValue::new(std::mem::take(&mut document.access_token));
        let refresh = SecretValue::new(effective_refresh);
        let expires_after = document.expires_in.map(Duration::from_secs);
        document.zeroize();
        self.material
            .stage_candidate(operation, access, refresh, expires_after, &adapter_version)
            .await
    }
}

#[derive(Deserialize)]
struct RefreshDocument {
    access_token: String,
    refresh_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<u64>,
}

impl RefreshDocument {
    fn zeroize(&mut self) {
        self.access_token.zeroize();
        if let Some(refresh) = self.refresh_token.as_mut() {
            refresh.zeroize();
        }
        if let Some(token_type) = self.token_type.as_mut() {
            token_type.zeroize();
        }
    }
}

fn refresh_form(profile: &ProviderEndpointProfile, refresh_token: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    append_form(&mut body, b"grant_type", b"refresh_token");
    append_form(&mut body, b"refresh_token", refresh_token);
    append_form(&mut body, b"client_id", profile.client_id.as_bytes());
    if !profile.scopes.is_empty() {
        let scopes = profile.scopes.join(" ");
        append_form(&mut body, b"scope", scopes.as_bytes());
    }
    body
}

fn refresh_json(profile: &ProviderEndpointProfile, refresh_token: &[u8]) -> Result<Vec<u8>, CredentialServiceError> {
    let refresh_token =
        std::str::from_utf8(refresh_token).map_err(|_| CredentialServiceError::InvalidAuthentication)?;
    serde_json::to_vec(&serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": profile.client_id,
        "scope": profile.scopes.join(" "),
    }))
    .map_err(|_| CredentialServiceError::Transient)
}

fn append_form(output: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    if !output.is_empty() {
        output.push(b'&');
    }
    percent_encode(output, name);
    output.push(b'=');
    percent_encode(output, value);
}

fn percent_encode(output: &mut Vec<u8>, value: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => output.push(*byte),
            b' ' => output.push(b'+'),
            _ => {
                output.push(b'%');
                output.push(HEX[usize::from(byte >> 4)]);
                output.push(HEX[usize::from(byte & 0x0f)]);
            }
        }
    }
}

fn classify_status(response: &ProviderHttpResponse) -> Result<(), CredentialServiceError> {
    match response.status {
        200..=299 => Ok(()),
        400 | 401 => {
            let invalid_grant = serde_json::from_slice::<serde_json::Value>(response.body.expose())
                .ok()
                .and_then(|value| {
                    value
                        .get("error")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .is_some_and(|error| matches!(error.as_str(), "invalid_grant" | "invalid_token"));
            if invalid_grant {
                Err(CredentialServiceError::InvalidAuthentication)
            } else {
                Err(CredentialServiceError::Transient)
            }
        }
        429 => Err(CredentialServiceError::RateLimited(
            numeric_retry_after(&response.headers).unwrap_or(Duration::from_mins(1)),
        )),
        500..=599 => Err(CredentialServiceError::Transient),
        _ => Err(CredentialServiceError::EvidencePending),
    }
}

fn numeric_retry_after(headers: &[(Box<str>, Box<[u8]>)]) -> Option<Duration> {
    let values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return None;
    }
    let seconds = std::str::from_utf8(&values[0].1).ok()?.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds.clamp(1, 900)))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use gateway_domain::{AnthropicAccountUuid, EgressBindingId, EgressBindingSnapshot, EgressMode};

    use super::*;

    struct FakeHttp {
        requests: Mutex<Vec<ProviderHttpRequest>>,
        response: Mutex<Option<ProviderHttpResponse>>,
    }

    #[async_trait]
    impl ProviderHttpPort for FakeHttp {
        async fn execute(&self, request: ProviderHttpRequest) -> Result<ProviderHttpResponse, CredentialServiceError> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request);
            self.response
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .ok_or(CredentialServiceError::Transient)
        }
    }

    #[derive(Default)]
    struct FakeMaterial {
        staged: Mutex<Option<(String, String)>>,
    }

    #[async_trait]
    impl RefreshMaterialPort for FakeMaterial {
        async fn load(
            &self,
            _operation: &AuthOperationSnapshot,
        ) -> Result<OAuthRefreshMaterial, CredentialServiceError> {
            Ok(OAuthRefreshMaterial {
                profile: ProviderEndpointProfile {
                    profile_code: "subscription".into(),
                    version: 7,
                    token_endpoint: "https://provider.invalid/oauth/token"
                        .parse()
                        .map_err(|_| CredentialServiceError::EvidencePending)?,
                    client_id: "client fixture".into(),
                    scopes: vec!["scope:a".into(), "scope:b".into()],
                    request_encoding: ProviderRequestEncoding::FormUrlencoded,
                    max_response_bytes: 4096,
                },
                refresh_token: SecretBytes::new(b"refresh+/fixture".to_vec()),
            })
        }

        async fn stage_candidate(
            &self,
            operation: &AuthOperationSnapshot,
            access_token: SecretValue,
            refresh_token: SecretValue,
            expires_after: Option<Duration>,
            adapter_version: &str,
        ) -> Result<AuthCandidate, CredentialServiceError> {
            *self.staged.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some((access_token.expose().to_owned(), refresh_token.expose().to_owned()));
            Ok(AuthCandidate {
                access_secret_id: None,
                refresh_secret_id: None,
                console_secret_id: None,
                verified_account_uuid: operation.account_uuid,
                expires_after,
                adapter_code: "oauth_refresh".into(),
                adapter_version: adapter_version.to_owned().into_boxed_str(),
            })
        }
    }

    fn operation() -> AuthOperationSnapshot {
        AuthOperationSnapshot {
            credential_id: gateway_domain::CredentialId::new("credential_1")
                .unwrap_or_else(|error| std::panic::panic_any(error)),
            account_uuid: Some(AnthropicAccountUuid::new(uuid::Uuid::from_u128(1))),
            auth_kind: AuthKind::OauthSubscription,
            credential_revision: 2,
            token_version: 3,
            egress: EgressBindingSnapshot {
                binding_id: EgressBindingId::new("egress_1").unwrap_or_else(|error| std::panic::panic_any(error)),
                mode: EgressMode::Direct,
                proxy_id: None,
                egress_epoch: 1,
            },
            operation_id: "operation_1".into(),
            operation_generation: 1,
            joined_existing: false,
        }
    }

    #[tokio::test]
    async fn refresh_is_form_encoded_and_rotates_tokens_without_logging_them() -> Result<(), Box<dyn std::error::Error>>
    {
        let http = Arc::new(FakeHttp {
            requests: Mutex::new(Vec::new()),
            response: Mutex::new(Some(ProviderHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: SecretBytes::new(
                    br#"{"access_token":"access-new","refresh_token":"refresh-new","token_type":"Bearer","expires_in":3600}"#
                        .to_vec(),
                ),
            })),
        });
        let material = Arc::new(FakeMaterial::default());
        let adapter = SubscriptionOAuthRefreshAdapter::new(http.clone(), material.clone());
        let candidate = adapter.execute(&operation()).await?;
        assert_eq!(candidate.expires_after, Some(Duration::from_hours(1)));
        let requests = http.requests.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(requests[0].method, Method::POST);
        let body = std::str::from_utf8(requests[0].body.expose())?;
        assert!(body.contains("refresh_token=refresh%2B%2Ffixture"));
        assert!(body.contains("client_id=client+fixture"));
        assert_eq!(
            *material
                .staged
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(("access-new".to_owned(), "refresh-new".to_owned()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn invalid_grant_is_terminal_and_retry_after_is_bounded() {
        let invalid = ProviderHttpResponse {
            status: 400,
            headers: Vec::new(),
            body: SecretBytes::new(br#"{"error":"invalid_grant"}"#.to_vec()),
        };
        assert!(matches!(
            classify_status(&invalid),
            Err(CredentialServiceError::InvalidAuthentication)
        ));
        let limited = ProviderHttpResponse {
            status: 429,
            headers: vec![("retry-after".into(), Box::from(b"1200".as_slice()))],
            body: SecretBytes::new(Vec::new()),
        };
        assert!(matches!(
            classify_status(&limited),
            Err(CredentialServiceError::RateLimited(duration)) if duration == Duration::from_mins(15)
        ));
    }
}
