//! Evidence-versioned Anthropic subscription enrollment adapters.
#![allow(clippy::missing_errors_doc)]

use std::{sync::Arc, time::Duration};

use gateway_domain::{EgressBindingSnapshot, SecretBytes, SecretValue};
use http::{Method, Uri};
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroize as _;

use crate::{
    credential::CredentialServiceError,
    credential_provider::{ProviderHttpHeader, ProviderHttpPort, ProviderHttpRequest, ProviderHttpResponse},
};

/// Frozen provider endpoints and OAuth parameters backed by one evidence version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentProviderProfile {
    /// Stable profile code.
    pub profile_code: Box<str>,
    /// Monotonic profile version.
    pub version: u64,
    /// Human-readable evidence identifier used in Audit and `AuthVersion` records.
    pub evidence_version: Box<str>,
    /// Browser authorization endpoint.
    pub authorize_endpoint: Uri,
    /// Authorization-code exchange endpoint.
    pub token_endpoint: Uri,
    /// Bearer profile endpoint used to verify the account UUID.
    pub profile_endpoint: Uri,
    /// Claude Code bootstrap endpoint used to identify inference-only Setup Tokens.
    pub bootstrap_endpoint: Uri,
    /// Claude Code OAuth client ID.
    pub client_id: Box<str>,
    /// Manual authorization-code redirect URI.
    pub redirect_uri: Uri,
    /// Default full Claude Code subscription scopes.
    pub scopes: Vec<Box<str>>,
    /// Maximum token/profile response body.
    pub max_response_bytes: usize,
}

impl EnrollmentProviderProfile {
    /// Validate that the frozen profile is HTTPS-only and bounded.
    pub fn validate(&self) -> Result<(), CredentialServiceError> {
        if self.profile_code.trim().is_empty()
            || self.version == 0
            || self.evidence_version.trim().is_empty()
            || self.client_id.trim().is_empty()
            || self.scopes.is_empty()
            || self.scopes.iter().any(|scope| scope.trim().is_empty())
            || self.max_response_bytes == 0
            || self.max_response_bytes > 1024 * 1024
        {
            return Err(CredentialServiceError::EvidencePending);
        }
        for endpoint in [
            &self.authorize_endpoint,
            &self.token_endpoint,
            &self.profile_endpoint,
            &self.bootstrap_endpoint,
            &self.redirect_uri,
        ] {
            let authority = endpoint.authority().ok_or(CredentialServiceError::EvidencePending)?;
            if endpoint.scheme_str() != Some("https") || authority.as_str().contains('@') || endpoint.path().is_empty()
            {
                return Err(CredentialServiceError::EvidencePending);
            }
        }
        Ok(())
    }

    /// Adapter version persisted alongside the resulting `AuthVersion`.
    #[must_use]
    pub fn adapter_version(&self) -> String {
        format!("{}-v{}:{}", self.profile_code, self.version, self.evidence_version)
    }

    /// Build the manual authorization URL for a previously persisted PKCE session.
    pub fn authorization_uri(&self, challenge: &str, state: &SecretValue) -> Result<Uri, CredentialServiceError> {
        self.validate()?;
        if challenge.is_empty() || state.expose().is_empty() {
            return Err(CredentialServiceError::EvidencePending);
        }
        let mut query = Vec::new();
        append_query(&mut query, b"code", b"true");
        append_query(&mut query, b"client_id", self.client_id.as_bytes());
        append_query(&mut query, b"response_type", b"code");
        append_query(&mut query, b"redirect_uri", self.redirect_uri.to_string().as_bytes());
        append_query(&mut query, b"scope", self.scopes.join(" ").as_bytes());
        append_query(&mut query, b"code_challenge", challenge.as_bytes());
        append_query(&mut query, b"code_challenge_method", b"S256");
        append_query(&mut query, b"state", state.expose().as_bytes());
        let value = format!(
            "{}?{}",
            self.authorize_endpoint,
            String::from_utf8(query).map_err(|_| CredentialServiceError::EvidencePending)?
        );
        value.parse().map_err(|_| CredentialServiceError::EvidencePending)
    }
}

/// Captured Claude Code 2.1.220 production OAuth profile.
#[must_use]
pub fn claude_code_subscription_profile() -> EnrollmentProviderProfile {
    EnrollmentProviderProfile {
        profile_code: "claude_code_subscription".into(),
        version: 1,
        evidence_version: "claude-code-2.1.220-local-source".into(),
        authorize_endpoint: Uri::from_static("https://claude.com/cai/oauth/authorize"),
        token_endpoint: Uri::from_static("https://platform.claude.com/v1/oauth/token"),
        profile_endpoint: Uri::from_static("https://api.anthropic.com/api/oauth/profile"),
        bootstrap_endpoint: Uri::from_static("https://api.anthropic.com/api/claude_cli/bootstrap"),
        client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e".into(),
        redirect_uri: Uri::from_static("https://platform.claude.com/oauth/code/callback"),
        scopes: [
            "org:create_api_key",
            "user:profile",
            "user:inference",
            "user:sessions:claude_code",
            "user:mcp_servers",
            "user:file_upload",
        ]
        .into_iter()
        .map(Into::into)
        .collect(),
        max_response_bytes: 64 * 1024,
    }
}

/// Verified long-lived material returned by an enrollment adapter.
pub struct VerifiedEnrollmentMaterial {
    /// OAuth access token.
    pub access_token: SecretValue,
    /// OAuth refresh token, when present.
    pub refresh_token: Option<SecretValue>,
    /// Provider-verified account UUID.
    pub account_uuid: Uuid,
    /// Optional organization UUID returned by the provider.
    pub organization_uuid: Option<Uuid>,
    /// Absolute lifetime expressed as a duration from exchange time.
    pub expires_after: Option<Duration>,
    /// Versioned adapter identity.
    pub adapter_version: Box<str>,
}

/// Setup Token verification failures that require enrollment-specific handling.
#[derive(Debug, thiserror::Error)]
pub enum SetupTokenVerificationError {
    /// Provider/transport failure using the shared credential taxonomy.
    #[error(transparent)]
    Provider(#[from] CredentialServiceError),
    /// The inference-only token was accepted but the provider did not expose a
    /// trustworthy account UUID, so global account de-duplication cannot run.
    #[error("setup token account identity is unavailable")]
    AccountIdentityUnavailable,
}

impl std::fmt::Debug for VerifiedEnrollmentMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedEnrollmentMaterial")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "[REDACTED]"))
            .field("account_uuid", &self.account_uuid)
            .field("organization_uuid", &self.organization_uuid)
            .field("expires_after", &self.expires_after)
            .field("adapter_version", &self.adapter_version)
            .finish()
    }
}

/// OAuth enrollment adapter that always receives a frozen Credential Egress snapshot.
pub struct SubscriptionEnrollmentAdapter<H> {
    http: Arc<H>,
    profile: EnrollmentProviderProfile,
}

impl<H> SubscriptionEnrollmentAdapter<H>
where
    H: ProviderHttpPort,
{
    /// Create an adapter from a validated, immutable provider profile.
    pub fn new(http: Arc<H>, profile: EnrollmentProviderProfile) -> Result<Self, CredentialServiceError> {
        profile.validate()?;
        Ok(Self { http, profile })
    }

    /// Build the manual authorization URL for a previously persisted PKCE session.
    pub fn authorization_uri(&self, challenge: &str, state: &SecretValue) -> Result<Uri, CredentialServiceError> {
        self.profile.authorization_uri(challenge, state)
    }

    /// Exchange an authorization code and require the token response to carry a valid account UUID.
    pub async fn exchange_authorization_code(
        &self,
        code: &SecretValue,
        state: &SecretValue,
        verifier: &SecretValue,
        egress: EgressBindingSnapshot,
    ) -> Result<VerifiedEnrollmentMaterial, CredentialServiceError> {
        if code.expose().is_empty() || state.expose().is_empty() || verifier.expose().is_empty() {
            return Err(CredentialServiceError::InvalidAuthentication);
        }
        let request = serde_json::json!({
            "grant_type": "authorization_code",
            "code": code.expose(),
            "redirect_uri": self.profile.redirect_uri.to_string(),
            "client_id": self.profile.client_id,
            "code_verifier": verifier.expose(),
            "state": state.expose(),
        });
        let response = self
            .http
            .execute(ProviderHttpRequest {
                method: Method::POST,
                endpoint: self.profile.token_endpoint.clone(),
                headers: vec![ProviderHttpHeader {
                    name: "content-type",
                    value: SecretBytes::new(b"application/json".to_vec()),
                }],
                body: SecretBytes::new(
                    serde_json::to_vec(&request).map_err(|_| CredentialServiceError::EvidencePending)?,
                ),
                response_limit: self.profile.max_response_bytes,
                egress,
            })
            .await?;
        classify_enrollment_status(&response)?;
        let mut document: TokenExchangeDocument = serde_json::from_slice(response.body.expose())
            .map_err(|_| CredentialServiceError::InvalidAuthentication)?;
        let account_uuid = parse_uuid(&document.account.uuid)?;
        let organization_uuid = document
            .organization
            .as_ref()
            .map(|organization| parse_uuid(&organization.uuid))
            .transpose()?;
        if document.access_token.is_empty()
            || document
                .token_type
                .as_deref()
                .is_some_and(|token_type| !token_type.eq_ignore_ascii_case("bearer"))
        {
            document.zeroize();
            return Err(CredentialServiceError::InvalidAuthentication);
        }
        let access_token = SecretValue::new(std::mem::take(&mut document.access_token));
        let refresh_token = document
            .refresh_token
            .take()
            .filter(|token| !token.is_empty())
            .map(SecretValue::new);
        let expires_after = document.expires_in.map(Duration::from_secs);
        document.zeroize();
        Ok(VerifiedEnrollmentMaterial {
            access_token,
            refresh_token,
            account_uuid,
            organization_uuid,
            expires_after,
            adapter_version: self.profile.adapter_version().into_boxed_str(),
        })
    }

    /// Verify imported OAuth tokens through the captured `/api/oauth/profile` endpoint.
    pub async fn verify_existing_oauth(
        &self,
        access_token: SecretValue,
        refresh_token: Option<SecretValue>,
        egress: EgressBindingSnapshot,
    ) -> Result<VerifiedEnrollmentMaterial, CredentialServiceError> {
        if access_token.expose().is_empty() {
            return Err(CredentialServiceError::InvalidAuthentication);
        }
        let mut authorization = Vec::with_capacity(access_token.expose().len() + 7);
        authorization.extend_from_slice(b"Bearer ");
        authorization.extend_from_slice(access_token.expose().as_bytes());
        let response = self
            .http
            .execute(ProviderHttpRequest {
                method: Method::GET,
                endpoint: self.profile.profile_endpoint.clone(),
                headers: vec![
                    ProviderHttpHeader {
                        name: "authorization",
                        value: SecretBytes::new(authorization),
                    },
                    ProviderHttpHeader {
                        name: "cache-control",
                        value: SecretBytes::new(b"no-cache".to_vec()),
                    },
                ],
                body: SecretBytes::new(Vec::new()),
                response_limit: self.profile.max_response_bytes,
                egress,
            })
            .await?;
        classify_enrollment_status(&response)?;
        let document: OAuthProfileDocument = serde_json::from_slice(response.body.expose())
            .map_err(|_| CredentialServiceError::InvalidAuthentication)?;
        Ok(VerifiedEnrollmentMaterial {
            access_token,
            refresh_token,
            account_uuid: parse_uuid(&document.account.uuid)?,
            organization_uuid: parse_uuid(&document.organization.uuid).ok(),
            expires_after: None,
            adapter_version: self.profile.adapter_version().into_boxed_str(),
        })
    }

    /// Verify an inference-only Claude Code Setup Token through the captured
    /// bootstrap contract without inventing refresh material or account identity.
    pub async fn verify_setup_token(
        &self,
        setup_token: SecretValue,
        egress: EgressBindingSnapshot,
    ) -> Result<VerifiedEnrollmentMaterial, SetupTokenVerificationError> {
        if setup_token.expose().is_empty() {
            return Err(CredentialServiceError::InvalidAuthentication.into());
        }
        let mut authorization = Vec::with_capacity(setup_token.expose().len() + 7);
        authorization.extend_from_slice(b"Bearer ");
        authorization.extend_from_slice(setup_token.expose().as_bytes());
        let response = self
            .http
            .execute(ProviderHttpRequest {
                method: Method::GET,
                endpoint: self.profile.bootstrap_endpoint.clone(),
                headers: vec![
                    ProviderHttpHeader {
                        name: "authorization",
                        value: SecretBytes::new(authorization),
                    },
                    ProviderHttpHeader {
                        name: "anthropic-beta",
                        value: SecretBytes::new(b"oauth-2025-04-20".to_vec()),
                    },
                    ProviderHttpHeader {
                        name: "user-agent",
                        value: SecretBytes::new(b"claude-code/2.1.220".to_vec()),
                    },
                ],
                body: SecretBytes::new(Vec::new()),
                response_limit: self.profile.max_response_bytes,
                egress,
            })
            .await?;
        match response.status {
            200..=299 => {}
            401 => return Err(CredentialServiceError::InvalidAuthentication.into()),
            403 => return Err(SetupTokenVerificationError::AccountIdentityUnavailable),
            _ => {
                classify_enrollment_status(&response)?;
                return Err(CredentialServiceError::EvidencePending.into());
            }
        }
        let document: BootstrapDocument = serde_json::from_slice(response.body.expose())
            .map_err(|_| SetupTokenVerificationError::AccountIdentityUnavailable)?;
        let account = document
            .oauth_account
            .ok_or(SetupTokenVerificationError::AccountIdentityUnavailable)?;
        let account_uuid = account
            .account_uuid
            .as_deref()
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or(SetupTokenVerificationError::AccountIdentityUnavailable)?;
        let organization_uuid = account
            .organization_uuid
            .as_deref()
            .and_then(|value| Uuid::parse_str(value).ok());
        Ok(VerifiedEnrollmentMaterial {
            access_token: setup_token,
            refresh_token: None,
            account_uuid,
            organization_uuid,
            expires_after: None,
            adapter_version: self.profile.adapter_version().into_boxed_str(),
        })
    }
}

#[derive(Deserialize)]
struct TokenExchangeDocument {
    access_token: String,
    refresh_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<u64>,
    account: AccountDocument,
    organization: Option<OrganizationDocument>,
}

impl TokenExchangeDocument {
    fn zeroize(&mut self) {
        self.access_token.zeroize();
        if let Some(value) = self.refresh_token.as_mut() {
            value.zeroize();
        }
        if let Some(value) = self.token_type.as_mut() {
            value.zeroize();
        }
    }
}

#[derive(Deserialize)]
struct OAuthProfileDocument {
    account: AccountDocument,
    organization: OrganizationDocument,
}

#[derive(Deserialize)]
struct AccountDocument {
    uuid: String,
}

#[derive(Deserialize)]
struct OrganizationDocument {
    uuid: String,
}

#[derive(Deserialize)]
struct BootstrapDocument {
    oauth_account: Option<BootstrapAccountDocument>,
}

#[derive(Deserialize)]
struct BootstrapAccountDocument {
    account_uuid: Option<String>,
    organization_uuid: Option<String>,
}

fn classify_enrollment_status(response: &ProviderHttpResponse) -> Result<(), CredentialServiceError> {
    match response.status {
        200..=299 => Ok(()),
        400 | 401 | 403 => Err(CredentialServiceError::InvalidAuthentication),
        429 => Err(CredentialServiceError::RateLimited(
            numeric_retry_after(
                &response
                    .headers
                    .iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                    .collect::<Vec<_>>(),
            )
            .unwrap_or(Duration::from_mins(1)),
        )),
        500..=599 => Err(CredentialServiceError::Transient),
        _ => Err(CredentialServiceError::EvidencePending),
    }
}

fn numeric_retry_after(values: &[&(Box<str>, Box<[u8]>)]) -> Option<Duration> {
    if values.len() != 1 {
        return None;
    }
    let seconds = std::str::from_utf8(&values[0].1).ok()?.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds.clamp(1, 900)))
}

fn parse_uuid(value: &str) -> Result<Uuid, CredentialServiceError> {
    Uuid::parse_str(value).map_err(|_| CredentialServiceError::InvalidAuthentication)
}

fn append_query(output: &mut Vec<u8>, name: &[u8], value: &[u8]) {
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
            _ => {
                output.push(b'%');
                output.push(HEX[usize::from(byte >> 4)]);
                output.push(HEX[usize::from(byte & 0x0f)]);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use gateway_domain::{EgressBindingId, EgressMode};

    use super::*;

    struct FakeHttp {
        requests: Mutex<Vec<ProviderHttpRequest>>,
        responses: Mutex<Vec<ProviderHttpResponse>>,
    }

    #[async_trait]
    impl ProviderHttpPort for FakeHttp {
        async fn execute(&self, request: ProviderHttpRequest) -> Result<ProviderHttpResponse, CredentialServiceError> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request);
            self.responses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop()
                .ok_or(CredentialServiceError::Transient)
        }
    }

    fn egress() -> EgressBindingSnapshot {
        EgressBindingSnapshot {
            binding_id: EgressBindingId::new("egress_fixture").expect("fixture id"),
            mode: EgressMode::Direct,
            proxy_id: None,
            egress_epoch: 3,
        }
    }

    #[test]
    fn captured_profile_builds_exact_bounded_authorization_uri() -> Result<(), Box<dyn std::error::Error>> {
        let http = Arc::new(FakeHttp {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(Vec::new()),
        });
        let adapter = SubscriptionEnrollmentAdapter::new(http, claude_code_subscription_profile())?;
        let uri = adapter.authorization_uri("challenge/fixture", &SecretValue::new("state fixture".to_owned()))?;
        let rendered = uri.to_string();
        assert!(rendered.starts_with("https://claude.com/cai/oauth/authorize?code=true&"));
        assert!(rendered.contains("client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e"));
        assert!(rendered.contains("redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback"));
        assert!(rendered.contains("code_challenge=challenge%2Ffixture"));
        assert!(rendered.contains("state=state%20fixture"));
        Ok(())
    }

    #[tokio::test]
    async fn existing_oauth_is_verified_through_profile_on_the_frozen_egress() -> Result<(), Box<dyn std::error::Error>>
    {
        let account_uuid = Uuid::now_v7();
        let organization_uuid = Uuid::now_v7();
        let http = Arc::new(FakeHttp {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(vec![ProviderHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: SecretBytes::new(serde_json::to_vec(&serde_json::json!({
                    "account":{"uuid":account_uuid,"email":"fixture@example.invalid"},
                    "organization":{"uuid":organization_uuid}
                }))?),
            }]),
        });
        let adapter = SubscriptionEnrollmentAdapter::new(http.clone(), claude_code_subscription_profile())?;
        let verified = adapter
            .verify_existing_oauth(
                SecretValue::new("access-fixture".to_owned()),
                Some(SecretValue::new("refresh-fixture".to_owned())),
                egress(),
            )
            .await?;
        assert_eq!(verified.account_uuid, account_uuid);
        assert_eq!(verified.organization_uuid, Some(organization_uuid));
        let requests = http.requests.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[0].endpoint.path(), "/api/oauth/profile");
        assert_eq!(requests[0].egress.egress_epoch, 3);
        assert_eq!(requests[0].headers[0].name, "authorization");
        assert_eq!(requests[0].headers[0].value.expose(), b"Bearer access-fixture");
        Ok(())
    }

    #[tokio::test]
    async fn setup_token_uses_bootstrap_and_preserves_inference_only_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        let account_uuid = Uuid::now_v7();
        let organization_uuid = Uuid::now_v7();
        let http = Arc::new(FakeHttp {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(vec![ProviderHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: SecretBytes::new(serde_json::to_vec(&serde_json::json!({
                    "oauth_account": {
                        "account_uuid": account_uuid,
                        "organization_uuid": organization_uuid
                    },
                    "narrowed": true
                }))?),
            }]),
        });
        let adapter = SubscriptionEnrollmentAdapter::new(http.clone(), claude_code_subscription_profile())?;
        let verified = adapter
            .verify_setup_token(SecretValue::new("setup-fixture".to_owned()), egress())
            .await?;
        assert_eq!(verified.account_uuid, account_uuid);
        assert_eq!(verified.organization_uuid, Some(organization_uuid));
        assert!(verified.refresh_token.is_none());
        assert!(verified.expires_after.is_none());
        let requests = http.requests.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[0].endpoint.path(), "/api/claude_cli/bootstrap");
        assert_eq!(requests[0].egress.egress_epoch, 3);
        assert_eq!(requests[0].headers[0].value.expose(), b"Bearer setup-fixture");
        assert_eq!(requests[0].headers[1].value.expose(), b"oauth-2025-04-20");
        assert_eq!(requests[0].headers[2].value.expose(), b"claude-code/2.1.220");
        Ok(())
    }

    #[tokio::test]
    async fn setup_token_requires_provider_verified_account_identity() -> Result<(), Box<dyn std::error::Error>> {
        for (status, body) in [
            (403, serde_json::json!({})),
            (200, serde_json::json!({"narrowed":true})),
        ] {
            let http = Arc::new(FakeHttp {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(vec![ProviderHttpResponse {
                    status,
                    headers: Vec::new(),
                    body: SecretBytes::new(serde_json::to_vec(&body)?),
                }]),
            });
            let adapter = SubscriptionEnrollmentAdapter::new(http, claude_code_subscription_profile())?;
            let error = adapter
                .verify_setup_token(SecretValue::new("setup-fixture".to_owned()), egress())
                .await
                .expect_err("identity-less setup token must be rejected");
            assert!(matches!(error, SetupTokenVerificationError::AccountIdentityUnavailable));
        }
        Ok(())
    }

    #[tokio::test]
    async fn setup_token_unauthorized_is_invalid_authentication() -> Result<(), Box<dyn std::error::Error>> {
        let http = Arc::new(FakeHttp {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(vec![ProviderHttpResponse {
                status: 401,
                headers: Vec::new(),
                body: SecretBytes::new(Vec::new()),
            }]),
        });
        let adapter = SubscriptionEnrollmentAdapter::new(http, claude_code_subscription_profile())?;
        let error = adapter
            .verify_setup_token(SecretValue::new("setup-fixture".to_owned()), egress())
            .await
            .expect_err("unauthorized setup token must be rejected");
        assert!(matches!(
            error,
            SetupTokenVerificationError::Provider(CredentialServiceError::InvalidAuthentication)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn token_exchange_parses_nested_account_and_uses_json_post() -> Result<(), Box<dyn std::error::Error>> {
        let account_uuid = Uuid::now_v7();
        let organization_uuid = Uuid::now_v7();
        let http = Arc::new(FakeHttp {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(vec![ProviderHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: SecretBytes::new(serde_json::to_vec(&serde_json::json!({
                    "access_token":"access-new",
                    "refresh_token":"refresh-new",
                    "token_type":"Bearer",
                    "expires_in":3600,
                    "account":{"uuid":account_uuid},
                    "organization":{"uuid":organization_uuid}
                }))?),
            }]),
        });
        let adapter = SubscriptionEnrollmentAdapter::new(http.clone(), claude_code_subscription_profile())?;
        let verified = adapter
            .exchange_authorization_code(
                &SecretValue::new("code".to_owned()),
                &SecretValue::new("state".to_owned()),
                &SecretValue::new("verifier".to_owned()),
                egress(),
            )
            .await?;
        assert_eq!(verified.account_uuid, account_uuid);
        assert_eq!(verified.expires_after, Some(Duration::from_hours(1)));
        let requests = http.requests.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(requests[0].method, Method::POST);
        assert_eq!(requests[0].endpoint.path(), "/v1/oauth/token");
        assert_eq!(requests[0].headers[0].value.expose(), b"application/json");
        Ok(())
    }
}
