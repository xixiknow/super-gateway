//! Production provider HTTPS adapter with frozen Credential Egress resolution.

use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gateway_domain::{EgressMode, EgressRouteSnapshot, ProxyCredentials, SecretBytes, SecretValue, Socks5DnsMode};
use gateway_services::{
    credential::CredentialServiceError,
    credential_provider::{ProviderHttpPort, ProviderHttpRequest, ProviderHttpResponse},
    security::{EnvelopeAad, EnvelopeService, LocalAesKeyProvider, SecretEnvelope},
};
use gateway_storage::PgStorage;
use gateway_transport::{ProviderHttpsClient, ProviderHttpsHeader, ProviderHttpsRequest};
use serde::Deserialize;
use sqlx::Row as _;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug)]
pub(crate) struct PgProviderHttpPort {
    storage: Arc<PgStorage>,
    client: ProviderHttpsClient,
}

impl PgProviderHttpPort {
    pub(crate) fn new(storage: Arc<PgStorage>) -> Arc<Self> {
        Arc::new(Self {
            storage,
            client: ProviderHttpsClient::default(),
        })
    }
}

#[async_trait]
impl crate::managed_browser::ManagedBrowserEgressResolver for PgProviderHttpPort {
    async fn resolve(
        &self,
        snapshot: &gateway_domain::EgressBindingSnapshot,
    ) -> Result<EgressRouteSnapshot, CredentialServiceError> {
        resolve_egress(&self.storage, snapshot).await
    }
}

#[async_trait]
impl ProviderHttpPort for PgProviderHttpPort {
    async fn execute(&self, request: ProviderHttpRequest) -> Result<ProviderHttpResponse, CredentialServiceError> {
        let route = resolve_egress(&self.storage, &request.egress).await?;
        let proxied = !matches!(route, EgressRouteSnapshot::Direct);
        let host = request
            .endpoint
            .host()
            .filter(|host| !host.is_empty())
            .ok_or(CredentialServiceError::EvidencePending)?;
        let port = request.endpoint.port_u16().unwrap_or(443);
        let authority = request
            .endpoint
            .authority()
            .ok_or(CredentialServiceError::EvidencePending)?
            .as_str();
        let path_and_query = request
            .endpoint
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        let response = self
            .client
            .execute(ProviderHttpsRequest {
                method: request.method,
                host: host.to_owned().into_boxed_str(),
                port,
                host_header: authority.to_owned().into_boxed_str(),
                path_and_query: SecretValue::new(path_and_query.to_owned()),
                headers: request
                    .headers
                    .into_iter()
                    .map(|header| ProviderHttpsHeader {
                        name: header.name,
                        value: header.value,
                    })
                    .collect(),
                body: request.body,
                response_limit: request.response_limit,
                egress: route,
                cancellation: CancellationToken::new(),
            })
            .await
            .map_err(|_| {
                if proxied {
                    CredentialServiceError::WaitingEgress
                } else {
                    CredentialServiceError::Transient
                }
            })?;
        Ok(ProviderHttpResponse {
            status: response.status,
            headers: response
                .retry_after
                .into_iter()
                .map(|value| ("retry-after".into(), value))
                .collect(),
            body: response.body,
        })
    }
}

pub(crate) async fn resolve_egress(
    storage: &PgStorage,
    snapshot: &gateway_domain::EgressBindingSnapshot,
) -> Result<EgressRouteSnapshot, CredentialServiceError> {
    let binding_id =
        Uuid::parse_str(snapshot.binding_id.as_str()).map_err(|_| CredentialServiceError::WaitingEgress)?;
    let expected_proxy = snapshot
        .proxy_id
        .as_ref()
        .map(|id| Uuid::parse_str(id.as_str()).map_err(|_| CredentialServiceError::WaitingEgress))
        .transpose()?;
    let row = sqlx::query(
        "SELECT b.mode_code,b.proxy_id,p.proxy_type_code,p.host,p.port,p.auth_secret_id \
         FROM gateway.credential_egress_binding b \
         LEFT JOIN gateway.proxy_endpoint p ON p.id=b.proxy_id AND p.lifecycle_code='active' \
              AND p.health_code='healthy' AND p.stability_code='static' \
         WHERE b.id=$1 AND b.egress_epoch=$2 AND b.lifecycle_code='active' AND b.stability_code='stable'",
    )
    .bind(binding_id)
    .bind(i64::try_from(snapshot.egress_epoch).map_err(|_| CredentialServiceError::WaitingEgress)?)
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| CredentialServiceError::Transient)?
    .ok_or(CredentialServiceError::WaitingEgress)?;
    let mode: String = row
        .try_get("mode_code")
        .map_err(|_| CredentialServiceError::Transient)?;
    let proxy_id: Option<Uuid> = row.try_get("proxy_id").map_err(|_| CredentialServiceError::Transient)?;
    if proxy_id != expected_proxy
        || (snapshot.mode == EgressMode::Direct) != (mode == "direct")
        || (mode == "direct") != proxy_id.is_none()
    {
        return Err(CredentialServiceError::WaitingEgress);
    }
    if mode == "direct" {
        return Ok(EgressRouteSnapshot::Direct);
    }
    let host = row
        .try_get::<Option<String>, _>("host")
        .map_err(|_| CredentialServiceError::Transient)?
        .ok_or(CredentialServiceError::WaitingEgress)?;
    let port = u16::try_from(
        row.try_get::<Option<i32>, _>("port")
            .map_err(|_| CredentialServiceError::Transient)?
            .ok_or(CredentialServiceError::WaitingEgress)?,
    )
    .map_err(|_| CredentialServiceError::WaitingEgress)?;
    let credentials = row
        .try_get::<Option<Uuid>, _>("auth_secret_id")
        .map_err(|_| CredentialServiceError::Transient)?
        .map(|secret_id| async move {
            let secret = decrypt_secret(
                storage,
                secret_id,
                "proxy_endpoint",
                &proxy_id.ok_or(CredentialServiceError::WaitingEgress)?.to_string(),
                "proxy_authentication",
            )
            .await?;
            parse_proxy_credentials(&secret).map(Arc::new)
        });
    let credentials = match credentials {
        Some(future) => Some(future.await?),
        None => None,
    };
    match row
        .try_get::<Option<String>, _>("proxy_type_code")
        .map_err(|_| CredentialServiceError::Transient)?
        .as_deref()
    {
        Some("http_connect") => Ok(EgressRouteSnapshot::HttpConnect {
            host: host.into_boxed_str(),
            port,
            credentials,
        }),
        Some("socks5") => Ok(EgressRouteSnapshot::Socks5 {
            host: host.into_boxed_str(),
            port,
            dns: Socks5DnsMode::Remote,
            credentials,
        }),
        _ => Err(CredentialServiceError::WaitingEgress),
    }
}

async fn decrypt_secret(
    storage: &PgStorage,
    secret_id: Uuid,
    expected_owner_type: &str,
    expected_owner_id: &str,
    expected_purpose: &str,
) -> Result<SecretBytes, CredentialServiceError> {
    let row = sqlx::query(
        "SELECT secret_kind_code,provider_role_code,cipher_suite_code,ciphertext,nonce,wrapped_dek,key_version, \
                aad_schema_version,owner_type_code,owner_id,purpose_code \
         FROM security.encrypted_secret WHERE id=$1 AND destroyed_at IS NULL AND superseded_at IS NULL",
    )
    .bind(secret_id)
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| CredentialServiceError::Transient)?
    .ok_or(CredentialServiceError::WaitingEgress)?;
    if row
        .try_get::<String, _>("secret_kind_code")
        .map_err(|_| CredentialServiceError::Transient)?
        != "proxy_password"
        || row
            .try_get::<String, _>("owner_type_code")
            .map_err(|_| CredentialServiceError::Transient)?
            != expected_owner_type
        || row
            .try_get::<String, _>("owner_id")
            .map_err(|_| CredentialServiceError::Transient)?
            != expected_owner_id
        || row
            .try_get::<String, _>("purpose_code")
            .map_err(|_| CredentialServiceError::Transient)?
            != expected_purpose
    {
        return Err(CredentialServiceError::WaitingEgress);
    }
    let key_version: i64 = row
        .try_get("key_version")
        .map_err(|_| CredentialServiceError::Transient)?;
    let key = storage
        .load_database_business_key(key_version)
        .await
        .map_err(|_| CredentialServiceError::Transient)?;
    let key_version = u64::try_from(key_version).map_err(|_| CredentialServiceError::Transient)?;
    let schema_version = u32::try_from(
        row.try_get::<i32, _>("aad_schema_version")
            .map_err(|_| CredentialServiceError::Transient)?,
    )
    .map_err(|_| CredentialServiceError::Transient)?;
    let aad = EnvelopeAad {
        schema_version,
        secret_id,
        secret_kind: row
            .try_get("secret_kind_code")
            .map_err(|_| CredentialServiceError::Transient)?,
        provider_role: row
            .try_get("provider_role_code")
            .map_err(|_| CredentialServiceError::Transient)?,
        owner_type: row
            .try_get("owner_type_code")
            .map_err(|_| CredentialServiceError::Transient)?,
        owner_id: row.try_get("owner_id").map_err(|_| CredentialServiceError::Transient)?,
        purpose: row
            .try_get("purpose_code")
            .map_err(|_| CredentialServiceError::Transient)?,
        key_version,
    };
    let envelope = SecretEnvelope {
        schema_version,
        cipher_suite: row
            .try_get("cipher_suite_code")
            .map_err(|_| CredentialServiceError::Transient)?,
        provider_role: aad.provider_role.clone(),
        key_version,
        ciphertext_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("ciphertext")
                .map_err(|_| CredentialServiceError::Transient)?,
        ),
        nonce_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("nonce")
                .map_err(|_| CredentialServiceError::Transient)?,
        ),
        wrapped_dek_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("wrapped_dek")
                .map_err(|_| CredentialServiceError::Transient)?,
        ),
    };
    let provider = LocalAesKeyProvider::new("business", key_version, key.expose().to_vec())
        .map_err(|_| CredentialServiceError::Transient)?;
    EnvelopeService::new(provider)
        .decrypt(&envelope, &aad)
        .map_err(|_| CredentialServiceError::WaitingEgress)
}

pub(crate) async fn resolve_proxy_route(
    storage: &PgStorage,
    proxy_id: Uuid,
) -> Result<EgressRouteSnapshot, CredentialServiceError> {
    let row = sqlx::query(
        "SELECT proxy_type_code,host,port,auth_secret_id FROM gateway.proxy_endpoint \
         WHERE id=$1 AND lifecycle_code IN ('active','disabled') AND stability_code='static'",
    )
    .bind(proxy_id)
    .fetch_optional(&storage.pool())
    .await
    .map_err(|_| CredentialServiceError::Transient)?
    .ok_or(CredentialServiceError::WaitingEgress)?;
    let host: String = row.try_get("host").map_err(|_| CredentialServiceError::Transient)?;
    let port = u16::try_from(
        row.try_get::<i32, _>("port")
            .map_err(|_| CredentialServiceError::Transient)?,
    )
    .map_err(|_| CredentialServiceError::WaitingEgress)?;
    let credentials = match row
        .try_get::<Option<Uuid>, _>("auth_secret_id")
        .map_err(|_| CredentialServiceError::Transient)?
    {
        Some(secret_id) => {
            let secret = decrypt_secret(
                storage,
                secret_id,
                "proxy_endpoint",
                &proxy_id.to_string(),
                "proxy_authentication",
            )
            .await?;
            Some(Arc::new(parse_proxy_credentials(&secret)?))
        }
        None => None,
    };
    match row
        .try_get::<String, _>("proxy_type_code")
        .map_err(|_| CredentialServiceError::Transient)?
        .as_str()
    {
        "http_connect" => Ok(EgressRouteSnapshot::HttpConnect {
            host: host.into_boxed_str(),
            port,
            credentials,
        }),
        "socks5" => Ok(EgressRouteSnapshot::Socks5 {
            host: host.into_boxed_str(),
            port,
            dns: Socks5DnsMode::Remote,
            credentials,
        }),
        _ => Err(CredentialServiceError::WaitingEgress),
    }
}

#[derive(Deserialize)]
struct ProxySecretDocument {
    username: String,
    password: String,
}

fn parse_proxy_credentials(secret: &SecretBytes) -> Result<ProxyCredentials, CredentialServiceError> {
    let text = std::str::from_utf8(secret.expose()).map_err(|_| CredentialServiceError::WaitingEgress)?;
    let (username, password) = if let Ok(document) = serde_json::from_str::<ProxySecretDocument>(text) {
        (document.username, document.password)
    } else {
        let (username, password) = text.split_once(':').ok_or(CredentialServiceError::WaitingEgress)?;
        (username.to_owned(), password.to_owned())
    };
    if username.is_empty() || username.contains(['\r', '\n']) || password.contains(['\r', '\n']) {
        return Err(CredentialServiceError::WaitingEgress);
    }
    Ok(ProxyCredentials {
        username: SecretValue::new(username),
        password: SecretValue::new(password),
    })
}
