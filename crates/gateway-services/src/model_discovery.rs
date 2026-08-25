//! Authoritative Anthropic Models API collector.
#![allow(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::{collections::BTreeSet, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gateway_domain::{EgressBindingId, EgressBindingSnapshot, EgressMode, ProxyEndpointId, SecretBytes};
use gateway_storage::{DiscoveredModel, ModelDiscoveryCommit, PgStorage};
use http::{Method, Uri};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    credential::CredentialServiceError,
    credential_provider::{ProviderHttpHeader, ProviderHttpPort, ProviderHttpRequest},
    security::{EnvelopeAad, EnvelopeService, LocalAesKeyProvider, SecretEnvelope},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelDiscoveryRetry {
    pub error_code: &'static str,
    pub retry_after_seconds: u32,
}

pub struct PgModelCatalogCollector {
    storage: Arc<PgStorage>,
    http: Arc<dyn ProviderHttpPort>,
}

impl PgModelCatalogCollector {
    #[must_use]
    pub fn new(storage: Arc<PgStorage>, http: Arc<dyn ProviderHttpPort>) -> Arc<Self> {
        Arc::new(Self { storage, http })
    }

    pub async fn execute(
        &self,
        source_credential_id: Uuid,
        expected_revision: i64,
        expected_token_version: i64,
        expected_binding_id: Uuid,
        expected_egress_epoch: i64,
        job_id: Uuid,
        job_generation: i64,
    ) -> Result<(), ModelDiscoveryRetry> {
        let material = self
            .load_material(
                source_credential_id,
                expected_revision,
                expected_token_version,
                expected_binding_id,
                expected_egress_epoch,
            )
            .await?;
        let mut cursor: Option<String> = None;
        let mut cursors = BTreeSet::new();
        let mut model_ids = BTreeSet::new();
        let mut models = Vec::new();
        let mut source_models = Vec::new();
        let mut page_count = 0_u32;
        loop {
            page_count = page_count.checked_add(1).ok_or_else(schema_retry)?;
            if page_count > 100 {
                return Err(schema_retry());
            }
            let endpoint = model_endpoint(cursor.as_deref()).map_err(|()| schema_retry())?;
            let response = self
                .http
                .execute(ProviderHttpRequest {
                    method: Method::GET,
                    endpoint,
                    headers: vec![
                        ProviderHttpHeader {
                            name: "x-api-key",
                            value: SecretBytes::new(material.api_key.expose().to_vec()),
                        },
                        ProviderHttpHeader {
                            name: "anthropic-version",
                            value: SecretBytes::new(b"2023-06-01".to_vec()),
                        },
                    ],
                    body: SecretBytes::new(Vec::new()),
                    response_limit: 1024 * 1024,
                    egress: material.egress.clone(),
                })
                .await
                .map_err(|error| provider_retry(&error))?;
            match response.status {
                200..=299 => {}
                429 => {
                    return Err(ModelDiscoveryRetry {
                        error_code: "model_discovery_rate_limited",
                        retry_after_seconds: retry_after(&response.headers).unwrap_or(60),
                    });
                }
                500..=599 => {
                    return Err(ModelDiscoveryRetry {
                        error_code: "model_discovery_provider_unavailable",
                        retry_after_seconds: 30,
                    });
                }
                401 | 403 => {
                    return Err(ModelDiscoveryRetry {
                        error_code: "model_discovery_authentication_rejected",
                        retry_after_seconds: 300,
                    });
                }
                _ => return Err(schema_retry()),
            }
            let page: ModelPage = serde_json::from_slice(response.body.expose()).map_err(|_| schema_retry())?;
            if page.data.len() > 1_000 {
                return Err(schema_retry());
            }
            for model in page.data {
                if model.model_type != "model"
                    || model.id.is_empty()
                    || model.id.len() > 256
                    || model.display_name.is_empty()
                    || model.display_name.len() > 256
                    || !model_ids.insert(model.id.clone())
                {
                    return Err(schema_retry());
                }
                if models.len() >= 10_000 {
                    return Err(schema_retry());
                }
                let canonical = json!({
                    "created_at":model.created_at,
                    "display_name":model.display_name,
                    "id":model.id,
                    "max_input_tokens":model.max_input_tokens,
                    "max_tokens":model.max_tokens,
                    "type":model.model_type,
                });
                let canonical_bytes = serde_json::to_vec(&canonical).map_err(|_| schema_retry())?;
                let content_digest = Sha256::digest(&canonical_bytes).to_vec();
                source_models.push(canonical);
                models.push(DiscoveredModel {
                    upstream_model_id: model.id,
                    display_name: model.display_name,
                    created_at: model.created_at.filter(|value| value.len() <= 64),
                    content_digest,
                });
            }
            if !page.has_more {
                break;
            }
            let next = page
                .last_id
                .filter(|value| !value.is_empty() && value.len() <= 256)
                .ok_or_else(schema_retry)?;
            if !cursors.insert(next.clone()) {
                return Err(schema_retry());
            }
            cursor = Some(next);
        }
        models.sort_by(|left, right| left.upstream_model_id.cmp(&right.upstream_model_id));
        source_models.sort_by(|left, right| {
            left.get("id")
                .and_then(Value::as_str)
                .cmp(&right.get("id").and_then(Value::as_str))
        });
        let source_digest = Sha256::digest(serde_json::to_vec(&source_models).map_err(|_| schema_retry())?).to_vec();
        self.storage
            .commit_model_discovery(&ModelDiscoveryCommit {
                run_id: Uuid::now_v7(),
                job_id,
                job_generation,
                source_credential_id,
                source_credential_revision: expected_revision,
                source_token_version: expected_token_version,
                source_egress_binding_id: expected_binding_id,
                source_egress_epoch: expected_egress_epoch,
                source_digest,
                sanitized_manifest: json!({"schema_version":1,"source":"anthropic_models_api",
                  "api_version":"2023-06-01","page_count":page_count,"item_count":models.len()}),
                models,
            })
            .await
            .map_err(|_| ModelDiscoveryRetry {
                error_code: "model_discovery_commit_failed",
                retry_after_seconds: 30,
            })
    }

    async fn load_material(
        &self,
        credential_id: Uuid,
        revision: i64,
        token_version: i64,
        binding_id: Uuid,
        egress_epoch: i64,
    ) -> Result<ModelSourceMaterial, ModelDiscoveryRetry> {
        let row = sqlx::query(
            "SELECT binding.mode_code,binding.proxy_id,secret.id AS secret_id,secret.secret_kind_code, \
                    secret.provider_role_code,secret.cipher_suite_code,secret.ciphertext,secret.nonce,secret.wrapped_dek, \
                    secret.key_version,secret.aad_schema_version,secret.owner_type_code,secret.owner_id,secret.purpose_code \
             FROM gateway.anthropic_credential credential \
             JOIN gateway.credential_auth_version auth ON auth.id=credential.active_auth_version_id \
               AND auth.credential_id=credential.id AND auth.material_state_code='active' \
             JOIN security.encrypted_secret secret ON secret.id=auth.console_secret_id \
               AND secret.secret_kind_code='console_api_key' AND secret.destroyed_at IS NULL AND secret.superseded_at IS NULL \
             JOIN gateway.credential_egress_binding binding ON binding.id=$4 AND binding.credential_id=credential.id \
               AND binding.lifecycle_code='active' AND binding.stability_code='stable' \
             WHERE credential.id=$1 AND credential.revision=$2 AND credential.token_version=$3 \
               AND auth.token_version=$3 AND credential.auth_kind_code='console_api_key' \
               AND binding.egress_epoch=$5 AND credential.lifecycle_state_code NOT IN ('revoked','archived')",
        )
        .bind(credential_id)
        .bind(revision)
        .bind(token_version)
        .bind(binding_id)
        .bind(egress_epoch)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| material_retry())?
        .ok_or_else(material_retry)?;
        let proxy_id: Option<Uuid> = row.try_get("proxy_id").map_err(|_| material_retry())?;
        let mode = match row
            .try_get::<String, _>("mode_code")
            .map_err(|_| material_retry())?
            .as_str()
        {
            "direct" if proxy_id.is_none() => EgressMode::Direct,
            "proxy" if proxy_id.is_some() => EgressMode::Proxy,
            _ => return Err(material_retry()),
        };
        let api_key = decrypt_console_secret(&self.storage, &row, credential_id).await?;
        Ok(ModelSourceMaterial {
            api_key,
            egress: EgressBindingSnapshot {
                binding_id: EgressBindingId::new(binding_id.to_string()).map_err(|_| material_retry())?,
                mode,
                proxy_id: proxy_id
                    .map(|id| ProxyEndpointId::new(id.to_string()).map_err(|_| material_retry()))
                    .transpose()?,
                egress_epoch: u64::try_from(egress_epoch).map_err(|_| material_retry())?,
            },
        })
    }
}

struct ModelSourceMaterial {
    api_key: SecretBytes,
    egress: EgressBindingSnapshot,
}

#[derive(Deserialize)]
struct ModelPage {
    data: Vec<ModelDocument>,
    has_more: bool,
    last_id: Option<String>,
}

#[derive(Deserialize)]
struct ModelDocument {
    id: String,
    #[serde(rename = "type")]
    model_type: String,
    display_name: String,
    created_at: Option<String>,
    max_input_tokens: Option<u64>,
    max_tokens: Option<u64>,
}

async fn decrypt_console_secret(
    storage: &PgStorage,
    row: &sqlx::postgres::PgRow,
    credential_id: Uuid,
) -> Result<SecretBytes, ModelDiscoveryRetry> {
    let owner_type: String = row.try_get("owner_type_code").map_err(|_| material_retry())?;
    let owner_id: String = row.try_get("owner_id").map_err(|_| material_retry())?;
    let purpose: String = row.try_get("purpose_code").map_err(|_| material_retry())?;
    let provider_role: String = row.try_get("provider_role_code").map_err(|_| material_retry())?;
    if owner_type != "credential"
        || owner_id != credential_id.to_string()
        || purpose != "anthropic_auth"
        || provider_role != "business"
    {
        return Err(material_retry());
    }
    let key_version: i64 = row.try_get("key_version").map_err(|_| material_retry())?;
    let key = storage
        .load_database_business_key(key_version)
        .await
        .map_err(|_| material_retry())?;
    let schema_version = u32::try_from(
        row.try_get::<i32, _>("aad_schema_version")
            .map_err(|_| material_retry())?,
    )
    .map_err(|_| material_retry())?;
    let aad = EnvelopeAad {
        schema_version,
        secret_id: row.try_get("secret_id").map_err(|_| material_retry())?,
        secret_kind: "console_api_key".to_owned(),
        provider_role,
        owner_type,
        owner_id,
        purpose,
        key_version: u64::try_from(key_version).map_err(|_| material_retry())?,
    };
    let envelope = SecretEnvelope {
        schema_version,
        cipher_suite: row.try_get("cipher_suite_code").map_err(|_| material_retry())?,
        provider_role: aad.provider_role.clone(),
        key_version: aad.key_version,
        ciphertext_base64: STANDARD.encode(row.try_get::<Vec<u8>, _>("ciphertext").map_err(|_| material_retry())?),
        nonce_base64: STANDARD.encode(row.try_get::<Vec<u8>, _>("nonce").map_err(|_| material_retry())?),
        wrapped_dek_base64: STANDARD.encode(row.try_get::<Vec<u8>, _>("wrapped_dek").map_err(|_| material_retry())?),
    };
    let provider =
        LocalAesKeyProvider::new("business", aad.key_version, key.expose().to_vec()).map_err(|_| material_retry())?;
    EnvelopeService::new(provider)
        .decrypt(&envelope, &aad)
        .map_err(|_| material_retry())
}

fn model_endpoint(after_id: Option<&str>) -> Result<Uri, ()> {
    let mut value = "https://api.anthropic.com/v1/models?limit=1000".to_owned();
    if let Some(after_id) = after_id {
        value.push_str("&after_id=");
        percent_encode(&mut value, after_id.as_bytes());
    }
    value.parse().map_err(|_| ())
}

fn percent_encode(output: &mut String, value: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                output.push(char::from(*byte));
            }
            _ => {
                output.push('%');
                output.push(char::from(HEX[usize::from(byte >> 4)]));
                output.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
}

fn provider_retry(error: &CredentialServiceError) -> ModelDiscoveryRetry {
    match error {
        CredentialServiceError::RateLimited(duration) => ModelDiscoveryRetry {
            error_code: "model_discovery_rate_limited",
            retry_after_seconds: u32::try_from(duration.as_secs().clamp(1, 900)).unwrap_or(900),
        },
        CredentialServiceError::WaitingEgress => ModelDiscoveryRetry {
            error_code: "model_discovery_waiting_egress",
            retry_after_seconds: 30,
        },
        _ => ModelDiscoveryRetry {
            error_code: "model_discovery_transport_failed",
            retry_after_seconds: 30,
        },
    }
}

fn material_retry() -> ModelDiscoveryRetry {
    ModelDiscoveryRetry {
        error_code: "model_discovery_source_changed",
        retry_after_seconds: 30,
    }
}

fn schema_retry() -> ModelDiscoveryRetry {
    ModelDiscoveryRetry {
        error_code: "model_discovery_schema_invalid",
        retry_after_seconds: 300,
    }
}

fn retry_after(headers: &[(Box<str>, Box<[u8]>)]) -> Option<u32> {
    let values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return None;
    }
    std::str::from_utf8(&values[0].1)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
        .map(|seconds| seconds.clamp(1, 900))
}
