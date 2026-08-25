//! Credential PLAN collection through frozen provider and Egress snapshots.
#![allow(missing_docs, clippy::missing_errors_doc, clippy::too_many_lines)]

use std::{collections::BTreeMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gateway_domain::{EgressBindingId, EgressBindingSnapshot, EgressMode, ProxyEndpointId, SecretBytes};
use gateway_storage::{PgStorage, PlanObservationCommit, PlanObservationFence};
use http::{Method, Uri};
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
pub struct PlanCollectionRetry {
    pub error_code: &'static str,
    pub retry_after_seconds: u32,
}

pub struct PgPlanCollector {
    storage: Arc<PgStorage>,
    http: Arc<dyn ProviderHttpPort>,
}

impl PgPlanCollector {
    #[must_use]
    pub fn new(storage: Arc<PgStorage>, http: Arc<dyn ProviderHttpPort>) -> Arc<Self> {
        Arc::new(Self { storage, http })
    }

    pub async fn execute(
        &self,
        credential_id: Uuid,
        expected_revision: i64,
        job_id: Uuid,
        job_generation: i64,
    ) -> Result<(), PlanCollectionRetry> {
        let material = self
            .load_material(credential_id, expected_revision, job_id, job_generation)
            .await
            .map_err(|error_code| PlanCollectionRetry {
                error_code,
                retry_after_seconds: 30,
            })?;
        let mut authorization = Vec::with_capacity(material.access_token.expose().len() + 7);
        authorization.extend_from_slice(b"Bearer ");
        authorization.extend_from_slice(material.access_token.expose());
        let mut headers = vec![ProviderHttpHeader {
            name: "authorization",
            value: SecretBytes::new(authorization),
        }];
        if material.source == "oauth_profile" {
            headers.push(ProviderHttpHeader {
                name: "cache-control",
                value: SecretBytes::new(b"no-cache".to_vec()),
            });
        } else {
            headers.push(ProviderHttpHeader {
                name: "anthropic-beta",
                value: SecretBytes::new(b"oauth-2025-04-20".to_vec()),
            });
            headers.push(ProviderHttpHeader {
                name: "user-agent",
                value: SecretBytes::new(b"claude-code/2.1.220".to_vec()),
            });
        }
        let response = self
            .http
            .execute(ProviderHttpRequest {
                method: Method::GET,
                endpoint: material.endpoint.clone(),
                headers,
                body: SecretBytes::new(Vec::new()),
                response_limit: material.max_response_bytes,
                egress: material.egress.clone(),
            })
            .await;
        let response = match response {
            Ok(response) => response,
            Err(CredentialServiceError::RateLimited(duration)) => {
                return Err(PlanCollectionRetry {
                    error_code: "credential_plan_rate_limited",
                    retry_after_seconds: u32::try_from(duration.as_secs().clamp(1, 900)).unwrap_or(900),
                });
            }
            Err(CredentialServiceError::WaitingEgress) => {
                return Err(PlanCollectionRetry {
                    error_code: "credential_plan_waiting_egress",
                    retry_after_seconds: 30,
                });
            }
            Err(_) => {
                return Err(PlanCollectionRetry {
                    error_code: "credential_plan_transport_failed",
                    retry_after_seconds: 30,
                });
            }
        };
        match response.status {
            200..=299 => {}
            429 => {
                return Err(PlanCollectionRetry {
                    error_code: "credential_plan_rate_limited",
                    retry_after_seconds: retry_after(&response.headers).unwrap_or(60),
                });
            }
            500..=599 => {
                return Err(PlanCollectionRetry {
                    error_code: "credential_plan_provider_unavailable",
                    retry_after_seconds: 30,
                });
            }
            401 | 403 => {
                return self
                    .commit_failure(&material, "authentication_rejected")
                    .await
                    .map_err(storage_retry);
            }
            404 => {
                return self
                    .commit_failure(&material, "provider_endpoint_not_found")
                    .await
                    .map_err(storage_retry);
            }
            _ => {
                return self
                    .commit_failure(&material, "provider_response_rejected")
                    .await
                    .map_err(storage_retry);
            }
        }
        let document: Value = match serde_json::from_slice(response.body.expose()) {
            Ok(document) => document,
            Err(_) => {
                return self
                    .commit_failure(&material, "provider_schema_changed")
                    .await
                    .map_err(storage_retry);
            }
        };
        let Some(redacted) = plan_fields(&document) else {
            return self
                .commit_failure(&material, "provider_schema_changed")
                .await
                .map_err(storage_retry);
        };
        let canonical = serde_json::to_vec(&redacted).map_err(|_| PlanCollectionRetry {
            error_code: "credential_plan_canonicalization_failed",
            retry_after_seconds: 30,
        })?;
        let digest = Sha256::digest(&canonical).to_vec();
        let raw_plan_code = format!("v1:sha256:{}", lower_hex(&digest));
        let mapping = sqlx::query(
            "SELECT artifact.id,artifact.artifact_version,artifact.payload->'mappings'->>$1 AS normalized \
             FROM catalog.active_artifact_pointer pointer \
             JOIN catalog.versioned_artifact artifact ON artifact.id=pointer.artifact_id \
             WHERE pointer.artifact_kind_code='plan_mapping' AND pointer.scope_type_code IS NULL \
               AND artifact.artifact_kind_code='plan_mapping' AND artifact.lifecycle_code='active'",
        )
        .bind(&raw_plan_code)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| PlanCollectionRetry {
            error_code: "credential_plan_mapping_load_failed",
            retry_after_seconds: 30,
        })?;
        let mapping_artifact_id = mapping.as_ref().and_then(|row| row.try_get::<Uuid, _>("id").ok());
        let mapping_version = mapping
            .as_ref()
            .and_then(|row| row.try_get::<i64, _>("artifact_version").ok());
        let normalized = mapping
            .as_ref()
            .and_then(|row| row.try_get::<Option<String>, _>("normalized").ok().flatten())
            .unwrap_or_else(|| "unknown".to_owned());
        let temporary_display_name = display_plan(&redacted);
        self.storage
            .commit_plan_observation_with_job(
                &PlanObservationCommit {
                    observation_id: Uuid::now_v7(),
                    credential_id,
                    source: material.source.to_owned(),
                    raw_plan_code: Some(raw_plan_code),
                    normalized_plan_code: normalized,
                    raw_redacted: redacted,
                    raw_digest: Some(digest),
                    temporary_display_name,
                    mapping_version,
                    mapping_artifact_id,
                    adapter_version: Some(material.adapter_version.clone()),
                    success: true,
                    failure_category: None,
                    failure_summary: None,
                },
                &material.fence,
            )
            .await
            .map_err(storage_retry)
    }

    pub async fn finish_failure(
        &self,
        credential_id: Uuid,
        expected_revision: i64,
        job_id: Uuid,
        job_generation: i64,
        category: &str,
    ) -> Result<(), PlanCollectionRetry> {
        let material = self
            .load_material(credential_id, expected_revision, job_id, job_generation)
            .await
            .map_err(|error_code| PlanCollectionRetry {
                error_code,
                retry_after_seconds: 30,
            })?;
        self.commit_failure(&material, category).await.map_err(storage_retry)
    }

    async fn commit_failure(
        &self,
        material: &PlanMaterial,
        category: &str,
    ) -> Result<(), gateway_storage::StorageError> {
        self.storage
            .commit_plan_observation_with_job(
                &PlanObservationCommit {
                    observation_id: Uuid::now_v7(),
                    credential_id: material.credential_id,
                    source: material.source.to_owned(),
                    raw_plan_code: None,
                    normalized_plan_code: "unknown".to_owned(),
                    raw_redacted: json!({}),
                    raw_digest: None,
                    temporary_display_name: None,
                    mapping_version: None,
                    mapping_artifact_id: None,
                    adapter_version: Some(material.adapter_version.clone()),
                    success: false,
                    failure_category: Some(category.to_owned()),
                    failure_summary: Some(category.to_owned()),
                },
                &material.fence,
            )
            .await
    }

    async fn load_material(
        &self,
        credential_id: Uuid,
        expected_revision: i64,
        job_id: Uuid,
        job_generation: i64,
    ) -> Result<PlanMaterial, &'static str> {
        let row = sqlx::query(
            "SELECT credential.revision,credential.token_version,credential.auth_kind_code,credential.provider_profile_id, \
                    auth.access_secret_id,binding.id AS binding_id,binding.mode_code,binding.proxy_id,binding.egress_epoch, \
                    provider.profile_code,provider.profile_version,provider.evidence_version,provider.profile_endpoint, \
                    provider.bootstrap_endpoint,provider.max_response_bytes,secret.id AS secret_id,secret.secret_kind_code, \
                    secret.provider_role_code,secret.cipher_suite_code,secret.ciphertext,secret.nonce,secret.wrapped_dek, \
                    secret.key_version,secret.aad_schema_version,secret.owner_type_code,secret.owner_id,secret.purpose_code \
             FROM gateway.anthropic_credential credential \
             JOIN gateway.credential_auth_version auth ON auth.id=credential.active_auth_version_id \
               AND auth.credential_id=credential.id AND auth.material_state_code='active' \
             JOIN security.encrypted_secret secret ON secret.id=auth.access_secret_id \
               AND secret.destroyed_at IS NULL AND secret.superseded_at IS NULL \
             JOIN gateway.credential_egress_binding binding ON binding.credential_id=credential.id \
               AND binding.lifecycle_code='active' AND binding.stability_code='stable' \
             JOIN gateway.credential_provider_profile provider ON provider.id=credential.provider_profile_id \
               AND provider.lifecycle_code='active' AND provider.auth_kind_codes ? credential.auth_kind_code \
             WHERE credential.id=$1 AND credential.revision=$2 \
               AND credential.lifecycle_state_code NOT IN ('revoked','archived') \
               AND credential.auth_kind_code IN ('oauth_subscription','setup_token_subscription')",
        )
        .bind(credential_id)
        .bind(expected_revision)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| "credential_plan_snapshot_load_failed")?
        .ok_or("credential_plan_snapshot_changed")?;
        let auth_kind: String = row
            .try_get("auth_kind_code")
            .map_err(|_| "credential_plan_snapshot_invalid")?;
        let source = match auth_kind.as_str() {
            "oauth_subscription" => "oauth_profile",
            "setup_token_subscription" => "claude_cli_bootstrap",
            _ => return Err("credential_plan_not_applicable"),
        };
        let secret_kind: String = row
            .try_get("secret_kind_code")
            .map_err(|_| "credential_plan_secret_invalid")?;
        if (source == "oauth_profile" && secret_kind != "oauth_access_token")
            || (source == "claude_cli_bootstrap" && secret_kind != "setup_token")
        {
            return Err("credential_plan_secret_invalid");
        }
        let access_token = decrypt_secret(&self.storage, &row, credential_id).await?;
        let binding_id: Uuid = row
            .try_get("binding_id")
            .map_err(|_| "credential_plan_snapshot_invalid")?;
        let proxy_id: Option<Uuid> = row
            .try_get("proxy_id")
            .map_err(|_| "credential_plan_snapshot_invalid")?;
        let mode = match row
            .try_get::<String, _>("mode_code")
            .map_err(|_| "credential_plan_snapshot_invalid")?
            .as_str()
        {
            "direct" if proxy_id.is_none() => EgressMode::Direct,
            "proxy" if proxy_id.is_some() => EgressMode::Proxy,
            _ => return Err("credential_plan_egress_invalid"),
        };
        let egress_epoch: i64 = row
            .try_get("egress_epoch")
            .map_err(|_| "credential_plan_snapshot_invalid")?;
        let provider_profile_id: Uuid = row
            .try_get("provider_profile_id")
            .map_err(|_| "credential_plan_snapshot_invalid")?;
        let endpoint = row
            .try_get::<String, _>(if source == "oauth_profile" {
                "profile_endpoint"
            } else {
                "bootstrap_endpoint"
            })
            .map_err(|_| "credential_plan_provider_profile_invalid")?
            .parse::<Uri>()
            .map_err(|_| "credential_plan_provider_profile_invalid")?;
        let profile_code: String = row
            .try_get("profile_code")
            .map_err(|_| "credential_plan_provider_profile_invalid")?;
        let profile_version: i64 = row
            .try_get("profile_version")
            .map_err(|_| "credential_plan_provider_profile_invalid")?;
        let evidence: String = row
            .try_get("evidence_version")
            .map_err(|_| "credential_plan_provider_profile_invalid")?;
        let token_version: i64 = row
            .try_get("token_version")
            .map_err(|_| "credential_plan_snapshot_invalid")?;
        Ok(PlanMaterial {
            credential_id,
            source,
            endpoint,
            max_response_bytes: usize::try_from(
                row.try_get::<i32, _>("max_response_bytes")
                    .map_err(|_| "credential_plan_provider_profile_invalid")?,
            )
            .map_err(|_| "credential_plan_provider_profile_invalid")?,
            adapter_version: format!("{profile_code}-v{profile_version}:{evidence}"),
            access_token,
            egress: EgressBindingSnapshot {
                binding_id: EgressBindingId::new(binding_id.to_string())
                    .map_err(|_| "credential_plan_snapshot_invalid")?,
                mode,
                proxy_id: proxy_id
                    .map(|id| ProxyEndpointId::new(id.to_string()).map_err(|_| "credential_plan_snapshot_invalid"))
                    .transpose()?,
                egress_epoch: u64::try_from(egress_epoch).map_err(|_| "credential_plan_snapshot_invalid")?,
            },
            fence: PlanObservationFence {
                credential_revision: expected_revision,
                token_version,
                provider_profile_id,
                egress_binding_id: binding_id,
                egress_epoch,
                job_id,
                job_generation,
            },
        })
    }
}

struct PlanMaterial {
    credential_id: Uuid,
    source: &'static str,
    endpoint: Uri,
    max_response_bytes: usize,
    adapter_version: String,
    access_token: SecretBytes,
    egress: EgressBindingSnapshot,
    fence: PlanObservationFence,
}

async fn decrypt_secret(
    storage: &PgStorage,
    row: &sqlx::postgres::PgRow,
    credential_id: Uuid,
) -> Result<SecretBytes, &'static str> {
    let owner_type: String = row
        .try_get("owner_type_code")
        .map_err(|_| "credential_plan_secret_invalid")?;
    let owner_id: String = row.try_get("owner_id").map_err(|_| "credential_plan_secret_invalid")?;
    let purpose: String = row
        .try_get("purpose_code")
        .map_err(|_| "credential_plan_secret_invalid")?;
    let provider_role: String = row
        .try_get("provider_role_code")
        .map_err(|_| "credential_plan_secret_invalid")?;
    if owner_type != "credential"
        || owner_id != credential_id.to_string()
        || purpose != "anthropic_auth"
        || provider_role != "business"
    {
        return Err("credential_plan_secret_invalid");
    }
    let key_version: i64 = row
        .try_get("key_version")
        .map_err(|_| "credential_plan_secret_invalid")?;
    let key = storage
        .load_database_business_key(key_version)
        .await
        .map_err(|_| "credential_plan_key_unavailable")?;
    let schema_version = u32::try_from(
        row.try_get::<i32, _>("aad_schema_version")
            .map_err(|_| "credential_plan_secret_invalid")?,
    )
    .map_err(|_| "credential_plan_secret_invalid")?;
    let aad = EnvelopeAad {
        schema_version,
        secret_id: row.try_get("secret_id").map_err(|_| "credential_plan_secret_invalid")?,
        secret_kind: row
            .try_get("secret_kind_code")
            .map_err(|_| "credential_plan_secret_invalid")?,
        provider_role,
        owner_type,
        owner_id,
        purpose,
        key_version: u64::try_from(key_version).map_err(|_| "credential_plan_secret_invalid")?,
    };
    let envelope = SecretEnvelope {
        schema_version,
        cipher_suite: row
            .try_get("cipher_suite_code")
            .map_err(|_| "credential_plan_secret_invalid")?,
        provider_role: aad.provider_role.clone(),
        key_version: aad.key_version,
        ciphertext_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("ciphertext")
                .map_err(|_| "credential_plan_secret_invalid")?,
        ),
        nonce_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("nonce")
                .map_err(|_| "credential_plan_secret_invalid")?,
        ),
        wrapped_dek_base64: STANDARD.encode(
            row.try_get::<Vec<u8>, _>("wrapped_dek")
                .map_err(|_| "credential_plan_secret_invalid")?,
        ),
    };
    let provider = LocalAesKeyProvider::new("business", aad.key_version, key.expose().to_vec())
        .map_err(|_| "credential_plan_key_unavailable")?;
    EnvelopeService::new(provider)
        .decrypt(&envelope, &aad)
        .map_err(|_| "credential_plan_secret_invalid")
}

fn plan_fields(document: &Value) -> Option<Value> {
    const KEYS: [&str; 8] = [
        "organization_type",
        "rate_limit_tier",
        "seat_tier",
        "billing_type",
        "has_extra_usage_enabled",
        "subscription_type",
        "plan_type",
        "plan",
    ];
    let mut fields = BTreeMap::new();
    for key in KEYS {
        if let Some(value) = find_scalar(document, key) {
            fields.insert(key.to_owned(), value.clone());
        }
    }
    (!fields.is_empty())
        .then(|| serde_json::to_value(fields).ok())
        .flatten()
}

fn find_scalar<'a>(document: &'a Value, key: &str) -> Option<&'a Value> {
    let object = document.as_object()?;
    object
        .get(key)
        .filter(|value| value.is_string() || value.is_boolean() || value.is_number())
        .or_else(|| {
            ["organization", "account", "oauth_account"]
                .into_iter()
                .filter_map(|container| object.get(container).and_then(Value::as_object))
                .find_map(|nested| {
                    nested
                        .get(key)
                        .filter(|value| value.is_string() || value.is_boolean() || value.is_number())
                })
        })
}

fn display_plan(redacted: &Value) -> Option<String> {
    [
        "subscription_type",
        "rate_limit_tier",
        "seat_tier",
        "plan_type",
        "plan",
        "organization_type",
    ]
    .into_iter()
    .find_map(|key| redacted.get(key).and_then(Value::as_str))
    .filter(|value| !value.trim().is_empty() && value.len() <= 128)
    .map(str::to_owned)
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

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn storage_retry(_: gateway_storage::StorageError) -> PlanCollectionRetry {
    PlanCollectionRetry {
        error_code: "credential_plan_commit_failed",
        retry_after_seconds: 30,
    }
}
