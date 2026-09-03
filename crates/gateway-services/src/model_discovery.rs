//! Anthropic model catalog collector with public-directory bootstrap and credential verification.
#![allow(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use gateway_domain::{EgressBindingId, EgressBindingSnapshot, EgressMode, ProxyEndpointId, SecretBytes};
use gateway_policy::{
    CapabilityAction, CapabilityCondition, CapabilityRule, CompiledCapabilitySnapshot, JsonType, MatchMode,
};
use gateway_storage::{
    DiscoveredCapabilityCandidate, DiscoveredModel, ModelDiscoveryCommit, ModelDiscoverySource, PgStorage,
};
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

#[async_trait]
pub trait PublicModelDirectoryHttpPort: Send + Sync {
    async fn execute_public(
        &self,
        endpoint: Uri,
        response_limit: usize,
    ) -> Result<crate::credential_provider::ProviderHttpResponse, CredentialServiceError>;
}

pub struct PgModelCatalogCollector {
    storage: Arc<PgStorage>,
    http: Arc<dyn ProviderHttpPort>,
    public_http: Arc<dyn PublicModelDirectoryHttpPort>,
}

impl PgModelCatalogCollector {
    #[must_use]
    pub fn new(
        storage: Arc<PgStorage>,
        http: Arc<dyn ProviderHttpPort>,
        public_http: Arc<dyn PublicModelDirectoryHttpPort>,
    ) -> Arc<Self> {
        Arc::new(Self {
            storage,
            http,
            public_http,
        })
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
                let model = enrich_model_document(model)?;
                if models.len() >= 10_000 {
                    return Err(schema_retry());
                }
                let canonical = json!({
                    "capabilities":model.capabilities,
                    "created_at":model.created_at,
                    "display_name":model.display_name,
                    "id":model.id,
                    "max_input_tokens":model.max_input_tokens,
                    "max_tokens":model.max_tokens,
                    "type":model.model_type,
                });
                let canonical_bytes = serde_json::to_vec(&canonical).map_err(|_| schema_retry())?;
                let content_digest = Sha256::digest(&canonical_bytes).to_vec();
                let capability_candidate = build_gateway_capability_candidate(&model)?;
                source_models.push(canonical);
                models.push(DiscoveredModel {
                    upstream_model_id: model.id,
                    display_name: model.display_name,
                    created_at: model.created_at.filter(|value| value.len() <= 64),
                    max_input_tokens: optional_i64(model.max_input_tokens)?,
                    max_output_tokens: optional_i64(model.max_tokens)?,
                    provider_capabilities: model.capabilities,
                    capability_candidate,
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
                source: ModelDiscoverySource::AnthropicModelsApi {
                    credential_id: source_credential_id,
                    credential_revision: expected_revision,
                    token_version: expected_token_version,
                    egress_binding_id: expected_binding_id,
                    egress_epoch: expected_egress_epoch,
                },
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

    pub async fn execute_public(&self, job_id: Uuid, job_generation: i64) -> Result<(), ModelDiscoveryRetry> {
        let public_documents = self.load_public_model_directory().await;
        let (source, documents, manifest) = match public_documents {
            Ok(documents) => (
                ModelDiscoverySource::AnthropicPublicDocs,
                documents,
                json!({
                    "schema_version":1,
                    "source":"anthropic_public_docs",
                    "source_url":PUBLIC_MODEL_DIRECTORY_URL,
                    "fallback":false
                }),
            ),
            Err(()) => builtin_model_directory()?,
        };
        let (models, mut source_models) = normalize_model_documents(documents)?;
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
                source,
                source_digest,
                sanitized_manifest: merge_item_count(manifest, models.len())?,
                models,
            })
            .await
            .map_err(|_| ModelDiscoveryRetry {
                error_code: "model_discovery_commit_failed",
                retry_after_seconds: 30,
            })
    }

    async fn load_public_model_directory(&self) -> Result<Vec<ModelDocument>, ()> {
        let endpoint: Uri = PUBLIC_MODEL_DIRECTORY_URL.parse().map_err(|_| ())?;
        let response = self
            .public_http
            .execute_public(endpoint, 256 * 1024)
            .await
            .map_err(|_| ())?;
        if !(200..=299).contains(&response.status) {
            return Err(());
        }
        let directory = parse_public_model_directory(response.body.expose())?;
        let summaries = directory
            .models
            .into_iter()
            .map(|model| (model.id.clone(), model))
            .collect::<BTreeMap<_, _>>();
        let mut models = Vec::with_capacity(directory.detail_models.len());
        for reference in directory.detail_models {
            let endpoint: Uri = reference.endpoint.parse().map_err(|_| ())?;
            let response = self
                .public_http
                .execute_public(endpoint, 256 * 1024)
                .await
                .map_err(|_| ())?;
            if !(200..=299).contains(&response.status) {
                return Err(());
            }
            let mut model = parse_public_model_detail(
                response.body.expose(),
                &reference.display_name,
                &reference.catalog_status,
            )?;
            if reference
                .expected_id
                .as_deref()
                .is_some_and(|expected| expected != model.id)
            {
                return Err(());
            }
            if let Some(summary) = summaries.get(&model.id) {
                model.max_input_tokens = summary.max_input_tokens.or(model.max_input_tokens);
                model.max_tokens = summary.max_tokens.or(model.max_tokens);
                merge_provider_capabilities(&mut model.capabilities, summary.capabilities.as_ref())?;
            }
            models.push(model);
        }
        if models.len() != summaries.len() + directory.legacy_model_count {
            return Err(());
        }
        Ok(models)
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

#[derive(Clone, Deserialize)]
struct ModelDocument {
    id: String,
    #[serde(rename = "type")]
    model_type: String,
    display_name: String,
    created_at: Option<String>,
    max_input_tokens: Option<u64>,
    max_tokens: Option<u64>,
    #[serde(default)]
    capabilities: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ModelDetailReference {
    expected_id: Option<String>,
    display_name: String,
    endpoint: String,
    catalog_status: String,
}

struct ParsedPublicDirectory {
    models: Vec<ModelDocument>,
    detail_models: Vec<ModelDetailReference>,
    legacy_model_count: usize,
}

#[derive(Deserialize)]
struct BuiltinModelDirectory {
    schema_version: u32,
    source_url: String,
    snapshot_date: String,
    models: Vec<ModelDocument>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestCapabilityProfile {
    thinking_modes: Vec<String>,
    effort_levels: Vec<String>,
    sampling_profile: String,
    profile_completeness: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestCapabilityMatrix {
    schema_version: u32,
    profile_version: String,
    reviewed_at: String,
    source_urls: Vec<String>,
    profiles: BTreeMap<String, RequestCapabilityProfile>,
}

struct ResolvedRequestProfile {
    profile: RequestCapabilityProfile,
    profile_version: String,
    reviewed_at: String,
    source_urls: Vec<String>,
    effort_known: bool,
}

const PUBLIC_MODEL_DIRECTORY_URL: &str = "https://platform.claude.com/docs/en/models/overview.md";
const BUILTIN_MODEL_DIRECTORY: &[u8] = include_bytes!("../assets/anthropic-public-models.json");
const REQUEST_CAPABILITY_MATRIX: &[u8] = include_bytes!("../assets/anthropic-request-capabilities.json");

fn builtin_model_directory() -> Result<(ModelDiscoverySource, Vec<ModelDocument>, Value), ModelDiscoveryRetry> {
    let snapshot: BuiltinModelDirectory =
        serde_json::from_slice(BUILTIN_MODEL_DIRECTORY).map_err(|_| schema_retry())?;
    if snapshot.schema_version != 1 || snapshot.models.is_empty() {
        return Err(schema_retry());
    }
    Ok((
        ModelDiscoverySource::BuiltinSnapshot,
        snapshot.models,
        json!({
            "schema_version":1,
            "source":"builtin_snapshot",
            "source_url":snapshot.source_url,
            "snapshot_date":snapshot.snapshot_date,
            "fallback":true
        }),
    ))
}

fn merge_item_count(mut manifest: Value, item_count: usize) -> Result<Value, ModelDiscoveryRetry> {
    manifest
        .as_object_mut()
        .ok_or_else(schema_retry)?
        .insert("item_count".to_owned(), json!(item_count));
    Ok(manifest)
}

fn request_capability_matrix() -> Result<RequestCapabilityMatrix, ModelDiscoveryRetry> {
    let matrix: RequestCapabilityMatrix =
        serde_json::from_slice(REQUEST_CAPABILITY_MATRIX).map_err(|_| schema_retry())?;
    const THINKING_MODES: &[&str] = &["adaptive", "enabled", "disabled"];
    const EFFORT_LEVELS: &[&str] = &["low", "medium", "high", "xhigh", "max"];
    if matrix.schema_version != 1
        || matrix.profile_version.is_empty()
        || matrix.profile_version.len() > 64
        || matrix.reviewed_at.len() != 10
        || matrix.source_urls.is_empty()
        || matrix.source_urls.len() > 16
        || matrix
            .source_urls
            .iter()
            .any(|url| !url.starts_with("https://platform.claude.com/") || url.len() > 512)
        || matrix.profiles.is_empty()
        || matrix.profiles.iter().any(|(model_id, profile)| {
            model_id.is_empty()
                || model_id.len() > 256
                || profile.thinking_modes.is_empty()
                || profile
                    .thinking_modes
                    .iter()
                    .any(|mode| !THINKING_MODES.contains(&mode.as_str()))
                || profile
                    .effort_levels
                    .iter()
                    .any(|level| !EFFORT_LEVELS.contains(&level.as_str()))
                || !matches!(profile.sampling_profile.as_str(), "default_only" | "thinking_sensitive")
                || profile.profile_completeness != "complete"
        })
    {
        return Err(schema_retry());
    }
    Ok(matrix)
}

fn resolve_request_profile(model: &ModelDocument) -> Result<ResolvedRequestProfile, ModelDiscoveryRetry> {
    let matrix = request_capability_matrix()?;
    if let Some(profile) = matrix.profiles.get(&model.id) {
        return Ok(ResolvedRequestProfile {
            profile: profile.clone(),
            profile_version: matrix.profile_version,
            reviewed_at: matrix.reviewed_at,
            source_urls: matrix.source_urls,
            effort_known: true,
        });
    }
    let capabilities = model.capabilities.as_ref().and_then(Value::as_object);
    let thinking = capabilities
        .and_then(|value| value.get("thinking"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let thinking_modes = if thinking.contains("always on") {
        vec!["adaptive".to_owned()]
    } else if thinking.contains("adaptive") {
        vec!["adaptive".to_owned(), "disabled".to_owned()]
    } else if thinking.contains("extended") {
        vec!["enabled".to_owned(), "disabled".to_owned()]
    } else {
        Vec::new()
    };
    let effort_known = capabilities
        .and_then(|value| value.get("default_effort"))
        .and_then(Value::as_str)
        .is_some_and(|value| value == "not_supported");
    Ok(ResolvedRequestProfile {
        profile: RequestCapabilityProfile {
            thinking_modes,
            effort_levels: Vec::new(),
            sampling_profile: "standard".to_owned(),
            profile_completeness: "partial".to_owned(),
        },
        profile_version: matrix.profile_version,
        reviewed_at: matrix.reviewed_at,
        source_urls: matrix.source_urls,
        effort_known,
    })
}

fn enrich_model_document(mut model: ModelDocument) -> Result<ModelDocument, ModelDiscoveryRetry> {
    let resolved = resolve_request_profile(&model)?;
    let capabilities = model.capabilities.get_or_insert_with(|| json!({}));
    let object = capabilities.as_object_mut().ok_or_else(schema_retry)?;
    object.insert("thinking_modes".to_owned(), json!(resolved.profile.thinking_modes));
    object.insert("effort_levels".to_owned(), json!(resolved.profile.effort_levels));
    object.insert("sampling_profile".to_owned(), json!(resolved.profile.sampling_profile));
    object.insert(
        "profile_completeness".to_owned(),
        json!(resolved.profile.profile_completeness),
    );
    object.insert("profile_version".to_owned(), json!(resolved.profile_version));
    Ok(model)
}

fn merge_provider_capabilities(target: &mut Option<Value>, source: Option<&Value>) -> Result<(), ()> {
    let Some(source) = source else {
        return Ok(());
    };
    let source = source.as_object().ok_or(())?;
    let target = target.get_or_insert_with(|| json!({})).as_object_mut().ok_or(())?;
    for (key, value) in source {
        target.entry(key.clone()).or_insert_with(|| value.clone());
    }
    Ok(())
}

fn normalize_model_documents(
    documents: Vec<ModelDocument>,
) -> Result<(Vec<DiscoveredModel>, Vec<Value>), ModelDiscoveryRetry> {
    if documents.is_empty() || documents.len() > 10_000 {
        return Err(schema_retry());
    }
    let mut model_ids = BTreeSet::new();
    let mut models = Vec::with_capacity(documents.len());
    let mut source_models = Vec::with_capacity(documents.len());
    for model in documents {
        let model = enrich_model_document(model)?;
        if model.model_type != "model"
            || model.id.is_empty()
            || model.id.len() > 256
            || model.display_name.is_empty()
            || model.display_name.len() > 256
            || !model_ids.insert(model.id.clone())
        {
            return Err(schema_retry());
        }
        let canonical = json!({
            "capabilities":model.capabilities,
            "created_at":model.created_at,
            "display_name":model.display_name,
            "id":model.id,
            "max_input_tokens":model.max_input_tokens,
            "max_tokens":model.max_tokens,
            "type":model.model_type,
        });
        let canonical_bytes = serde_json::to_vec(&canonical).map_err(|_| schema_retry())?;
        let capability_candidate = build_gateway_capability_candidate(&model)?;
        models.push(DiscoveredModel {
            upstream_model_id: model.id,
            display_name: model.display_name,
            created_at: model.created_at.filter(|value| value.len() <= 64),
            max_input_tokens: optional_i64(model.max_input_tokens)?,
            max_output_tokens: optional_i64(model.max_tokens)?,
            provider_capabilities: model.capabilities,
            capability_candidate,
            content_digest: Sha256::digest(&canonical_bytes).to_vec(),
        });
        source_models.push(canonical);
    }
    models.sort_by(|left, right| left.upstream_model_id.cmp(&right.upstream_model_id));
    Ok((models, source_models))
}

fn optional_i64(value: Option<u64>) -> Result<Option<i64>, ModelDiscoveryRetry> {
    value.map(i64::try_from).transpose().map_err(|_| schema_retry())
}

fn build_gateway_capability_candidate(
    model: &ModelDocument,
) -> Result<Option<DiscoveredCapabilityCandidate>, ModelDiscoveryRetry> {
    const MAX_EXACT_F64_INTEGER: u64 = 9_007_199_254_740_991;
    if model
        .max_tokens
        .is_some_and(|value| value == 0 || value > MAX_EXACT_F64_INTEGER)
    {
        return Err(schema_retry());
    }
    let resolved = resolve_request_profile(model)?;
    let mut rules = base_messages_rules(model);
    append_thinking_rules(&mut rules, model, &resolved.profile);
    append_effort_rules(&mut rules, &resolved);
    append_sampling_rules(&mut rules, &resolved.profile);
    CompiledCapabilitySnapshot::compile("system-discovery-preview", model.id.clone(), rules.clone())
        .map_err(|_| schema_retry())?;
    let schema_payload = json!({
        "schema_version":1,
        "rules":rules,
        "metadata":{
            "profile_completeness":resolved.profile.profile_completeness,
            "profile_version":resolved.profile_version,
            "reviewed_at":resolved.reviewed_at,
            "source_urls":resolved.source_urls,
        }
    });
    let content_hash = Sha256::digest(canonical_json_bytes(&schema_payload)?).to_vec();
    Ok(Some(DiscoveredCapabilityCandidate {
        schema_payload,
        content_hash,
    }))
}

fn base_messages_rules(model: &ModelDocument) -> Vec<CapabilityRule> {
    vec![
        capability_rule(
            "base-model",
            "body:/model",
            CapabilityAction::Required,
            &[JsonType::String],
            vec![json!(model.id)],
            None,
            None,
            None,
            CapabilityCondition::Always,
        ),
        capability_rule(
            "base-messages",
            "body:/messages",
            CapabilityAction::Required,
            &[JsonType::Array],
            Vec::new(),
            None,
            None,
            None,
            CapabilityCondition::Always,
        ),
        capability_rule(
            "output-max-tokens",
            "body:/max_tokens",
            CapabilityAction::Required,
            &[JsonType::Integer],
            Vec::new(),
            Some(1.0),
            model.max_tokens.map(|value| value as f64),
            None,
            CapabilityCondition::Always,
        ),
        simple_allowed("base-stream", "body:/stream", &[JsonType::Boolean]),
        simple_allowed("base-system", "body:/system", &[JsonType::String, JsonType::Array]),
        simple_allowed("base-stop-sequences", "body:/stop_sequences", &[JsonType::Array]),
        simple_allowed("base-metadata", "body:/metadata", &[JsonType::Object]),
        capability_rule(
            "base-service-tier",
            "body:/service_tier",
            CapabilityAction::Allowed,
            &[JsonType::String],
            vec![json!("auto"), json!("standard_only")],
            None,
            None,
            None,
            CapabilityCondition::Always,
        ),
        simple_allowed("base-tools", "body:/tools", &[JsonType::Array]),
        simple_allowed("base-tool-choice", "body:/tool_choice", &[JsonType::Object]),
        simple_allowed("base-output-config", "body:/output_config", &[JsonType::Object]),
        simple_allowed("thinking-object", "body:/thinking", &[JsonType::Object]),
    ]
}

fn append_thinking_rules(rules: &mut Vec<CapabilityRule>, model: &ModelDocument, profile: &RequestCapabilityProfile) {
    if profile.thinking_modes.is_empty() {
        return;
    }
    let thinking_present = present("body:/thinking");
    let thinking_values = profile
        .thinking_modes
        .iter()
        .map(|mode| json!(mode))
        .collect::<Vec<_>>();
    if model.id == "claude-opus-5" {
        let high_effort = in_values("body:/output_config/effort", &["xhigh", "max"]);
        rules.push(capability_rule(
            "thinking-type-high-effort",
            "body:/thinking/type",
            CapabilityAction::Required,
            &[JsonType::String],
            vec![json!("adaptive")],
            None,
            None,
            None,
            all(vec![thinking_present.clone(), high_effort.clone()]),
        ));
        rules.push(capability_rule(
            "thinking-type-standard-effort",
            "body:/thinking/type",
            CapabilityAction::Required,
            &[JsonType::String],
            thinking_values,
            None,
            None,
            None,
            all(vec![thinking_present, not(high_effort)]),
        ));
    } else {
        rules.push(capability_rule(
            "thinking-type",
            "body:/thinking/type",
            CapabilityAction::Required,
            &[JsonType::String],
            thinking_values,
            None,
            None,
            None,
            thinking_present,
        ));
    }
    rules.push(capability_rule(
        "thinking-display",
        "body:/thinking/display",
        CapabilityAction::Allowed,
        &[JsonType::String],
        vec![json!("summarized"), json!("omitted")],
        None,
        None,
        None,
        present("body:/thinking"),
    ));
    if !profile.thinking_modes.iter().any(|mode| mode == "enabled") {
        return;
    }
    let enabled = equals("body:/thinking/type", "enabled");
    rules.push(capability_rule(
        "thinking-budget",
        "body:/thinking/budget_tokens",
        CapabilityAction::Required,
        &[JsonType::Integer],
        Vec::new(),
        Some(1_024.0),
        None,
        Some("body:/max_tokens"),
        enabled.clone(),
    ));
    rules.push(capability_rule(
        "thinking-budget-forbidden-without-manual-thinking",
        "body:/thinking/budget_tokens",
        CapabilityAction::Forbidden,
        &[],
        Vec::new(),
        None,
        None,
        None,
        not(enabled),
    ));
}

fn append_effort_rules(rules: &mut Vec<CapabilityRule>, resolved: &ResolvedRequestProfile) {
    if !resolved.effort_known {
        return;
    }
    let profile = &resolved.profile;
    let (action, values) = if profile.effort_levels.is_empty() {
        (CapabilityAction::Forbidden, Vec::new())
    } else {
        (
            CapabilityAction::Allowed,
            profile.effort_levels.iter().map(|level| json!(level)).collect(),
        )
    };
    rules.push(capability_rule(
        "effort-level",
        "body:/output_config/effort",
        action,
        if action == CapabilityAction::Forbidden {
            &[]
        } else {
            &[JsonType::String]
        },
        values,
        None,
        None,
        None,
        CapabilityCondition::Always,
    ));
}

fn append_sampling_rules(rules: &mut Vec<CapabilityRule>, profile: &RequestCapabilityProfile) {
    match profile.sampling_profile.as_str() {
        "default_only" => {
            rules.push(numeric_rule(
                "sampling-temperature-default",
                "body:/temperature",
                JsonType::Number,
                1.0,
                1.0,
                CapabilityCondition::Always,
            ));
            rules.push(numeric_rule(
                "sampling-top-p-default",
                "body:/top_p",
                JsonType::Number,
                0.99,
                1.0,
                CapabilityCondition::Always,
            ));
            rules.push(forbidden_rule(
                "sampling-top-k-forbidden",
                "body:/top_k",
                CapabilityCondition::Always,
            ));
        }
        "thinking_sensitive" => {
            let active = in_values("body:/thinking/type", &["adaptive", "enabled"]);
            let inactive = not(active.clone());
            rules.push(numeric_rule(
                "sampling-temperature-standard",
                "body:/temperature",
                JsonType::Number,
                0.0,
                1.0,
                inactive.clone(),
            ));
            rules.push(forbidden_rule(
                "sampling-temperature-thinking",
                "body:/temperature",
                active.clone(),
            ));
            rules.push(numeric_rule(
                "sampling-top-p-standard",
                "body:/top_p",
                JsonType::Number,
                0.0,
                1.0,
                inactive.clone(),
            ));
            rules.push(numeric_rule(
                "sampling-top-p-thinking",
                "body:/top_p",
                JsonType::Number,
                0.95,
                1.0,
                active.clone(),
            ));
            rules.push(capability_rule(
                "sampling-top-k-standard",
                "body:/top_k",
                CapabilityAction::Allowed,
                &[JsonType::Integer],
                Vec::new(),
                Some(0.0),
                None,
                None,
                inactive,
            ));
            rules.push(forbidden_rule("sampling-top-k-thinking", "body:/top_k", active));
        }
        _ => {
            rules.push(numeric_rule(
                "sampling-temperature-standard",
                "body:/temperature",
                JsonType::Number,
                0.0,
                1.0,
                CapabilityCondition::Always,
            ));
            rules.push(numeric_rule(
                "sampling-top-p-standard",
                "body:/top_p",
                JsonType::Number,
                0.0,
                1.0,
                CapabilityCondition::Always,
            ));
            rules.push(capability_rule(
                "sampling-top-k-standard",
                "body:/top_k",
                CapabilityAction::Allowed,
                &[JsonType::Integer],
                Vec::new(),
                Some(0.0),
                None,
                None,
                CapabilityCondition::Always,
            ));
        }
    }
}

fn simple_allowed(id: &str, path: &str, types: &[JsonType]) -> CapabilityRule {
    capability_rule(
        id,
        path,
        CapabilityAction::Allowed,
        types,
        Vec::new(),
        None,
        None,
        None,
        CapabilityCondition::Always,
    )
}

fn numeric_rule(
    id: &str,
    path: &str,
    json_type: JsonType,
    minimum: f64,
    maximum: f64,
    when: CapabilityCondition,
) -> CapabilityRule {
    capability_rule(
        id,
        path,
        CapabilityAction::Allowed,
        &[json_type],
        Vec::new(),
        Some(minimum),
        Some(maximum),
        None,
        when,
    )
}

fn forbidden_rule(id: &str, path: &str, when: CapabilityCondition) -> CapabilityRule {
    capability_rule(
        id,
        path,
        CapabilityAction::Forbidden,
        &[],
        Vec::new(),
        None,
        None,
        None,
        when,
    )
}

#[allow(clippy::too_many_arguments)]
fn capability_rule(
    id: &str,
    path: &str,
    action: CapabilityAction,
    types: &[JsonType],
    enum_values: Vec<Value>,
    minimum: Option<f64>,
    maximum: Option<f64>,
    exclusive_maximum_path: Option<&str>,
    when: CapabilityCondition,
) -> CapabilityRule {
    CapabilityRule {
        id: id.into(),
        path: path.into(),
        action,
        types: types.iter().copied().collect(),
        enum_values,
        minimum,
        maximum,
        exclusive_maximum_path: exclusive_maximum_path.map(Into::into),
        required_children: BTreeSet::new(),
        when,
    }
}

fn present(path: &str) -> CapabilityCondition {
    CapabilityCondition::Present {
        path: path.into(),
        mode: MatchMode::AnyMatch,
    }
}

fn equals(path: &str, value: &str) -> CapabilityCondition {
    CapabilityCondition::Equals {
        path: path.into(),
        value: json!(value),
        mode: MatchMode::AnyMatch,
    }
}

fn in_values(path: &str, values: &[&str]) -> CapabilityCondition {
    CapabilityCondition::In {
        path: path.into(),
        values: values.iter().map(|value| json!(value)).collect(),
        mode: MatchMode::AnyMatch,
    }
}

fn all(conditions: Vec<CapabilityCondition>) -> CapabilityCondition {
    CapabilityCondition::All { conditions }
}

fn not(condition: CapabilityCondition) -> CapabilityCondition {
    CapabilityCondition::Not {
        condition: Box::new(condition),
    }
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, ModelDiscoveryRetry> {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys = map.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                Value::Object(keys.into_iter().map(|key| (key.clone(), sort(&map[key]))).collect())
            }
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            scalar => scalar.clone(),
        }
    }
    serde_json::to_vec(&sort(value)).map_err(|_| schema_retry())
}

fn parse_public_model_directory(body: &[u8]) -> Result<ParsedPublicDirectory, ()> {
    let markdown = std::str::from_utf8(body).map_err(|_| ())?;
    let rows = markdown.lines().filter_map(markdown_table_row).collect::<Vec<_>>();
    let header = rows
        .iter()
        .find(|row| row.first().is_some_and(|cell| cell.trim() == "Feature"))
        .ok_or(())?;
    let ids = find_public_row(&rows, "Claude API ID")?;
    let input_limits = find_public_row(&rows, "Context window")?;
    let output_limits = find_public_row(&rows, "Max output")?;
    let model_pages = find_public_row(&rows, "Model page")?;
    let thinking = find_public_row(&rows, "Thinking").ok();
    let default_effort = find_public_row(&rows, "Default effort").ok();
    let width = header.len();
    if width < 2
        || ids.len() != width
        || input_limits.len() != width
        || output_limits.len() != width
        || model_pages.len() != width
    {
        return Err(());
    }
    let models = (1..width)
        .map(|index| {
            let id = ids[index].trim().trim_matches('`').to_owned();
            let display_name = header[index].trim().to_owned();
            if !id.starts_with("claude-") || display_name.is_empty() {
                return Err(());
            }
            Ok(ModelDocument {
                id,
                model_type: "model".to_owned(),
                display_name,
                created_at: None,
                max_input_tokens: Some(parse_public_token_count(&input_limits[index])?),
                max_tokens: Some(parse_public_token_count(&output_limits[index])?),
                capabilities: Some(json!({
                    "catalog_status":"current",
                    "thinking":thinking.and_then(|row| row.get(index)).map(|value| clean_public_value(value)),
                    "default_effort":default_effort
                        .and_then(|row| row.get(index))
                        .map(|value| normalize_default_effort(value)),
                })),
            })
        })
        .collect::<Result<Vec<_>, ()>>()?;
    let mut detail_models = (1..width)
        .map(|index| {
            Ok(ModelDetailReference {
                expected_id: Some(ids[index].trim().trim_matches('`').to_owned()),
                display_name: header[index].trim().to_owned(),
                endpoint: public_model_detail_endpoint(&model_pages[index])?,
                catalog_status: "current".to_owned(),
            })
        })
        .collect::<Result<Vec<_>, ()>>()?;
    let legacy_models = parse_legacy_model_references(markdown)?;
    let legacy_model_count = legacy_models.len();
    detail_models.extend(legacy_models);
    Ok(ParsedPublicDirectory {
        models,
        detail_models,
        legacy_model_count,
    })
}

fn parse_legacy_model_references(markdown: &str) -> Result<Vec<ModelDetailReference>, ()> {
    let Some(line) = markdown
        .lines()
        .find(|line| line.trim_start().starts_with("Legacy models (still available):"))
    else {
        return Ok(Vec::new());
    };
    let mut rest = line.split_once(':').map_or("", |(_, value)| value);
    let mut references = Vec::new();
    let mut endpoints = BTreeSet::new();
    while let Some(label_start) = rest.find('[') {
        rest = &rest[label_start + 1..];
        let label_end = rest.find("](").ok_or(())?;
        let display_name = rest[..label_end].trim();
        rest = &rest[label_end + 2..];
        let url_end = rest.find(')').ok_or(())?;
        let url = &rest[..url_end];
        rest = &rest[url_end + 1..];
        let path = url
            .strip_prefix("https://platform.claude.com/docs/en/models/")
            .and_then(|value| value.strip_suffix("/overview"))
            .ok_or(())?;
        if display_name.is_empty()
            || display_name.len() > 256
            || path.is_empty()
            || path.len() > 64
            || !path.chars().all(|value| value.is_ascii_alphanumeric() || value == '-')
        {
            return Err(());
        }
        let endpoint = format!("https://platform.claude.com/docs/en/models/{path}/overview.md");
        if !endpoints.insert(endpoint.clone()) || references.len() >= 32 {
            return Err(());
        }
        references.push(ModelDetailReference {
            expected_id: None,
            display_name: display_name.to_owned(),
            endpoint,
            catalog_status: "legacy_available".to_owned(),
        });
    }
    Ok(references)
}

fn public_model_detail_endpoint(value: &str) -> Result<String, ()> {
    let start = value.find("](").map(|index| index + 2).ok_or(())?;
    let end = value[start..].find(')').map(|index| start + index).ok_or(())?;
    let url = &value[start..end];
    let path = url
        .strip_prefix("https://platform.claude.com/docs/en/models/")
        .or_else(|| url.strip_prefix("/docs/en/models/"))
        .ok_or(())?
        .trim_end_matches(".md")
        .strip_suffix("/overview")
        .ok_or(())?;
    if path.is_empty() || path.len() > 64 || !path.chars().all(|value| value.is_ascii_alphanumeric() || value == '-') {
        return Err(());
    }
    Ok(format!("https://platform.claude.com/docs/en/models/{path}/overview.md"))
}

fn parse_public_model_detail(body: &[u8], display_name: &str, catalog_status: &str) -> Result<ModelDocument, ()> {
    let markdown = std::str::from_utf8(body).map_err(|_| ())?;
    let id = markdown
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("Model ID: `")
                .and_then(|value| value.strip_suffix('`'))
        })
        .filter(|value| value.starts_with("claude-") && value.len() <= 256)
        .ok_or(())?;
    let rows = markdown.lines().filter_map(markdown_table_row).collect::<Vec<_>>();
    let input_limit = public_detail_value(&rows, "Context window")?;
    let output_limit = public_detail_value(&rows, "Max output")?;
    let thinking = public_detail_value(&rows, "Thinking").ok().map(clean_public_value);
    let default_effort = public_detail_value(&rows, "Default effort")
        .ok()
        .map(normalize_default_effort);
    Ok(ModelDocument {
        id: id.to_owned(),
        model_type: "model".to_owned(),
        display_name: display_name.to_owned(),
        created_at: Some(parse_public_release_date(markdown, &rows)?),
        max_input_tokens: Some(parse_public_token_count(input_limit)?),
        max_tokens: Some(parse_public_token_count(output_limit)?),
        capabilities: Some(json!({
            "catalog_status":catalog_status,
            "thinking":thinking,
            "default_effort":default_effort,
        })),
    })
}

fn parse_public_release_date(markdown: &str, rows: &[Vec<String>]) -> Result<String, ()> {
    let table_value = public_detail_value(rows, "Released")
        .or_else(|_| public_detail_value(rows, "Release date"))
        .ok();
    table_value
        .into_iter()
        .chain(markdown.lines().filter(|line| line.contains("Released")))
        .find_map(parse_english_release_date)
        .ok_or(())
}

fn parse_english_release_date(value: &str) -> Option<String> {
    let tokens = value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        let month = match token.to_ascii_lowercase().as_str() {
            "january" | "jan" => 1,
            "february" | "feb" => 2,
            "march" | "mar" => 3,
            "april" | "apr" => 4,
            "may" => 5,
            "june" | "jun" => 6,
            "july" | "jul" => 7,
            "august" | "aug" => 8,
            "september" | "sep" | "sept" => 9,
            "october" | "oct" => 10,
            "november" | "nov" => 11,
            "december" | "dec" => 12,
            _ => continue,
        };
        let day = tokens.get(index + 1)?.parse::<u32>().ok()?;
        let year = tokens.get(index + 2)?.parse::<u32>().ok()?;
        let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let maximum_day = match month {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        if !(2020..=2200).contains(&year) || day == 0 || day > maximum_day {
            return None;
        }
        return Some(format!("{year:04}-{month:02}-{day:02}T00:00:00Z"));
    }
    None
}

fn public_detail_value<'a>(rows: &'a [Vec<String>], label: &str) -> Result<&'a str, ()> {
    find_public_row(rows, label)?
        .get(1)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(())
}

fn clean_public_value(value: &str) -> String {
    value.trim().trim_matches('`').to_owned()
}

fn normalize_default_effort(value: &str) -> String {
    let value = clean_public_value(value);
    if value.eq_ignore_ascii_case("not supported") {
        "not_supported".to_owned()
    } else {
        value
    }
}

fn markdown_table_row(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    if !trimmed.starts_with('|') || !trimmed.ends_with('|') {
        return None;
    }
    Some(
        trimmed[1..trimmed.len() - 1]
            .split('|')
            .map(|cell| cell.trim().to_owned())
            .collect(),
    )
}

fn find_public_row<'a>(rows: &'a [Vec<String>], label: &str) -> Result<&'a Vec<String>, ()> {
    rows.iter()
        .find(|row| row.first().is_some_and(|cell| cell.contains(label)))
        .ok_or(())
}

fn parse_public_token_count(value: &str) -> Result<u64, ()> {
    let token = value
        .trim()
        .trim_matches('`')
        .split_whitespace()
        .next()
        .ok_or(())?
        .replace(',', "")
        .to_ascii_uppercase();
    let (number, multiplier) = match token.chars().last() {
        Some('K') => (&token[..token.len() - 1], 1_000_u64),
        Some('M') => (&token[..token.len() - 1], 1_000_000_u64),
        Some(_) => (token.as_str(), 1_u64),
        None => return Err(()),
    };
    number
        .parse::<u64>()
        .ok()
        .and_then(|count| count.checked_mul(multiplier))
        .ok_or(())
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

#[cfg(test)]
mod tests {
    use gateway_policy::{CapabilityRule, CompiledCapabilitySnapshot};
    use serde_json::{Value, json};

    use super::{
        ModelDocument, append_effort_rules, append_sampling_rules, append_thinking_rules, base_messages_rules,
        build_gateway_capability_candidate, builtin_model_directory, parse_public_model_detail,
        parse_public_model_directory, parse_public_token_count, request_capability_matrix, resolve_request_profile,
    };

    #[test]
    fn parses_the_public_models_markdown_table_without_credentials() {
        let markdown = br#"
| Feature | Claude Opus Fixture | Claude Haiku Fixture |
| :-- | :-- | :-- |
| Claude API ID | `claude-opus-fixture` | `claude-haiku-fixture` |
| Thinking | Adaptive | Extended |
| Default effort | `high` | Not supported |
| [Context window](https://example.test) | 1M tokens | 200K tokens |
| Max output | 128K tokens | 64K tokens |
| Model page | [Opus](https://platform.claude.com/docs/en/models/opus-fixture/overview) | [Haiku](/docs/en/models/haiku-fixture/overview) |

Legacy models (still available): [Claude Opus Legacy](https://platform.claude.com/docs/en/models/opus-legacy/overview).
"#;
        let directory = parse_public_model_directory(markdown).expect("public model table");
        assert_eq!(directory.models.len(), 2);
        assert_eq!(directory.models[0].id, "claude-opus-fixture");
        assert_eq!(directory.models[0].max_input_tokens, Some(1_000_000));
        assert_eq!(directory.models[1].max_tokens, Some(64_000));
        assert_eq!(
            directory.models[1].capabilities.as_ref().expect("capabilities")["default_effort"],
            "not_supported"
        );
        assert_eq!(directory.detail_models.len(), 3);
        assert_eq!(directory.legacy_model_count, 1);
        assert_eq!(
            directory.detail_models[2].endpoint,
            "https://platform.claude.com/docs/en/models/opus-legacy/overview.md"
        );
    }

    #[test]
    fn parses_legacy_model_details_with_provider_limits() {
        let markdown = br#"
Model ID: `claude-opus-legacy`

**Legacy.** Released November 24, 2025.

| [Context window](https://example.test) | 1M tokens |
| Max output | 128K tokens |
| [Thinking](https://example.test) | Adaptive |
| [Default effort](https://example.test) | `high` |
"#;
        let model =
            parse_public_model_detail(markdown, "Claude Opus Legacy", "legacy_available").expect("legacy model detail");
        assert_eq!(model.id, "claude-opus-legacy");
        assert_eq!(model.created_at.as_deref(), Some("2025-11-24T00:00:00Z"));
        assert_eq!(model.max_input_tokens, Some(1_000_000));
        assert_eq!(model.max_tokens, Some(128_000));
        assert_eq!(
            model.capabilities.expect("capabilities")["catalog_status"],
            "legacy_available"
        );
    }

    #[test]
    fn rejects_incomplete_public_tables_and_keeps_a_valid_builtin_snapshot() {
        assert!(parse_public_model_directory(b"| Feature | Claude |\n| Claude API ID | `claude-x` |").is_err());
        let (_, models, manifest) = builtin_model_directory().expect("builtin model directory");
        assert_eq!(models.len(), 10);
        assert!(models.iter().any(|model| model.id == "claude-opus-4-5-20251101"));
        assert!(models.iter().any(|model| model.id == "claude-sonnet-4-5-20250929"));
        let released = models
            .iter()
            .map(|model| model.created_at.as_deref().expect("built-in release date"))
            .collect::<Vec<_>>();
        assert!(released.iter().all(|value| value.ends_with("T00:00:00Z")));
        assert_eq!(manifest["source"], "builtin_snapshot");
    }

    #[test]
    fn builtin_models_sort_by_official_release_date_descending() {
        let (_, mut models, _) = builtin_model_directory().expect("built-in directory");
        models.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.id.cmp(&left.id))
        });
        assert_eq!(
            models.iter().map(|model| model.id.as_str()).collect::<Vec<_>>(),
            vec![
                "claude-opus-5",
                "claude-sonnet-5",
                "claude-fable-5",
                "claude-opus-4-8",
                "claude-opus-4-7",
                "claude-sonnet-4-6",
                "claude-opus-4-6",
                "claude-opus-4-5-20251101",
                "claude-haiku-4-5-20251001",
                "claude-sonnet-4-5-20250929",
            ]
        );
    }

    #[test]
    fn parses_documented_token_suffixes() {
        assert_eq!(parse_public_token_count("1M tokens"), Ok(1_000_000));
        assert_eq!(parse_public_token_count("200K tokens"), Ok(200_000));
        assert_eq!(parse_public_token_count("128,000 tokens"), Ok(128_000));
    }

    #[test]
    fn builds_a_deterministic_gateway_candidate_from_provider_limits() {
        let model = ModelDocument {
            id: "claude-fixture".to_owned(),
            model_type: "model".to_owned(),
            display_name: "Claude Fixture".to_owned(),
            created_at: None,
            max_input_tokens: Some(200_000),
            max_tokens: Some(128_000),
            capabilities: None,
        };
        let first = build_gateway_capability_candidate(&model)
            .expect("valid capability")
            .expect("candidate");
        let second = build_gateway_capability_candidate(&model)
            .expect("valid capability")
            .expect("candidate");
        assert_eq!(first.content_hash, second.content_hash);
        assert_eq!(first.content_hash.len(), 32);
        assert_eq!(first.schema_payload["schema_version"], 1);
        assert!(
            first.schema_payload["rules"]
                .as_array()
                .is_some_and(|rules| rules.len() >= 15)
        );
        assert_eq!(first.schema_payload["metadata"]["profile_completeness"], "partial");
        let max_tokens = first.schema_payload["rules"]
            .as_array()
            .and_then(|rules| rules.iter().find(|rule| rule["path"] == "body:/max_tokens"))
            .expect("max tokens rule");
        assert_eq!(max_tokens["minimum"], 1.0);
        assert_eq!(max_tokens["maximum"], 128_000.0);
    }

    #[test]
    fn embedded_request_capability_matrix_is_valid() {
        let matrix = request_capability_matrix().expect("request capability matrix");
        assert_eq!(matrix.profiles.len(), 10);
    }

    #[test]
    fn creates_a_partial_gateway_candidate_when_a_new_model_has_no_output_limit() {
        let model = ModelDocument {
            id: "claude-fixture".to_owned(),
            model_type: "model".to_owned(),
            display_name: "Claude Fixture".to_owned(),
            created_at: None,
            max_input_tokens: None,
            max_tokens: None,
            capabilities: None,
        };
        let candidate = build_gateway_capability_candidate(&model)
            .expect("valid model")
            .expect("partial candidate");
        assert_eq!(candidate.schema_payload["metadata"]["profile_completeness"], "partial");
        let max_tokens = candidate.schema_payload["rules"]
            .as_array()
            .and_then(|rules| rules.iter().find(|rule| rule["path"] == "body:/max_tokens"))
            .expect("max tokens rule");
        assert!(max_tokens["maximum"].is_null());
    }

    fn known_model(id: &str, max_tokens: u64) -> ModelDocument {
        ModelDocument {
            id: id.to_owned(),
            model_type: "model".to_owned(),
            display_name: id.to_owned(),
            created_at: Some("2026-01-01T00:00:00Z".to_owned()),
            max_input_tokens: Some(1_000_000),
            max_tokens: Some(max_tokens),
            capabilities: None,
        }
    }

    fn compiled_model(model: &ModelDocument) -> CompiledCapabilitySnapshot {
        let candidate = build_gateway_capability_candidate(model)
            .expect("valid candidate")
            .expect("candidate");
        let rules: Vec<CapabilityRule> =
            serde_json::from_value(candidate.schema_payload["rules"].clone()).expect("rules");
        CompiledCapabilitySnapshot::compile("candidate", model.id.clone(), rules).expect("compiled")
    }

    fn validate(snapshot: &CompiledCapabilitySnapshot, body: Value) -> Vec<String> {
        snapshot
            .validate(&body, &Default::default(), true)
            .expect("runtime validation")
            .into_iter()
            .map(|diagnostic| diagnostic.code.into())
            .collect()
    }

    #[test]
    fn generates_differentiated_thinking_effort_and_sampling_profiles() {
        let preview = known_model("claude-fable-5", 128_000);
        let resolved = resolve_request_profile(&preview).expect("resolved profile");
        let mut preview_rules = base_messages_rules(&preview);
        append_thinking_rules(&mut preview_rules, &preview, &resolved.profile);
        append_effort_rules(&mut preview_rules, &resolved);
        append_sampling_rules(&mut preview_rules, &resolved.profile);
        CompiledCapabilitySnapshot::compile("preview", preview.id.clone(), preview_rules)
            .expect("matrix rules compile");
        let fable = build_gateway_capability_candidate(&known_model("claude-fable-5", 128_000))
            .expect("fable")
            .expect("candidate");
        let opus_46 = build_gateway_capability_candidate(&known_model("claude-opus-4-6", 128_000))
            .expect("opus 4.6")
            .expect("candidate");
        let sonnet_45 = build_gateway_capability_candidate(&known_model("claude-sonnet-4-5-20250929", 64_000))
            .expect("sonnet 4.5")
            .expect("candidate");
        assert_ne!(fable.content_hash, opus_46.content_hash);
        assert_ne!(opus_46.content_hash, sonnet_45.content_hash);
        assert!(
            fable.schema_payload["rules"]
                .as_array()
                .is_some_and(|rules| rules.iter().any(|rule| rule["id"] == "sampling-top-k-forbidden"))
        );
        assert!(opus_46.schema_payload["rules"].as_array().is_some_and(|rules| {
            rules
                .iter()
                .any(|rule| rule["id"] == "thinking-budget" && rule["exclusive_maximum_path"] == "body:/max_tokens")
        }));
        assert!(sonnet_45.schema_payload["rules"].as_array().is_some_and(|rules| {
            rules
                .iter()
                .any(|rule| rule["id"] == "effort-level" && rule["action"] == "forbidden")
        }));
    }

    #[test]
    fn runtime_enforces_model_specific_combinations_and_allows_valid_requests() {
        let fable = compiled_model(&known_model("claude-fable-5", 128_000));
        let opus_5 = compiled_model(&known_model("claude-opus-5", 128_000));
        let opus_46 = compiled_model(&known_model("claude-opus-4-6", 128_000));
        let sonnet_45 = compiled_model(&known_model("claude-sonnet-4-5-20250929", 64_000));
        let haiku_45 = compiled_model(&known_model("claude-haiku-4-5-20251001", 64_000));
        let base = |model: &str| json!({"model":model,"messages":[],"max_tokens":4096});

        let mut invalid_fable = base("claude-fable-5");
        invalid_fable["thinking"] = json!({"type":"enabled","budget_tokens":1024});
        assert!(validate(&fable, invalid_fable).contains(&"invalid_enum".to_owned()));

        let mut invalid_haiku = base("claude-haiku-4-5-20251001");
        invalid_haiku["thinking"] = json!({"type":"adaptive"});
        assert!(validate(&haiku_45, invalid_haiku).contains(&"invalid_enum".to_owned()));

        let mut invalid_effort = base("claude-sonnet-4-5-20250929");
        invalid_effort["output_config"] = json!({"effort":"high"});
        assert!(validate(&sonnet_45, invalid_effort).contains(&"forbidden".to_owned()));

        let mut invalid_opus_5 = base("claude-opus-5");
        invalid_opus_5["thinking"] = json!({"type":"disabled"});
        invalid_opus_5["output_config"] = json!({"effort":"xhigh"});
        assert!(validate(&opus_5, invalid_opus_5).contains(&"invalid_enum".to_owned()));

        let mut invalid_budget = base("claude-opus-4-6");
        invalid_budget["thinking"] = json!({"type":"enabled","budget_tokens":4096});
        assert!(validate(&opus_46, invalid_budget).contains(&"exclusive_maximum".to_owned()));

        let mut invalid_sampling = base("claude-opus-4-6");
        invalid_sampling["thinking"] = json!({"type":"enabled","budget_tokens":1024});
        invalid_sampling["temperature"] = json!(0.5);
        assert!(validate(&opus_46, invalid_sampling).contains(&"forbidden".to_owned()));

        let mut valid = base("claude-opus-4-6");
        valid["thinking"] = json!({"type":"enabled","budget_tokens":1024});
        valid["output_config"] = json!({"effort":"max"});
        valid["top_p"] = json!(0.97);
        assert!(validate(&opus_46, valid).is_empty());
    }
}
