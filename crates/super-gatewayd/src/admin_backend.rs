//! PostgreSQL-backed R8 management authentication and core read models.
#![allow(
    missing_docs,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::ignored_unit_patterns,
    clippy::items_after_statements,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::unused_self
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Write as _,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use gateway_api::{
    BackgroundCatalog, BackgroundCatalogDocument, ManagementBackend, ManagementBackendError, ManagementBackendResponse,
    ManagementDownload, ManagementPrincipal, ManagementRequest, ManagementRole, ManagementRuntimeBridge,
};
use gateway_domain::{
    AuthKind, ClientClass, CredentialPurpose, EnrollmentAuthMethod, EnrollmentMode, ManagementClass, SecretBytes,
    SecretValue, TrafficClass,
};
use gateway_policy::{
    CapabilityRule, CompiledCapabilitySnapshot, CompiledRuleSet, PolicyContext, RuleDefinition, SystemPolicy,
};
use gateway_services::{
    ReadinessCoordinator,
    content_audit::{AuditCaptureKind, AuditObjectContext, AuditObjectManifest, ContentAuditStore},
    credential_enrollment_postgres::load_active_enrollment_provider_profile,
    export::{ExportArtifactContext, ExportArtifactManifest, ExportArtifactStore, ExportFormat, lower_hex},
    observability::DataPlaneObservability,
    security::{
        EnvelopeAad, EnvelopeService, LocalAesKeyProvider, OAuthCallbackDigestDomain, SecretEnvelope,
        generate_oauth_pkce, generate_totp_seed, hash_bootstrap_password, lookup_digest, oauth_callback_digest,
        verify_password, verify_totp,
    },
};
use gateway_storage::{
    AuditOutboxRecord, CredentialEnrollmentCreate, CredentialGroupMigrationBegin, CredentialLifecycleCommand,
    DeviceIdentityRebuild, EgressAllocation, EgressAllocationRequest, OAuthCallbackClaim, PgStorage,
    ProfileCohortUpgrade, StorageError,
};
use gateway_transport::{
    ApplicationProfile, BundleEvidenceGate, BundleLifecycle, BundleLoadContext, BundleRuntimeState, BundleTrustStore,
    CatalogActivation, CompiledTransportEngine, EngineCatalogHandle, PreparedCatalogActivation, SignedBundleEnvelope,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use uuid::Uuid;

use crate::operations::IntegrityGuard;
use crate::production_dispatcher::ProductionDispatcher;

#[derive(Debug)]
pub struct PgManagementBackend {
    storage: Arc<PgStorage>,
    session_digest_key: Arc<SecretBytes>,
    readiness: ReadinessCoordinator,
    data_metrics: DataPlaneObservability,
    integrity_guard: IntegrityGuard,
    export_store: Arc<ExportArtifactStore>,
    content_audit_store: Option<Arc<ContentAuditStore>>,
    management_runtime: ManagementRuntimeBridge,
    scheduler_runtime: Option<Arc<ProductionDispatcher>>,
    transport_runtime: Option<Arc<TransportManagementRuntime>>,
    managed_browser_available: bool,
}

#[derive(Debug)]
pub(crate) struct TransportManagementRuntime {
    trust_store: Arc<BundleTrustStore>,
    bundle_dir: PathBuf,
    catalog: Arc<EngineCatalogHandle>,
    activation_lock: tokio::sync::Mutex<()>,
}

struct PreparedDeviceIdentity {
    encrypted: Vec<(Uuid, EnvelopeAad, SecretEnvelope)>,
    installation_digest: Vec<u8>,
    client_digest: Vec<u8>,
}

impl TransportManagementRuntime {
    pub(crate) fn new(
        trust_store: Arc<BundleTrustStore>,
        bundle_dir: PathBuf,
        catalog: Arc<EngineCatalogHandle>,
    ) -> Result<Self, ManagementBackendError> {
        std::fs::create_dir_all(&bundle_dir).map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(Self {
            trust_store,
            bundle_dir,
            catalog,
            activation_lock: tokio::sync::Mutex::new(()),
        })
    }

    fn load_context(&self, for_new_activation: bool) -> Result<BundleLoadContext, ManagementBackendError> {
        let now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ManagementBackendError::Unavailable)?
            .as_secs();
        Ok(BundleLoadContext {
            engine_abi_version: "1.0".into(),
            engine_build: env!("CARGO_PKG_VERSION").into(),
            target: crate::app::runtime_target().into(),
            supported_capabilities: BTreeSet::from(["tls_client_hello".into(), "ordered_http1".into()]),
            now_unix_seconds,
            for_new_activation,
        })
    }

    fn verify_and_compile(
        &self,
        bytes: &[u8],
        for_new_activation: bool,
    ) -> Result<CompiledTransportEngine, ManagementBackendError> {
        let verified =
            SignedBundleEnvelope::verify_json(bytes, &self.trust_store, &self.load_context(for_new_activation)?)
                .map_err(|_| ManagementBackendError::Precondition)?;
        CompiledTransportEngine::compile(verified).map_err(|_| ManagementBackendError::Precondition)
    }

    fn stage_directory(&self) -> Result<PreparedCatalogActivation, ManagementBackendError> {
        let mut paths = std::fs::read_dir(&self.bundle_dir)
            .map_err(|_| ManagementBackendError::Unavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ManagementBackendError::Unavailable)?;
        paths.sort_by_key(std::fs::DirEntry::file_name);
        let mut engines = Vec::new();
        for entry in paths {
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = std::fs::read(path).map_err(|_| ManagementBackendError::Unavailable)?;
            engines.push(self.verify_and_compile(&bytes, false)?);
        }
        self.catalog
            .stage(engines)
            .map_err(|_| ManagementBackendError::Unavailable)
    }

    fn publish(&self, prepared: PreparedCatalogActivation) -> CatalogActivation {
        self.catalog.publish(prepared)
    }
}

impl PgManagementBackend {
    pub fn new(
        storage: Arc<PgStorage>,
        session_digest_key: SecretBytes,
        readiness: ReadinessCoordinator,
        data_metrics: DataPlaneObservability,
        integrity_guard: IntegrityGuard,
        export_store: Arc<ExportArtifactStore>,
        content_audit_store: Option<Arc<ContentAuditStore>>,
        management_runtime: ManagementRuntimeBridge,
        scheduler_runtime: Option<Arc<ProductionDispatcher>>,
        transport_runtime: Option<Arc<TransportManagementRuntime>>,
        managed_browser_available: bool,
    ) -> Result<Self, ManagementBackendError> {
        if session_digest_key.expose().len() < 32 {
            return Err(ManagementBackendError::Unavailable);
        }
        Ok(Self {
            storage,
            session_digest_key: Arc::new(session_digest_key),
            readiness,
            data_metrics,
            integrity_guard,
            export_store,
            content_audit_store,
            management_runtime,
            scheduler_runtime,
            transport_runtime,
            managed_browser_available,
        })
    }

    async fn reload_management_runtime(&self) -> Result<(), ManagementBackendError> {
        let (access, models) = crate::app::load_access_snapshot(
            &self.storage,
            SecretBytes::new(self.session_digest_key.expose().to_vec()),
        )
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.management_runtime.publish(access, models);
        Ok(())
    }

    fn token_digest(&self, token: &SecretValue) -> Result<[u8; 32], ManagementBackendError> {
        let mut framed = b"management-session:".to_vec();
        framed.extend_from_slice(token.expose().as_bytes());
        lookup_digest(&self.session_digest_key, &SecretBytes::new(framed))
            .map_err(|_| ManagementBackendError::Unavailable)
    }

    fn csrf_token(&self, token: &SecretValue) -> Result<SecretValue, ManagementBackendError> {
        let mut framed = b"management-csrf:".to_vec();
        framed.extend_from_slice(token.expose().as_bytes());
        let digest = lookup_digest(&self.session_digest_key, &SecretBytes::new(framed))
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(SecretValue::new(URL_SAFE_NO_PAD.encode(digest)))
    }

    fn fresh_session_material(&self) -> Result<(SecretValue, [u8; 32], SecretValue), ManagementBackendError> {
        let mut token_bytes = [0_u8; 32];
        getrandom::fill(&mut token_bytes).map_err(|_| ManagementBackendError::Unavailable)?;
        let token = SecretValue::new(URL_SAFE_NO_PAD.encode(token_bytes));
        let digest = self.token_digest(&token)?;
        let csrf = self.csrf_token(&token)?;
        Ok((token, digest, csrf))
    }

    fn platform_key_digest(&self, secret: &SecretValue) -> Result<[u8; 32], ManagementBackendError> {
        let mut framed = b"platform-key:v1:".to_vec();
        framed.extend_from_slice(secret.expose().as_bytes());
        lookup_digest(&self.session_digest_key, &SecretBytes::new(framed))
            .map_err(|_| ManagementBackendError::Unavailable)
    }

    async fn encrypt_proxy_secret(
        &self,
        proxy_id: Uuid,
        secret_id: Uuid,
        username: &str,
        password: &str,
    ) -> Result<(EnvelopeAad, SecretEnvelope), ManagementBackendError> {
        let key_row = sqlx::query(
            "SELECT key_version,key_material FROM security.business_key_material \
             WHERE provider_code='database' AND state_code='active'",
        )
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let key_version = u64::try_from(required::<i64>(&key_row, "key_version")?)
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let aad = EnvelopeAad {
            schema_version: 1,
            secret_id,
            secret_kind: "proxy_password".to_owned(),
            provider_role: "business".to_owned(),
            owner_type: "proxy_endpoint".to_owned(),
            owner_id: proxy_id.to_string(),
            purpose: "proxy_authentication".to_owned(),
            key_version,
        };
        let material = serde_json::to_vec(&json!({"username":username,"password":password}))
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let envelope = EnvelopeService::new(
            LocalAesKeyProvider::new("business", key_version, required(&key_row, "key_material")?)
                .map_err(|_| ManagementBackendError::Unavailable)?,
        )
        .encrypt(&SecretBytes::new(material), aad.clone())
        .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok((aad, envelope))
    }

    async fn encrypt_notification_secret(
        &self,
        destination_id: Uuid,
        secret_id: Uuid,
        kind: &str,
        secret: &SecretValue,
    ) -> Result<(EnvelopeAad, SecretEnvelope), ManagementBackendError> {
        let key_row = sqlx::query(
            "SELECT key_version,key_material FROM security.business_key_material \
             WHERE provider_code='database' AND state_code='active'",
        )
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let key_version = u64::try_from(required::<i64>(&key_row, "key_version")?)
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let aad = EnvelopeAad {
            schema_version: 1,
            secret_id,
            secret_kind: "notification_destination".to_owned(),
            provider_role: "business".to_owned(),
            owner_type: "notification_destination".to_owned(),
            owner_id: destination_id.to_string(),
            purpose: "notification_delivery".to_owned(),
            key_version,
        };
        let material = serde_json::to_vec(&json!({"kind":kind,"secret":secret.expose()}))
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let envelope = EnvelopeService::new(
            LocalAesKeyProvider::new("business", key_version, required(&key_row, "key_material")?)
                .map_err(|_| ManagementBackendError::Unavailable)?,
        )
        .encrypt(&SecretBytes::new(material), aad.clone())
        .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok((aad, envelope))
    }

    async fn prepare_device_identity(
        &self,
        credential_id: Uuid,
    ) -> Result<PreparedDeviceIdentity, ManagementBackendError> {
        let key_version: i64 = sqlx::query_scalar(
            "SELECT key_version FROM security.business_key_material \
             WHERE provider_code='database' AND state_code='active'",
        )
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Unavailable)?;
        let root_key = self
            .storage
            .load_database_business_key(key_version)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let key_version = u64::try_from(key_version).map_err(|_| ManagementBackendError::Unavailable)?;
        let service = EnvelopeService::new(
            LocalAesKeyProvider::new("business", key_version, root_key.expose().to_vec())
                .map_err(|_| ManagementBackendError::Unavailable)?,
        );
        let mut installation_raw = [0_u8; 32];
        let mut profile_seed = [0_u8; 32];
        let mut session_hmac = [0_u8; 32];
        getrandom::fill(&mut installation_raw)
            .and_then(|()| getrandom::fill(&mut profile_seed))
            .and_then(|()| getrandom::fill(&mut session_hmac))
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let installation = SecretValue::new(URL_SAFE_NO_PAD.encode(installation_raw));
        let client = SecretValue::new(Uuid::now_v7().to_string());
        let installation_digest = Sha256::digest(installation.expose().as_bytes()).to_vec();
        let client_digest = Sha256::digest(client.expose().as_bytes()).to_vec();
        let values = [
            (
                "device_identity",
                "device_identity",
                SecretBytes::new(installation.expose().as_bytes().to_vec()),
            ),
            (
                "device_identity",
                "device_identity",
                SecretBytes::new(client.expose().as_bytes().to_vec()),
            ),
            (
                "device_identity",
                "device_identity",
                SecretBytes::new(profile_seed.to_vec()),
            ),
            (
                "session_hmac",
                "session_derivation",
                SecretBytes::new(session_hmac.to_vec()),
            ),
        ];
        let mut encrypted = Vec::with_capacity(values.len());
        for (kind, purpose, plaintext) in values {
            let secret_id = Uuid::now_v7();
            let aad = EnvelopeAad {
                schema_version: 1,
                secret_id,
                secret_kind: kind.to_owned(),
                provider_role: "business".to_owned(),
                owner_type: "credential".to_owned(),
                owner_id: credential_id.to_string(),
                purpose: purpose.to_owned(),
                key_version,
            };
            let envelope = service
                .encrypt(&plaintext, aad.clone())
                .map_err(|_| ManagementBackendError::Unavailable)?;
            encrypted.push((secret_id, aad, envelope));
        }
        Ok(PreparedDeviceIdentity {
            encrypted,
            installation_digest,
            client_digest,
        })
    }

    async fn login(&self, request: &ManagementRequest) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: LoginCommand = deserialize_body(request)?;
        let password = SecretValue::new(command.password);
        if command.username.trim().is_empty() || command.username.len() > 128 || password.expose().len() > 1_024 {
            return Err(ManagementBackendError::Authentication);
        }
        let row = sqlx::query(
            "SELECT u.id,u.role_code,u.status_code,p.password_phc,p.force_change, \
                    COALESCE(m.state_code='verified',false) AS mfa_enrolled \
             FROM iam.user_account u JOIN iam.password_credential p ON p.id=u.password_credential_id \
             LEFT JOIN iam.mfa_enrollment m ON m.user_id=u.id \
             WHERE u.username_normalized=lower($1) AND p.superseded_at IS NULL",
        )
        .bind(command.username.trim())
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Authentication)?;
        let status: String = row
            .try_get("status_code")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if matches!(status.as_str(), "disabled" | "archived" | "locked") {
            return Err(ManagementBackendError::Authentication);
        }
        let password_phc: String = row
            .try_get("password_phc")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if !verify_password(&password, &SecretValue::new(password_phc))
            .map_err(|_| ManagementBackendError::Authentication)?
        {
            return Err(ManagementBackendError::Authentication);
        }
        let user_id: Uuid = row.try_get("id").map_err(|_| ManagementBackendError::Unavailable)?;
        let role: String = row
            .try_get("role_code")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let force_change: bool = row
            .try_get("force_change")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let mfa_enrolled: bool = row
            .try_get("mfa_enrolled")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let (token, digest, csrf) = self.fresh_session_material()?;
        let session_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO iam.management_session \
             (id,user_id,token_digest,digest_key_version,created_at,last_seen_at,expires_at,mfa_verified,session_revision) \
             VALUES ($1,$2,$3,1,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '12 hours',false,1)",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(digest.as_slice())
        .execute(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({
                "data": {
                    "id": user_id,
                    "role": role,
                    "session_id": session_id,
                    "csrf_token": csrf.expose(),
                    "next_action": if force_change { "change_password" } else if !mfa_enrolled { "enroll_mfa" } else { "verify_mfa" }
                },
                "meta": {}
            }),
            etag: None,
            session_cookie: Some(token),
            clear_session_cookie: false,
            no_store: true,
        })
    }

    fn auth_me(principal: &ManagementPrincipal) -> ManagementBackendResponse {
        ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({
                "data": {
                    "id": principal.user_id,
                    "role": role_code(principal.role),
                    "session_id": principal.session_id,
                    "csrf_token": principal.csrf_token.expose(),
                    "mfa_verified": principal.mfa_verified,
                    "password_change_required": principal.password_change_required
                },
                "meta": {}
            }),
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        }
    }

    async fn list_sessions(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let user_id = parse_uuid(&principal.user_id)?;
        let rows = sqlx::query(
            "SELECT id,created_at,last_seen_at,expires_at,mfa_verified,source_ip,user_agent_summary \
             FROM iam.management_session WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp() \
             ORDER BY created_at DESC,id DESC",
        )
        .bind(user_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut data = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.try_get("id").map_err(|_| ManagementBackendError::Unavailable)?;
            data.push(json!({
                "id": id,
                "current": id.to_string() == principal.session_id.as_ref(),
                "created_at": timestamp_text(&row, "created_at")?,
                "last_seen_at": timestamp_text(&row, "last_seen_at")?,
                "expires_at": timestamp_text(&row, "expires_at")?,
                "mfa_verified": row.try_get::<bool,_>("mfa_verified").map_err(|_| ManagementBackendError::Unavailable)?,
                "source_ip": row.try_get::<Option<String>,_>("source_ip").unwrap_or(None),
                "user_agent_summary": row.try_get::<Option<String>,_>("user_agent_summary").unwrap_or(None)
            }));
        }
        Ok(ManagementBackendResponse::ok(
            json!({"data":data,"meta":{"has_more":false}}),
        ))
    }

    async fn list_user_sessions(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let user_id = path_uuid(request, "id")?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM iam.user_account WHERE id=$1)")
            .bind(user_id)
            .fetch_one(&self.storage.pool())
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if !exists {
            return Err(ManagementBackendError::NotFound);
        }
        let rows = sqlx::query(
            "SELECT id,created_at,last_seen_at,expires_at,mfa_verified,host(source_ip) AS source_ip,user_agent_summary,session_revision \
             FROM iam.management_session WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp() \
             ORDER BY created_at DESC,id DESC LIMIT 100",
        )
        .bind(user_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let current_session_id = parse_uuid(&principal.session_id)?;
        let data = rows
            .iter()
            .map(|row| {
                let id = required::<Uuid>(row, "id")?;
                Ok(json!({
                    "id":id,
                    "current":id == current_session_id,
                    "created_at":timestamp_text(row,"created_at")?,
                    "last_seen_at":timestamp_text(row,"last_seen_at")?,
                    "expires_at":timestamp_text(row,"expires_at")?,
                    "mfa_verified":required::<bool>(row,"mfa_verified")?,
                    "source_ip":optional::<String>(row,"source_ip")?,
                    "user_agent_summary":optional::<String>(row,"user_agent_summary")?,
                    "revision":required::<i64>(row,"session_revision")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        Ok(list_response(&data))
    }

    async fn revoke_session(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let target = request
            .path_parameters
            .get("id")
            .map_or(principal.session_id.as_ref(), AsRef::as_ref);
        let result = sqlx::query(
            "UPDATE iam.management_session SET revoked_at=clock_timestamp(),session_revision=session_revision+1 \
             WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL",
        )
        .bind(parse_uuid(target)?)
        .bind(parse_uuid(&principal.user_id)?)
        .execute(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if result.rows_affected() != 1 {
            return Err(ManagementBackendError::NotFound);
        }
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::NO_CONTENT,
            body: Value::Null,
            etag: None,
            session_cookie: None,
            clear_session_cookie: target == principal.session_id.as_ref(),
            no_store: true,
        })
    }

    async fn revoke_all_user_sessions(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: LifecycleActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(command.reason.as_deref())?;
        let user_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|expected| expected != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "UPDATE iam.user_account SET revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND status_code<>'archived' \
             RETURNING revision",
        )
        .bind(user_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let next_revision: i64 = required(&row, "revision")?;
        let revoked = sqlx::query(
            "UPDATE iam.management_session \
             SET revoked_at=clock_timestamp(),session_revision=session_revision+1 \
             WHERE user_id=$1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .rows_affected();
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "user_sessions_revoked_all",
                    "user_account",
                    user_id,
                    next_revision,
                    json!({"revoked_session_count":revoked,"reason":reason}),
                )?,
            )
            .await
            .map_err(|error| {
                tracing::error!(error = ?error, "user creation audit transaction failed");
                ManagementBackendError::Unavailable
            })?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(
                database_code = error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .as_deref()
                    .unwrap_or("unknown"),
                "user creation commit failed"
            );
            ManagementBackendError::Unavailable
        })?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({"data":{"id":user_id,"revoked_session_count":revoked,"revision":next_revision},"meta":{}}),
            etag: Some(format!("\"rev-{next_revision}\"").into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: user_id == parse_uuid(&principal.user_id)?,
            no_store: true,
        })
    }

    async fn enroll_mfa(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let user_id = parse_uuid(&principal.user_id)?;
        let existing: Option<String> = sqlx::query_scalar("SELECT state_code FROM iam.mfa_enrollment WHERE user_id=$1")
            .bind(user_id)
            .fetch_optional(&self.storage.pool())
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if existing.is_some() {
            return Err(ManagementBackendError::Precondition);
        }
        let (seed, display_seed) = generate_totp_seed().map_err(|_| ManagementBackendError::Unavailable)?;
        let key_row = sqlx::query(
            "SELECT key_version,key_material FROM security.business_key_material \
             WHERE provider_code='database' AND state_code='active'",
        )
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let key_version: i64 = key_row
            .try_get("key_version")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let key_material: Vec<u8> = key_row
            .try_get("key_material")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let secret_id = Uuid::now_v7();
        let aad = EnvelopeAad {
            schema_version: 1,
            secret_id,
            secret_kind: "totp_seed".to_owned(),
            provider_role: "business".to_owned(),
            owner_type: "user_account".to_owned(),
            owner_id: user_id.to_string(),
            purpose: "management_mfa".to_owned(),
            key_version: u64::try_from(key_version).map_err(|_| ManagementBackendError::Unavailable)?,
        };
        let envelope = EnvelopeService::new(
            LocalAesKeyProvider::new("business", aad.key_version, key_material)
                .map_err(|_| ManagementBackendError::Unavailable)?,
        )
        .encrypt(&seed, aad.clone())
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_secret(&mut transaction, secret_id, &aad, &envelope).await?;
        sqlx::query(
            "INSERT INTO iam.mfa_enrollment \
             (user_id,totp_secret_id,state_code,algorithm_code,digits,period_seconds,revision,created_at,updated_at) \
             VALUES ($1,$2,'pending','sha1',6,30,1,clock_timestamp(),clock_timestamp())",
        )
        .bind(user_id)
        .bind(secret_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "mfa_enrollment_created",
                    "user_account",
                    user_id,
                    1,
                    json!({"state":"pending"}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({
                "data": {
                    "id": user_id,
                    "secret": display_seed.expose(),
                    "otpauth_uri": format!("otpauth://totp/SuperGateway:{}?secret={}&issuer=SuperGateway&algorithm=SHA1&digits=6&period=30", user_id, display_seed.expose())
                },
                "meta": {}
            }),
            etag: Some("\"1\"".into()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn verify_mfa(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        confirming: bool,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: TotpCommand = deserialize_body(request)?;
        let code = SecretValue::new(command.code);
        let user_id = parse_uuid(&principal.user_id)?;
        let row = sqlx::query(
            "SELECT m.state_code,m.last_accepted_step,s.id,s.ciphertext,s.nonce,s.wrapped_dek,s.key_version, \
                    s.aad_schema_version,s.owner_type_code,s.owner_id,s.purpose_code \
             FROM iam.mfa_enrollment m JOIN security.encrypted_secret s ON s.id=m.totp_secret_id \
             WHERE m.user_id=$1 AND s.destroyed_at IS NULL",
        )
        .bind(user_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let state: String = row
            .try_get("state_code")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if (confirming && state != "pending") || (!confirming && state != "verified") {
            return Err(ManagementBackendError::Precondition);
        }
        let secret_id: Uuid = row.try_get("id").map_err(|_| ManagementBackendError::Unavailable)?;
        let key_version: i64 = row
            .try_get("key_version")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let key = self
            .storage
            .load_database_business_key(key_version)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let provider = LocalAesKeyProvider::new(
            "business",
            u64::try_from(key_version).map_err(|_| ManagementBackendError::Unavailable)?,
            key.expose().to_vec(),
        )
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let aad = EnvelopeAad {
            schema_version: row
                .try_get::<i32, _>("aad_schema_version")
                .ok()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(ManagementBackendError::Unavailable)?,
            secret_id,
            secret_kind: "totp_seed".to_owned(),
            provider_role: "business".to_owned(),
            owner_type: row
                .try_get("owner_type_code")
                .map_err(|_| ManagementBackendError::Unavailable)?,
            owner_id: row
                .try_get("owner_id")
                .map_err(|_| ManagementBackendError::Unavailable)?,
            purpose: row
                .try_get("purpose_code")
                .map_err(|_| ManagementBackendError::Unavailable)?,
            key_version: u64::try_from(key_version).map_err(|_| ManagementBackendError::Unavailable)?,
        };
        let envelope = row_envelope(&row, aad.schema_version, aad.key_version)?;
        let seed = EnvelopeService::new(provider)
            .decrypt(&envelope, &aad)
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ManagementBackendError::Unavailable)?
            .as_secs();
        let last = row
            .try_get::<Option<i64>, _>("last_accepted_step")
            .map_err(|_| ManagementBackendError::Unavailable)?
            .and_then(|value| u64::try_from(value).ok());
        let accepted = verify_totp(&seed, &code, unix_seconds, last)
            .map_err(|_| ManagementBackendError::Authentication)?
            .ok_or(ManagementBackendError::Authentication)?;
        let (rotated_token, rotated_digest, rotated_csrf) = self.fresh_session_material()?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let update = sqlx::query(
            "UPDATE iam.mfa_enrollment SET last_accepted_step=$2,state_code=CASE WHEN $3 THEN 'verified' ELSE state_code END, \
                    verified_at=CASE WHEN $3 THEN COALESCE(verified_at,clock_timestamp()) ELSE verified_at END, \
                    revision=revision+1,updated_at=clock_timestamp() \
             WHERE user_id=$1 AND (last_accepted_step IS NULL OR last_accepted_step<$2)",
        )
        .bind(user_id)
        .bind(i64::try_from(accepted).map_err(|_| ManagementBackendError::Unavailable)?)
        .bind(confirming)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if update.rows_affected() != 1 {
            return Err(ManagementBackendError::Authentication);
        }
        sqlx::query("UPDATE iam.management_session SET mfa_verified=true,token_digest=$3,digest_key_version=1,session_revision=session_revision+1 WHERE id=$1 AND user_id=$2")
            .bind(parse_uuid(&principal.session_id)?)
            .bind(user_id)
            .bind(rotated_digest.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "UPDATE iam.user_account u SET status_code='active',updated_at=clock_timestamp(),revision=revision+1 \
             FROM iam.password_credential p WHERE u.id=$1 AND p.id=u.password_credential_id AND NOT p.force_change \
               AND u.status_code='mfa_pending' AND $2",
        )
        .bind(user_id)
        .bind(confirming)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({"data":{"id":user_id,"mfa_verified":true,"csrf_token":rotated_csrf.expose()},"meta":{}}),
            etag: None,
            session_cookie: Some(rotated_token),
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn step_up(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: StepUpCommand = deserialize_body(request)?;
        if !matches!(
            command.purpose.as_str(),
            "key_secret_reveal"
                | "irreversible_lifecycle"
                | "content_audit_access"
                | "approval_decision"
                | "key_provider_change"
                | "backup_restore_security"
                | "bundle_activation"
                | "device_rebuild"
        ) {
            return Err(ManagementBackendError::InvalidInput);
        }
        let user_id = parse_uuid(&principal.user_id)?;
        let session_id = parse_uuid(&principal.session_id)?;
        let row = sqlx::query(
            "SELECT m.last_accepted_step,p.id AS password_credential_id,p.password_phc, \
                    s.id,s.ciphertext,s.nonce,s.wrapped_dek,s.key_version, \
                    s.aad_schema_version,s.owner_type_code,s.owner_id,s.purpose_code \
             FROM iam.mfa_enrollment m \
             JOIN iam.user_account u ON u.id=m.user_id \
             JOIN iam.password_credential p ON p.id=u.password_credential_id AND p.superseded_at IS NULL \
             JOIN security.encrypted_secret s ON s.id=m.totp_secret_id \
             WHERE m.user_id=$1 AND m.state_code='verified' AND u.status_code='active' AND s.destroyed_at IS NULL",
        )
        .bind(user_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let password_credential_id: Uuid = required(&row, "password_credential_id")?;
        let password_phc = SecretValue::new(required::<String>(&row, "password_phc")?);
        if !verify_password(&SecretValue::new(command.current_password), &password_phc)
            .map_err(|_| ManagementBackendError::Authentication)?
        {
            return Err(ManagementBackendError::Authentication);
        }
        let secret_id: Uuid = required(&row, "id")?;
        let key_version: i64 = required(&row, "key_version")?;
        let key = self
            .storage
            .load_database_business_key(key_version)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let provider = LocalAesKeyProvider::new(
            "business",
            u64::try_from(key_version).map_err(|_| ManagementBackendError::Unavailable)?,
            key.expose().to_vec(),
        )
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let aad = EnvelopeAad {
            schema_version: required::<i32>(&row, "aad_schema_version")?
                .try_into()
                .map_err(|_| ManagementBackendError::Unavailable)?,
            secret_id,
            secret_kind: "totp_seed".to_owned(),
            provider_role: "business".to_owned(),
            owner_type: required(&row, "owner_type_code")?,
            owner_id: required(&row, "owner_id")?,
            purpose: required(&row, "purpose_code")?,
            key_version: u64::try_from(key_version).map_err(|_| ManagementBackendError::Unavailable)?,
        };
        let seed = EnvelopeService::new(provider)
            .decrypt(&row_envelope(&row, aad.schema_version, aad.key_version)?, &aad)
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ManagementBackendError::Unavailable)?
            .as_secs();
        let last = required::<Option<i64>>(&row, "last_accepted_step")?.and_then(|value| value.try_into().ok());
        let accepted = verify_totp(&seed, &SecretValue::new(command.totp_code), unix_seconds, last)
            .map_err(|_| ManagementBackendError::Authentication)?
            .ok_or(ManagementBackendError::Authentication)?;
        let grant_id = Uuid::now_v7();
        let mut auth_context = Vec::new();
        auth_context.extend_from_slice(session_id.as_bytes());
        auth_context.extend_from_slice(password_credential_id.as_bytes());
        auth_context.extend_from_slice(command.purpose.as_bytes());
        auth_context.extend_from_slice(&accepted.to_be_bytes());
        let auth_context_digest = lookup_digest(&self.session_digest_key, &SecretBytes::new(auth_context))
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let (rotated_token, rotated_digest, rotated_csrf) = self.fresh_session_material()?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let update = sqlx::query(
            "UPDATE iam.mfa_enrollment SET last_accepted_step=$2,updated_at=clock_timestamp(),revision=revision+1 \
             WHERE user_id=$1 AND state_code='verified' AND (last_accepted_step IS NULL OR last_accepted_step<$2)",
        )
        .bind(user_id)
        .bind(i64::try_from(accepted).map_err(|_| ManagementBackendError::Unavailable)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if update.rows_affected() != 1 {
            return Err(ManagementBackendError::Authentication);
        }
        sqlx::query(
            "INSERT INTO iam.management_step_up_grant \
             (id,management_session_id,user_id,purpose_code,auth_context_digest,verified_at,expires_at,created_at) \
             VALUES ($1,$2,$3,$4,$5,clock_timestamp(),clock_timestamp()+interval '5 minutes',clock_timestamp())",
        )
        .bind(grant_id)
        .bind(session_id)
        .bind(user_id)
        .bind(&command.purpose)
        .bind(auth_context_digest.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "UPDATE iam.management_session SET token_digest=$2,digest_key_version=1,session_revision=session_revision+1 \
             WHERE id=$1 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .bind(rotated_digest.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":grant_id,"purpose":command.purpose,"expires_in_seconds":300,"csrf_token":rotated_csrf.expose()},"meta":{}}),
            etag: None,
            session_cookie: Some(rotated_token),
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn create_approval(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: ApprovalCreateCommand = deserialize_body(request)?;
        if !matches!(
            command.kind.as_str(),
            "key_full_audit"
                | "group_audit_policy"
                | "content_read"
                | "content_export"
                | "device_rebuild"
                | "key_provider_change"
                | "legal_hold"
                | "manual_delete"
                | "background_catalog_activate"
                | "background_catalog_risk_acceptance"
                | "enforcement_activate"
        ) || command.reason.trim().is_empty()
            || command.reason.len() > 2_048
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let object_type = command
            .scope
            .get("object_type")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(ManagementBackendError::InvalidInput)?;
        let object_id = command
            .scope
            .get("object_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(ManagementBackendError::InvalidInput)?;
        let step_up_id =
            Uuid::parse_str(&command.step_up_grant_id).map_err(|_| ManagementBackendError::InvalidInput)?;
        require_step_up(
            &self.storage,
            principal,
            step_up_id,
            approval_request_purpose(&command.kind),
        )
        .await?;
        let request_bytes = serde_json::to_vec(&request.body).map_err(|_| ManagementBackendError::InvalidInput)?;
        let request_digest = lookup_digest(&self.session_digest_key, &SecretBytes::new(request_bytes))
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let snapshot_digest = decode_sha256_hex(&command.action_snapshot_digest)?;
        let id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO security.approval_case \
             (id,operation_code,object_type_code,object_id,requested_by,state_code,required_approvals,request_digest, \
              expires_at,created_at,revision,request_reason,requester_step_up_grant_id,action_snapshot_digest) \
             VALUES ($1,$2,$3,$4,$5,'pending',2,$6,clock_timestamp()+interval '30 minutes',clock_timestamp(),1,$7,$8,$9)",
        )
        .bind(id)
        .bind(&command.kind)
        .bind(object_type)
        .bind(object_id)
        .bind(parse_uuid(&principal.user_id)?)
        .bind(request_digest.as_slice())
        .bind(command.reason.trim())
        .bind(step_up_id)
        .bind(snapshot_digest.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "approval_requested",
                    "approval_case",
                    id,
                    1,
                    json!({"kind":command.kind,"object_type":object_type,"object_id":object_id}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":id,"kind":command.kind,"object_type":object_type,"object_id":object_id,"state":"pending","revision":1},"meta":{}}),
            etag: Some("\"rev-1\"".into()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn list_approvals(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT id,operation_code,object_type_code,object_id,requested_by,state_code,required_approvals,request_reason, \
                    expires_at::text AS expires_at,consumed_at::text AS consumed_at,created_at::text AS created_at,revision \
             FROM security.approval_case ORDER BY created_at DESC,id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(approval_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn create_platform_key(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let command: PlatformKeyCreateCommand = deserialize_body(request)?;
        if command.name.trim().is_empty()
            || command.body_limit_bytes == 0
            || command.messages_rate.rpm == 0
            || command.messages_rate.burst == 0
            || command.models_rate.rpm == 0
            || command.models_rate.burst == 0
            || command.concurrency.limit == 0
            || command.endpoint_permissions.is_empty()
            || command
                .endpoint_permissions
                .iter()
                .any(|value| !matches!(value.as_str(), "messages" | "models"))
            || !matches!(
                command.requested_content_audit.as_str(),
                "metadata_only" | "full_encrypted"
            )
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let owner_user_id = parse_input_uuid(&command.owner_user_id)?;
        let group_id = parse_input_uuid(&command.group_id)?;
        let audit_approval_id = command
            .content_audit_approval_case_id
            .as_deref()
            .map(parse_input_uuid)
            .transpose()?;
        if command.requested_content_audit == "full_encrypted" && audit_approval_id.is_none() {
            return Err(ManagementBackendError::Precondition);
        }
        if command.requested_content_audit == "metadata_only"
            && (audit_approval_id.is_some() || command.content_audit_expires_at.is_some())
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let eligible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM iam.user_account u CROSS JOIN gateway.credential_group g \
             WHERE u.id=$1 AND u.role_code='key_owner' AND u.status_code='active' \
               AND g.id=$2 AND g.status_code='active')",
        )
        .bind(owner_user_id)
        .bind(group_id)
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if !eligible {
            return Err(ManagementBackendError::NotFound);
        }
        if command.requested_content_audit == "full_encrypted" {
            let expiry_valid: bool = sqlx::query_scalar(
                "SELECT CASE WHEN $1::text IS NULL THEN true ELSE \
                   $1::timestamptz>clock_timestamp() AND $1::timestamptz<=clock_timestamp()+interval '30 days' END",
            )
            .bind(command.content_audit_expires_at.as_deref())
            .fetch_one(&self.storage.pool())
            .await
            .map_err(|_| ManagementBackendError::InvalidInput)?;
            if !expiry_valid {
                return Err(ManagementBackendError::InvalidInput);
            }
        }
        let full_audit_snapshot_digest = (command.requested_content_audit == "full_encrypted")
            .then(|| platform_key_full_audit_snapshot_digest(&command, owner_user_id, group_id))
            .transpose()?;
        let key_id = Uuid::now_v7();
        let secret_id = Uuid::now_v7();
        let config_id = Uuid::now_v7();
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).map_err(|_| ManagementBackendError::Unavailable)?;
        let secret = SecretValue::new(format!("sgw_v1_{}", URL_SAFE_NO_PAD.encode(random)));
        let prefix = format!("{}…", &secret.expose()[..15]);
        let lookup = self.platform_key_digest(&secret)?;
        let key_row = sqlx::query(
            "SELECT key_version,key_material FROM security.business_key_material \
             WHERE provider_code='database' AND state_code='active'",
        )
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let key_version: i64 = required(&key_row, "key_version")?;
        let aad = EnvelopeAad {
            schema_version: 1,
            secret_id,
            secret_kind: "platform_key".to_owned(),
            provider_role: "business".to_owned(),
            owner_type: "platform_key".to_owned(),
            owner_id: key_id.to_string(),
            purpose: "authentication".to_owned(),
            key_version: key_version
                .try_into()
                .map_err(|_| ManagementBackendError::Unavailable)?,
        };
        let envelope = EnvelopeService::new(
            LocalAesKeyProvider::new("business", aad.key_version, required(&key_row, "key_material")?)
                .map_err(|_| ManagementBackendError::Unavailable)?,
        )
        .encrypt(&SecretBytes::new(secret.expose().as_bytes().to_vec()), aad.clone())
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let content_hash = lookup_digest(
            &self.session_digest_key,
            &SecretBytes::new(serde_json::to_vec(&request.body).map_err(|_| ManagementBackendError::InvalidInput)?),
        )
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some(approval_id) = audit_approval_id {
            let expected_object_id = format!(
                "new:{owner_user_id}:{group_id}:{}",
                command.name.trim().to_ascii_lowercase()
            );
            consume_approved_case_bound(
                &mut transaction,
                approval_id,
                "key_full_audit",
                "platform_key",
                &expected_object_id,
                full_audit_snapshot_digest
                    .as_ref()
                    .ok_or(ManagementBackendError::Precondition)?,
            )
            .await?;
        }
        insert_secret(&mut transaction, secret_id, &aad, &envelope).await?;
        sqlx::query(
            "UPDATE security.encrypted_secret SET lookup_digest=$2,digest_key_version=1,display_prefix=$3 WHERE id=$1",
        )
        .bind(secret_id)
        .bind(lookup.as_slice())
        .bind(&prefix)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO iam.platform_key \
             (id,owner_user_id,group_id,name,secret_id,status_code,expires_at,revision,created_at,updated_at) \
             VALUES ($1,$2,$3,$4,$5,'active',CASE WHEN $6::text IS NULL THEN NULL ELSE $6::timestamptz END,1,clock_timestamp(),clock_timestamp())",
        )
        .bind(key_id)
        .bind(owner_user_id)
        .bind(group_id)
        .bind(command.name.trim())
        .bind(secret_id)
        .bind(command.expires_at.as_deref())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        let messages_enabled = command.endpoint_permissions.iter().any(|value| value == "messages");
        let models_enabled = command.endpoint_permissions.iter().any(|value| value == "models");
        let audit_mode = if command.requested_content_audit == "full_encrypted" {
            "full_encrypted"
        } else {
            "metadata"
        };
        sqlx::query(
            "INSERT INTO iam.platform_key_config \
             (id,platform_key_id,config_version,content_hash,messages_enabled,models_enabled,max_body_bytes,messages_rpm, \
              messages_burst,models_rpm,models_burst,max_concurrency,audit_mode_code,created_by,created_at, \
              content_audit_approval_case_id,content_audit_expires_at) \
             VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,clock_timestamp(),$14, \
                     CASE WHEN $12='full_encrypted' \
                          THEN COALESCE($15::timestamptz,clock_timestamp()+interval '7 days') \
                          ELSE NULL END)",
        )
        .bind(config_id)
        .bind(key_id)
        .bind(content_hash.as_slice())
        .bind(messages_enabled)
        .bind(models_enabled)
        .bind(i64::try_from(command.body_limit_bytes).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i32::try_from(command.messages_rate.rpm).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i32::try_from(command.messages_rate.burst).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i32::try_from(command.models_rate.rpm).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i32::try_from(command.models_rate.burst).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i32::try_from(command.concurrency.limit).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(audit_mode)
        .bind(parse_uuid(&principal.user_id)?)
        .bind(audit_approval_id)
        .bind(command.content_audit_expires_at.as_deref())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO iam.platform_key_active_config (platform_key_id,config_id,revision,activated_by,activated_at) \
             VALUES ($1,$2,1,$3,clock_timestamp())",
        )
        .bind(key_id)
        .bind(config_id)
        .bind(parse_uuid(&principal.user_id)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "platform_key_created",
                    "platform_key",
                    key_id,
                    1,
                    json!({"group_id":group_id,"owner_user_id":owner_user_id,"display_prefix":prefix}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.reload_management_runtime().await?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":key_id,"owner_user_id":owner_user_id,"group_id":group_id,"name":command.name.trim(),"display_prefix":prefix,"status":"active","revision":1},"meta":{}}),
            etag: Some("\"rev-1\"".into()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn reveal_platform_key(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: PlatformKeyRevealCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let step_up_id = parse_input_uuid(&command.step_up_grant_id)?;
        let key_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "SELECT k.revision,s.id,s.ciphertext,s.nonce,s.wrapped_dek,s.key_version,s.aad_schema_version, \
                    s.owner_type_code,s.owner_id,s.purpose_code \
             FROM iam.platform_key k JOIN security.encrypted_secret s ON s.id=k.secret_id \
             WHERE k.id=$1 AND k.status_code<>'revoked' AND ($2 OR k.owner_user_id=$3) AND s.destroyed_at IS NULL \
             FOR UPDATE OF k",
        )
        .bind(key_id)
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let key_revision: i64 = required(&row, "revision")?;
        if key_revision != expected_revision {
            return Err(ManagementBackendError::Precondition);
        }
        let secret_id: Uuid = required(&row, "id")?;
        let key_version: i64 = required(&row, "key_version")?;
        let key = self
            .storage
            .load_database_business_key(key_version)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let aad = EnvelopeAad {
            schema_version: required::<i32>(&row, "aad_schema_version")?
                .try_into()
                .map_err(|_| ManagementBackendError::Unavailable)?,
            secret_id,
            secret_kind: "platform_key".to_owned(),
            provider_role: "business".to_owned(),
            owner_type: required(&row, "owner_type_code")?,
            owner_id: required(&row, "owner_id")?,
            purpose: required(&row, "purpose_code")?,
            key_version: key_version
                .try_into()
                .map_err(|_| ManagementBackendError::Unavailable)?,
        };
        let plaintext = EnvelopeService::new(
            LocalAesKeyProvider::new("business", aad.key_version, key.expose().to_vec())
                .map_err(|_| ManagementBackendError::Unavailable)?,
        )
        .decrypt(&row_envelope(&row, aad.schema_version, aad.key_version)?, &aad)
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let value = String::from_utf8(plaintext.expose().to_vec()).map_err(|_| ManagementBackendError::Unavailable)?;
        let reveal_id = Uuid::now_v7();
        let consumed = sqlx::query(
            "UPDATE iam.management_step_up_grant SET consumed_at=clock_timestamp() \
             WHERE id=$1 AND management_session_id=$2 AND user_id=$3 AND purpose_code='key_secret_reveal' \
               AND expires_at>clock_timestamp() AND consumed_at IS NULL",
        )
        .bind(step_up_id)
        .bind(parse_uuid(&principal.session_id)?)
        .bind(parse_uuid(&principal.user_id)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if consumed.rows_affected() != 1 {
            return Err(ManagementBackendError::Authorization);
        }
        sqlx::query(
            "INSERT INTO iam.platform_key_secret_reveal \
             (id,platform_key_id,requested_by,step_up_grant_id,revealed_at,expires_at) \
             VALUES ($1,$2,$3,$4,clock_timestamp(),clock_timestamp()+interval '60 seconds')",
        )
        .bind(reveal_id)
        .bind(key_id)
        .bind(parse_uuid(&principal.user_id)?)
        .bind(step_up_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "platform_key_secret_revealed",
                    "platform_key_secret_reveal",
                    reveal_id,
                    1,
                    json!({"platform_key_id":key_id,"reason":reason,"expires_in_seconds":60}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({"data":{"id":reveal_id,"platform_key_id":key_id,"secret":value,"expires_in_seconds":60},"meta":{}}),
            etag: Some(format!("\"rev-{key_revision}\"").into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn get_approval(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT id,operation_code,object_type_code,object_id,requested_by,state_code,required_approvals,request_reason, \
                    expires_at::text AS expires_at,consumed_at::text AS consumed_at,created_at::text AS created_at,revision \
             FROM security.approval_case WHERE id=$1",
        )
        .bind(path_uuid(request, "id")?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision = required(&row, "revision")?;
        Ok(single_response(&approval_projection(&row)?, revision))
    }

    async fn decide_approval(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        decision: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: ApprovalDecisionCommand = deserialize_body(request)?;
        if command.reason.trim().is_empty() || command.reason.len() > 2_048 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let step_up_id =
            Uuid::parse_str(&command.step_up_grant_id).map_err(|_| ManagementBackendError::InvalidInput)?;
        require_step_up(&self.storage, principal, step_up_id, "approval_decision").await?;
        let case_id = path_uuid(request, "id")?;
        let user_id = parse_uuid(&principal.user_id)?;
        let grant_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let approval = sqlx::query(
            "SELECT requested_by,required_approvals,state_code,expires_at>clock_timestamp() AS valid \
             FROM security.approval_case WHERE id=$1 FOR UPDATE",
        )
        .bind(case_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        if required::<String>(&approval, "state_code")? != "pending"
            || !required::<bool>(&approval, "valid")?
            || required::<Option<Uuid>>(&approval, "requested_by")? == Some(user_id)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let required_approvals = i64::from(required::<i16>(&approval, "required_approvals")?);
        sqlx::query(
            "INSERT INTO security.approval_grant \
             (id,approval_case_id,approver_user_id,decision_code,decided_at,step_up_grant_id) \
             VALUES ($1,$2,$3,$4,clock_timestamp(),$5)",
        )
        .bind(grant_id)
        .bind(case_id)
        .bind(user_id)
        .bind(decision)
        .bind(step_up_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        let approval_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM security.approval_grant \
             WHERE approval_case_id=$1 AND decision_code='approve'",
        )
        .bind(case_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let target_state = if decision == "reject" {
            "rejected"
        } else if approval_count.saturating_add(1) >= required_approvals {
            "approved"
        } else {
            "pending"
        };
        sqlx::query(
            "UPDATE security.approval_case SET state_code=$2, \
               decided_at=CASE WHEN $2<>'pending' THEN clock_timestamp() ELSE NULL END,revision=revision+1 \
             WHERE id=$1 AND state_code='pending'",
        )
        .bind(case_id)
        .bind(target_state)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    if decision == "reject" {
                        "approval_rejected"
                    } else {
                        "approval_approved"
                    },
                    "approval_case",
                    case_id,
                    1,
                    json!({"decision":decision,"state":target_state,"reason":command.reason.trim()}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "UPDATE iam.management_step_up_grant SET consumed_at=clock_timestamp() WHERE id=$1 AND consumed_at IS NULL",
        )
        .bind(step_up_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse::ok(
            json!({"data":{"id":case_id,"state":target_state},"meta":{}}),
        ))
    }

    async fn cancel_approval(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: ApprovalCancelCommand = deserialize_body(request)?;
        if command.reason.trim().is_empty() || command.reason.len() > 2_048 || command.expected_revision < 1 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let case_id = path_uuid(request, "id")?;
        let user_id = parse_uuid(&principal.user_id)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let result = sqlx::query(
            "UPDATE security.approval_case SET state_code='cancelled',decided_at=clock_timestamp(),revision=revision+1 \
             WHERE id=$1 AND requested_by=$2 AND state_code='pending' AND revision=$3",
        )
        .bind(case_id)
        .bind(user_id)
        .bind(command.expected_revision)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if result.rows_affected() != 1 {
            return Err(ManagementBackendError::Precondition);
        }
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "approval_cancelled",
                    "approval_case",
                    case_id,
                    command.expected_revision + 1,
                    json!({"reason":command.reason.trim()}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse::ok(
            json!({"data":{"id":case_id,"state":"cancelled","revision":command.expected_revision+1},"meta":{}}),
        ))
    }

    async fn create_content_audit_search_session(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        if self.content_audit_store.is_none() {
            return Err(ManagementBackendError::Unavailable);
        }
        let command: ContentAuditSearchCommand = deserialize_body(request)?;
        let reason = command.reason.trim();
        if reason.is_empty()
            || reason.len() > 2_048
            || command.filters.object_kind.as_deref().is_some_and(|kind| {
                !matches!(
                    kind,
                    "original_request" | "final_upstream_request" | "upstream_response"
                )
            })
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let valid_time_range: bool = sqlx::query_scalar(
            "SELECT created_from IS NULL OR created_to IS NULL OR created_from<=created_to \
             FROM (SELECT CASE WHEN $1::text IS NULL THEN NULL ELSE $1::timestamptz END AS created_from, \
                          CASE WHEN $2::text IS NULL THEN NULL ELSE $2::timestamptz END AS created_to) parsed",
        )
        .bind(command.filters.created_from.as_deref())
        .bind(command.filters.created_to.as_deref())
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::InvalidInput)?;
        if !valid_time_range {
            return Err(ManagementBackendError::InvalidInput);
        }
        let approval_id = parse_input_uuid(&command.approval_case_id)?;
        let step_up_id = parse_input_uuid(&command.step_up_grant_id)?;
        let filters = serde_json::to_value(&command.filters).map_err(|_| ManagementBackendError::InvalidInput)?;
        let digest: [u8; 32] = Sha256::digest(canonical_json_bytes(&json!({
            "schema_version":1,
            "operation":"content_audit_search",
            "filters":filters
        }))?)
        .into();
        let scope_id = format!("scope:{}", lower_hex(&digest));
        let actor_id = parse_uuid(&principal.user_id)?;
        let management_session_id = parse_uuid(&principal.session_id)?;
        let search_session_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        lock_content_audit_execution_approval(
            &mut transaction,
            principal,
            approval_id,
            "content_read",
            &scope_id,
            &digest,
        )
        .await?;
        let candidates = sqlx::query(
            "SELECT object.id FROM security.content_audit_object object \
             WHERE object.scope_code='full_encrypted' AND object.storage_state_code='finalized' \
               AND object.state_code IN ('active','held') AND object.deleted_at IS NULL \
               AND object.request_id IS NOT NULL AND object.owner_user_id IS NOT NULL \
               AND object.platform_key_id IS NOT NULL AND object.group_id IS NOT NULL \
               AND object.object_kind_code IS NOT NULL \
               AND (object.state_code='held' OR object.legal_hold_count>0 OR object.expires_at>clock_timestamp()) \
               AND ($1::uuid IS NULL OR object.request_id=$1) \
               AND ($2::uuid IS NULL OR object.owner_user_id=$2) \
               AND ($3::uuid IS NULL OR object.platform_key_id=$3) \
               AND ($4::uuid IS NULL OR object.group_id=$4) \
               AND ($5::uuid IS NULL OR object.attempt_id=$5) \
               AND ($6::text IS NULL OR object.object_kind_code=$6) \
               AND ($7::text IS NULL OR object.created_at>=$7::timestamptz) \
               AND ($8::text IS NULL OR object.created_at<=$8::timestamptz) \
             ORDER BY object.created_at DESC,object.id DESC LIMIT 1001",
        )
        .bind(command.filters.request_id)
        .bind(command.filters.owner_user_id)
        .bind(command.filters.platform_key_id)
        .bind(command.filters.group_id)
        .bind(command.filters.attempt_id)
        .bind(command.filters.object_kind.as_deref())
        .bind(command.filters.created_from.as_deref())
        .bind(command.filters.created_to.as_deref())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if candidates.len() > 1_000 {
            return Err(ManagementBackendError::Precondition);
        }
        consume_step_up_in(&mut transaction, principal, step_up_id, "content_audit_access").await?;
        let consumed = sqlx::query(
            "UPDATE security.approval_case SET state_code='consumed',consumed_at=clock_timestamp(),revision=revision+1 \
             WHERE id=$1 AND state_code='approved' AND consumed_at IS NULL RETURNING id",
        )
        .bind(approval_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if consumed.is_none() {
            return Err(ManagementBackendError::Precondition);
        }
        sqlx::query(
            "INSERT INTO security.content_audit_search_session \
             (id,actor_user_id,management_session_id,approval_case_id,step_up_grant_id,reason,filters, \
              action_snapshot_digest,candidate_count,created_at,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp(),clock_timestamp()+interval '30 minutes')",
        )
        .bind(search_session_id)
        .bind(actor_id)
        .bind(management_session_id)
        .bind(approval_id)
        .bind(step_up_id)
        .bind(reason)
        .bind(&filters)
        .bind(digest.as_slice())
        .bind(i32::try_from(candidates.len()).map_err(|_| ManagementBackendError::Unavailable)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        for (index, candidate) in candidates.iter().enumerate() {
            sqlx::query(
                "INSERT INTO security.content_audit_search_candidate \
                 (search_session_id,content_audit_object_id,ordinal,created_at) \
                 VALUES ($1,$2,$3,clock_timestamp())",
            )
            .bind(search_session_id)
            .bind(required::<Uuid>(candidate, "id")?)
            .bind(i16::try_from(index + 1).map_err(|_| ManagementBackendError::Unavailable)?)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        sqlx::query(
            "INSERT INTO security.content_audit_access \
             (id,content_audit_object_id,actor_user_id,approval_case_id,action_code,occurred_at, \
              search_session_id,management_session_id) \
             SELECT gen_random_uuid(),candidate.content_audit_object_id,$2,$3,'metadata_read',clock_timestamp(),$1,$4 \
             FROM security.content_audit_search_candidate candidate WHERE candidate.search_session_id=$1",
        )
        .bind(search_session_id)
        .bind(actor_id)
        .bind(approval_id)
        .bind(management_session_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "content_audit_search_created",
                    "content_audit_search_session",
                    search_session_id,
                    1,
                    json!({"scope_digest":lower_hex(&digest),"candidate_count":candidates.len(),"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":search_session_id,"state":"active","candidate_count":candidates.len(),"expires_in_seconds":1800},"meta":{}}),
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn list_content_audit_search_records(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        if self.content_audit_store.is_none() {
            return Err(ManagementBackendError::Unavailable);
        }
        let query: ContentAuditPageQuery = serde_urlencoded::from_str(request.query.as_deref().unwrap_or(""))
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let page_size = query.page_size.unwrap_or(20);
        if !(1..=100).contains(&page_size) {
            return Err(ManagementBackendError::InvalidInput);
        }
        let after = query.page_after.unwrap_or(0);
        let search_session_id = path_uuid(request, "id")?;
        let valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM security.content_audit_search_session \
             WHERE id=$1 AND actor_user_id=$2 AND management_session_id=$3 AND expires_at>clock_timestamp())",
        )
        .bind(search_session_id)
        .bind(parse_uuid(&principal.user_id)?)
        .bind(parse_uuid(&principal.session_id)?)
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if !valid {
            return Err(ManagementBackendError::NotFound);
        }
        let rows = sqlx::query(
            "SELECT candidate.ordinal,object.id,object.request_id,object.owner_user_id,object.platform_key_id, \
                    object.group_id,object.attempt_id,object.attempt_no,object.object_kind_code,object.content_length, \
                    object.state_code,object.legal_hold_count,object.created_at::text AS created_at, \
                    object.expires_at::text AS expires_at, \
                    COALESCE((object.frame_manifest->>'capture_complete')::boolean,false) AS capture_complete, \
                    COALESCE((object.frame_manifest->'manifest'->>'truncated')::boolean,false) AS truncated \
             FROM security.content_audit_search_candidate candidate \
             JOIN security.content_audit_object object ON object.id=candidate.content_audit_object_id \
             WHERE candidate.search_session_id=$1 AND candidate.ordinal>$2 \
             ORDER BY candidate.ordinal LIMIT $3",
        )
        .bind(search_session_id)
        .bind(i16::try_from(after).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i64::try_from(page_size + 1).map_err(|_| ManagementBackendError::InvalidInput)?)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let has_more = rows.len() > page_size;
        let visible = rows.iter().take(page_size);
        let data = visible
            .map(content_audit_metadata_projection)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = has_more
            .then(|| rows.get(page_size - 1))
            .flatten()
            .map(|row| required::<i16>(row, "ordinal").map(|value| value.to_string()))
            .transpose()?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({"data":data,"page":{"next_cursor":next_cursor},"meta":{"has_more":has_more,"page_size":page_size}}),
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn get_content_audit_record(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let store = self
            .content_audit_store
            .as_ref()
            .ok_or(ManagementBackendError::Unavailable)?
            .clone();
        let query: ContentAuditRecordQuery = serde_urlencoded::from_str(request.query.as_deref().unwrap_or(""))
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let object_id = path_uuid(request, "id")?;
        let actor_id = parse_uuid(&principal.user_id)?;
        let management_session_id = parse_uuid(&principal.session_id)?;
        let row = sqlx::query(
            "SELECT object.request_id,object.attempt_id,object.object_kind_code,object.object_uri, \
                    object.encrypted_dek,object.cipher_suite_code,object.content_sha256,object.content_length, \
                    object.frame_manifest,session.approval_case_id \
             FROM security.content_audit_search_candidate candidate \
             JOIN security.content_audit_search_session session ON session.id=candidate.search_session_id \
             JOIN security.content_audit_object object ON object.id=candidate.content_audit_object_id \
             WHERE candidate.search_session_id=$1 AND candidate.content_audit_object_id=$2 \
               AND session.actor_user_id=$3 AND session.management_session_id=$4 \
               AND session.expires_at>clock_timestamp() AND object.scope_code='full_encrypted' \
               AND object.storage_state_code='finalized' AND object.state_code IN ('active','held') \
               AND object.deleted_at IS NULL AND object.request_id IS NOT NULL \
               AND (object.state_code='held' OR object.legal_hold_count>0 OR object.expires_at>clock_timestamp())",
        )
        .bind(query.search_session_id)
        .bind(object_id)
        .bind(actor_id)
        .bind(management_session_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let frame_manifest = required::<Value>(&row, "frame_manifest")?;
        let manifest: AuditObjectManifest = serde_json::from_value(
            frame_manifest
                .get("manifest")
                .cloned()
                .ok_or(ManagementBackendError::Unavailable)?,
        )
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let internal_kind = frame_manifest
            .get("capture_kind")
            .and_then(Value::as_str)
            .ok_or(ManagementBackendError::Unavailable)?;
        let (capture_kind, contract_kind) = match internal_kind {
            "original_request" => (AuditCaptureKind::OriginalRequest, "original_request"),
            "final_request" | "final_upstream_request" => (AuditCaptureKind::FinalRequest, "final_upstream_request"),
            "response" | "upstream_response" => (AuditCaptureKind::Response, "upstream_response"),
            _ => return Err(ManagementBackendError::Unavailable),
        };
        let policy_version = frame_manifest
            .get("policy_version")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(ManagementBackendError::Unavailable)?;
        let object_uri = required::<Option<String>>(&row, "object_uri")?.ok_or(ManagementBackendError::Unavailable)?;
        let encrypted_dek =
            required::<Option<Vec<u8>>>(&row, "encrypted_dek")?.ok_or(ManagementBackendError::Unavailable)?;
        let cipher_suite =
            required::<Option<String>>(&row, "cipher_suite_code")?.ok_or(ManagementBackendError::Unavailable)?;
        let content_hash =
            required::<Option<Vec<u8>>>(&row, "content_sha256")?.ok_or(ManagementBackendError::Unavailable)?;
        let content_length =
            required::<Option<i64>>(&row, "content_length")?.ok_or(ManagementBackendError::Unavailable)?;
        let manifest_dek = base64::engine::general_purpose::STANDARD
            .decode(manifest.wrapped_dek_base64.as_bytes())
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if manifest.object_id != object_id
            || manifest.object_uri.as_ref() != object_uri
            || manifest_dek != encrypted_dek
            || manifest.cipher_suite.as_ref() != cipher_suite
            || required::<String>(&row, "object_kind_code")? != contract_kind
            || u64::try_from(content_length).ok() != Some(manifest.plaintext_length)
        {
            return Err(ManagementBackendError::Unavailable);
        }
        let context = AuditObjectContext {
            object_id,
            request_id: required::<Uuid>(&row, "request_id")?,
            attempt_id: required::<Option<Uuid>>(&row, "attempt_id")?,
            kind: capture_kind,
            policy_version: policy_version.to_owned().into_boxed_str(),
        };
        let plaintext = store
            .read(&context, &manifest)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if Sha256::digest(&plaintext).as_slice() != content_hash.as_slice() {
            return Err(ManagementBackendError::Unavailable);
        }
        let approval_id = required::<Uuid>(&row, "approval_case_id")?;
        let access_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let inserted = sqlx::query(
            "INSERT INTO security.content_audit_access \
             (id,content_audit_object_id,actor_user_id,approval_case_id,action_code,occurred_at, \
              search_session_id,management_session_id) \
             SELECT $1,$2,$3,$4,'content_read',clock_timestamp(),session.id,$5 \
             FROM security.content_audit_search_session session \
             JOIN security.content_audit_search_candidate candidate ON candidate.search_session_id=session.id \
             WHERE session.id=$6 AND session.actor_user_id=$3 AND session.management_session_id=$5 \
               AND session.expires_at>clock_timestamp() AND candidate.content_audit_object_id=$2 \
             RETURNING id",
        )
        .bind(access_id)
        .bind(object_id)
        .bind(actor_id)
        .bind(approval_id)
        .bind(management_session_id)
        .bind(query.search_session_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if inserted.is_none() {
            return Err(ManagementBackendError::NotFound);
        }
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "content_audit_content_read",
                    "content_audit_object",
                    object_id,
                    1,
                    json!({"search_session_id":query.search_session_id,"object_kind":contract_kind}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({
                "data":{
                    "id":object_id,
                    "search_session_id":query.search_session_id,
                    "object_kind":contract_kind,
                    "capture_complete":frame_manifest.get("capture_complete").and_then(Value::as_bool).unwrap_or(false),
                    "truncated":manifest.truncated,
                    "content":{"encoding":"base64","data":base64::engine::general_purpose::STANDARD.encode(&plaintext)}
                },
                "meta":{}
            }),
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn create_content_audit_export(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        if self.content_audit_store.is_none() {
            return Err(ManagementBackendError::Unavailable);
        }
        let command: ContentAuditExportCommand = deserialize_body(request)?;
        let reason = command.reason.trim();
        if reason.is_empty() || reason.len() > 2_048 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let object_id = path_uuid(request, "id")?;
        let actor_id = parse_uuid(&principal.user_id)?;
        let management_session_id = parse_uuid(&principal.session_id)?;
        let digest: [u8; 32] = Sha256::digest(canonical_json_bytes(&json!({
            "schema_version":1,
            "operation":"content_audit_export",
            "search_session_id":command.search_session_id,
            "content_audit_object_id":object_id,
            "format":"raw"
        }))?)
        .into();
        let scope_id = format!("scope:{}", lower_hex(&digest));
        let export_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let query = json!({
            "schema_version":1,
            "dataset":"content_audit_record_v1",
            "search_session_id":command.search_session_id,
            "content_audit_object_id":object_id
        });
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let source_exists = sqlx::query(
            "SELECT object.id FROM security.content_audit_search_session session \
             JOIN security.content_audit_search_candidate candidate ON candidate.search_session_id=session.id \
             JOIN security.content_audit_object object ON object.id=candidate.content_audit_object_id \
             WHERE session.id=$1 AND session.actor_user_id=$2 AND session.management_session_id=$3 \
               AND session.expires_at>clock_timestamp() AND candidate.content_audit_object_id=$4 \
               AND object.scope_code='full_encrypted' AND object.storage_state_code='finalized' \
               AND object.state_code IN ('active','held') AND object.deleted_at IS NULL \
               AND (object.state_code='held' OR object.legal_hold_count>0 OR object.expires_at>clock_timestamp()) \
             FOR SHARE OF session,object",
        )
        .bind(command.search_session_id)
        .bind(actor_id)
        .bind(management_session_id)
        .bind(object_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if source_exists.is_none() {
            return Err(ManagementBackendError::NotFound);
        }
        lock_content_audit_execution_approval(
            &mut transaction,
            principal,
            command.approval_case_id,
            "content_export",
            &scope_id,
            &digest,
        )
        .await?;
        consume_step_up_in(
            &mut transaction,
            principal,
            command.step_up_grant_id,
            "content_audit_access",
        )
        .await?;
        let consumed = sqlx::query(
            "UPDATE security.approval_case SET state_code='consumed',consumed_at=clock_timestamp(),revision=revision+1 \
             WHERE id=$1 AND state_code='approved' AND consumed_at IS NULL RETURNING id",
        )
        .bind(command.approval_case_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if consumed.is_none() {
            return Err(ManagementBackendError::Precondition);
        }
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'content_audit_export_generate',$2,'scheduled',1,$3,clock_timestamp(),0,0,5, \
                     clock_timestamp(),clock_timestamp()) RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("content-audit-export:{export_id}"))
        .bind(json!({"export_job_id":export_id}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,'scheduled',0,'content_audit_export_scheduled','{}'::jsonb,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO ops.export_job \
             (id,requested_by,scope_code,query,state_code,created_at,durable_job_id,dataset_code,format_code, \
              query_sha256,download_count,revision) \
             VALUES ($1,$2,'all',$3,'queued',clock_timestamp(),$4,'content_audit_record_v1','raw',$5,0,1)",
        )
        .bind(export_id)
        .bind(actor_id)
        .bind(&query)
        .bind(job_id)
        .bind(digest.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO security.content_audit_export_binding \
             (export_job_id,content_audit_object_id,search_session_id,execution_approval_case_id,actor_user_id, \
              management_session_id,execution_step_up_grant_id,action_snapshot_digest,reason,created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp())",
        )
        .bind(export_id)
        .bind(object_id)
        .bind(command.search_session_id)
        .bind(command.approval_case_id)
        .bind(actor_id)
        .bind(management_session_id)
        .bind(command.step_up_grant_id)
        .bind(digest.as_slice())
        .bind(reason)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO security.content_audit_access \
             (id,content_audit_object_id,actor_user_id,approval_case_id,action_code,occurred_at, \
              search_session_id,management_session_id) \
             VALUES ($1,$2,$3,$4,'export',clock_timestamp(),$5,$6)",
        )
        .bind(Uuid::now_v7())
        .bind(object_id)
        .bind(actor_id)
        .bind(command.approval_case_id)
        .bind(command.search_session_id)
        .bind(management_session_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "content_audit_export_scheduled",
                    "content_audit_export",
                    export_id,
                    1,
                    json!({"object_id":object_id,"search_session_id":command.search_session_id,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::ACCEPTED,
            body: json!({"data":{"id":export_id,"job_id":job_id,"dataset":"content_audit_record_v1","format":"raw","state":"queued","revision":1,"created_at":created_at},"meta":{}}),
            etag: Some("\"rev-1\"".into()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn list_legal_holds(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT h.id,h.name,h.reason,h.state_code,h.review_due_at::text AS review_due_at, \
                    h.last_reviewed_at::text AS last_reviewed_at,h.created_at::text AS created_at,h.revision, \
                    count(o.object_id)::bigint AS active_object_count \
             FROM security.legal_hold h LEFT JOIN security.legal_hold_object o \
               ON o.legal_hold_id=h.id AND o.released_at IS NULL \
             GROUP BY h.id ORDER BY h.created_at DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(legal_hold_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn get_legal_hold(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT h.id,h.name,h.reason,h.state_code,h.review_due_at::text AS review_due_at, \
                    h.last_reviewed_at::text AS last_reviewed_at,h.created_at::text AS created_at,h.revision, \
                    count(o.object_id)::bigint AS active_object_count \
             FROM security.legal_hold h LEFT JOIN security.legal_hold_object o \
               ON o.legal_hold_id=h.id AND o.released_at IS NULL \
             WHERE h.id=$1 GROUP BY h.id",
        )
        .bind(path_uuid(request, "id")?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision = required(&row, "revision")?;
        Ok(single_response(&legal_hold_projection(&row)?, revision))
    }

    async fn create_legal_hold(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: LegalHoldCreateCommand = deserialize_body(request)?;
        if command.name.trim().is_empty()
            || command.reason.trim().is_empty()
            || command.objects.is_empty()
            || command.objects.len() > 10_000
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let approval_id = parse_input_uuid(&command.approval_case_id)?;
        let hold_id = Uuid::now_v7();
        let object_ids = command
            .objects
            .iter()
            .map(|item| parse_input_uuid(&item.content_audit_object_id))
            .collect::<Result<Vec<_>, _>>()?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        consume_approved_case(
            &mut transaction,
            approval_id,
            "legal_hold",
            "legal_hold",
            &format!("new:{}", command.name.trim().to_ascii_lowercase()),
        )
        .await?;
        let locked_objects = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM security.content_audit_object \
             WHERE id=ANY($1) AND state_code IN ('active','held') AND storage_state_code='finalized' \
             ORDER BY id FOR UPDATE",
        )
        .bind(&object_ids)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if locked_objects.len() != object_ids.len() {
            return Err(ManagementBackendError::Precondition);
        }
        sqlx::query(
            "INSERT INTO security.legal_hold \
             (id,name,reason,state_code,created_by,created_at,revision,approval_case_id,review_due_at) \
             VALUES ($1,$2,$3,'active',$4,clock_timestamp(),1,$5, \
                     COALESCE(CASE WHEN $6::text IS NULL THEN NULL ELSE $6::timestamptz END,clock_timestamp()+interval '90 days'))",
        )
        .bind(hold_id)
        .bind(command.name.trim())
        .bind(command.reason.trim())
        .bind(parse_uuid(&principal.user_id)?)
        .bind(approval_id)
        .bind(command.review_due_at.as_deref())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        for object_id in &object_ids {
            sqlx::query(
                "INSERT INTO security.legal_hold_object \
                 (legal_hold_id,object_type_code,object_id,created_at) \
                 VALUES ($1,'content_audit_object',$2,clock_timestamp())",
            )
            .bind(hold_id)
            .bind(object_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        sqlx::query(
            "UPDATE security.content_audit_object SET legal_hold_count=legal_hold_count+1,state_code='held' \
             WHERE id=ANY($1)",
        )
        .bind(&object_ids)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "legal_hold_created",
                    "legal_hold",
                    hold_id,
                    1,
                    json!({"object_count":object_ids.len(),"reason":command.reason.trim()}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":hold_id,"name":command.name.trim(),"state":"active","active_object_count":object_ids.len(),"revision":1},"meta":{}}),
            etag: Some("\"rev-1\"".into()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn legal_hold_action(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        release: bool,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: LegalHoldActionCommand = deserialize_body(request)?;
        if command.reason.trim().is_empty() || command.expected_revision < 1 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let hold_id = path_uuid(request, "id")?;
        let approval_id = parse_input_uuid(&command.approval_case_id)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        consume_approved_case(
            &mut transaction,
            approval_id,
            "legal_hold",
            "legal_hold",
            &hold_id.to_string(),
        )
        .await?;
        let next_revision = command.expected_revision + 1;
        if release {
            let update = sqlx::query(
                "UPDATE security.legal_hold SET state_code='released',released_by=$2,released_at=clock_timestamp(), \
                   revision=revision+1 WHERE id=$1 AND state_code='active' AND revision=$3",
            )
            .bind(hold_id)
            .bind(parse_uuid(&principal.user_id)?)
            .bind(command.expected_revision)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            if update.rows_affected() != 1 {
                return Err(ManagementBackendError::Precondition);
            }
            let object_ids = sqlx::query_scalar::<_, Uuid>(
                "SELECT object_id::uuid FROM security.legal_hold_object \
                 WHERE legal_hold_id=$1 AND object_type_code='content_audit_object' AND released_at IS NULL FOR UPDATE",
            )
            .bind(hold_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                "UPDATE security.legal_hold_object SET released_at=clock_timestamp() \
                 WHERE legal_hold_id=$1 AND released_at IS NULL",
            )
            .bind(hold_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                "UPDATE security.content_audit_object SET legal_hold_count=legal_hold_count-1, \
                   state_code=CASE WHEN legal_hold_count=1 THEN 'active' ELSE 'held' END \
                 WHERE id=ANY($1) AND legal_hold_count>0",
            )
            .bind(&object_ids)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        } else {
            let update = sqlx::query(
                "UPDATE security.legal_hold SET last_reviewed_at=clock_timestamp(), \
                   review_due_at=clock_timestamp()+interval '90 days',revision=revision+1 \
                 WHERE id=$1 AND state_code='active' AND revision=$2",
            )
            .bind(hold_id)
            .bind(command.expected_revision)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            if update.rows_affected() != 1 {
                return Err(ManagementBackendError::Precondition);
            }
        }
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    if release {
                        "legal_hold_released"
                    } else {
                        "legal_hold_reviewed"
                    },
                    "legal_hold",
                    hold_id,
                    next_revision,
                    json!({"reason":command.reason.trim()}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse::ok(json!({
            "data":{"id":hold_id,"state":if release {"released"} else {"active"},"revision":next_revision},"meta":{}
        })))
    }

    async fn create_content_purge_job(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: ContentPurgeCommand = deserialize_body(request)?;
        if command.reason.trim().is_empty() || command.object_ids.is_empty() || command.object_ids.len() > 10_000 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let approval_id = parse_input_uuid(&command.approval_case_id)?;
        let mut object_ids = command
            .object_ids
            .iter()
            .map(|value| parse_input_uuid(value))
            .collect::<Result<Vec<_>, _>>()?;
        object_ids.sort_unstable();
        object_ids.dedup();
        let framed = object_ids.iter().map(Uuid::to_string).collect::<Vec<_>>().join("\n");
        let scope_id = format!("batch:sha256:{:x}", Sha256::digest(framed.as_bytes()));
        let job_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        consume_approved_case(
            &mut transaction,
            approval_id,
            "manual_delete",
            "content_audit_batch",
            &scope_id,
        )
        .await?;
        let eligible: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM security.content_audit_object \
             WHERE id=ANY($1) AND state_code IN ('active','deletion_pending') AND legal_hold_count=0",
        )
        .bind(&object_ids)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if usize::try_from(eligible).ok() != Some(object_ids.len()) {
            return Err(ManagementBackendError::Precondition);
        }
        sqlx::query(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'content_audit_purge',$2,'scheduled',1,$3,clock_timestamp(),0,0,20,clock_timestamp(),clock_timestamp())",
        )
        .bind(job_id)
        .bind(&scope_id)
        .bind(json!({"object_ids":object_ids,"reason":command.reason.trim(),"requested_by":principal.user_id.as_ref()}))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "content_audit_purge_scheduled",
                    "durable_job",
                    job_id,
                    1,
                    json!({"scope_id":scope_id,"object_count":object_ids.len()}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::ACCEPTED,
            body: json!({"data":{"id":job_id,"kind":"content_audit_purge","state":"scheduled"},"meta":{}}),
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn create_business_key_rotation_job(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let command: KeyRotationCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        if !(1..=1_000).contains(&command.batch_size) || command.expected_key_version < 1 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let approval_id = parse_input_uuid(&command.approval_case_id)?;
        let step_up_id = parse_input_uuid(&command.step_up_grant_id)?;
        let snapshot_digest = business_key_rotation_snapshot_digest(command.expected_key_version, command.batch_size)?;
        let job_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        consume_step_up_in(&mut transaction, principal, step_up_id, "key_provider_change").await?;
        consume_approved_case_bound(
            &mut transaction,
            approval_id,
            "key_provider_change",
            "business_key_provider",
            "database",
            &snapshot_digest,
        )
        .await?;
        let (old_key_version, new_key_version) = self
            .storage
            .activate_database_business_key_in(&mut transaction, Some(command.expected_key_version))
            .await
            .map_err(|error| map_storage_error(&error))?;
        let rotation_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ops.durable_job WHERE kind_code='business_key_rotation' \
             AND state_code IN ('scheduled','leased','retry_wait'))",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if rotation_exists {
            return Err(ManagementBackendError::Precondition);
        }
        let payload = json!({
            "schema_version":1,
            "provider":"database",
            "old_key_version":old_key_version,
            "new_key_version":new_key_version,
            "batch_size":command.batch_size,
            "approval_case_id":approval_id,
            "requested_by":principal.user_id.as_ref(),
            "reason":reason
        });
        sqlx::query(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,checkpoint,run_after, \
              lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'business_key_rotation',$2,'scheduled',1,$3,$4,clock_timestamp(),0,0,20,clock_timestamp(),clock_timestamp())",
        )
        .bind(job_id)
        .bind(format!("approval:{approval_id}"))
        .bind(&payload)
        .bind(json!({
            "schema_version":1,
            "phase":"rewrapping",
            "after_secret_id":null,
            "rewrapped":0,
            "cas_conflicts":0,
            "remaining_old_references":null
        }))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,NULL,'scheduled',0,'created',$3,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(json!({"old_key_version":old_key_version,"new_key_version":new_key_version}))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "business_key_rotation_scheduled",
                    "durable_job",
                    job_id,
                    1,
                    json!({
                        "provider":"database",
                        "old_key_version":old_key_version,
                        "new_key_version":new_key_version,
                        "batch_size":command.batch_size,
                        "approval_case_id":approval_id,
                        "reason":reason
                    }),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::ACCEPTED,
            body: json!({"data":{
                "id":job_id,
                "kind":"business_key_rotation",
                "state":"scheduled",
                "old_key_version":old_key_version,
                "new_key_version":new_key_version
            },"meta":{}}),
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn create_business_key_lifecycle_job(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: KeyLifecycleCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        if command.key_version < 1 || !matches!(command.target_state.as_str(), "retired" | "destroyed") {
            return Err(ManagementBackendError::InvalidInput);
        }
        let approval_id = parse_input_uuid(&command.approval_case_id)?;
        let step_up_id = parse_input_uuid(&command.step_up_grant_id)?;
        let rotation_job_id = parse_input_uuid(&command.rotation_job_id)?;
        let backup_run_id = parse_input_uuid(&command.backup_run_id)?;
        let restore_drill_id = parse_input_uuid(&command.restore_drill_id)?;
        let snapshot_digest = business_key_lifecycle_snapshot_digest(
            command.key_version,
            &command.target_state,
            rotation_job_id,
            backup_run_id,
            restore_drill_id,
        )?;
        let job_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        consume_step_up_in(
            &mut transaction,
            principal,
            step_up_id,
            if command.target_state == "destroyed" {
                "irreversible_lifecycle"
            } else {
                "key_provider_change"
            },
        )
        .await?;
        consume_approved_case_bound(
            &mut transaction,
            approval_id,
            "key_provider_change",
            "business_key_version",
            &format!("database:{}", command.key_version),
            &snapshot_digest,
        )
        .await?;
        let checksum = business_key_lifecycle_evidence_in(
            &mut transaction,
            command.key_version,
            &command.target_state,
            rotation_job_id,
            backup_run_id,
            restore_drill_id,
        )
        .await?;
        let references: i64 = sqlx::query_scalar(
            "SELECT \
               (SELECT count(*) FROM security.encrypted_secret \
                WHERE provider_role_code='business' AND key_version=$1 AND destroyed_at IS NULL) \
               + (SELECT count(*) FROM ops.export_job WHERE key_version=$1 AND wrapped_dek IS NOT NULL)",
        )
        .bind(command.key_version)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if references != 0 {
            return Err(ManagementBackendError::Precondition);
        }
        let active_job: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ops.durable_job \
             WHERE kind_code='business_key_lifecycle' AND state_code IN ('scheduled','leased','retry_wait') \
               AND (payload->>'key_version')::bigint=$1)",
        )
        .bind(command.key_version)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if active_job {
            return Err(ManagementBackendError::Precondition);
        }
        let payload = json!({
            "schema_version":1,
            "provider":"database",
            "key_version":command.key_version,
            "target_state":command.target_state,
            "rotation_job_id":rotation_job_id,
            "backup_run_id":backup_run_id,
            "restore_drill_id":restore_drill_id,
            "approval_case_id":approval_id,
            "requested_by":principal.user_id.as_ref(),
            "reason":reason
        });
        sqlx::query(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,checkpoint,run_after, \
              lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'business_key_lifecycle',$2,'scheduled',1,$3,$4,clock_timestamp(),0,0,10,clock_timestamp(),clock_timestamp())",
        )
        .bind(job_id)
        .bind(format!("approval:{approval_id}"))
        .bind(&payload)
        .bind(json!({"schema_version":1,"phase":"evidence_recheck"}))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,NULL,'scheduled',0,'created',$3,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(json!({"key_version":command.key_version,"target_state":command.target_state}))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if command.target_state == "destroyed" {
            let checksum: [u8; 32] = checksum
                .as_slice()
                .try_into()
                .map_err(|_| ManagementBackendError::Precondition)?;
            self.storage
                .append_deletion_ledger_in(
                    &mut transaction,
                    "business_key_material",
                    &format!("database:{}", command.key_version),
                    &checksum,
                    "scheduled",
                    &json!({"job_id":job_id,"backup_run_id":backup_run_id,"restore_drill_id":restore_drill_id}),
                )
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "business_key_lifecycle_scheduled",
                    "durable_job",
                    job_id,
                    1,
                    json!({
                        "provider":"database","key_version":command.key_version,
                        "target_state":command.target_state,"rotation_job_id":rotation_job_id,
                        "backup_run_id":backup_run_id,"restore_drill_id":restore_drill_id,
                        "approval_case_id":approval_id,"reason":reason
                    }),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::ACCEPTED,
            body: json!({"data":{
                "id":job_id,"kind":"business_key_lifecycle","state":"scheduled",
                "key_version":command.key_version,"target_state":command.target_state
            },"meta":{}}),
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn change_password(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: PasswordChangeCommand = deserialize_body(request)?;
        let current_password = SecretValue::new(command.current_password);
        let new_password = SecretValue::new(command.new_password);
        let new_password_length = new_password.expose().chars().count();
        if !(14..=128).contains(&new_password_length) {
            return Err(ManagementBackendError::InvalidInput);
        }
        let user_id = parse_uuid(&principal.user_id)?;
        let row = sqlx::query(
            "SELECT p.id,p.password_phc FROM iam.user_account u JOIN iam.password_credential p ON p.id=u.password_credential_id \
             WHERE u.id=$1 AND p.superseded_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Authentication)?;
        let old_id: Uuid = row.try_get("id").map_err(|_| ManagementBackendError::Unavailable)?;
        let phc: String = row
            .try_get("password_phc")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if !verify_password(&current_password, &SecretValue::new(phc))
            .map_err(|_| ManagementBackendError::Authentication)?
        {
            return Err(ManagementBackendError::Authentication);
        }
        let new_phc = hash_bootstrap_password(&new_password).map_err(|_| ManagementBackendError::Unavailable)?;
        let new_id = Uuid::now_v7();
        let session_id = parse_uuid(&principal.session_id)?;
        let (rotated_token, rotated_digest, rotated_csrf) = self.fresh_session_material()?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let superseded = sqlx::query(
            "UPDATE iam.password_credential SET superseded_at=clock_timestamp() WHERE id=$1 AND superseded_at IS NULL",
        )
        .bind(old_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if superseded.rows_affected() != 1 {
            return Err(ManagementBackendError::Precondition);
        }
        sqlx::query(
            "INSERT INTO iam.password_credential \
             (id,user_id,password_phc,parameters_version,created_at,last_changed_at,force_change) \
             VALUES ($1,$2,$3,1,clock_timestamp(),clock_timestamp(),false)",
        )
        .bind(new_id)
        .bind(user_id)
        .bind(new_phc.expose())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("UPDATE iam.user_account SET password_credential_id=$2,updated_at=clock_timestamp(),revision=revision+1 WHERE id=$1")
            .bind(user_id)
            .bind(new_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("UPDATE iam.management_session SET revoked_at=clock_timestamp() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL")
            .bind(user_id)
            .bind(session_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "UPDATE iam.management_session SET token_digest=$2,digest_key_version=1,session_revision=session_revision+1 \
             WHERE id=$1 AND user_id=$3 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .bind(rotated_digest.as_slice())
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({"data":{"id":user_id,"password_changed":true,"csrf_token":rotated_csrf.expose()},"meta":{}}),
            etag: None,
            session_cookie: Some(rotated_token),
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn list_users(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT id,username,display_name,email,role_code,status_code,revision,created_at::text AS created_at,updated_at::text AS updated_at \
             FROM iam.user_account ORDER BY created_at DESC,id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(user_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn create_user(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: UserCreateCommand = deserialize_body(request)?;
        if command.role != "key_owner"
            || command.username.trim().is_empty()
            || command.username.len() > 128
            || command.display_name.trim().is_empty()
            || command.email.trim().is_empty()
            || !(14..=128).contains(&command.temporary_password.chars().count())
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let user_id = Uuid::now_v7();
        let password_id = Uuid::now_v7();
        let password = hash_bootstrap_password(&SecretValue::new(command.temporary_password)).map_err(|error| {
            tracing::error!(error = ?error, "user creation password hashing failed");
            ManagementBackendError::Unavailable
        })?;
        let mut transaction = self.storage.pool().begin().await.map_err(|error| {
            tracing::error!(
                database_code = error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .as_deref()
                    .unwrap_or("unknown"),
                "user creation transaction start failed"
            );
            ManagementBackendError::Unavailable
        })?;
        sqlx::query(
            "INSERT INTO iam.user_account \
             (id,username,username_normalized,display_name,email,email_normalized,role_code,status_code,password_credential_id,revision,created_at,updated_at) \
             VALUES ($1,$2,lower($2),$3,$4,lower($4),'key_owner','mfa_pending',$5,1,clock_timestamp(),clock_timestamp())",
        )
        .bind(user_id)
        .bind(command.username.trim())
        .bind(command.display_name.trim())
        .bind(command.email.trim())
        .bind(password_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        sqlx::query(
            "INSERT INTO iam.password_credential \
             (id,user_id,password_phc,parameters_version,created_at,last_changed_at,force_change) \
             VALUES ($1,$2,$3,1,clock_timestamp(),clock_timestamp(),true)",
        )
        .bind(password_id)
        .bind(user_id)
        .bind(password.expose())
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            tracing::error!(
                database_code = error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .as_deref()
                    .unwrap_or("unknown"),
                "user password credential insert failed"
            );
            ManagementBackendError::Unavailable
        })?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "user_created",
                    "user_account",
                    user_id,
                    1,
                    json!({"role":"key_owner","status":"mfa_pending"}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":user_id,"username":command.username.trim(),"display_name":command.display_name.trim(),"email":command.email.trim(),"role":"key_owner","status":"mfa_pending","revision":1},"meta":{}}),
            etag: Some("\"rev-1\"".into()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn patch_user(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: UserPatchCommand = deserialize_body(request)?;
        if command
            .display_name
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
            || command.email.as_ref().is_some_and(|value| value.trim().is_empty())
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let revision = request_revision(request)?;
        let row = sqlx::query(
            "UPDATE iam.user_account SET display_name=COALESCE($3,display_name),email=COALESCE($4,email), \
                    email_normalized=CASE WHEN $4::text IS NULL THEN email_normalized ELSE lower($4) END, \
                    revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND status_code<>'archived' \
             RETURNING id,username,display_name,email,role_code,status_code,revision,created_at::text AS created_at,updated_at::text AS updated_at",
        )
        .bind(path_uuid(request, "id")?)
        .bind(revision)
        .bind(command.display_name.as_deref().map(str::trim))
        .bind(command.email.as_deref().map(str::trim))
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Precondition)?
        .ok_or(ManagementBackendError::Precondition)?;
        let next_revision: i64 = required(&row, "revision")?;
        Ok(single_response(&user_projection(&row)?, next_revision))
    }

    async fn user_lifecycle(
        &self,
        request: &ManagementRequest,
        action: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let id = path_uuid(request, "id")?;
        let revision = request_revision(request)?;
        let target = match action {
            "disable" => "disabled",
            "archive" => "archived",
            "reactivate" | "unlock" => "active",
            _ => return Err(ManagementBackendError::InvalidInput),
        };
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let update = sqlx::query(
            "UPDATE iam.user_account SET status_code=CASE WHEN $3='active' AND ( \
                    NOT EXISTS(SELECT 1 FROM iam.mfa_enrollment m WHERE m.user_id=$1 AND m.state_code='verified') OR \
                    EXISTS(SELECT 1 FROM iam.password_credential p WHERE p.id=password_credential_id AND p.force_change) \
                  ) THEN 'mfa_pending' ELSE $3 END, \
                  archived_at=CASE WHEN $3='archived' THEN clock_timestamp() ELSE NULL END, \
                  revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 AND revision=$2 AND role_code='key_owner'",
        )
        .bind(id)
        .bind(revision)
        .bind(target)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if update.rows_affected() != 1 {
            return Err(ManagementBackendError::Precondition);
        }
        if matches!(action, "disable" | "archive") {
            sqlx::query(
                "UPDATE iam.management_session SET revoked_at=COALESCE(revoked_at,clock_timestamp()),session_revision=session_revision+1 \
                 WHERE user_id=$1 AND revoked_at IS NULL",
            )
            .bind(id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.reload_management_runtime().await?;
        Ok(ManagementBackendResponse::ok(
            json!({"data":{"id":id,"status":target,"revision":revision+1},"meta":{}}),
        ))
    }

    async fn get_user(&self, request: &ManagementRequest) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let id = path_uuid(request, "id")?;
        let row = sqlx::query(
            "SELECT id,username,display_name,email,role_code,status_code,revision,created_at::text AS created_at,updated_at::text AS updated_at \
             FROM iam.user_account WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision: i64 = row
            .try_get("revision")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(&user_projection(&row)?, revision))
    }

    async fn list_platform_keys(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT k.id,k.owner_user_id,k.group_id,k.name,k.status_code,k.expires_at::text AS expires_at, \
                    k.revision,k.created_at::text AS created_at,k.updated_at::text AS updated_at,s.display_prefix, \
                    c.max_concurrency,c.messages_rpm,c.models_rpm,c.max_body_bytes,c.audit_mode_code \
             FROM iam.platform_key k JOIN security.encrypted_secret s ON s.id=k.secret_id \
             LEFT JOIN iam.platform_key_active_config a ON a.platform_key_id=k.id \
             LEFT JOIN iam.platform_key_config c ON c.id=a.config_id \
             WHERE ($1 OR k.owner_user_id=$2) ORDER BY k.created_at DESC,k.id DESC LIMIT 100",
        )
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .map(platform_key_projection)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn get_platform_key(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT k.id,k.owner_user_id,k.group_id,k.name,k.status_code,k.expires_at::text AS expires_at, \
                    k.revision,k.created_at::text AS created_at,k.updated_at::text AS updated_at,s.display_prefix, \
                    c.max_concurrency,c.messages_rpm,c.models_rpm,c.max_body_bytes,c.audit_mode_code \
             FROM iam.platform_key k JOIN security.encrypted_secret s ON s.id=k.secret_id \
             LEFT JOIN iam.platform_key_active_config a ON a.platform_key_id=k.id \
             LEFT JOIN iam.platform_key_config c ON c.id=a.config_id \
             WHERE k.id=$1 AND ($2 OR k.owner_user_id=$3)",
        )
        .bind(path_uuid(request, "id")?)
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision: i64 = row
            .try_get("revision")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(&platform_key_projection(&row)?, revision))
    }

    async fn list_platform_key_audit_events(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let key_id = path_uuid(request, "id")?;
        let owner_id = parse_uuid(&principal.user_id)?;
        let visible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM iam.platform_key WHERE id=$1 AND ($2 OR owner_user_id=$3))",
        )
        .bind(key_id)
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(owner_id)
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if !visible {
            return Err(ManagementBackendError::NotFound);
        }
        let rows = sqlx::query(
            "SELECT event_id,event_day::text AS event_day,daily_sequence,actor_type_code,actor_id,action_code, \
                    object_type_code,object_id,outcome_code,canonical_redacted_event,occurred_at::text AS occurred_at \
             FROM security.audit_event \
             WHERE (object_type_code='platform_key' AND object_id=$1::text) \
                OR (actor_type_code='platform_key' AND actor_id=$1) \
             ORDER BY occurred_at DESC,event_id DESC LIMIT 100",
        )
        .bind(key_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(audit_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn get_platform_key_client_config(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT k.id,k.name,k.status_code,k.revision,s.display_prefix,c.id AS config_id,c.config_version, \
                    c.messages_enabled,c.models_enabled,c.max_body_bytes,c.messages_rpm,c.messages_burst, \
                    c.models_rpm,c.models_burst,c.max_concurrency,c.audit_mode_code \
             FROM iam.platform_key k JOIN security.encrypted_secret s ON s.id=k.secret_id \
             JOIN iam.platform_key_active_config a ON a.platform_key_id=k.id \
             JOIN iam.platform_key_config c ON c.id=a.config_id \
             WHERE k.id=$1 AND ($2 OR k.owner_user_id=$3)",
        )
        .bind(path_uuid(request, "id")?)
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let key_id = required::<Uuid>(&row, "id")?;
        let revision = required::<i64>(&row, "revision")?;
        Ok(single_response(
            &json!({
                "id":key_id,
                "platform_key_id":key_id,
                "name":required::<String>(&row,"name")?,
                "display_prefix":required::<Option<String>>(&row,"display_prefix")?,
                "status":required::<String>(&row,"status_code")?,
                "template_kind":"claude_code_environment",
                "contains_secret":false,
                "environment":{
                    "ANTHROPIC_BASE_URL":"${GATEWAY_BASE_URL}",
                    "ANTHROPIC_AUTH_TOKEN":"${PLATFORM_KEY}"
                },
                "active_config":{
                    "id":required::<Uuid>(&row,"config_id")?,
                    "version":required::<i64>(&row,"config_version")?,
                    "messages_enabled":required::<bool>(&row,"messages_enabled")?,
                    "models_enabled":required::<bool>(&row,"models_enabled")?,
                    "max_body_bytes":required::<i64>(&row,"max_body_bytes")?,
                    "messages_rpm":required::<i32>(&row,"messages_rpm")?,
                    "messages_burst":required::<i32>(&row,"messages_burst")?,
                    "models_rpm":required::<i32>(&row,"models_rpm")?,
                    "models_burst":required::<i32>(&row,"models_burst")?,
                    "max_concurrency":required::<i32>(&row,"max_concurrency")?,
                    "audit_mode":required::<String>(&row,"audit_mode_code")?
                }
            }),
            revision,
        ))
    }

    async fn list_platform_key_config_versions(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let key_id = path_uuid(request, "id")?;
        let visible: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM iam.platform_key WHERE id=$1 AND ($2 OR owner_user_id=$3))",
        )
        .bind(key_id)
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if !visible {
            return Err(ManagementBackendError::NotFound);
        }
        let rows = sqlx::query(
            "SELECT c.id,c.platform_key_id,c.config_version,c.content_hash,c.messages_enabled,c.models_enabled, \
                    c.max_body_bytes,c.messages_rpm,c.messages_burst,c.models_rpm,c.models_burst,c.max_concurrency, \
                    c.ruleset_artifact_id,c.audit_mode_code,c.content_audit_approval_case_id, \
                    c.content_audit_expires_at::text AS content_audit_expires_at,c.created_by,c.created_at::text AS created_at, \
                    COALESCE(ARRAY(SELECT a.model_id FROM iam.platform_key_model_allowlist a \
                                   WHERE a.platform_key_config_id=c.id ORDER BY a.model_id),'{}'::uuid[]) AS model_allowlist, \
                    COALESCE(ARRAY(SELECT a.network::text FROM iam.platform_key_ip_allowlist a \
                                   WHERE a.platform_key_config_id=c.id ORDER BY a.network::text),'{}'::text[]) AS ip_allowlist, \
                    (active.config_id=c.id) AS is_active,active.revision AS pointer_revision \
             FROM iam.platform_key_config c \
             LEFT JOIN iam.platform_key_active_config active ON active.platform_key_id=c.platform_key_id \
             WHERE c.platform_key_id=$1 ORDER BY c.config_version DESC LIMIT 100",
        )
        .bind(key_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "id":required::<Uuid>(row,"id")?,
                    "platform_key_id":required::<Uuid>(row,"platform_key_id")?,
                    "version":required::<i64>(row,"config_version")?,
                    "content_sha256":lower_hex(&required::<Vec<u8>>(row,"content_hash")?),
                    "messages_enabled":required::<bool>(row,"messages_enabled")?,
                    "models_enabled":required::<bool>(row,"models_enabled")?,
                    "max_body_bytes":required::<i64>(row,"max_body_bytes")?,
                    "messages_rate":{"rpm":required::<i32>(row,"messages_rpm")?,"burst":required::<i32>(row,"messages_burst")?},
                    "models_rate":{"rpm":required::<i32>(row,"models_rpm")?,"burst":required::<i32>(row,"models_burst")?},
                    "max_concurrency":required::<i32>(row,"max_concurrency")?,
                    "ruleset_artifact_id":required::<Option<Uuid>>(row,"ruleset_artifact_id")?,
                    "model_allowlist":required::<Vec<Uuid>>(row,"model_allowlist")?,
                    "ip_allowlist":required::<Vec<String>>(row,"ip_allowlist")?,
                    "audit_mode":required::<String>(row,"audit_mode_code")?,
                    "content_audit_approval_case_id":required::<Option<Uuid>>(row,"content_audit_approval_case_id")?,
                    "content_audit_expires_at":required::<Option<String>>(row,"content_audit_expires_at")?,
                    "created_by":required::<Option<Uuid>>(row,"created_by")?,
                    "created_at":required::<String>(row,"created_at")?,
                    "is_active":required::<bool>(row,"is_active")?,
                    "pointer_revision":required::<Option<i64>>(row,"pointer_revision")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        Ok(list_response(&data))
    }

    async fn patch_platform_key(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command = parse_platform_key_patch(request)?;
        let key_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        let owner_id = parse_uuid(&principal.user_id)?;
        let (expires_present, expires_at) = match &command.expires_at {
            ExpirationPatch::Unchanged => (false, None),
            ExpirationPatch::Clear => (true, None),
            ExpirationPatch::Set(value) => (true, Some(value.as_str())),
        };
        if let Some(value) = expires_at {
            let future: bool = sqlx::query_scalar("SELECT $1::timestamptz > clock_timestamp()")
                .bind(value)
                .fetch_one(&self.storage.pool())
                .await
                .map_err(|_| ManagementBackendError::InvalidInput)?;
            if !future {
                return Err(ManagementBackendError::InvalidInput);
            }
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let update = sqlx::query(
            "UPDATE iam.platform_key \
             SET name=CASE WHEN $4::text IS NULL THEN name ELSE $4 END, \
                 expires_at=CASE WHEN $5 THEN $6::timestamptz ELSE expires_at END, \
                 revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND ($3 OR owner_user_id=$7) AND status_code<>'revoked' \
             RETURNING revision",
        )
        .bind(key_id)
        .bind(expected_revision)
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(command.name.as_deref())
        .bind(expires_present)
        .bind(expires_at)
        .bind(owner_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?
        .ok_or(ManagementBackendError::Precondition)?;
        let next_revision: i64 = required(&update, "revision")?;
        let changed_fields = match (&command.name, &command.expires_at) {
            (Some(_), ExpirationPatch::Unchanged) => vec!["name"],
            (None, _) => vec!["expires_at"],
            (Some(_), _) => vec!["name", "expires_at"],
        };
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "platform_key_updated",
                    "platform_key",
                    key_id,
                    next_revision,
                    json!({"changed_fields":changed_fields}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "SELECT k.id,k.owner_user_id,k.group_id,k.name,k.status_code,k.expires_at::text AS expires_at, \
                    k.revision,k.created_at::text AS created_at,k.updated_at::text AS updated_at,s.display_prefix, \
                    c.max_concurrency,c.messages_rpm,c.models_rpm,c.max_body_bytes,c.audit_mode_code \
             FROM iam.platform_key k JOIN security.encrypted_secret s ON s.id=k.secret_id \
             LEFT JOIN iam.platform_key_active_config a ON a.platform_key_id=k.id \
             LEFT JOIN iam.platform_key_config c ON c.id=a.config_id WHERE k.id=$1",
        )
        .bind(key_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.reload_management_runtime().await?;
        Ok(single_response(&platform_key_projection(&row)?, next_revision))
    }

    async fn platform_key_lifecycle(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        target: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: LifecycleActionCommand = deserialize_body(request)?;
        let irreversible_grant = if target == "revoked" {
            required_action_reason(command.reason.as_deref())?;
            Some(parse_input_uuid(
                command
                    .step_up_grant_id
                    .as_deref()
                    .ok_or(ManagementBackendError::InvalidInput)?,
            )?)
        } else {
            if command
                .reason
                .as_deref()
                .is_some_and(|reason| reason.trim().is_empty() || reason.len() > 2_048)
            {
                return Err(ManagementBackendError::InvalidInput);
            }
            None
        };
        let id = path_uuid(request, "id")?;
        let revision = request_revision(request)?;
        if command.expected_revision.is_some_and(|expected| expected != revision) {
            return Err(ManagementBackendError::Precondition);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some(grant_id) = irreversible_grant {
            consume_step_up_in(&mut transaction, principal, grant_id, "irreversible_lifecycle").await?;
        }
        let row = sqlx::query(
            "UPDATE iam.platform_key SET status_code=$4, \
                 revoked_at=CASE WHEN $4='revoked' THEN clock_timestamp() ELSE revoked_at END, \
                 revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND ($3 OR owner_user_id=$5) AND \
               (($4='disabled' AND status_code='active') OR \
                ($4='active' AND status_code='disabled' AND (expires_at IS NULL OR expires_at>clock_timestamp())) OR \
                ($4='revoked' AND status_code IN ('active','disabled','expired'))) \
             RETURNING secret_id,revision",
        )
        .bind(id)
        .bind(revision)
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(target)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let next_revision: i64 = required(&row, "revision")?;
        if target == "revoked" {
            let secret_id: Uuid = required(&row, "secret_id")?;
            sqlx::query(
                "UPDATE security.encrypted_secret SET superseded_at=COALESCE(superseded_at,clock_timestamp()), \
                   destroyed_at=clock_timestamp(),ciphertext='\\x'::bytea,wrapped_dek='\\x'::bytea \
                 WHERE id=$1 AND destroyed_at IS NULL",
            )
            .bind(secret_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    match target {
                        "disabled" => "platform_key_disabled",
                        "active" => "platform_key_reactivated",
                        "revoked" => "platform_key_revoked",
                        _ => return Err(ManagementBackendError::InvalidInput),
                    },
                    "platform_key",
                    id,
                    next_revision,
                    json!({"status":target,"reason":command.reason.as_deref()}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.reload_management_runtime().await?;
        Ok(single_response(
            &json!({"id":id,"status":target,"revision":next_revision}),
            next_revision,
        ))
    }

    async fn list_groups(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT g.id,g.name,g.status_code,g.owner_executor_id,g.owner_generation,g.revision, \
                    g.created_at::text AS created_at,g.updated_at::text AS updated_at,COUNT(c.id)::bigint AS credential_count \
             FROM gateway.credential_group g LEFT JOIN gateway.anthropic_credential c ON c.group_id=g.id \
             GROUP BY g.id ORDER BY g.created_at DESC,g.id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(group_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn create_group(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: GroupCreateCommand = deserialize_body(request)?;
        if command.name.trim().is_empty() || command.name.len() > 128 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let group_id = Uuid::now_v7();
        let config_id = Uuid::now_v7();
        let enforcement_artifact_id = Uuid::now_v7();
        let enforcement_payload = json!({
            "name":"default-preserve",
            "payload":{
                "group_id":group_id.to_string(),
                "system":{"mode":"preserve"}
            },
            "source_refs":["builtin:group-default-v1"]
        });
        let enforcement_hash = Sha256::digest(canonical_json_bytes(&enforcement_payload)?).to_vec();
        let config_bytes = serde_json::to_vec(&json!({
            "default_rpm":60,"default_rpm_burst":10,"max_concurrency":null,"queue_timeout_ms":30000,
            "system_prompt_mode":"preserve","proxy_policy":"auto","model_scope":"all_published",
            "accepted_clients":["claude_code_cli","non_claude_code_cli"]
        }))
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let content_hash = lookup_digest(&self.session_digest_key, &SecretBytes::new(config_bytes))
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let actor = parse_uuid(&principal.user_id)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO gateway.credential_group \
             (id,name,status_code,owner_generation,revision,created_by,created_at,updated_at) \
             VALUES ($1,$2,'active',1,1,$3,clock_timestamp(),clock_timestamp())",
        )
        .bind(group_id)
        .bind(command.name.trim())
        .bind(actor)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        sqlx::query(
            "INSERT INTO catalog.versioned_artifact \
             (id,artifact_kind_code,scope_type_code,scope_id,artifact_version,lifecycle_code,payload,content_hash, \
              schema_version,created_by,created_at) \
             VALUES ($1,'enforcement','group',$2,1,'active',$3,$4,1,$5,clock_timestamp())",
        )
        .bind(enforcement_artifact_id)
        .bind(group_id)
        .bind(&enforcement_payload)
        .bind(&enforcement_hash)
        .bind(actor)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO catalog.artifact_rollout_evidence \
             (artifact_id,validation_report,validated_by,validated_at,deterministic_sample_count,revision,updated_at) \
             VALUES ($1,'{\"valid\":true,\"source\":\"group_create_defaults\"}'::jsonb,$2,clock_timestamp(),0,1,clock_timestamp())",
        )
        .bind(enforcement_artifact_id)
        .bind(actor)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO gateway.group_config \
             (id,group_id,config_version,content_hash,default_rpm,queue_timeout_ms,enforcement_artifact_id,system_prompt_mode_code,proxy_policy_code, \
              model_scope_code,created_by,created_at,default_rpm_burst,pre_upstream_wait_ms,preferred_capacity_wait_ms, \
              affinity_ttl_ms,affinity_migration_successes,quota_guard_basis_points,fully_managed_required,console_business_fallback_enabled, \
              lifecycle_code,validation_report,validated_at,published_at) \
             VALUES ($1,$2,1,$3,60,30000,$4,'preserve','auto','all_published',$5,clock_timestamp(),10,30000,2000,86400000,3,9500,false,false, \
                     'active','{\"valid\":true,\"source\":\"group_create_defaults\"}'::jsonb,clock_timestamp(),clock_timestamp())",
        )
        .bind(config_id)
        .bind(group_id)
        .bind(content_hash.as_slice())
        .bind(enforcement_artifact_id)
        .bind(actor)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        for client_class in ["claude_code_cli", "non_claude_code_cli"] {
            sqlx::query(
                "INSERT INTO gateway.group_accepted_client_class (group_config_id,client_class_code) VALUES ($1,$2)",
            )
            .bind(config_id)
            .bind(client_class)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        sqlx::query(
            "INSERT INTO gateway.group_active_config (group_id,config_id,revision,activated_by,activated_at) \
             VALUES ($1,$2,1,$3,clock_timestamp())",
        )
        .bind(group_id)
        .bind(config_id)
        .bind(actor)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO catalog.active_artifact_pointer \
             (id,artifact_kind_code,scope_type_code,scope_id,artifact_id,revision,activated_by,activated_at) \
             VALUES ($1,'enforcement','group',$2,$3,1,$4,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(group_id)
        .bind(enforcement_artifact_id)
        .bind(actor)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "credential_group_created",
                    "credential_group",
                    group_id,
                    1,
                    json!({"status":"active","config_version":1}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some(runtime) = &self.scheduler_runtime {
            match runtime.ensure_group_projection(group_id).await {
                Ok(true) => {}
                Ok(false) => tracing::warn!(
                    event = "group_runtime_install_deferred",
                    group_id = %group_id,
                    reason = "durable_owner_currently_unavailable"
                ),
                Err(error) => tracing::warn!(
                    event = "group_runtime_install_failed",
                    group_id = %group_id,
                    error = ?error
                ),
            }
        }
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":group_id,"name":command.name.trim(),"status":"active","revision":1,"active_config_version":1},"meta":{}}),
            etag: Some("\"rev-1\"".into()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn group_config_versions(
        &self,
        request: &ManagementRequest,
        exact_version: Option<i64>,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let group_id = path_uuid(request, "id")?;
        let rows = sqlx::query(
            "SELECT gc.id,gc.group_id,gc.config_version,gc.lifecycle_code,encode(gc.content_hash,'hex') AS content_hash, \
                    gc.default_rpm,gc.default_rpm_burst,gc.max_concurrency,gc.queue_capacity,gc.queue_timeout_ms, \
                    gc.pre_upstream_wait_ms,gc.preferred_capacity_wait_ms,gc.upstream_connect_ms, \
                    gc.upstream_non_stream_total_ms,gc.upstream_stream_idle_ms,gc.min_retry_budget_ms,gc.cancel_grace_ms, \
                    gc.queue_full_retry_after_ms,gc.queue_wait_retry_after_ms,gc.fully_managed_required,gc.proxy_policy_code, \
                    gc.default_credential_concurrency,gc.default_credential_rpm,gc.content_audit_policy_code, \
                    gc.content_audit_retention_days,gc.enforcement_artifact_id,gc.validation_report,gc.validated_at::text AS validated_at, \
                    gc.published_at::text AS published_at,gc.created_at::text AS created_at, \
                    COALESCE(array_agg(classes.client_class_code ORDER BY classes.client_class_code) \
                      FILTER (WHERE classes.client_class_code IS NOT NULL),ARRAY[]::text[]) AS accepted_clients, \
                    active.config_id=gc.id AS is_active,active.revision AS pointer_revision \
             FROM gateway.group_config gc \
             LEFT JOIN gateway.group_accepted_client_class classes ON classes.group_config_id=gc.id \
             LEFT JOIN gateway.group_active_config active ON active.group_id=gc.group_id \
             WHERE gc.group_id=$1 AND ($2::bigint IS NULL OR gc.config_version=$2) \
             GROUP BY gc.id,active.config_id,active.revision ORDER BY gc.config_version DESC LIMIT 100",
        )
        .bind(group_id)
        .bind(exact_version)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if exact_version.is_some() && rows.is_empty() {
            return Err(ManagementBackendError::NotFound);
        }
        let data = rows
            .iter()
            .map(group_config_projection)
            .collect::<Result<Vec<_>, _>>()?;
        if exact_version.is_some() {
            let item = data.into_iter().next().ok_or(ManagementBackendError::NotFound)?;
            let version = item["version"].as_i64().ok_or(ManagementBackendError::Unavailable)?;
            Ok(single_response(&item, version))
        } else {
            Ok(list_response(&data))
        }
    }

    async fn create_group_config_version(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: GroupConfigCandidateCommand = deserialize_body(request)?;
        validate_group_config_candidate(&command)?;
        let group_id = path_uuid(request, "id")?;
        let proxy_policy = group_proxy_policy(&command.egress_mode)?;
        let payload = serde_json::to_value(&command).map_err(|_| ManagementBackendError::Unavailable)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))")
            .bind(group_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let inherited = sqlx::query(
            "SELECT gc.config_version,gc.queue_capacity,gc.ruleset_artifact_id,gc.enforcement_artifact_id,gc.system_prompt_mode_code, \
                    gc.system_prompt_ref,gc.system_prompt_content,gc.model_scope_code,gc.console_business_fallback_enabled, \
                    gc.preferred_capacity_wait_ms,gc.affinity_ttl_ms,gc.affinity_migration_successes, \
                    gc.quota_guard_basis_points,gc.min_retry_budget_ms,gc.cancel_grace_ms, \
                    gc.queue_full_retry_after_ms,gc.queue_wait_retry_after_ms \
             FROM gateway.credential_group g JOIN gateway.group_active_config active ON active.group_id=g.id \
             JOIN gateway.group_config gc ON gc.id=active.config_id \
             WHERE g.id=$1 AND g.status_code='active' FOR UPDATE OF g,active",
        )
        .bind(group_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let version: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(config_version),0)+1 FROM gateway.group_config WHERE group_id=$1")
                .bind(group_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
        let normalized = json!({
            "candidate":payload,"inherits_active_version":required::<i64>(&inherited,"config_version")?
        });
        let content_hash = Sha256::digest(canonical_json_bytes(&normalized)?).to_vec();
        let config_id = Uuid::now_v7();
        let rpm = command
            .limits
            .messages_rpm
            .map(i32::try_from)
            .transpose()
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let burst = command
            .limits
            .messages_burst
            .map(i32::try_from)
            .transpose()
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        sqlx::query(
            "INSERT INTO gateway.group_config \
             (id,group_id,config_version,content_hash,default_rpm,default_rpm_burst,max_concurrency,queue_capacity, \
              queue_timeout_ms,pre_upstream_wait_ms,preferred_capacity_wait_ms,ruleset_artifact_id,enforcement_artifact_id,system_prompt_mode_code, \
              system_prompt_ref,system_prompt_content,proxy_policy_code,model_scope_code,created_by,created_at, \
              affinity_ttl_ms,affinity_migration_successes,quota_guard_basis_points,fully_managed_required, \
              console_business_fallback_enabled,upstream_connect_ms,upstream_non_stream_total_ms,upstream_stream_idle_ms, \
              min_retry_budget_ms,cancel_grace_ms,queue_full_retry_after_ms,queue_wait_retry_after_ms, \
              content_audit_policy_code,content_audit_retention_days,lifecycle_code,default_credential_concurrency, \
              default_credential_rpm) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,clock_timestamp(), \
                     $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,'draft',$33,$34)",
        )
        .bind(config_id)
        .bind(group_id)
        .bind(version)
        .bind(&content_hash)
        .bind(rpm)
        .bind(burst)
        .bind(command.limits.concurrency.map(i32::try_from).transpose().map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(required::<Option<i32>>(&inherited, "queue_capacity")?)
        .bind(i64::try_from(command.queue.pre_upstream_timeout_ms).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(required::<i64>(&inherited, "preferred_capacity_wait_ms")?)
        .bind(required::<Option<Uuid>>(&inherited, "ruleset_artifact_id")?)
        .bind(required::<Option<Uuid>>(&inherited, "enforcement_artifact_id")?)
        .bind(required::<String>(&inherited, "system_prompt_mode_code")?)
        .bind(required::<Option<String>>(&inherited, "system_prompt_ref")?)
        .bind(required::<Option<Value>>(&inherited, "system_prompt_content")?)
        .bind(proxy_policy)
        .bind(required::<String>(&inherited, "model_scope_code")?)
        .bind(parse_uuid(&principal.user_id)?)
        .bind(required::<i64>(&inherited, "affinity_ttl_ms")?)
        .bind(required::<i32>(&inherited, "affinity_migration_successes")?)
        .bind(required::<i32>(&inherited, "quota_guard_basis_points")?)
        .bind(command.fully_managed_required)
        .bind(required::<bool>(&inherited, "console_business_fallback_enabled")?)
        .bind(i64::try_from(command.timeouts.upstream_connect_ms).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i64::try_from(command.timeouts.upstream_non_stream_total_ms).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i64::try_from(command.timeouts.upstream_stream_idle_ms).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(required::<i64>(&inherited, "min_retry_budget_ms")?)
        .bind(required::<i64>(&inherited, "cancel_grace_ms")?)
        .bind(required::<i64>(&inherited, "queue_full_retry_after_ms")?)
        .bind(required::<i64>(&inherited, "queue_wait_retry_after_ms")?)
        .bind(&command.content_audit.policy)
        .bind(i32::from(command.content_audit.retention_days))
        .bind(i32::try_from(command.credential_defaults.concurrency).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i32::try_from(command.credential_defaults.messages_rpm).map_err(|_| ManagementBackendError::InvalidInput)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        for client in &command.accepted_client_classes {
            sqlx::query(
                "INSERT INTO gateway.group_accepted_client_class (group_config_id,client_class_code) VALUES ($1,$2)",
            )
            .bind(config_id)
            .bind(client)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        }
        sqlx::query(
            "INSERT INTO gateway.group_model_allowlist (group_config_id,model_id) \
             SELECT $1,model_id FROM gateway.group_model_allowlist source \
             JOIN gateway.group_active_config active ON active.config_id=source.group_config_id \
             WHERE active.group_id=$2",
        )
        .bind(config_id)
        .bind(group_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "group_config_candidate_created",
                    "group_config",
                    config_id,
                    version,
                    json!({"group_id":group_id,"version":version,"content_hash":lower_hex(&content_hash)}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut response = self.group_config_versions(request, Some(version)).await?;
        response.status = axum::http::StatusCode::CREATED;
        Ok(response)
    }

    async fn transition_group_config_version(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        action: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: LifecycleActionCommand = deserialize_body(request)?;
        let group_id = path_uuid(request, "id")?;
        let version = path_i64(request, "version")?;
        if request_revision(request)? != version
            || command.expected_revision.is_some_and(|expected| expected != version)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let reason = command.reason.as_deref().unwrap_or(action);
        if reason.trim().is_empty() || reason.len() > 2_048 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let target = sqlx::query(
            "SELECT id,lifecycle_code,fully_managed_required,proxy_policy_code FROM gateway.group_config \
             WHERE group_id=$1 AND config_version=$2 FOR UPDATE",
        )
        .bind(group_id)
        .bind(version)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let config_id = required::<Uuid>(&target, "id")?;
        let lifecycle = required::<String>(&target, "lifecycle_code")?;
        let next = match action {
            "validate" if lifecycle == "draft" => "validated",
            "publish_shadow" if matches!(lifecycle.as_str(), "validated" | "shadow") => "shadow",
            "promote_canary" if matches!(lifecycle.as_str(), "shadow" | "canary") => "canary",
            _ => return Err(ManagementBackendError::Precondition),
        };
        let non_managed: i64 = if required::<bool>(&target, "fully_managed_required")? {
            sqlx::query_scalar(
                "SELECT count(*) FROM gateway.anthropic_credential \
                 WHERE group_id=$1 AND lifecycle_state_code='active' AND management_class_code<>'fully_managed'",
            )
            .bind(group_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?
        } else {
            0
        };
        let proxy_capacity: bool = if required::<String>(&target, "proxy_policy_code")? == "proxy_required" {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM gateway.proxy_endpoint \
                 WHERE lifecycle_code='active' AND health_code='healthy' AND stability_code='static')",
            )
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?
        } else {
            true
        };
        if matches!(next, "shadow" | "canary") {
            sqlx::query(
                "UPDATE gateway.group_config SET lifecycle_code='validated' \
                 WHERE group_id=$1 AND lifecycle_code=$2 AND id<>$3",
            )
            .bind(group_id)
            .bind(next)
            .bind(config_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        let warnings = [
            if non_managed > 0 {
                Some("non_managed_credentials_will_be_blocked")
            } else {
                None
            },
            if !proxy_capacity {
                Some("proxy_capacity_unavailable")
            } else {
                None
            },
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let validation = json!({
            "valid":true,"checked_at":"database_clock","non_managed_credentials_affected":non_managed,
            "proxy_capacity_currently_available":proxy_capacity,
            "warnings":warnings
        });
        sqlx::query(
            "UPDATE gateway.group_config SET lifecycle_code=$3,validation_report=$4, \
               validated_at=COALESCE(validated_at,clock_timestamp()) WHERE group_id=$1 AND config_version=$2",
        )
        .bind(group_id)
        .bind(version)
        .bind(next)
        .bind(&validation)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    match action {
                        "validate" => "group_config_validated",
                        "publish_shadow" => "group_config_shadow_published",
                        "promote_canary" => "group_config_canary_promoted",
                        _ => return Err(ManagementBackendError::InvalidInput),
                    },
                    "group_config",
                    config_id,
                    version,
                    json!({"group_id":group_id,"version":version,"state":next,"reason":reason,"validation":validation}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.group_config_versions(request, Some(version)).await
    }

    async fn simulate_group_config_version(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let group_id = path_uuid(request, "id")?;
        let version = path_i64(request, "version")?;
        let row = sqlx::query(
            "SELECT target.id,target.lifecycle_code,target.max_concurrency,target.default_rpm,target.default_rpm_burst, \
                    target.fully_managed_required,target.proxy_policy_code,target.content_audit_policy_code, \
                    active_config.config_version AS active_version,active_config.max_concurrency AS active_concurrency, \
                    active_config.default_rpm AS active_rpm,active_config.proxy_policy_code AS active_proxy_policy, \
                    (SELECT count(*) FROM gateway.anthropic_credential c WHERE c.group_id=$1 AND c.lifecycle_state_code='active') AS active_credentials, \
                    (SELECT count(*) FROM gateway.anthropic_credential c WHERE c.group_id=$1 AND c.lifecycle_state_code='active' \
                       AND c.management_class_code<>'fully_managed') AS non_managed_credentials \
             FROM gateway.group_config target JOIN gateway.group_active_config pointer ON pointer.group_id=target.group_id \
             JOIN gateway.group_config active_config ON active_config.id=pointer.config_id \
             WHERE target.group_id=$1 AND target.config_version=$2",
        )
        .bind(group_id)
        .bind(version)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        Ok(single_response(
            &json!({
                "id":required::<Uuid>(&row,"id")?,"group_id":group_id,"version":version,
                "lifecycle":required::<String>(&row,"lifecycle_code")?,"active_version":required::<i64>(&row,"active_version")?,
                "changes":{
                    "concurrency":{"from":required::<Option<i32>>(&row,"active_concurrency")?,"to":required::<Option<i32>>(&row,"max_concurrency")?},
                    "messages_rpm":{"from":required::<Option<i32>>(&row,"active_rpm")?,"to":required::<Option<i32>>(&row,"default_rpm")?},
                    "messages_burst":required::<Option<i32>>(&row,"default_rpm_burst")?,
                    "egress":{"from":required::<String>(&row,"active_proxy_policy")?,"to":required::<String>(&row,"proxy_policy_code")?},
                    "fully_managed_required":required::<bool>(&row,"fully_managed_required")?,
                    "content_audit_policy":required::<String>(&row,"content_audit_policy_code")?
                },
                "impact":{
                    "active_credentials":required::<i64>(&row,"active_credentials")?,
                    "non_managed_credentials":required::<i64>(&row,"non_managed_credentials")?
                },
                "mutates_runtime":false,"revision":version
            }),
            version,
        ))
    }

    async fn activate_group_config_version(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        rollback: bool,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let group_id = path_uuid(request, "id")?;
        let expected_pointer_revision = request_revision(request)?;
        let (target_version, reason, approval_case_id, body_expected_revision) = if rollback {
            let command: GroupConfigRollbackCommand = deserialize_body(request)?;
            (
                command.target_version,
                command.reason,
                command.approval_case_id,
                command.expected_revision,
            )
        } else {
            let command: LifecycleActionCommand = deserialize_body(request)?;
            (
                path_i64(request, "version")?,
                required_action_reason(command.reason.as_deref())?.to_owned(),
                command.approval_case_id,
                command.expected_revision,
            )
        };
        if target_version < 1
            || body_expected_revision.is_some_and(|revision| revision != expected_pointer_revision)
            || reason.trim().is_empty()
            || reason.len() > 2_048
        {
            return Err(ManagementBackendError::Precondition);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let pointer = sqlx::query(
            "SELECT active.config_id,active.revision,current.config_version,current.content_audit_policy_code, \
                    current.content_audit_retention_days \
             FROM gateway.group_active_config active JOIN gateway.group_config current ON current.id=active.config_id \
             WHERE active.group_id=$1 AND active.revision=$2 FOR UPDATE OF active,current",
        )
        .bind(group_id)
        .bind(expected_pointer_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let current_id = required::<Uuid>(&pointer, "config_id")?;
        let target = sqlx::query(
            "SELECT id,lifecycle_code,validation_report,content_audit_policy_code,content_audit_retention_days \
             FROM gateway.group_config WHERE group_id=$1 AND config_version=$2 FOR UPDATE",
        )
        .bind(group_id)
        .bind(target_version)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let target_id = required::<Uuid>(&target, "id")?;
        let target_lifecycle = required::<String>(&target, "lifecycle_code")?;
        let allowed = if rollback {
            target_lifecycle == "retired"
        } else {
            matches!(target_lifecycle.as_str(), "validated" | "shadow" | "canary")
        };
        if !allowed
            || !required::<Value>(&target, "validation_report")?
                .get("valid")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let audit_policy_changed = required::<String>(&pointer, "content_audit_policy_code")?
            != required::<String>(&target, "content_audit_policy_code")?
            || required::<i32>(&pointer, "content_audit_retention_days")?
                != required::<i32>(&target, "content_audit_retention_days")?;
        if audit_policy_changed {
            let approval_id = approval_case_id
                .as_deref()
                .ok_or(ManagementBackendError::Precondition)
                .and_then(parse_input_uuid)?;
            consume_approved_case(
                &mut transaction,
                approval_id,
                "group_content_audit_policy",
                "credential_group",
                &group_id.to_string(),
            )
            .await?;
        }
        sqlx::query("UPDATE gateway.group_config SET lifecycle_code='retired' WHERE id=$1 AND lifecycle_code='active'")
            .bind(current_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "UPDATE gateway.group_config SET lifecycle_code='active',published_at=clock_timestamp() WHERE id=$1",
        )
        .bind(target_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let pointer_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.group_active_config SET config_id=$3,revision=revision+1,activated_by=$4, \
               activated_at=clock_timestamp() WHERE group_id=$1 AND revision=$2 RETURNING revision",
        )
        .bind(group_id)
        .bind(expected_pointer_revision)
        .bind(target_id)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        let group_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.credential_group SET revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 RETURNING revision",
        )
        .bind(group_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    if rollback {
                        "group_config_rolled_back"
                    } else {
                        "group_config_activated"
                    },
                    "credential_group",
                    group_id,
                    group_revision,
                    json!({
                        "from_version":required::<i64>(&pointer,"config_version")?,"to_version":target_version,
                        "pointer_revision":pointer_revision,"reason":reason,"audit_policy_changed":audit_policy_changed
                    }),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let runtime_projection_applied = if let Some(runtime) = &self.scheduler_runtime {
            runtime
                .reconfigure_group_projection(group_id)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
        } else {
            false
        };
        self.reload_management_runtime().await?;
        Ok(single_response(
            &json!({
                "id":target_id,"group_id":group_id,"version":target_version,"lifecycle":"active",
                "pointer_revision":pointer_revision,"group_revision":group_revision,
                "runtime_projection_applied":runtime_projection_applied,"revision":pointer_revision
            }),
            pointer_revision,
        ))
    }

    async fn group_lifecycle(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        target: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let id = path_uuid(request, "id")?;
        let revision = request_revision(request)?;
        let archived = target == "archived";
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let next_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.credential_group SET status_code=$3,archived_at=CASE WHEN $4 THEN clock_timestamp() ELSE NULL END, \
                    revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 AND revision=$2 RETURNING revision",
        )
        .bind(id)
        .bind(revision)
        .bind(target)
        .bind(archived)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    match target {
                        "disabled" => "credential_group_disabled",
                        "archived" => "credential_group_archived",
                        "active" => "credential_group_reactivated",
                        _ => return Err(ManagementBackendError::InvalidInput),
                    },
                    "credential_group",
                    id,
                    next_revision,
                    json!({"status":target}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some(runtime) = &self.scheduler_runtime
            && let Err(error) = runtime.reconcile_group_registry().await
        {
            tracing::warn!(event = "group_registry_reconcile_failed", group_id = %id, error = ?error);
        }
        self.reload_management_runtime().await?;
        Ok(ManagementBackendResponse::ok(
            json!({"data":{"id":id,"status":target,"revision":next_revision},"meta":{}}),
        ))
    }

    async fn get_group(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT g.id,g.name,g.status_code,g.owner_executor_id,g.owner_generation,g.revision, \
                    g.created_at::text AS created_at,g.updated_at::text AS updated_at,COUNT(c.id)::bigint AS credential_count \
             FROM gateway.credential_group g LEFT JOIN gateway.anthropic_credential c ON c.group_id=g.id \
             WHERE g.id=$1 GROUP BY g.id",
        )
        .bind(path_uuid(request, "id")?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision: i64 = row
            .try_get("revision")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(&group_projection(&row)?, revision))
    }

    async fn get_group_capacity(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let group_id = path_uuid(request, "id")?;
        let row = sqlx::query(
            "SELECT g.revision,g.owner_generation,g.status_code,gc.max_concurrency,gc.queue_capacity, \
                    COALESCE(SUM(CASE WHEN csc.enabled THEN csc.max_concurrency ELSE 0 END),0)::bigint AS credential_capacity \
             FROM gateway.credential_group g JOIN gateway.group_active_config active ON active.group_id=g.id \
             JOIN gateway.group_config gc ON gc.id=active.config_id \
             LEFT JOIN gateway.anthropic_credential c ON c.group_id=g.id \
             LEFT JOIN gateway.credential_active_scheduling_config ac ON ac.credential_id=c.id \
             LEFT JOIN gateway.credential_scheduling_config csc ON csc.id=ac.config_id \
             WHERE g.id=$1 GROUP BY g.id,gc.max_concurrency,gc.queue_capacity",
        )
        .bind(group_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let group_revision = required::<i64>(&row, "revision")?;
        if let Some(runtime) = &self.scheduler_runtime
            && let Some(mut projection) = runtime
                .group_capacity_projection(group_id)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
        {
            if let Some(object) = projection.as_object_mut() {
                object.insert("group_revision".to_owned(), json!(group_revision));
                object.insert("status".to_owned(), json!(required::<String>(&row, "status_code")?));
            }
            return Ok(single_response(&projection, group_revision));
        }
        let configured = required::<Option<i32>>(&row, "max_concurrency")?;
        let total_capacity = required::<i64>(&row, "credential_capacity")?;
        let effective = configured.map_or(total_capacity, |limit| i64::from(limit).min(total_capacity));
        let queue_capacity = required::<Option<i32>>(&row, "queue_capacity")?
            .map(i64::from)
            .unwrap_or_else(|| effective.saturating_mul(2));
        Ok(single_response(
            &json!({
                "id":group_id,"group_id":group_id,"owner_generation":required::<i64>(&row,"owner_generation")?,
                "owner_valid":false,"lifecycle":"owner_unavailable","status":required::<String>(&row,"status_code")?,
                "configured_concurrency":configured,"effective_concurrency":effective,
                "total_credential_capacity":total_capacity,"active_group_permits":0,"active_leases":0,
                "queue":{"used":0,"capacity":queue_capacity},"active_session_claims":0,"credential_inflight":[],
                "resource_balance":0,"group_revision":group_revision,"revision":group_revision
            }),
            group_revision,
        ))
    }

    async fn patch_group_metadata(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: GroupPatchCommand = deserialize_body(request)?;
        let name = command.name.trim();
        if name.is_empty() || name.len() > 256 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let group_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "UPDATE gateway.credential_group SET name=$3,revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 RETURNING revision",
        )
        .bind(group_id)
        .bind(expected_revision)
        .bind(name)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?
        .ok_or(ManagementBackendError::Precondition)?;
        let revision = required::<i64>(&row, "revision")?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "credential_group_metadata_updated",
                    "credential_group",
                    group_id,
                    revision,
                    json!({"name":name}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut response = self.get_group(request).await?;
        response.etag = Some(format!("\"rev-{revision}\"").into_boxed_str());
        Ok(response)
    }

    async fn list_group_credentials(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let group_id = path_uuid(request, "id")?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM gateway.credential_group WHERE id=$1)")
            .bind(group_id)
            .fetch_one(&self.storage.pool())
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if !exists {
            return Err(ManagementBackendError::NotFound);
        }
        let rows = sqlx::query(
            "SELECT c.id,c.group_id,c.account_uuid,c.purpose_code,c.auth_kind_code,c.lifecycle_state_code,c.auth_state_code, \
                    c.scheduling_state_code,c.quota_state_code,c.transport_state_code,c.management_class_code,c.token_version, \
                    c.cooldown_until::text AS cooldown_until,c.revision,c.created_at::text AS created_at,c.updated_at::text AS updated_at, \
                    p.profile_epoch,d.device_epoch,p.lifecycle_code AS profile_state,e.mode_code AS egress_mode,e.stability_code AS egress_stability, \
                    a.normalized_plan_code,a.freshness_code AS plan_freshness,sc.config_version AS scheduling_config_version, \
                    active_sc.revision AS scheduling_pointer_revision,sc.max_concurrency,sc.rpm_limit,sc.rpm_burst, \
                    sc.priority_layer,ROUND(sc.weight)::bigint AS scheduling_weight \
             FROM gateway.anthropic_credential c \
             LEFT JOIN gateway.credential_profile p ON p.credential_id=c.id \
             LEFT JOIN gateway.device_identity d ON d.id=p.device_identity_id \
             LEFT JOIN gateway.credential_egress_binding e ON e.credential_id=c.id \
             LEFT JOIN gateway.credential_active_scheduling_config active_sc ON active_sc.credential_id=c.id \
             LEFT JOIN gateway.credential_scheduling_config sc ON sc.id=active_sc.config_id \
             LEFT JOIN telemetry.subscription_plan_current a ON a.credential_id=c.id \
             WHERE c.group_id=$1 ORDER BY c.created_at DESC,c.id DESC LIMIT 100",
        )
        .bind(group_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(credential_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn list_credentials(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT c.id,c.group_id,c.account_uuid,c.purpose_code,c.auth_kind_code,c.lifecycle_state_code,c.auth_state_code, \
                    c.scheduling_state_code,c.quota_state_code,c.transport_state_code,c.management_class_code,c.token_version, \
                    c.cooldown_until::text AS cooldown_until,c.revision,c.created_at::text AS created_at,c.updated_at::text AS updated_at, \
                    p.profile_epoch,d.device_epoch,p.lifecycle_code AS profile_state,e.mode_code AS egress_mode,e.stability_code AS egress_stability, \
                    a.normalized_plan_code,a.freshness_code AS plan_freshness,sc.config_version AS scheduling_config_version, \
                    active_sc.revision AS scheduling_pointer_revision,sc.max_concurrency,sc.rpm_limit,sc.rpm_burst, \
                    sc.priority_layer,ROUND(sc.weight)::bigint AS scheduling_weight \
             FROM gateway.anthropic_credential c \
             LEFT JOIN gateway.credential_profile p ON p.credential_id=c.id \
             LEFT JOIN gateway.device_identity d ON d.id=p.device_identity_id \
             LEFT JOIN gateway.credential_egress_binding e ON e.credential_id=c.id \
             LEFT JOIN gateway.credential_active_scheduling_config active_sc ON active_sc.credential_id=c.id \
             LEFT JOIN gateway.credential_scheduling_config sc ON sc.id=active_sc.config_id \
             LEFT JOIN telemetry.subscription_plan_current a ON a.credential_id=c.id \
             ORDER BY c.created_at DESC,c.id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(credential_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn get_credential(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT c.id,c.group_id,c.account_uuid,c.purpose_code,c.auth_kind_code,c.lifecycle_state_code,c.auth_state_code, \
                    c.scheduling_state_code,c.quota_state_code,c.transport_state_code,c.management_class_code,c.token_version, \
                    c.cooldown_until::text AS cooldown_until,c.revision,c.created_at::text AS created_at,c.updated_at::text AS updated_at, \
                    p.profile_epoch,d.device_epoch,p.lifecycle_code AS profile_state,e.mode_code AS egress_mode,e.stability_code AS egress_stability, \
                    a.normalized_plan_code,a.freshness_code AS plan_freshness,sc.config_version AS scheduling_config_version, \
                    active_sc.revision AS scheduling_pointer_revision,sc.max_concurrency,sc.rpm_limit,sc.rpm_burst, \
                    sc.priority_layer,ROUND(sc.weight)::bigint AS scheduling_weight \
             FROM gateway.anthropic_credential c \
             LEFT JOIN gateway.credential_profile p ON p.credential_id=c.id \
             LEFT JOIN gateway.device_identity d ON d.id=p.device_identity_id \
             LEFT JOIN gateway.credential_egress_binding e ON e.credential_id=c.id \
             LEFT JOIN gateway.credential_active_scheduling_config active_sc ON active_sc.credential_id=c.id \
             LEFT JOIN gateway.credential_scheduling_config sc ON sc.id=active_sc.config_id \
             LEFT JOIN telemetry.subscription_plan_current a ON a.credential_id=c.id WHERE c.id=$1",
        )
        .bind(path_uuid(request, "id")?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision: i64 = row
            .try_get("revision")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(&credential_projection(&row)?, revision))
    }

    async fn patch_credential_scheduling_config(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: CredentialSchedulingPatchCommand = deserialize_body(request)?;
        if command.is_empty() || command.priority.is_null() || command.weight.is_null() {
            return Err(ManagementBackendError::InvalidInput);
        }
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let credential = sqlx::query(
            "SELECT c.group_id,c.revision,config.default_credential_concurrency,config.default_credential_rpm \
             FROM gateway.anthropic_credential c \
             JOIN gateway.credential_group g ON g.id=c.group_id \
             JOIN gateway.group_active_config active ON active.group_id=g.id \
             JOIN gateway.group_config config ON config.id=active.config_id \
             WHERE c.id=$1 AND c.lifecycle_state_code<>'archived' FOR UPDATE OF c",
        )
        .bind(credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let current_credential_revision = required::<i64>(&credential, "revision")?;
        if current_credential_revision != expected_revision {
            return Err(ManagementBackendError::Precondition);
        }
        let group_id = required::<Uuid>(&credential, "group_id")?;
        let default_concurrency = required::<i32>(&credential, "default_credential_concurrency")?;
        let default_rpm = required::<i32>(&credential, "default_credential_rpm")?;
        let current = sqlx::query(
            "SELECT sc.id,sc.config_version,sc.max_concurrency,sc.rpm_limit,sc.rpm_burst,sc.priority_layer, \
                    GREATEST(1,ROUND(sc.weight*1000))::bigint AS weight_scaled,sc.enabled, \
                    sc.session_capacity_enabled,sc.max_active_sessions,sc.session_idle_ttl_ms,sc.new_session_wait_ms, \
                    active.revision AS pointer_revision \
             FROM gateway.credential_active_scheduling_config active \
             JOIN gateway.credential_scheduling_config sc ON sc.id=active.config_id \
             WHERE active.credential_id=$1 FOR UPDATE OF active",
        )
        .bind(credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let current_concurrency = current
            .as_ref()
            .map_or(Ok(default_concurrency), |row| required::<i32>(row, "max_concurrency"))?;
        let current_rpm = current
            .as_ref()
            .map_or(Ok(default_rpm), |row| required::<i32>(row, "rpm_limit"))?;
        let current_burst = current
            .as_ref()
            .map_or(Ok(10_i32), |row| required::<i32>(row, "rpm_burst"))?;
        let current_priority = current
            .as_ref()
            .map_or(Ok(100_i32), |row| required::<i32>(row, "priority_layer"))?;
        let current_weight_scaled = current
            .as_ref()
            .map_or(Ok(1_000_i64), |row| required::<i64>(row, "weight_scaled"))?;
        let concurrency = command.concurrency.resolve(current_concurrency, default_concurrency)?;
        let rpm = command.messages_rpm.resolve(current_rpm, default_rpm)?;
        let priority = command.priority.resolve_non_null(current_priority)?;
        let weight_scaled = match command.weight {
            PatchField::Missing => current_weight_scaled,
            PatchField::Null => return Err(ManagementBackendError::InvalidInput),
            PatchField::Value(value) => {
                i64::from(value.checked_mul(1_000).ok_or(ManagementBackendError::InvalidInput)?)
            }
        };
        if concurrency < 1 || rpm < 1 || !(0..=i32::from(u16::MAX)).contains(&priority) {
            return Err(ManagementBackendError::InvalidInput);
        }
        let session_capacity_enabled = current
            .as_ref()
            .map_or(Ok(false), |row| required::<bool>(row, "session_capacity_enabled"))?;
        let max_active_sessions = current
            .as_ref()
            .map_or(Ok(None), |row| required::<Option<i32>>(row, "max_active_sessions"))?;
        let session_idle_ttl_ms = current
            .as_ref()
            .map_or(Ok(1_800_000_i64), |row| required::<i64>(row, "session_idle_ttl_ms"))?;
        let new_session_wait_ms = current
            .as_ref()
            .map_or(Ok(5_000_i64), |row| required::<i64>(row, "new_session_wait_ms"))?;
        let enabled = current
            .as_ref()
            .map_or(Ok(true), |row| required::<bool>(row, "enabled"))?;
        let normalized = json!({
            "enabled":enabled,
            "max_concurrency":concurrency,
            "max_active_sessions":max_active_sessions,
            "new_session_wait_ms":new_session_wait_ms,
            "priority_layer":priority,
            "rpm_burst":current_burst,
            "rpm_limit":rpm,
            "session_capacity_enabled":session_capacity_enabled,
            "session_idle_ttl_ms":session_idle_ttl_ms,
            "weight_scaled":weight_scaled
        });
        let content_hash = Sha256::digest(canonical_json_bytes(&normalized)?).to_vec();
        let unchanged = if let Some(row) = current.as_ref() {
            required::<i32>(row, "max_concurrency")? == concurrency
                && required::<i32>(row, "rpm_limit")? == rpm
                && required::<i32>(row, "priority_layer")? == priority
                && required::<i64>(row, "weight_scaled")? == weight_scaled
        } else {
            false
        };
        let (config_id, config_version, pointer_revision, credential_revision) = if unchanged {
            let row = current.as_ref().ok_or(ManagementBackendError::Precondition)?;
            (
                required::<Uuid>(row, "id")?,
                required::<i64>(row, "config_version")?,
                required::<i64>(row, "pointer_revision")?,
                current_credential_revision,
            )
        } else {
            let existing = sqlx::query(
                "SELECT id,config_version FROM gateway.credential_scheduling_config \
                 WHERE credential_id=$1 AND content_hash=$2",
            )
            .bind(credential_id)
            .bind(&content_hash)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let (config_id, config_version) = if let Some(row) = existing {
                (required::<Uuid>(&row, "id")?, required::<i64>(&row, "config_version")?)
            } else {
                let config_id = Uuid::now_v7();
                let config_version: i64 = sqlx::query_scalar(
                    "SELECT COALESCE(MAX(config_version),0)+1 FROM gateway.credential_scheduling_config \
                     WHERE credential_id=$1",
                )
                .bind(credential_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                sqlx::query(
                    "INSERT INTO gateway.credential_scheduling_config \
                     (id,credential_id,config_version,max_concurrency,rpm_limit,rpm_burst,priority_layer,weight,enabled, \
                      session_capacity_enabled,max_active_sessions,session_idle_ttl_ms,new_session_wait_ms,content_hash,created_at) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8::numeric/1000,$9,$10,$11,$12,$13,$14,clock_timestamp())",
                )
                .bind(config_id)
                .bind(credential_id)
                .bind(config_version)
                .bind(concurrency)
                .bind(rpm)
                .bind(current_burst)
                .bind(priority)
                .bind(weight_scaled)
                .bind(enabled)
                .bind(session_capacity_enabled)
                .bind(max_active_sessions)
                .bind(session_idle_ttl_ms)
                .bind(new_session_wait_ms)
                .bind(&content_hash)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                (config_id, config_version)
            };
            let pointer_revision = if current.is_some() {
                sqlx::query_scalar(
                    "UPDATE gateway.credential_active_scheduling_config \
                     SET config_id=$2,revision=revision+1,activated_at=clock_timestamp() \
                     WHERE credential_id=$1 RETURNING revision",
                )
                .bind(credential_id)
                .bind(config_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
            } else {
                sqlx::query_scalar(
                    "INSERT INTO gateway.credential_active_scheduling_config \
                     (credential_id,config_id,revision,activated_at) VALUES ($1,$2,1,clock_timestamp()) RETURNING revision",
                )
                .bind(credential_id)
                .bind(config_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
            };
            let credential_revision: i64 = sqlx::query_scalar(
                "UPDATE gateway.anthropic_credential SET revision=revision+1,updated_at=clock_timestamp() \
                 WHERE id=$1 RETURNING revision",
            )
            .bind(credential_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                "INSERT INTO gateway.credential_lifecycle_event \
                 (id,credential_id,event_kind_code,aggregate_revision,redacted_detail,occurred_at) \
                 VALUES ($1,$2,'scheduling_config_updated',$3,$4,clock_timestamp())",
            )
            .bind(Uuid::now_v7())
            .bind(credential_id)
            .bind(credential_revision)
            .bind(json!({"config_id":config_id,"config_version":config_version,"pointer_revision":pointer_revision}))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            self.storage
                .append_audit_outbox_in(
                    &mut transaction,
                    &management_audit(
                        principal,
                        "credential_scheduling_config_updated",
                        "anthropic_credential",
                        credential_id,
                        credential_revision,
                        json!({"config_id":config_id,"config_version":config_version,"pointer_revision":pointer_revision}),
                    )?,
                )
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            (config_id, config_version, pointer_revision, credential_revision)
        };
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let runtime_projection_applied = if let Some(runtime) = &self.scheduler_runtime {
            runtime
                .reconfigure_credential_projection(group_id, credential_id)
                .await
                .unwrap_or(false)
        } else {
            false
        };
        let mut response = single_response(
            &json!({
                "id":config_id,
                "credential_id":credential_id,
                "config_version":config_version,
                "pointer_revision":pointer_revision,
                "concurrency":concurrency,
                "messages_rpm":rpm,
                "messages_burst":current_burst,
                "priority":priority,
                "weight":weight_scaled / 1000,
                "session_capacity_enabled":session_capacity_enabled,
                "max_active_sessions":max_active_sessions,
                "session_idle_ttl_ms":session_idle_ttl_ms,
                "new_session_wait_ms":new_session_wait_ms,
                "runtime_projection_applied":runtime_projection_applied,
                "credential_revision":credential_revision
            }),
            credential_revision,
        );
        response.etag = Some(format!("\"rev-{credential_revision}\"").into_boxed_str());
        Ok(response)
    }

    async fn migrate_credential_group(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: CredentialGroupMigrationCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|value| value != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let snapshot = self
            .storage
            .load_credential_r5_snapshot(credential_id)
            .await
            .map_err(|error| map_storage_error(&error))?;
        if snapshot.revision != expected_revision || snapshot.group_id == command.target_group_id {
            return Err(ManagementBackendError::Precondition);
        }
        let runtime = self
            .scheduler_runtime
            .as_ref()
            .ok_or(ManagementBackendError::Unavailable)?;
        let active_leases = runtime
            .fence_credential_for_admin(snapshot.group_id, credential_id)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?
            .ok_or(ManagementBackendError::Unavailable)?;
        let migration_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(ManagementBackendError::Precondition)?;
        let audit = management_audit(
            principal,
            "credential_group_migration_scheduled",
            "anthropic_credential",
            credential_id,
            next_revision,
            json!({"migration_id":migration_id,"source_group_id":snapshot.group_id,
              "target_group_id":command.target_group_id,"drain_seconds":300,
              "active_leases_at_fence":active_leases,"reason":reason}),
        )?;
        let started = self
            .storage
            .begin_credential_group_migration_with_job(
                &CredentialGroupMigrationBegin {
                    migration_id,
                    credential_id,
                    source_group_id: snapshot.group_id,
                    target_group_id: command.target_group_id,
                    expected_credential_revision: expected_revision,
                    requested_by: parse_uuid(&principal.user_id)?,
                    drain_seconds: 300,
                },
                job_id,
                &audit,
            )
            .await;
        let (credential_revision, created_at) = match started {
            Ok(started) => started,
            Err(error) => {
                let _ = runtime
                    .unfence_credential_for_admin(snapshot.group_id, credential_id)
                    .await;
                return Err(map_storage_error(&error));
            }
        };
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::ACCEPTED,
            body: json!({"data":{
                "id":job_id,"type":"credential_group_migration_v1","status":"queued",
                "progress":{"completed":0,"total":1},"created_at":created_at,"expires_at":null,
                "migration_id":migration_id,"credential_id":credential_id,
                "source_group_id":snapshot.group_id,"target_group_id":command.target_group_id,
                "drain_seconds":300,"credential_revision":credential_revision
            },"meta":{}}),
            etag: Some(format!("\"rev-{credential_revision}\"").into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn rebind_credential_egress(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: EgressRebindCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        if command.expected_profile_epoch < 1 || command.expected_egress_epoch < 1 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        let (mode, proxy_id) = match command.target {
            EgressRebindTarget::Direct => ("direct", None),
            EgressRebindTarget::Proxy { proxy_id } => ("proxy", Some(proxy_id)),
        };
        let job_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "SELECT credential.group_id,credential.revision,profile.profile_epoch,binding.egress_epoch, \
                    binding.mode_code,binding.proxy_id,config.proxy_policy_code \
             FROM gateway.anthropic_credential credential \
             JOIN gateway.credential_profile profile ON profile.credential_id=credential.id \
             JOIN gateway.credential_egress_binding binding ON binding.id=profile.egress_binding_id \
             JOIN gateway.group_active_config pointer ON pointer.group_id=credential.group_id \
             JOIN gateway.group_config config ON config.id=pointer.config_id \
             WHERE credential.id=$1 AND credential.revision=$2 \
               AND credential.lifecycle_state_code IN ('active','disabled') \
               AND profile.lifecycle_code='active' AND binding.lifecycle_code='active' \
             FOR UPDATE OF credential,profile,binding",
        )
        .bind(credential_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let group_id = required::<Uuid>(&row, "group_id")?;
        let profile_epoch = required::<i64>(&row, "profile_epoch")?;
        let egress_epoch = required::<i64>(&row, "egress_epoch")?;
        if profile_epoch != command.expected_profile_epoch || egress_epoch != command.expected_egress_epoch {
            return Err(ManagementBackendError::Precondition);
        }
        let current_mode = required::<String>(&row, "mode_code")?;
        let current_proxy = required::<Option<Uuid>>(&row, "proxy_id")?;
        if current_mode == mode && current_proxy == proxy_id {
            return Err(ManagementBackendError::Precondition);
        }
        let policy = required::<String>(&row, "proxy_policy_code")?;
        if (policy == "direct" && mode != "direct") || (policy == "proxy_required" && mode != "proxy") {
            return Err(ManagementBackendError::Precondition);
        }
        if let Some(proxy_id) = proxy_id {
            let eligible: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM gateway.proxy_endpoint proxy \
                 WHERE proxy.id=$1 AND proxy.lifecycle_code='active' AND proxy.health_code='healthy' \
                   AND proxy.stability_code='static' AND \
                     (SELECT count(*) FROM gateway.credential_egress_binding binding \
                      WHERE binding.proxy_id=proxy.id AND binding.credential_id<>$2 \
                        AND binding.lifecycle_code IN ('pending','active','transport_unavailable','rebinding')) \
                     < proxy.max_active_bindings)",
            )
            .bind(proxy_id)
            .bind(credential_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            if !eligible {
                return Err(ManagementBackendError::Precondition);
            }
        }
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'credential_egress_rebind_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,200,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("credential-egress-rebind:{credential_id}:{expected_revision}:{profile_epoch}:{egress_epoch}"))
        .bind(json!({"credential_id":credential_id,"group_id":group_id,"credential_revision":expected_revision,
          "profile_epoch":profile_epoch,"egress_epoch":egress_epoch,"mode":mode,"proxy_id":proxy_id,"reason":reason}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        insert_job_created_history(&mut transaction, job_id, "credential_egress_rebind_scheduled").await?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "credential_egress_rebind_scheduled",
                    "anthropic_credential",
                    credential_id,
                    expected_revision,
                    json!({"job_id":job_id,"group_id":group_id,"mode":mode,"proxy_id":proxy_id,
                      "profile_epoch":profile_epoch,"egress_epoch":egress_epoch,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(async_job_response(
            job_id,
            "credential_egress_rebind_v1",
            "queued",
            &created_at,
        ))
    }

    async fn migrate_credential_profile_cohort(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ProfileCohortCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        if command.target_capture_cohort.trim().is_empty() || command.target_capture_cohort.len() > 128 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|value| value != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let snapshot = self
            .storage
            .load_credential_r5_snapshot(credential_id)
            .await
            .map_err(|error| map_storage_error(&error))?;
        if snapshot.revision != expected_revision {
            return Err(ManagementBackendError::Precondition);
        }
        let expected_profile_epoch = snapshot.profile_epoch.ok_or(ManagementBackendError::Precondition)?;
        let mut runtime_fenced = false;
        if let Some(runtime) = &self.scheduler_runtime {
            runtime_fenced = runtime
                .fence_credential_for_admin(snapshot.group_id, credential_id)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .is_some();
        }
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(ManagementBackendError::Precondition)?;
        let audit = management_audit(
            principal,
            "credential_profile_cohort_migrated",
            "credential_profile",
            credential_id,
            next_revision,
            json!({
                "target_archetype_version_id":command.target_archetype_version_id,
                "target_capture_cohort":command.target_capture_cohort,
                "allow_explicit_rollback":command.allow_explicit_rollback,
                "reason":reason
            }),
        )?;
        let commit = self
            .storage
            .upgrade_profile_cohort_with_audit(
                &ProfileCohortUpgrade {
                    change_id: Uuid::now_v7(),
                    credential_id,
                    target_archetype_version_id: command.target_archetype_version_id,
                    target_capture_cohort: command.target_capture_cohort,
                    reason_code: reason.to_owned(),
                    approved_by: parse_uuid(&principal.user_id)?,
                    expected_credential_revision: expected_revision,
                    expected_profile_epoch,
                    allow_explicit_rollback: command.allow_explicit_rollback,
                },
                &audit,
            )
            .await;
        let commit = match commit {
            Ok(commit) => commit,
            Err(error) => {
                if runtime_fenced && let Some(runtime) = &self.scheduler_runtime {
                    let _ = runtime
                        .unfence_credential_for_admin(snapshot.group_id, credential_id)
                        .await;
                }
                return Err(map_storage_error(&error));
            }
        };
        let drained_connections = if let Some(runtime) = &self.scheduler_runtime {
            runtime
                .advance_credential_profile_epoch(
                    credential_id,
                    u64::try_from(commit.profile_epoch).map_err(|_| ManagementBackendError::Unavailable)?,
                )
                .unwrap_or_default()
        } else {
            0
        };
        let runtime_projection_applied = if let Some(runtime) = &self.scheduler_runtime {
            runtime
                .reconfigure_credential_projection(snapshot.group_id, credential_id)
                .await
                .unwrap_or(false)
        } else {
            false
        };
        if runtime_projection_applied
            && runtime_fenced
            && let Some(runtime) = &self.scheduler_runtime
        {
            let _ = runtime
                .unfence_credential_for_admin(snapshot.group_id, credential_id)
                .await;
            runtime_fenced = false;
        }
        let mut response = single_response(
            &json!({
                "id":credential_id,
                "group_id":snapshot.group_id,
                "target_archetype_version_id":command.target_archetype_version_id,
                "profile_epoch":commit.profile_epoch,
                "device_epoch":commit.device_epoch,
                "egress_epoch":commit.egress_epoch,
                "drained_connections":drained_connections,
                "runtime_projection_applied":runtime_projection_applied,
                "runtime_fenced":runtime_fenced,
                "revision":commit.credential_revision
            }),
            commit.credential_revision,
        );
        response.etag = Some(format!("\"rev-{}\"", commit.credential_revision).into_boxed_str());
        Ok(response)
    }

    async fn rebuild_credential_device_identity(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: DeviceIdentityRebuildCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|value| value != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let snapshot = self
            .storage
            .load_credential_r5_snapshot(credential_id)
            .await
            .map_err(|error| map_storage_error(&error))?;
        if snapshot.revision != expected_revision {
            return Err(ManagementBackendError::Precondition);
        }
        let expected_profile_epoch = snapshot.profile_epoch.ok_or(ManagementBackendError::Precondition)?;
        let expected_device_epoch = snapshot.device_epoch.ok_or(ManagementBackendError::Precondition)?;
        let action_digest = device_rebuild_snapshot_digest(
            credential_id,
            expected_revision,
            expected_profile_epoch,
            expected_device_epoch,
            reason,
        )?;
        let prepared = self.prepare_device_identity(credential_id).await?;
        let mut runtime_fenced = false;
        if let Some(runtime) = &self.scheduler_runtime {
            runtime_fenced = runtime
                .fence_credential_for_admin(snapshot.group_id, credential_id)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .is_some();
        }
        let mutation = async {
            let mut transaction = self
                .storage
                .pool()
                .begin()
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            let (requested_by, approved_by) = consume_device_rebuild_approval(
                &mut transaction,
                principal,
                command.approval_case_id,
                credential_id,
                &action_digest,
            )
            .await?;
            for (secret_id, aad, envelope) in &prepared.encrypted {
                insert_secret(&mut transaction, *secret_id, aad, envelope).await?;
            }
            let next_revision = expected_revision
                .checked_add(1)
                .ok_or(ManagementBackendError::Precondition)?;
            let audit = management_audit(
                principal,
                "credential_device_identity_rebuilt",
                "credential_profile",
                credential_id,
                next_revision,
                json!({
                    "approval_case_id":command.approval_case_id,
                    "expected_profile_epoch":expected_profile_epoch,
                    "expected_device_epoch":expected_device_epoch,
                    "reason":reason
                }),
            )?;
            let commit = self
                .storage
                .rebuild_device_identity_in(
                    &mut transaction,
                    &DeviceIdentityRebuild {
                        change_id: Uuid::now_v7(),
                        credential_id,
                        installation_secret_id: prepared.encrypted[0].0,
                        client_secret_id: prepared.encrypted[1].0,
                        profile_seed_secret_id: prepared.encrypted[2].0,
                        session_hmac_secret_id: prepared.encrypted[3].0,
                        installation_digest: prepared.installation_digest.clone(),
                        client_digest: prepared.client_digest.clone(),
                        requested_by,
                        approved_by,
                        reason_code: reason.to_owned(),
                        expected_credential_revision: expected_revision,
                        expected_profile_epoch,
                        expected_device_epoch,
                    },
                    Some(&audit),
                )
                .await
                .map_err(|error| map_storage_error(&error))?;
            transaction
                .commit()
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            Ok::<_, ManagementBackendError>(commit)
        }
        .await;
        let commit = match mutation {
            Ok(commit) => commit,
            Err(error) => {
                if runtime_fenced && let Some(runtime) = &self.scheduler_runtime {
                    let _ = runtime
                        .unfence_credential_for_admin(snapshot.group_id, credential_id)
                        .await;
                }
                return Err(error);
            }
        };
        let drained_connections = if let Some(runtime) = &self.scheduler_runtime {
            runtime
                .advance_credential_profile_epoch(
                    credential_id,
                    u64::try_from(commit.profile_epoch).map_err(|_| ManagementBackendError::Unavailable)?,
                )
                .unwrap_or_default()
        } else {
            0
        };
        let runtime_projection_applied = if let Some(runtime) = &self.scheduler_runtime {
            runtime
                .reconfigure_credential_projection(snapshot.group_id, credential_id)
                .await
                .unwrap_or(false)
        } else {
            false
        };
        if runtime_projection_applied
            && runtime_fenced
            && let Some(runtime) = &self.scheduler_runtime
        {
            let _ = runtime
                .unfence_credential_for_admin(snapshot.group_id, credential_id)
                .await;
            runtime_fenced = false;
        }
        let mut response = single_response(
            &json!({
                "id":credential_id,
                "group_id":snapshot.group_id,
                "profile_epoch":commit.profile_epoch,
                "device_epoch":commit.device_epoch,
                "egress_epoch":commit.egress_epoch,
                "drained_connections":drained_connections,
                "runtime_projection_applied":runtime_projection_applied,
                "runtime_fenced":runtime_fenced,
                "revision":commit.credential_revision
            }),
            commit.credential_revision,
        );
        response.etag = Some(format!("\"rev-{}\"", commit.credential_revision).into_boxed_str());
        response.no_store = true;
        Ok(response)
    }

    async fn list_credential_maintenance(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let credential_id = path_uuid(request, "id")?;
        let rows = sqlx::query(
            "SELECT id,credential_id,kind_code,trigger_code,conflict_class_code,state_code, \
                    expected_credential_revision,expected_token_version,egress_epoch_snapshot,operation_generation, \
                    retry_count,retry_after::text AS retry_after,outcome_code,adapter_code,adapter_version, \
                    result_summary,error_category_code,created_at::text AS created_at,updated_at::text AS updated_at, \
                    started_at::text AS started_at,completed_at::text AS completed_at \
             FROM gateway.maintenance_operation WHERE credential_id=$1 ORDER BY created_at DESC,id DESC LIMIT 100",
        )
        .bind(credential_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if rows.is_empty() {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM gateway.anthropic_credential WHERE id=$1)")
                    .bind(credential_id)
                    .fetch_one(&self.storage.pool())
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?;
            if !exists {
                return Err(ManagementBackendError::NotFound);
            }
        }
        let data = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "id":required::<Uuid>(row,"id")?,"credential_id":required::<Uuid>(row,"credential_id")?,
                    "kind":required::<String>(row,"kind_code")?,"trigger":required::<String>(row,"trigger_code")?,
                    "conflict_class":required::<String>(row,"conflict_class_code")?,"state":required::<String>(row,"state_code")?,
                    "expected_credential_revision":required::<Option<i64>>(row,"expected_credential_revision")?,
                    "expected_token_version":required::<Option<i64>>(row,"expected_token_version")?,
                    "egress_epoch_snapshot":required::<Option<i64>>(row,"egress_epoch_snapshot")?,
                    "generation":required::<i64>(row,"operation_generation")?,"attempt_count":required::<i32>(row,"retry_count")?,
                    "next_retry_at":required::<Option<String>>(row,"retry_after")?,"outcome_code":required::<Option<String>>(row,"outcome_code")?,
                    "adapter":required::<Option<String>>(row,"adapter_code")?,"adapter_version":required::<Option<String>>(row,"adapter_version")?,
                    "result":required::<Value>(row,"result_summary")?,"error_category":required::<Option<String>>(row,"error_category_code")?,
                    "created_at":required::<String>(row,"created_at")?,"updated_at":required::<String>(row,"updated_at")?,
                    "started_at":required::<Option<String>>(row,"started_at")?,"completed_at":required::<Option<String>>(row,"completed_at")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        Ok(list_response(&data))
    }

    async fn get_credential_reauth_strategy(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let credential_id = path_uuid(request, "id")?;
        let row = sqlx::query(
            "SELECT s.id,s.credential_id,s.strategy_kind_code,s.state_code,s.browser_provider_code,s.priority, \
                    s.active_material_version_id,s.adapter_version,s.last_verified_at::text AS last_verified_at, \
                    s.last_error_code,s.next_health_at::text AS next_health_at,s.revision,s.created_at::text AS created_at, \
                    s.updated_at::text AS updated_at,m.material_version,m.egress_epoch,m.expires_at::text AS material_expires_at \
             FROM gateway.auto_reauth_strategy s LEFT JOIN gateway.managed_browser_material_version m \
               ON m.id=s.active_material_version_id WHERE s.credential_id=$1",
        )
        .bind(credential_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision = required::<i64>(&row, "revision")?;
        Ok(single_response(
            &json!({
                "id":required::<Uuid>(&row,"id")?,"credential_id":required::<Uuid>(&row,"credential_id")?,
                "kind":required::<String>(&row,"strategy_kind_code")?,"state":required::<String>(&row,"state_code")?,
                "browser_provider":required::<Option<String>>(&row,"browser_provider_code")?,"priority":required::<i32>(&row,"priority")?,
                "active_material_version_id":required::<Option<Uuid>>(&row,"active_material_version_id")?,
                "material_version":required::<Option<i64>>(&row,"material_version")?,"egress_epoch":required::<Option<i64>>(&row,"egress_epoch")?,
                "adapter_version":required::<Option<String>>(&row,"adapter_version")?,"last_verified_at":required::<Option<String>>(&row,"last_verified_at")?,
                "last_error_code":required::<Option<String>>(&row,"last_error_code")?,"next_health_at":required::<Option<String>>(&row,"next_health_at")?,
                "material_expires_at":required::<Option<String>>(&row,"material_expires_at")?,"revision":revision,
                "created_at":required::<String>(&row,"created_at")?,"updated_at":required::<String>(&row,"updated_at")?
            }),
            revision,
        ))
    }

    async fn schedule_managed_browser_strategy(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        intent: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        if !self.managed_browser_available {
            return Err(ManagementBackendError::Precondition);
        }
        let command: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!("credential-browser:{credential_id}"))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let snapshot = sqlx::query(
            "SELECT credential.group_id,credential.revision,credential.token_version,credential.account_uuid, \
                    credential.provider_profile_id,credential.lifecycle_state_code,config.fully_managed_required, \
                    binding.id AS binding_id,binding.egress_epoch \
             FROM gateway.anthropic_credential credential \
             JOIN gateway.credential_auth_version auth ON auth.id=credential.active_auth_version_id \
               AND auth.credential_id=credential.id AND auth.material_state_code='active' \
             JOIN gateway.credential_egress_binding binding ON binding.credential_id=credential.id \
               AND binding.lifecycle_code='active' AND binding.stability_code='stable' \
             JOIN gateway.credential_provider_profile provider ON provider.id=credential.provider_profile_id \
               AND provider.lifecycle_code='active' AND provider.auth_kind_codes ? credential.auth_kind_code \
             JOIN gateway.group_active_config active ON active.group_id=credential.group_id \
             JOIN gateway.group_config config ON config.id=active.config_id \
             WHERE credential.id=$1 AND credential.auth_kind_code='oauth_subscription' \
               AND credential.account_uuid IS NOT NULL AND credential.lifecycle_state_code NOT IN ('revoked','archived') \
             FOR UPDATE OF credential,auth,binding,provider",
        )
        .bind(credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let credential_revision = required::<i64>(&snapshot, "revision")?;
        let existing = sqlx::query(
            "SELECT id,state_code,revision FROM gateway.auto_reauth_strategy \
             WHERE credential_id=$1 AND strategy_kind_code='managed_browser_session' FOR UPDATE",
        )
        .bind(credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let (strategy_id, strategy_revision) = match (intent, existing) {
            ("initialize", None) if credential_revision == expected_revision => {
                let strategy_id = Uuid::now_v7();
                sqlx::query(
                    "INSERT INTO gateway.auto_reauth_strategy \
                     (id,credential_id,strategy_kind_code,priority,state_code,browser_provider_code,adapter_version,revision,created_at,updated_at) \
                     VALUES ($1,$2,'managed_browser_session',100,'pending','command','managed-browser-command-v1',1,clock_timestamp(),clock_timestamp())",
                )
                .bind(strategy_id)
                .bind(credential_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Precondition)?;
                (strategy_id, 1_i64)
            }
            ("reactivate", Some(existing))
                if required::<i64>(&existing, "revision")? == expected_revision
                    && matches!(
                        required::<String>(&existing, "state_code")?.as_str(),
                        "disabled" | "invalid"
                    ) =>
            {
                let strategy_id = required::<Uuid>(&existing, "id")?;
                let revision: i64 = sqlx::query_scalar(
                    "UPDATE gateway.auto_reauth_strategy SET state_code='pending',browser_provider_code='command', \
                       adapter_version='managed-browser-command-v1',last_error_code=NULL,next_health_at=NULL, \
                       revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision",
                )
                .bind(strategy_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                (strategy_id, revision)
            }
            _ => return Err(ManagementBackendError::Precondition),
        };
        let fully_managed_required = required::<bool>(&snapshot, "fully_managed_required")?;
        let next_credential_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET revision=revision+1, \
               management_class_code=CASE WHEN $2 THEN 'pending_reauth_strategy' ELSE management_class_code END, \
               lifecycle_state_code=CASE WHEN $2 AND lifecycle_state_code='active' THEN 'pending_reauth_strategy' ELSE lifecycle_state_code END, \
               scheduling_state_code=CASE WHEN $2 THEN 'blocked' ELSE scheduling_state_code END,updated_at=clock_timestamp() \
             WHERE id=$1 RETURNING revision",
        )
        .bind(credential_id)
        .bind(fully_managed_required)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let operation_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let group_id = required::<Uuid>(&snapshot, "group_id")?;
        let token_version = required::<i64>(&snapshot, "token_version")?;
        let account_uuid = required::<Uuid>(&snapshot, "account_uuid")?;
        let provider_profile_id = required::<Uuid>(&snapshot, "provider_profile_id")?;
        let binding_id = required::<Uuid>(&snapshot, "binding_id")?;
        let egress_epoch = required::<i64>(&snapshot, "egress_epoch")?;
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'credential_managed_browser_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,5,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("credential-browser:{credential_id}:{operation_id}"))
        .bind(json!({"credential_id":credential_id,"group_id":group_id,"strategy_id":strategy_id,
          "strategy_revision":strategy_revision,"operation_id":operation_id,"operation_generation":1,
          "credential_revision":next_credential_revision,"token_version":token_version,"account_uuid":account_uuid,
          "provider_profile_id":provider_profile_id,"binding_id":binding_id,"egress_epoch":egress_epoch,"intent":intent}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO gateway.maintenance_operation \
             (id,credential_id,kind_code,trigger_code,conflict_class_code,state_code,expected_credential_revision, \
              expected_token_version,egress_epoch_snapshot,operation_generation,adapter_code,adapter_version, \
              egress_binding_id,provider_profile_id,durable_job_id,created_at,updated_at) \
             VALUES ($1,$2,'reauthenticate','admin','auth_material_write','planned',$3,$4,$5,1, \
                     'managed_browser','managed-browser-command-v1',$6,$7,$8,clock_timestamp(),clock_timestamp())",
        )
        .bind(operation_id)
        .bind(credential_id)
        .bind(next_credential_revision)
        .bind(token_version)
        .bind(egress_epoch)
        .bind(binding_id)
        .bind(provider_profile_id)
        .bind(job_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        insert_job_created_history(&mut transaction, job_id, "managed_browser_operation_scheduled").await?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "managed_browser_operation_scheduled",
                    "anthropic_credential",
                    credential_id,
                    next_credential_revision,
                    json!({"job_id":job_id,"operation_id":operation_id,"strategy_id":strategy_id,
                      "intent":intent,"egress_epoch":egress_epoch,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if fully_managed_required && let Some(runtime) = &self.scheduler_runtime {
            let _ = runtime.fence_credential_for_admin(group_id, credential_id).await;
        }
        Ok(async_job_response(
            job_id,
            "credential_managed_browser_v1",
            "queued",
            &created_at,
        ))
    }

    async fn list_credential_browser_operations(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let credential_id = path_uuid(request, "id")?;
        let rows = sqlx::query(
            "SELECT operation.id,operation.credential_id,operation.kind_code,operation.state_code, \
                    operation.operation_generation,operation.retry_count,operation.retry_after::text AS retry_after, \
                    operation.outcome_code,operation.error_category_code,operation.adapter_version, \
                    operation.result_summary,operation.created_at::text AS created_at, \
                    operation.started_at::text AS started_at,operation.updated_at::text AS updated_at, \
                    operation.completed_at::text AS completed_at,operation.durable_job_id, \
                    strategy.id AS strategy_id,strategy.state_code AS strategy_state,strategy.browser_provider_code, \
                    material.material_version,material.expires_at::text AS material_expires_at, \
                    binding.id AS binding_id,binding.mode_code,binding.proxy_id,binding.egress_epoch, \
                    binding.lifecycle_code AS binding_state,proxy.health_code AS proxy_health, \
                    job.state_code AS job_state \
             FROM gateway.maintenance_operation operation \
             LEFT JOIN gateway.auto_reauth_strategy strategy ON strategy.credential_id=operation.credential_id \
               AND strategy.strategy_kind_code='managed_browser_session' \
             LEFT JOIN gateway.managed_browser_material_version material ON material.id=strategy.active_material_version_id \
             LEFT JOIN gateway.credential_egress_binding binding ON binding.id=operation.egress_binding_id \
             LEFT JOIN gateway.proxy_endpoint proxy ON proxy.id=binding.proxy_id \
             LEFT JOIN ops.durable_job job ON job.id=operation.durable_job_id \
             WHERE operation.credential_id=$1 AND operation.adapter_code='managed_browser' \
             ORDER BY operation.created_at DESC,operation.id DESC LIMIT 100",
        )
        .bind(credential_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if rows.is_empty() {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM gateway.anthropic_credential WHERE id=$1)")
                    .bind(credential_id)
                    .fetch_one(&self.storage.pool())
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?;
            if !exists {
                return Err(ManagementBackendError::NotFound);
            }
        }
        let data = rows
            .iter()
            .map(|row| {
                let state = required::<String>(row, "state_code")?;
                Ok(json!({
                    "id":required::<Uuid>(row,"id")?,
                    "credential_id":required::<Uuid>(row,"credential_id")?,
                    "strategy_id":required::<Option<Uuid>>(row,"strategy_id")?,
                    "kind":required::<String>(row,"kind_code")?,
                    "state":state,
                    "can_cancel":matches!(state.as_str(),"planned"|"leased"|"running"|"verifying_account"|"committing"|"waiting_backoff"|"waiting_egress"|"needs_attention"),
                    "generation":required::<i64>(row,"operation_generation")?,
                    "attempt_count":required::<i32>(row,"retry_count")?,
                    "next_retry_at":required::<Option<String>>(row,"retry_after")?,
                    "browser_provider":required::<Option<String>>(row,"browser_provider_code")?,
                    "strategy_state":required::<Option<String>>(row,"strategy_state")?,
                    "adapter_version":required::<Option<String>>(row,"adapter_version")?,
                    "material_version":required::<Option<i64>>(row,"material_version")?,
                    "material_expires_at":required::<Option<String>>(row,"material_expires_at")?,
                    "egress":{
                        "binding_id":required::<Option<Uuid>>(row,"binding_id")?,
                        "mode":required::<Option<String>>(row,"mode_code")?,
                        "proxy_id":required::<Option<Uuid>>(row,"proxy_id")?,
                        "egress_epoch":required::<Option<i64>>(row,"egress_epoch")?,
                        "binding_state":required::<Option<String>>(row,"binding_state")?,
                        "proxy_health":required::<Option<String>>(row,"proxy_health")?
                    },
                    "job_id":required::<Option<Uuid>>(row,"durable_job_id")?,
                    "job_state":required::<Option<String>>(row,"job_state")?,
                    "outcome_code":required::<Option<String>>(row,"outcome_code")?,
                    "error_category":required::<Option<String>>(row,"error_category_code")?,
                    "created_at":required::<String>(row,"created_at")?,
                    "started_at":required::<Option<String>>(row,"started_at")?,
                    "updated_at":required::<String>(row,"updated_at")?,
                    "completed_at":required::<Option<String>>(row,"completed_at")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        let mut response = list_response(&data);
        response.no_store = true;
        Ok(response)
    }

    async fn cancel_credential_browser_operation(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let command: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let credential_id = path_uuid(request, "id")?;
        let operation_id = path_uuid(request, "operation_id")?;
        let expected_generation = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|value| value != expected_generation)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "SELECT operation.durable_job_id,job.state_code AS job_state,job.lease_generation \
             FROM gateway.maintenance_operation operation \
             LEFT JOIN ops.durable_job job ON job.id=operation.durable_job_id \
             WHERE operation.id=$1 AND operation.credential_id=$2 AND operation.adapter_code='managed_browser' \
               AND operation.operation_generation=$3 AND operation.state_code IN \
                 ('planned','leased','running','verifying_account','committing','waiting_backoff', \
                  'waiting_egress','needs_attention') FOR UPDATE OF operation",
        )
        .bind(operation_id)
        .bind(credential_id)
        .bind(expected_generation)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let next_generation = expected_generation.saturating_add(1);
        let changed = sqlx::query(
            "UPDATE gateway.maintenance_operation SET state_code='cancelled',outcome_code='admin_cancelled', \
                    retry_after=NULL,completed_at=clock_timestamp(),operation_generation=operation_generation+1, \
                    updated_at=clock_timestamp() \
             WHERE id=$1 AND credential_id=$2 AND operation_generation=$3",
        )
        .bind(operation_id)
        .bind(credential_id)
        .bind(expected_generation)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if changed.rows_affected() != 1 {
            return Err(ManagementBackendError::Precondition);
        }
        if let Some(job_id) = required::<Option<Uuid>>(&row, "durable_job_id")? {
            let job_state = required::<Option<String>>(&row, "job_state")?;
            let lease_generation = required::<Option<i64>>(&row, "lease_generation")?;
            let cancelled = sqlx::query(
                "UPDATE ops.durable_job SET state_code='cancelled',lease_owner=NULL,lease_expires_at=NULL, \
                        completed_at=clock_timestamp(),updated_at=clock_timestamp() \
                 WHERE id=$1 AND state_code IN ('scheduled','retry_wait','leased') RETURNING lease_generation",
            )
            .bind(job_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            if cancelled.is_some() {
                sqlx::query(
                    "INSERT INTO ops.durable_job_history \
                     (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
                     VALUES ($1,$2,$3,'cancelled',$4,'admin_cancelled','{}'::jsonb,clock_timestamp())",
                )
                .bind(Uuid::now_v7())
                .bind(job_id)
                .bind(job_state)
                .bind(lease_generation.unwrap_or(0))
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            }
        }
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "browser_operation_cancelled",
                    "maintenance_operation",
                    operation_id,
                    next_generation,
                    json!({"credential_id":credential_id,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut response = single_response(
            &json!({"id":operation_id,"credential_id":credential_id,"state":"cancelled","generation":next_generation}),
            next_generation,
        );
        response.no_store = true;
        Ok(response)
    }

    async fn disable_credential_reauth_strategy(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let command: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|value| value != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let snapshot = sqlx::query(
            "SELECT credential.group_id,credential.revision AS credential_revision,credential.auth_state_code, \
                    config.fully_managed_required \
             FROM gateway.auto_reauth_strategy strategy \
             JOIN gateway.anthropic_credential credential ON credential.id=strategy.credential_id \
             JOIN gateway.group_active_config active ON active.group_id=credential.group_id \
             JOIN gateway.group_config config ON config.id=active.config_id \
             WHERE strategy.credential_id=$1 AND strategy.revision=$2 AND strategy.state_code<>'disabled'",
        )
        .bind(credential_id)
        .bind(expected_revision)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let group_id = required::<Uuid>(&snapshot, "group_id")?;
        let fully_managed_required = required::<bool>(&snapshot, "fully_managed_required")?;
        let manual_recovery = required::<String>(&snapshot, "auth_state_code")? == "manual_recovery_required";
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let strategy_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.auto_reauth_strategy SET state_code='disabled',next_health_at=NULL, \
                    revision=revision+1,updated_at=clock_timestamp() \
             WHERE credential_id=$1 AND revision=$2 AND state_code IN ('pending','healthy','degraded','invalid') \
             RETURNING revision",
        )
        .bind(credential_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let jobs = sqlx::query(
            "WITH cancelled_operations AS ( \
               UPDATE gateway.maintenance_operation SET state_code='cancelled',outcome_code='strategy_disabled', \
                 retry_after=NULL,completed_at=clock_timestamp(),operation_generation=operation_generation+1, \
                 updated_at=clock_timestamp() \
               WHERE credential_id=$1 AND adapter_code='managed_browser' AND state_code IN \
                 ('planned','leased','running','verifying_account','committing','waiting_backoff','waiting_egress','needs_attention') \
               RETURNING durable_job_id \
             ) SELECT durable_job_id FROM cancelled_operations WHERE durable_job_id IS NOT NULL",
        )
        .bind(credential_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        for job in jobs {
            let job_id = required::<Uuid>(&job, "durable_job_id")?;
            sqlx::query(
                "UPDATE ops.durable_job SET state_code='cancelled',lease_owner=NULL,lease_expires_at=NULL, \
                 completed_at=clock_timestamp(),updated_at=clock_timestamp() \
                 WHERE id=$1 AND state_code IN ('scheduled','retry_wait','leased')",
            )
            .bind(job_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        let credential_revision: i64 = sqlx::query_scalar(
            "UPDATE gateway.anthropic_credential SET \
               management_class_code=CASE WHEN auth_state_code='manual_recovery_required' THEN 'manual_recovery_required' \
                 WHEN $2 THEN 'pending_reauth_strategy' ELSE 'non_managed' END, \
               lifecycle_state_code=CASE WHEN $2 AND lifecycle_state_code='active' THEN 'pending_reauth_strategy' \
                 ELSE lifecycle_state_code END, \
               scheduling_state_code=CASE WHEN auth_state_code='manual_recovery_required' OR $2 THEN 'blocked' \
                 ELSE scheduling_state_code END,revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$3 RETURNING revision",
        )
        .bind(credential_id)
        .bind(fully_managed_required)
        .bind(required::<i64>(&snapshot, "credential_revision")?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "managed_browser_strategy_disabled",
                    "credential",
                    credential_id,
                    credential_revision,
                    json!({"strategy_revision":strategy_revision,"fully_managed_required":fully_managed_required,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut runtime_fenced = if let Some(runtime) = &self.scheduler_runtime {
            runtime
                .fence_credential_for_admin(group_id, credential_id)
                .await
                .ok()
                .flatten()
                .is_some()
        } else {
            false
        };
        let runtime_projection_applied = if !fully_managed_required && !manual_recovery {
            if let Some(runtime) = &self.scheduler_runtime {
                let projected = runtime
                    .reconfigure_credential_projection(group_id, credential_id)
                    .await
                    .unwrap_or(false);
                if projected {
                    let _ = runtime.unfence_credential_for_admin(group_id, credential_id).await;
                    runtime_fenced = false;
                }
                projected
            } else {
                false
            }
        } else {
            false
        };
        let mut response = single_response(
            &json!({"id":credential_id,"state":"disabled","strategy_revision":strategy_revision,"credential_revision":credential_revision,"runtime_projection_applied":runtime_projection_applied,"runtime_fenced":runtime_fenced}),
            strategy_revision,
        );
        response.no_store = true;
        Ok(response)
    }

    async fn credential_lifecycle(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        action: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::Authorization);
        }
        let action_command: LifecycleActionCommand = deserialize_body(request)?;
        if action_command
            .reason
            .as_deref()
            .is_some_and(|reason| reason.trim().is_empty() || reason.len() > 2_048)
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if action_command
            .expected_revision
            .is_some_and(|expected| expected != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let reason_code = action_command.reason.as_deref().unwrap_or(action).trim().to_owned();
        let target = match action {
            "disable" => "disabled",
            "reactivate" => "active",
            "revoke" => "revoked",
            _ => return Err(ManagementBackendError::InvalidInput),
        };
        let group_id: Uuid =
            sqlx::query_scalar("SELECT group_id FROM gateway.anthropic_credential WHERE id=$1 AND revision=$2")
                .bind(credential_id)
                .bind(expected_revision)
                .fetch_optional(&self.storage.pool())
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .ok_or(ManagementBackendError::Precondition)?;
        let fence_before_commit = matches!(action, "disable" | "revoke");
        let mut runtime_projection_applied = false;
        if fence_before_commit && let Some(runtime) = &self.scheduler_runtime {
            runtime_projection_applied = runtime
                .fence_credential_for_admin(group_id, credential_id)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .is_some();
        }
        let command = CredentialLifecycleCommand {
            credential_id,
            expected_revision,
            actor_id: parse_uuid(&principal.user_id)?,
            reason_code,
        };
        let audit = management_audit(
            principal,
            match action {
                "disable" => "credential_disabled",
                "reactivate" => "credential_reactivated",
                "revoke" => "credential_revoked",
                _ => return Err(ManagementBackendError::InvalidInput),
            },
            "credential",
            credential_id,
            expected_revision + 1,
            json!({"status":target,"reason":action_command.reason.as_deref()}),
        )?;
        let next_revision = match match action {
            "disable" => self.storage.disable_credential_with_audit(&command, &audit).await,
            "reactivate" => self.storage.reactivate_credential_with_audit(&command, &audit).await,
            "revoke" => self.storage.revoke_credential_with_audit(&command, &audit).await,
            _ => return Err(ManagementBackendError::InvalidInput),
        } {
            Ok(revision) => revision,
            Err(error) => {
                if fence_before_commit && let Some(runtime) = &self.scheduler_runtime {
                    let _ = runtime.unfence_credential_for_admin(group_id, credential_id).await;
                }
                return Err(map_storage_error(&error));
            }
        };
        if action == "reactivate" {
            if let Some(runtime) = &self.scheduler_runtime {
                runtime_projection_applied = runtime
                    .unfence_credential_for_admin(group_id, credential_id)
                    .await
                    .unwrap_or(false);
            }
        }
        Ok(single_response(
            &json!({
                "id":credential_id,"group_id":group_id,"status":target,
                "runtime_projection_applied":runtime_projection_applied,"revision":next_revision
            }),
            next_revision,
        ))
    }

    async fn begin_credential_recovery(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::Authorization);
        }
        let command: LifecycleActionCommand = deserialize_body(request)?;
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|value| value != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let row = sqlx::query(
            "SELECT group_id,auth_kind_code FROM gateway.anthropic_credential \
             WHERE id=$1 AND revision=$2 AND auth_state_code='manual_recovery_required'",
        )
        .bind(credential_id)
        .bind(expected_revision)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let group_id: Uuid = row
            .try_get("group_id")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let auth_kind: String = row
            .try_get("auth_kind_code")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let requested_method = command
            .payload
            .as_ref()
            .and_then(|payload| payload.get("auth_method"))
            .and_then(Value::as_str);
        let auth_method = match (auth_kind.as_str(), requested_method) {
            ("oauth_subscription", None | Some("oauth_pkce")) => "oauth_pkce",
            ("oauth_subscription", Some("existing_oauth" | "existing_oauth_material")) => "existing_oauth",
            ("setup_token_subscription", None | Some("setup_token")) => "setup_token",
            ("console_api_key", None | Some("console_api_key")) => "console_api_key",
            _ => return Err(ManagementBackendError::InvalidInput),
        };
        let mut delegated = request.clone();
        delegated.body = Some(json!({
            "target_group_id":group_id,
            "mode":"recover",
            "auth_method":auth_method,
            "recovery_credential_id":credential_id,
            "expected_credential_revision":expected_revision,
        }));
        let mut response = self.create_credential_enrollment(principal, &delegated).await?;
        response.status = axum::http::StatusCode::OK;
        Ok(response)
    }

    async fn create_credential_enrollment(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: EnrollmentCreateCommand = deserialize_body(request)?;
        let mode = parse_enrollment_mode(&command.mode)?;
        let auth_method = parse_enrollment_auth_method(&command.auth_method)?;
        let recovery_credential_id = command
            .recovery_credential_id
            .as_deref()
            .map(parse_input_uuid)
            .transpose()?;
        let expected_credential_revision = command.expected_credential_revision;
        if matches!(mode, EnrollmentMode::Create)
            && (recovery_credential_id.is_some() || expected_credential_revision.is_some())
            || matches!(mode, EnrollmentMode::Recover)
                && (recovery_credential_id.is_none() || expected_credential_revision.is_none())
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let enrollment_id = Uuid::now_v7();
        let credential_id = recovery_credential_id.unwrap_or_else(Uuid::now_v7);
        let auth_kind = auth_kind_for_enrollment(auth_method);
        let purpose = if matches!(auth_kind, AuthKind::ConsoleApiKey) {
            CredentialPurpose::CountTokens
        } else {
            CredentialPurpose::Business
        };
        let management_class = if matches!(auth_kind, AuthKind::ConsoleApiKey | AuthKind::SetupTokenSubscription) {
            ManagementClass::NonManaged
        } else {
            ManagementClass::PendingReauthStrategy
        };
        let record = self
            .storage
            .create_credential_enrollment(&CredentialEnrollmentCreate {
                enrollment_id,
                credential_id,
                group_id: parse_input_uuid(&command.target_group_id)?,
                created_by: Some(parse_uuid(&principal.user_id)?),
                mode,
                auth_method,
                auth_kind,
                purpose,
                management_class,
                recovery_credential_id,
                expected_credential_revision,
                expires_in_seconds: 30 * 60,
                callback_window_seconds: 10 * 60,
            })
            .await
            .map_err(|error| map_storage_error(&error))?;
        let mut egress_ready = matches!(mode, EnrollmentMode::Recover);
        if matches!(mode, EnrollmentMode::Create) {
            let allocation = self
                .storage
                .allocate_enrollment_egress(&EgressAllocationRequest {
                    enrollment_id,
                    credential_id,
                    binding_id: Uuid::now_v7(),
                    expected_enrollment_revision: record.revision,
                    expected_credential_revision: 1,
                })
                .await
                .map_err(|error| map_storage_error(&error))?;
            egress_ready = !matches!(allocation, EgressAllocation::WaitForEgress);
        }
        let mut callback_nonce = None;
        if matches!(auth_method, EnrollmentAuthMethod::OauthPkce) && egress_ready {
            let enrollment_revision: i64 =
                sqlx::query_scalar("SELECT revision FROM gateway.credential_enrollment WHERE id=$1")
                    .bind(enrollment_id)
                    .fetch_optional(&self.storage.pool())
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?
                    .ok_or(ManagementBackendError::NotFound)?;
            let profile_id: Uuid =
                sqlx::query_scalar("SELECT provider_profile_id FROM gateway.credential_enrollment WHERE id=$1")
                    .bind(enrollment_id)
                    .fetch_optional(&self.storage.pool())
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?
                    .flatten()
                    .ok_or(ManagementBackendError::Unavailable)?;
            let profile = load_active_enrollment_provider_profile(&self.storage, profile_id)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            let pkce =
                generate_oauth_pkce(&self.session_digest_key).map_err(|_| ManagementBackendError::Unavailable)?;
            let authorization_uri = profile
                .authorization_uri(&pkce.challenge, &pkce.state)
                .map_err(|_| ManagementBackendError::Unavailable)?;
            let (verifier_secret_id, verifier_aad, verifier_envelope) = self
                .prepare_enrollment_secret(
                    enrollment_id,
                    "pkce_verifier",
                    "credential_enrollment",
                    SecretBytes::new(pkce.verifier.expose().as_bytes().to_vec()),
                )
                .await?;
            let mut transaction = self
                .storage
                .pool()
                .begin()
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            insert_secret(&mut transaction, verifier_secret_id, &verifier_aad, &verifier_envelope).await?;
            let configured = self
                .storage
                .configure_enrollment_oauth_pkce_in(
                    &mut transaction,
                    enrollment_id,
                    enrollment_revision,
                    &authorization_uri.to_string(),
                    &profile.redirect_uri.to_string(),
                    &pkce.state_digest,
                    &pkce.callback_nonce_digest,
                    verifier_secret_id,
                )
                .await;
            if let Err(error) = configured {
                return Err(map_storage_error(&error));
            }
            transaction
                .commit()
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            callback_nonce = Some(pkce.callback_nonce.expose().to_owned());
        }
        let mut response = self.enrollment_response(record.enrollment_id).await?;
        if let Some(callback_nonce) = callback_nonce {
            response.body["data"]["oauth_callback_nonce"] = json!(callback_nonce);
            response.no_store = true;
        }
        response.status = axum::http::StatusCode::CREATED;
        Ok(response)
    }

    async fn prepare_enrollment_secret(
        &self,
        enrollment_id: Uuid,
        secret_kind: &str,
        purpose: &str,
        plaintext: SecretBytes,
    ) -> Result<(Uuid, EnvelopeAad, SecretEnvelope), ManagementBackendError> {
        let key_version: i64 = sqlx::query_scalar(
            "SELECT key_version FROM security.business_key_material \
             WHERE provider_code='database' AND state_code='active'",
        )
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Unavailable)?;
        let root_key = self
            .storage
            .load_database_business_key(key_version)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let key_version_u64 = u64::try_from(key_version).map_err(|_| ManagementBackendError::Unavailable)?;
        let secret_id = Uuid::now_v7();
        let aad = EnvelopeAad {
            schema_version: 1,
            secret_id,
            secret_kind: secret_kind.to_owned(),
            provider_role: "business".to_owned(),
            owner_type: "credential_enrollment".to_owned(),
            owner_id: enrollment_id.to_string(),
            purpose: purpose.to_owned(),
            key_version: key_version_u64,
        };
        let provider = LocalAesKeyProvider::new("business", key_version_u64, root_key.expose().to_vec())
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let envelope = EnvelopeService::new(provider)
            .encrypt(&plaintext, aad.clone())
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok((secret_id, aad, envelope))
    }

    async fn enrollment_response(
        &self,
        enrollment_id: Uuid,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT e.id,e.kind_code,e.requested_group_id,e.auth_method_code,e.pending_credential_id, \
                    e.recover_credential_id,e.expected_credential_revision,e.state_code,e.next_action_code, \
                    e.egress_binding_id,e.egress_epoch,e.authorization_uri,e.callback_uri,e.identified_account_uuid, \
                    e.material_secret_refs,e.attempt_count,e.expires_at::text AS expires_at,e.error_code,e.revision, \
                    e.created_at::text AS created_at,e.updated_at::text AS updated_at \
             FROM gateway.credential_enrollment e WHERE e.id=$1",
        )
        .bind(enrollment_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision: i64 = row
            .try_get("revision")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let material_refs = row
            .try_get::<Vec<Uuid>, _>("material_secret_refs")
            .map_err(|_| ManagementBackendError::Unavailable)?
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        let account_uuid = row
            .try_get::<Option<Uuid>, _>("identified_account_uuid")
            .map_err(|_| ManagementBackendError::Unavailable)?
            .map(masked_account_uuid);
        let data = json!({
            "id": required::<Uuid>(&row,"id")?,
            "mode": required::<String>(&row,"kind_code")?,
            "target_group_id": optional::<Uuid>(&row,"requested_group_id")?,
            "auth_method": required::<String>(&row,"auth_method_code")?,
            "pending_credential_id": optional::<Uuid>(&row,"pending_credential_id")?,
            "recovery_credential_id": optional::<Uuid>(&row,"recover_credential_id")?,
            "expected_credential_revision": optional::<i64>(&row,"expected_credential_revision")?,
            "state": required::<String>(&row,"state_code")?,
            "next_action": required::<String>(&row,"next_action_code")?,
            "egress_binding_snapshot": {
                "binding_id": optional::<Uuid>(&row,"egress_binding_id")?,
                "egress_epoch": optional::<i64>(&row,"egress_epoch")?
            },
            "authorization_uri": optional::<String>(&row,"authorization_uri")?,
            "callback_uri": optional::<String>(&row,"callback_uri")?,
            "account_uuid_digest": account_uuid,
            "material_secret_refs": material_refs,
            "attempt_count": required::<i32>(&row,"attempt_count")?,
            "expires_at": required::<String>(&row,"expires_at")?,
            "error_code": optional::<String>(&row,"error_code")?,
            "revision": revision,
            "created_at": required::<String>(&row,"created_at")?,
            "updated_at": required::<String>(&row,"updated_at")?
        });
        Ok(single_response(&data, revision))
    }

    async fn clear_credential_cooldown(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "UPDATE gateway.anthropic_credential SET consecutive_cooldown_count=0,cooldown_until=NULL, \
               scheduling_state_code=CASE WHEN scheduling_state_code='cooldown' THEN 'eligible' ELSE scheduling_state_code END, \
               capacity_state_code=CASE WHEN capacity_state_code='cooldown' THEN 'available' ELSE capacity_state_code END, \
               revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND lifecycle_state_code='active' \
             RETURNING group_id,revision,scheduling_state_code,capacity_state_code",
        )
        .bind(credential_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let group_id = required::<Uuid>(&row, "group_id")?;
        let revision = required::<i64>(&row, "revision")?;
        sqlx::query(
            "UPDATE telemetry.credential_cooldown_event SET cleared_at=COALESCE(cleared_at,clock_timestamp()) \
             WHERE credential_id=$1 AND cleared_at IS NULL",
        )
        .bind(credential_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "credential_cooldown_cleared",
                    "credential",
                    credential_id,
                    revision,
                    json!({"group_id":group_id,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let runtime_applied = if let Some(runtime) = &self.scheduler_runtime {
            runtime
                .clear_credential_cooldown_projection(group_id, credential_id)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
        } else {
            false
        };
        Ok(single_response(
            &json!({
                "id":credential_id,"group_id":group_id,"cooldown_until":null,
                "scheduling_state":required::<String>(&row,"scheduling_state_code")?,
                "capacity_state":required::<String>(&row,"capacity_state_code")?,
                "runtime_projection_applied":runtime_applied,"revision":revision
            }),
            revision,
        ))
    }

    async fn archive_credential(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let action: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&action.reason))?;
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if action
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let row = sqlx::query(
            "SELECT group_id,lifecycle_state_code FROM gateway.anthropic_credential \
             WHERE id=$1 AND revision=$2",
        )
        .bind(credential_id)
        .bind(expected_revision)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let group_id = required::<Uuid>(&row, "group_id")?;
        let lifecycle = required::<String>(&row, "lifecycle_state_code")?;
        if !matches!(lifecycle.as_str(), "disabled" | "revoked") {
            return Err(ManagementBackendError::Precondition);
        }
        let active_leases = if let Some(runtime) = &self.scheduler_runtime {
            runtime
                .fence_credential_for_admin(group_id, credential_id)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .unwrap_or(0)
        } else {
            0
        };
        if active_leases != 0 {
            if let Some(runtime) = &self.scheduler_runtime {
                let _ = runtime.unfence_credential_for_admin(group_id, credential_id).await;
            }
            return Err(ManagementBackendError::Precondition);
        }
        let command = CredentialLifecycleCommand {
            credential_id,
            expected_revision,
            actor_id: parse_uuid(&principal.user_id)?,
            reason_code: reason.to_owned(),
        };
        let audit = management_audit(
            principal,
            "credential_archived",
            "credential",
            credential_id,
            expected_revision + 1,
            json!({"group_id":group_id,"reason":reason,"secret_cleanup":"completed"}),
        )?;
        let revision = match self
            .storage
            .archive_credential_with_audit(&command, active_leases, &audit)
            .await
        {
            Ok(revision) => revision,
            Err(error) => {
                if let Some(runtime) = &self.scheduler_runtime {
                    let _ = runtime.unfence_credential_for_admin(group_id, credential_id).await;
                }
                return Err(map_storage_error(&error));
            }
        };
        let runtime_projection_applied = if let Some(runtime) = &self.scheduler_runtime {
            runtime
                .remove_archived_credential_projection(group_id, credential_id)
                .await
                .unwrap_or(false)
        } else {
            false
        };
        Ok(single_response(
            &json!({
                "id":credential_id,"group_id":group_id,"status":"archived",
                "secrets":"destroyed","runtime_projection_applied":runtime_projection_applied,
                "revision":revision
            }),
            revision,
        ))
    }

    async fn refresh_credential_token(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let action: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&action.reason))?;
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if action
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "SELECT c.group_id,c.token_version,c.revision FROM gateway.anthropic_credential c \
             JOIN gateway.credential_auth_version av ON av.id=c.active_auth_version_id AND av.credential_id=c.id \
             WHERE c.id=$1 AND c.revision=$2 AND c.lifecycle_state_code='active' \
               AND c.auth_kind_code IN ('oauth_subscription','setup_token_subscription') \
               AND av.material_state_code='active' AND av.refresh_secret_id IS NOT NULL FOR UPDATE OF c",
        )
        .bind(credential_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let group_id = required::<Uuid>(&row, "group_id")?;
        let token_version = required::<i64>(&row, "token_version")?;
        let job_key = format!("credential:{credential_id}:token:{token_version}:admin_refresh");
        let new_job_id = Uuid::now_v7();
        let inserted = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'credential_admin_refresh',$2,'scheduled',1,$3,clock_timestamp(),0,0,10,clock_timestamp(),clock_timestamp()) \
             ON CONFLICT (kind_code,idempotency_key) DO NOTHING RETURNING id",
        )
        .bind(new_job_id)
        .bind(&job_key)
        .bind(json!({
            "credential_id":credential_id,"group_id":group_id,
            "expected_token_version":token_version,"requested_by":principal.user_id.as_ref(),
            "reason":reason
        }))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let (job_id, state) = if let Some(job_id) = inserted {
            sqlx::query(
                "INSERT INTO ops.durable_job_history \
                 (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
                 VALUES ($1,$2,NULL,'scheduled',0,'created',$3,clock_timestamp())",
            )
            .bind(Uuid::now_v7())
            .bind(job_id)
            .bind(json!({"credential_id":credential_id,"expected_token_version":token_version}))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            self.storage
                .append_audit_outbox_in(
                    &mut transaction,
                    &management_audit(
                        principal,
                        "credential_token_refresh_scheduled",
                        "durable_job",
                        job_id,
                        1,
                        json!({
                            "credential_id":credential_id,"group_id":group_id,
                            "expected_token_version":token_version,"reason":reason
                        }),
                    )?,
                )
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            (job_id, "scheduled".to_owned())
        } else {
            let existing = sqlx::query(
                "SELECT id,state_code FROM ops.durable_job \
                 WHERE kind_code='credential_admin_refresh' AND idempotency_key=$1",
            )
            .bind(&job_key)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            (
                required::<Uuid>(&existing, "id")?,
                required::<String>(&existing, "state_code")?,
            )
        };
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::ACCEPTED,
            body: json!({"data":{
                "id":job_id,"kind":"credential_admin_refresh","state":state,
                "credential_id":credential_id,"expected_token_version":token_version
            },"meta":{}}),
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn refresh_credential_plan(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let action: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&action.reason))?;
        let credential_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if action
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!("credential-plan:{credential_id}"))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let snapshot = sqlx::query(
            "SELECT credential.group_id,credential.revision,credential.token_version,credential.auth_kind_code, \
                    credential.provider_profile_id,binding.id AS binding_id,binding.egress_epoch \
             FROM gateway.anthropic_credential credential \
             JOIN gateway.credential_auth_version auth ON auth.id=credential.active_auth_version_id \
               AND auth.credential_id=credential.id AND auth.material_state_code='active' \
             JOIN gateway.credential_egress_binding binding ON binding.credential_id=credential.id \
               AND binding.lifecycle_code='active' AND binding.stability_code='stable' \
             JOIN gateway.credential_provider_profile provider ON provider.id=credential.provider_profile_id \
               AND provider.lifecycle_code='active' AND provider.auth_kind_codes ? credential.auth_kind_code \
             WHERE credential.id=$1 AND credential.revision=$2 \
               AND credential.lifecycle_state_code NOT IN ('revoked','archived') \
               AND credential.auth_kind_code IN ('oauth_subscription','setup_token_subscription') \
             FOR SHARE OF credential,auth,binding,provider",
        )
        .bind(credential_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let existing = sqlx::query(
            "SELECT id,state_code,created_at::text AS created_at FROM ops.durable_job \
             WHERE kind_code='credential_plan_collect_v1' \
               AND payload->>'credential_id'=$1 AND state_code IN ('scheduled','leased','retry_wait') \
             ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
        )
        .bind(credential_id.to_string())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some(existing) = existing {
            let job_id = required::<Uuid>(&existing, "id")?;
            let state = required::<String>(&existing, "state_code")?;
            let created_at = required::<String>(&existing, "created_at")?;
            transaction
                .commit()
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            return Ok(async_job_response(
                job_id,
                "credential_plan_collect_v1",
                if state == "leased" { "running" } else { "queued" },
                &created_at,
            ));
        }
        let group_id = required::<Uuid>(&snapshot, "group_id")?;
        let token_version = required::<i64>(&snapshot, "token_version")?;
        let egress_epoch = required::<i64>(&snapshot, "egress_epoch")?;
        let provider_profile_id = required::<Uuid>(&snapshot, "provider_profile_id")?;
        let binding_id = required::<Uuid>(&snapshot, "binding_id")?;
        let job_id = Uuid::now_v7();
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'credential_plan_collect_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,8,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("credential-plan:{credential_id}:{job_id}"))
        .bind(json!({"credential_id":credential_id,"group_id":group_id,"credential_revision":expected_revision,
          "token_version":token_version,"provider_profile_id":provider_profile_id,"binding_id":binding_id,
          "egress_epoch":egress_epoch,"trigger":"admin"}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_job_created_history(&mut transaction, job_id, "credential_plan_collection_scheduled").await?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "credential_plan_collection_scheduled",
                    "anthropic_credential",
                    credential_id,
                    expected_revision,
                    json!({"job_id":job_id,"group_id":group_id,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(async_job_response(
            job_id,
            "credential_plan_collect_v1",
            "queued",
            &created_at,
        ))
    }

    async fn get_credential_enrollment(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        self.enrollment_response(path_uuid(request, "id")?).await
    }

    async fn cancel_credential_enrollment(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let enrollment_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        self.storage
            .cancel_credential_enrollment(enrollment_id, expected_revision)
            .await
            .map_err(|error| map_storage_error(&error))?;
        self.enrollment_response(enrollment_id).await
    }

    async fn submit_credential_material(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: EnrollmentMaterialCommand = deserialize_body(request)?;
        let enrollment_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        let row = sqlx::query(
            "SELECT auth_method_code,state_code,pending_credential_id FROM gateway.credential_enrollment WHERE id=$1",
        )
        .bind(enrollment_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let method: String = required(&row, "auth_method_code")?;
        let state: String = required(&row, "state_code")?;
        let credential_id: Uuid = required(&row, "pending_credential_id")?;
        if state != "awaiting_user_action" {
            return Err(ManagementBackendError::Precondition);
        }
        let material = enrollment_materials(&method, command)?;
        let key_row = sqlx::query(
            "SELECT key_version,key_material FROM security.business_key_material \
             WHERE provider_code='database' AND state_code='active'",
        )
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let key_version: i64 = required(&key_row, "key_version")?;
        let key_material: Vec<u8> = required(&key_row, "key_material")?;
        let provider = LocalAesKeyProvider::new(
            "business",
            key_version
                .try_into()
                .map_err(|_| ManagementBackendError::Unavailable)?,
            key_material,
        )
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let envelope_service = EnvelopeService::new(provider);
        let mut encrypted = Vec::with_capacity(material.len());
        for (secret_kind, purpose, plaintext) in material {
            let secret_id = Uuid::now_v7();
            let aad = EnvelopeAad {
                schema_version: 1,
                secret_id,
                secret_kind: secret_kind.to_owned(),
                provider_role: "business".to_owned(),
                owner_type: "credential_enrollment".to_owned(),
                owner_id: enrollment_id.to_string(),
                purpose: purpose.to_owned(),
                key_version: key_version
                    .try_into()
                    .map_err(|_| ManagementBackendError::Unavailable)?,
            };
            let envelope = envelope_service
                .encrypt(&SecretBytes::new(plaintext.into_bytes()), aad.clone())
                .map_err(|_| ManagementBackendError::Unavailable)?;
            encrypted.push((secret_id, aad, envelope));
        }
        let secret_ids = encrypted.iter().map(|item| item.0).collect::<Vec<_>>();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        for (secret_id, aad, envelope) in &encrypted {
            insert_secret(&mut transaction, *secret_id, aad, envelope).await?;
        }
        let update = sqlx::query(
            "UPDATE gateway.credential_enrollment SET material_secret_refs=material_secret_refs || $3::uuid[], \
                    state_code='exchanging_material',next_action_code='retry',operation_checkpoint_code='material_staged', \
                    revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND state_code='awaiting_user_action'",
        )
        .bind(enrollment_id)
        .bind(expected_revision)
        .bind(&secret_ids)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if update.rows_affected() != 1 {
            return Err(ManagementBackendError::Precondition);
        }
        sqlx::query(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'credential_enrollment_exchange',$2,'scheduled',1,$3,clock_timestamp(),0,0,10,clock_timestamp(),clock_timestamp()) \
             ON CONFLICT (kind_code,idempotency_key) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(format!("enrollment:{enrollment_id}:revision:{expected_revision}"))
        .bind(json!({"enrollment_id":enrollment_id,"credential_id":credential_id,"material_count":secret_ids.len()}))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "credential_material_staged",
                    "credential_enrollment",
                    enrollment_id,
                    expected_revision + 1,
                    json!({"enrollment_id":enrollment_id,"material_count":secret_ids.len()}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut response = self.enrollment_response(enrollment_id).await?;
        response.no_store = true;
        Ok(response)
    }

    async fn complete_credential_oauth_callback(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: OAuthCallbackCommand = deserialize_body(request)?;
        if command.authorization_code.is_empty()
            || command.authorization_code.len() > 32 * 1024
            || command.state.is_empty()
            || command.state.len() > 1_024
            || command.callback_nonce.is_empty()
            || command.callback_nonce.len() > 1_024
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let enrollment_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        let state = SecretValue::new(command.state);
        let callback_nonce = SecretValue::new(command.callback_nonce);
        let state_digest = oauth_callback_digest(&self.session_digest_key, OAuthCallbackDigestDomain::State, &state)
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let nonce_digest = oauth_callback_digest(
            &self.session_digest_key,
            OAuthCallbackDigestDomain::CallbackNonce,
            &callback_nonce,
        )
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let callback_document = serde_json::to_vec(&json!({
            "authorization_code":command.authorization_code,
            "state":state.expose(),
        }))
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let (callback_secret_id, callback_aad, callback_envelope) = self
            .prepare_enrollment_secret(
                enrollment_id,
                "oauth_callback_material",
                "oauth_callback",
                SecretBytes::new(callback_document),
            )
            .await?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_secret(&mut transaction, callback_secret_id, &callback_aad, &callback_envelope).await?;
        let outcome = self
            .storage
            .claim_oauth_callback_in(
                &mut transaction,
                enrollment_id,
                expected_revision,
                &state_digest,
                &nonce_digest,
                callback_secret_id,
            )
            .await
            .map_err(|error| map_storage_error(&error))?;
        let OAuthCallbackClaim::Claimed(revision) = outcome else {
            transaction
                .commit()
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            return Err(ManagementBackendError::Precondition);
        };
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "credential_oauth_callback_claimed",
                    "credential_enrollment",
                    enrollment_id,
                    revision,
                    json!({"enrollment_id":enrollment_id}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut response = self.enrollment_response(enrollment_id).await?;
        response.no_store = true;
        Ok(response)
    }

    async fn list_requests(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT r.request_id,r.request_month::text AS request_month,r.platform_key_id,r.group_id,r.endpoint_code, \
                    r.client_class_code,r.phase_code,r.outcome_code,r.http_status,r.request_body_bytes,r.response_body_bytes, \
                    r.response_mode_code,r.client_commit_state_code,r.terminal_kind_code,r.usage_completeness_code, \
                    r.created_at::text AS created_at,r.completed_at::text AS completed_at \
             FROM telemetry.request_record r JOIN iam.platform_key k ON k.id=r.platform_key_id \
             WHERE ($1 OR k.owner_user_id=$2) ORDER BY r.created_at DESC,r.request_id DESC LIMIT 100",
        )
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(request_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn get_request(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT r.request_id,r.request_month::text AS request_month,r.platform_key_id,r.group_id,r.endpoint_code, \
                    r.client_class_code,r.phase_code,r.outcome_code,r.http_status,r.request_body_bytes,r.response_body_bytes, \
                    r.response_mode_code,r.client_commit_state_code,r.terminal_kind_code,r.usage_completeness_code, \
                    r.created_at::text AS created_at,r.completed_at::text AS completed_at \
             FROM telemetry.request_record r JOIN iam.platform_key k ON k.id=r.platform_key_id \
             WHERE r.request_id=$1 AND ($2 OR k.owner_user_id=$3) ORDER BY r.request_month DESC LIMIT 1",
        )
        .bind(path_uuid(request, "id")?)
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        Ok(ManagementBackendResponse::ok(
            json!({"data":request_projection(&row)?,"meta":{}}),
        ))
    }

    async fn list_request_attempts(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let request_id = path_uuid(request, "id")?;
        let request_month: String = sqlx::query_scalar(
            "SELECT r.request_month::text FROM telemetry.request_record r \
             JOIN iam.platform_key k ON k.id=r.platform_key_id \
             WHERE r.request_id=$1 AND ($2 OR k.owner_user_id=$3) \
             ORDER BY r.request_month DESC LIMIT 1",
        )
        .bind(request_id)
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let rows = sqlx::query(
            "SELECT c.id,c.ordinal,c.state_code,c.credential_id,c.profile_epoch,c.egress_epoch, \
                    c.transport_bundle_id,c.bundle_version,c.authority,c.protocol_code,c.proxy_endpoint_id, \
                    c.request_bytes_written,c.failure_domain_code,c.retry_safe,c.started_at::text AS started_at, \
                    c.completed_at::text AS completed_at,i.state_code AS intent_state, \
                    a.id AS messages_id,a.ordinal AS messages_ordinal,a.reason_code,a.state_code AS messages_state, \
                    a.submitted_at::text AS submitted_at,a.response_committed_at::text AS response_committed_at, \
                    a.completed_at::text AS messages_completed_at,a.http_status,a.retry_decision_code,a.is_final, \
                    COALESCE((SELECT jsonb_agg(jsonb_build_object( \
                        'id',t.id,'event',t.event_code,'detail',t.redacted_detail,'occurred_at',t.occurred_at, \
                        'request_bytes_written',t.request_bytes_written,'response_bytes_read',t.response_bytes_read, \
                        'diagnostic',t.diagnostic_code) ORDER BY t.occurred_at,t.id) \
                      FROM telemetry.transport_event t \
                      WHERE t.connection_attempt_id=c.id OR t.attempt_id=a.id),'[]'::jsonb) AS transport_events \
             FROM telemetry.connection_attempt_record c \
             JOIN telemetry.attempt_submission_intent i ON i.id=c.submission_intent_id \
             LEFT JOIN telemetry.attempt_record a ON a.connection_attempt_id=c.id \
             WHERE c.request_id=$1 AND c.request_month=$2::date \
             ORDER BY c.ordinal,c.id",
        )
        .bind(request_id)
        .bind(request_month)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let is_admin = principal.role == ManagementRole::PlatformAdmin;
        let data = rows
            .iter()
            .map(|row| {
                let messages_id = required::<Option<Uuid>>(row, "messages_id")?;
                let messages = if let Some(id) = messages_id {
                    json!({
                        "id":id,
                        "ordinal":required::<Option<i16>>(row,"messages_ordinal")?,
                        "reason":required::<Option<String>>(row,"reason_code")?,
                        "state":required::<Option<String>>(row,"messages_state")?,
                        "submitted_at":required::<Option<String>>(row,"submitted_at")?,
                        "response_committed_at":required::<Option<String>>(row,"response_committed_at")?,
                        "completed_at":required::<Option<String>>(row,"messages_completed_at")?,
                        "http_status":required::<Option<i32>>(row,"http_status")?,
                        "retry_decision":required::<Option<String>>(row,"retry_decision_code")?,
                        "is_final":required::<Option<bool>>(row,"is_final")?.unwrap_or(false)
                    })
                } else {
                    Value::Null
                };
                let mut item = json!({
                    "id":required::<Uuid>(row,"id")?,
                    "type":"connection_attempt",
                    "ordinal":required::<i16>(row,"ordinal")?,
                    "state":required::<String>(row,"state_code")?,
                    "intent_state":required::<String>(row,"intent_state")?,
                    "request_bytes_written":required::<i64>(row,"request_bytes_written")?,
                    "retry_safe":required::<bool>(row,"retry_safe")?,
                    "started_at":required::<String>(row,"started_at")?,
                    "completed_at":required::<Option<String>>(row,"completed_at")?,
                    "messages_attempt":messages
                });
                if is_admin {
                    item["internal"] = json!({
                        "credential_id":required::<Uuid>(row,"credential_id")?,
                        "profile_epoch":required::<i64>(row,"profile_epoch")?,
                        "egress_epoch":required::<i64>(row,"egress_epoch")?,
                        "transport_bundle_id":required::<Uuid>(row,"transport_bundle_id")?,
                        "bundle_version":required::<Option<i64>>(row,"bundle_version")?,
                        "authority":required::<Option<String>>(row,"authority")?,
                        "protocol":required::<Option<String>>(row,"protocol_code")?,
                        "proxy_endpoint_id":required::<Option<Uuid>>(row,"proxy_endpoint_id")?,
                        "failure_domain":required::<Option<String>>(row,"failure_domain_code")?,
                        "transport_events":required::<Value>(row,"transport_events")?
                    });
                }
                Ok(item)
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        Ok(list_response(&data))
    }

    async fn usage_summary(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(u.request_count),0)::bigint AS request_count, \
                    SUM(u.input_tokens)::bigint AS input_tokens,SUM(u.output_tokens)::bigint AS output_tokens, \
                    SUM(u.estimated_amount)::text AS estimated_amount, \
                    CASE WHEN BOOL_OR(u.completeness_code='unknown') THEN 'unknown' \
                         WHEN BOOL_OR(u.completeness_code='partial') THEN 'partial' ELSE 'complete' END AS completeness \
             FROM telemetry.usage_daily u JOIN iam.platform_key k ON k.id=u.platform_key_id \
             WHERE ($1 OR k.owner_user_id=$2)",
        )
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse::ok(json!({"data":{
            "request_count": row.try_get::<i64,_>("request_count").map_err(|_| ManagementBackendError::Unavailable)?,
            "input_tokens": row.try_get::<Option<i64>,_>("input_tokens").map_err(|_| ManagementBackendError::Unavailable)?,
            "output_tokens": row.try_get::<Option<i64>,_>("output_tokens").map_err(|_| ManagementBackendError::Unavailable)?,
            "estimated_amount": row.try_get::<Option<String>,_>("estimated_amount").map_err(|_| ManagementBackendError::Unavailable)?,
            "currency":"USD",
            "completeness": row.try_get::<String,_>("completeness").map_err(|_| ManagementBackendError::Unavailable)?
        },"meta":{}})))
    }

    async fn usage_timeseries(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT u.bucket_day::text AS bucket_start, \
                    (u.bucket_day::timestamptz+interval '1 day')::text AS bucket_end, \
                    SUM(u.request_count)::bigint AS request_count, \
                    SUM(u.input_tokens)::bigint AS input_tokens,SUM(u.output_tokens)::bigint AS output_tokens, \
                    SUM(u.estimated_amount)::text AS estimated_amount, \
                    CASE WHEN BOOL_OR(u.completeness_code='unknown') THEN 'unknown' \
                         WHEN BOOL_OR(u.completeness_code='partial') THEN 'partial' ELSE 'complete' END AS completeness \
             FROM telemetry.usage_daily u JOIN iam.platform_key k ON k.id=u.platform_key_id \
             WHERE ($1 OR k.owner_user_id=$2) \
             GROUP BY u.bucket_day ORDER BY u.bucket_day DESC LIMIT 100",
        )
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .map(|row| {
                let bucket_start = required::<String>(row, "bucket_start")?;
                Ok(json!({
                    "id":bucket_start,
                    "bucket_start":bucket_start,
                    "bucket_end":required::<String>(row,"bucket_end")?,
                    "granularity":"daily",
                    "request_count":required::<i64>(row,"request_count")?,
                    "input_tokens":required::<Option<i64>>(row,"input_tokens")?,
                    "output_tokens":required::<Option<i64>>(row,"output_tokens")?,
                    "estimated_amount":required::<Option<String>>(row,"estimated_amount")?,
                    "currency":"USD",
                    "completeness":required::<String>(row,"completeness")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        Ok(list_response(&data))
    }

    async fn create_usage_export(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if !matches!(principal.role, ManagementRole::PlatformAdmin | ManagementRole::KeyOwner) {
            return Err(ManagementBackendError::NotFound);
        }
        let command: UsageExportCreateCommand = deserialize_body(request)?;
        if command.dataset != "usage_requests_v1"
            || !matches!(command.format.as_str(), "jsonl" | "csv")
            || !matches!(command.scope.as_str(), "own" | "all")
            || command.from.len() > 64
            || command.to.len() > 64
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let filters = command.filters.unwrap_or_default();
        if filters
            .completeness
            .as_deref()
            .is_some_and(|value| !matches!(value, "complete" | "partial" | "unknown"))
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let platform_key_id = filters.platform_key_id.as_deref().map(parse_input_uuid).transpose()?;
        let group_id = filters.group_id.as_deref().map(parse_input_uuid).transpose()?;
        let model_id = filters.model_id.as_deref().map(parse_input_uuid).transpose()?;
        let time = sqlx::query(
            "SELECT ($1::timestamptz)::text AS from_time,($2::timestamptz)::text AS to_time \
             WHERE $2::timestamptz>$1::timestamptz \
               AND $2::timestamptz-$1::timestamptz<=interval '31 days'",
        )
        .bind(&command.from)
        .bind(&command.to)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::InvalidInput)?
        .ok_or(ManagementBackendError::InvalidInput)?;
        let requested_by = parse_uuid(&principal.user_id)?;
        let scope = if principal.role == ManagementRole::PlatformAdmin && command.scope == "all" {
            "all"
        } else {
            "own"
        };
        let query = json!({
            "schema_version":1,
            "dataset":"usage_requests_v1",
            "from":required::<String>(&time,"from_time")?,
            "to":required::<String>(&time,"to_time")?,
            "filters":{
                "platform_key_id":platform_key_id,
                "group_id":group_id,
                "model_id":model_id,
                "completeness":filters.completeness
            }
        });
        let query_sha256 =
            Sha256::digest(serde_json::to_vec(&query).map_err(|_| ManagementBackendError::InvalidInput)?).to_vec();
        let export_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'usage_export_generate',$2,'scheduled',1,$3,clock_timestamp(),0,0,5,clock_timestamp(),clock_timestamp())",
        )
        .bind(job_id)
        .bind(format!("usage-export:{export_id}"))
        .bind(json!({"export_job_id":export_id}))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,'scheduled',0,'usage_export_scheduled','{}'::jsonb,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO ops.export_job \
             (id,requested_by,scope_code,query,state_code,created_at,durable_job_id,dataset_code,format_code, \
              query_sha256,download_count,revision) \
             VALUES ($1,$2,$3,$4,'queued',clock_timestamp(),$5,'usage_requests_v1',$6,$7,0,1)",
        )
        .bind(export_id)
        .bind(requested_by)
        .bind(scope)
        .bind(&query)
        .bind(job_id)
        .bind(&command.format)
        .bind(&query_sha256)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "usage_export_scheduled",
                    "usage_export",
                    export_id,
                    1,
                    json!({"scope":scope,"dataset":"usage_requests_v1","format":command.format}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::ACCEPTED,
            body: json!({"data":{
                "id":export_id,"job_id":job_id,"dataset":"usage_requests_v1","format":command.format,
                "scope":scope,"state":"queued","revision":1
            },"meta":{}}),
            etag: Some("\"rev-1\"".into()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn get_usage_export(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if !matches!(principal.role, ManagementRole::PlatformAdmin | ManagementRole::KeyOwner) {
            return Err(ManagementBackendError::NotFound);
        }
        let row = sqlx::query(
            "SELECT e.id,e.durable_job_id,e.dataset_code,e.format_code,e.scope_code,e.state_code,e.row_count, \
                    e.content_length,e.created_at::text AS created_at,e.completed_at::text AS completed_at, \
                    e.expires_at::text AS expires_at,e.download_count,e.downloaded_at::text AS downloaded_at, \
                    e.last_error_code,e.revision, \
                    e.state_code='succeeded' AND e.download_count=0 AND e.expires_at>clock_timestamp() AS download_available \
             FROM ops.export_job e WHERE e.id=$1 AND e.requested_by=$2",
        )
        .bind(path_uuid(request, "id")?)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        if required::<String>(&row, "dataset_code")? == "content_audit_record_v1"
            && principal.role != ManagementRole::PlatformAdmin
        {
            return Err(ManagementBackendError::NotFound);
        }
        let revision = required::<i64>(&row, "revision")?;
        Ok(single_response(
            &json!({
                "id":required::<Uuid>(&row,"id")?,
                "job_id":required::<Option<Uuid>>(&row,"durable_job_id")?,
                "dataset":required::<String>(&row,"dataset_code")?,
                "format":required::<String>(&row,"format_code")?,
                "scope":required::<String>(&row,"scope_code")?,
                "state":required::<String>(&row,"state_code")?,
                "row_count":required::<Option<i64>>(&row,"row_count")?,
                "content_length":required::<Option<i64>>(&row,"content_length")?,
                "created_at":required::<String>(&row,"created_at")?,
                "completed_at":required::<Option<String>>(&row,"completed_at")?,
                "expires_at":required::<Option<String>>(&row,"expires_at")?,
                "download_count":required::<i32>(&row,"download_count")?,
                "downloaded_at":required::<Option<String>>(&row,"downloaded_at")?,
                "error_code":required::<Option<String>>(&row,"last_error_code")?,
                "download_available":required::<bool>(&row,"download_available")?,
                "revision":revision
            }),
            revision,
        ))
    }

    async fn download_usage_export(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementDownload, ManagementBackendError> {
        if !matches!(principal.role, ManagementRole::PlatformAdmin | ManagementRole::KeyOwner) {
            return Err(ManagementBackendError::NotFound);
        }
        let requested_by = parse_uuid(&principal.user_id)?;
        let export_id = path_uuid(request, "id")?;
        let artifact = self
            .storage
            .load_usage_export_download(export_id, requested_by)
            .await
            .map_err(|error| match error {
                StorageError::RevisionConflict => ManagementBackendError::NotFound,
                _ => ManagementBackendError::Unavailable,
            })?;
        if artifact.dataset == "content_audit_record_v1"
            && (principal.role != ManagementRole::PlatformAdmin || !self.integrity_guard.healthy())
        {
            return Err(if principal.role == ManagementRole::PlatformAdmin {
                ManagementBackendError::Unavailable
            } else {
                ManagementBackendError::NotFound
            });
        }
        let format = match artifact.format.as_str() {
            "jsonl" => ExportFormat::Jsonl,
            "csv" => ExportFormat::Csv,
            "raw" if artifact.dataset == "content_audit_record_v1" => ExportFormat::Raw,
            _ => return Err(ManagementBackendError::Unavailable),
        };
        let root_key = self
            .storage
            .load_database_business_key(artifact.key_version)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let context = ExportArtifactContext {
            export_id,
            requested_by,
            dataset: artifact.dataset.clone().into_boxed_str(),
            format,
            query_sha256_hex: lower_hex(&artifact.query_sha256).into_boxed_str(),
        };
        let manifest = ExportArtifactManifest {
            object_uri: artifact.object_uri.clone().into_boxed_str(),
            cipher_suite: artifact.cipher_suite.clone().into_boxed_str(),
            nonce: artifact.nonce,
            wrapped_dek: artifact.wrapped_dek,
            key_version: artifact.key_version,
            content_sha256: artifact.content_sha256,
            content_length: artifact.content_length,
        };
        let plaintext = self
            .export_store
            .read(&context, &manifest, &root_key)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .consume_usage_export_download(export_id, requested_by, artifact.revision, role_code(principal.role))
            .await
            .map_err(|error| match error {
                StorageError::RevisionConflict => ManagementBackendError::NotFound,
                _ => ManagementBackendError::Unavailable,
            })?;
        if let Err(error) = self.export_store.remove_uri(&artifact.object_uri).await {
            tracing::warn!(event="usage_export_consumed_object_cleanup_failed", export_id=%export_id, error=%error);
        }
        Ok(ManagementDownload {
            body: Bytes::copy_from_slice(plaintext.expose()),
            content_type: format.content_type().into(),
            filename: if format == ExportFormat::Raw {
                format!("content-audit-{}.bin", export_id.simple()).into_boxed_str()
            } else {
                format!("usage-export-{}.{}", export_id.simple(), format.as_code()).into_boxed_str()
            },
        })
    }

    async fn create_backup_job(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let command: BackupJobCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let step_up_id = parse_input_uuid(&command.step_up_grant_id)?;
        let run_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        consume_step_up_in(&mut transaction, principal, step_up_id, "backup_restore_security").await?;
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'backup_create',$2,'scheduled',1,$3,clock_timestamp(),0,0,5,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("backup-run:{run_id}"))
        .bind(json!({"backup_run_id":run_id}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_job_created_history(&mut transaction, job_id, "backup_scheduled").await?;
        sqlx::query(
            "INSERT INTO ops.backup_run \
             (id,state_code,durable_job_id,requested_by,kind_code,requested_at,revision) \
             VALUES ($1,'queued',$2,$3,'base_backup',clock_timestamp(),1)",
        )
        .bind(run_id)
        .bind(job_id)
        .bind(parse_uuid(&principal.user_id)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "backup_scheduled",
                    "backup_run",
                    run_id,
                    1,
                    json!({"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(async_job_response(job_id, "backup_create", "queued", &created_at))
    }

    async fn create_upgrade_check(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: UpgradeCheckCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let (release_version, source_revision) = validate_upgrade_release_manifest(&command.release_manifest)?;
        let manifest_bytes = canonical_json_bytes(&command.release_manifest)?;
        if manifest_bytes.len() > 2 * 1024 * 1024 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let manifest_digest: [u8; 32] = Sha256::digest(&manifest_bytes).into();
        let run_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let candidate_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let existing =
            sqlx::query("SELECT id,manifest_sha256 FROM ops.release_manifest WHERE release_version=$1 FOR UPDATE")
                .bind(&release_version)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
        let release_id = if let Some(row) = existing {
            let stored: Vec<u8> = row
                .try_get("manifest_sha256")
                .map_err(|_| ManagementBackendError::Unavailable)?;
            if stored.as_slice() != manifest_digest {
                return Err(ManagementBackendError::Precondition);
            }
            row.try_get("id").map_err(|_| ManagementBackendError::Unavailable)?
        } else {
            sqlx::query(
                "INSERT INTO ops.release_manifest \
                 (id,release_version,source_revision,manifest,manifest_sha256,created_at) \
                 VALUES ($1,$2,$3,$4,$5,clock_timestamp())",
            )
            .bind(candidate_id)
            .bind(&release_version)
            .bind(&source_revision)
            .bind(&command.release_manifest)
            .bind(manifest_digest.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            candidate_id
        };
        let from_release_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM ops.release_manifest WHERE id<>$1 ORDER BY created_at DESC,id DESC LIMIT 1",
        )
        .bind(release_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'upgrade_preflight_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,3,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("upgrade-preflight:{run_id}"))
        .bind(json!({"upgrade_run_id":run_id}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_job_created_history(&mut transaction, job_id, "upgrade_preflight_scheduled").await?;
        sqlx::query(
            "INSERT INTO ops.upgrade_run \
             (id,from_release_id,to_release_id,state_code,detail,created_at,durable_job_id,requested_by, \
              preflight_state_code,preflight_result,revision) \
             VALUES ($1,$2,$3,'planned',$4,clock_timestamp(),$5,$6,'queued','{}'::jsonb,1)",
        )
        .bind(run_id)
        .bind(from_release_id)
        .bind(release_id)
        .bind(json!({"reason":reason,"candidate_digest":lower_hex(&manifest_digest)}))
        .bind(job_id)
        .bind(parse_uuid(&principal.user_id)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "upgrade_preflight_scheduled",
                    "upgrade_check",
                    run_id,
                    1,
                    json!({"reason":reason,"candidate_release":release_version,"candidate_digest":lower_hex(&manifest_digest)}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::ACCEPTED,
            body: json!({"data":{
                "id":job_id,"type":"upgrade_preflight_v1","status":"queued",
                "progress":{"completed":0,"total":1},"created_at":created_at,"expires_at":null,
                "upgrade_check_id":run_id,"candidate_release":release_version,
                "candidate_digest":lower_hex(&manifest_digest)
            },"meta":{}}),
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn list_upgrade_checks(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let query: UpgradeCheckQuery = serde_urlencoded::from_str(request.query.as_deref().unwrap_or(""))
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let page_size = query.page_size.unwrap_or(20);
        if !(1..=100).contains(&page_size) {
            return Err(ManagementBackendError::InvalidInput);
        }
        let after = query.page_after.as_deref().map(parse_input_uuid).transpose()?;
        if let Some(after_id) = after {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ops.upgrade_run WHERE id=$1)")
                .bind(after_id)
                .fetch_one(&self.storage.pool())
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            if !exists {
                return Err(ManagementBackendError::InvalidInput);
            }
        }
        let rows = sqlx::query(
            "SELECT run.id,run.durable_job_id,run.state_code,run.preflight_state_code,run.preflight_result, \
                    run.preflight_started_at::text AS preflight_started_at, \
                    run.preflight_completed_at::text AS preflight_completed_at, \
                    run.preflight_valid_until::text AS preflight_valid_until,run.error_code,run.revision, \
                    run.created_at::text AS created_at,release.release_version,release.source_revision, \
                    encode(release.manifest_sha256,'hex') AS candidate_digest,job.state_code AS job_state, \
                    COALESCE(jsonb_agg(jsonb_build_object('code',gate.gate_code,'state',gate.state_code,'detail',gate.detail) \
                      ORDER BY gate.gate_code) FILTER (WHERE gate.id IS NOT NULL),'[]'::jsonb) AS checks \
             FROM ops.upgrade_run run JOIN ops.release_manifest release ON release.id=run.to_release_id \
             LEFT JOIN ops.durable_job job ON job.id=run.durable_job_id \
             LEFT JOIN ops.release_gate_run gate ON gate.upgrade_run_id=run.id \
             WHERE ($1::uuid IS NULL OR (run.created_at,run.id)<(SELECT cursor.created_at,cursor.id FROM ops.upgrade_run cursor WHERE cursor.id=$1)) \
             GROUP BY run.id,release.id,job.id ORDER BY run.created_at DESC,run.id DESC LIMIT $2",
        )
        .bind(after)
        .bind(i64::try_from(page_size + 1).map_err(|_| ManagementBackendError::InvalidInput)?)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let has_more = rows.len() > page_size;
        let visible = rows.iter().take(page_size).collect::<Vec<_>>();
        let data = visible
            .iter()
            .map(|row| upgrade_check_projection(row))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = has_more
            .then(|| visible.last())
            .flatten()
            .map(|row| required::<Uuid>(row, "id").map(|id| id.to_string()))
            .transpose()?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({"data":data,"page":{"next_cursor":next_cursor},"meta":{"has_more":has_more,"page_size":page_size}}),
            etag: None,
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn create_restore_operation(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        kind: &str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let command: RestoreOperationCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let backup_run_id = parse_input_uuid(&command.backup_run_id)?;
        let step_up_id = parse_input_uuid(&command.step_up_grant_id)?;
        let recovery_point = if let Some(value) = command.recovery_point.as_deref() {
            Some(
                sqlx::query_scalar::<_, String>("SELECT ($1::timestamptz)::text")
                    .bind(value)
                    .fetch_one(&self.storage.pool())
                    .await
                    .map_err(|_| ManagementBackendError::InvalidInput)?,
            )
        } else {
            None
        };
        let drill_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let job_kind = if kind == "manifest_validation" {
            "restore_manifest_validation"
        } else if kind == "full_restore_drill" {
            "restore_full_drill"
        } else {
            return Err(ManagementBackendError::InvalidInput);
        };
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        consume_step_up_in(&mut transaction, principal, step_up_id, "backup_restore_security").await?;
        let backup_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ops.backup_run WHERE id=$1 AND state_code='succeeded' \
             AND manifest IS NOT NULL AND octet_length(manifest_sha256)=32)",
        )
        .bind(backup_run_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if !backup_exists {
            return Err(ManagementBackendError::Precondition);
        }
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,$2,$3,'scheduled',1,$4,clock_timestamp(),0,0,3,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(job_kind)
        .bind(format!("{job_kind}:{drill_id}"))
        .bind(json!({"restore_drill_id":drill_id}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_job_created_history(&mut transaction, job_id, "restore_scheduled").await?;
        sqlx::query(
            "INSERT INTO ops.restore_drill \
             (id,backup_run_id,state_code,isolated,durable_job_id,requested_by,kind_code,recovery_point,requested_at,revision) \
             VALUES ($1,$2,'queued',true,$3,$4,$5,$6::timestamptz,clock_timestamp(),1)",
        )
        .bind(drill_id)
        .bind(backup_run_id)
        .bind(job_id)
        .bind(parse_uuid(&principal.user_id)?)
        .bind(kind)
        .bind(&recovery_point)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "restore_scheduled",
                    kind,
                    drill_id,
                    1,
                    json!({"backup_run_id":backup_run_id,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(async_job_response(job_id, job_kind, "queued", &created_at))
    }

    async fn list_backup_runs(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let rows = sqlx::query(
            "SELECT id,durable_job_id,kind_code,state_code,database_system_id,timeline,lsn_start::text AS lsn_start, \
                    lsn_end::text AS lsn_end,wal_archived_at::text AS wal_archived_at,watermarks,backup_key_version,bytes_written, \
                    encode(manifest_sha256,'hex') AS manifest_sha256,requested_at::text AS requested_at, \
                    started_at::text AS started_at,completed_at::text AS completed_at,error_code,revision \
             FROM ops.backup_run ORDER BY requested_at DESC,id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(backup_run_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn get_backup_run(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let row = sqlx::query(
            "SELECT id,durable_job_id,kind_code,state_code,database_system_id,timeline,lsn_start::text AS lsn_start, \
                    lsn_end::text AS lsn_end,wal_archived_at::text AS wal_archived_at,watermarks,backup_key_version,bytes_written, \
                    encode(manifest_sha256,'hex') AS manifest_sha256,requested_at::text AS requested_at, \
                    started_at::text AS started_at,completed_at::text AS completed_at,error_code,revision \
             FROM ops.backup_run WHERE id=$1",
        )
        .bind(path_uuid(request, "id")?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision = required::<i64>(&row, "revision")?;
        Ok(single_response(&backup_run_projection(&row)?, revision))
    }

    async fn list_restore_operations(
        &self,
        principal: &ManagementPrincipal,
        kind: &str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let rows = sqlx::query(
            "SELECT id,durable_job_id,backup_run_id,kind_code,state_code,recovery_point::text AS recovery_point, \
                    isolated_environment_id,db_recovered,object_replayed,ledger_replayed,checks,lineage,rpo_seconds,rto_seconds, \
                    encode(manifest_sha256,'hex') AS manifest_sha256,serving_simulated_at::text AS serving_simulated_at, \
                    destroyed_at::text AS destroyed_at,requested_at::text AS requested_at,started_at::text AS started_at, \
                    completed_at::text AS completed_at,error_code,revision FROM ops.restore_drill \
             WHERE kind_code=$1 ORDER BY requested_at DESC,id DESC LIMIT 100",
        )
        .bind(kind)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(restore_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn get_restore_operation(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        kind: &str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let row = sqlx::query(
            "SELECT id,durable_job_id,backup_run_id,kind_code,state_code,recovery_point::text AS recovery_point, \
                    isolated_environment_id,db_recovered,object_replayed,ledger_replayed,checks,lineage,rpo_seconds,rto_seconds, \
                    encode(manifest_sha256,'hex') AS manifest_sha256,serving_simulated_at::text AS serving_simulated_at, \
                    destroyed_at::text AS destroyed_at,requested_at::text AS requested_at,started_at::text AS started_at, \
                    completed_at::text AS completed_at,error_code,revision FROM ops.restore_drill WHERE id=$1 AND kind_code=$2",
        )
        .bind(path_uuid(request, "id")?)
        .bind(kind)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision = required::<i64>(&row, "revision")?;
        Ok(single_response(&restore_projection(&row)?, revision))
    }

    async fn list_proxies(&self, proxy_id: Option<Uuid>) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT p.id,p.name,p.proxy_type_code,p.host,p.port,p.auth_secret_id IS NOT NULL AS has_auth, \
                    p.lifecycle_code,p.health_code,p.stability_code,p.max_active_bindings,p.probe_generation, \
                    p.last_probed_at::text AS last_probed_at,p.last_success_at::text AS last_success_at, \
                    p.last_error_code,p.revision,p.created_at::text AS created_at,p.updated_at::text AS updated_at, \
                    (SELECT count(*) FROM gateway.credential_egress_binding b WHERE b.proxy_id=p.id \
                      AND b.lifecycle_code IN ('pending','active','transport_unavailable','rebinding'))::bigint AS active_bindings \
             FROM gateway.proxy_endpoint p WHERE ($1::uuid IS NULL OR p.id=$1) \
             ORDER BY p.created_at DESC,p.id DESC LIMIT 100",
        )
        .bind(proxy_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if proxy_id.is_some() && rows.is_empty() {
            return Err(ManagementBackendError::NotFound);
        }
        let data = rows.iter().map(proxy_projection).collect::<Result<Vec<_>, _>>()?;
        if proxy_id.is_some() {
            let row = data.into_iter().next().ok_or(ManagementBackendError::NotFound)?;
            let revision = row["revision"].as_i64().ok_or(ManagementBackendError::Unavailable)?;
            Ok(single_response(&row, revision))
        } else {
            Ok(list_response(&data))
        }
    }

    async fn create_proxy(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ProxyCreateCommand = deserialize_body(request)?;
        let has_credentials = match (&command.username, &command.password) {
            (Some(username), Some(password)) => {
                if username.is_empty()
                    || username.len() > 1_024
                    || password.is_empty()
                    || password.len() > 4_096
                    || username.contains(['\r', '\n'])
                    || password.contains(['\r', '\n'])
                {
                    return Err(ManagementBackendError::InvalidInput);
                }
                true
            }
            (None, None) => false,
            _ => return Err(ManagementBackendError::InvalidInput),
        };
        if command.name.trim().is_empty()
            || command.name.len() > 128
            || command.host.is_empty()
            || command.host.len() > 253
            || command
                .host
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, '/' | '\\' | '@'))
            || !matches!(command.proxy_type.as_str(), "http_connect" | "socks5")
            || command.stability != "static"
            || !(1..=1_000).contains(&command.max_active_credentials)
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let proxy_id = Uuid::now_v7();
        let secret_id = has_credentials.then(Uuid::now_v7);
        let encrypted = match (secret_id, command.username.as_deref(), command.password.as_deref()) {
            (Some(secret_id), Some(username), Some(password)) => Some((
                secret_id,
                self.encrypt_proxy_secret(proxy_id, secret_id, username, password)
                    .await?,
            )),
            _ => None,
        };
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some((secret_id, (aad, envelope))) = &encrypted {
            insert_secret(&mut transaction, *secret_id, aad, envelope).await?;
        }
        sqlx::query(
            "INSERT INTO gateway.proxy_endpoint \
             (id,name,proxy_type_code,host,port,auth_secret_id,lifecycle_code,health_code,stability_code, \
              max_active_bindings,probe_generation,revision,created_at,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,'active','unknown','static',$7,0,1,clock_timestamp(),clock_timestamp())",
        )
        .bind(proxy_id)
        .bind(command.name.trim())
        .bind(&command.proxy_type)
        .bind(&command.host)
        .bind(i32::from(command.port))
        .bind(secret_id)
        .bind(command.max_active_credentials)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "proxy_created",
                    "proxy",
                    proxy_id,
                    1,
                    json!({"type":command.proxy_type,"stability":"static","has_auth":has_credentials}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut response = self.list_proxies(Some(proxy_id)).await?;
        response.status = axum::http::StatusCode::CREATED;
        Ok(response)
    }

    async fn patch_proxy(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ProxyPatchCommand = deserialize_body(request)?;
        if command.name.is_none() && command.max_active_credentials.is_none() {
            return Err(ManagementBackendError::InvalidInput);
        }
        if command
            .name
            .as_deref()
            .is_some_and(|name| name.trim().is_empty() || name.len() > 128)
            || command
                .max_active_credentials
                .is_some_and(|capacity| !(1..=1_000).contains(&capacity))
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let proxy_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "UPDATE gateway.proxy_endpoint p SET \
               name=COALESCE($3,name),max_active_bindings=COALESCE($4,max_active_bindings), \
               revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND lifecycle_code<>'archived' \
               AND ($4::integer IS NULL OR $4 >= (SELECT count(*) FROM gateway.credential_egress_binding b \
                    WHERE b.proxy_id=p.id AND b.lifecycle_code IN ('pending','active','transport_unavailable','rebinding'))) \
             RETURNING revision",
        )
        .bind(proxy_id)
        .bind(expected_revision)
        .bind(command.name.as_deref().map(str::trim))
        .bind(command.max_active_credentials)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?
        .ok_or(ManagementBackendError::Precondition)?;
        let revision = required::<i64>(&row, "revision")?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "proxy_updated",
                    "proxy",
                    proxy_id,
                    revision,
                    json!({"name_changed":command.name.is_some(),"capacity_changed":command.max_active_credentials.is_some()}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.list_proxies(Some(proxy_id)).await
    }

    async fn list_proxy_bindings(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let proxy_id = path_uuid(request, "id")?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM gateway.proxy_endpoint WHERE id=$1)")
            .bind(proxy_id)
            .fetch_one(&self.storage.pool())
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if !exists {
            return Err(ManagementBackendError::NotFound);
        }
        let rows = sqlx::query(
            "SELECT id,credential_id,mode_code,proxy_id,stability_code,lifecycle_code,egress_epoch, \
                    expected_egress_ip IS NOT NULL AS expected_ip_present,observed_egress_ip IS NOT NULL AS observed_ip_present, \
                    rebind_reason_code,revision,created_at::text AS created_at,updated_at::text AS updated_at \
             FROM gateway.credential_egress_binding WHERE proxy_id=$1 ORDER BY created_at DESC,id DESC LIMIT 100",
        )
        .bind(proxy_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "id":required::<Uuid>(row,"id")?,"credential_id":required::<Uuid>(row,"credential_id")?,
                    "mode":required::<String>(row,"mode_code")?,"proxy_id":required::<Option<Uuid>>(row,"proxy_id")?,
                    "stability":required::<String>(row,"stability_code")?,"lifecycle":required::<String>(row,"lifecycle_code")?,
                    "egress_epoch":required::<i64>(row,"egress_epoch")?,
                    "expected_exit_ip_digest":if required::<bool>(row,"expected_ip_present")? {Some("redacted")} else {None},
                    "observed_exit_ip_digest":if required::<bool>(row,"observed_ip_present")? {Some("redacted")} else {None},
                    "rebind_reason":required::<Option<String>>(row,"rebind_reason_code")?,
                    "revision":required::<i64>(row,"revision")?,"created_at":required::<String>(row,"created_at")?,
                    "updated_at":required::<String>(row,"updated_at")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        Ok(list_response(&data))
    }

    async fn enqueue_proxy_probe(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let proxy_id = path_uuid(request, "id")?;
        let job_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let proxy = sqlx::query(
            "UPDATE gateway.proxy_endpoint SET health_code='probing',probe_generation=probe_generation+1, \
               revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 AND lifecycle_code IN ('active','disabled') \
             RETURNING probe_generation,revision",
        )
        .bind(proxy_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let generation = required::<i64>(&proxy, "probe_generation")?;
        let revision = required::<i64>(&proxy, "revision")?;
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'proxy_full_path_probe_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,5,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("proxy-probe:{proxy_id}:{generation}"))
        .bind(json!({"proxy_id":proxy_id,"probe_generation":generation}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_job_created_history(&mut transaction, job_id, "proxy_probe_scheduled").await?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "proxy_probe_scheduled",
                    "proxy",
                    proxy_id,
                    revision,
                    json!({"reason":reason,"probe_generation":generation,"job_id":job_id}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(async_job_response(
            job_id,
            "proxy_full_path_probe_v1",
            "queued",
            &created_at,
        ))
    }

    async fn proxy_lifecycle(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        action: &str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let proxy_id = path_uuid(request, "id")?;
        let credential_ids = sqlx::query_scalar::<_, Uuid>(
            "SELECT credential_id FROM gateway.credential_egress_binding WHERE proxy_id=$1 ORDER BY credential_id",
        )
        .bind(proxy_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        for credential_id in &credential_ids {
            sqlx::query("SELECT id FROM gateway.anthropic_credential WHERE id=$1 FOR UPDATE")
                .bind(credential_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query("SELECT id FROM gateway.credential_egress_binding WHERE credential_id=$1 FOR UPDATE")
                .bind(credential_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        let row = match action {
            "disable" => {
                let row = sqlx::query(
                    "UPDATE gateway.proxy_endpoint SET lifecycle_code='disabled',drain_deadline_at=NULL,drained_at=clock_timestamp(), \
                       revision=revision+1,updated_at=clock_timestamp() \
                     WHERE id=$1 AND revision=$2 AND lifecycle_code IN ('active','draining') RETURNING revision,auth_secret_id",
                )
                .bind(proxy_id)
                .bind(expected_revision)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                sqlx::query(
                    "UPDATE gateway.credential_egress_binding SET stability_code='unavailable', \
                       lifecycle_code='transport_unavailable',rebind_reason_code='proxy_disabled',revision=revision+1, \
                       updated_at=clock_timestamp() WHERE proxy_id=$1 AND lifecycle_code<>'disabled'",
                )
                .bind(proxy_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                sqlx::query(
                    "UPDATE gateway.anthropic_credential SET transport_state_code='transport_unavailable', \
                       revision=revision+1,updated_at=clock_timestamp() WHERE id=ANY($1)",
                )
                .bind(&credential_ids)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                row
            }
            "reactivate" => {
                let row = sqlx::query(
                    "UPDATE gateway.proxy_endpoint SET lifecycle_code='active',drained_at=NULL,revision=revision+1, \
                       updated_at=clock_timestamp() WHERE id=$1 AND revision=$2 AND lifecycle_code='disabled' \
                       AND health_code='healthy' RETURNING revision,auth_secret_id",
                )
                .bind(proxy_id)
                .bind(expected_revision)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                sqlx::query(
                    "UPDATE gateway.credential_egress_binding SET stability_code='stable',lifecycle_code='active', \
                       rebind_reason_code=NULL,revision=revision+1,updated_at=clock_timestamp() \
                     WHERE proxy_id=$1 AND lifecycle_code='transport_unavailable' AND rebind_reason_code='proxy_disabled'",
                )
                .bind(proxy_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                sqlx::query(
                    "UPDATE gateway.anthropic_credential c SET transport_state_code='ready',revision=revision+1, \
                       updated_at=clock_timestamp() WHERE id=ANY($1) AND EXISTS (SELECT 1 FROM gateway.credential_egress_binding b \
                         WHERE b.credential_id=c.id AND b.proxy_id=$2 AND b.lifecycle_code='active' AND b.stability_code='stable')",
                )
                .bind(&credential_ids)
                .bind(proxy_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                row
            }
            "archive" => {
                if !credential_ids.is_empty() {
                    return Err(ManagementBackendError::Precondition);
                }
                sqlx::query(
                    "UPDATE gateway.proxy_endpoint SET lifecycle_code='archived',archived_at=clock_timestamp(), \
                       revision=revision+1,updated_at=clock_timestamp() \
                     WHERE id=$1 AND revision=$2 AND lifecycle_code='disabled' RETURNING revision,auth_secret_id",
                )
                .bind(proxy_id)
                .bind(expected_revision)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
            }
            _ => return Err(ManagementBackendError::InvalidInput),
        }
        .ok_or(ManagementBackendError::Precondition)?;
        let revision = required::<i64>(&row, "revision")?;
        if action == "archive"
            && let Some(secret_id) = required::<Option<Uuid>>(&row, "auth_secret_id")?
        {
            sqlx::query(
                "UPDATE security.encrypted_secret SET superseded_at=COALESCE(superseded_at,clock_timestamp()), \
                   destroyed_at=clock_timestamp(),ciphertext='\\x'::bytea,wrapped_dek='\\x'::bytea \
                 WHERE id=$1 AND destroyed_at IS NULL",
            )
            .bind(secret_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    &format!("proxy_{action}"),
                    "proxy",
                    proxy_id,
                    revision,
                    json!({"reason":reason,"affected_credentials":credential_ids.len()}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.list_proxies(Some(proxy_id)).await
    }

    async fn replace_proxy_secret(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ProxyReplaceSecretCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        if command.username.is_empty()
            || command.username.len() > 1_024
            || command.password.is_empty()
            || command.password.len() > 4_096
            || command.username.contains(['\r', '\n'])
            || command.password.contains(['\r', '\n'])
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let proxy_id = path_uuid(request, "id")?;
        let secret_id = Uuid::now_v7();
        let (aad, envelope) = self
            .encrypt_proxy_secret(proxy_id, secret_id, &command.username, &command.password)
            .await?;
        let job_id = Uuid::now_v7();
        let grant_id = parse_input_uuid(&command.step_up_grant_id)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        consume_step_up_in(&mut transaction, principal, grant_id, "key_provider_change").await?;
        let proxy = sqlx::query(
            "SELECT auth_secret_id FROM gateway.proxy_endpoint WHERE id=$1 AND revision=$2 \
             AND lifecycle_code<>'archived' FOR UPDATE",
        )
        .bind(proxy_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let previous_secret_id = required::<Option<Uuid>>(&proxy, "auth_secret_id")?;
        insert_secret(&mut transaction, secret_id, &aad, &envelope).await?;
        let update = sqlx::query(
            "UPDATE gateway.proxy_endpoint SET auth_secret_id=$3,health_code='probing', \
               probe_generation=probe_generation+1,revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 AND revision=$2 RETURNING probe_generation,revision",
        )
        .bind(proxy_id)
        .bind(expected_revision)
        .bind(secret_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some(previous_secret_id) = previous_secret_id {
            sqlx::query(
                "UPDATE security.encrypted_secret SET superseded_at=clock_timestamp(),destroyed_at=clock_timestamp(), \
                   ciphertext='\\x'::bytea,wrapped_dek='\\x'::bytea WHERE id=$1 AND destroyed_at IS NULL",
            )
            .bind(previous_secret_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        let generation = required::<i64>(&update, "probe_generation")?;
        let revision = required::<i64>(&update, "revision")?;
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'proxy_full_path_probe_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,5,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("proxy-secret-probe:{proxy_id}:{generation}"))
        .bind(json!({"proxy_id":proxy_id,"probe_generation":generation}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_job_created_history(&mut transaction, job_id, "proxy_secret_replaced_probe_scheduled").await?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "proxy_secret_replaced",
                    "proxy",
                    proxy_id,
                    revision,
                    json!({"reason":reason,"probe_generation":generation,"job_id":job_id}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(async_job_response(
            job_id,
            "proxy_full_path_probe_v1",
            "queued",
            &created_at,
        ))
    }

    async fn list_credential_profiles(
        &self,
        profile_id: Option<Uuid>,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT p.id,p.credential_id,p.archetype_version_id,p.device_identity_id,p.egress_binding_id, \
                    p.profile_epoch,p.capture_cohort,p.lifecycle_code,p.session_derivation_version,p.allocation_evidence, \
                    p.revision,p.created_at::text AS created_at,p.updated_at::text AS updated_at,d.device_epoch, \
                    encode(d.installation_id_digest,'hex') AS installation_id_digest, \
                    encode(d.client_id_digest,'hex') AS client_id_digest,a.version AS archetype_version, \
                    root.name AS archetype_name,root.os_family_code,root.architecture_code,b.transport_bundle_id \
             FROM gateway.credential_profile p JOIN gateway.device_identity d ON d.id=p.device_identity_id \
             JOIN catalog.environment_archetype_version a ON a.id=p.archetype_version_id \
             JOIN catalog.environment_archetype root ON root.id=a.archetype_id \
             LEFT JOIN LATERAL (SELECT transport_bundle_id FROM catalog.archetype_bundle_binding \
               WHERE archetype_version_id=a.id AND state_code='active' ORDER BY protocol_code LIMIT 1) b ON true \
             WHERE ($1::uuid IS NULL OR p.id=$1) ORDER BY p.created_at DESC,p.id DESC LIMIT 100",
        )
        .bind(profile_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if profile_id.is_some() && rows.is_empty() {
            return Err(ManagementBackendError::NotFound);
        }
        let data = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "id":required::<Uuid>(row,"id")?,"credential_id":required::<Uuid>(row,"credential_id")?,
                    "archetype_version_id":required::<Uuid>(row,"archetype_version_id")?,
                    "device_identity_id":required::<Uuid>(row,"device_identity_id")?,"egress_binding_id":required::<Uuid>(row,"egress_binding_id")?,
                    "profile_epoch":required::<i64>(row,"profile_epoch")?,"capture_cohort":required::<String>(row,"capture_cohort")?,
                    "bundle_id":required::<Option<Uuid>>(row,"transport_bundle_id")?,"lifecycle":required::<String>(row,"lifecycle_code")?,
                    "session_derivation_version":required::<i32>(row,"session_derivation_version")?,
                    "allocation_evidence":required::<Value>(row,"allocation_evidence")?,"device_epoch":required::<i64>(row,"device_epoch")?,
                    "installation_id_digest":required::<String>(row,"installation_id_digest")?,
                    "client_id_digest":required::<String>(row,"client_id_digest")?,"archetype_version":required::<i64>(row,"archetype_version")?,
                    "archetype_name":required::<String>(row,"archetype_name")?,"os_family":required::<String>(row,"os_family_code")?,
                    "architecture":required::<String>(row,"architecture_code")?,"revision":required::<i64>(row,"revision")?,
                    "created_at":required::<String>(row,"created_at")?,"updated_at":required::<String>(row,"updated_at")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        if profile_id.is_some() {
            let row = data.into_iter().next().ok_or(ManagementBackendError::NotFound)?;
            let revision = row["revision"].as_i64().ok_or(ManagementBackendError::Unavailable)?;
            Ok(single_response(&row, revision))
        } else {
            Ok(list_response(&data))
        }
    }

    async fn list_egress_bindings(
        &self,
        binding_id: Option<Uuid>,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT e.id,e.credential_id,e.mode_code,e.proxy_id,e.stability_code,e.lifecycle_code,e.egress_epoch, \
                    e.expected_egress_ip IS NOT NULL AS expected_ip_present,e.observed_egress_ip IS NOT NULL AS observed_ip_present, \
                    e.observed_at::text AS observed_at,e.rebound_at::text AS rebound_at,e.rebind_reason_code,e.revision, \
                    e.created_at::text AS created_at,e.updated_at::text AS updated_at,p.proxy_type_code,p.lifecycle_code AS proxy_lifecycle, \
                    p.health_code AS proxy_health,p.stability_code AS proxy_stability \
             FROM gateway.credential_egress_binding e LEFT JOIN gateway.proxy_endpoint p ON p.id=e.proxy_id \
             WHERE ($1::uuid IS NULL OR e.id=$1) ORDER BY e.created_at DESC,e.id DESC LIMIT 100",
        )
        .bind(binding_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if binding_id.is_some() && rows.is_empty() {
            return Err(ManagementBackendError::NotFound);
        }
        let data = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "id":required::<Uuid>(row,"id")?,"credential_id":required::<Uuid>(row,"credential_id")?,
                    "mode":required::<String>(row,"mode_code")?,"proxy_id":required::<Option<Uuid>>(row,"proxy_id")?,
                    "stability":required::<String>(row,"stability_code")?,"lifecycle":required::<String>(row,"lifecycle_code")?,
                    "egress_epoch":required::<i64>(row,"egress_epoch")?,
                    "expected_exit_ip_digest":if required::<bool>(row,"expected_ip_present")? {Some("redacted") } else {None},
                    "observed_exit_ip_digest":if required::<bool>(row,"observed_ip_present")? {Some("redacted") } else {None},
                    "observed_at":required::<Option<String>>(row,"observed_at")?,"rebound_at":required::<Option<String>>(row,"rebound_at")?,
                    "rebind_reason":required::<Option<String>>(row,"rebind_reason_code")?,"proxy_type":required::<Option<String>>(row,"proxy_type_code")?,
                    "proxy_lifecycle":required::<Option<String>>(row,"proxy_lifecycle")?,"proxy_health":required::<Option<String>>(row,"proxy_health")?,
                    "proxy_stability":required::<Option<String>>(row,"proxy_stability")?,"revision":required::<i64>(row,"revision")?,
                    "created_at":required::<String>(row,"created_at")?,"updated_at":required::<String>(row,"updated_at")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        if binding_id.is_some() {
            let row = data.into_iter().next().ok_or(ManagementBackendError::NotFound)?;
            let revision = row["revision"].as_i64().ok_or(ManagementBackendError::Unavailable)?;
            Ok(single_response(&row, revision))
        } else {
            Ok(list_response(&data))
        }
    }

    async fn list_environment_archetypes(
        &self,
        archetype_id: Option<Uuid>,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT root.id,root.name,root.os_family_code,root.architecture_code,root.os_build,root.client_family_code, \
                    root.lifecycle_code,root.revision,root.created_at::text AS created_at,root.updated_at::text AS updated_at, \
                    version.id AS version_id,version.version,version.lifecycle_code AS version_lifecycle,version.runtime_code, \
                    version.runtime_version,version.client_version,version.profile_schema_version,version.capture_cohort, \
                    evidence.state_code AS evidence_state,capacity.max_credentials,capacity.max_connections, \
                    capacity.allocation_weight,capacity.allocation_cohort,bundle.transport_bundle_id \
             FROM catalog.environment_archetype root LEFT JOIN LATERAL (SELECT * FROM catalog.environment_archetype_version \
               WHERE archetype_id=root.id ORDER BY version DESC LIMIT 1) version ON true \
             LEFT JOIN catalog.evidence_set evidence ON evidence.id=version.evidence_set_id \
             LEFT JOIN catalog.archetype_capacity_policy capacity ON capacity.archetype_version_id=version.id \
             LEFT JOIN LATERAL (SELECT transport_bundle_id FROM catalog.archetype_bundle_binding \
               WHERE archetype_version_id=version.id AND state_code='active' ORDER BY protocol_code LIMIT 1) bundle ON true \
             WHERE ($1::uuid IS NULL OR root.id=$1) ORDER BY root.created_at DESC,root.id DESC LIMIT 100",
        )
        .bind(archetype_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if archetype_id.is_some() && rows.is_empty() {
            return Err(ManagementBackendError::NotFound);
        }
        let data = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "id":required::<Uuid>(row,"id")?,"name":required::<String>(row,"name")?,
                    "os_family":required::<String>(row,"os_family_code")?,"architecture":required::<String>(row,"architecture_code")?,
                    "os_build":required::<Option<String>>(row,"os_build")?,"client_family":required::<String>(row,"client_family_code")?,
                    "lifecycle":required::<String>(row,"lifecycle_code")?,"version_id":required::<Option<Uuid>>(row,"version_id")?,
                    "version":required::<Option<i64>>(row,"version")?,"version_lifecycle":required::<Option<String>>(row,"version_lifecycle")?,
                    "runtime":required::<Option<String>>(row,"runtime_code")?,"runtime_version":required::<Option<String>>(row,"runtime_version")?,
                    "client_version":required::<Option<String>>(row,"client_version")?,"profile_schema_version":required::<Option<i32>>(row,"profile_schema_version")?,
                    "capture_cohort":required::<Option<String>>(row,"capture_cohort")?,"evidence_state":required::<Option<String>>(row,"evidence_state")?,
                    "max_credentials":required::<Option<i32>>(row,"max_credentials")?,"max_connections":required::<Option<i32>>(row,"max_connections")?,
                    "allocation_weight":required::<Option<i32>>(row,"allocation_weight")?,"allocation_cohort":required::<Option<String>>(row,"allocation_cohort")?,
                    "active_bundle_id":required::<Option<Uuid>>(row,"transport_bundle_id")?,"revision":required::<i64>(row,"revision")?,
                    "created_at":required::<String>(row,"created_at")?,"updated_at":required::<String>(row,"updated_at")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        if archetype_id.is_some() {
            let row = data.into_iter().next().ok_or(ManagementBackendError::NotFound)?;
            let revision = row["revision"].as_i64().ok_or(ManagementBackendError::Unavailable)?;
            Ok(single_response(&row, revision))
        } else {
            Ok(list_response(&data))
        }
    }

    async fn list_transport_bundles(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT bundle.id,bundle.artifact_version,bundle.engine_abi_version,bundle.lifecycle_code, \
                    encode(bundle.manifest_hash,'hex') AS manifest_hash,bundle.signing_key_id,bundle.object_uri, \
                    bundle.source_archetype_version_id,bundle.capture_cohort,bundle.protocol_code,bundle.backend_id, \
                    bundle.evidence_gate_code,bundle.runtime_state_code,bundle.min_engine_build,bundle.max_engine_build, \
                    bundle.engine_activation_generation,bundle.created_at::text AS created_at, \
                    bundle.activated_at::text AS activated_at,binding.state_code AS binding_state, \
                    root.id AS archetype_id,root.name AS archetype_name,version.version AS archetype_version \
             FROM catalog.transport_bundle bundle \
             LEFT JOIN catalog.archetype_bundle_binding binding ON binding.transport_bundle_id=bundle.id \
             LEFT JOIN catalog.environment_archetype_version version ON version.id=bundle.source_archetype_version_id \
             LEFT JOIN catalog.environment_archetype root ON root.id=version.archetype_id \
             ORDER BY bundle.artifact_version DESC,bundle.id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .map(transport_bundle_projection)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn create_transport_bundle(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let runtime = self
            .transport_runtime
            .as_ref()
            .ok_or(ManagementBackendError::Unavailable)?;
        let command: TransportBundleCreateCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        if command.name.trim().is_empty()
            || command.name.len() > 128
            || command.schema_version != 1
            || command.source_refs.len() > 128
            || command
                .source_refs
                .iter()
                .any(|value| value.is_empty() || value.len() > 2_048 || value.contains(['\r', '\n']))
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let envelope: SignedBundleEnvelope = serde_json::from_value(command.signed_envelope.clone())
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        if envelope.payload.lifecycle != BundleLifecycle::Verified
            || envelope.payload.evidence_gate != BundleEvidenceGate::Passed
            || envelope.payload.runtime_state != BundleRuntimeState::Loadable
        {
            return Err(ManagementBackendError::Precondition);
        }
        let envelope_bytes = serde_json::to_vec(&envelope).map_err(|_| ManagementBackendError::InvalidInput)?;
        if envelope_bytes.len() > 8 * 1024 * 1024 {
            return Err(ManagementBackendError::InvalidInput);
        }
        runtime.verify_and_compile(&envelope_bytes, true)?;
        let source_version_id = parse_input_uuid(&envelope.payload.source_archetype_version_id)?;
        let protocol = bundle_protocol(&envelope.payload.application);
        let manifest_hash = decode_sha256_hex(&envelope.canonicalization.canonical_hash)?.to_vec();
        let signature = base64::engine::general_purpose::STANDARD
            .decode(envelope.signature.detached_signature_base64.as_bytes())
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        if signature.len() != 64 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let artifact_version =
            i64::try_from(envelope.payload.artifact_version).map_err(|_| ManagementBackendError::InvalidInput)?;
        let bundle_id = Uuid::now_v7();
        let stage_path = runtime.bundle_dir.join(format!("{bundle_id}.stage"));
        let final_path = runtime.bundle_dir.join(format!("{bundle_id}.json"));
        let mut stage = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&stage_path)
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let write_result = stage.write_all(&envelope_bytes).and_then(|()| stage.sync_all());
        drop(stage);
        if write_result.is_err() {
            let _ = std::fs::remove_file(&stage_path);
            return Err(ManagementBackendError::Unavailable);
        }
        if std::fs::rename(&stage_path, &final_path).is_err() {
            let _ = std::fs::remove_file(&stage_path);
            return Err(ManagementBackendError::Unavailable);
        }

        let result: Result<ManagementBackendResponse, ManagementBackendError> = async {
            let mut transaction = self
                .storage
                .pool()
                .begin()
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            let source_valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM catalog.environment_archetype_version version \
                 JOIN catalog.evidence_set evidence ON evidence.id=version.evidence_set_id \
                 WHERE version.id=$1 AND version.lifecycle_code IN ('verified','canary','active') \
                   AND version.capture_cohort=$2 AND evidence.state_code='complete')",
            )
            .bind(source_version_id)
            .bind(&envelope.payload.capture_cohort)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            if !source_valid {
                return Err(ManagementBackendError::Precondition);
            }
            sqlx::query(
                "INSERT INTO catalog.transport_bundle \
                 (id,artifact_version,engine_abi_version,lifecycle_code,manifest,manifest_hash,signature,signing_key_id, \
                  object_uri,created_at,source_archetype_version_id,capture_cohort,protocol_code,backend_id, \
                  canonicalization_algorithm,signature_domain,signature_algorithm,evidence_gate_code,runtime_state_code, \
                  min_engine_build,max_engine_build,engine_activation_generation) \
                 VALUES ($1,$2,$3,'draft',$4,$5,$6,$7,$8,clock_timestamp(),$9,$10,$11,$12, \
                         'jcs_rfc8785','transport_bundle_v1','ed25519','pending','loadable',$13,$14,1)",
            )
            .bind(bundle_id)
            .bind(artifact_version)
            .bind(envelope.payload.engine_abi_version.as_ref())
            .bind(&command.signed_envelope)
            .bind(&manifest_hash)
            .bind(&signature)
            .bind(envelope.signature.key_id.as_ref())
            .bind(final_path.to_string_lossy().as_ref())
            .bind(source_version_id)
            .bind(envelope.payload.capture_cohort.as_ref())
            .bind(protocol)
            .bind(envelope.payload.backend_id.as_ref())
            .bind(envelope.payload.min_engine_build.as_ref())
            .bind(envelope.payload.max_engine_build.as_deref())
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Precondition)?;
            sqlx::query(
                "INSERT INTO catalog.archetype_bundle_binding \
                 (archetype_version_id,transport_bundle_id,state_code,created_at,protocol_code) \
                 VALUES ($1,$2,'candidate',clock_timestamp(),$3)",
            )
            .bind(source_version_id)
            .bind(bundle_id)
            .bind(protocol)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Precondition)?;
            self.storage
                .append_audit_outbox_in(
                    &mut transaction,
                    &management_audit(
                        principal,
                        "transport_bundle_created",
                        "transport_bundle",
                        bundle_id,
                        artifact_version,
                        json!({
                            "name":command.name.trim(),"source_archetype_version_id":source_version_id,
                            "capture_cohort":envelope.payload.capture_cohort,"protocol":protocol,
                            "manifest_hash":lower_hex(&manifest_hash),"reason":reason
                        }),
                    )?,
                )
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            transaction
                .commit()
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            Ok(ManagementBackendResponse {
                status: axum::http::StatusCode::CREATED,
                body: json!({"data":{"id":bundle_id,"artifact_version":artifact_version,"lifecycle":"draft",
                    "source_archetype_version_id":source_version_id,"capture_cohort":envelope.payload.capture_cohort,
                    "protocol":protocol,"evidence_gate":"pending","runtime_state":"loadable","revision":artifact_version},"meta":{}}),
                etag: Some(format!("\"rev-{artifact_version}\"").into_boxed_str()),
                session_cookie: None,
                clear_session_cookie: false,
                no_store: false,
            })
        }
        .await;
        if result.is_err() {
            let _ = std::fs::remove_file(&final_path);
        }
        result
    }

    async fn verify_transport_bundle(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let runtime = self
            .transport_runtime
            .as_ref()
            .ok_or(ManagementBackendError::Unavailable)?;
        let command: LifecycleActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(command.reason.as_deref())?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let bundle_id = path_uuid(request, "id")?;
        let row = sqlx::query(
            "SELECT artifact_version,lifecycle_code,object_uri,source_archetype_version_id,capture_cohort,protocol_code, \
                    engine_abi_version,backend_id,manifest_hash,signing_key_id,min_engine_build,max_engine_build \
             FROM catalog.transport_bundle WHERE id=$1",
        )
        .bind(bundle_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let artifact_version = required::<i64>(&row, "artifact_version")?;
        if artifact_version != expected_revision || required::<String>(&row, "lifecycle_code")? != "draft" {
            return Err(ManagementBackendError::Precondition);
        }
        let path = checked_bundle_path(runtime, &required::<String>(&row, "object_uri")?)?;
        let bytes = std::fs::read(path).map_err(|_| ManagementBackendError::Unavailable)?;
        runtime.verify_and_compile(&bytes, true)?;
        let envelope: SignedBundleEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| ManagementBackendError::InvalidInput)?;
        let source_version_id = parse_input_uuid(&envelope.payload.source_archetype_version_id)?;
        if i64::try_from(envelope.payload.artifact_version).ok() != Some(artifact_version)
            || required::<Uuid>(&row, "source_archetype_version_id")? != source_version_id
            || required::<String>(&row, "capture_cohort")? != envelope.payload.capture_cohort.as_ref()
            || required::<String>(&row, "protocol_code")? != bundle_protocol(&envelope.payload.application)
            || required::<String>(&row, "engine_abi_version")? != envelope.payload.engine_abi_version.as_ref()
            || required::<String>(&row, "backend_id")? != envelope.payload.backend_id.as_ref()
            || required::<Vec<u8>>(&row, "manifest_hash")?
                != decode_sha256_hex(&envelope.canonicalization.canonical_hash)?.to_vec()
            || required::<String>(&row, "signing_key_id")? != envelope.signature.key_id.as_ref()
            || required::<String>(&row, "min_engine_build")? != envelope.payload.min_engine_build.as_ref()
            || required::<Option<String>>(&row, "max_engine_build")?.as_deref()
                != envelope.payload.max_engine_build.as_deref()
        {
            return Err(ManagementBackendError::Precondition);
        }
        let evidence_set_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT evidence_set_id FROM catalog.environment_archetype_version \
             WHERE id=$1 AND lifecycle_code IN ('verified','canary','active') AND capture_cohort=$2",
        )
        .bind(source_version_id)
        .bind(envelope.payload.capture_cohort.as_ref())
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .flatten();
        let evidence_set_id = evidence_set_id.ok_or(ManagementBackendError::Precondition)?;
        for hash in &envelope.payload.evidence_hashes {
            let digest = decode_sha256_hex(hash)?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM catalog.evidence_item WHERE evidence_set_id=$1 AND content_hash=$2)",
            )
            .bind(evidence_set_id)
            .bind(digest.to_vec())
            .fetch_one(&self.storage.pool())
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            if !exists {
                return Err(ManagementBackendError::Precondition);
            }
        }
        let replay_passed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM catalog.replay_verification \
             WHERE archetype_version_id=$1 AND transport_bundle_id=$2 AND evidence_set_id=$3 AND state_code='passed')",
        )
        .bind(source_version_id)
        .bind(bundle_id)
        .bind(evidence_set_id)
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if !replay_passed {
            return Err(ManagementBackendError::Precondition);
        }

        let job_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let updated = sqlx::query(
            "UPDATE catalog.transport_bundle SET lifecycle_code='verified',evidence_gate_code='passed', \
             runtime_state_code='loadable' WHERE id=$1 AND artifact_version=$2 AND lifecycle_code='draft'",
        )
        .bind(bundle_id)
        .bind(artifact_version)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if updated.rows_affected() != 1 {
            return Err(ManagementBackendError::Precondition);
        }
        let completed_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at,completed_at) \
             VALUES ($1,'transport_bundle_verify_v1',$2,'succeeded',1,$3,clock_timestamp(),0,1,1, \
                     clock_timestamp(),clock_timestamp(),clock_timestamp()) RETURNING completed_at::text",
        )
        .bind(job_id)
        .bind(format!("transport-bundle-verify:{bundle_id}:{artifact_version}"))
        .bind(json!({"transport_bundle_id":bundle_id,"artifact_version":artifact_version}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,NULL,'succeeded',0,'verified',$3,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(json!({"bundle_id":bundle_id,"evidence_set_id":evidence_set_id}))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "transport_bundle_verified",
                    "transport_bundle",
                    bundle_id,
                    artifact_version,
                    json!({"evidence_set_id":evidence_set_id,"job_id":job_id,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(completed_job_response(
            job_id,
            "transport_bundle_verify_v1",
            &completed_at,
        ))
    }

    async fn promote_transport_bundle_canary(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: LifecycleActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(command.reason.as_deref())?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let bundle_id = path_uuid(request, "id")?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let target = sqlx::query(
            "SELECT artifact_version,lifecycle_code,manifest_hash,source_archetype_version_id, \
                    evidence_gate_code,runtime_state_code \
             FROM catalog.transport_bundle WHERE id=$1 FOR UPDATE",
        )
        .bind(bundle_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let artifact_version = required::<i64>(&target, "artifact_version")?;
        let source_version_id = required::<Uuid>(&target, "source_archetype_version_id")?;
        if artifact_version != expected_revision
            || required::<String>(&target, "lifecycle_code")? != "verified"
            || required::<String>(&target, "evidence_gate_code")? != "passed"
            || required::<String>(&target, "runtime_state_code")? != "loadable"
        {
            return Err(ManagementBackendError::Precondition);
        }
        let source_verified: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM catalog.environment_archetype_version \
             WHERE id=$1 AND lifecycle_code IN ('verified','canary','active'))",
        )
        .bind(source_version_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let replay = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT result FROM catalog.replay_verification \
             WHERE archetype_version_id=$1 AND transport_bundle_id=$2 AND state_code='passed' \
             ORDER BY verified_at DESC,id DESC LIMIT 1",
        )
        .bind(source_version_id)
        .bind(bundle_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let manifest_hash = required::<Vec<u8>>(&target, "manifest_hash")?;
        if !source_verified
            || !replay
                .as_ref()
                .is_some_and(|result| transport_canary_evidence_valid(result, &manifest_hash))
        {
            return Err(ManagementBackendError::Precondition);
        }
        let updated = sqlx::query(
            "UPDATE catalog.transport_bundle SET lifecycle_code='canary' \
             WHERE id=$1 AND artifact_version=$2 AND lifecycle_code='verified'",
        )
        .bind(bundle_id)
        .bind(artifact_version)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if updated.rows_affected() != 1 {
            return Err(ManagementBackendError::Precondition);
        }
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "transport_bundle_canary_promoted",
                    "transport_bundle",
                    bundle_id,
                    artifact_version,
                    json!({
                        "source_archetype_version_id":source_version_id,
                        "fresh_iterations":replay.as_ref().and_then(|value| value.get("iterations")),
                        "report_sha256":replay.as_ref().and_then(|value| value.get("report_sha256")),
                        "reason":reason
                    }),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(
            &json!({
                "id":bundle_id,"artifact_version":artifact_version,"lifecycle":"canary",
                "source_archetype_version_id":source_version_id,"revision":artifact_version
            }),
            artifact_version,
        ))
    }

    async fn activate_transport_bundle(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        rollback: bool,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let runtime = self
            .transport_runtime
            .as_ref()
            .ok_or(ManagementBackendError::Unavailable)?;
        let _activation_guard = runtime.activation_lock.lock().await;
        let command: TransportBundleActivateCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let bundle_id = path_uuid(request, "id")?;
        let approval_id = parse_input_uuid(&command.approval_case_id)?;
        let step_up_id = parse_input_uuid(&command.step_up_grant_id)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('catalog:transport-bundle-activation'))")
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let target = sqlx::query(
            "SELECT artifact_version,lifecycle_code,object_uri,source_archetype_version_id,protocol_code, \
                    evidence_gate_code,runtime_state_code \
             FROM catalog.transport_bundle WHERE id=$1 FOR UPDATE",
        )
        .bind(bundle_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let artifact_version = required::<i64>(&target, "artifact_version")?;
        let lifecycle = required::<String>(&target, "lifecycle_code")?;
        let allowed = if rollback {
            lifecycle == "retired"
        } else {
            lifecycle == "canary"
        };
        if artifact_version != expected_revision
            || !allowed
            || required::<String>(&target, "evidence_gate_code")? != "passed"
            || required::<String>(&target, "runtime_state_code")? != "loadable"
        {
            return Err(ManagementBackendError::Precondition);
        }
        let source_version_id = required::<Uuid>(&target, "source_archetype_version_id")?;
        let protocol = required::<String>(&target, "protocol_code")?;
        let source_ready: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM catalog.environment_archetype_version \
             WHERE id=$1 AND lifecycle_code IN ('canary','active'))",
        )
        .bind(source_version_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if !source_ready {
            return Err(ManagementBackendError::Precondition);
        }
        consume_step_up_in(&mut transaction, principal, step_up_id, "bundle_activation").await?;
        consume_approved_case(
            &mut transaction,
            approval_id,
            "bundle_activation",
            "transport_bundle",
            &bundle_id.to_string(),
        )
        .await?;
        let path = checked_bundle_path(runtime, &required::<String>(&target, "object_uri")?)?;
        let bytes = std::fs::read(path).map_err(|_| ManagementBackendError::Unavailable)?;
        runtime.verify_and_compile(&bytes, true)?;
        let prepared_catalog = runtime.stage_directory()?;
        let current = sqlx::query(
            "SELECT binding.transport_bundle_id FROM catalog.archetype_bundle_binding binding \
             WHERE binding.archetype_version_id=$1 AND binding.protocol_code=$2 AND binding.state_code='active' FOR UPDATE",
        )
        .bind(source_version_id)
        .bind(&protocol)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let previous_bundle_id = current
            .as_ref()
            .map(|row| required::<Uuid>(row, "transport_bundle_id"))
            .transpose()?;
        if previous_bundle_id == Some(bundle_id) {
            return Err(ManagementBackendError::Precondition);
        }
        if let Some(previous) = previous_bundle_id {
            sqlx::query(
                "UPDATE catalog.archetype_bundle_binding SET state_code='retired' \
                 WHERE archetype_version_id=$1 AND protocol_code=$2 AND transport_bundle_id=$3",
            )
            .bind(source_version_id)
            .bind(&protocol)
            .bind(previous)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                "UPDATE catalog.transport_bundle SET lifecycle_code='retired' WHERE id=$1 AND lifecycle_code='active'",
            )
            .bind(previous)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        let activation_generation: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(engine_activation_generation),0)+1 FROM catalog.transport_bundle")
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "UPDATE catalog.transport_bundle SET lifecycle_code='active',activated_at=clock_timestamp(), \
             engine_activation_generation=$2 WHERE id=$1",
        )
        .bind(bundle_id)
        .bind(activation_generation)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "UPDATE catalog.archetype_bundle_binding SET state_code='active',activated_at=clock_timestamp() \
             WHERE archetype_version_id=$1 AND protocol_code=$2 AND transport_bundle_id=$3",
        )
        .bind(source_version_id)
        .bind(&protocol)
        .bind(bundle_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    if rollback {
                        "transport_bundle_rolled_back"
                    } else {
                        "transport_bundle_activated"
                    },
                    "transport_bundle",
                    bundle_id,
                    activation_generation,
                    json!({
                        "artifact_version":artifact_version,"source_archetype_version_id":source_version_id,
                        "protocol":protocol,"previous_bundle_id":previous_bundle_id,"approval_case_id":approval_id,
                        "reason":reason
                    }),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let runtime_activation = runtime.publish(prepared_catalog);
        if let Some(dispatcher) = &self.scheduler_runtime {
            dispatcher.drain_transport_generation(runtime_activation.previous);
        }
        Ok(single_response(
            &json!({
                "id":bundle_id,"artifact_version":artifact_version,"lifecycle":"active",
                "source_archetype_version_id":source_version_id,"protocol":protocol,
                "previous_bundle_id":previous_bundle_id,"engine_activation_generation":activation_generation,
                "runtime_generation":runtime_activation.current.get(),"revision":artifact_version
            }),
            artifact_version,
        ))
    }

    async fn create_environment_archetype(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: EnvironmentArchetypeCreateCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let payload = &command.payload;
        if command.name.trim().is_empty()
            || command.name.len() > 128
            || command.schema_version != 1
            || !matches!(payload.os_family.as_str(), "windows" | "macos" | "linux")
            || !matches!(payload.architecture.as_str(), "x86_64" | "aarch64")
            || payload.os_build.trim().is_empty()
            || payload.client_family != "claude_code_cli"
            || payload.runtime.trim().is_empty()
            || payload.runtime_version.trim().is_empty()
            || payload.client_version.trim().is_empty()
            || payload.profile_schema_version == 0
            || payload.capture_cohort.trim().is_empty()
            || !payload.protocol_profile.is_object()
            || payload.capacity.max_credentials == 0
            || payload.capacity.max_connections == 0
            || payload.capacity.allocation_weight == 0
            || payload.capacity.allocation_cohort.trim().is_empty()
            || command.source_refs.len() > 128
            || command
                .source_refs
                .iter()
                .any(|value| value.is_empty() || value.len() > 2_048 || value.contains(['\r', '\n']))
            || [
                &payload.os_build,
                &payload.runtime,
                &payload.runtime_version,
                &payload.client_version,
                &payload.capture_cohort,
                &payload.capacity.allocation_cohort,
            ]
            .into_iter()
            .any(|value| value.len() > 256)
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let requested_root_id = command.archetype_id.as_deref().map(parse_input_uuid).transpose()?;
        let evidence_set_id = payload.evidence_set_id.as_deref().map(parse_input_uuid).transpose()?;
        let normalized = serde_json::to_value(payload).map_err(|_| ManagementBackendError::Unavailable)?;
        let content_hash = Sha256::digest(canonical_json_bytes(&normalized)?).to_vec();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!(
                "catalog:archetype:{}",
                requested_root_id.map_or_else(|| command.name.trim().to_owned(), |id| id.to_string())
            ))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some(evidence_id) = evidence_set_id {
            let evidence_valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM catalog.evidence_set \
                 WHERE id=$1 AND state_code<>'invalidated' AND capture_cohort IS NOT DISTINCT FROM $2)",
            )
            .bind(evidence_id)
            .bind(&payload.capture_cohort)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            if !evidence_valid {
                return Err(ManagementBackendError::Precondition);
            }
        }
        let (archetype_id, root_revision, version) = if let Some(archetype_id) = requested_root_id {
            let root = sqlx::query(
                "SELECT name,os_family_code,architecture_code,client_family_code,lifecycle_code,revision \
                 FROM catalog.environment_archetype WHERE id=$1 FOR UPDATE",
            )
            .bind(archetype_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?
            .ok_or(ManagementBackendError::NotFound)?;
            if required::<String>(&root, "name")? != command.name.trim()
                || required::<String>(&root, "os_family_code")? != payload.os_family
                || required::<String>(&root, "architecture_code")? != payload.architecture
                || required::<String>(&root, "client_family_code")? != payload.client_family
                || required::<String>(&root, "lifecycle_code")? != "active"
            {
                return Err(ManagementBackendError::Precondition);
            }
            let version: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(version),0)+1 FROM catalog.environment_archetype_version WHERE archetype_id=$1",
            )
            .bind(archetype_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let revision: i64 = sqlx::query_scalar(
                "UPDATE catalog.environment_archetype SET revision=revision+1,updated_at=clock_timestamp() \
                 WHERE id=$1 RETURNING revision",
            )
            .bind(archetype_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            (archetype_id, revision, version)
        } else {
            let archetype_id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO catalog.environment_archetype \
                 (id,name,os_family_code,architecture_code,lifecycle_code,created_at,updated_at,revision,os_build,client_family_code) \
                 VALUES ($1,$2,$3,$4,'active',clock_timestamp(),clock_timestamp(),1,$5,$6)",
            )
            .bind(archetype_id)
            .bind(command.name.trim())
            .bind(&payload.os_family)
            .bind(&payload.architecture)
            .bind(&payload.os_build)
            .bind(&payload.client_family)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Precondition)?;
            (archetype_id, 1, 1)
        };
        let version_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO catalog.environment_archetype_version \
             (id,archetype_id,version,lifecycle_code,runtime_code,runtime_version,client_version,protocol_profile, \
              evidence_set_id,content_hash,created_at,os_build,architecture_code,client_family_code,capture_cohort,profile_schema_version) \
             VALUES ($1,$2,$3,'draft',$4,$5,$6,$7,$8,$9,clock_timestamp(),$10,$11,$12,$13,$14)",
        )
        .bind(version_id)
        .bind(archetype_id)
        .bind(version)
        .bind(&payload.runtime)
        .bind(&payload.runtime_version)
        .bind(&payload.client_version)
        .bind(&payload.protocol_profile)
        .bind(evidence_set_id)
        .bind(&content_hash)
        .bind(&payload.os_build)
        .bind(&payload.architecture)
        .bind(&payload.client_family)
        .bind(&payload.capture_cohort)
        .bind(i32::try_from(payload.profile_schema_version).map_err(|_| ManagementBackendError::InvalidInput)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        sqlx::query(
            "INSERT INTO catalog.archetype_capacity_policy \
             (id,archetype_version_id,max_credentials,max_connections,revision,created_at,updated_at,allocation_weight,allocation_cohort) \
             VALUES ($1,$2,$3,$4,1,clock_timestamp(),clock_timestamp(),$5,$6)",
        )
        .bind(Uuid::now_v7())
        .bind(version_id)
        .bind(i32::try_from(payload.capacity.max_credentials).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i32::try_from(payload.capacity.max_connections).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(i32::try_from(payload.capacity.allocation_weight).map_err(|_| ManagementBackendError::InvalidInput)?)
        .bind(&payload.capacity.allocation_cohort)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "environment_archetype_version_created",
                    "environment_archetype",
                    archetype_id,
                    root_revision,
                    json!({
                        "version_id":version_id,"version":version,"os_family":payload.os_family,
                        "architecture":payload.architecture,"capture_cohort":payload.capture_cohort,
                        "evidence_set_id":evidence_set_id,"content_hash":lower_hex(&content_hash),"reason":reason
                    }),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":archetype_id,"version_id":version_id,"version":version,"lifecycle":"active",
                "version_lifecycle":"draft","content_hash":lower_hex(&content_hash),"revision":root_revision},"meta":{}}),
            etag: Some(format!("\"rev-{root_revision}\"").into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn transition_environment_archetype(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        action: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: LifecycleActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(command.reason.as_deref())?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let archetype_id = path_uuid(request, "id")?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let root = sqlx::query(
            "SELECT os_family_code,architecture_code,client_family_code,lifecycle_code,revision \
             FROM catalog.environment_archetype WHERE id=$1 AND revision=$2 FOR UPDATE",
        )
        .bind(archetype_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let version = sqlx::query(
            "SELECT id,version,lifecycle_code,evidence_set_id,capture_cohort,client_version \
             FROM catalog.environment_archetype_version WHERE archetype_id=$1 \
             ORDER BY version DESC LIMIT 1 FOR UPDATE",
        )
        .bind(archetype_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let version_id = required::<Uuid>(&version, "id")?;
        let version_number = required::<i64>(&version, "version")?;
        let state = required::<String>(&version, "lifecycle_code")?;
        match action {
            "verify" => {
                if state != "draft" {
                    return Err(ManagementBackendError::Precondition);
                }
                let evidence_set_id = required::<Option<Uuid>>(&version, "evidence_set_id")?
                    .ok_or(ManagementBackendError::Precondition)?;
                let evidence_ready: bool = sqlx::query_scalar(
                    "SELECT evidence.state_code='complete' \
                       AND evidence.capture_cohort IS NOT DISTINCT FROM $2 \
                       AND EXISTS (SELECT 1 FROM catalog.capture_run run \
                         WHERE run.evidence_set_id=evidence.id AND run.state_code='succeeded' \
                           AND run.os_family_code=$3 AND run.client_version=$4 \
                           AND run.privacy_scan_code LIKE '%:passed') \
                       AND NOT EXISTS (SELECT 1 FROM (VALUES ('headers'),('metadata'),('attribution'),('tls'),('privacy_scan')) required(kind) \
                         WHERE NOT EXISTS (SELECT 1 FROM catalog.evidence_item item \
                           WHERE item.evidence_set_id=evidence.id AND item.kind_code=required.kind)) \
                     FROM catalog.evidence_set evidence WHERE evidence.id=$1",
                )
                .bind(evidence_set_id)
                .bind(required::<Option<String>>(&version, "capture_cohort")?)
                .bind(required::<String>(&root, "os_family_code")?)
                .bind(required::<String>(&version, "client_version")?)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .unwrap_or(false);
                if !evidence_ready {
                    return Err(ManagementBackendError::Precondition);
                }
                sqlx::query("UPDATE catalog.environment_archetype_version SET lifecycle_code='verified' WHERE id=$1")
                    .bind(version_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?;
            }
            "promote_canary" => {
                if state != "verified" {
                    return Err(ManagementBackendError::Precondition);
                }
                let bundle_canary_ready: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM catalog.archetype_bundle_binding binding \
                     JOIN catalog.transport_bundle bundle ON bundle.id=binding.transport_bundle_id \
                     WHERE binding.archetype_version_id=$1 AND binding.state_code IN ('candidate','active') \
                       AND bundle.lifecycle_code IN ('canary','active') \
                       AND bundle.evidence_gate_code='passed' AND bundle.runtime_state_code='loadable')",
                )
                .bind(version_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                if !bundle_canary_ready {
                    return Err(ManagementBackendError::Precondition);
                }
                sqlx::query("UPDATE catalog.environment_archetype_version SET lifecycle_code='canary' WHERE id=$1")
                    .bind(version_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?;
            }
            "activate" => {
                if state != "canary" {
                    return Err(ManagementBackendError::Precondition);
                }
                let bundle_ready: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM catalog.archetype_bundle_binding binding \
                     JOIN catalog.transport_bundle bundle ON bundle.id=binding.transport_bundle_id \
                     WHERE binding.archetype_version_id=$1 AND binding.state_code='active' \
                       AND bundle.lifecycle_code='active' AND bundle.evidence_gate_code='passed' \
                       AND bundle.runtime_state_code='loadable' AND bundle.protocol_code='h1')",
                )
                .bind(version_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                if !bundle_ready {
                    return Err(ManagementBackendError::Precondition);
                }
                sqlx::query(
                    "UPDATE catalog.environment_archetype_version SET lifecycle_code='retired',retired_at=clock_timestamp() \
                     WHERE archetype_id=$1 AND lifecycle_code='active' AND id<>$2",
                )
                .bind(archetype_id)
                .bind(version_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                sqlx::query(
                    "UPDATE catalog.environment_archetype_version SET lifecycle_code='active',activated_at=clock_timestamp(), \
                     retired_at=NULL WHERE id=$1",
                )
                .bind(version_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            }
            "retire" => {
                if required::<String>(&root, "lifecycle_code")? != "active" {
                    return Err(ManagementBackendError::Precondition);
                }
                let active_profiles: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM gateway.credential_profile \
                     WHERE archetype_version_id=$1 AND lifecycle_code='active'",
                )
                .bind(version_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
                if active_profiles != 0 {
                    return Err(ManagementBackendError::Precondition);
                }
                sqlx::query(
                    "UPDATE catalog.environment_archetype_version SET lifecycle_code='retired',retired_at=clock_timestamp() \
                     WHERE id=$1 AND lifecycle_code<>'retired'",
                )
                .bind(version_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            }
            _ => return Err(ManagementBackendError::InvalidInput),
        }
        let root_lifecycle = if action == "retire" { "retired" } else { "active" };
        let root_revision: i64 = sqlx::query_scalar(
            "UPDATE catalog.environment_archetype SET lifecycle_code=$2,revision=revision+1,updated_at=clock_timestamp() \
             WHERE id=$1 RETURNING revision",
        )
        .bind(archetype_id)
        .bind(root_lifecycle)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let next_state = match action {
            "verify" => "verified",
            "promote_canary" => "canary",
            "activate" => "active",
            "retire" => "retired",
            _ => unreachable!(),
        };
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    &format!("environment_archetype_{action}"),
                    "environment_archetype",
                    archetype_id,
                    root_revision,
                    json!({
                        "version_id":version_id,"version":version_number,"from":state,"to":next_state,"reason":reason
                    }),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(
            &json!({
                "id":archetype_id,"version_id":version_id,"version":version_number,
                "lifecycle":root_lifecycle,"version_lifecycle":next_state,"revision":root_revision
            }),
            root_revision,
        ))
    }

    async fn list_plan_mapping_versions(
        &self,
        artifact_id: Option<Uuid>,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT a.id,a.artifact_version,a.lifecycle_code,a.payload,encode(a.content_hash,'hex') AS content_hash, \
                    a.schema_version,a.created_by,a.created_at::text AS created_at,p.revision AS pointer_revision, \
                    p.artifact_id=a.id AS is_active FROM catalog.versioned_artifact a \
             LEFT JOIN catalog.active_artifact_pointer p ON p.artifact_kind_code='plan_mapping' \
               AND p.scope_type_code IS NULL AND p.scope_id IS NULL \
             WHERE a.artifact_kind_code='plan_mapping' AND ($1::uuid IS NULL OR a.id=$1) \
             ORDER BY a.artifact_version DESC,a.id DESC LIMIT 100",
        )
        .bind(artifact_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if artifact_id.is_some() && rows.is_empty() {
            return Err(ManagementBackendError::NotFound);
        }
        let data = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "id":required::<Uuid>(row,"id")?,"version":required::<i64>(row,"artifact_version")?,
                    "lifecycle":required::<String>(row,"lifecycle_code")?,"mapping":required::<Value>(row,"payload")?.get("mappings").cloned().unwrap_or_else(||json!({})),
                    "content_sha256":required::<String>(row,"content_hash")?,"schema_version":required::<i64>(row,"schema_version")?,
                    "created_by":required::<Option<Uuid>>(row,"created_by")?,"created_at":required::<String>(row,"created_at")?,
                    "is_active":required::<Option<bool>>(row,"is_active")?.unwrap_or(false),
                    "pointer_revision":required::<Option<i64>>(row,"pointer_revision")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        if artifact_id.is_some() {
            let row = data.into_iter().next().ok_or(ManagementBackendError::NotFound)?;
            let revision = row["version"].as_i64().ok_or(ManagementBackendError::Unavailable)?;
            Ok(single_response(&row, revision))
        } else {
            Ok(list_response(&data))
        }
    }

    async fn create_plan_mapping_version(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: PlanMappingCreateCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        validate_plan_mapping_value(&command.mapping)?;
        let artifact_id = Uuid::now_v7();
        let payload = json!({"mappings":command.mapping});
        let hash = Sha256::digest(canonical_json_bytes(&payload)?).to_vec();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('catalog:plan_mapping'))")
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let version: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(artifact_version),0)+1 FROM catalog.versioned_artifact \
             WHERE artifact_kind_code='plan_mapping' AND scope_type_code IS NULL AND scope_id IS NULL",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO catalog.versioned_artifact \
             (id,artifact_kind_code,scope_type_code,scope_id,artifact_version,lifecycle_code,payload,content_hash, \
              schema_version,created_by,created_at) VALUES ($1,'plan_mapping',NULL,NULL,$2,'eligible',$3,$4,1,$5,clock_timestamp())",
        )
        .bind(artifact_id)
        .bind(version)
        .bind(&payload)
        .bind(&hash)
        .bind(parse_uuid(&principal.user_id)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "plan_mapping_created",
                    "plan_mapping",
                    artifact_id,
                    version,
                    json!({"reason":reason,"content_sha256":lower_hex(&hash)}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":artifact_id,"version":version,"lifecycle":"eligible","content_sha256":lower_hex(&hash)},"meta":{}}),
            etag: Some(format!("\"rev-{version}\"").into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn validate_plan_mapping_version(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let artifact_id = path_uuid(request, "id")?;
        let mapping: Value = sqlx::query_scalar(
            "SELECT payload->'mappings' FROM catalog.versioned_artifact \
             WHERE id=$1 AND artifact_kind_code='plan_mapping'",
        )
        .bind(artifact_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        validate_plan_mapping_value(&mapping)?;
        let stats: (i64, i64, i64) = sqlx::query_as(
            "SELECT count(*)::bigint, \
                    count(*) FILTER (WHERE normalized_plan_code='unknown')::bigint, \
                    count(*) FILTER (WHERE normalized_plan_code='unknown' AND $1::jsonb ? raw_plan_code)::bigint \
             FROM telemetry.subscription_plan_observation WHERE raw_plan_code IS NOT NULL",
        )
        .bind(&mapping)
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse::ok(json!({"data":{
            "id":artifact_id,"valid":true,"raw_code_count":stats.0,"currently_unknown_count":stats.1,
            "unknown_resolved_count":stats.2,"mapping_count":mapping.as_object().map_or(0,serde_json::Map::len)
        },"meta":{}})))
    }

    async fn activate_plan_mapping_version(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ArtifactActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let expected_revision = command.expected_revision;
        let artifact_id = path_uuid(request, "id")?;
        let job_id = Uuid::now_v7();
        let pointer_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let target = sqlx::query(
            "SELECT lifecycle_code FROM catalog.versioned_artifact WHERE id=$1 AND artifact_kind_code='plan_mapping' \
             AND scope_type_code IS NULL AND scope_id IS NULL FOR UPDATE",
        )
        .bind(artifact_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let state = required::<String>(&target, "lifecycle_code")?;
        if !matches!(state.as_str(), "eligible" | "canary" | "active") {
            return Err(ManagementBackendError::Precondition);
        }
        let pointer = sqlx::query(
            "SELECT id,artifact_id,revision FROM catalog.active_artifact_pointer WHERE artifact_kind_code='plan_mapping' \
             AND scope_type_code IS NULL AND scope_id IS NULL FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let pointer_revision = if let Some(pointer) = pointer {
            let current = required::<i64>(&pointer, "revision")?;
            if expected_revision != Some(current) {
                return Err(ManagementBackendError::Precondition);
            }
            let previous = required::<Uuid>(&pointer, "artifact_id")?;
            if previous != artifact_id {
                sqlx::query("UPDATE catalog.versioned_artifact SET lifecycle_code='eligible' WHERE id=$1 AND lifecycle_code='active'")
                    .bind(previous)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?;
            }
            let next = current.checked_add(1).ok_or(ManagementBackendError::Unavailable)?;
            sqlx::query(
                "UPDATE catalog.active_artifact_pointer SET artifact_id=$2,revision=$3,activated_by=$4,activated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(required::<Uuid>(&pointer, "id")?)
            .bind(artifact_id)
            .bind(next)
            .bind(parse_uuid(&principal.user_id)?)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            next
        } else {
            if expected_revision.is_some() {
                return Err(ManagementBackendError::Precondition);
            }
            sqlx::query(
                "INSERT INTO catalog.active_artifact_pointer \
                 (id,artifact_kind_code,scope_type_code,scope_id,artifact_id,revision,activated_by,activated_at) \
                 VALUES ($1,'plan_mapping',NULL,NULL,$2,1,$3,clock_timestamp())",
            )
            .bind(pointer_id)
            .bind(artifact_id)
            .bind(parse_uuid(&principal.user_id)?)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            1
        };
        sqlx::query("UPDATE catalog.versioned_artifact SET lifecycle_code='active' WHERE id=$1")
            .bind(artifact_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'plan_mapping_recompute',$2,'scheduled',1,$3,clock_timestamp(),0,0,8,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("plan-mapping:{artifact_id}:{pointer_revision}"))
        .bind(json!({"mapping_artifact_id":artifact_id,"pointer_revision":pointer_revision}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_job_created_history(&mut transaction, job_id, "plan_mapping_recompute_scheduled").await?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "plan_mapping_activated",
                    "plan_mapping",
                    artifact_id,
                    pointer_revision,
                    json!({"reason":reason,"recompute_job_id":job_id}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(async_job_response(
            job_id,
            "plan_mapping_recompute",
            "queued",
            &created_at,
        ))
    }

    async fn enqueue_plan_mapping_recompute(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let artifact_id = path_uuid(request, "id")?;
        let job_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let pointer_revision: i64 = sqlx::query_scalar(
            "SELECT revision FROM catalog.active_artifact_pointer WHERE artifact_kind_code='plan_mapping' \
             AND scope_type_code IS NULL AND scope_id IS NULL AND artifact_id=$1 FOR SHARE",
        )
        .bind(artifact_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'plan_mapping_recompute',$2,'scheduled',1,$3,clock_timestamp(),0,0,8,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("plan-mapping-manual:{artifact_id}:{job_id}"))
        .bind(json!({"mapping_artifact_id":artifact_id,"pointer_revision":pointer_revision}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_job_created_history(&mut transaction, job_id, "plan_mapping_manual_recompute_scheduled").await?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "plan_mapping_recompute_scheduled",
                    "plan_mapping",
                    artifact_id,
                    pointer_revision,
                    json!({"job_id":job_id}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(async_job_response(
            job_id,
            "plan_mapping_recompute",
            "queued",
            &created_at,
        ))
    }

    async fn get_artifact(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT a.id,a.artifact_kind_code,a.scope_type_code,a.scope_id,a.artifact_version,a.lifecycle_code, \
                    a.content_hash,a.schema_version,a.created_by,a.created_at::text AS created_at, \
                    a.retired_at::text AS retired_at,a.quarantined_at::text AS quarantined_at, \
                    COALESCE(p.artifact_id=a.id,false) AS is_active,p.revision AS pointer_revision, \
                    p.activated_by,p.activated_at::text AS activated_at,e.id AS evidence_id,e.name AS evidence_name, \
                    e.source_code AS evidence_source,e.state_code AS evidence_state,e.capture_cohort, \
                    e.content_hash AS evidence_content_hash,e.created_at::text AS evidence_created_at \
             FROM catalog.versioned_artifact a \
             LEFT JOIN catalog.active_artifact_pointer p ON p.artifact_id=a.id \
             LEFT JOIN catalog.evidence_set e ON e.id=a.evidence_set_id WHERE a.id=$1",
        )
        .bind(path_uuid(request, "id")?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let content_hash = required::<Vec<u8>>(&row, "content_hash")?;
        let evidence_id = required::<Option<Uuid>>(&row, "evidence_id")?;
        let evidence = if let Some(id) = evidence_id {
            json!({
                "id":id,
                "name":required::<Option<String>>(&row,"evidence_name")?,
                "source":required::<Option<String>>(&row,"evidence_source")?,
                "state":required::<Option<String>>(&row,"evidence_state")?,
                "capture_cohort":required::<Option<String>>(&row,"capture_cohort")?,
                "content_sha256":required::<Option<Vec<u8>>>(&row,"evidence_content_hash")?.map(|value| lower_hex(&value)),
                "created_at":required::<Option<String>>(&row,"evidence_created_at")?
            })
        } else {
            Value::Null
        };
        let data = json!({
            "id":required::<Uuid>(&row,"id")?,
            "kind":required::<String>(&row,"artifact_kind_code")?,
            "scope_type":required::<Option<String>>(&row,"scope_type_code")?,
            "scope_id":required::<Option<Uuid>>(&row,"scope_id")?,
            "version":required::<i64>(&row,"artifact_version")?,
            "lifecycle":required::<String>(&row,"lifecycle_code")?,
            "content_sha256":lower_hex(&content_hash),
            "schema_version":required::<i64>(&row,"schema_version")?,
            "created_by":required::<Option<Uuid>>(&row,"created_by")?,
            "created_at":required::<String>(&row,"created_at")?,
            "retired_at":required::<Option<String>>(&row,"retired_at")?,
            "quarantined_at":required::<Option<String>>(&row,"quarantined_at")?,
            "is_active":required::<bool>(&row,"is_active")?,
            "pointer_revision":required::<Option<i64>>(&row,"pointer_revision")?,
            "activated_by":required::<Option<Uuid>>(&row,"activated_by")?,
            "activated_at":required::<Option<String>>(&row,"activated_at")?,
            "provenance":evidence
        });
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({"data":data,"meta":{}}),
            etag: Some(format!("\"{}\"", lower_hex(&content_hash)).into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn list_models(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT m.id,m.upstream_model_id,m.display_name,m.lifecycle_code,m.revision, \
                    m.first_seen_at::text AS first_seen_at,m.last_seen_at::text AS last_seen_at, \
                    c.capability_version,c.lifecycle_code AS capability_state \
             FROM catalog.model_definition m LEFT JOIN catalog.model_capability c ON c.model_id=m.id AND c.lifecycle_code='active' \
             ORDER BY m.last_seen_at DESC,m.id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(model_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn refresh_models(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ModelRefreshCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('model-catalog-discovery-v1'))")
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let existing = sqlx::query(
            "SELECT id,state_code,created_at::text AS created_at FROM ops.durable_job \
             WHERE kind_code='model_catalog_discovery_v1' AND state_code IN ('scheduled','leased','retry_wait') \
             ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some(existing) = existing {
            let job_id = required::<Uuid>(&existing, "id")?;
            let state = required::<String>(&existing, "state_code")?;
            let created_at = required::<String>(&existing, "created_at")?;
            transaction
                .commit()
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            return Ok(async_job_response(
                job_id,
                "model_catalog_discovery_v1",
                if state == "leased" { "running" } else { "queued" },
                &created_at,
            ));
        }
        let source = sqlx::query(
            "SELECT credential.id,credential.group_id,credential.revision,credential.token_version, \
                    binding.id AS binding_id,binding.egress_epoch \
             FROM gateway.anthropic_credential credential \
             JOIN gateway.credential_auth_version auth ON auth.id=credential.active_auth_version_id \
               AND auth.credential_id=credential.id AND auth.material_state_code='active' AND auth.console_secret_id IS NOT NULL \
             JOIN security.encrypted_secret secret ON secret.id=auth.console_secret_id \
               AND secret.secret_kind_code='console_api_key' AND secret.destroyed_at IS NULL AND secret.superseded_at IS NULL \
             JOIN gateway.credential_egress_binding binding ON binding.credential_id=credential.id \
               AND binding.lifecycle_code='active' AND binding.stability_code='stable' \
             WHERE credential.lifecycle_state_code='active' AND credential.auth_kind_code='console_api_key' \
               AND credential.auth_state_code='healthy' AND credential.transport_state_code='ready' \
             ORDER BY credential.scheduling_state_code='eligible' DESC,credential.updated_at DESC,credential.id LIMIT 1 \
             FOR SHARE OF credential,auth,binding,secret",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let credential_id = required::<Uuid>(&source, "id")?;
        let group_id = required::<Uuid>(&source, "group_id")?;
        let revision = required::<i64>(&source, "revision")?;
        let token_version = required::<i64>(&source, "token_version")?;
        let binding_id = required::<Uuid>(&source, "binding_id")?;
        let egress_epoch = required::<i64>(&source, "egress_epoch")?;
        let job_id = Uuid::now_v7();
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'model_catalog_discovery_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,8,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(format!("model-catalog-discovery:{job_id}"))
        .bind(json!({"source_credential_id":credential_id,"group_id":group_id,"credential_revision":revision,
          "token_version":token_version,"binding_id":binding_id,"egress_epoch":egress_epoch,"trigger":"admin"}))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_job_created_history(&mut transaction, job_id, "model_catalog_discovery_scheduled").await?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "model_catalog_discovery_scheduled",
                    "model_catalog",
                    job_id,
                    1,
                    json!({"job_id":job_id,"reason":reason,"source":"anthropic_models_api"}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(async_job_response(
            job_id,
            "model_catalog_discovery_v1",
            "queued",
            &created_at,
        ))
    }

    async fn get_model(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT m.id,m.upstream_model_id,m.display_name,m.lifecycle_code,m.revision, \
                    m.first_seen_at::text AS first_seen_at,m.last_seen_at::text AS last_seen_at, \
                    c.capability_version,c.lifecycle_code AS capability_state \
             FROM catalog.model_definition m LEFT JOIN catalog.model_capability c ON c.model_id=m.id AND c.lifecycle_code='active' \
             WHERE m.id=$1",
        )
        .bind(path_uuid(request, "id")?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision: i64 = row
            .try_get("revision")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(&model_projection(&row)?, revision))
    }

    async fn list_capability_versions(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT c.id,c.model_id,m.upstream_model_id,c.capability_version,c.lifecycle_code,c.schema_payload, \
                    encode(c.content_hash,'hex') AS content_hash,c.created_at::text AS created_at, \
                    c.activated_at::text AS activated_at,m.revision AS model_revision \
             FROM catalog.model_capability c JOIN catalog.model_definition m ON m.id=c.model_id \
             ORDER BY c.created_at DESC,c.id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(capability_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn create_capability_version(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: CapabilityCreateCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let model_id = parse_input_uuid(&command.model_id)?;
        if command.schema_version != 1 || command.rules.is_empty() || command.rules.len() > 4_096 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!("catalog:model-capability:{model_id}"))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let model =
            sqlx::query("SELECT upstream_model_id,revision FROM catalog.model_definition WHERE id=$1 FOR UPDATE")
                .bind(model_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .ok_or(ManagementBackendError::NotFound)?;
        let upstream_model_id = required::<String>(&model, "upstream_model_id")?;
        let model_revision = required::<i64>(&model, "revision")?;
        let capability_id = Uuid::now_v7();
        CompiledCapabilitySnapshot::compile(capability_id.to_string(), upstream_model_id, command.rules.clone())
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let payload = json!({"schema_version":1,"rules":command.rules});
        let payload_bytes = canonical_json_bytes(&payload)?;
        let content_hash = Sha256::digest(&payload_bytes).to_vec();
        let version: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(capability_version),0)+1 FROM catalog.model_capability WHERE model_id=$1",
        )
        .bind(model_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO catalog.model_capability \
             (id,model_id,capability_version,lifecycle_code,schema_payload,content_hash,created_at) \
             VALUES ($1,$2,$3,'candidate',$4,$5,clock_timestamp())",
        )
        .bind(capability_id)
        .bind(model_id)
        .bind(version)
        .bind(&payload)
        .bind(&content_hash)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "capability_version_created",
                    "model_capability",
                    capability_id,
                    model_revision,
                    json!({"model_id":model_id,"capability_version":version,"content_hash":lower_hex(&content_hash),"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{
                "id":capability_id,"model_id":model_id,"capability_version":version,"lifecycle":"candidate",
                "schema_payload":payload,"content_hash":lower_hex(&content_hash),"model_revision":model_revision,
                "revision":model_revision
            },"meta":{}}),
            etag: Some(format!("\"rev-{model_revision}\"").into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn validate_capability_version(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: CapabilityActionCommand = deserialize_body(request)?;
        let capability_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let row = sqlx::query(
            "SELECT c.model_id,m.upstream_model_id,m.revision,c.lifecycle_code,c.schema_payload \
             FROM catalog.model_capability c JOIN catalog.model_definition m ON m.id=c.model_id WHERE c.id=$1",
        )
        .bind(capability_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let model_revision = required::<i64>(&row, "revision")?;
        if model_revision != expected_revision {
            return Err(ManagementBackendError::Precondition);
        }
        let payload = required::<Value>(&row, "schema_payload")?;
        let envelope: CapabilityPayload =
            serde_json::from_value(payload).map_err(|_| ManagementBackendError::Precondition)?;
        CompiledCapabilitySnapshot::compile(
            capability_id.to_string(),
            required::<String>(&row, "upstream_model_id")?,
            envelope.rules,
        )
        .map_err(|_| ManagementBackendError::Precondition)?;
        Ok(single_response(
            &json!({
                "id":capability_id,"valid":true,"diagnostics":[],"model_id":required::<Uuid>(&row,"model_id")?,
                "lifecycle":required::<String>(&row,"lifecycle_code")?,"revision":model_revision
            }),
            model_revision,
        ))
    }

    async fn activate_capability_version(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: CapabilityActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(command.reason.as_deref())?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let capability_id = path_uuid(request, "id")?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let target = sqlx::query(
            "SELECT c.model_id,c.lifecycle_code,c.schema_payload,m.upstream_model_id,m.revision \
             FROM catalog.model_capability c JOIN catalog.model_definition m ON m.id=c.model_id \
             WHERE c.id=$1 FOR UPDATE OF c,m",
        )
        .bind(capability_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let model_id = required::<Uuid>(&target, "model_id")?;
        let model_revision = required::<i64>(&target, "revision")?;
        let lifecycle = required::<String>(&target, "lifecycle_code")?;
        if model_revision != expected_revision || !matches!(lifecycle.as_str(), "candidate" | "active") {
            return Err(ManagementBackendError::Precondition);
        }
        let payload = required::<Value>(&target, "schema_payload")?;
        let envelope: CapabilityPayload =
            serde_json::from_value(payload).map_err(|_| ManagementBackendError::Precondition)?;
        CompiledCapabilitySnapshot::compile(
            capability_id.to_string(),
            required::<String>(&target, "upstream_model_id")?,
            envelope.rules,
        )
        .map_err(|_| ManagementBackendError::Precondition)?;
        if lifecycle != "active" {
            sqlx::query(
                "UPDATE catalog.model_capability SET lifecycle_code='retired' \
                 WHERE model_id=$1 AND lifecycle_code='active' AND id<>$2",
            )
            .bind(model_id)
            .bind(capability_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                "UPDATE catalog.model_capability SET lifecycle_code='active',activated_at=clock_timestamp() \
                 WHERE id=$1 AND lifecycle_code='candidate'",
            )
            .bind(capability_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        }
        let new_revision: i64 = sqlx::query_scalar(
            "UPDATE catalog.model_definition SET revision=revision+1 WHERE id=$1 AND revision=$2 RETURNING revision",
        )
        .bind(model_id)
        .bind(expected_revision)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "capability_version_activated",
                    "model_capability",
                    capability_id,
                    new_revision,
                    json!({"model_id":model_id,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.reload_management_runtime().await?;
        Ok(single_response(
            &json!({"id":capability_id,"model_id":model_id,"lifecycle":"active","revision":new_revision}),
            new_revision,
        ))
    }

    async fn model_lifecycle(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        action: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ModelLifecycleCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let (target, allowed): (&str, &[&str]) = match action {
            "approve" => ("published", &["discovered", "reviewing"]),
            "deprecate" => ("deprecated", &["published"]),
            "disable" => ("disabled", &["discovered", "reviewing", "published", "deprecated"]),
            _ => return Err(ManagementBackendError::InvalidInput),
        };
        let model_id = path_uuid(request, "id")?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query("SELECT lifecycle_code,revision FROM catalog.model_definition WHERE id=$1 FOR UPDATE")
            .bind(model_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?
            .ok_or(ManagementBackendError::NotFound)?;
        let current = required::<String>(&row, "lifecycle_code")?;
        let revision = required::<i64>(&row, "revision")?;
        if revision != expected_revision || !allowed.contains(&current.as_str()) {
            return Err(ManagementBackendError::Precondition);
        }
        if action == "approve" {
            let active: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM catalog.model_capability WHERE model_id=$1 AND lifecycle_code='active')",
            )
            .bind(model_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            if !active {
                return Err(ManagementBackendError::Precondition);
            }
        }
        let new_revision: i64 = sqlx::query_scalar(
            "UPDATE catalog.model_definition SET lifecycle_code=$3,revision=revision+1 WHERE id=$1 AND revision=$2 RETURNING revision",
        )
        .bind(model_id)
        .bind(expected_revision)
        .bind(target)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    &format!("model_{action}"),
                    "model",
                    model_id,
                    new_revision,
                    json!({"from":current,"to":target,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.reload_management_runtime().await?;
        self.get_model(request).await
    }

    async fn list_price_versions(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT v.price_version,v.currency_code,v.effective_from::text AS effective_from, \
                    v.effective_to::text AS effective_to,v.source_uri,encode(v.content_hash,'hex') AS content_hash, \
                    v.created_by,v.created_at::text AS created_at, \
                    jsonb_agg(jsonb_build_object('id',p.id,'model_id',p.model_id,'upstream_model_id',m.upstream_model_id, \
                      'input_per_million',p.input_per_million::text,'output_per_million',p.output_per_million::text, \
                      'cache_write_per_million',p.cache_write_per_million::text, \
                      'cache_read_per_million',p.cache_read_per_million::text) ORDER BY m.upstream_model_id,p.id) AS entries \
             FROM catalog.price_version v JOIN catalog.price_entry p ON p.price_version=v.price_version \
             JOIN catalog.model_definition m ON m.id=p.model_id \
             GROUP BY v.price_version,v.currency_code,v.effective_from,v.effective_to,v.source_uri,v.content_hash, \
                      v.created_by,v.created_at ORDER BY v.price_version DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .map(|row| {
                let version = required::<i64>(row, "price_version")?;
                Ok(json!({
                    "id":format!("price-version-{version}"),"price_version":version,
                    "currency":required::<String>(row,"currency_code")?,
                    "effective_from":required::<String>(row,"effective_from")?,
                    "effective_to":required::<Option<String>>(row,"effective_to")?,
                    "source_uri":required::<Option<String>>(row,"source_uri")?,
                    "content_hash":required::<String>(row,"content_hash")?,
                    "entries":required::<Value>(row,"entries")?,"created_by":required::<Option<Uuid>>(row,"created_by")?,
                    "created_at":required::<String>(row,"created_at")?,"revision":version
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        Ok(list_response(&data))
    }

    async fn create_price_version(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: PriceVersionCreateCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        if command.currency != "USD"
            || command.entries.is_empty()
            || command.entries.len() > 1_000
            || command.effective_from.is_empty()
            || command.effective_from.len() > 128
            || command
                .effective_to
                .as_deref()
                .is_some_and(|value| value.is_empty() || value.len() > 128)
            || command
                .source_uri
                .as_deref()
                .is_some_and(|value| value.is_empty() || value.len() > 2_048 || value.contains(['\r', '\n']))
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let mut model_ids = Vec::with_capacity(command.entries.len());
        for entry in &command.entries {
            let model_id = parse_input_uuid(&entry.model_id)?;
            if model_ids.contains(&model_id)
                || ![
                    entry.input_per_million.as_str(),
                    entry.output_per_million.as_str(),
                    entry.cache_write_per_million.as_str(),
                    entry.cache_read_per_million.as_str(),
                ]
                .into_iter()
                .all(valid_nonnegative_decimal)
            {
                return Err(ManagementBackendError::InvalidInput);
            }
            model_ids.push(model_id);
        }
        let payload = serde_json::to_value(&command).map_err(|_| ManagementBackendError::InvalidInput)?;
        let hash = Sha256::digest(canonical_json_bytes(&payload)?).to_vec();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('catalog:price-version'))")
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let eligible_models: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM catalog.model_definition WHERE id=ANY($1) AND lifecycle_code IN ('published','deprecated')",
        )
        .bind(&model_ids)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if usize::try_from(eligible_models).ok() != Some(model_ids.len()) {
            return Err(ManagementBackendError::Precondition);
        }
        let overlaps: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM catalog.price_entry WHERE model_id=ANY($1) \
               AND effective_from<COALESCE($3::timestamptz,'infinity'::timestamptz) \
               AND COALESCE(effective_to,'infinity'::timestamptz)>$2::timestamptz)",
        )
        .bind(&model_ids)
        .bind(&command.effective_from)
        .bind(command.effective_to.as_deref())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::InvalidInput)?;
        if overlaps {
            return Err(ManagementBackendError::Precondition);
        }
        let version: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(price_version),0)+1 FROM catalog.price_version")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO catalog.price_version \
             (price_version,currency_code,effective_from,effective_to,source_uri,content_hash,created_by,created_at) \
             VALUES ($1,'USD',$2::timestamptz,$3::timestamptz,$4,$5,$6,clock_timestamp())",
        )
        .bind(version)
        .bind(&command.effective_from)
        .bind(command.effective_to.as_deref())
        .bind(command.source_uri.as_deref())
        .bind(&hash)
        .bind(parse_uuid(&principal.user_id)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::InvalidInput)?;
        for (entry, model_id) in command.entries.iter().zip(&model_ids) {
            sqlx::query(
                "INSERT INTO catalog.price_entry \
                 (id,model_id,price_version,currency_code,input_per_million,output_per_million, \
                  cache_write_per_million,cache_read_per_million,effective_from,effective_to,source_uri) \
                 VALUES ($1,$2,$3,'USD',$4::numeric,$5::numeric,$6::numeric,$7::numeric, \
                         $8::timestamptz,$9::timestamptz,$10)",
            )
            .bind(Uuid::now_v7())
            .bind(model_id)
            .bind(version)
            .bind(&entry.input_per_million)
            .bind(&entry.output_per_million)
            .bind(&entry.cache_write_per_million)
            .bind(&entry.cache_read_per_million)
            .bind(&command.effective_from)
            .bind(command.effective_to.as_deref())
            .bind(command.source_uri.as_deref())
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        }
        let aggregate_id = Uuid::now_v7();
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "price_version_created",
                    "price_version",
                    aggregate_id,
                    version,
                    json!({"price_version":version,"currency":"USD","entry_count":model_ids.len(),"content_hash":lower_hex(&hash),"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":format!("price-version-{version}"),"price_version":version,"currency":"USD",
                "effective_from":command.effective_from,"effective_to":command.effective_to,"source_uri":command.source_uri,
                "content_hash":lower_hex(&hash),"entry_count":model_ids.len(),"revision":version},"meta":{}}),
            etag: Some(format!("\"rev-{version}\"").into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn list_typed_artifacts(
        &self,
        kind: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT a.id,a.artifact_version,a.lifecycle_code,a.scope_type_code,a.scope_id,a.payload, \
                    encode(a.content_hash,'hex') AS content_hash,a.schema_version,a.created_by, \
                    a.created_at::text AS created_at,p.artifact_id=a.id AS is_active,p.revision AS pointer_revision, \
                    evidence.validated_at::text AS validated_at,evidence.shadow_started_at::text AS shadow_started_at, \
                    evidence.shadow_minimum_until::text AS shadow_minimum_until, \
                    evidence.deterministic_sample_count,evidence.risk_acceptance_case_id,evidence.revision AS evidence_revision \
             FROM catalog.versioned_artifact a LEFT JOIN catalog.active_artifact_pointer p \
               ON p.artifact_kind_code=a.artifact_kind_code \
              AND p.scope_type_code IS NOT DISTINCT FROM a.scope_type_code \
              AND p.scope_id IS NOT DISTINCT FROM a.scope_id \
             LEFT JOIN catalog.artifact_rollout_evidence evidence ON evidence.artifact_id=a.id \
             WHERE a.artifact_kind_code=$1 ORDER BY a.created_at DESC,a.id DESC LIMIT 100",
        )
        .bind(kind)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "id":required::<Uuid>(row,"id")?,"kind":kind,
                    "version":required::<i64>(row,"artifact_version")?,"lifecycle":required::<String>(row,"lifecycle_code")?,
                    "scope_type":required::<Option<String>>(row,"scope_type_code")?,"scope_id":required::<Option<Uuid>>(row,"scope_id")?,
                    "payload":required::<Value>(row,"payload")?,"content_hash":required::<String>(row,"content_hash")?,
                    "schema_version":required::<i64>(row,"schema_version")?,"created_by":required::<Option<Uuid>>(row,"created_by")?,
                    "created_at":required::<String>(row,"created_at")?,"is_active":required::<Option<bool>>(row,"is_active")?.unwrap_or(false),
                    "pointer_revision":required::<Option<i64>>(row,"pointer_revision")?,
                    "validated_at":required::<Option<String>>(row,"validated_at")?,
                    "shadow_started_at":required::<Option<String>>(row,"shadow_started_at")?,
                    "shadow_minimum_until":required::<Option<String>>(row,"shadow_minimum_until")?,
                    "deterministic_sample_count":required::<Option<i32>>(row,"deterministic_sample_count")?.unwrap_or(0),
                    "risk_acceptance_case_id":required::<Option<Uuid>>(row,"risk_acceptance_case_id")?,
                    "evidence_revision":required::<Option<i64>>(row,"evidence_revision")?,
                    "revision":required::<i64>(row,"artifact_version")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        Ok(list_response(&data))
    }

    async fn create_ruleset(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: RuleSetCreateCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let scope_id = parse_input_uuid(&command.scope_id)?;
        if command.name.trim().is_empty()
            || command.name.len() > 128
            || command.schema_version != 1
            || command.rules.is_empty()
            || command.rules.len() > 1_024
            || !matches!(command.scope_type.as_str(), "group" | "platform_key")
            || command.source_refs.len() > 128
            || command
                .source_refs
                .iter()
                .any(|value| value.is_empty() || value.len() > 2_048 || value.contains(['\r', '\n']))
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        CompiledRuleSet::compile("ruleset-candidate", command.rules.clone())
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let payload = serde_json::to_value(StoredRuleSetPayload {
            name: command.name.trim().to_owned(),
            rules: command.rules,
            source_refs: command.source_refs,
        })
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let payload_bytes = canonical_json_bytes(&payload)?;
        let content_hash = Sha256::digest(&payload_bytes).to_vec();
        let artifact_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!("catalog:ruleset:{}:{scope_id}", command.scope_type))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let scope_exists: bool = match command.scope_type.as_str() {
            "group" => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM gateway.credential_group WHERE id=$1 AND status_code<>'archived')",
                )
                .bind(scope_id)
                .fetch_one(&mut *transaction)
                .await
            }
            "platform_key" => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM iam.platform_key WHERE id=$1 AND status_code NOT IN ('revoked','expired'))",
                )
                .bind(scope_id)
                .fetch_one(&mut *transaction)
                .await
            }
            _ => unreachable!(),
        }
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if !scope_exists {
            return Err(ManagementBackendError::NotFound);
        }
        let version: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(artifact_version),0)+1 FROM catalog.versioned_artifact \
             WHERE artifact_kind_code='ruleset' AND scope_type_code=$1 AND scope_id=$2",
        )
        .bind(&command.scope_type)
        .bind(scope_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO catalog.versioned_artifact \
             (id,artifact_kind_code,scope_type_code,scope_id,artifact_version,lifecycle_code,payload,content_hash, \
              schema_version,created_by,created_at) \
             VALUES ($1,'ruleset',$2,$3,$4,'eligible',$5,$6,1,$7,clock_timestamp())",
        )
        .bind(artifact_id)
        .bind(&command.scope_type)
        .bind(scope_id)
        .bind(version)
        .bind(&payload)
        .bind(&content_hash)
        .bind(parse_uuid(&principal.user_id)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        sqlx::query(
            "INSERT INTO catalog.compiled_rule_index \
             (artifact_id,compiler_version,compiled_payload,compiled_hash,created_at) \
             VALUES ($1,'gateway-policy-v1',$2,$3,clock_timestamp())",
        )
        .bind(artifact_id)
        .bind(&payload_bytes)
        .bind(Sha256::digest(&payload_bytes).to_vec())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "ruleset_created",
                    "ruleset",
                    artifact_id,
                    version,
                    json!({
                        "scope_type":command.scope_type,"scope_id":scope_id,"rule_count":payload["rules"].as_array().map_or(0,Vec::len),
                        "content_hash":lower_hex(&content_hash),"reason":reason
                    }),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":artifact_id,"kind":"ruleset","version":version,"lifecycle":"eligible",
                "scope_type":command.scope_type,"scope_id":scope_id,"content_hash":lower_hex(&content_hash),"revision":version},"meta":{}}),
            etag: Some(format!("\"rev-{version}\"").into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn validate_ruleset(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: ArtifactActionCommand = deserialize_body(request)?;
        required_action_reason(Some(&command.reason))?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let artifact_id = path_uuid(request, "id")?;
        let row = sqlx::query(
            "SELECT artifact_version,lifecycle_code,payload FROM catalog.versioned_artifact \
             WHERE id=$1 AND artifact_kind_code='ruleset'",
        )
        .bind(artifact_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let version = required::<i64>(&row, "artifact_version")?;
        if version != expected_revision
            || !matches!(
                required::<String>(&row, "lifecycle_code")?.as_str(),
                "eligible" | "canary" | "active"
            )
        {
            return Err(ManagementBackendError::Precondition);
        }
        let payload = required::<Value>(&row, "payload")?;
        let stored: StoredRuleSetPayload =
            serde_json::from_value(payload).map_err(|_| ManagementBackendError::InvalidInput)?;
        CompiledRuleSet::compile(format!("ruleset:{artifact_id}:{version}"), stored.rules.clone())
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        Ok(single_response(
            &json!({
                "id":artifact_id,"valid":true,"compiler_version":"gateway-policy-v1",
                "rule_count":stored.rules.len(),"lifecycle":required::<String>(&row,"lifecycle_code")?,"revision":version
            }),
            version,
        ))
    }

    async fn simulate_ruleset(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: RuleSetSimulationCommand = deserialize_body(request)?;
        let expected_revision = request_revision(request)?;
        if command.protocol_headers.len() > 2
            || command.protocol_headers.iter().any(|(name, value)| {
                !matches!(name.as_str(), "anthropic-version" | "anthropic-beta")
                    || value.is_empty()
                    || value.len() > 1_024
                    || value.contains(['\r', '\n'])
            })
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let artifact_id = path_uuid(request, "id")?;
        let row = sqlx::query(
            "SELECT artifact_version,lifecycle_code,payload FROM catalog.versioned_artifact \
             WHERE id=$1 AND artifact_kind_code='ruleset'",
        )
        .bind(artifact_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let version = required::<i64>(&row, "artifact_version")?;
        if version != expected_revision
            || matches!(
                required::<String>(&row, "lifecycle_code")?.as_str(),
                "retired" | "quarantined"
            )
        {
            return Err(ManagementBackendError::Precondition);
        }
        let stored: StoredRuleSetPayload = serde_json::from_value(required::<Value>(&row, "payload")?)
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let compiled = CompiledRuleSet::compile(format!("ruleset:{artifact_id}:{version}"), stored.rules)
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let context = PolicyContext {
            client_class: command.client_class,
            traffic_class: command.traffic_class,
            protocol_headers: command
                .protocol_headers
                .into_iter()
                .map(|(name, value)| (name.into_boxed_str(), Value::String(value)))
                .collect(),
            affinity_credential: None,
        };
        let result = compiled
            .simulate(command.request, &context)
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::OK,
            body: json!({"data":{"id":artifact_id,"valid":true,"adjusted_request_digest":result.adjusted_request_digest,
                "change_set":result.changes,"revision":version},"meta":{}}),
            etag: Some(format!("\"rev-{version}\"").into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn activate_ruleset(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: ArtifactActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let expected_artifact_version = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_artifact_version)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let artifact_id = path_uuid(request, "id")?;
        let actor_id = parse_uuid(&principal.user_id)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let target = sqlx::query(
            "SELECT artifact_version,lifecycle_code,scope_type_code,scope_id,payload,content_hash \
             FROM catalog.versioned_artifact WHERE id=$1 AND artifact_kind_code='ruleset' FOR UPDATE",
        )
        .bind(artifact_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let artifact_version = required::<i64>(&target, "artifact_version")?;
        let scope_type =
            required::<Option<String>>(&target, "scope_type_code")?.ok_or(ManagementBackendError::Precondition)?;
        let scope_id = required::<Option<Uuid>>(&target, "scope_id")?.ok_or(ManagementBackendError::Precondition)?;
        if artifact_version != expected_artifact_version
            || !matches!(
                required::<String>(&target, "lifecycle_code")?.as_str(),
                "eligible" | "canary"
            )
            || !matches!(scope_type.as_str(), "group" | "platform_key")
        {
            return Err(ManagementBackendError::Precondition);
        }
        let stored: StoredRuleSetPayload = serde_json::from_value(required::<Value>(&target, "payload")?)
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        CompiledRuleSet::compile(format!("ruleset:{artifact_id}:{artifact_version}"), stored.rules)
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!("catalog:ruleset:{scope_type}:{scope_id}"))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let pointer = sqlx::query(
            "SELECT id,artifact_id,revision FROM catalog.active_artifact_pointer \
             WHERE artifact_kind_code='ruleset' AND scope_type_code=$1 AND scope_id=$2 FOR UPDATE",
        )
        .bind(&scope_type)
        .bind(scope_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let artifact_pointer_revision = if let Some(pointer) = pointer {
            let previous_artifact = required::<Uuid>(&pointer, "artifact_id")?;
            let previous_revision = required::<i64>(&pointer, "revision")?;
            if previous_artifact == artifact_id {
                return Err(ManagementBackendError::Precondition);
            }
            sqlx::query(
                "UPDATE catalog.versioned_artifact SET lifecycle_code='retired',retired_at=clock_timestamp() \
                 WHERE id=$1 AND lifecycle_code='active'",
            )
            .bind(previous_artifact)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let next = previous_revision
                .checked_add(1)
                .ok_or(ManagementBackendError::Unavailable)?;
            sqlx::query(
                "UPDATE catalog.active_artifact_pointer SET artifact_id=$2,revision=$3,activated_by=$4, \
                 activated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(required::<Uuid>(&pointer, "id")?)
            .bind(artifact_id)
            .bind(next)
            .bind(actor_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            next
        } else {
            sqlx::query(
                "INSERT INTO catalog.active_artifact_pointer \
                 (id,artifact_kind_code,scope_type_code,scope_id,artifact_id,revision,activated_by,activated_at) \
                 VALUES ($1,'ruleset',$2,$3,$4,1,$5,clock_timestamp())",
            )
            .bind(Uuid::now_v7())
            .bind(&scope_type)
            .bind(scope_id)
            .bind(artifact_id)
            .bind(actor_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            1
        };
        sqlx::query("UPDATE catalog.versioned_artifact SET lifecycle_code='active',retired_at=NULL WHERE id=$1")
            .bind(artifact_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;

        let target_hash = required::<Vec<u8>>(&target, "content_hash")?;
        let (configuration_version, configuration_pointer_revision, resource_revision) = if scope_type == "group" {
            let current = sqlx::query(
                    "SELECT config.id,config.config_version,config.content_hash,pointer.revision \
                     FROM gateway.group_active_config pointer JOIN gateway.group_config config ON config.id=pointer.config_id \
                     JOIN gateway.credential_group resource ON resource.id=pointer.group_id \
                     WHERE pointer.group_id=$1 AND resource.status_code='active' FOR UPDATE OF pointer,config,resource",
                )
                .bind(scope_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .ok_or(ManagementBackendError::Precondition)?;
            let current_id = required::<Uuid>(&current, "id")?;
            let next_version: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(config_version),0)+1 FROM gateway.group_config WHERE group_id=$1",
            )
            .bind(scope_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let mut hash_input = required::<Vec<u8>>(&current, "content_hash")?;
            hash_input.extend_from_slice(&target_hash);
            hash_input.extend_from_slice(&next_version.to_be_bytes());
            let next_hash = Sha256::digest(hash_input).to_vec();
            let next_config_id = Uuid::now_v7();
            sqlx::query(
                "UPDATE gateway.group_config SET lifecycle_code='retired' WHERE id=$1 AND lifecycle_code='active'",
            )
            .bind(current_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                    "INSERT INTO gateway.group_config \
                     (id,group_id,config_version,content_hash,default_rpm,queue_capacity,queue_timeout_ms,ruleset_artifact_id, \
                      enforcement_artifact_id,system_prompt_mode_code,proxy_policy_code,model_scope_code,created_by,created_at,default_rpm_burst, \
                      max_concurrency,pre_upstream_wait_ms,preferred_capacity_wait_ms,affinity_ttl_ms,affinity_migration_successes, \
                      quota_guard_basis_points,fully_managed_required,console_business_fallback_enabled,content_audit_policy_code, \
                      content_audit_retention_days,system_prompt_ref,system_prompt_content,upstream_connect_ms, \
                      upstream_non_stream_total_ms,upstream_stream_idle_ms,min_retry_budget_ms,cancel_grace_ms, \
                      queue_full_retry_after_ms,queue_wait_retry_after_ms,lifecycle_code,validation_report,validated_at,published_at, \
                      default_credential_concurrency,default_credential_rpm) \
                     SELECT $1,group_id,$2,$3,default_rpm,queue_capacity,queue_timeout_ms,$4,enforcement_artifact_id,system_prompt_mode_code, \
                      proxy_policy_code,model_scope_code,$5,clock_timestamp(),default_rpm_burst,max_concurrency,pre_upstream_wait_ms, \
                      preferred_capacity_wait_ms,affinity_ttl_ms,affinity_migration_successes,quota_guard_basis_points, \
                      fully_managed_required,console_business_fallback_enabled,content_audit_policy_code,content_audit_retention_days, \
                      system_prompt_ref,system_prompt_content,upstream_connect_ms,upstream_non_stream_total_ms,upstream_stream_idle_ms, \
                      min_retry_budget_ms,cancel_grace_ms,queue_full_retry_after_ms,queue_wait_retry_after_ms,'active', \
                      jsonb_build_object('valid',true,'source','ruleset_activation'),clock_timestamp(),clock_timestamp(), \
                      default_credential_concurrency,default_credential_rpm \
                     FROM gateway.group_config WHERE id=$6",
                )
                .bind(next_config_id)
                .bind(next_version)
                .bind(next_hash)
                .bind(artifact_id)
                .bind(actor_id)
                .bind(current_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                "INSERT INTO gateway.group_accepted_client_class (group_config_id,client_class_code) \
                     SELECT $1,client_class_code FROM gateway.group_accepted_client_class WHERE group_config_id=$2",
            )
            .bind(next_config_id)
            .bind(current_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                "INSERT INTO gateway.group_model_allowlist (group_config_id,model_id) \
                     SELECT $1,model_id FROM gateway.group_model_allowlist WHERE group_config_id=$2",
            )
            .bind(next_config_id)
            .bind(current_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let config_pointer_revision: i64 = sqlx::query_scalar(
                "UPDATE gateway.group_active_config SET config_id=$2,revision=revision+1,activated_by=$3, \
                     activated_at=clock_timestamp() WHERE group_id=$1 RETURNING revision",
            )
            .bind(scope_id)
            .bind(next_config_id)
            .bind(actor_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let resource_revision: i64 = sqlx::query_scalar(
                "UPDATE gateway.credential_group SET revision=revision+1,updated_at=clock_timestamp() \
                     WHERE id=$1 RETURNING revision",
            )
            .bind(scope_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            (next_version, config_pointer_revision, resource_revision)
        } else {
            let current = sqlx::query(
                    "SELECT config.id,config.config_version,config.content_hash,pointer.revision \
                     FROM iam.platform_key_active_config pointer JOIN iam.platform_key_config config ON config.id=pointer.config_id \
                     JOIN iam.platform_key resource ON resource.id=pointer.platform_key_id \
                     WHERE pointer.platform_key_id=$1 AND resource.status_code='active' FOR UPDATE OF pointer,config,resource",
                )
                .bind(scope_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .ok_or(ManagementBackendError::Precondition)?;
            let current_id = required::<Uuid>(&current, "id")?;
            let next_version: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(config_version),0)+1 FROM iam.platform_key_config WHERE platform_key_id=$1",
            )
            .bind(scope_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let mut hash_input = required::<Vec<u8>>(&current, "content_hash")?;
            hash_input.extend_from_slice(&target_hash);
            hash_input.extend_from_slice(&next_version.to_be_bytes());
            let next_hash = Sha256::digest(hash_input).to_vec();
            let next_config_id = Uuid::now_v7();
            sqlx::query(
                    "INSERT INTO iam.platform_key_config \
                     (id,platform_key_id,config_version,content_hash,messages_enabled,models_enabled,max_body_bytes,messages_rpm, \
                      messages_burst,models_rpm,models_burst,max_concurrency,ruleset_artifact_id,audit_mode_code,created_by,created_at, \
                      content_audit_approval_case_id,content_audit_expires_at) \
                     SELECT $1,platform_key_id,$2,$3,messages_enabled,models_enabled,max_body_bytes,messages_rpm,messages_burst, \
                      models_rpm,models_burst,max_concurrency,$4,audit_mode_code,$5,clock_timestamp(), \
                      content_audit_approval_case_id,content_audit_expires_at \
                     FROM iam.platform_key_config WHERE id=$6",
                )
                .bind(next_config_id)
                .bind(next_version)
                .bind(next_hash)
                .bind(artifact_id)
                .bind(actor_id)
                .bind(current_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                "INSERT INTO iam.platform_key_model_allowlist (platform_key_config_id,model_id) \
                     SELECT $1,model_id FROM iam.platform_key_model_allowlist WHERE platform_key_config_id=$2",
            )
            .bind(next_config_id)
            .bind(current_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                "INSERT INTO iam.platform_key_ip_allowlist (platform_key_config_id,network) \
                     SELECT $1,network FROM iam.platform_key_ip_allowlist WHERE platform_key_config_id=$2",
            )
            .bind(next_config_id)
            .bind(current_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let config_pointer_revision: i64 = sqlx::query_scalar(
                "UPDATE iam.platform_key_active_config SET config_id=$2,revision=revision+1,activated_by=$3, \
                     activated_at=clock_timestamp() WHERE platform_key_id=$1 RETURNING revision",
            )
            .bind(scope_id)
            .bind(next_config_id)
            .bind(actor_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let resource_revision: i64 = sqlx::query_scalar(
                "UPDATE iam.platform_key SET revision=revision+1,updated_at=clock_timestamp() \
                     WHERE id=$1 RETURNING revision",
            )
            .bind(scope_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            (next_version, config_pointer_revision, resource_revision)
        };
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "ruleset_activated",
                    "ruleset",
                    artifact_id,
                    artifact_pointer_revision,
                    json!({
                        "scope_type":scope_type,"scope_id":scope_id,"artifact_version":artifact_version,
                        "configuration_version":configuration_version,"configuration_pointer_revision":configuration_pointer_revision,
                        "resource_revision":resource_revision,"reason":reason
                    }),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let scheduler_projection_applied = if scope_type == "group" {
            if let Some(runtime) = &self.scheduler_runtime {
                runtime
                    .reconfigure_group_projection(scope_id)
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?
            } else {
                false
            }
        } else {
            false
        };
        self.reload_management_runtime().await?;
        Ok(single_response(
            &json!({
                "id":artifact_id,"kind":"ruleset","version":artifact_version,"lifecycle":"active",
                "scope_type":scope_type,"scope_id":scope_id,"pointer_revision":artifact_pointer_revision,
                "configuration_version":configuration_version,"configuration_pointer_revision":configuration_pointer_revision,
                "resource_revision":resource_revision,"scheduler_projection_applied":scheduler_projection_applied,
                "revision":artifact_pointer_revision
            }),
            artifact_pointer_revision,
        ))
    }

    async fn create_typed_artifact(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        kind: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: TypedArtifactCreateCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        if command.name.trim().is_empty()
            || command.name.len() > 128
            || command.schema_version != 1
            || !command.payload.is_object()
            || command.source_refs.len() > 128
            || command
                .source_refs
                .iter()
                .any(|value| value.is_empty() || value.len() > 2_048 || value.contains(['\r', '\n']))
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        validate_policy_artifact_payload(kind, &command.payload)?;
        let (scope_type, scope_id) = match kind {
            "background_catalog" => {
                let entries = command
                    .payload
                    .get("entries")
                    .and_then(Value::as_array)
                    .ok_or(ManagementBackendError::InvalidInput)?;
                if entries.is_empty() || entries.len() > 10_000 {
                    return Err(ManagementBackendError::InvalidInput);
                }
                (None, None)
            }
            "enforcement" => {
                let group_id = command
                    .payload
                    .get("group_id")
                    .and_then(Value::as_str)
                    .ok_or(ManagementBackendError::InvalidInput)
                    .and_then(parse_input_uuid)?;
                let system = command
                    .payload
                    .get("system")
                    .and_then(Value::as_object)
                    .ok_or(ManagementBackendError::InvalidInput)?;
                if !system
                    .get("mode")
                    .and_then(Value::as_str)
                    .is_some_and(|mode| matches!(mode, "preserve" | "strip_client" | "replace" | "strip_all"))
                {
                    return Err(ManagementBackendError::InvalidInput);
                }
                (Some("group"), Some(group_id))
            }
            _ => return Err(ManagementBackendError::InvalidInput),
        };
        let payload = json!({
            "name":command.name.trim(),"payload":command.payload,"source_refs":command.source_refs
        });
        let hash = Sha256::digest(canonical_json_bytes(&payload)?).to_vec();
        let artifact_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!(
                "catalog:{kind}:{}",
                scope_id.map_or_else(|| "global".to_owned(), |id| id.to_string())
            ))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some(scope_id) = scope_id {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM gateway.credential_group WHERE id=$1 AND status_code<>'archived')",
            )
            .bind(scope_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            if !exists {
                return Err(ManagementBackendError::NotFound);
            }
        }
        let version: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(artifact_version),0)+1 FROM catalog.versioned_artifact \
             WHERE artifact_kind_code=$1 AND scope_type_code IS NOT DISTINCT FROM $2 \
               AND scope_id IS NOT DISTINCT FROM $3",
        )
        .bind(kind)
        .bind(scope_type)
        .bind(scope_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query(
            "INSERT INTO catalog.versioned_artifact \
             (id,artifact_kind_code,scope_type_code,scope_id,artifact_version,lifecycle_code,payload,content_hash, \
              schema_version,created_by,created_at) VALUES ($1,$2,$3,$4,$5,'draft',$6,$7,$8,$9,clock_timestamp())",
        )
        .bind(artifact_id)
        .bind(kind)
        .bind(scope_type)
        .bind(scope_id)
        .bind(version)
        .bind(&payload)
        .bind(&hash)
        .bind(command.schema_version)
        .bind(parse_uuid(&principal.user_id)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Precondition)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    &format!("{kind}_version_created"),
                    kind,
                    artifact_id,
                    version,
                    json!({"scope_id":scope_id,"content_hash":lower_hex(&hash),"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":{"id":artifact_id,"kind":kind,"version":version,"lifecycle":"draft",
                "scope_type":scope_type,"scope_id":scope_id,"content_hash":lower_hex(&hash),"revision":version},"meta":{}}),
            etag: Some(format!("\"rev-{version}\"").into_boxed_str()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn validate_policy_artifact(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        kind: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: PolicyArtifactActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
            || command.approval_case_id.is_some()
            || command.samples.len() > 10_000
        {
            return Err(ManagementBackendError::Precondition);
        }
        let artifact_id = path_uuid(request, "id")?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "SELECT artifact_version,lifecycle_code,payload FROM catalog.versioned_artifact \
             WHERE id=$1 AND artifact_kind_code=$2 FOR UPDATE",
        )
        .bind(artifact_id)
        .bind(kind)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let version = required::<i64>(&row, "artifact_version")?;
        if version != expected_revision
            || !matches!(
                required::<String>(&row, "lifecycle_code")?.as_str(),
                "draft" | "eligible"
            )
        {
            return Err(ManagementBackendError::Precondition);
        }
        let compiled = compile_stored_policy_artifact(kind, required::<Value>(&row, "payload")?)?;
        let deterministic_sample_count = match compiled {
            CompiledPolicyArtifact::Background(catalog) => {
                for sample in &command.samples {
                    if sample.expected_entry_id.is_empty()
                        || sample.expected_entry_id.len() > 128
                        || !sample.body.is_object()
                    {
                        return Err(ManagementBackendError::InvalidInput);
                    }
                    let headers = background_sample_headers(sample)?;
                    if catalog.classify(&headers, &sample.body, sample.client_class)
                        != Some(sample.expected_entry_id.as_str())
                    {
                        return Err(ManagementBackendError::InvalidInput);
                    }
                }
                i32::try_from(command.samples.len()).map_err(|_| ManagementBackendError::InvalidInput)?
            }
            CompiledPolicyArtifact::Enforcement(_) => {
                if !command.samples.is_empty() {
                    return Err(ManagementBackendError::InvalidInput);
                }
                0
            }
        };
        let report = json!({
            "valid":true,
            "compiler_version":"gateway-policy-artifact-v1",
            "deterministic_sample_count":deterministic_sample_count
        });
        sqlx::query(
            "INSERT INTO catalog.artifact_rollout_evidence \
             (artifact_id,validation_report,validated_by,validated_at,deterministic_sample_count,revision,updated_at) \
             VALUES ($1,$2,$3,clock_timestamp(),$4,1,clock_timestamp()) \
             ON CONFLICT (artifact_id) DO UPDATE SET validation_report=EXCLUDED.validation_report, \
               validated_by=EXCLUDED.validated_by,validated_at=EXCLUDED.validated_at, \
               deterministic_sample_count=EXCLUDED.deterministic_sample_count,revision=catalog.artifact_rollout_evidence.revision+1, \
               updated_at=clock_timestamp()",
        )
        .bind(artifact_id)
        .bind(&report)
        .bind(parse_uuid(&principal.user_id)?)
        .bind(deterministic_sample_count)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        sqlx::query("UPDATE catalog.versioned_artifact SET lifecycle_code='eligible' WHERE id=$1")
            .bind(artifact_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    &format!("{kind}_validated"),
                    kind,
                    artifact_id,
                    version,
                    json!({"compiler_version":"gateway-policy-artifact-v1","deterministic_sample_count":deterministic_sample_count,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(
            &json!({"id":artifact_id,"kind":kind,"version":version,"lifecycle":"eligible",
                "valid":true,"deterministic_sample_count":deterministic_sample_count,"revision":version}),
            version,
        ))
    }

    async fn publish_policy_artifact_shadow(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        kind: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: PolicyArtifactActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
            || command.approval_case_id.is_some()
            || !command.samples.is_empty()
        {
            return Err(ManagementBackendError::Precondition);
        }
        let artifact_id = path_uuid(request, "id")?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "SELECT artifact_version,lifecycle_code,payload FROM catalog.versioned_artifact \
             WHERE id=$1 AND artifact_kind_code=$2 FOR UPDATE",
        )
        .bind(artifact_id)
        .bind(kind)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let version = required::<i64>(&row, "artifact_version")?;
        if version != expected_revision || required::<String>(&row, "lifecycle_code")? != "eligible" {
            return Err(ManagementBackendError::Precondition);
        }
        compile_stored_policy_artifact(kind, required::<Value>(&row, "payload")?)?;
        let updated = sqlx::query(
            "UPDATE catalog.artifact_rollout_evidence SET shadow_started_at=clock_timestamp(), \
               shadow_minimum_until=clock_timestamp()+interval '7 days',revision=revision+1,updated_at=clock_timestamp() \
             WHERE artifact_id=$1 AND validated_at IS NOT NULL \
             RETURNING shadow_started_at::text AS shadow_started_at,shadow_minimum_until::text AS shadow_minimum_until, \
                       deterministic_sample_count,revision",
        )
        .bind(artifact_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        sqlx::query("UPDATE catalog.versioned_artifact SET lifecycle_code='shadow' WHERE id=$1")
            .bind(artifact_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    &format!("{kind}_shadow_published"),
                    kind,
                    artifact_id,
                    version,
                    json!({"minimum_days":7,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(
            &json!({"id":artifact_id,"kind":kind,"version":version,"lifecycle":"shadow",
                "shadow_started_at":required::<String>(&updated,"shadow_started_at")?,
                "shadow_minimum_until":required::<String>(&updated,"shadow_minimum_until")?,
                "deterministic_sample_count":required::<i32>(&updated,"deterministic_sample_count")?,
                "evidence_revision":required::<i64>(&updated,"revision")?,"revision":version}),
            version,
        ))
    }

    async fn activate_policy_artifact(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        kind: &'static str,
        rollback: bool,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: PolicyArtifactActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|revision| revision != expected_revision)
            || !command.samples.is_empty()
        {
            return Err(ManagementBackendError::Precondition);
        }
        let artifact_id = path_uuid(request, "id")?;
        let actor_id = parse_uuid(&principal.user_id)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let target = sqlx::query(
            "SELECT artifact.artifact_version,artifact.lifecycle_code,artifact.scope_type_code,artifact.scope_id, \
                    artifact.payload,artifact.content_hash,evidence.validated_at IS NOT NULL AS validated, \
                    COALESCE(evidence.shadow_minimum_until<=clock_timestamp(),false) AS shadow_mature, \
                    COALESCE(evidence.deterministic_sample_count,0) AS deterministic_sample_count \
             FROM catalog.versioned_artifact artifact \
             LEFT JOIN catalog.artifact_rollout_evidence evidence ON evidence.artifact_id=artifact.id \
             WHERE artifact.id=$1 AND artifact.artifact_kind_code=$2 FOR UPDATE OF artifact",
        )
        .bind(artifact_id)
        .bind(kind)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let artifact_version = required::<i64>(&target, "artifact_version")?;
        let lifecycle = required::<String>(&target, "lifecycle_code")?;
        if artifact_version != expected_revision
            || rollback != (lifecycle == "retired")
            || (!rollback && !matches!(lifecycle.as_str(), "eligible" | "shadow"))
            || !required::<bool>(&target, "validated")?
        {
            return Err(ManagementBackendError::Precondition);
        }
        let compiled = compile_stored_policy_artifact(kind, required::<Value>(&target, "payload")?)?;
        let target_hash: [u8; 32] = required::<Vec<u8>>(&target, "content_hash")?
            .try_into()
            .map_err(|_| ManagementBackendError::Precondition)?;
        let scope_type = required::<Option<String>>(&target, "scope_type_code")?;
        let scope_id = required::<Option<Uuid>>(&target, "scope_id")?;
        let approval_operation = match &compiled {
            CompiledPolicyArtifact::Background(catalog) => {
                if scope_type.is_some() || scope_id.is_some() {
                    return Err(ManagementBackendError::Precondition);
                }
                let high_risk = catalog
                    .entries()
                    .iter()
                    .any(|entry| entry.action != gateway_api::ProbeAction::Observe);
                if high_risk {
                    if !rollback && !required::<bool>(&target, "shadow_mature")? {
                        return Err(ManagementBackendError::Precondition);
                    }
                    let enough_samples = required::<i32>(&target, "deterministic_sample_count")? >= 100;
                    Some(if enough_samples {
                        "background_catalog_activate"
                    } else {
                        "background_catalog_risk_acceptance"
                    })
                } else {
                    None
                }
            }
            CompiledPolicyArtifact::Enforcement(candidate) => {
                if scope_type.as_deref() != Some("group")
                    || scope_id != Some(parse_input_uuid(&candidate.group_id)?)
                    || (!rollback && lifecycle != "shadow")
                {
                    return Err(ManagementBackendError::Precondition);
                }
                Some("enforcement_activate")
            }
        };
        if let Some(operation) = approval_operation {
            let approval_id = command.approval_case_id.ok_or(ManagementBackendError::Precondition)?;
            consume_approved_case_bound(
                &mut transaction,
                approval_id,
                operation,
                kind,
                &artifact_id.to_string(),
                &target_hash,
            )
            .await?;
            if operation == "background_catalog_risk_acceptance" {
                sqlx::query(
                    "UPDATE catalog.artifact_rollout_evidence SET risk_acceptance_case_id=$2,revision=revision+1, \
                     updated_at=clock_timestamp() WHERE artifact_id=$1",
                )
                .bind(artifact_id)
                .bind(approval_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            }
        } else if command.approval_case_id.is_some() {
            return Err(ManagementBackendError::InvalidInput);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!(
                "catalog:{kind}:{}",
                scope_id.map_or_else(|| "global".to_owned(), |id| id.to_string())
            ))
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let pointer = sqlx::query(
            "SELECT id,artifact_id,revision FROM catalog.active_artifact_pointer \
             WHERE artifact_kind_code=$1 AND scope_type_code IS NOT DISTINCT FROM $2 \
               AND scope_id IS NOT DISTINCT FROM $3 FOR UPDATE",
        )
        .bind(kind)
        .bind(scope_type.as_deref())
        .bind(scope_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let pointer_revision = if let Some(pointer) = pointer {
            let previous_artifact = required::<Uuid>(&pointer, "artifact_id")?;
            if previous_artifact == artifact_id {
                return Err(ManagementBackendError::Precondition);
            }
            sqlx::query(
                "UPDATE catalog.versioned_artifact SET lifecycle_code='retired',retired_at=clock_timestamp() \
                 WHERE id=$1 AND lifecycle_code='active'",
            )
            .bind(previous_artifact)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let next = required::<i64>(&pointer, "revision")?
                .checked_add(1)
                .ok_or(ManagementBackendError::Unavailable)?;
            sqlx::query(
                "UPDATE catalog.active_artifact_pointer SET artifact_id=$2,revision=$3,activated_by=$4, \
                 activated_at=clock_timestamp() WHERE id=$1",
            )
            .bind(required::<Uuid>(&pointer, "id")?)
            .bind(artifact_id)
            .bind(next)
            .bind(actor_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            next
        } else {
            if rollback {
                return Err(ManagementBackendError::Precondition);
            }
            sqlx::query(
                "INSERT INTO catalog.active_artifact_pointer \
                 (id,artifact_kind_code,scope_type_code,scope_id,artifact_id,revision,activated_by,activated_at) \
                 VALUES ($1,$2,$3,$4,$5,1,$6,clock_timestamp())",
            )
            .bind(Uuid::now_v7())
            .bind(kind)
            .bind(scope_type.as_deref())
            .bind(scope_id)
            .bind(artifact_id)
            .bind(actor_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            1
        };
        sqlx::query("UPDATE catalog.versioned_artifact SET lifecycle_code='active',retired_at=NULL WHERE id=$1")
            .bind(artifact_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;

        let mut configuration_version: Option<i64> = None;
        let mut configuration_pointer_revision: Option<i64> = None;
        let mut resource_revision: Option<i64> = None;
        if let CompiledPolicyArtifact::Enforcement(candidate) = compiled {
            let group_id = scope_id.ok_or(ManagementBackendError::Precondition)?;
            let current = sqlx::query(
                "SELECT config.id,config.config_version,config.content_hash \
                 FROM gateway.group_active_config pointer JOIN gateway.group_config config ON config.id=pointer.config_id \
                 JOIN gateway.credential_group resource ON resource.id=pointer.group_id \
                 WHERE pointer.group_id=$1 AND resource.status_code='active' FOR UPDATE OF pointer,config,resource",
            )
            .bind(group_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?
            .ok_or(ManagementBackendError::Precondition)?;
            let current_id = required::<Uuid>(&current, "id")?;
            let next_version: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(config_version),0)+1 FROM gateway.group_config WHERE group_id=$1",
            )
            .bind(group_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            let mut hash_input = required::<Vec<u8>>(&current, "content_hash")?;
            hash_input.extend_from_slice(&target_hash);
            hash_input.extend_from_slice(&next_version.to_be_bytes());
            let next_hash = Sha256::digest(hash_input).to_vec();
            let next_config_id = Uuid::now_v7();
            let system = candidate.system;
            compile_enforcement_system(&system)?;
            sqlx::query(
                "UPDATE gateway.group_config SET lifecycle_code='retired' WHERE id=$1 AND lifecycle_code='active'",
            )
            .bind(current_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            sqlx::query(
                "INSERT INTO gateway.group_config \
                 (id,group_id,config_version,content_hash,default_rpm,queue_capacity,queue_timeout_ms,ruleset_artifact_id, \
                  enforcement_artifact_id,system_prompt_mode_code,proxy_policy_code,model_scope_code,created_by,created_at, \
                  default_rpm_burst,max_concurrency,pre_upstream_wait_ms,preferred_capacity_wait_ms,affinity_ttl_ms, \
                  affinity_migration_successes,quota_guard_basis_points,fully_managed_required,console_business_fallback_enabled, \
                  content_audit_policy_code,content_audit_retention_days,system_prompt_ref,system_prompt_content,upstream_connect_ms, \
                  upstream_non_stream_total_ms,upstream_stream_idle_ms,min_retry_budget_ms,cancel_grace_ms,queue_full_retry_after_ms, \
                  queue_wait_retry_after_ms,lifecycle_code,validation_report,validated_at,published_at, \
                  default_credential_concurrency,default_credential_rpm) \
                 SELECT $1,group_id,$2,$3,default_rpm,queue_capacity,queue_timeout_ms,ruleset_artifact_id,$4,$5,proxy_policy_code, \
                  model_scope_code,$6,clock_timestamp(),default_rpm_burst,max_concurrency,pre_upstream_wait_ms, \
                  preferred_capacity_wait_ms,affinity_ttl_ms,affinity_migration_successes,quota_guard_basis_points, \
                  fully_managed_required,console_business_fallback_enabled,content_audit_policy_code,content_audit_retention_days, \
                  $7,$8,upstream_connect_ms,upstream_non_stream_total_ms,upstream_stream_idle_ms,min_retry_budget_ms,cancel_grace_ms, \
                  queue_full_retry_after_ms,queue_wait_retry_after_ms,'active', \
                  jsonb_build_object('valid',true,'source','enforcement_activation'),clock_timestamp(),clock_timestamp(), \
                  default_credential_concurrency,default_credential_rpm FROM gateway.group_config WHERE id=$9",
            )
            .bind(next_config_id)
            .bind(next_version)
            .bind(next_hash)
            .bind(artifact_id)
            .bind(&system.mode)
            .bind(actor_id)
            .bind(system.platform_system_ref.as_deref())
            .bind(system.content.as_ref())
            .bind(current_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
            for table in ["gateway.group_accepted_client_class", "gateway.group_model_allowlist"] {
                let (column, value_column) = if table.ends_with("client_class") {
                    ("group_config_id", "client_class_code")
                } else {
                    ("group_config_id", "model_id")
                };
                let statement = format!(
                    "INSERT INTO {table} ({column},{value_column}) SELECT $1,{value_column} FROM {table} WHERE {column}=$2"
                );
                sqlx::query(&statement)
                    .bind(next_config_id)
                    .bind(current_id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?;
            }
            configuration_pointer_revision = Some(
                sqlx::query_scalar(
                    "UPDATE gateway.group_active_config SET config_id=$2,revision=revision+1,activated_by=$3, \
                     activated_at=clock_timestamp() WHERE group_id=$1 RETURNING revision",
                )
                .bind(group_id)
                .bind(next_config_id)
                .bind(actor_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?,
            );
            resource_revision = Some(
                sqlx::query_scalar(
                    "UPDATE gateway.credential_group SET revision=revision+1,updated_at=clock_timestamp() \
                     WHERE id=$1 RETURNING revision",
                )
                .bind(group_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?,
            );
            configuration_version = Some(next_version);
        }
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    &format!("{kind}_{}", if rollback { "rolled_back" } else { "activated" }),
                    kind,
                    artifact_id,
                    pointer_revision,
                    json!({
                        "artifact_version":artifact_version,"pointer_revision":pointer_revision,
                        "configuration_version":configuration_version,
                        "configuration_pointer_revision":configuration_pointer_revision,
                        "resource_revision":resource_revision,"approval_operation":approval_operation,"reason":reason
                    }),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let scheduler_projection_applied = if kind == "enforcement" {
            if let (Some(runtime), Some(group_id)) = (&self.scheduler_runtime, scope_id) {
                runtime
                    .reconfigure_group_projection(group_id)
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?
            } else {
                false
            }
        } else {
            false
        };
        self.reload_management_runtime().await?;
        Ok(single_response(
            &json!({
                "id":artifact_id,"kind":kind,"version":artifact_version,"lifecycle":"active",
                "scope_type":scope_type,"scope_id":scope_id,"pointer_revision":pointer_revision,
                "configuration_version":configuration_version,
                "configuration_pointer_revision":configuration_pointer_revision,
                "resource_revision":resource_revision,"scheduler_projection_applied":scheduler_projection_applied,
                "revision":pointer_revision
            }),
            pointer_revision,
        ))
    }

    async fn list_alerts(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT id,severity_code,type_code,state_code,object_type_code,object_id,summary,detail,revision, \
                    first_seen_at::text AS first_seen_at,last_seen_at::text AS last_seen_at,resolved_at::text AS resolved_at \
             FROM ops.alert ORDER BY last_seen_at DESC,id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(alert_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn alert_action(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        target: &'static str,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let command: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let alert_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|value| value != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let current = sqlx::query("SELECT state_code,revision FROM ops.alert WHERE id=$1 FOR UPDATE")
            .bind(alert_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?
            .ok_or(ManagementBackendError::NotFound)?;
        let current_state: String = required(&current, "state_code")?;
        let current_revision: i64 = required(&current, "revision")?;
        let transition_allowed = match target {
            "acknowledged" => current_state == "open",
            "resolved" => matches!(current_state.as_str(), "open" | "acknowledged" | "silenced"),
            _ => false,
        };
        if current_revision != expected_revision || !transition_allowed {
            return Err(ManagementBackendError::Precondition);
        }
        let row = sqlx::query(
            "UPDATE ops.alert SET state_code=$2, \
               resolved_at=CASE WHEN $2='resolved' THEN clock_timestamp() ELSE resolved_at END, \
               detail=(CASE WHEN jsonb_typeof(detail)='object' THEN detail ELSE '{}'::jsonb END) \
                 || jsonb_build_object( \
                    CASE WHEN $2='resolved' THEN 'resolved_by' ELSE 'acknowledged_by' END,$3::text, \
                    CASE WHEN $2='resolved' THEN 'resolved_at' ELSE 'acknowledged_at' END,clock_timestamp(), \
                    CASE WHEN $2='resolved' THEN 'resolution_note' ELSE 'acknowledgement_reason' END,$4::text), \
               revision=revision+1 \
             WHERE id=$1 AND revision=$5 \
             RETURNING id,severity_code,type_code,state_code,object_type_code,object_id,summary,detail,revision, \
              first_seen_at::text AS first_seen_at,last_seen_at::text AS last_seen_at,resolved_at::text AS resolved_at",
        )
        .bind(alert_id)
        .bind(target)
        .bind(parse_uuid(&principal.user_id)?)
        .bind(reason)
        .bind(expected_revision)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let revision: i64 = required(&row, "revision")?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    if target == "resolved" {
                        "alert_resolved"
                    } else {
                        "alert_acknowledged"
                    },
                    "alert",
                    alert_id,
                    revision,
                    json!({"from":current_state,"to":target,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(&alert_projection(&row)?, revision))
    }

    async fn list_alert_silences(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let rows = sqlx::query(
            "SELECT id,fingerprint_pattern,reason,starts_at::text AS starts_at,expires_at::text AS expires_at, \
                    created_by,revision,created_at::text AS created_at, \
                    starts_at<=clock_timestamp() AND expires_at>clock_timestamp() AS active \
             FROM ops.alert_silence ORDER BY created_at DESC,id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .map(alert_silence_projection)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn create_alert_silence(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let command: AlertSilenceCreateCommand = deserialize_body(request)?;
        let pattern = command.fingerprint_pattern.trim();
        let reason = required_action_reason(Some(&command.reason))?;
        if pattern.is_empty() || pattern.len() > 512 || command.expires_at.len() > 128 {
            return Err(ManagementBackendError::InvalidInput);
        }
        if command.starts_at.as_ref().is_some_and(|value| value.len() > 128) {
            return Err(ManagementBackendError::InvalidInput);
        }
        let silence_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "INSERT INTO ops.alert_silence \
             (id,fingerprint_pattern,reason,starts_at,expires_at,created_by,revision,created_at) \
             SELECT $1,$2,$3,COALESCE($4::timestamptz,clock_timestamp()),$5::timestamptz,$6,1,clock_timestamp() \
             WHERE $5::timestamptz>COALESCE($4::timestamptz,clock_timestamp()) \
             RETURNING id,fingerprint_pattern,reason,starts_at::text AS starts_at,expires_at::text AS expires_at, \
              created_by,revision,created_at::text AS created_at, \
              starts_at<=clock_timestamp() AND expires_at>clock_timestamp() AS active",
        )
        .bind(silence_id)
        .bind(pattern)
        .bind(reason)
        .bind(command.starts_at.as_deref())
        .bind(&command.expires_at)
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::InvalidInput)?
        .ok_or(ManagementBackendError::InvalidInput)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "alert_silence_created",
                    "alert_silence",
                    silence_id,
                    1,
                    json!({"fingerprint_pattern":pattern,"expires_at":command.expires_at,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":alert_silence_projection(&row)?,"meta":{}}),
            etag: Some("\"rev-1\"".into()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: false,
        })
    }

    async fn get_alert_silence(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let row = sqlx::query(
            "SELECT id,fingerprint_pattern,reason,starts_at::text AS starts_at,expires_at::text AS expires_at, \
                    created_by,revision,created_at::text AS created_at, \
                    starts_at<=clock_timestamp() AND expires_at>clock_timestamp() AS active \
             FROM ops.alert_silence WHERE id=$1",
        )
        .bind(path_uuid(request, "id")?)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let revision: i64 = required(&row, "revision")?;
        Ok(single_response(&alert_silence_projection(&row)?, revision))
    }

    async fn end_alert_silence(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let command: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let silence_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command
            .expected_revision
            .is_some_and(|value| value != expected_revision)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let current = sqlx::query(
            "SELECT revision,expires_at>clock_timestamp() AS active FROM ops.alert_silence WHERE id=$1 FOR UPDATE",
        )
        .bind(silence_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        if required::<i64>(&current, "revision")? != expected_revision || !required::<bool>(&current, "active")? {
            return Err(ManagementBackendError::Precondition);
        }
        let row = sqlx::query(
            "UPDATE ops.alert_silence SET \
               expires_at=CASE WHEN starts_at<clock_timestamp() THEN clock_timestamp() ELSE starts_at+interval '1 microsecond' END, \
               revision=revision+1 WHERE id=$1 AND revision=$2 \
             RETURNING id,fingerprint_pattern,reason,starts_at::text AS starts_at,expires_at::text AS expires_at, \
              created_by,revision,created_at::text AS created_at,false AS active",
        )
        .bind(silence_id)
        .bind(expected_revision)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let revision: i64 = required(&row, "revision")?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "alert_silence_ended",
                    "alert_silence",
                    silence_id,
                    revision,
                    json!({"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(&alert_silence_projection(&row)?, revision))
    }

    async fn list_notification_channels(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let rows = sqlx::query(
            "SELECT d.id,d.kind_code,d.name,d.configuration,d.state_code,d.revision, \
                    d.secret_id IS NOT NULL AS secret_present,d.created_at::text AS created_at, \
                    d.updated_at::text AS updated_at, \
                    (SELECT count(*) FROM ops.notification_delivery x WHERE x.destination_id=d.id) AS delivery_count, \
                    (SELECT x.state_code FROM ops.notification_delivery x WHERE x.destination_id=d.id \
                     ORDER BY x.created_at DESC,x.id DESC LIMIT 1) AS last_delivery_state, \
                    (SELECT x.updated_at::text FROM ops.notification_delivery x WHERE x.destination_id=d.id \
                     ORDER BY x.created_at DESC,x.id DESC LIMIT 1) AS last_delivery_at \
             FROM ops.notification_destination d WHERE d.kind_code<>'inbox' \
             ORDER BY d.created_at DESC,d.id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .map(notification_channel_projection)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn create_notification_channel(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: NotificationChannelCreateCommand = deserialize_body(request)?;
        let name = command.name.trim();
        if name.is_empty() || name.len() > 128 || command.severities.is_empty() || command.severities.len() > 3 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let severities = command
            .severities
            .iter()
            .map(|value| value.trim())
            .collect::<BTreeSet<_>>();
        if severities.len() != command.severities.len()
            || severities
                .iter()
                .any(|value| !matches!(*value, "info" | "warning" | "critical"))
            || command.alert_types.len() > 100
            || command
                .alert_types
                .iter()
                .any(|value| value.trim().is_empty() || value.len() > 128)
            || command.group_ids.len() > 100
            || command.group_ids.iter().collect::<BTreeSet<_>>().len() != command.group_ids.len()
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let (kind, secret) = match command.provider {
            NotificationProviderCommand::Serverchan3 { send_key } => {
                let secret = SecretValue::new(send_key);
                crate::operations::serverchan3_target(secret.expose())
                    .map_err(|_| ManagementBackendError::InvalidInput)?;
                ("serverchan3", secret)
            }
        };
        let destination_id = Uuid::now_v7();
        let secret_id = Uuid::now_v7();
        let (aad, envelope) = self
            .encrypt_notification_secret(destination_id, secret_id, kind, &secret)
            .await?;
        let configuration = json!({
            "provider":{"kind":kind},
            "severities":command.severities,
            "alert_types":command.alert_types,
            "group_ids":command.group_ids,
            "send_recovery":command.send_recovery
        });
        let state = if command.enabled { "active" } else { "disabled" };
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_secret(&mut transaction, secret_id, &aad, &envelope).await?;
        let row = sqlx::query(
            "INSERT INTO ops.notification_destination \
             (id,kind_code,name,secret_id,configuration,state_code,revision,created_at,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,1,clock_timestamp(),clock_timestamp()) \
             RETURNING id,kind_code,name,configuration,state_code,revision,true AS secret_present, \
               created_at::text AS created_at,updated_at::text AS updated_at,0::bigint AS delivery_count, \
               NULL::text AS last_delivery_state,NULL::text AS last_delivery_at",
        )
        .bind(destination_id)
        .bind(kind)
        .bind(name)
        .bind(secret_id)
        .bind(configuration)
        .bind(state)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "notification_channel_created",
                    "notification_destination",
                    destination_id,
                    1,
                    json!({"kind":kind,"state":state,"name":name}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(ManagementBackendResponse {
            status: axum::http::StatusCode::CREATED,
            body: json!({"data":notification_channel_projection(&row)?,"meta":{}}),
            etag: Some("\"rev-1\"".into()),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: true,
        })
    }

    async fn test_notification_channel(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        require_platform_admin(principal)?;
        let command: NotificationChannelTestCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let destination_id = path_uuid(request, "id")?;
        let expected_revision = request_revision(request)?;
        if command.expected_revision != expected_revision {
            return Err(ManagementBackendError::Precondition);
        }
        let request_key = request
            .idempotency_key
            .as_deref()
            .ok_or(ManagementBackendError::InvalidInput)?;
        let dedupe_key = format!("notification-test:{destination_id}:{request_key}");
        if dedupe_key.len() > 512 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let delivery_id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let destination =
            sqlx::query("SELECT kind_code,state_code,revision FROM ops.notification_destination WHERE id=$1 FOR SHARE")
                .bind(destination_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .ok_or(ManagementBackendError::NotFound)?;
        if required::<i64>(&destination, "revision")? != expected_revision
            || required::<String>(&destination, "state_code")? != "active"
            || required::<String>(&destination, "kind_code")? != "serverchan3"
        {
            return Err(ManagementBackendError::Precondition);
        }
        let payload = json!({
            "title":"Super Gateway 通知渠道测试",
            "summary":"通知渠道已由管理员发起连通性测试。",
            "tags":["super-gateway","test"]
        });
        sqlx::query(
            "INSERT INTO ops.notification_delivery \
             (id,alert_id,destination_id,attempt_ordinal,state_code,response_code,next_attempt_at,created_at,delivered_at, \
              delivery_kind_code,dedupe_key,payload,last_outcome,attempt_count,updated_at) \
             VALUES ($1,NULL,$2,1,'pending',NULL,NULL,clock_timestamp(),NULL,'test',$3,$4,'{}'::jsonb,0,clock_timestamp())",
        )
        .bind(delivery_id)
        .bind(destination_id)
        .bind(&dedupe_key)
        .bind(payload)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let created_at: String = sqlx::query_scalar(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,run_after,lease_generation, \
              attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'notification_channel_test_v1',$2,'scheduled',1,$3,clock_timestamp(),0,0,5,clock_timestamp(),clock_timestamp()) \
             RETURNING created_at::text",
        )
        .bind(job_id)
        .bind(&dedupe_key)
        .bind(json!({
            "delivery_id":delivery_id,
            "destination_id":destination_id,
            "destination_revision":expected_revision
        }))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_job_created_history(&mut transaction, job_id, "notification_test_scheduled").await?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "notification_channel_test_scheduled",
                    "notification_destination",
                    destination_id,
                    expected_revision,
                    json!({"delivery_id":delivery_id,"job_id":job_id,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(async_job_response(
            job_id,
            "notification_channel_test_v1",
            "queued",
            &created_at,
        ))
    }

    async fn list_notifications(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let rows = sqlx::query(
            "SELECT id,alert_id,severity_code,title,summary,read_at::text AS read_at,created_at::text AS created_at \
             FROM ops.notification_inbox WHERE user_id=$1 ORDER BY created_at DESC,id DESC LIMIT 100",
        )
        .bind(parse_uuid(&principal.user_id)?)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .map(|row| {
                Ok(json!({
                    "id": required::<Uuid>(row,"id")?,
                    "alert_id": required::<Option<Uuid>>(row,"alert_id")?,
                    "severity": required::<String>(row,"severity_code")?,
                    "title": required::<String>(row,"title")?,
                    "summary": required::<String>(row,"summary")?,
                    "read_at": required::<Option<String>>(row,"read_at")?,
                    "created_at": required::<String>(row,"created_at")?
                }))
            })
            .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        Ok(list_response(&data))
    }

    async fn mark_notification_read(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let expected_revision = request_revision(request)?;
        let row = sqlx::query(
            "UPDATE ops.notification_inbox SET read_at=COALESCE(read_at,clock_timestamp()) \
             WHERE id=$1 AND user_id=$2 AND $3=CASE WHEN read_at IS NULL THEN 1 ELSE 2 END \
             RETURNING id,alert_id,severity_code,title,summary,read_at::text AS read_at,created_at::text AS created_at",
        )
        .bind(path_uuid(request, "id")?)
        .bind(parse_uuid(&principal.user_id)?)
        .bind(expected_revision)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        let data = json!({
            "id": required::<Uuid>(&row,"id")?,
            "alert_id": required::<Option<Uuid>>(&row,"alert_id")?,
            "severity": required::<String>(&row,"severity_code")?,
            "title": required::<String>(&row,"title")?,
            "summary": required::<String>(&row,"summary")?,
            "read_at": required::<String>(&row,"read_at")?,
            "created_at": required::<String>(&row,"created_at")?
        });
        Ok(single_response(&data, 2))
    }

    async fn mark_all_notifications_read(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let changed = sqlx::query(
            "UPDATE ops.notification_inbox SET read_at=clock_timestamp() WHERE user_id=$1 AND read_at IS NULL",
        )
        .bind(parse_uuid(&principal.user_id)?)
        .execute(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .rows_affected();
        Ok(ManagementBackendResponse::ok(
            json!({"data":{"updated_count":changed},"meta":{}}),
        ))
    }

    async fn list_jobs(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let rows = sqlx::query(
            "SELECT id,kind_code,state_code,run_after::text AS run_after,lease_generation,attempt_count,max_attempts, \
                    last_error_code,created_at::text AS created_at,updated_at::text AS updated_at, \
                    completed_at::text AS completed_at \
             FROM ops.durable_job ORDER BY created_at DESC,id DESC LIMIT 100",
        )
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(job_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn get_job(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let job_id = path_uuid(request, "id")?;
        let row = sqlx::query(
            "SELECT id,kind_code,state_code,run_after::text AS run_after,lease_generation,attempt_count,max_attempts, \
                    last_error_code,checkpoint,created_at::text AS created_at,updated_at::text AS updated_at, \
                    completed_at::text AS completed_at \
             FROM ops.durable_job WHERE id=$1",
        )
        .bind(job_id)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let history = sqlx::query(
            "SELECT from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at::text AS occurred_at \
             FROM ops.durable_job_history WHERE job_id=$1 ORDER BY occurred_at,id",
        )
        .bind(job_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .iter()
        .map(|item| {
            Ok(json!({
                "from_state": required::<Option<String>>(item,"from_state_code")?,
                "to_state": required::<String>(item,"to_state_code")?,
                "lease_generation": required::<i64>(item,"lease_generation")?,
                "outcome": required::<Option<String>>(item,"outcome_code")?,
                "detail": required::<Value>(item,"detail")?,
                "occurred_at": required::<String>(item,"occurred_at")?
            }))
        })
        .collect::<Result<Vec<_>, ManagementBackendError>>()?;
        let mut data = job_projection(&row)?;
        data["checkpoint"] = required::<Option<Value>>(&row, "checkpoint")?.unwrap_or(Value::Null);
        data["history"] = Value::Array(history);
        let revision = required::<i64>(&row, "lease_generation")?.saturating_add(1);
        Ok(single_response(&data, revision))
    }

    async fn cancel_job(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if principal.role != ManagementRole::PlatformAdmin {
            return Err(ManagementBackendError::NotFound);
        }
        let command: ReasonActionCommand = deserialize_body(request)?;
        let reason = required_action_reason(Some(&command.reason))?;
        let job_id = path_uuid(request, "id")?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "SELECT kind_code,state_code,lease_generation,payload FROM ops.durable_job WHERE id=$1 FOR UPDATE",
        )
        .bind(job_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::NotFound)?;
        let kind = required::<String>(&row, "kind_code")?;
        let state = required::<String>(&row, "state_code")?;
        let generation = required::<i64>(&row, "lease_generation")?;
        let payload = required::<Value>(&row, "payload")?;
        if request_revision(request)? != generation.saturating_add(1)
            || command
                .expected_revision
                .is_some_and(|revision| revision != generation.saturating_add(1))
            || !matches!(state.as_str(), "scheduled" | "retry_wait")
            || !job_kind_is_cancellable(&kind)
        {
            return Err(ManagementBackendError::Precondition);
        }
        let cancelled = sqlx::query(
            "UPDATE ops.durable_job SET state_code='cancelled',lease_owner=NULL,lease_expires_at=NULL, \
               updated_at=clock_timestamp(),completed_at=clock_timestamp() \
             WHERE id=$1 AND state_code=$2 AND lease_generation=$3",
        )
        .bind(job_id)
        .bind(&state)
        .bind(generation)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if cancelled.rows_affected() != 1 {
            return Err(ManagementBackendError::Precondition);
        }
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,$3,'cancelled',$4,'cancelled',jsonb_build_object('reason',$5),clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(&state)
        .bind(generation)
        .bind(reason)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        cancel_job_projection(&mut transaction, &kind, job_id, &payload).await?;
        self.storage
            .append_audit_outbox_in(
                &mut transaction,
                &management_audit(
                    principal,
                    "durable_job_cancelled",
                    "durable_job",
                    job_id,
                    generation.saturating_add(1),
                    json!({"kind":kind,"from_state":state,"reason":reason}),
                )?,
            )
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(
            &json!({"id":job_id,"kind":kind,"state":"cancelled","lease_generation":generation}),
            generation.saturating_add(1),
        ))
    }

    async fn list_audit_events(
        &self,
        principal: &ManagementPrincipal,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let user_id = parse_uuid(&principal.user_id)?;
        let rows = sqlx::query(
            "SELECT event_id,event_day::text AS event_day,daily_sequence,actor_type_code,actor_id,action_code, \
                    object_type_code,object_id,outcome_code,canonical_redacted_event,occurred_at::text AS occurred_at \
             FROM security.audit_event event \
             WHERE $1 OR event.actor_id=$2 OR (event.object_type_code='user' AND event.object_id=$2::text) \
                OR EXISTS (SELECT 1 FROM iam.platform_key key \
                           WHERE key.owner_user_id=$2 AND \
                             ((event.object_type_code='platform_key' AND event.object_id=key.id::text) \
                               OR (event.actor_type_code='platform_key' AND event.actor_id=key.id))) \
             ORDER BY occurred_at DESC,event_id DESC LIMIT 100",
        )
        .bind(principal.role == ManagementRole::PlatformAdmin)
        .bind(user_id)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows.iter().map(audit_projection).collect::<Result<Vec<_>, _>>()?;
        Ok(list_response(&data))
    }

    async fn begin_idempotency(
        &self,
        principal: Option<&ManagementPrincipal>,
        request: &ManagementRequest,
    ) -> Result<IdempotencyState, ManagementBackendError> {
        let Some(principal) = principal else {
            return Ok(IdempotencyState::Bypassed);
        };
        let Some(key) = request.idempotency_key.as_deref() else {
            return Ok(IdempotencyState::Bypassed);
        };
        if !idempotency_cacheable(request) {
            return Ok(IdempotencyState::Bypassed);
        }
        let actor_id = parse_uuid(&principal.user_id)?;
        let mut bytes = request.method.as_str().as_bytes().to_vec();
        bytes.extend_from_slice(request.path.as_bytes());
        bytes.extend_from_slice(&serde_json::to_vec(&request.body).map_err(|_| ManagementBackendError::InvalidInput)?);
        let digest = lookup_digest(&self.session_digest_key, &SecretBytes::new(bytes))
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let id = Uuid::now_v7();
        let inserted = sqlx::query(
            "INSERT INTO iam.api_idempotency_record \
             (id,actor_type_code,actor_id,method,normalized_path,idempotency_key,request_digest,created_at,expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,clock_timestamp(),clock_timestamp()+interval '24 hours') \
             ON CONFLICT (actor_type_code,actor_id,method,normalized_path,idempotency_key) DO NOTHING RETURNING id",
        )
        .bind(id)
        .bind(role_code(principal.role))
        .bind(actor_id)
        .bind(request.method.as_str())
        .bind(request.path.as_ref())
        .bind(key)
        .bind(digest.as_slice())
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        if inserted.is_some() {
            return Ok(IdempotencyState::New(id));
        }
        let row = sqlx::query(
            "SELECT request_digest,result_status,result_reference FROM iam.api_idempotency_record \
             WHERE actor_type_code=$1 AND actor_id=$2 AND method=$3 AND normalized_path=$4 AND idempotency_key=$5 \
               AND expires_at>clock_timestamp()",
        )
        .bind(role_code(principal.role))
        .bind(actor_id)
        .bind(request.method.as_str())
        .bind(request.path.as_ref())
        .bind(key)
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .ok_or(ManagementBackendError::Precondition)?;
        if required::<Vec<u8>>(&row, "request_digest")? != digest {
            return Err(ManagementBackendError::Precondition);
        }
        let status = required::<Option<i32>>(&row, "result_status")?.ok_or(ManagementBackendError::Precondition)?;
        let reference =
            required::<Option<Value>>(&row, "result_reference")?.ok_or(ManagementBackendError::Precondition)?;
        let status = u16::try_from(status)
            .ok()
            .and_then(|value| axum::http::StatusCode::from_u16(value).ok())
            .ok_or(ManagementBackendError::Unavailable)?;
        Ok(IdempotencyState::Replay(ManagementBackendResponse {
            status,
            body: reference
                .get("body")
                .cloned()
                .ok_or(ManagementBackendError::Unavailable)?,
            etag: reference.get("etag").and_then(Value::as_str).map(Box::from),
            session_cookie: None,
            clear_session_cookie: false,
            no_store: reference.get("no_store").and_then(Value::as_bool).unwrap_or(false),
        }))
    }

    async fn finish_idempotency(
        &self,
        state: IdempotencyState,
        result: &Result<ManagementBackendResponse, ManagementBackendError>,
    ) -> Result<(), ManagementBackendError> {
        let IdempotencyState::New(id) = state else {
            return Ok(());
        };
        match result {
            Ok(response) => {
                sqlx::query(
                    "UPDATE iam.api_idempotency_record SET result_status=$2,result_reference=$3 WHERE id=$1 AND result_status IS NULL",
                )
                .bind(id)
                .bind(i32::from(response.status.as_u16()))
                .bind(json!({"body":response.body,"etag":response.etag,"no_store":response.no_store}))
                .execute(&self.storage.pool())
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            }
            Err(_) => {
                sqlx::query("DELETE FROM iam.api_idempotency_record WHERE id=$1 AND result_status IS NULL")
                    .bind(id)
                    .execute(&self.storage.pool())
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?;
            }
        }
        Ok(())
    }

    fn system_status(&self) -> ManagementBackendResponse {
        let readiness = self.readiness.internal_snapshot();
        let metrics = self.data_metrics.snapshot();
        ManagementBackendResponse::ok(json!({
            "data": {
                "id": "local-instance",
                "readiness": readiness,
                "metrics": {
                    "accepted": metrics.accepted,
                    "response_committed": metrics.response_committed,
                    "completed": metrics.completed,
                    "client_disconnected": metrics.client_disconnected,
                    "client_write_timeout": metrics.client_write_timeout,
                    "upstream_body_error": metrics.upstream_body_error,
                    "delivered_bytes": metrics.delivered_bytes
                }
            },
            "meta": {}
        }))
    }
}

#[async_trait]
impl ManagementBackend for PgManagementBackend {
    async fn resolve_session(
        &self,
        token: &SecretValue,
    ) -> Result<Option<ManagementPrincipal>, ManagementBackendError> {
        let digest = self.token_digest(token)?;
        let row = sqlx::query(
            "SELECT s.id,s.user_id,s.mfa_verified,u.role_code,u.status_code,p.force_change \
             FROM iam.management_session s JOIN iam.user_account u ON u.id=s.user_id \
             JOIN iam.password_credential p ON p.id=u.password_credential_id \
             WHERE s.token_digest=$1 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() \
               AND s.last_seen_at>clock_timestamp()-interval '30 minutes' AND u.status_code NOT IN ('disabled','archived','locked')",
        )
        .bind(digest.as_slice())
        .fetch_optional(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let Some(row) = row else { return Ok(None) };
        let session_id: Uuid = row.try_get("id").map_err(|_| ManagementBackendError::Unavailable)?;
        let user_id: Uuid = row
            .try_get("user_id")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let role: String = row
            .try_get("role_code")
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let role = parse_role(&role)?;
        sqlx::query(
            "UPDATE iam.management_session SET last_seen_at=clock_timestamp() \
             WHERE id=$1 AND last_seen_at<clock_timestamp()-interval '1 minute'",
        )
        .bind(session_id)
        .execute(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(Some(ManagementPrincipal {
            user_id: user_id.to_string().into_boxed_str(),
            session_id: session_id.to_string().into_boxed_str(),
            role,
            csrf_token: self.csrf_token(token)?,
            mfa_verified: row
                .try_get("mfa_verified")
                .map_err(|_| ManagementBackendError::Unavailable)?,
            password_change_required: row
                .try_get("force_change")
                .map_err(|_| ManagementBackendError::Unavailable)?,
        }))
    }

    async fn execute(
        &self,
        principal: Option<&ManagementPrincipal>,
        request: ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        if !self.integrity_guard.healthy() && high_risk_management_operation(&request) {
            return Err(ManagementBackendError::Unavailable);
        }
        let idempotency = match self.begin_idempotency(principal, &request).await? {
            IdempotencyState::Replay(response) => return Ok(response),
            state => state,
        };
        let result = match request.operation_id.as_ref() {
            "postAuthLogin" => self.login(&request).await,
            "getAuthMe" => Ok(Self::auth_me(required_principal(principal)?)),
            "getAuthSessions" => self.list_sessions(required_principal(principal)?).await,
            "deleteAuthSession" | "deleteAuthSessionsById" => {
                self.revoke_session(required_principal(principal)?, &request).await
            }
            "postAuthMfaEnrollments" => self.enroll_mfa(required_principal(principal)?).await,
            "postAuthMfaEnrollmentsByIdConfirm" => {
                self.verify_mfa(required_principal(principal)?, &request, true).await
            }
            "postAuthMfaVerify" => self.verify_mfa(required_principal(principal)?, &request, false).await,
            "postAuthPasswordChange" => self.change_password(required_principal(principal)?, &request).await,
            "postAuthStepUp" => self.step_up(required_principal(principal)?, &request).await,
            "getApprovalCases" => self.list_approvals().await,
            "postApprovalCases" => self.create_approval(required_principal(principal)?, &request).await,
            "getApprovalCasesById" => self.get_approval(&request).await,
            "postApprovalCasesByIdApprove" => {
                self.decide_approval(required_principal(principal)?, &request, "approve")
                    .await
            }
            "postApprovalCasesByIdReject" => {
                self.decide_approval(required_principal(principal)?, &request, "reject")
                    .await
            }
            "postApprovalCasesByIdCancel" => self.cancel_approval(required_principal(principal)?, &request).await,
            "postContentAuditSearchSessions" => {
                self.create_content_audit_search_session(required_principal(principal)?, &request)
                    .await
            }
            "getContentAuditSearchSessionsByIdRecords" => {
                self.list_content_audit_search_records(required_principal(principal)?, &request)
                    .await
            }
            "getContentAuditRecordsById" => {
                self.get_content_audit_record(required_principal(principal)?, &request)
                    .await
            }
            "postContentAuditRecordsByIdExport" => {
                self.create_content_audit_export(required_principal(principal)?, &request)
                    .await
            }
            "getContentAuditLegalHolds" => self.list_legal_holds().await,
            "getContentAuditLegalHoldsById" => self.get_legal_hold(&request).await,
            "postContentAuditLegalHolds" => self.create_legal_hold(required_principal(principal)?, &request).await,
            "postContentAuditLegalHoldsByIdReview" => {
                self.legal_hold_action(required_principal(principal)?, &request, false)
                    .await
            }
            "postContentAuditLegalHoldsByIdRelease" => {
                self.legal_hold_action(required_principal(principal)?, &request, true)
                    .await
            }
            "postContentAuditPurgeJobs" => {
                self.create_content_purge_job(required_principal(principal)?, &request)
                    .await
            }
            "postOperationsKeyRotationJobs" => {
                self.create_business_key_rotation_job(required_principal(principal)?, &request)
                    .await
            }
            "postOperationsKeyLifecycleJobs" => {
                self.create_business_key_lifecycle_job(required_principal(principal)?, &request)
                    .await
            }
            "postOperationsBackupJobs" => self.create_backup_job(required_principal(principal)?, &request).await,
            "postOperationsUpgradeChecks" => {
                self.create_upgrade_check(required_principal(principal)?, &request)
                    .await
            }
            "getOperationsUpgradeChecks" => self.list_upgrade_checks(required_principal(principal)?, &request).await,
            "getOperationsBackupRuns" => self.list_backup_runs(required_principal(principal)?).await,
            "getOperationsBackupRunsById" => self.get_backup_run(required_principal(principal)?, &request).await,
            "postOperationsRestoreValidations" => {
                self.create_restore_operation(required_principal(principal)?, &request, "manifest_validation")
                    .await
            }
            "getOperationsRestoreValidations" => {
                self.list_restore_operations(required_principal(principal)?, "manifest_validation")
                    .await
            }
            "getOperationsRestoreValidationsById" => {
                self.get_restore_operation(required_principal(principal)?, &request, "manifest_validation")
                    .await
            }
            "postOperationsDrills" => {
                self.create_restore_operation(required_principal(principal)?, &request, "full_restore_drill")
                    .await
            }
            "getOperationsDrills" => {
                self.list_restore_operations(required_principal(principal)?, "full_restore_drill")
                    .await
            }
            "getOperationsDrillsById" => {
                self.get_restore_operation(required_principal(principal)?, &request, "full_restore_drill")
                    .await
            }
            "getSystemStatus" | "getDashboardSummary" => Ok(self.system_status()),
            "getUsers" => self.list_users().await,
            "postUsers" => self.create_user(required_principal(principal)?, &request).await,
            "getUsersById" => self.get_user(&request).await,
            "patchUsersById" => self.patch_user(&request).await,
            "postUsersByIdDisable" => self.user_lifecycle(&request, "disable").await,
            "postUsersByIdArchive" => self.user_lifecycle(&request, "archive").await,
            "postUsersByIdReactivate" => self.user_lifecycle(&request, "reactivate").await,
            "postUsersByIdUnlock" => self.user_lifecycle(&request, "unlock").await,
            "postUsersByIdSessionsRevokeAll" => {
                self.revoke_all_user_sessions(required_principal(principal)?, &request)
                    .await
            }
            "getUsersByIdSessions" => self.list_user_sessions(required_principal(principal)?, &request).await,
            "getPlatformKeys" => self.list_platform_keys(required_principal(principal)?).await,
            "postPlatformKeys" => self.create_platform_key(required_principal(principal)?, &request).await,
            "getPlatformKeysById" => self.get_platform_key(required_principal(principal)?, &request).await,
            "patchPlatformKeysById" => self.patch_platform_key(required_principal(principal)?, &request).await,
            "postPlatformKeysByIdReveal" => self.reveal_platform_key(required_principal(principal)?, &request).await,
            "postPlatformKeysByIdDisable" => {
                self.platform_key_lifecycle(required_principal(principal)?, &request, "disabled")
                    .await
            }
            "postPlatformKeysByIdReactivate" => {
                self.platform_key_lifecycle(required_principal(principal)?, &request, "active")
                    .await
            }
            "postPlatformKeysByIdRevoke" => {
                self.platform_key_lifecycle(required_principal(principal)?, &request, "revoked")
                    .await
            }
            "getPlatformKeysByIdAuditEvents" => {
                self.list_platform_key_audit_events(required_principal(principal)?, &request)
                    .await
            }
            "getPlatformKeysByIdClientConfig" => {
                self.get_platform_key_client_config(required_principal(principal)?, &request)
                    .await
            }
            "getPlatformKeysByIdConfigVersions" => {
                self.list_platform_key_config_versions(required_principal(principal)?, &request)
                    .await
            }
            "getGroups" => self.list_groups().await,
            "postGroups" => self.create_group(required_principal(principal)?, &request).await,
            "getGroupsById" => self.get_group(&request).await,
            "getGroupsByIdCapacity" => self.get_group_capacity(&request).await,
            "getGroupsByIdConfigVersions" => self.group_config_versions(&request, None).await,
            "postGroupsByIdConfigVersions" => {
                self.create_group_config_version(required_principal(principal)?, &request)
                    .await
            }
            "getGroupsByIdConfigVersionsByVersion" => {
                self.group_config_versions(&request, Some(path_i64(&request, "version")?))
                    .await
            }
            "postGroupsByIdConfigVersionsByVersionValidate" => {
                self.transition_group_config_version(required_principal(principal)?, &request, "validate")
                    .await
            }
            "postGroupsByIdConfigVersionsByVersionPublishShadow" => {
                self.transition_group_config_version(required_principal(principal)?, &request, "publish_shadow")
                    .await
            }
            "postGroupsByIdConfigVersionsByVersionPromoteCanary" => {
                self.transition_group_config_version(required_principal(principal)?, &request, "promote_canary")
                    .await
            }
            "postGroupsByIdConfigVersionsByVersionSimulate" => self.simulate_group_config_version(&request).await,
            "postGroupsByIdConfigVersionsByVersionActivate" => {
                self.activate_group_config_version(required_principal(principal)?, &request, false)
                    .await
            }
            "postGroupsByIdRollbackConfig" => {
                self.activate_group_config_version(required_principal(principal)?, &request, true)
                    .await
            }
            "patchGroupsById" => {
                self.patch_group_metadata(required_principal(principal)?, &request)
                    .await
            }
            "getGroupsByIdCredentials" => self.list_group_credentials(&request).await,
            "postGroupsByIdDisable" => {
                self.group_lifecycle(required_principal(principal)?, &request, "disabled")
                    .await
            }
            "postGroupsByIdArchive" => {
                self.group_lifecycle(required_principal(principal)?, &request, "archived")
                    .await
            }
            "postGroupsByIdReactivate" => {
                self.group_lifecycle(required_principal(principal)?, &request, "active")
                    .await
            }
            "getCredentials" => self.list_credentials().await,
            "getCredentialsById" => self.get_credential(&request).await,
            "patchCredentialsByIdSchedulingConfig" => {
                self.patch_credential_scheduling_config(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialsByIdMigrateGroup" => {
                self.migrate_credential_group(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialsByIdRebindEgress" => {
                self.rebind_credential_egress(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialsByIdMigrateProfileCohort" => {
                self.migrate_credential_profile_cohort(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialsByIdRebuildDeviceIdentity" => {
                self.rebuild_credential_device_identity(required_principal(principal)?, &request)
                    .await
            }
            "getCredentialsByIdMaintenanceOperations" => self.list_credential_maintenance(&request).await,
            "getCredentialsByIdReauthStrategy" => self.get_credential_reauth_strategy(&request).await,
            "getCredentialsByIdBrowserOperations" => {
                self.list_credential_browser_operations(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialsByIdBrowserOperationsByOperationIdCancel" => {
                self.cancel_credential_browser_operation(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialsByIdReauthStrategyDisable" => {
                self.disable_credential_reauth_strategy(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialsByIdReauthStrategyInitialize" => {
                self.schedule_managed_browser_strategy(required_principal(principal)?, &request, "initialize")
                    .await
            }
            "postCredentialsByIdReauthStrategyReactivate" => {
                self.schedule_managed_browser_strategy(required_principal(principal)?, &request, "reactivate")
                    .await
            }
            "postCredentialsByIdDisable" => {
                self.credential_lifecycle(required_principal(principal)?, &request, "disable")
                    .await
            }
            "postCredentialsByIdReactivate" => {
                self.credential_lifecycle(required_principal(principal)?, &request, "reactivate")
                    .await
            }
            "postCredentialsByIdRevoke" => {
                self.credential_lifecycle(required_principal(principal)?, &request, "revoke")
                    .await
            }
            "postCredentialsByIdBeginRecovery" => {
                self.begin_credential_recovery(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialsByIdClearCooldown" => {
                self.clear_credential_cooldown(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialsByIdArchive" => self.archive_credential(required_principal(principal)?, &request).await,
            "postCredentialsByIdRefreshToken" => {
                self.refresh_credential_token(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialsByIdRefreshPlan" => {
                self.refresh_credential_plan(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialEnrollments" => {
                self.create_credential_enrollment(required_principal(principal)?, &request)
                    .await
            }
            "getCredentialEnrollmentsById" => self.get_credential_enrollment(&request).await,
            "postCredentialEnrollmentsByIdCancel" => self.cancel_credential_enrollment(&request).await,
            "postCredentialEnrollmentsByIdSubmitMaterial" => {
                self.submit_credential_material(required_principal(principal)?, &request)
                    .await
            }
            "postCredentialEnrollmentsByIdCompleteCallback" => {
                self.complete_credential_oauth_callback(required_principal(principal)?, &request)
                    .await
            }
            "getRequests" => self.list_requests(required_principal(principal)?).await,
            "getRequestsById" => self.get_request(required_principal(principal)?, &request).await,
            "getRequestsByIdAttempts" => {
                self.list_request_attempts(required_principal(principal)?, &request)
                    .await
            }
            "getUsageSummary" => self.usage_summary(required_principal(principal)?).await,
            "getUsageTimeseries" => self.usage_timeseries(required_principal(principal)?).await,
            "postExports" => self.create_usage_export(required_principal(principal)?, &request).await,
            "getExportsById" => self.get_usage_export(required_principal(principal)?, &request).await,
            "getCredentialProfiles" => self.list_credential_profiles(None).await,
            "getCredentialProfilesById" => self.list_credential_profiles(Some(path_uuid(&request, "id")?)).await,
            "getProxies" => self.list_proxies(None).await,
            "postProxies" => self.create_proxy(required_principal(principal)?, &request).await,
            "getProxiesById" => self.list_proxies(Some(path_uuid(&request, "id")?)).await,
            "patchProxiesById" => self.patch_proxy(required_principal(principal)?, &request).await,
            "getProxiesByIdBindings" => self.list_proxy_bindings(&request).await,
            "postProxiesByIdProbe" => self.enqueue_proxy_probe(required_principal(principal)?, &request).await,
            "postProxiesByIdDisable" => {
                self.proxy_lifecycle(required_principal(principal)?, &request, "disable")
                    .await
            }
            "postProxiesByIdReactivate" => {
                self.proxy_lifecycle(required_principal(principal)?, &request, "reactivate")
                    .await
            }
            "postProxiesByIdArchive" => {
                self.proxy_lifecycle(required_principal(principal)?, &request, "archive")
                    .await
            }
            "postProxiesByIdReplaceSecret" => {
                self.replace_proxy_secret(required_principal(principal)?, &request)
                    .await
            }
            "getEgressBindings" => self.list_egress_bindings(None).await,
            "getEgressBindingsById" => self.list_egress_bindings(Some(path_uuid(&request, "id")?)).await,
            "getEnvironmentArchetypes" => self.list_environment_archetypes(None).await,
            "getEnvironmentArchetypesById" => self.list_environment_archetypes(Some(path_uuid(&request, "id")?)).await,
            "postEnvironmentArchetypes" => {
                self.create_environment_archetype(required_principal(principal)?, &request)
                    .await
            }
            "postEnvironmentArchetypesByIdVerify" => {
                self.transition_environment_archetype(required_principal(principal)?, &request, "verify")
                    .await
            }
            "postEnvironmentArchetypesByIdPromoteCanary" => {
                self.transition_environment_archetype(required_principal(principal)?, &request, "promote_canary")
                    .await
            }
            "postEnvironmentArchetypesByIdActivate" => {
                self.transition_environment_archetype(required_principal(principal)?, &request, "activate")
                    .await
            }
            "postEnvironmentArchetypesByIdRetire" => {
                self.transition_environment_archetype(required_principal(principal)?, &request, "retire")
                    .await
            }
            "getTransportBundles" => self.list_transport_bundles().await,
            "postTransportBundles" => {
                self.create_transport_bundle(required_principal(principal)?, &request)
                    .await
            }
            "postTransportBundlesByIdVerify" => {
                self.verify_transport_bundle(required_principal(principal)?, &request)
                    .await
            }
            "postTransportBundlesByIdPromoteCanary" => {
                self.promote_transport_bundle_canary(required_principal(principal)?, &request)
                    .await
            }
            "postTransportBundlesByIdActivate" => {
                self.activate_transport_bundle(required_principal(principal)?, &request, false)
                    .await
            }
            "postTransportBundlesByIdRollback" => {
                self.activate_transport_bundle(required_principal(principal)?, &request, true)
                    .await
            }
            "getPlanMappingVersions" => self.list_plan_mapping_versions(None).await,
            "getPlanMappingVersionsById" => self.list_plan_mapping_versions(Some(path_uuid(&request, "id")?)).await,
            "postPlanMappingVersions" => {
                self.create_plan_mapping_version(required_principal(principal)?, &request)
                    .await
            }
            "postPlanMappingVersionsByIdValidate" => {
                self.validate_plan_mapping_version(required_principal(principal)?, &request)
                    .await
            }
            "postPlanMappingVersionsByIdActivate" | "postPlanMappingVersionsByIdRollback" => {
                self.activate_plan_mapping_version(required_principal(principal)?, &request)
                    .await
            }
            "postPlanMappingVersionsByIdRecompute" => {
                self.enqueue_plan_mapping_recompute(required_principal(principal)?, &request)
                    .await
            }
            "getArtifactsById" => self.get_artifact(&request).await,
            "getModels" => self.list_models().await,
            "getModelsById" => self.get_model(&request).await,
            "postModelsRefresh" => self.refresh_models(required_principal(principal)?, &request).await,
            "postModelsByIdApprove" => {
                self.model_lifecycle(required_principal(principal)?, &request, "approve")
                    .await
            }
            "postModelsByIdDeprecate" => {
                self.model_lifecycle(required_principal(principal)?, &request, "deprecate")
                    .await
            }
            "postModelsByIdDisable" => {
                self.model_lifecycle(required_principal(principal)?, &request, "disable")
                    .await
            }
            "getCapabilityVersions" => self.list_capability_versions().await,
            "postCapabilityVersions" => {
                self.create_capability_version(required_principal(principal)?, &request)
                    .await
            }
            "postCapabilityVersionsByIdValidate" => self.validate_capability_version(&request).await,
            "postCapabilityVersionsByIdActivate" => {
                self.activate_capability_version(required_principal(principal)?, &request)
                    .await
            }
            "getPriceVersions" => self.list_price_versions().await,
            "postPriceVersions" => {
                self.create_price_version(required_principal(principal)?, &request)
                    .await
            }
            "getBackgroundCatalogVersions" => self.list_typed_artifacts("background_catalog").await,
            "postBackgroundCatalogVersions" => {
                self.create_typed_artifact(required_principal(principal)?, &request, "background_catalog")
                    .await
            }
            "postBackgroundCatalogVersionsByIdValidate" => {
                self.validate_policy_artifact(required_principal(principal)?, &request, "background_catalog")
                    .await
            }
            "postBackgroundCatalogVersionsByIdPublishShadow" => {
                self.publish_policy_artifact_shadow(required_principal(principal)?, &request, "background_catalog")
                    .await
            }
            "postBackgroundCatalogVersionsByIdActivate" => {
                self.activate_policy_artifact(required_principal(principal)?, &request, "background_catalog", false)
                    .await
            }
            "postBackgroundCatalogVersionsByIdRollback" => {
                self.activate_policy_artifact(required_principal(principal)?, &request, "background_catalog", true)
                    .await
            }
            "getEnforcementVersions" => self.list_typed_artifacts("enforcement").await,
            "postEnforcementVersions" => {
                self.create_typed_artifact(required_principal(principal)?, &request, "enforcement")
                    .await
            }
            "postEnforcementVersionsByIdValidate" => {
                self.validate_policy_artifact(required_principal(principal)?, &request, "enforcement")
                    .await
            }
            "postEnforcementVersionsByIdPublishShadow" => {
                self.publish_policy_artifact_shadow(required_principal(principal)?, &request, "enforcement")
                    .await
            }
            "postEnforcementVersionsByIdActivate" => {
                self.activate_policy_artifact(required_principal(principal)?, &request, "enforcement", false)
                    .await
            }
            "postEnforcementVersionsByIdRollback" => {
                self.activate_policy_artifact(required_principal(principal)?, &request, "enforcement", true)
                    .await
            }
            "getRulesets" => self.list_typed_artifacts("ruleset").await,
            "postRulesets" => self.create_ruleset(required_principal(principal)?, &request).await,
            "postRulesetsByIdValidate" => self.validate_ruleset(&request).await,
            "postRulesetsByIdSimulate" => self.simulate_ruleset(&request).await,
            "postRulesetsByIdActivate" => self.activate_ruleset(required_principal(principal)?, &request).await,
            "getAlerts" => self.list_alerts().await,
            "postAlertsByIdAcknowledge" => {
                self.alert_action(required_principal(principal)?, &request, "acknowledged")
                    .await
            }
            "postAlertsByIdResolve" => {
                self.alert_action(required_principal(principal)?, &request, "resolved")
                    .await
            }
            "getAlertSilences" => self.list_alert_silences(required_principal(principal)?).await,
            "postAlertSilences" => {
                self.create_alert_silence(required_principal(principal)?, &request)
                    .await
            }
            "getAlertSilencesById" => self.get_alert_silence(required_principal(principal)?, &request).await,
            "postAlertSilencesByIdEnd" => self.end_alert_silence(required_principal(principal)?, &request).await,
            "getNotificationChannels" => self.list_notification_channels(required_principal(principal)?).await,
            "postNotificationChannels" => {
                self.create_notification_channel(required_principal(principal)?, &request)
                    .await
            }
            "postNotificationChannelsByIdTest" => {
                self.test_notification_channel(required_principal(principal)?, &request)
                    .await
            }
            "getNotifications" => self.list_notifications(required_principal(principal)?).await,
            "postNotificationsByIdRead" => {
                self.mark_notification_read(required_principal(principal)?, &request)
                    .await
            }
            "postNotificationsReadAll" => self.mark_all_notifications_read(required_principal(principal)?).await,
            "getOperationsJobs" => self.list_jobs(required_principal(principal)?).await,
            "getOperationsJobsById" => self.get_job(required_principal(principal)?, &request).await,
            "postOperationsJobsByIdCancel" => self.cancel_job(required_principal(principal)?, &request).await,
            "getAuditEvents" => self.list_audit_events(required_principal(principal)?).await,
            _ => Err(ManagementBackendError::Unavailable),
        };
        self.finish_idempotency(idempotency, &result).await?;
        result
    }

    async fn execute_download(
        &self,
        principal: Option<&ManagementPrincipal>,
        request: ManagementRequest,
    ) -> Result<ManagementDownload, ManagementBackendError> {
        if request.operation_id.as_ref() != "getExportsByIdDownload" {
            return Err(ManagementBackendError::NotFound);
        }
        self.download_usage_export(required_principal(principal)?, &request)
            .await
    }
}

enum IdempotencyState {
    Bypassed,
    New(Uuid),
    Replay(ManagementBackendResponse),
}

fn idempotency_cacheable(request: &ManagementRequest) -> bool {
    request.method != axum::http::Method::GET
        && request.method != axum::http::Method::HEAD
        && !matches!(
            request.operation_id.as_ref(),
            "postAuthLogin"
                | "postAuthMfaEnrollments"
                | "postAuthMfaEnrollmentsByIdConfirm"
                | "postAuthMfaVerify"
                | "postAuthPasswordChange"
                | "postAuthStepUp"
                | "postPlatformKeysByIdReveal"
        )
}

#[derive(Deserialize)]
struct LoginCommand {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct TotpCommand {
    code: String,
}

#[derive(Deserialize)]
struct PasswordChangeCommand {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct StepUpCommand {
    purpose: String,
    current_password: String,
    totp_code: String,
}

#[derive(Deserialize)]
struct ApprovalCreateCommand {
    kind: String,
    scope: Value,
    reason: String,
    action_snapshot_digest: String,
    step_up_grant_id: String,
}

#[derive(Deserialize)]
struct ApprovalDecisionCommand {
    reason: String,
    step_up_grant_id: String,
}

fn high_risk_management_operation(request: &ManagementRequest) -> bool {
    matches!(
        request.operation_id.as_ref(),
        "getContentAuditSearchSessionsByIdRecords" | "getContentAuditRecordsById"
    ) || (request.method != axum::http::Method::GET
        && matches!(
            request.operation_id.as_ref(),
            "postApprovalCases"
                | "postApprovalCasesByIdApprove"
                | "postApprovalCasesByIdReject"
                | "postApprovalCasesByIdCancel"
                | "postPlatformKeys"
                | "postPlatformKeysByIdReveal"
                | "postPlatformKeysByIdDisable"
                | "postPlatformKeysByIdReactivate"
                | "postPlatformKeysByIdRevoke"
                | "patchPlatformKeysById"
                | "postUsersByIdSessionsRevokeAll"
                | "postCredentialsByIdDisable"
                | "postCredentialsByIdReactivate"
                | "postCredentialsByIdRevoke"
                | "postCredentialsByIdClearCooldown"
                | "postCredentialsByIdArchive"
                | "postCredentialsByIdRefreshToken"
                | "postCredentialsByIdRefreshPlan"
                | "patchCredentialsByIdSchedulingConfig"
                | "postCredentialsByIdMigrateGroup"
                | "postCredentialsByIdRebindEgress"
                | "postCredentialsByIdMigrateProfileCohort"
                | "postCredentialsByIdRebuildDeviceIdentity"
                | "postCredentialsByIdBrowserOperationsByOperationIdCancel"
                | "postCredentialsByIdReauthStrategyDisable"
                | "postCredentialsByIdReauthStrategyInitialize"
                | "postCredentialsByIdReauthStrategyReactivate"
                | "postContentAuditSearchSessions"
                | "postContentAuditRecordsByIdExport"
                | "postContentAuditLegalHolds"
                | "postContentAuditLegalHoldsByIdRelease"
                | "postContentAuditLegalHoldsByIdReview"
                | "postContentAuditPurgeJobs"
                | "postOperationsBackupJobs"
                | "postOperationsRestoreValidations"
                | "postOperationsDrills"
                | "postPlanMappingVersionsByIdActivate"
                | "postPlanMappingVersionsByIdRollback"
                | "postOperationsKeyRotationJobs"
                | "postOperationsKeyLifecycleJobs"
                | "postProxies"
                | "postProxiesByIdArchive"
                | "postProxiesByIdReplaceSecret"
                | "postAlertsByIdAcknowledge"
                | "postAlertsByIdResolve"
                | "postAlertSilences"
                | "postAlertSilencesByIdEnd"
                | "postNotificationChannels"
                | "postNotificationChannelsByIdTest"
                | "postModelsByIdApprove"
                | "postModelsRefresh"
                | "postModelsByIdDeprecate"
                | "postModelsByIdDisable"
                | "postCapabilityVersionsByIdActivate"
                | "postPriceVersions"
                | "postGroupsByIdConfigVersionsByVersionActivate"
                | "postGroupsByIdRollbackConfig"
                | "postRulesetsByIdActivate"
                | "postBackgroundCatalogVersionsByIdActivate"
                | "postBackgroundCatalogVersionsByIdRollback"
                | "postEnforcementVersionsByIdActivate"
                | "postEnforcementVersionsByIdRollback"
                | "postEnvironmentArchetypes"
                | "postEnvironmentArchetypesByIdVerify"
                | "postEnvironmentArchetypesByIdPromoteCanary"
                | "postEnvironmentArchetypesByIdActivate"
                | "postEnvironmentArchetypesByIdRetire"
                | "postTransportBundles"
                | "postTransportBundlesByIdVerify"
                | "postTransportBundlesByIdPromoteCanary"
                | "postTransportBundlesByIdActivate"
                | "postTransportBundlesByIdRollback"
        ))
}

#[derive(Deserialize)]
struct ApprovalCancelCommand {
    reason: String,
    expected_revision: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentAuditSearchCommand {
    approval_case_id: String,
    step_up_grant_id: String,
    reason: String,
    filters: ContentAuditSearchFilters,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContentAuditSearchFilters {
    request_id: Option<Uuid>,
    owner_user_id: Option<Uuid>,
    platform_key_id: Option<Uuid>,
    group_id: Option<Uuid>,
    attempt_id: Option<Uuid>,
    object_kind: Option<String>,
    created_from: Option<String>,
    created_to: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ContentAuditPageQuery {
    #[serde(rename = "page[size]")]
    page_size: Option<usize>,
    #[serde(rename = "page[after]")]
    page_after: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct ContentAuditRecordQuery {
    search_session_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentAuditExportCommand {
    search_session_id: Uuid,
    approval_case_id: Uuid,
    step_up_grant_id: Uuid,
    reason: String,
}

#[derive(Deserialize)]
struct LegalHoldCreateCommand {
    name: String,
    reason: String,
    approval_case_id: String,
    review_due_at: Option<String>,
    objects: Vec<LegalHoldObjectCommand>,
}

#[derive(Deserialize)]
struct LegalHoldObjectCommand {
    content_audit_object_id: String,
}

#[derive(Deserialize)]
struct LegalHoldActionCommand {
    approval_case_id: String,
    reason: String,
    expected_revision: i64,
}

#[derive(Deserialize)]
struct ContentPurgeCommand {
    approval_case_id: String,
    reason: String,
    object_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRotationCommand {
    approval_case_id: String,
    step_up_grant_id: String,
    reason: String,
    expected_key_version: i64,
    batch_size: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyLifecycleCommand {
    approval_case_id: String,
    step_up_grant_id: String,
    reason: String,
    key_version: i64,
    target_state: String,
    rotation_job_id: String,
    backup_run_id: String,
    restore_drill_id: String,
}

#[derive(Deserialize)]
struct BackupJobCommand {
    step_up_grant_id: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpgradeCheckCommand {
    reason: String,
    release_manifest: Value,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct UpgradeCheckQuery {
    page_size: Option<usize>,
    page_after: Option<String>,
}

#[derive(Deserialize)]
struct RestoreOperationCommand {
    backup_run_id: String,
    recovery_point: Option<String>,
    step_up_grant_id: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasonActionCommand {
    reason: String,
    expected_revision: Option<i64>,
}

#[derive(Deserialize)]
struct AlertSilenceCreateCommand {
    fingerprint_pattern: String,
    reason: String,
    starts_at: Option<String>,
    expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationChannelCreateCommand {
    name: String,
    enabled: bool,
    severities: Vec<String>,
    alert_types: Vec<String>,
    group_ids: Vec<Uuid>,
    send_recovery: bool,
    provider: NotificationProviderCommand,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum NotificationProviderCommand {
    Serverchan3 { send_key: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationChannelTestCommand {
    reason: String,
    expected_revision: i64,
}

#[derive(Deserialize)]
struct UserCreateCommand {
    username: String,
    display_name: String,
    email: String,
    role: String,
    temporary_password: String,
}

#[derive(Deserialize)]
struct UserPatchCommand {
    display_name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GroupCreateCommand {
    name: String,
}

#[derive(Deserialize, Serialize)]
struct GroupConfigCandidateCommand {
    accepted_client_classes: Vec<String>,
    fully_managed_required: bool,
    egress_mode: String,
    limits: GroupConfigLimitsCommand,
    credential_defaults: GroupCredentialDefaultsCommand,
    queue: GroupQueueCommand,
    timeouts: GroupTimeoutsCommand,
    content_audit: GroupContentAuditCommand,
}

#[derive(Deserialize, Serialize)]
struct GroupConfigLimitsCommand {
    concurrency: Option<u32>,
    messages_rpm: Option<u32>,
    messages_burst: Option<u32>,
}

#[derive(Deserialize, Serialize)]
struct GroupCredentialDefaultsCommand {
    concurrency: u32,
    messages_rpm: u32,
}

#[derive(Deserialize, Serialize)]
struct GroupQueueCommand {
    pre_upstream_timeout_ms: u64,
}

#[derive(Deserialize, Serialize)]
struct GroupTimeoutsCommand {
    upstream_connect_ms: u64,
    upstream_non_stream_total_ms: u64,
    upstream_stream_idle_ms: u64,
}

#[derive(Deserialize, Serialize)]
struct GroupContentAuditCommand {
    policy: String,
    retention_days: u16,
}

#[derive(Deserialize)]
struct GroupConfigRollbackCommand {
    target_version: i64,
    reason: String,
    expected_revision: Option<i64>,
    approval_case_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentArchetypeCreateCommand {
    name: String,
    schema_version: i64,
    archetype_id: Option<String>,
    payload: EnvironmentArchetypePayload,
    #[serde(default)]
    source_refs: Vec<String>,
    reason: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentArchetypePayload {
    os_family: String,
    architecture: String,
    os_build: String,
    client_family: String,
    runtime: String,
    runtime_version: String,
    client_version: String,
    profile_schema_version: u32,
    capture_cohort: String,
    protocol_profile: Value,
    evidence_set_id: Option<String>,
    capacity: EnvironmentArchetypeCapacity,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentArchetypeCapacity {
    max_credentials: u32,
    max_connections: u32,
    allocation_weight: u32,
    allocation_cohort: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportBundleCreateCommand {
    name: String,
    schema_version: i64,
    signed_envelope: Value,
    #[serde(default)]
    source_refs: Vec<String>,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportBundleActivateCommand {
    approval_case_id: String,
    step_up_grant_id: String,
    reason: String,
    expected_revision: Option<i64>,
}

#[derive(Deserialize)]
struct GroupPatchCommand {
    name: String,
}

#[derive(Default)]
enum PatchField<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}

fn deserialize_patch_field<'de, D, T>(deserializer: D) -> Result<PatchField<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(match Option::<T>::deserialize(deserializer)? {
        Some(value) => PatchField::Value(value),
        None => PatchField::Null,
    })
}

impl<T: Copy> PatchField<T> {
    fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    fn resolve_non_null(&self, current: T) -> Result<T, ManagementBackendError> {
        match self {
            Self::Missing => Ok(current),
            Self::Null => Err(ManagementBackendError::InvalidInput),
            Self::Value(value) => Ok(*value),
        }
    }
}

impl PatchField<i32> {
    fn resolve(&self, current: i32, inherited: i32) -> Result<i32, ManagementBackendError> {
        Ok(match self {
            Self::Missing => current,
            Self::Null => inherited,
            Self::Value(value) => *value,
        })
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct CredentialSchedulingPatchCommand {
    #[serde(default, deserialize_with = "deserialize_patch_field")]
    priority: PatchField<i32>,
    #[serde(default, deserialize_with = "deserialize_patch_field")]
    weight: PatchField<u32>,
    #[serde(default, deserialize_with = "deserialize_patch_field")]
    concurrency: PatchField<i32>,
    #[serde(default, deserialize_with = "deserialize_patch_field")]
    messages_rpm: PatchField<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialGroupMigrationCommand {
    target_group_id: Uuid,
    reason: String,
    expected_revision: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressRebindCommand {
    target: EgressRebindTarget,
    reason: String,
    expected_profile_epoch: i64,
    expected_egress_epoch: i64,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum EgressRebindTarget {
    Direct,
    Proxy { proxy_id: Uuid },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileCohortCommand {
    target_archetype_version_id: Uuid,
    target_capture_cohort: String,
    #[serde(default)]
    allow_explicit_rollback: bool,
    reason: String,
    expected_revision: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceIdentityRebuildCommand {
    approval_case_id: Uuid,
    reason: String,
    expected_revision: Option<i64>,
}

impl CredentialSchedulingPatchCommand {
    fn is_empty(&self) -> bool {
        matches!(self.priority, PatchField::Missing)
            && matches!(self.weight, PatchField::Missing)
            && matches!(self.concurrency, PatchField::Missing)
            && matches!(self.messages_rpm, PatchField::Missing)
    }
}

#[derive(Deserialize)]
struct PlanMappingCreateCommand {
    mapping: Value,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRefreshCommand {
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyCreateCommand {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    stability: String,
    max_active_credentials: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyPatchCommand {
    name: Option<String>,
    max_active_credentials: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyReplaceSecretCommand {
    username: String,
    password: String,
    step_up_grant_id: String,
    reason: String,
    expected_revision: Option<i64>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityCreateCommand {
    model_id: String,
    schema_version: i64,
    rules: Vec<CapabilityRule>,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityActionCommand {
    reason: Option<String>,
    expected_revision: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelLifecycleCommand {
    reason: String,
    expected_revision: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityPayload {
    #[allow(dead_code)]
    schema_version: Option<i64>,
    rules: Vec<CapabilityRule>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PriceVersionCreateCommand {
    effective_from: String,
    effective_to: Option<String>,
    currency: String,
    source_uri: Option<String>,
    entries: Vec<PriceEntryCommand>,
    reason: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PriceEntryCommand {
    model_id: String,
    input_per_million: String,
    output_per_million: String,
    cache_write_per_million: String,
    cache_read_per_million: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TypedArtifactCreateCommand {
    name: String,
    schema_version: i64,
    payload: Value,
    #[serde(default)]
    source_refs: Vec<String>,
    reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnforcementArtifactPayload {
    group_id: String,
    system: EnforcementSystemPayload,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnforcementSystemPayload {
    mode: String,
    platform_system_ref: Option<String>,
    content: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyArtifactActionCommand {
    reason: String,
    expected_revision: Option<i64>,
    approval_case_id: Option<Uuid>,
    #[serde(default)]
    samples: Vec<BackgroundCatalogSample>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackgroundCatalogSample {
    #[serde(default)]
    headers: BTreeMap<String, String>,
    body: Value,
    client_class: ClientClass,
    expected_entry_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTypedArtifactEnvelope {
    #[allow(dead_code)]
    name: String,
    payload: Value,
    #[serde(default)]
    #[allow(dead_code)]
    source_refs: Vec<String>,
}

enum CompiledPolicyArtifact {
    Background(BackgroundCatalog),
    Enforcement(EnforcementArtifactPayload),
}

fn validate_policy_artifact_payload(
    kind: &str,
    payload: &Value,
) -> Result<CompiledPolicyArtifact, ManagementBackendError> {
    match kind {
        "background_catalog" => {
            let document: BackgroundCatalogDocument =
                serde_json::from_value(payload.clone()).map_err(|_| ManagementBackendError::InvalidInput)?;
            let catalog = BackgroundCatalog::compile(document).map_err(|_| ManagementBackendError::InvalidInput)?;
            Ok(CompiledPolicyArtifact::Background(catalog))
        }
        "enforcement" => {
            let candidate: EnforcementArtifactPayload =
                serde_json::from_value(payload.clone()).map_err(|_| ManagementBackendError::InvalidInput)?;
            parse_input_uuid(&candidate.group_id)?;
            compile_enforcement_system(&candidate.system)?;
            Ok(CompiledPolicyArtifact::Enforcement(candidate))
        }
        _ => Err(ManagementBackendError::InvalidInput),
    }
}

fn compile_stored_policy_artifact(
    kind: &str,
    envelope: Value,
) -> Result<CompiledPolicyArtifact, ManagementBackendError> {
    let envelope: StoredTypedArtifactEnvelope =
        serde_json::from_value(envelope).map_err(|_| ManagementBackendError::InvalidInput)?;
    validate_policy_artifact_payload(kind, &envelope.payload)
}

fn compile_enforcement_system(system: &EnforcementSystemPayload) -> Result<SystemPolicy, ManagementBackendError> {
    match system.mode.as_str() {
        "preserve" if system.platform_system_ref.is_none() && system.content.is_none() => Ok(SystemPolicy::Preserve),
        "strip_client" if system.platform_system_ref.is_none() && system.content.is_none() => {
            Ok(SystemPolicy::StripClient)
        }
        "strip_all" if system.platform_system_ref.is_none() && system.content.is_none() => Ok(SystemPolicy::StripAll),
        "replace" => {
            let platform_system_ref = system
                .platform_system_ref
                .as_deref()
                .filter(|value| !value.trim().is_empty() && value.len() <= 256)
                .ok_or(ManagementBackendError::InvalidInput)?;
            let content = system.content.clone().ok_or(ManagementBackendError::InvalidInput)?;
            if !content.is_string() && !content.is_array() {
                return Err(ManagementBackendError::InvalidInput);
            }
            Ok(SystemPolicy::Replace {
                platform_system_ref: platform_system_ref.into(),
                content,
            })
        }
        _ => Err(ManagementBackendError::InvalidInput),
    }
}

fn background_sample_headers(
    sample: &BackgroundCatalogSample,
) -> Result<axum::http::HeaderMap, ManagementBackendError> {
    let mut headers = axum::http::HeaderMap::new();
    for (name, value) in &sample.headers {
        let name = axum::http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let value = axum::http::HeaderValue::from_str(value).map_err(|_| ManagementBackendError::InvalidInput)?;
        headers.append(name, value);
    }
    Ok(headers)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuleSetCreateCommand {
    name: String,
    schema_version: i64,
    scope_type: String,
    scope_id: String,
    rules: Vec<RuleDefinition>,
    #[serde(default)]
    source_refs: Vec<String>,
    reason: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRuleSetPayload {
    name: String,
    rules: Vec<RuleDefinition>,
    #[serde(default)]
    source_refs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSetSimulationCommand {
    request: Value,
    client_class: ClientClass,
    traffic_class: TrafficClass,
    #[serde(default)]
    protocol_headers: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ArtifactActionCommand {
    reason: String,
    expected_revision: Option<i64>,
}

#[derive(Deserialize)]
struct EnrollmentCreateCommand {
    mode: String,
    target_group_id: String,
    auth_method: String,
    recovery_credential_id: Option<String>,
    expected_credential_revision: Option<i64>,
}

#[derive(Deserialize)]
struct EnrollmentMaterialCommand {
    setup_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    console_api_key: Option<String>,
}

#[derive(Deserialize)]
struct OAuthCallbackCommand {
    authorization_code: String,
    state: String,
    callback_nonce: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageExportCreateCommand {
    dataset: String,
    format: String,
    scope: String,
    from: String,
    to: String,
    filters: Option<UsageExportFiltersCommand>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageExportFiltersCommand {
    platform_key_id: Option<String>,
    group_id: Option<String>,
    model_id: Option<String>,
    completeness: Option<String>,
}

fn enrollment_materials(
    auth_method: &str,
    command: EnrollmentMaterialCommand,
) -> Result<Vec<(&'static str, &'static str, String)>, ManagementBackendError> {
    let all_lengths_valid = [
        command.setup_token.as_deref(),
        command.access_token.as_deref(),
        command.refresh_token.as_deref(),
        command.console_api_key.as_deref(),
    ]
    .into_iter()
    .flatten()
    .all(|value| !value.is_empty() && value.len() <= 32 * 1024);
    if !all_lengths_valid {
        return Err(ManagementBackendError::InvalidInput);
    }
    match (
        auth_method,
        command.setup_token,
        command.access_token,
        command.refresh_token,
        command.console_api_key,
    ) {
        ("setup_token", Some(setup_token), None, None, None) => {
            Ok(vec![("setup_token", "credential_enrollment", setup_token)])
        }
        ("existing_oauth", None, Some(access_token), Some(refresh_token), None) => Ok(vec![
            ("oauth_access_token", "credential_enrollment", access_token),
            ("oauth_refresh_token", "credential_enrollment", refresh_token),
        ]),
        ("console_api_key", None, None, None, Some(console_api_key)) => {
            Ok(vec![("console_api_key", "credential_enrollment", console_api_key)])
        }
        _ => Err(ManagementBackendError::InvalidInput),
    }
}

#[derive(Deserialize)]
struct PlatformKeyCreateCommand {
    name: String,
    owner_user_id: String,
    group_id: String,
    expires_at: Option<String>,
    endpoint_permissions: Vec<String>,
    body_limit_bytes: u64,
    messages_rate: RateLimitCommand,
    models_rate: RateLimitCommand,
    concurrency: ConcurrencyCommand,
    requested_content_audit: String,
    content_audit_approval_case_id: Option<String>,
    content_audit_expires_at: Option<String>,
}

#[derive(Deserialize)]
struct RateLimitCommand {
    rpm: u64,
    burst: u64,
}

#[derive(Deserialize)]
struct ConcurrencyCommand {
    limit: u64,
    retry_after_ms: u64,
}

#[derive(Deserialize)]
struct PlatformKeyRevealCommand {
    step_up_grant_id: String,
    reason: String,
}

#[derive(Debug, PartialEq, Eq)]
enum ExpirationPatch {
    Unchanged,
    Clear,
    Set(String),
}

#[derive(Debug, PartialEq, Eq)]
struct PlatformKeyPatchCommand {
    name: Option<String>,
    expires_at: ExpirationPatch,
}

#[derive(Deserialize)]
struct LifecycleActionCommand {
    reason: Option<String>,
    step_up_grant_id: Option<String>,
    expected_revision: Option<i64>,
    #[allow(dead_code)]
    approval_case_id: Option<String>,
    #[allow(dead_code)]
    payload: Option<serde_json::Map<String, Value>>,
}

fn deserialize_body<T: for<'de> Deserialize<'de>>(request: &ManagementRequest) -> Result<T, ManagementBackendError> {
    request
        .body
        .clone()
        .ok_or(ManagementBackendError::InvalidInput)
        .and_then(|value| serde_json::from_value(value).map_err(|_| ManagementBackendError::InvalidInput))
}

fn parse_platform_key_patch(request: &ManagementRequest) -> Result<PlatformKeyPatchCommand, ManagementBackendError> {
    let body = request
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or(ManagementBackendError::InvalidInput)?;
    if body.is_empty() || body.keys().any(|key| !matches!(key.as_str(), "name" | "expires_at")) {
        return Err(ManagementBackendError::InvalidInput);
    }
    let name = body
        .get("name")
        .map(|value| {
            let value = value.as_str().ok_or(ManagementBackendError::InvalidInput)?.trim();
            if value.is_empty() || value.chars().count() > 128 {
                return Err(ManagementBackendError::InvalidInput);
            }
            Ok(value.to_owned())
        })
        .transpose()?;
    let expires_at = match body.get("expires_at") {
        None => ExpirationPatch::Unchanged,
        Some(Value::Null) => ExpirationPatch::Clear,
        Some(Value::String(value)) if !value.is_empty() && value.len() <= 128 => ExpirationPatch::Set(value.clone()),
        Some(_) => return Err(ManagementBackendError::InvalidInput),
    };
    Ok(PlatformKeyPatchCommand { name, expires_at })
}

fn required_action_reason(reason: Option<&str>) -> Result<&str, ManagementBackendError> {
    let reason = reason.map(str::trim).filter(|reason| !reason.is_empty());
    match reason {
        Some(reason) if reason.len() <= 2_048 => Ok(reason),
        _ => Err(ManagementBackendError::InvalidInput),
    }
}

fn valid_nonnegative_decimal(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || matches!(value.as_bytes().first(), Some(b'+' | b'-')) {
        return false;
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some() || whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    fraction.is_none_or(|digits| {
        !digits.is_empty() && digits.len() <= 12 && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn required_principal(principal: Option<&ManagementPrincipal>) -> Result<&ManagementPrincipal, ManagementBackendError> {
    principal.ok_or(ManagementBackendError::Authentication)
}

fn parse_role(value: &str) -> Result<ManagementRole, ManagementBackendError> {
    match value {
        "platform_admin" => Ok(ManagementRole::PlatformAdmin),
        "key_owner" => Ok(ManagementRole::KeyOwner),
        _ => Err(ManagementBackendError::Unavailable),
    }
}

const fn role_code(role: ManagementRole) -> &'static str {
    match role {
        ManagementRole::PlatformAdmin => "platform_admin",
        ManagementRole::KeyOwner => "key_owner",
        ManagementRole::Anonymous => "anonymous",
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, ManagementBackendError> {
    Uuid::parse_str(value).map_err(|_| ManagementBackendError::NotFound)
}

fn parse_input_uuid(value: &str) -> Result<Uuid, ManagementBackendError> {
    Uuid::parse_str(value).map_err(|_| ManagementBackendError::InvalidInput)
}

fn parse_enrollment_mode(value: &str) -> Result<EnrollmentMode, ManagementBackendError> {
    match value {
        "create" => Ok(EnrollmentMode::Create),
        "recover" => Ok(EnrollmentMode::Recover),
        _ => Err(ManagementBackendError::InvalidInput),
    }
}

fn parse_enrollment_auth_method(value: &str) -> Result<EnrollmentAuthMethod, ManagementBackendError> {
    match value {
        "oauth_pkce" => Ok(EnrollmentAuthMethod::OauthPkce),
        "setup_token" => Ok(EnrollmentAuthMethod::SetupToken),
        "existing_oauth_material" | "existing_oauth" => Ok(EnrollmentAuthMethod::ExistingOauth),
        "browser_session_import" => Ok(EnrollmentAuthMethod::BrowserSessionImport),
        "console_api_key" => Ok(EnrollmentAuthMethod::ConsoleApiKey),
        _ => Err(ManagementBackendError::InvalidInput),
    }
}

const fn auth_kind_for_enrollment(method: EnrollmentAuthMethod) -> AuthKind {
    match method {
        EnrollmentAuthMethod::OauthPkce
        | EnrollmentAuthMethod::ExistingOauth
        | EnrollmentAuthMethod::BrowserSessionImport => AuthKind::OauthSubscription,
        EnrollmentAuthMethod::SetupToken => AuthKind::SetupTokenSubscription,
        EnrollmentAuthMethod::ConsoleApiKey => AuthKind::ConsoleApiKey,
    }
}

fn map_storage_error(error: &StorageError) -> ManagementBackendError {
    match error {
        StorageError::RevisionConflict => ManagementBackendError::Precondition,
        StorageError::AccountConflict
        | StorageError::AccountMismatch
        | StorageError::InvalidLifecycle
        | StorageError::CapacityExceeded
        | StorageError::EgressUnavailable => ManagementBackendError::Precondition,
        _ => ManagementBackendError::Unavailable,
    }
}

fn masked_account_uuid(value: Uuid) -> String {
    let encoded = value.simple().to_string();
    format!("{}…{}", &encoded[..8], &encoded[encoded.len() - 4..])
}

fn management_audit(
    principal: &ManagementPrincipal,
    action: &str,
    object_type: &str,
    aggregate_id: Uuid,
    aggregate_revision: i64,
    redacted_detail: Value,
) -> Result<AuditOutboxRecord, ManagementBackendError> {
    Ok(AuditOutboxRecord {
        actor_type: role_code(principal.role).to_owned(),
        actor_id: Some(parse_uuid(&principal.user_id)?),
        action: action.to_owned(),
        object_type: object_type.to_owned(),
        object_id: Some(aggregate_id.to_string()),
        outcome: "success".to_owned(),
        redacted_detail,
        topic: format!("{object_type}.{action}"),
        aggregate_id,
        aggregate_revision,
        payload: json!({"object_id":aggregate_id,"revision":aggregate_revision}),
    })
}

fn path_uuid(request: &ManagementRequest, name: &str) -> Result<Uuid, ManagementBackendError> {
    request
        .path_parameters
        .get(name)
        .ok_or(ManagementBackendError::NotFound)
        .and_then(|value| parse_uuid(value))
}

fn request_revision(request: &ManagementRequest) -> Result<i64, ManagementBackendError> {
    request
        .if_match
        .as_deref()
        .and_then(|value| value.strip_prefix("\"rev-").and_then(|value| value.strip_suffix('"')))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 1)
        .ok_or(ManagementBackendError::InvalidInput)
}

fn list_response(data: &[Value]) -> ManagementBackendResponse {
    ManagementBackendResponse::ok(json!({"data":data,"meta":{"has_more":false,"page_size":data.len()}}))
}

fn single_response(data: &Value, revision: i64) -> ManagementBackendResponse {
    ManagementBackendResponse {
        status: axum::http::StatusCode::OK,
        body: json!({"data":data,"meta":{}}),
        etag: Some(format!("\"rev-{revision}\"").into_boxed_str()),
        session_cookie: None,
        clear_session_cookie: false,
        no_store: false,
    }
}

fn required<T>(row: &sqlx::postgres::PgRow, column: &str) -> Result<T, ManagementBackendError>
where
    for<'decode> T: sqlx::Decode<'decode, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column).map_err(|_| ManagementBackendError::Unavailable)
}

fn optional<T>(row: &sqlx::postgres::PgRow, column: &str) -> Result<Option<T>, ManagementBackendError>
where
    for<'decode> T: sqlx::Decode<'decode, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column).map_err(|_| ManagementBackendError::Unavailable)
}

fn user_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "username":required::<String>(row,"username")?,
        "display_name":required::<Option<String>>(row,"display_name")?,
        "email":required::<Option<String>>(row,"email")?,
        "role":required::<String>(row,"role_code")?,
        "status":required::<String>(row,"status_code")?,
        "revision":required::<i64>(row,"revision")?,
        "created_at":required::<String>(row,"created_at")?,
        "updated_at":required::<String>(row,"updated_at")?
    }))
}

fn platform_key_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "owner_user_id":required::<Uuid>(row,"owner_user_id")?,
        "group_id":required::<Uuid>(row,"group_id")?,
        "name":required::<String>(row,"name")?,
        "display_prefix":required::<Option<String>>(row,"display_prefix")?,
        "status":required::<String>(row,"status_code")?,
        "expires_at":required::<Option<String>>(row,"expires_at")?,
        "revision":required::<i64>(row,"revision")?,
        "max_concurrency":required::<Option<i32>>(row,"max_concurrency")?,
        "messages_rpm":required::<Option<i32>>(row,"messages_rpm")?,
        "models_rpm":required::<Option<i32>>(row,"models_rpm")?,
        "max_body_bytes":required::<Option<i64>>(row,"max_body_bytes")?,
        "audit_mode":required::<Option<String>>(row,"audit_mode_code")?,
        "created_at":required::<String>(row,"created_at")?,
        "updated_at":required::<String>(row,"updated_at")?
    }))
}

fn group_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "name":required::<String>(row,"name")?,
        "status":required::<String>(row,"status_code")?,
        "owner_executor_id":required::<Option<String>>(row,"owner_executor_id")?,
        "owner_generation":required::<i64>(row,"owner_generation")?,
        "credential_count":required::<i64>(row,"credential_count")?,
        "revision":required::<i64>(row,"revision")?,
        "created_at":required::<String>(row,"created_at")?,
        "updated_at":required::<String>(row,"updated_at")?
    }))
}

fn path_i64(request: &ManagementRequest, name: &str) -> Result<i64, ManagementBackendError> {
    request
        .path_parameters
        .get(name)
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 1)
        .ok_or(ManagementBackendError::NotFound)
}

fn group_config_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    let proxy_policy = required::<String>(row, "proxy_policy_code")?;
    let egress_mode = match proxy_policy.as_str() {
        "auto" => "auto",
        "direct" => "direct_only",
        "proxy_required" => "proxy_only",
        _ => return Err(ManagementBackendError::Unavailable),
    };
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,"group_id":required::<Uuid>(row,"group_id")?,
        "version":required::<i64>(row,"config_version")?,"lifecycle":required::<String>(row,"lifecycle_code")?,
        "content_hash":required::<String>(row,"content_hash")?,"accepted_client_classes":required::<Vec<String>>(row,"accepted_clients")?,
        "fully_managed_required":required::<bool>(row,"fully_managed_required")?,"egress_mode":egress_mode,
        "limits":{
            "concurrency":required::<Option<i32>>(row,"max_concurrency")?,
            "messages_rpm":required::<Option<i32>>(row,"default_rpm")?,
            "messages_burst":required::<Option<i32>>(row,"default_rpm_burst")?
        },
        "credential_defaults":{
            "concurrency":required::<i32>(row,"default_credential_concurrency")?,
            "messages_rpm":required::<i32>(row,"default_credential_rpm")?
        },
        "queue":{
            "capacity":required::<Option<i32>>(row,"queue_capacity")?,
            "pre_upstream_timeout_ms":required::<i64>(row,"pre_upstream_wait_ms")?
        },
        "timeouts":{
            "upstream_connect_ms":required::<i64>(row,"upstream_connect_ms")?,
            "upstream_non_stream_total_ms":required::<i64>(row,"upstream_non_stream_total_ms")?,
            "upstream_stream_idle_ms":required::<i64>(row,"upstream_stream_idle_ms")?,
            "min_retry_budget_ms":required::<i64>(row,"min_retry_budget_ms")?,
            "cancel_grace_ms":required::<i64>(row,"cancel_grace_ms")?,
            "queue_full_retry_after_ms":required::<i64>(row,"queue_full_retry_after_ms")?,
            "queue_wait_retry_after_ms":required::<i64>(row,"queue_wait_retry_after_ms")?
        },
        "content_audit":{
            "policy":required::<String>(row,"content_audit_policy_code")?,
            "retention_days":required::<i32>(row,"content_audit_retention_days")?
        },
        "enforcement_artifact_id":required::<Option<Uuid>>(row,"enforcement_artifact_id")?,
        "validation":required::<Value>(row,"validation_report")?,
        "validated_at":required::<Option<String>>(row,"validated_at")?,"published_at":required::<Option<String>>(row,"published_at")?,
        "is_active":required::<Option<bool>>(row,"is_active")?.unwrap_or(false),
        "pointer_revision":required::<Option<i64>>(row,"pointer_revision")?,"created_at":required::<String>(row,"created_at")?,
        "revision":required::<i64>(row,"config_version")?
    }))
}

fn validate_group_config_candidate(command: &GroupConfigCandidateCommand) -> Result<(), ManagementBackendError> {
    let clients = command
        .accepted_client_classes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if clients.len() != command.accepted_client_classes.len()
        || clients.is_empty()
        || clients
            .iter()
            .any(|client| !matches!(*client, "claude_code_cli" | "non_claude_code_cli"))
        || command.limits.messages_rpm.is_some() != command.limits.messages_burst.is_some()
        || command.credential_defaults.concurrency == 0
        || command.credential_defaults.messages_rpm == 0
        || command.queue.pre_upstream_timeout_ms == 0
        || !(1_000..=30_000).contains(&command.timeouts.upstream_connect_ms)
        || !(5_000..=3_600_000).contains(&command.timeouts.upstream_non_stream_total_ms)
        || !(5_000..=600_000).contains(&command.timeouts.upstream_stream_idle_ms)
        || !(1..=365).contains(&command.content_audit.retention_days)
        || !matches!(command.content_audit.policy.as_str(), "allow" | "require" | "forbid")
    {
        return Err(ManagementBackendError::InvalidInput);
    }
    group_proxy_policy(&command.egress_mode)?;
    Ok(())
}

fn group_proxy_policy(value: &str) -> Result<&'static str, ManagementBackendError> {
    match value {
        "auto" => Ok("auto"),
        "direct_only" => Ok("direct"),
        "proxy_only" => Ok("proxy_required"),
        _ => Err(ManagementBackendError::InvalidInput),
    }
}

fn credential_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "group_id":required::<Uuid>(row,"group_id")?,
        "account_uuid":required::<Option<Uuid>>(row,"account_uuid")?,
        "purpose":required::<String>(row,"purpose_code")?,
        "auth_kind":required::<String>(row,"auth_kind_code")?,
        "lifecycle_state":required::<String>(row,"lifecycle_state_code")?,
        "auth_state":required::<String>(row,"auth_state_code")?,
        "scheduling_state":required::<String>(row,"scheduling_state_code")?,
        "quota_state":required::<String>(row,"quota_state_code")?,
        "transport_state":required::<String>(row,"transport_state_code")?,
        "management_class":required::<String>(row,"management_class_code")?,
        "token_version":required::<i64>(row,"token_version")?,
        "cooldown_until":required::<Option<String>>(row,"cooldown_until")?,
        "profile_epoch":required::<Option<i64>>(row,"profile_epoch")?,
        "device_epoch":required::<Option<i64>>(row,"device_epoch")?,
        "profile_state":required::<Option<String>>(row,"profile_state")?,
        "egress_mode":required::<Option<String>>(row,"egress_mode")?,
        "egress_stability":required::<Option<String>>(row,"egress_stability")?,
        "subscription_plan":required::<Option<String>>(row,"normalized_plan_code")?,
        "plan_freshness":required::<Option<String>>(row,"plan_freshness")?,
        "scheduling_config":{
            "config_version":required::<Option<i64>>(row,"scheduling_config_version")?,
            "pointer_revision":required::<Option<i64>>(row,"scheduling_pointer_revision")?,
            "concurrency":required::<Option<i32>>(row,"max_concurrency")?,
            "messages_rpm":required::<Option<i32>>(row,"rpm_limit")?,
            "messages_burst":required::<Option<i32>>(row,"rpm_burst")?,
            "priority":required::<Option<i32>>(row,"priority_layer")?,
            "weight":required::<Option<i64>>(row,"scheduling_weight")?
        },
        "revision":required::<i64>(row,"revision")?,
        "created_at":required::<String>(row,"created_at")?,
        "updated_at":required::<String>(row,"updated_at")?
    }))
}

fn request_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"request_id")?,
        "request_month":required::<String>(row,"request_month")?,
        "platform_key_id":required::<Uuid>(row,"platform_key_id")?,
        "group_id":required::<Uuid>(row,"group_id")?,
        "endpoint":required::<String>(row,"endpoint_code")?,
        "client_class":required::<String>(row,"client_class_code")?,
        "phase":required::<String>(row,"phase_code")?,
        "outcome":required::<Option<String>>(row,"outcome_code")?,
        "http_status":required::<Option<i32>>(row,"http_status")?,
        "request_body_bytes":required::<i64>(row,"request_body_bytes")?,
        "response_body_bytes":required::<Option<i64>>(row,"response_body_bytes")?,
        "response_mode":required::<Option<String>>(row,"response_mode_code")?,
        "commit_state":required::<String>(row,"client_commit_state_code")?,
        "terminal_kind":required::<Option<String>>(row,"terminal_kind_code")?,
        "usage_completeness":required::<Option<String>>(row,"usage_completeness_code")?,
        "created_at":required::<String>(row,"created_at")?,
        "completed_at":required::<Option<String>>(row,"completed_at")?
    }))
}

fn bundle_protocol(application: &ApplicationProfile) -> &'static str {
    match application {
        ApplicationProfile::H1 { .. } => "h1",
        ApplicationProfile::H2 { .. } => "h2",
    }
}

fn checked_bundle_path(
    runtime: &TransportManagementRuntime,
    object_uri: &str,
) -> Result<PathBuf, ManagementBackendError> {
    let path = PathBuf::from(object_uri);
    if path.parent() != Some(runtime.bundle_dir.as_path())
        || path.extension().and_then(|value| value.to_str()) != Some("json")
    {
        return Err(ManagementBackendError::Precondition);
    }
    Ok(path)
}

fn transport_bundle_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,"artifact_version":required::<i64>(row,"artifact_version")?,
        "engine_abi_version":required::<String>(row,"engine_abi_version")?,
        "lifecycle":required::<String>(row,"lifecycle_code")?,"manifest_hash":required::<String>(row,"manifest_hash")?,
        "signing_key_id":required::<String>(row,"signing_key_id")?,"artifact_present":!required::<String>(row,"object_uri")?.is_empty(),
        "source_archetype_version_id":required::<Option<Uuid>>(row,"source_archetype_version_id")?,
        "capture_cohort":required::<Option<String>>(row,"capture_cohort")?,"protocol":required::<Option<String>>(row,"protocol_code")?,
        "backend_id":required::<Option<String>>(row,"backend_id")?,"evidence_gate":required::<String>(row,"evidence_gate_code")?,
        "runtime_state":required::<String>(row,"runtime_state_code")?,"min_engine_build":required::<Option<String>>(row,"min_engine_build")?,
        "max_engine_build":required::<Option<String>>(row,"max_engine_build")?,
        "engine_activation_generation":required::<i64>(row,"engine_activation_generation")?,
        "binding_state":required::<Option<String>>(row,"binding_state")?,"archetype_id":required::<Option<Uuid>>(row,"archetype_id")?,
        "archetype_name":required::<Option<String>>(row,"archetype_name")?,"archetype_version":required::<Option<i64>>(row,"archetype_version")?,
        "created_at":required::<String>(row,"created_at")?,"activated_at":required::<Option<String>>(row,"activated_at")?,
        "revision":required::<i64>(row,"artifact_version")?
    }))
}

fn async_job_response(id: Uuid, kind: &str, state: &str, created_at: &str) -> ManagementBackendResponse {
    ManagementBackendResponse {
        status: axum::http::StatusCode::ACCEPTED,
        body: json!({"data":{
            "id":id,"type":kind,"status":state,"progress":{"completed":0,"total":1},
            "created_at":created_at,"expires_at":null
        },"meta":{}}),
        etag: None,
        session_cookie: None,
        clear_session_cookie: false,
        no_store: false,
    }
}

fn upgrade_check_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    let preflight_state = required::<String>(row, "preflight_state_code")?;
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "job_id":required::<Option<Uuid>>(row,"durable_job_id")?,
        "upgrade_state":required::<String>(row,"state_code")?,
        "preflight_state":preflight_state,
        "compatible":if preflight_state == "passed" { Some(true) } else if preflight_state == "failed" { Some(false) } else { None },
        "candidate_release":required::<String>(row,"release_version")?,
        "source_revision":required::<String>(row,"source_revision")?,
        "candidate_digest":required::<String>(row,"candidate_digest")?,
        "job_state":required::<Option<String>>(row,"job_state")?,
        "checks":required::<Value>(row,"checks")?,
        "result":required::<Value>(row,"preflight_result")?,
        "error_code":required::<Option<String>>(row,"error_code")?,
        "created_at":required::<String>(row,"created_at")?,
        "started_at":required::<Option<String>>(row,"preflight_started_at")?,
        "completed_at":required::<Option<String>>(row,"preflight_completed_at")?,
        "valid_until":required::<Option<String>>(row,"preflight_valid_until")?,
        "revision":required::<i64>(row,"revision")?
    }))
}

fn completed_job_response(id: Uuid, kind: &str, completed_at: &str) -> ManagementBackendResponse {
    ManagementBackendResponse {
        status: axum::http::StatusCode::ACCEPTED,
        body: json!({"data":{
            "id":id,"type":kind,"status":"succeeded","progress":{"completed":1,"total":1},
            "created_at":completed_at,"completed_at":completed_at,"expires_at":null
        },"meta":{}}),
        etag: None,
        session_cookie: None,
        clear_session_cookie: false,
        no_store: false,
    }
}

async fn insert_job_created_history(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: Uuid,
    outcome: &str,
) -> Result<(), ManagementBackendError> {
    sqlx::query(
        "INSERT INTO ops.durable_job_history \
         (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
         VALUES ($1,$2,NULL,'scheduled',0,$3,'{}'::jsonb,clock_timestamp())",
    )
    .bind(Uuid::now_v7())
    .bind(job_id)
    .bind(outcome)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?;
    Ok(())
}

fn require_platform_admin(principal: &ManagementPrincipal) -> Result<(), ManagementBackendError> {
    if principal.role == ManagementRole::PlatformAdmin {
        Ok(())
    } else {
        Err(ManagementBackendError::NotFound)
    }
}

fn backup_run_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "job_id":required::<Option<Uuid>>(row,"durable_job_id")?,
        "kind":required::<String>(row,"kind_code")?,
        "state":required::<String>(row,"state_code")?,
        "database_system_id":required::<Option<String>>(row,"database_system_id")?,
        "timeline":required::<Option<i64>>(row,"timeline")?,
        "lsn_start":required::<Option<String>>(row,"lsn_start")?,
        "lsn_end":required::<Option<String>>(row,"lsn_end")?,
        "wal_archived_at":required::<Option<String>>(row,"wal_archived_at")?,
        "watermarks":required::<Value>(row,"watermarks")?,
        "backup_key_version":required::<Option<i64>>(row,"backup_key_version")?,
        "bytes_written":required::<Option<i64>>(row,"bytes_written")?,
        "manifest_sha256":required::<Option<String>>(row,"manifest_sha256")?,
        "requested_at":required::<String>(row,"requested_at")?,
        "started_at":required::<Option<String>>(row,"started_at")?,
        "completed_at":required::<Option<String>>(row,"completed_at")?,
        "error_code":required::<Option<String>>(row,"error_code")?,
        "revision":required::<i64>(row,"revision")?
    }))
}

fn restore_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "job_id":required::<Option<Uuid>>(row,"durable_job_id")?,
        "backup_run_id":required::<Uuid>(row,"backup_run_id")?,
        "kind":required::<String>(row,"kind_code")?,
        "state":required::<String>(row,"state_code")?,
        "recovery_point":required::<Option<String>>(row,"recovery_point")?,
        "isolated_environment_id":required::<Option<String>>(row,"isolated_environment_id")?,
        "db_recovered":required::<Option<bool>>(row,"db_recovered")?,
        "object_replayed":required::<Option<bool>>(row,"object_replayed")?,
        "ledger_replayed":required::<Option<bool>>(row,"ledger_replayed")?,
        "checks":required::<Value>(row,"checks")?,
        "lineage":required::<Value>(row,"lineage")?,
        "rpo_seconds":required::<Option<i64>>(row,"rpo_seconds")?,
        "rto_seconds":required::<Option<i64>>(row,"rto_seconds")?,
        "manifest_sha256":required::<Option<String>>(row,"manifest_sha256")?,
        "serving_simulated_at":required::<Option<String>>(row,"serving_simulated_at")?,
        "destroyed_at":required::<Option<String>>(row,"destroyed_at")?,
        "requested_at":required::<String>(row,"requested_at")?,
        "started_at":required::<Option<String>>(row,"started_at")?,
        "completed_at":required::<Option<String>>(row,"completed_at")?,
        "error_code":required::<Option<String>>(row,"error_code")?,
        "revision":required::<i64>(row,"revision")?
    }))
}

fn model_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "upstream_model_id":required::<String>(row,"upstream_model_id")?,
        "display_name":required::<String>(row,"display_name")?,
        "lifecycle":required::<String>(row,"lifecycle_code")?,
        "capability_version":required::<Option<i64>>(row,"capability_version")?,
        "capability_state":required::<Option<String>>(row,"capability_state")?,
        "revision":required::<i64>(row,"revision")?,
        "first_seen_at":required::<String>(row,"first_seen_at")?,
        "last_seen_at":required::<String>(row,"last_seen_at")?
    }))
}

fn capability_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "model_id":required::<Uuid>(row,"model_id")?,
        "upstream_model_id":required::<String>(row,"upstream_model_id")?,
        "capability_version":required::<i64>(row,"capability_version")?,
        "lifecycle":required::<String>(row,"lifecycle_code")?,
        "schema_payload":required::<Value>(row,"schema_payload")?,
        "content_hash":required::<String>(row,"content_hash")?,
        "created_at":required::<String>(row,"created_at")?,
        "activated_at":required::<Option<String>>(row,"activated_at")?,
        "model_revision":required::<i64>(row,"model_revision")?,
        "revision":required::<i64>(row,"model_revision")?
    }))
}

fn proxy_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "name":required::<String>(row,"name")?,
        "type":required::<String>(row,"proxy_type_code")?,
        "host":required::<String>(row,"host")?,
        "port":required::<i32>(row,"port")?,
        "has_auth":required::<bool>(row,"has_auth")?,
        "lifecycle":required::<String>(row,"lifecycle_code")?,
        "health":required::<String>(row,"health_code")?,
        "stability":required::<String>(row,"stability_code")?,
        "max_active_credentials":required::<i32>(row,"max_active_bindings")?,
        "active_credentials":required::<i64>(row,"active_bindings")?,
        "probe_generation":required::<i64>(row,"probe_generation")?,
        "last_probed_at":required::<Option<String>>(row,"last_probed_at")?,
        "last_success_at":required::<Option<String>>(row,"last_success_at")?,
        "last_error":required::<Option<String>>(row,"last_error_code")?,
        "revision":required::<i64>(row,"revision")?,
        "created_at":required::<String>(row,"created_at")?,
        "updated_at":required::<String>(row,"updated_at")?
    }))
}

fn alert_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "severity":required::<String>(row,"severity_code")?,
        "type":required::<String>(row,"type_code")?,
        "state":required::<String>(row,"state_code")?,
        "object_type":required::<Option<String>>(row,"object_type_code")?,
        "object_id":required::<Option<String>>(row,"object_id")?,
        "summary":required::<String>(row,"summary")?,
        "detail":required::<Value>(row,"detail")?,
        "revision":required::<i64>(row,"revision")?,
        "first_seen_at":required::<String>(row,"first_seen_at")?,
        "last_seen_at":required::<String>(row,"last_seen_at")?,
        "resolved_at":required::<Option<String>>(row,"resolved_at")?
    }))
}

fn alert_silence_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "fingerprint_pattern":required::<String>(row,"fingerprint_pattern")?,
        "reason":required::<String>(row,"reason")?,
        "starts_at":required::<String>(row,"starts_at")?,
        "expires_at":required::<String>(row,"expires_at")?,
        "created_by":required::<Uuid>(row,"created_by")?,
        "revision":required::<i64>(row,"revision")?,
        "created_at":required::<String>(row,"created_at")?,
        "active":required::<bool>(row,"active")?
    }))
}

fn notification_channel_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "kind":required::<String>(row,"kind_code")?,
        "name":required::<String>(row,"name")?,
        "configuration":required::<Value>(row,"configuration")?,
        "state":required::<String>(row,"state_code")?,
        "secret_present":required::<bool>(row,"secret_present")?,
        "delivery_count":required::<i64>(row,"delivery_count")?,
        "last_delivery_state":required::<Option<String>>(row,"last_delivery_state")?,
        "last_delivery_at":required::<Option<String>>(row,"last_delivery_at")?,
        "revision":required::<i64>(row,"revision")?,
        "created_at":required::<String>(row,"created_at")?,
        "updated_at":required::<String>(row,"updated_at")?
    }))
}

fn job_kind_is_cancellable(kind: &str) -> bool {
    matches!(
        kind,
        "usage_export_generate"
            | "content_audit_export_generate"
            | "notification_channel_test_v1"
            | "model_catalog_discovery_v1"
            | "upgrade_preflight_v1"
            | "backup_create"
            | "restore_manifest_validation"
            | "restore_full_drill"
    )
}

async fn cancel_job_projection(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    kind: &str,
    job_id: Uuid,
    payload: &Value,
) -> Result<(), ManagementBackendError> {
    let affected = match kind {
        "usage_export_generate" | "content_audit_export_generate" => sqlx::query(
            "UPDATE ops.export_job SET state_code='failed',last_error_code='cancelled', \
               completed_at=clock_timestamp(),revision=revision+1 \
             WHERE durable_job_id=$1 AND state_code='queued'",
        )
        .bind(job_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .rows_affected(),
        "notification_channel_test_v1" => {
            let delivery_id = payload
                .get("delivery_id")
                .and_then(Value::as_str)
                .ok_or(ManagementBackendError::Precondition)
                .and_then(parse_input_uuid)?;
            sqlx::query(
                "UPDATE ops.notification_delivery SET state_code='failed',response_code='cancelled', \
                   next_attempt_at=NULL,last_outcome=jsonb_build_object('code','cancelled'),updated_at=clock_timestamp() \
                 WHERE id=$1 AND state_code IN ('pending','retry_wait')",
            )
            .bind(delivery_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?
            .rows_affected()
        }
        "model_catalog_discovery_v1" => 1,
        "upgrade_preflight_v1" => sqlx::query(
            "UPDATE ops.upgrade_run SET state_code='failed',preflight_state_code='cancelled', \
               preflight_completed_at=clock_timestamp(),error_code='cancelled',revision=revision+1 \
             WHERE durable_job_id=$1 AND preflight_state_code='queued'",
        )
        .bind(job_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .rows_affected(),
        "backup_create" => sqlx::query(
            "UPDATE ops.backup_run SET state_code='cancelled',completed_at=clock_timestamp(), \
               error_code='cancelled',revision=revision+1 \
             WHERE durable_job_id=$1 AND state_code='queued'",
        )
        .bind(job_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .rows_affected(),
        "restore_manifest_validation" | "restore_full_drill" => sqlx::query(
            "UPDATE ops.restore_drill SET state_code='cancelled',completed_at=clock_timestamp(), \
               error_code='cancelled',revision=revision+1 \
             WHERE durable_job_id=$1 AND state_code='queued'",
        )
        .bind(job_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?
        .rows_affected(),
        _ => return Err(ManagementBackendError::Precondition),
    };
    if affected != 1 {
        return Err(ManagementBackendError::Precondition);
    }
    Ok(())
}

fn job_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "kind":required::<String>(row,"kind_code")?,
        "state":required::<String>(row,"state_code")?,
        "run_after":required::<String>(row,"run_after")?,
        "lease_generation":required::<i64>(row,"lease_generation")?,
        "attempt_count":required::<i32>(row,"attempt_count")?,
        "max_attempts":required::<i32>(row,"max_attempts")?,
        "last_error":required::<Option<String>>(row,"last_error_code")?,
        "created_at":required::<String>(row,"created_at")?,
        "updated_at":required::<String>(row,"updated_at")?,
        "completed_at":required::<Option<String>>(row,"completed_at")?
    }))
}

fn audit_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"event_id")?,
        "event_day":required::<String>(row,"event_day")?,
        "sequence":required::<i64>(row,"daily_sequence")?,
        "actor_type":required::<String>(row,"actor_type_code")?,
        "actor_id":required::<Option<Uuid>>(row,"actor_id")?,
        "action":required::<String>(row,"action_code")?,
        "object_type":required::<String>(row,"object_type_code")?,
        "object_id":required::<Option<String>>(row,"object_id")?,
        "outcome":required::<String>(row,"outcome_code")?,
        "event":required::<Value>(row,"canonical_redacted_event")?,
        "occurred_at":required::<String>(row,"occurred_at")?
    }))
}

fn approval_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id":required::<Uuid>(row,"id")?,
        "kind":required::<String>(row,"operation_code")?,
        "object_type":required::<String>(row,"object_type_code")?,
        "object_id":required::<String>(row,"object_id")?,
        "requested_by":required::<Option<Uuid>>(row,"requested_by")?,
        "state":required::<String>(row,"state_code")?,
        "required_approvals":required::<i16>(row,"required_approvals")?,
        "reason":required::<Option<String>>(row,"request_reason")?,
        "expires_at":required::<String>(row,"expires_at")?,
        "consumed_at":required::<Option<String>>(row,"consumed_at")?,
        "created_at":required::<String>(row,"created_at")?,
        "revision":required::<i64>(row,"revision")?
    }))
}

fn legal_hold_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "id": required::<Uuid>(row,"id")?,
        "name": required::<String>(row,"name")?,
        "reason": required::<String>(row,"reason")?,
        "state": required::<String>(row,"state_code")?,
        "review_due_at": required::<Option<String>>(row,"review_due_at")?,
        "last_reviewed_at": required::<Option<String>>(row,"last_reviewed_at")?,
        "created_at": required::<String>(row,"created_at")?,
        "active_object_count": required::<i64>(row,"active_object_count")?,
        "revision": required::<i64>(row,"revision")?,
    }))
}

fn content_audit_metadata_projection(row: &sqlx::postgres::PgRow) -> Result<Value, ManagementBackendError> {
    Ok(json!({
        "ordinal":required::<i16>(row,"ordinal")?,
        "id":required::<Uuid>(row,"id")?,
        "request_id":required::<Uuid>(row,"request_id")?,
        "owner_user_id":required::<Option<Uuid>>(row,"owner_user_id")?,
        "platform_key_id":required::<Option<Uuid>>(row,"platform_key_id")?,
        "group_id":required::<Option<Uuid>>(row,"group_id")?,
        "attempt_id":required::<Option<Uuid>>(row,"attempt_id")?,
        "attempt_no":required::<Option<i16>>(row,"attempt_no")?,
        "object_kind":required::<String>(row,"object_kind_code")?,
        "content_length":required::<Option<i64>>(row,"content_length")?,
        "capture_complete":required::<bool>(row,"capture_complete")?,
        "truncated":required::<bool>(row,"truncated")?,
        "state":required::<String>(row,"state_code")?,
        "legal_hold_count":required::<i32>(row,"legal_hold_count")?,
        "created_at":required::<String>(row,"created_at")?,
        "expires_at":required::<Option<String>>(row,"expires_at")?
    }))
}

async fn lock_content_audit_execution_approval(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal: &ManagementPrincipal,
    approval_id: Uuid,
    operation: &str,
    scope_id: &str,
    action_snapshot_digest: &[u8; 32],
) -> Result<(), ManagementBackendError> {
    let requester_id = parse_uuid(&principal.user_id)?;
    let row = sqlx::query(
        "SELECT required_approvals FROM security.approval_case \
         WHERE id=$1 AND operation_code=$2 AND object_type_code='content_audit_scope' \
           AND object_id=$3 AND requested_by=$4 AND action_snapshot_digest=$5 \
           AND state_code='approved' AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
    )
    .bind(approval_id)
    .bind(operation)
    .bind(scope_id)
    .bind(requester_id)
    .bind(action_snapshot_digest.as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?
    .ok_or(ManagementBackendError::Precondition)?;
    let required_approvals = required::<i16>(&row, "required_approvals")?;
    let active_approvals: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT grant.approver_user_id) FROM security.approval_grant grant \
         JOIN iam.user_account approver ON approver.id=grant.approver_user_id \
           AND approver.role_code='platform_admin' AND approver.status_code='active' \
         WHERE grant.approval_case_id=$1 AND grant.decision_code='approve' AND grant.approver_user_id<>$2",
    )
    .bind(approval_id)
    .bind(requester_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?;
    if active_approvals < i64::from(required_approvals) {
        return Err(ManagementBackendError::Precondition);
    }
    Ok(())
}

async fn consume_approved_case(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    approval_id: Uuid,
    operation: &str,
    object_type: &str,
    object_id: &str,
) -> Result<(), ManagementBackendError> {
    let consumed = sqlx::query(
        "UPDATE security.approval_case SET state_code='consumed',consumed_at=clock_timestamp(),revision=revision+1 \
         WHERE id=$1 AND operation_code=$2 AND object_type_code=$3 AND object_id=$4 \
           AND state_code='approved' AND consumed_at IS NULL AND expires_at>clock_timestamp()",
    )
    .bind(approval_id)
    .bind(operation)
    .bind(object_type)
    .bind(object_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?;
    if consumed.rows_affected() != 1 {
        return Err(ManagementBackendError::Precondition);
    }
    Ok(())
}

async fn consume_approved_case_bound(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    approval_id: Uuid,
    operation: &str,
    object_type: &str,
    object_id: &str,
    action_snapshot_digest: &[u8; 32],
) -> Result<(), ManagementBackendError> {
    let consumed = sqlx::query(
        "UPDATE security.approval_case SET state_code='consumed',consumed_at=clock_timestamp(),revision=revision+1 \
         WHERE id=$1 AND operation_code=$2 AND object_type_code=$3 AND object_id=$4 \
           AND action_snapshot_digest=$5 AND state_code='approved' AND consumed_at IS NULL \
           AND expires_at>clock_timestamp()",
    )
    .bind(approval_id)
    .bind(operation)
    .bind(object_type)
    .bind(object_id)
    .bind(action_snapshot_digest.as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?;
    if consumed.rows_affected() != 1 {
        return Err(ManagementBackendError::Precondition);
    }
    Ok(())
}

async fn consume_device_rebuild_approval(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal: &ManagementPrincipal,
    approval_id: Uuid,
    credential_id: Uuid,
    action_snapshot_digest: &[u8; 32],
) -> Result<(Uuid, Uuid), ManagementBackendError> {
    let requester_id = parse_uuid(&principal.user_id)?;
    let row = sqlx::query(
        "UPDATE security.approval_case SET state_code='consumed',consumed_at=clock_timestamp(),revision=revision+1 \
         WHERE id=$1 AND operation_code='device_rebuild' AND object_type_code='credential' AND object_id=$2 \
           AND requested_by=$3 AND action_snapshot_digest=$4 AND state_code='approved' AND consumed_at IS NULL \
           AND expires_at>clock_timestamp() RETURNING requested_by,requester_step_up_grant_id",
    )
    .bind(approval_id)
    .bind(credential_id.to_string())
    .bind(requester_id)
    .bind(action_snapshot_digest.as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?
    .ok_or(ManagementBackendError::Precondition)?;
    let requested_by = required::<Uuid>(&row, "requested_by")?;
    let requester_grant =
        required::<Option<Uuid>>(&row, "requester_step_up_grant_id")?.ok_or(ManagementBackendError::Precondition)?;
    consume_step_up_in(transaction, principal, requester_grant, "device_rebuild").await?;
    let approved_by: Uuid = sqlx::query_scalar(
        "SELECT grant.approver_user_id FROM security.approval_grant grant \
         JOIN iam.user_account approver ON approver.id=grant.approver_user_id AND approver.status_code='active' \
         WHERE grant.approval_case_id=$1 AND grant.decision_code='approve' AND grant.approver_user_id<>$2 \
         ORDER BY grant.decided_at,grant.id LIMIT 1",
    )
    .bind(approval_id)
    .bind(requested_by)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?
    .ok_or(ManagementBackendError::Precondition)?;
    Ok((requested_by, approved_by))
}

fn device_rebuild_snapshot_digest(
    credential_id: Uuid,
    expected_revision: i64,
    expected_profile_epoch: i64,
    expected_device_epoch: i64,
    reason: &str,
) -> Result<[u8; 32], ManagementBackendError> {
    let bytes = canonical_json_bytes(&json!({
        "schema_version":1,
        "operation":"device_rebuild",
        "credential_id":credential_id,
        "expected_credential_revision":expected_revision,
        "expected_profile_epoch":expected_profile_epoch,
        "expected_device_epoch":expected_device_epoch,
        "reason":reason
    }))?;
    Ok(Sha256::digest(bytes).into())
}

fn transport_canary_evidence_valid(result: &serde_json::Value, manifest_hash: &[u8]) -> bool {
    let iterations = result.get("iterations").and_then(serde_json::Value::as_u64);
    let passed = result.get("passed_runs").and_then(serde_json::Value::as_u64);
    let sha256 = |field: &str| {
        result
            .get(field)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    };
    iterations.is_some_and(|count| count >= 20)
        && passed == iterations
        && result
            .get("decision")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("pass"))
        && result.get("hard_mismatch_count").and_then(serde_json::Value::as_u64) == Some(0)
        && result
            .get("bundle_sha256")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == lower_hex(manifest_hash))
        && result
            .pointer("/target/authority")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == "api.anthropic.com")
        && result
            .get("engine_build_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty() && value.len() <= 256)
        && sha256("report_sha256")
        && (sha256("replay_plan_sha256") || sha256("official_plan_sha256"))
}

fn decode_sha256_hex(value: &str) -> Result<[u8; 32], ManagementBackendError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManagementBackendError::InvalidInput);
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(ManagementBackendError::InvalidInput)?;
        let low = hex_nibble(pair[1]).ok_or(ManagementBackendError::InvalidInput)?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, ManagementBackendError> {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort_unstable();
                Value::Object(keys.into_iter().map(|key| (key.clone(), sort(&map[key]))).collect())
            }
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            scalar => scalar.clone(),
        }
    }
    serde_json::to_vec(&sort(value)).map_err(|_| ManagementBackendError::InvalidInput)
}

fn validate_upgrade_release_manifest(value: &Value) -> Result<(String, String), ManagementBackendError> {
    let manifest = value.as_object().ok_or(ManagementBackendError::InvalidInput)?;
    const FIELDS: &[&str] = &[
        "schema_version",
        "application",
        "application_version",
        "target",
        "created_at",
        "source_revision",
        "rust_toolchain",
        "runtime_abi_version",
        "testkit_abi_version",
        "schema_compatibility",
        "cargo_lock_sha256",
        "contract_tree_sha256",
        "migration_checksums",
        "artifacts",
    ];
    if manifest.len() != FIELDS.len() || manifest.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(ManagementBackendError::InvalidInput);
    }
    let text = |name: &str, max: usize| -> Result<&str, ManagementBackendError> {
        manifest
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty() && value.len() <= max)
            .ok_or(ManagementBackendError::InvalidInput)
    };
    if text("schema_version", 16)? != "1.0.0" || text("application", 64)? != "super-gatewayd" {
        return Err(ManagementBackendError::InvalidInput);
    }
    let release_version = text("application_version", 128)?.to_owned();
    let source_revision = text("source_revision", 256)?.to_owned();
    for digest in [text("cargo_lock_sha256", 64)?, text("contract_tree_sha256", 64)?] {
        decode_sha256_hex(digest)?;
    }
    let compatibility = manifest
        .get("schema_compatibility")
        .and_then(Value::as_object)
        .ok_or(ManagementBackendError::InvalidInput)?;
    let minimum = compatibility.get("minimum").and_then(Value::as_i64);
    let maximum = compatibility.get("maximum").and_then(Value::as_i64);
    if compatibility.len() != 2 || minimum.is_none() || maximum.is_none() || minimum > maximum {
        return Err(ManagementBackendError::InvalidInput);
    }
    let checksums = manifest
        .get("migration_checksums")
        .and_then(Value::as_object)
        .ok_or(ManagementBackendError::InvalidInput)?;
    if checksums.len() > 10_000
        || checksums.iter().any(|(name, digest)| {
            name.is_empty() || name.len() > 256 || digest.as_str().is_none_or(|value| decode_sha256_hex(value).is_err())
        })
    {
        return Err(ManagementBackendError::InvalidInput);
    }
    let artifacts = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty() && items.len() <= 128)
        .ok_or(ManagementBackendError::InvalidInput)?;
    if artifacts.iter().any(|item| {
        item.as_object().is_none_or(|artifact| {
            artifact.len() != 4
                || artifact.get("name").and_then(Value::as_str).is_none_or(str::is_empty)
                || artifact.get("path").and_then(Value::as_str).is_none_or(str::is_empty)
                || artifact
                    .get("sha256")
                    .and_then(Value::as_str)
                    .is_none_or(|digest| decode_sha256_hex(digest).is_err())
                || artifact.get("size_bytes").and_then(Value::as_u64).is_none()
        })
    }) {
        return Err(ManagementBackendError::InvalidInput);
    }
    Ok((release_version, source_revision))
}

fn validate_plan_mapping_value(value: &Value) -> Result<(), ManagementBackendError> {
    let mapping = value.as_object().ok_or(ManagementBackendError::InvalidInput)?;
    if mapping.len() > 1_000
        || mapping.iter().any(|(raw, normalized)| {
            raw.is_empty()
                || raw.len() > 256
                || normalized
                    .as_str()
                    .is_none_or(|normalized| normalized.is_empty() || normalized.len() > 128)
        })
    {
        return Err(ManagementBackendError::InvalidInput);
    }
    Ok(())
}

fn platform_key_full_audit_snapshot_digest(
    command: &PlatformKeyCreateCommand,
    owner_user_id: Uuid,
    group_id: Uuid,
) -> Result<[u8; 32], ManagementBackendError> {
    let mut endpoint_permissions = command.endpoint_permissions.clone();
    endpoint_permissions.sort_unstable();
    endpoint_permissions.dedup();
    let audit_grant = command.content_audit_expires_at.as_ref().map_or_else(
        || json!({"duration_days":7}),
        |expires_at| json!({"expires_at":expires_at}),
    );
    let projection = json!({
        "domain":"platform-key-full-audit-v1",
        "name":command.name.trim(),
        "owner_user_id":owner_user_id,
        "group_id":group_id,
        "expires_at":command.expires_at,
        "endpoint_permissions":endpoint_permissions,
        "body_limit_bytes":command.body_limit_bytes,
        "messages_rate":{"rpm":command.messages_rate.rpm,"burst":command.messages_rate.burst},
        "models_rate":{"rpm":command.models_rate.rpm,"burst":command.models_rate.burst},
        "concurrency":{"limit":command.concurrency.limit,"retry_after_ms":command.concurrency.retry_after_ms},
        "requested_content_audit":"full_encrypted",
        "content_audit_grant":audit_grant
    });
    Ok(Sha256::digest(canonical_json_bytes(&projection)?).into())
}

fn business_key_rotation_snapshot_digest(
    expected_key_version: i64,
    batch_size: i64,
) -> Result<[u8; 32], ManagementBackendError> {
    let projection = json!({
        "schema_version":1,
        "operation":"business_key_rotation",
        "provider":"database",
        "expected_key_version":expected_key_version,
        "batch_size":batch_size
    });
    Ok(Sha256::digest(canonical_json_bytes(&projection)?).into())
}

fn business_key_lifecycle_snapshot_digest(
    key_version: i64,
    target_state: &str,
    rotation_job_id: Uuid,
    backup_run_id: Uuid,
    restore_drill_id: Uuid,
) -> Result<[u8; 32], ManagementBackendError> {
    let projection = json!({
        "schema_version":1,
        "operation":"business_key_lifecycle",
        "provider":"database",
        "key_version":key_version,
        "target_state":target_state,
        "rotation_job_id":rotation_job_id,
        "backup_run_id":backup_run_id,
        "restore_drill_id":restore_drill_id
    });
    Ok(Sha256::digest(canonical_json_bytes(&projection)?).into())
}

async fn business_key_lifecycle_evidence_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key_version: i64,
    target_state: &str,
    rotation_job_id: Uuid,
    backup_run_id: Uuid,
    restore_drill_id: Uuid,
) -> Result<Vec<u8>, ManagementBackendError> {
    let expected_state = if target_state == "retired" {
        "decrypt_only"
    } else if target_state == "destroyed" {
        "retired"
    } else {
        return Err(ManagementBackendError::InvalidInput);
    };
    sqlx::query_scalar(
        "SELECT target.checksum \
         FROM security.business_key_material target \
         JOIN ops.durable_job rotation ON rotation.id=$3 \
         JOIN ops.backup_run backup ON backup.id=$4 \
         JOIN ops.restore_drill drill ON drill.id=$5 AND drill.backup_run_id=backup.id \
         JOIN security.business_key_material active ON active.provider_code='database' AND active.state_code='active' \
         WHERE target.key_version=$1 AND target.provider_code='database' AND target.state_code=$2 \
           AND rotation.kind_code='business_key_rotation' AND rotation.state_code='succeeded' \
           AND (rotation.payload->>'old_key_version')::bigint=target.key_version \
           AND COALESCE((rotation.checkpoint->>'remaining_old_references')::bigint,-1)=0 \
           AND backup.state_code='succeeded' AND backup.kind_code='base_backup' \
           AND backup.completed_at >= CASE WHEN $6='retired' THEN rotation.completed_at ELSE target.retired_at END \
           AND drill.state_code='succeeded' AND drill.kind_code='full_restore_drill' \
           AND drill.completed_at>=backup.completed_at \
           AND drill.checks #> '{business_key,active_version}'=to_jsonb(active.key_version) \
           AND COALESCE(drill.checks #> '{business_key,excluded_versions}','[]'::jsonb) \
               @> jsonb_build_array(target.key_version) \
           AND drill.checks #> '{business_key,live_reference_count}'='0'::jsonb \
           AND drill.checks #> '{business_key,decrypt_probe}'='true'::jsonb \
         FOR UPDATE OF target",
    )
    .bind(key_version)
    .bind(expected_state)
    .bind(rotation_job_id)
    .bind(backup_run_id)
    .bind(restore_drill_id)
    .bind(target_state)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?
    .ok_or(ManagementBackendError::Precondition)
}

fn approval_request_purpose(kind: &str) -> &'static str {
    match kind {
        "device_rebuild" => "device_rebuild",
        "key_provider_change" => "key_provider_change",
        "content_read" | "content_export" | "key_full_audit" | "group_audit_policy" | "legal_hold"
        | "manual_delete" => "content_audit_access",
        _ => "approval_decision",
    }
}

async fn require_step_up(
    storage: &PgStorage,
    principal: &ManagementPrincipal,
    grant_id: Uuid,
    purpose: &str,
) -> Result<(), ManagementBackendError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM iam.management_step_up_grant \
         WHERE id=$1 AND management_session_id=$2 AND user_id=$3 AND purpose_code=$4 \
           AND expires_at>clock_timestamp() AND consumed_at IS NULL)",
    )
    .bind(grant_id)
    .bind(parse_uuid(&principal.session_id)?)
    .bind(parse_uuid(&principal.user_id)?)
    .bind(purpose)
    .fetch_one(&storage.pool())
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?;
    if !exists {
        return Err(ManagementBackendError::Authorization);
    }
    Ok(())
}

async fn consume_step_up_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal: &ManagementPrincipal,
    grant_id: Uuid,
    purpose: &str,
) -> Result<(), ManagementBackendError> {
    let consumed = sqlx::query(
        "UPDATE iam.management_step_up_grant SET consumed_at=clock_timestamp() \
         WHERE id=$1 AND management_session_id=$2 AND user_id=$3 AND purpose_code=$4 \
           AND expires_at>clock_timestamp() AND consumed_at IS NULL",
    )
    .bind(grant_id)
    .bind(parse_uuid(&principal.session_id)?)
    .bind(parse_uuid(&principal.user_id)?)
    .bind(purpose)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?;
    if consumed.rows_affected() != 1 {
        return Err(ManagementBackendError::Authorization);
    }
    Ok(())
}

fn timestamp_text(row: &sqlx::postgres::PgRow, column: &str) -> Result<String, ManagementBackendError> {
    row.try_get(column).map_err(|_| ManagementBackendError::Unavailable)
}

async fn insert_secret(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    secret_id: Uuid,
    aad: &EnvelopeAad,
    envelope: &SecretEnvelope,
) -> Result<(), ManagementBackendError> {
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&envelope.ciphertext_base64)
        .map_err(|_| ManagementBackendError::Unavailable)?;
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(&envelope.nonce_base64)
        .map_err(|_| ManagementBackendError::Unavailable)?;
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(&envelope.wrapped_dek_base64)
        .map_err(|_| ManagementBackendError::Unavailable)?;
    sqlx::query(
        "INSERT INTO security.encrypted_secret \
         (id,secret_kind_code,provider_role_code,cipher_suite_code,ciphertext,nonce,wrapped_dek,key_version, \
          aad_schema_version,owner_type_code,owner_id,purpose_code,created_at) \
         VALUES ($1,$2,$3,'aes_256_gcm',$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp())",
    )
    .bind(secret_id)
    .bind(&aad.secret_kind)
    .bind(&aad.provider_role)
    .bind(ciphertext)
    .bind(nonce)
    .bind(wrapped)
    .bind(i64::try_from(aad.key_version).map_err(|_| ManagementBackendError::Unavailable)?)
    .bind(i32::try_from(aad.schema_version).map_err(|_| ManagementBackendError::Unavailable)?)
    .bind(&aad.owner_type)
    .bind(&aad.owner_id)
    .bind(&aad.purpose)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ManagementBackendError::Unavailable)?;
    Ok(())
}

fn row_envelope(
    row: &sqlx::postgres::PgRow,
    schema_version: u32,
    key_version: u64,
) -> Result<SecretEnvelope, ManagementBackendError> {
    Ok(SecretEnvelope {
        schema_version,
        cipher_suite: "aes_256_gcm".to_owned(),
        provider_role: "business".to_owned(),
        key_version,
        ciphertext_base64: base64::engine::general_purpose::STANDARD.encode(
            row.try_get::<Vec<u8>, _>("ciphertext")
                .map_err(|_| ManagementBackendError::Unavailable)?,
        ),
        nonce_base64: base64::engine::general_purpose::STANDARD.encode(
            row.try_get::<Vec<u8>, _>("nonce")
                .map_err(|_| ManagementBackendError::Unavailable)?,
        ),
        wrapped_dek_base64: base64::engine::general_purpose::STANDARD.encode(
            row.try_get::<Vec<u8>, _>("wrapped_dek")
                .map_err(|_| ManagementBackendError::Unavailable)?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

    use gateway_api::{ManagementBackend as _, ManagementPrincipal, ManagementRole};
    use gateway_domain::{
        AuthKind, CredentialPurpose, EnrollmentAuthMethod, EnrollmentMode, InternalReadiness, ManagementClass,
        SecretBytes, SecretValue,
    };
    use gateway_services::{
        ReadinessCoordinator,
        export::{ExportArtifactContext, ExportArtifactStore, ExportFormat, lower_hex},
        observability::DataPlaneObservability,
        security::hash_bootstrap_password,
    };
    use gateway_storage::{
        BootstrapAdminRecord, CredentialEnrollmentCreate, PgStorage, RuntimeRolePolicy, UsageExportArtifactCommit,
        embedded_migration_count,
    };
    use hmac::{Hmac, Mac as _};
    use sha1::Sha1;
    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;

    use super::{
        CompiledPolicyArtifact, ConcurrencyCommand, EnforcementSystemPayload, ExpirationPatch,
        GroupConfigCandidateCommand, GroupConfigLimitsCommand, GroupContentAuditCommand,
        GroupCredentialDefaultsCommand, GroupQueueCommand, GroupTimeoutsCommand, ManagementBackendError,
        ManagementRequest, PgManagementBackend, PlatformKeyCreateCommand, RateLimitCommand,
        business_key_rotation_snapshot_digest, compile_enforcement_system, decode_sha256_hex, group_proxy_policy,
        parse_platform_key_patch, platform_key_full_audit_snapshot_digest, transport_canary_evidence_valid,
        valid_nonnegative_decimal, validate_group_config_candidate, validate_policy_artifact_payload,
    };

    #[test]
    fn transport_canary_requires_twenty_exact_machine_bound_runs() {
        let manifest_hash = [0x11_u8; 32];
        let mut evidence = serde_json::json!({
            "iterations":20,
            "passed_runs":20,
            "decision":"PASS",
            "hard_mismatch_count":0,
            "bundle_sha256":lower_hex(&manifest_hash),
            "target":{"authority":"api.anthropic.com"},
            "engine_build_id":"gateway-transport/fixture",
            "report_sha256":"22".repeat(32),
            "replay_plan_sha256":"33".repeat(32)
        });
        assert!(transport_canary_evidence_valid(&evidence, &manifest_hash));
        evidence["iterations"] = serde_json::json!(19);
        evidence["passed_runs"] = serde_json::json!(19);
        assert!(!transport_canary_evidence_valid(&evidence, &manifest_hash));
        evidence["iterations"] = serde_json::json!(20);
        evidence["passed_runs"] = serde_json::json!(20);
        evidence["hard_mismatch_count"] = serde_json::json!(1);
        assert!(!transport_canary_evidence_valid(&evidence, &manifest_hash));
    }

    #[test]
    fn policy_artifact_payloads_are_typed_and_enforcement_replace_is_strict() {
        let background = serde_json::json!({
            "entries":[{
                "id":"health-v1","action":"observe","client_classes":["claude_code_cli"],
                "match_all":[{"kind":"body_equals","pointer":"/max_tokens","value":1}]
            }]
        });
        assert!(matches!(
            validate_policy_artifact_payload("background_catalog", &background),
            Ok(CompiledPolicyArtifact::Background(_))
        ));
        let invalid_replace = EnforcementSystemPayload {
            mode: "replace".to_owned(),
            platform_system_ref: None,
            content: Some(serde_json::json!("system")),
        };
        assert!(matches!(
            compile_enforcement_system(&invalid_replace),
            Err(ManagementBackendError::InvalidInput)
        ));
        let valid_replace = EnforcementSystemPayload {
            mode: "replace".to_owned(),
            platform_system_ref: Some("platform-system-v1".to_owned()),
            content: Some(serde_json::json!([{"type":"text","text":"system"}])),
        };
        assert!(compile_enforcement_system(&valid_replace).is_ok());
    }

    fn valid_group_config_candidate() -> GroupConfigCandidateCommand {
        GroupConfigCandidateCommand {
            accepted_client_classes: vec!["claude_code_cli".to_owned(), "non_claude_code_cli".to_owned()],
            fully_managed_required: true,
            egress_mode: "auto".to_owned(),
            limits: GroupConfigLimitsCommand {
                concurrency: Some(15),
                messages_rpm: Some(60),
                messages_burst: Some(10),
            },
            credential_defaults: GroupCredentialDefaultsCommand {
                concurrency: 5,
                messages_rpm: 60,
            },
            queue: GroupQueueCommand {
                pre_upstream_timeout_ms: 30_000,
            },
            timeouts: GroupTimeoutsCommand {
                upstream_connect_ms: 30_000,
                upstream_non_stream_total_ms: 300_000,
                upstream_stream_idle_ms: 30_000,
            },
            content_audit: GroupContentAuditCommand {
                policy: "forbid".to_owned(),
                retention_days: 30,
            },
        }
    }

    #[test]
    fn group_config_candidate_validation_preserves_product_bounds() {
        let mut candidate = valid_group_config_candidate();
        assert!(validate_group_config_candidate(&candidate).is_ok());
        assert_eq!(group_proxy_policy("direct_only"), Ok("direct"));
        assert_eq!(group_proxy_policy("proxy_only"), Ok("proxy_required"));

        candidate.accepted_client_classes.push("claude_code_cli".to_owned());
        assert_eq!(
            validate_group_config_candidate(&candidate),
            Err(ManagementBackendError::InvalidInput)
        );

        candidate = valid_group_config_candidate();
        candidate.limits.messages_burst = None;
        assert_eq!(
            validate_group_config_candidate(&candidate),
            Err(ManagementBackendError::InvalidInput)
        );

        candidate = valid_group_config_candidate();
        candidate.timeouts.upstream_connect_ms = 999;
        assert_eq!(
            validate_group_config_candidate(&candidate),
            Err(ManagementBackendError::InvalidInput)
        );

        candidate = valid_group_config_candidate();
        candidate.egress_mode = "shared_proxy_fallback".to_owned();
        assert_eq!(
            validate_group_config_candidate(&candidate),
            Err(ManagementBackendError::InvalidInput)
        );
    }

    #[test]
    fn price_decimal_is_nonnegative_plain_and_bounded() {
        for valid in ["0", "3", "3.0", "15.000000000000"] {
            assert!(valid_nonnegative_decimal(valid), "{valid}");
        }
        for invalid in ["", "-1", "+1", ".1", "1.", "1e3", "1.0000000000000", "1.2.3"] {
            assert!(!valid_nonnegative_decimal(invalid), "{invalid}");
        }
    }

    #[test]
    fn platform_key_patch_preserves_absent_and_explicit_null() -> Result<(), Box<dyn std::error::Error>> {
        let absent = parse_platform_key_patch(&request(
            "patchPlatformKeysById",
            serde_json::json!({"name":" renamed "}),
        ))?;
        assert_eq!(absent.name.as_deref(), Some("renamed"));
        assert_eq!(absent.expires_at, ExpirationPatch::Unchanged);

        let cleared = parse_platform_key_patch(&request(
            "patchPlatformKeysById",
            serde_json::json!({"expires_at":null}),
        ))?;
        assert_eq!(cleared.name, None);
        assert_eq!(cleared.expires_at, ExpirationPatch::Clear);

        assert!(
            parse_platform_key_patch(&request(
                "patchPlatformKeysById",
                serde_json::json!({"group_id":Uuid::now_v7()})
            ))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn full_audit_snapshot_is_canonical_and_field_bound() -> Result<(), Box<dyn std::error::Error>> {
        let owner_id = Uuid::now_v7();
        let group_id = Uuid::now_v7();
        let first = full_audit_command(vec!["models".to_owned(), "messages".to_owned()], 60);
        let reordered = full_audit_command(vec!["messages".to_owned(), "models".to_owned()], 60);
        let changed = full_audit_command(vec!["messages".to_owned(), "models".to_owned()], 61);
        assert_eq!(
            platform_key_full_audit_snapshot_digest(&first, owner_id, group_id)?,
            platform_key_full_audit_snapshot_digest(&reordered, owner_id, group_id)?
        );
        assert_ne!(
            platform_key_full_audit_snapshot_digest(&first, owner_id, group_id)?,
            platform_key_full_audit_snapshot_digest(&changed, owner_id, group_id)?
        );
        assert!(decode_sha256_hex(&"ab".repeat(32)).is_ok());
        assert!(decode_sha256_hex(&"AB".repeat(32)).is_err());
        assert!(decode_sha256_hex("ab").is_err());
        assert_ne!(
            business_key_rotation_snapshot_digest(1, 256)?,
            business_key_rotation_snapshot_digest(1, 257)?
        );
        assert_ne!(
            business_key_rotation_snapshot_digest(1, 256)?,
            business_key_rotation_snapshot_digest(2, 256)?
        );
        Ok(())
    }

    fn full_audit_command(endpoint_permissions: Vec<String>, messages_rpm: u64) -> PlatformKeyCreateCommand {
        PlatformKeyCreateCommand {
            name: " full-audit-key ".to_owned(),
            owner_user_id: Uuid::nil().to_string(),
            group_id: Uuid::nil().to_string(),
            expires_at: None,
            endpoint_permissions,
            body_limit_bytes: 67_108_864,
            messages_rate: RateLimitCommand {
                rpm: messages_rpm,
                burst: 10,
            },
            models_rate: RateLimitCommand { rpm: 60, burst: 10 },
            concurrency: ConcurrencyCommand {
                limit: 5,
                retry_after_ms: 2_000,
            },
            requested_content_audit: "full_encrypted".to_owned(),
            content_audit_approval_case_id: Some(Uuid::nil().to_string()),
            content_audit_expires_at: None,
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn r8_postgres_auth_key_reveal_and_runtime_projection() -> Result<(), Box<dyn std::error::Error>> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let Ok(database_url) = std::env::var("TEST_R8_DATABASE_ADMIN_URL") else {
            return Ok(());
        };
        let database_url = SecretValue::new(database_url);
        let report = PgStorage::migrate(&database_url).await?;
        assert_eq!(report.applied_count, embedded_migration_count());
        let storage = Arc::new(PgStorage::connect(&database_url, RuntimeRolePolicy::AllowPrivilegedTest).await?);
        storage.ensure_database_business_key().await?;
        let admin_id = Uuid::now_v7();
        let temporary_password = "R8-temporary-password-01";
        storage
            .bootstrap_admin(Some(BootstrapAdminRecord {
                user_id: admin_id,
                password_credential_id: Uuid::now_v7(),
                username: "r8-admin".to_owned(),
                username_normalized: "r8-admin".to_owned(),
                display_name: Some("R8 Administrator".to_owned()),
                email: None,
                email_normalized: None,
                password_phc: hash_bootstrap_password(&SecretValue::new(temporary_password.to_owned()))?,
            }))
            .await?;
        let digest_key = SecretBytes::new(b"r8-digest-key-fixture-32-bytes!!".to_vec());
        let export_store = Arc::new(ExportArtifactStore::new(
            std::env::temp_dir().join(format!("gateway-r8-export-{}", Uuid::now_v7().simple())),
        ));
        export_store.preflight().await?;
        let backend = PgManagementBackend::new(
            storage.clone(),
            SecretBytes::new(digest_key.expose().to_vec()),
            ReadinessCoordinator::new(InternalReadiness::default()),
            DataPlaneObservability::default(),
            crate::operations::IntegrityGuard::new(true),
            export_store.clone(),
            None,
            gateway_api::ManagementRuntimeBridge::new(
                Arc::new(gateway_api::DenyAllAccessResolver),
                Arc::new(gateway_api::StaticModelCatalog::new(Vec::new())),
            ),
            None,
            None,
            false,
        )?;
        let login = backend
            .login(&request(
                "postAuthLogin",
                serde_json::json!({"username":"r8-admin","password":temporary_password}),
            ))
            .await?;
        let login_token = login.session_cookie.ok_or("login cookie")?;
        let login_principal = backend.resolve_session(&login_token).await?.ok_or("login principal")?;
        assert!(login_principal.password_change_required);

        let changed = backend
            .change_password(
                &login_principal,
                &request(
                    "postAuthPasswordChange",
                    serde_json::json!({"current_password":temporary_password,"new_password":"R8-new-password-strong-02"}),
                ),
            )
            .await?;
        let changed_token = changed.session_cookie.ok_or("changed cookie")?;
        assert!(backend.resolve_session(&login_token).await?.is_none());
        let changed_principal = backend
            .resolve_session(&changed_token)
            .await?
            .ok_or("changed principal")?;
        assert!(!changed_principal.password_change_required);

        let enrollment = backend.enroll_mfa(&changed_principal).await?;
        let seed = enrollment.body["data"]["secret"].as_str().ok_or("totp seed")?;
        let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let confirmed = backend
            .verify_mfa(
                &changed_principal,
                &request(
                    "postAuthMfaEnrollmentsByIdConfirm",
                    serde_json::json!({"code":totp(seed, now)?}),
                ),
                true,
            )
            .await?;
        let confirmed_token = confirmed.session_cookie.ok_or("confirmed cookie")?;
        let confirmed_principal = backend
            .resolve_session(&confirmed_token)
            .await?
            .ok_or("confirmed principal")?;
        assert!(confirmed_principal.mfa_verified);

        let owner_body = serde_json::json!({
            "username":"r8-owner","display_name":"R8 Owner","email":"r8-owner@example.test",
            "role":"key_owner","temporary_password":"R8-owner-password-strong-03"
        });
        let owner = backend
            .execute(Some(&confirmed_principal), request("postUsers", owner_body.clone()))
            .await?;
        let owner_replay = backend
            .execute(Some(&confirmed_principal), request("postUsers", owner_body))
            .await?;
        assert_eq!(owner.body, owner_replay.body);
        let owner_id = Uuid::parse_str(owner.body["data"]["id"].as_str().ok_or("owner id")?)?;
        sqlx::query("UPDATE iam.user_account SET status_code='active' WHERE id=$1")
            .bind(owner_id)
            .execute(&storage.pool())
            .await?;
        let group = backend
            .create_group(
                &confirmed_principal,
                &request("postGroups", serde_json::json!({"name":"r8-group"})),
            )
            .await?;
        let group_id = Uuid::parse_str(group.body["data"]["id"].as_str().ok_or("group id")?)?;
        let credential_id = Uuid::now_v7();
        storage
            .create_credential_enrollment(&CredentialEnrollmentCreate {
                enrollment_id: Uuid::now_v7(),
                credential_id,
                group_id,
                created_by: Some(admin_id),
                mode: EnrollmentMode::Create,
                auth_method: EnrollmentAuthMethod::ConsoleApiKey,
                auth_kind: AuthKind::ConsoleApiKey,
                purpose: CredentialPurpose::Business,
                management_class: ManagementClass::NonManaged,
                recovery_credential_id: None,
                expected_credential_revision: None,
                expires_in_seconds: 1_800,
                callback_window_seconds: 600,
            })
            .await?;
        let mut scheduling_patch = request(
            "patchCredentialsByIdSchedulingConfig",
            serde_json::json!({"concurrency":7,"messages_rpm":77,"priority":9,"weight":3}),
        );
        scheduling_patch.method = axum::http::Method::PATCH;
        scheduling_patch.path = "/admin/v1/credentials/{id}/scheduling-config".into();
        scheduling_patch
            .path_parameters
            .insert("id".into(), credential_id.to_string().into());
        scheduling_patch.if_match = Some("\"rev-1\"".into());
        scheduling_patch.idempotency_key = None;
        let scheduling = backend.execute(Some(&confirmed_principal), scheduling_patch).await?;
        assert_eq!(scheduling.etag.as_deref(), Some("\"rev-2\""));
        assert_eq!(scheduling.body["data"]["concurrency"], 7);
        assert_eq!(scheduling.body["data"]["messages_rpm"], 77);
        assert_eq!(scheduling.body["data"]["priority"], 9);
        assert_eq!(scheduling.body["data"]["weight"], 3);
        assert_eq!(scheduling.body["data"]["pointer_revision"], 2);
        let mut reset_patch = request(
            "patchCredentialsByIdSchedulingConfig",
            serde_json::json!({"concurrency":null,"messages_rpm":null}),
        );
        reset_patch.method = axum::http::Method::PATCH;
        reset_patch.path = "/admin/v1/credentials/{id}/scheduling-config".into();
        reset_patch
            .path_parameters
            .insert("id".into(), credential_id.to_string().into());
        reset_patch.if_match = Some("\"rev-2\"".into());
        reset_patch.idempotency_key = None;
        let reset = backend.execute(Some(&confirmed_principal), reset_patch).await?;
        assert_eq!(reset.etag.as_deref(), Some("\"rev-3\""));
        assert_eq!(reset.body["data"]["concurrency"], 5);
        assert_eq!(reset.body["data"]["messages_rpm"], 60);
        assert_eq!(reset.body["data"]["pointer_revision"], 3);
        let scheduling_audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM security.audit_event WHERE action_code='credential_scheduling_config_updated' \
             AND object_id=$1",
        )
        .bind(credential_id.to_string())
        .fetch_one(&storage.pool())
        .await?;
        assert_eq!(scheduling_audits, 2);
        let model_definition_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO catalog.model_definition \
             (id,upstream_model_id,display_name,lifecycle_code,first_seen_at,last_seen_at,revision) \
             VALUES ($1,'claude-r8-fixture','Claude R8 Fixture','published',clock_timestamp(),clock_timestamp(),1)",
        )
        .bind(model_definition_id)
        .execute(&storage.pool())
        .await?;
        sqlx::query(
            "INSERT INTO catalog.model_capability \
             (id,model_id,capability_version,lifecycle_code,schema_payload,content_hash,created_at,activated_at) \
             VALUES ($1,$2,1,'active',$3,$4,clock_timestamp(),clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(model_definition_id)
        .bind(serde_json::json!({"rules":[
            {"id":"model","path":"body:/model","action":"required","types":["string"],"enum_values":[],
             "minimum":null,"maximum":null,"required_children":[],"when":{"op":"always"}},
            {"id":"max_tokens","path":"body:/max_tokens","action":"required","types":["integer"],"enum_values":[],
             "minimum":1,"maximum":null,"required_children":[],"when":{"op":"always"}},
            {"id":"messages","path":"body:/messages","action":"required","types":["array"],"enum_values":[],
             "minimum":null,"maximum":null,"required_children":[],"when":{"op":"always"}},
            {"id":"stream","path":"body:/stream","action":"allowed","types":["boolean"],"enum_values":[],
             "minimum":null,"maximum":null,"required_children":[],"when":{"op":"always"}},
            {"id":"system","path":"body:/system","action":"allowed","types":["string","array"],"enum_values":[],
             "minimum":null,"maximum":null,"required_children":[],"when":{"op":"always"}}
        ]}))
        .bind(vec![0x42_u8; 32])
        .execute(&storage.pool())
        .await?;
        let created = backend
            .create_platform_key(
                &confirmed_principal,
                &request(
                    "postPlatformKeys",
                    serde_json::json!({
                        "name":"r8-key","owner_user_id":owner_id,"group_id":group_id,"expires_at":null,
                        "endpoint_permissions":["messages","models"],"body_limit_bytes":67_108_864,
                        "messages_rate":{"rpm":60,"burst":10},"models_rate":{"rpm":60,"burst":10},
                        "concurrency":{"limit":5,"retry_after_ms":2000},"requested_content_audit":"metadata_only"
                    }),
                ),
            )
            .await?;
        let key_id = Uuid::parse_str(created.body["data"]["id"].as_str().ok_or("key id")?)?;

        let elevated = backend
            .step_up(
                &confirmed_principal,
                &request(
                    "postAuthStepUp",
                    serde_json::json!({
                        "purpose":"key_secret_reveal",
                        "current_password":"R8-new-password-strong-02",
                        "totp_code":totp(seed, now+30)?
                    }),
                ),
            )
            .await?;
        let grant_id = elevated.body["data"]["id"].as_str().ok_or("grant id")?.to_owned();
        let elevated_token = elevated.session_cookie.ok_or("elevated cookie")?;
        let elevated_principal = backend
            .resolve_session(&elevated_token)
            .await?
            .ok_or("elevated principal")?;
        let revealed = backend
            .reveal_platform_key(
                &elevated_principal,
                &request_with_path(
                    "postPlatformKeysByIdReveal",
                    serde_json::json!({"step_up_grant_id":grant_id,"reason":"configure owner workstation"}),
                    key_id,
                ),
            )
            .await?;
        let plaintext = SecretValue::new(revealed.body["data"]["secret"].as_str().ok_or("secret")?.to_owned());
        assert!(plaintext.expose().starts_with("sgw_v1_"));
        assert!(matches!(
            backend
                .reveal_platform_key(
                    &elevated_principal,
                    &request_with_path(
                        "postPlatformKeysByIdReveal",
                        serde_json::json!({"step_up_grant_id":grant_id,"reason":"replay must fail"}),
                        key_id,
                    ),
                )
                .await,
            Err(gateway_api::ManagementBackendError::Authorization)
        ));
        let reveal_audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security.audit_event WHERE action_code='platform_key_secret_revealed' \
             AND object_type_code='platform_key_secret_reveal'",
        )
        .fetch_one(&storage.pool())
        .await?;
        assert_eq!(reveal_audits, 1);
        let (access, models) = crate::app::load_access_snapshot(&storage, digest_key).await?;
        let grant = access.resolve(&plaintext).ok_or("runtime grant")?;
        assert_eq!(grant.concurrency_limit, 5);
        assert_eq!(grant.platform_key_id.as_str(), key_id.to_string().as_str());
        assert_eq!(models.published().len(), 1);

        let newest_notification_id = Uuid::now_v7();
        let older_notification_id = Uuid::now_v7();
        let owner_notification_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO ops.notification_inbox \
             (id,user_id,alert_id,severity_code,title,summary,read_at,created_at) VALUES \
             ($1,$2,NULL,'critical','Critical fixture','newest admin notification',NULL,clock_timestamp()), \
             ($3,$2,NULL,'warning','Warning fixture','older admin notification',NULL,clock_timestamp()-interval '1 minute'), \
             ($4,$5,NULL,'info','Owner fixture','must remain invisible',NULL,clock_timestamp())",
        )
        .bind(newest_notification_id)
        .bind(admin_id)
        .bind(older_notification_id)
        .bind(owner_notification_id)
        .bind(owner_id)
        .execute(&storage.pool())
        .await?;

        let notifications = backend
            .execute(
                Some(&confirmed_principal),
                read_request("getNotifications", "/admin/v1/notifications", None),
            )
            .await?;
        let notification_rows = notifications.body["data"].as_array().ok_or("notification rows")?;
        assert_eq!(notification_rows.len(), 2);
        assert_eq!(notification_rows[0]["id"], newest_notification_id.to_string());
        assert_eq!(notification_rows[1]["id"], older_notification_id.to_string());
        assert!(
            notification_rows
                .iter()
                .all(|row| row["id"] != owner_notification_id.to_string())
        );

        let marked = backend
            .execute(
                Some(&confirmed_principal),
                mutation_request(
                    "postNotificationsByIdRead",
                    "/admin/v1/notifications/{id}:read",
                    newest_notification_id,
                    1,
                ),
            )
            .await?;
        assert_eq!(marked.etag.as_deref(), Some("\"rev-2\""));
        assert!(marked.body["data"]["read_at"].is_string());
        assert!(matches!(
            backend
                .execute(
                    Some(&confirmed_principal),
                    mutation_request(
                        "postNotificationsByIdRead",
                        "/admin/v1/notifications/{id}:read",
                        newest_notification_id,
                        1,
                    ),
                )
                .await,
            Err(gateway_api::ManagementBackendError::Precondition)
        ));
        let read_all = backend
            .execute(
                Some(&confirmed_principal),
                mutation_request_without_id("postNotificationsReadAll", "/admin/v1/notifications:read-all"),
            )
            .await?;
        assert_eq!(read_all.body["data"]["updated_count"], 1);
        let owner_notification_unread: bool =
            sqlx::query_scalar("SELECT read_at IS NULL FROM ops.notification_inbox WHERE id=$1")
                .bind(owner_notification_id)
                .fetch_one(&storage.pool())
                .await?;
        assert!(owner_notification_unread);

        let job_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO ops.durable_job \
             (id,kind_code,idempotency_key,state_code,payload_schema_version,payload,checkpoint,run_after, \
              lease_generation,attempt_count,max_attempts,created_at,updated_at) \
             VALUES ($1,'model_catalog_discovery_v1',$2,'scheduled',1,$3,$4,clock_timestamp(),0,0,3,clock_timestamp(),clock_timestamp())",
        )
        .bind(job_id)
        .bind(format!("r9-admin-fixture-{job_id}"))
        .bind(serde_json::json!({"fixture":true}))
        .bind(serde_json::json!({"phase":"queued"}))
        .execute(&storage.pool())
        .await?;
        sqlx::query(
            "INSERT INTO ops.durable_job_history \
             (id,job_id,from_state_code,to_state_code,lease_generation,outcome_code,detail,occurred_at) \
             VALUES ($1,$2,NULL,'scheduled',0,'created',$3,clock_timestamp())",
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(serde_json::json!({"source":"admin_backend_test"}))
        .execute(&storage.pool())
        .await?;

        let jobs = backend
            .execute(
                Some(&confirmed_principal),
                read_request("getOperationsJobs", "/admin/v1/operations/jobs", None),
            )
            .await?;
        let job = jobs.body["data"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == job_id.to_string()))
            .ok_or("fixture job in list")?;
        assert_eq!(job["kind"], "model_catalog_discovery_v1");
        assert_eq!(job["state"], "scheduled");
        assert!(job.get("checkpoint").is_none());

        let job_detail = backend
            .execute(
                Some(&confirmed_principal),
                read_request("getOperationsJobsById", "/admin/v1/operations/jobs/{id}", Some(job_id)),
            )
            .await?;
        assert_eq!(job_detail.etag.as_deref(), Some("\"rev-1\""));
        assert_eq!(
            job_detail.body["data"]["checkpoint"],
            serde_json::json!({"phase":"queued"})
        );
        assert_eq!(job_detail.body["data"]["history"][0]["outcome"], "created");
        assert!(matches!(
            backend
                .execute(Some(&confirmed_principal), job_cancel_request(job_id, 2),)
                .await,
            Err(gateway_api::ManagementBackendError::Precondition)
        ));
        let cancelled = backend
            .execute(Some(&confirmed_principal), job_cancel_request(job_id, 1))
            .await?;
        assert_eq!(cancelled.body["data"]["state"], "cancelled");
        assert_eq!(cancelled.etag.as_deref(), Some("\"rev-1\""));
        let cancelled_state: (String, bool) =
            sqlx::query_as("SELECT state_code,completed_at IS NOT NULL FROM ops.durable_job WHERE id=$1")
                .bind(job_id)
                .fetch_one(&storage.pool())
                .await?;
        assert_eq!(cancelled_state, ("cancelled".to_owned(), true));
        let cancel_outcome: Option<String> = sqlx::query_scalar(
            "SELECT outcome_code FROM ops.durable_job_history WHERE job_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT 1",
        )
        .bind(job_id)
        .fetch_one(&storage.pool())
        .await?;
        assert_eq!(cancel_outcome.as_deref(), Some("cancelled"));

        let alert_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO ops.alert \
             (id,fingerprint,severity_code,type_code,state_code,summary,detail,first_seen_at,last_seen_at,revision) \
             VALUES ($1,$2,'critical','r9_fixture','open','R9 alert fixture','{}'::jsonb,clock_timestamp(),clock_timestamp(),1)",
        )
        .bind(alert_id)
        .bind(format!("r9-alert-{alert_id}"))
        .execute(&storage.pool())
        .await?;
        let acknowledged = backend
            .alert_action(
                &confirmed_principal,
                &request_with_path(
                    "postAlertsByIdAcknowledge",
                    serde_json::json!({"reason":"operator investigating","expected_revision":1}),
                    alert_id,
                ),
                "acknowledged",
            )
            .await?;
        assert_eq!(acknowledged.body["data"]["state"], "acknowledged");
        assert_eq!(acknowledged.etag.as_deref(), Some("\"rev-2\""));
        let mut resolve_request = request_with_path(
            "postAlertsByIdResolve",
            serde_json::json!({"reason":"fixture condition cleared","expected_revision":2}),
            alert_id,
        );
        resolve_request.if_match = Some("\"rev-2\"".into());
        let resolved = backend
            .alert_action(&confirmed_principal, &resolve_request, "resolved")
            .await?;
        assert_eq!(resolved.body["data"]["state"], "resolved");
        assert!(resolved.body["data"]["resolved_at"].is_string());

        let silence_expiry: String = sqlx::query_scalar("SELECT (clock_timestamp()+interval '1 hour')::text")
            .fetch_one(&storage.pool())
            .await?;
        let silence = backend
            .create_alert_silence(
                &confirmed_principal,
                &request(
                    "postAlertSilences",
                    serde_json::json!({
                        "fingerprint_pattern":"r9-alert-*",
                        "reason":"planned maintenance",
                        "expires_at":silence_expiry
                    }),
                ),
            )
            .await?;
        let silence_id = Uuid::parse_str(silence.body["data"]["id"].as_str().ok_or("silence id")?)?;
        assert_eq!(silence.etag.as_deref(), Some("\"rev-1\""));
        assert!(silence.body["data"]["active"].as_bool().unwrap_or(false));
        let silence_detail = backend
            .get_alert_silence(
                &confirmed_principal,
                &read_request(
                    "getAlertSilencesById",
                    "/admin/v1/alert-silences/{id}",
                    Some(silence_id),
                ),
            )
            .await?;
        assert_eq!(silence_detail.body["data"]["fingerprint_pattern"], "r9-alert-*");
        let ended = backend
            .end_alert_silence(
                &confirmed_principal,
                &request_with_path(
                    "postAlertSilencesByIdEnd",
                    serde_json::json!({"reason":"maintenance complete","expected_revision":1}),
                    silence_id,
                ),
            )
            .await?;
        assert_eq!(ended.etag.as_deref(), Some("\"rev-2\""));
        assert_eq!(ended.body["data"]["active"], false);
        let alert_audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM security.audit_event WHERE action_code IN \
             ('alert_acknowledged','alert_resolved','alert_silence_created','alert_silence_ended') \
             AND object_id IN ($1,$2)",
        )
        .bind(alert_id.to_string())
        .bind(silence_id.to_string())
        .fetch_one(&storage.pool())
        .await?;
        assert_eq!(alert_audits, 4);

        // An owner requesting `all` is forcibly narrowed to `own`.  The
        // requester boundary remains in force even for another administrator,
        // and the generated artifact is cryptographically consumed once.
        let owner_principal = ManagementPrincipal {
            user_id: owner_id.to_string().into_boxed_str(),
            session_id: Uuid::now_v7().to_string().into_boxed_str(),
            role: ManagementRole::KeyOwner,
            csrf_token: SecretValue::new("r8-export-csrf".to_owned()),
            mfa_verified: true,
            password_change_required: false,
        };
        let export = backend
            .create_usage_export(
                &owner_principal,
                &request(
                    "postExports",
                    serde_json::json!({
                        "dataset":"usage_requests_v1","format":"jsonl","scope":"all",
                        "from":"2000-01-01T00:00:00Z","to":"2000-01-02T00:00:00Z",
                        "filters":{}
                    }),
                ),
            )
            .await?;
        assert_eq!(export.status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(export.body["data"]["scope"], "own");
        let export_id = Uuid::parse_str(export.body["data"]["id"].as_str().ok_or("export id")?)?;
        let export_job_id = Uuid::parse_str(export.body["data"]["job_id"].as_str().ok_or("export job id")?)?;
        assert!(matches!(
            backend
                .get_usage_export(
                    &confirmed_principal,
                    &read_request("getExportsById", "/admin/v1/exports/{id}", Some(export_id)),
                )
                .await,
            Err(gateway_api::ManagementBackendError::NotFound)
        ));

        let export_generation: i64 = sqlx::query_scalar(
            "UPDATE ops.durable_job SET state_code='leased',lease_owner='r8-export-worker', \
               lease_generation=lease_generation+1,lease_expires_at=clock_timestamp()+interval '1 minute', \
               attempt_count=attempt_count+1,updated_at=clock_timestamp() WHERE id=$1 AND state_code='scheduled' \
             RETURNING lease_generation",
        )
        .bind(export_job_id)
        .fetch_one(&storage.pool())
        .await?;
        let work = storage
            .start_usage_export(export_id, export_job_id, export_generation)
            .await?;
        assert_eq!(work.scope, "own");
        assert!(work.rows.is_empty());
        let key_version: i64 = sqlx::query_scalar(
            "SELECT key_version FROM security.business_key_material WHERE state_code='active' ORDER BY key_version DESC LIMIT 1",
        )
        .fetch_one(&storage.pool())
        .await?;
        let root_key = storage.load_database_business_key(key_version).await?;
        let artifact_context = ExportArtifactContext {
            export_id,
            requested_by: owner_id,
            dataset: "usage_requests_v1".into(),
            format: ExportFormat::Jsonl,
            query_sha256_hex: lower_hex(&work.query_sha256).into_boxed_str(),
        };
        let manifest = export_store.put(&artifact_context, b"", &root_key, key_version).await?;
        storage
            .commit_usage_export(&UsageExportArtifactCommit {
                export_id,
                job_id: export_job_id,
                generation: export_generation,
                object_uri: manifest.object_uri.to_string(),
                content_sha256: manifest.content_sha256.clone(),
                row_count: 0,
                content_length: manifest.content_length,
                cipher_suite: manifest.cipher_suite.to_string(),
                nonce: manifest.nonce.clone(),
                wrapped_dek: manifest.wrapped_dek.clone(),
                key_version,
            })
            .await?;
        let ready_export = backend
            .get_usage_export(
                &owner_principal,
                &read_request("getExportsById", "/admin/v1/exports/{id}", Some(export_id)),
            )
            .await?;
        assert_eq!(ready_export.body["data"]["download_available"], true);
        assert!(matches!(
            backend
                .download_usage_export(
                    &confirmed_principal,
                    &read_request(
                        "getExportsByIdDownload",
                        "/admin/v1/exports/{id}/download",
                        Some(export_id)
                    ),
                )
                .await,
            Err(gateway_api::ManagementBackendError::NotFound)
        ));
        let downloaded = backend
            .download_usage_export(
                &owner_principal,
                &read_request(
                    "getExportsByIdDownload",
                    "/admin/v1/exports/{id}/download",
                    Some(export_id),
                ),
            )
            .await?;
        assert!(downloaded.body.is_empty());
        assert_eq!(downloaded.content_type.as_ref(), "application/x-ndjson");
        assert!(matches!(
            backend
                .download_usage_export(
                    &owner_principal,
                    &read_request(
                        "getExportsByIdDownload",
                        "/admin/v1/exports/{id}/download",
                        Some(export_id)
                    ),
                )
                .await,
            Err(gateway_api::ManagementBackendError::NotFound)
        ));
        let consumed: (String, i32, bool, bool, bool) = sqlx::query_as(
            "SELECT state_code,download_count,object_uri IS NULL,nonce IS NULL,wrapped_dek IS NULL \
             FROM ops.export_job WHERE id=$1",
        )
        .bind(export_id)
        .fetch_one(&storage.pool())
        .await?;
        assert_eq!(consumed, ("expired".to_owned(), 1, true, true, true));
        let download_audits: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM security.audit_event WHERE action_code='usage_export_downloaded' AND object_id=$1",
        )
        .bind(export_id.to_string())
        .fetch_one(&storage.pool())
        .await?;
        assert_eq!(download_audits, 1);

        let backup_grant_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO iam.management_step_up_grant \
             (id,management_session_id,user_id,purpose_code,auth_context_digest,verified_at,expires_at,created_at) \
             VALUES ($1,$2,$3,'backup_restore_security',$4,clock_timestamp(),clock_timestamp()+interval '5 minutes',clock_timestamp())",
        )
        .bind(backup_grant_id)
        .bind(Uuid::parse_str(&elevated_principal.session_id)?)
        .bind(admin_id)
        .bind(vec![0x61_u8; 32])
        .execute(&storage.pool())
        .await?;
        let backup_job = backend
            .create_backup_job(
                &elevated_principal,
                &request(
                    "postOperationsBackupJobs",
                    serde_json::json!({
                        "step_up_grant_id":backup_grant_id,
                        "reason":"R9 isolated restore evidence fixture"
                    }),
                ),
            )
            .await?;
        assert_eq!(backup_job.status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(backup_job.body["data"]["status"], "queued");
        let backup_job_id = Uuid::parse_str(backup_job.body["data"]["id"].as_str().ok_or("backup job id")?)?;
        let backup_run_id: Uuid = sqlx::query_scalar("SELECT id FROM ops.backup_run WHERE durable_job_id=$1")
            .bind(backup_job_id)
            .fetch_one(&storage.pool())
            .await?;
        let manifest = serde_json::json!({"database_system_id":"r8-system","timeline":1,"lsn":"0/1"});
        let manifest_sha256 = Sha256::digest(serde_json::to_vec(&manifest)?).to_vec();
        sqlx::query(
            "UPDATE ops.backup_run SET state_code='succeeded',manifest=$2,manifest_sha256=$3, \
               database_system_id='r8-system',timeline=1,lsn_start='0/1',lsn_end='0/2',wal_archived_at=clock_timestamp(),watermarks=$4, \
               backup_key_version=1,repository_ref='fixture-repository',bytes_written=128, \
               started_at=clock_timestamp(),completed_at=clock_timestamp(),revision=revision+1 WHERE id=$1",
        )
        .bind(backup_run_id)
        .bind(&manifest)
        .bind(&manifest_sha256)
        .bind(serde_json::json!({"deletion_ledger":0,"audit_seal":"fixture"}))
        .execute(&storage.pool())
        .await?;
        let backup_detail = backend
            .get_backup_run(
                &elevated_principal,
                &read_request(
                    "getOperationsBackupRunsById",
                    "/admin/v1/operations/backup-runs/{id}",
                    Some(backup_run_id),
                ),
            )
            .await?;
        assert_eq!(backup_detail.body["data"]["state"], "succeeded");
        assert!(matches!(
            backend.list_backup_runs(&owner_principal).await,
            Err(gateway_api::ManagementBackendError::NotFound)
        ));

        let validation_grant_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO iam.management_step_up_grant \
             (id,management_session_id,user_id,purpose_code,auth_context_digest,verified_at,expires_at,created_at) \
             VALUES ($1,$2,$3,'backup_restore_security',$4,clock_timestamp(),clock_timestamp()+interval '5 minutes',clock_timestamp())",
        )
        .bind(validation_grant_id)
        .bind(Uuid::parse_str(&elevated_principal.session_id)?)
        .bind(admin_id)
        .bind(vec![0x62_u8; 32])
        .execute(&storage.pool())
        .await?;
        let validation_job = backend
            .create_restore_operation(
                &elevated_principal,
                &request(
                    "postOperationsRestoreValidations",
                    serde_json::json!({
                        "backup_run_id":backup_run_id,
                        "step_up_grant_id":validation_grant_id,
                        "reason":"validate R9 backup fixture"
                    }),
                ),
                "manifest_validation",
            )
            .await?;
        assert_eq!(validation_job.body["data"]["type"], "restore_manifest_validation");
        let validation_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM ops.restore_drill WHERE backup_run_id=$1 AND kind_code='manifest_validation' \
             AND state_code='queued'",
        )
        .bind(backup_run_id)
        .fetch_one(&storage.pool())
        .await?;
        assert_eq!(validation_count, 1);

        let revoke_grant_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO iam.management_step_up_grant \
             (id,management_session_id,user_id,purpose_code,auth_context_digest,verified_at,expires_at,created_at) \
             VALUES ($1,$2,$3,'irreversible_lifecycle',$4,clock_timestamp(),clock_timestamp()+interval '5 minutes',clock_timestamp())",
        )
        .bind(revoke_grant_id)
        .bind(Uuid::parse_str(&elevated_principal.session_id)?)
        .bind(Uuid::parse_str(&elevated_principal.user_id)?)
        .bind(vec![0x7a_u8; 32])
        .execute(&storage.pool())
        .await?;
        let revoke_request = request_with_path(
            "postPlatformKeysByIdRevoke",
            serde_json::json!({
                "reason":"credential retired by owner",
                "step_up_grant_id":revoke_grant_id,
                "expected_revision":1
            }),
            key_id,
        );
        let revoked = backend
            .platform_key_lifecycle(&elevated_principal, &revoke_request, "revoked")
            .await?;
        assert_eq!(revoked.body["data"]["status"], "revoked");
        assert!(matches!(
            backend
                .platform_key_lifecycle(&elevated_principal, &revoke_request, "revoked")
                .await,
            Err(gateway_api::ManagementBackendError::Authorization)
        ));
        let revoke_material: (bool, bool) = sqlx::query_as(
            "SELECT g.consumed_at IS NOT NULL,s.destroyed_at IS NOT NULL \
             FROM iam.management_step_up_grant g CROSS JOIN iam.platform_key k \
             JOIN security.encrypted_secret s ON s.id=k.secret_id WHERE g.id=$1 AND k.id=$2",
        )
        .bind(revoke_grant_id)
        .bind(key_id)
        .fetch_one(&storage.pool())
        .await?;
        assert_eq!(revoke_material, (true, true));
        Ok(())
    }

    fn request(operation: &str, body: serde_json::Value) -> ManagementRequest {
        ManagementRequest {
            operation_id: operation.into(),
            method: axum::http::Method::POST,
            path: "/admin/v1/test".into(),
            query: None,
            path_parameters: BTreeMap::new(),
            body: Some(body),
            idempotency_key: Some("r8-fixture-key".into()),
            if_match: None,
        }
    }

    fn request_with_path(operation: &str, body: serde_json::Value, id: Uuid) -> ManagementRequest {
        let mut request = request(operation, body);
        request.path_parameters.insert("id".into(), id.to_string().into());
        request.if_match = Some("\"rev-1\"".into());
        request
    }

    fn read_request(operation: &str, path: &str, id: Option<Uuid>) -> ManagementRequest {
        let mut request = request(operation, serde_json::Value::Null);
        request.method = axum::http::Method::GET;
        request.path = path.into();
        request.body = None;
        request.idempotency_key = None;
        if let Some(id) = id {
            request.path_parameters.insert("id".into(), id.to_string().into());
        }
        request
    }

    fn mutation_request(operation: &str, path: &str, id: Uuid, revision: i64) -> ManagementRequest {
        let mut request = request(operation, serde_json::json!({}));
        request.path = path.into();
        request.path_parameters.insert("id".into(), id.to_string().into());
        request.idempotency_key = None;
        request.if_match = Some(format!("\"rev-{revision}\"").into_boxed_str());
        request
    }

    fn job_cancel_request(id: Uuid, revision: i64) -> ManagementRequest {
        let mut request = mutation_request(
            "postOperationsJobsByIdCancel",
            "/admin/v1/operations/jobs/{id}:cancel",
            id,
            revision,
        );
        request.body = Some(serde_json::json!({"reason":"cancel queued fixture"}));
        request
    }

    fn mutation_request_without_id(operation: &str, path: &str) -> ManagementRequest {
        let mut request = request(operation, serde_json::json!({}));
        request.path = path.into();
        request.idempotency_key = None;
        request
    }

    fn totp(encoded: &str, unix_seconds: u64) -> Result<String, Box<dyn std::error::Error>> {
        let key = decode_base32(encoded)?;
        let mut mac = Hmac::<Sha1>::new_from_slice(&key)?;
        mac.update(&(unix_seconds / 30).to_be_bytes());
        let bytes = mac.finalize().into_bytes();
        let offset = usize::from(bytes[19] & 0x0f);
        let binary = (u32::from(bytes[offset] & 0x7f) << 24)
            | (u32::from(bytes[offset + 1]) << 16)
            | (u32::from(bytes[offset + 2]) << 8)
            | u32::from(bytes[offset + 3]);
        Ok(format!("{:06}", binary % 1_000_000))
    }

    fn decode_base32(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut output = Vec::new();
        let mut accumulator = 0_u32;
        let mut bits = 0_u8;
        for byte in value.bytes() {
            let digit = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'2'..=b'7' => byte - b'2' + 26,
                _ => return Err("invalid base32".into()),
            };
            accumulator = (accumulator << 5) | u32::from(digit);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                output.push(u8::try_from((accumulator >> bits) & 0xff)?);
                accumulator &= (1_u32 << bits).saturating_sub(1);
            }
        }
        Ok(output)
    }
}
