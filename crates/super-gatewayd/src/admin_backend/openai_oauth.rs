//! `OpenAI` authorization and bounded background renewal.
use super::*;
use gateway_domain::{EgressRouteSnapshot, Socks5DnsMode};
use gateway_transport::{ProviderHttpsClient, ProviderHttpsHeader, ProviderHttpsRequest};
use tokio_util::sync::CancellationToken;
const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const REDIRECT: &str = "http://localhost:1455/auth/callback";

enum TokenRequestFailure {
    BeforeSubmission,
    Uncertain,
}
impl From<ManagementBackendError> for TokenRequestFailure {
    fn from(_: ManagementBackendError) -> Self {
        Self::BeforeSubmission
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    replace_account_id: Option<Uuid>,
    name: String,
    group_id: Uuid,
    proxy_id: Option<Uuid>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Callback {
    code: String,
    state: String,
}

impl PgManagementBackend {
    pub(super) async fn manual_refresh_openai_account(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let id = path_uuid(request, "id")?;
        let revision = request_revision(request)?;
        self.refresh_openai_account_version(id, Some(revision), Some(principal))
            .await?;
        let next: i64 = sqlx::query_scalar("SELECT revision FROM gateway.openai_account WHERE id=$1")
            .bind(id)
            .fetch_one(&self.storage.pool())
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(
            &json!({"id":id,"revision":next,"refreshed":true}),
            next,
        ))
    }
    pub(super) async fn begin_openai_oauth(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: Start = deserialize_body(request)?;
        if command.name.trim().is_empty() || command.name.len() > 128 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM gateway.credential_group WHERE id=$1 AND provider_code='openai' AND status_code='active')")
            .bind(command.group_id).fetch_one(&self.storage.pool()).await.map_err(|_|ManagementBackendError::Unavailable)?;
        if !valid {
            return Err(ManagementBackendError::Precondition);
        }
        let revision = command
            .replace_account_id
            .map(|_| request_revision(request))
            .transpose()?;
        if let Some(account) = command.replace_account_id {
            let matches: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM gateway.openai_account WHERE id=$1 AND group_id=$2 AND revision=$3 AND auth_kind_code='oauth')")
                .bind(account).bind(command.group_id).bind(revision).fetch_one(&self.storage.pool()).await.map_err(|_|ManagementBackendError::Unavailable)?;
            if !matches {
                return Err(ManagementBackendError::Precondition);
            }
        }
        let policy: String = sqlx::query_scalar("SELECT c.proxy_policy_code FROM gateway.group_active_config a JOIN gateway.group_config c ON c.id=a.config_id WHERE a.group_id=$1")
            .bind(command.group_id).fetch_one(&self.storage.pool()).await.map_err(|_|ManagementBackendError::Unavailable)?;
        if (policy == "proxy_required" && command.proxy_id.is_none())
            || (policy == "direct" && command.proxy_id.is_some())
        {
            return Err(ManagementBackendError::Precondition);
        }
        let pkce = generate_oauth_pkce(&self.session_digest_key).map_err(|_| ManagementBackendError::Unavailable)?;
        let id = Uuid::now_v7();
        let (secret, aad, envelope) = self
            .openai_secret(id, "pkce_verifier", "openai_pkce", pkce.verifier.expose())
            .await?;
        let mut tx = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_secret(&mut tx, secret, &aad, &envelope).await?;
        sqlx::query("INSERT INTO gateway.openai_oauth_session(id,actor_id,group_id,name,state_digest,verifier_secret_id,proxy_id,expires_at,replace_account_id,account_revision) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '30 minutes',$8,$9)")
            .bind(id).bind(parse_uuid(&principal.user_id)?).bind(command.group_id).bind(command.name).bind(pkce.state_digest.as_slice()).bind(secret).bind(command.proxy_id)
            .bind(command.replace_account_id).bind(revision).execute(&mut *tx).await.map_err(|_|ManagementBackendError::Precondition)?;
        tx.commit().await.map_err(|_| ManagementBackendError::Unavailable)?;
        let query = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT),
            ("scope", "openid profile email offline_access"),
            ("state", pkce.state.expose()),
            ("code_challenge", pkce.challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("id_token_add_organizations", "true"),
            ("codex_cli_simplified_flow", "true"),
        ])
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut response = single_response(
            &json!({"id":id,"authorization_url":format!("https://auth.openai.com/oauth/authorize?{query}"),"redirect_uri":REDIRECT,"expires_in":1800}),
            1,
        );
        response.no_store = true;
        Ok(response)
    }

    pub(super) async fn finish_openai_oauth(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: Callback = deserialize_body(request)?;
        if command.code.is_empty() || command.code.len() > 16384 || command.state.len() > 256 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let id = path_uuid(request, "id")?;
        let digest = oauth_callback_digest(
            &self.session_digest_key,
            OAuthCallbackDigestDomain::State,
            &SecretValue::new(command.state),
        )
        .map_err(|_| ManagementBackendError::InvalidInput)?;
        let row = sqlx::query("UPDATE gateway.openai_oauth_session SET state_code=CASE WHEN state_code='pending' THEN 'exchanging' ELSE 'exchanged' END WHERE id=$1 AND actor_id=$2 AND state_digest=$3 AND state_code IN ('pending','exchanged','importing') AND expires_at>clock_timestamp() RETURNING *")
            .bind(id).bind(parse_uuid(&principal.user_id)?).bind(digest.as_slice()).fetch_optional(&self.storage.pool()).await.map_err(|_|ManagementBackendError::Unavailable)?.ok_or(ManagementBackendError::Precondition)?;
        let document = if let Some(secret) = required::<Option<Uuid>>(&row, "response_secret_id")? {
            let secret = crate::production_dispatcher::decrypt_secret(&self.storage, secret)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            serde_json::from_slice::<Value>(secret.expose()).map_err(|_| ManagementBackendError::Unavailable)?
        } else {
            let verifier =
                crate::production_dispatcher::decrypt_secret(&self.storage, required(&row, "verifier_secret_id")?)
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?;
            let result = self
                .openai_token_request(
                    vec![
                        ("grant_type", "authorization_code"),
                        ("client_id", CLIENT_ID),
                        ("redirect_uri", REDIRECT),
                        ("code", &command.code),
                        (
                            "code_verifier",
                            std::str::from_utf8(verifier.expose()).map_err(|_| ManagementBackendError::Unavailable)?,
                        ),
                    ],
                    required(&row, "proxy_id")?,
                )
                .await;
            let Ok((200, document)) = result else {
                let _ = sqlx::query("UPDATE gateway.openai_oauth_session SET state_code='failed' WHERE id=$1")
                    .bind(id)
                    .execute(&self.storage.pool())
                    .await;
                return Err(ManagementBackendError::Precondition);
            };
            let checkpoint = self
                .openai_secret(
                    id,
                    "oauth_callback_material",
                    "openai_oauth_checkpoint",
                    &document.to_string(),
                )
                .await?;
            let mut tx = self
                .storage
                .pool()
                .begin()
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
            insert_secret(&mut tx, checkpoint.0, &checkpoint.1, &checkpoint.2).await?;
            sqlx::query("UPDATE gateway.openai_oauth_session SET state_code='exchanged',response_secret_id=$2 WHERE id=$1 AND state_code='exchanging'").bind(id).bind(checkpoint.0).execute(&mut *tx).await.map_err(|_|ManagementBackendError::Unavailable)?;
            tx.commit().await.map_err(|_| ManagementBackendError::Unavailable)?;
            document
        };
        let mut imported = request.clone();
        imported.body = Some(
            json!({"name":required::<String>(&row,"name")?,"group_id":required::<Uuid>(&row,"group_id")?,"auth_kind":"oauth","credentials":document,"proxy_id":required::<Option<Uuid>>(&row,"proxy_id")?,"replace_account_id":required::<Option<Uuid>>(&row,"replace_account_id")?}),
        );
        if let Some(revision) = required::<Option<i64>>(&row, "account_revision")? {
            imported.if_match = Some(format!("\"rev-{revision}\"").into());
        }
        self.import_openai_account(principal, &imported, Some(id)).await
    }

    async fn openai_token_request(
        &self,
        fields: Vec<(&str, &str)>,
        proxy: Option<Uuid>,
    ) -> Result<(u16, Value), TokenRequestFailure> {
        let egress = if let Some(id) = proxy {
            let row = sqlx::query("SELECT * FROM gateway.proxy_endpoint WHERE id=$1 AND lifecycle_code='active'")
                .bind(id)
                .fetch_optional(&self.storage.pool())
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?
                .ok_or(ManagementBackendError::Precondition)?;
            let credentials = if let Some(id) = required::<Option<Uuid>>(&row, "auth_secret_id")? {
                Some(Arc::new(
                    crate::production_dispatcher::parse_proxy_credentials(
                        &crate::production_dispatcher::decrypt_secret(&self.storage, id)
                            .await
                            .map_err(|_| ManagementBackendError::Unavailable)?,
                    )
                    .map_err(|_| ManagementBackendError::Unavailable)?,
                ))
            } else {
                None
            };
            let host = required::<String>(&row, "host")?.into();
            let port =
                u16::try_from(required::<i32>(&row, "port")?).map_err(|_| ManagementBackendError::Unavailable)?;
            if required::<String>(&row, "proxy_type_code")? == "socks5" {
                EgressRouteSnapshot::Socks5 {
                    host,
                    port,
                    credentials,
                    dns: Socks5DnsMode::Remote,
                }
            } else {
                EgressRouteSnapshot::HttpConnect {
                    host,
                    port,
                    credentials,
                }
            }
        } else {
            EgressRouteSnapshot::Direct
        };
        let body = serde_urlencoded::to_string(fields).map_err(|_| ManagementBackendError::InvalidInput)?;
        let result = ProviderHttpsClient::default()
            .execute(ProviderHttpsRequest {
                method: http::Method::POST,
                host: "auth.openai.com".into(),
                host_header: "auth.openai.com".into(),
                port: 443,
                path_and_query: SecretValue::new("/oauth/token".into()),
                headers: vec![ProviderHttpsHeader {
                    name: "content-type",
                    value: SecretBytes::new(b"application/x-www-form-urlencoded".to_vec()),
                }],
                body: SecretBytes::new(body.into_bytes()),
                response_limit: 1024 * 1024,
                egress,
                cancellation: CancellationToken::new(),
            })
            .await
            .map_err(|error| {
                if error.retry_safety == gateway_transport::RetrySafety::SafeBeforeSubmission {
                    TokenRequestFailure::BeforeSubmission
                } else {
                    TokenRequestFailure::Uncertain
                }
            })?;
        Ok((
            result.status,
            serde_json::from_slice(result.body.expose()).map_err(|_| TokenRequestFailure::Uncertain)?,
        ))
    }

    pub(crate) fn spawn_openai_maintenance(self: Arc<Self>, cancel: &CancellationToken) -> tokio::task::JoinHandle<()> {
        let cancel = cancel.child_token();
        tokio::spawn(async move {
            loop {
                let interval = sqlx::query_scalar::<_, i32>(
                    "SELECT refresh_interval_seconds FROM gateway.openai_settings WHERE singleton",
                )
                .fetch_one(&self.storage.pool())
                .await
                .unwrap_or(60);
                tokio::select! {()=cancel.cancelled()=>break,()=tokio::time::sleep(std::time::Duration::from_secs(u64::try_from(interval).unwrap_or(60)))=>{}}
                // A lost response may have rotated the refresh token. Do not replay it after a crash.
                let _=sqlx::query("UPDATE gateway.openai_account SET auth_state_code='needs_reauth',refresh_attempt_id=NULL,refresh_lease_until=NULL,revision=revision+1 WHERE auth_state_code='refreshing' AND refresh_lease_until<clock_timestamp()")
                    .execute(&self.storage.pool()).await;
                let rows=sqlx::query("SELECT id FROM gateway.openai_account WHERE auth_kind_code='oauth' AND enabled AND refresh_secret_id IS NOT NULL AND auth_state_code IN ('healthy','manual_update') AND (expires_at IS NULL OR expires_at<clock_timestamp()+interval '5 minutes') AND (cooldown_until IS NULL OR cooldown_until<=clock_timestamp()) LIMIT 20")
                    .fetch_all(&self.storage.pool()).await.unwrap_or_default();
                for row in rows {
                    if cancel.is_cancelled() {
                        break;
                    }
                    if let Ok(id) = row.try_get::<Uuid, _>("id") {
                        tokio::select! { ()=cancel.cancelled()=>return, _=self.refresh_openai_account(id)=>{} }
                    }
                }
                let rows = sqlx::query("SELECT id,revision FROM gateway.openai_account WHERE enabled AND auth_kind_code='oauth' AND auth_state_code IN ('healthy','manual_update') AND (quota_observed_at IS NULL OR quota_observed_at<clock_timestamp()-interval '5 minutes') ORDER BY quota_observed_at NULLS FIRST LIMIT 20")
                    .fetch_all(&self.storage.pool()).await.unwrap_or_default();
                for row in rows {
                    let (Ok(id), Ok(revision)) = (row.try_get::<Uuid, _>("id"), row.try_get::<i64, _>("revision"))
                    else {
                        continue;
                    };
                    let request = ManagementRequest {
                        operation_id: "openai_maintenance".into(),
                        method: axum::http::Method::POST,
                        path: "/admin/v1/openai/accounts".into(),
                        query: None,
                        path_parameters: [("id".into(), id.to_string().into())].into(),
                        body: Some(json!({})),
                        idempotency_key: None,
                        if_match: Some(format!("\"rev-{revision}\"").into()),
                    };
                    tokio::select! { ()=cancel.cancelled()=>return, _=self.probe_openai_account(None,&request)=>{} }
                }
                let _ = sqlx::query("DELETE FROM gateway.openai_response_binding WHERE expires_at<clock_timestamp()")
                    .execute(&self.storage.pool())
                    .await;
            }
        })
    }

    pub(super) async fn refresh_openai_account(&self, id: Uuid) -> Result<(), ManagementBackendError> {
        self.refresh_openai_account_version(id, None, None).await
    }

    async fn refresh_openai_account_version(
        &self,
        id: Uuid,
        expected: Option<i64>,
        _principal: Option<&ManagementPrincipal>,
    ) -> Result<(), ManagementBackendError> {
        let claim = Uuid::now_v7();
        let row=sqlx::query("UPDATE gateway.openai_account SET auth_state_code='refreshing',refresh_attempt_id=$2,refresh_lease_until=clock_timestamp()+interval '2 minutes',updated_at=clock_timestamp() \
            WHERE id=$1 AND ($3::bigint IS NULL OR revision=$3) AND auth_kind_code='oauth' AND refresh_secret_id IS NOT NULL AND auth_state_code IN ('pending_verify','healthy','manual_update') AND (cooldown_until IS NULL OR cooldown_until<=clock_timestamp()) RETURNING *")
            .bind(id).bind(claim).bind(expected).fetch_optional(&self.storage.pool()).await.map_err(|_|ManagementBackendError::Unavailable)?.ok_or(ManagementBackendError::Precondition)?;
        let refresh = crate::production_dispatcher::decrypt_secret(&self.storage, required(&row, "refresh_secret_id")?)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let result = self
            .openai_token_request(
                vec![
                    ("grant_type", "refresh_token"),
                    ("client_id", CLIENT_ID),
                    (
                        "refresh_token",
                        std::str::from_utf8(refresh.expose()).map_err(|_| ManagementBackendError::Unavailable)?,
                    ),
                    ("scope", "openid profile email"),
                ],
                required(&row, "proxy_id")?,
            )
            .await;
        let document = match result {
            Ok((200, doc)) => doc,
            other => {
                let permanent = matches!(other, Ok((400 | 401 | 403, _)) | Err(TokenRequestFailure::Uncertain));
                sqlx::query("UPDATE gateway.openai_account SET auth_state_code=CASE WHEN $3 THEN 'needs_reauth' ELSE 'healthy' END,refresh_attempt_id=NULL,refresh_lease_until=NULL,refresh_failures=refresh_failures+1, \
                    cooldown_until=clock_timestamp()+LEAST(1800,30*power(2,LEAST(refresh_failures,6)))::integer*interval '1 second', \
                    last_error_code=CASE WHEN $3 THEN 'reauth_required' ELSE 'token_refresh_failed' END,last_error_message='token refresh failed',last_error_at=clock_timestamp(),revision=revision+1 WHERE id=$1 AND refresh_attempt_id=$2")
                    .bind(id).bind(claim).bind(permanent).execute(&self.storage.pool()).await.map_err(|_|ManagementBackendError::Unavailable)?;
                return Err(ManagementBackendError::Precondition);
            }
        };
        let old_access =
            crate::production_dispatcher::decrypt_secret(&self.storage, required(&row, "access_secret_id")?)
                .await
                .map_err(|_| ManagementBackendError::Unavailable)?;
        let identity: String = required(&row, "account_id")?;
        let mut material=gateway_services::openai::account::OAuthMaterial::import(&serde_json::to_vec(&json!({"access_token":std::str::from_utf8(old_access.expose()).map_err(|_|ManagementBackendError::Unavailable)?,"account_id":identity})).map_err(|_|ManagementBackendError::Unavailable)?)
            .map_err(|_|ManagementBackendError::Precondition)?;
        if material.rotate(&document, &identity).is_err() {
            sqlx::query("UPDATE gateway.openai_account SET auth_state_code='needs_reauth',refresh_attempt_id=NULL,refresh_lease_until=NULL,revision=revision+1 WHERE id=$1 AND refresh_attempt_id=$2")
                .bind(id).bind(claim).execute(&self.storage.pool()).await.map_err(|_|ManagementBackendError::Unavailable)?;
            return Err(ManagementBackendError::Precondition);
        }
        let access = self
            .openai_secret(
                id,
                "oauth_access_token",
                "openai_access_token",
                material.access_token.expose(),
            )
            .await?;
        let refresh = if let Some(token) = document
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
        {
            Some(
                self.openai_secret(id, "oauth_refresh_token", "openai_refresh_token", token)
                    .await?,
            )
        } else {
            None
        };
        let id_token = if let Some(token) = document
            .get("id_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
        {
            Some(
                self.openai_secret(id, "oauth_callback_material", "openai_id_token", token)
                    .await?,
            )
        } else {
            None
        };
        let expires = document
            .get("expires_in")
            .and_then(Value::as_i64)
            .filter(|v| *v > 0 && *v <= 86400 * 30)
            .map(|v| now_unix() + v);
        let mut tx = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        insert_secret(&mut tx, access.0, &access.1, &access.2).await?;
        if let Some((id, aad, envelope)) = &refresh {
            insert_secret(&mut tx, *id, aad, envelope).await?;
        }
        if let Some((id, aad, envelope)) = &id_token {
            insert_secret(&mut tx, *id, aad, envelope).await?;
        }
        let result=sqlx::query("UPDATE gateway.openai_account SET access_secret_id=$3,refresh_secret_id=COALESCE($4,refresh_secret_id),id_token_secret_id=COALESCE($7,id_token_secret_id),expires_at=to_timestamp($5::bigint::double precision),token_version=token_version+1,revision=revision+1,auth_state_code='healthy',refresh_attempt_id=NULL,refresh_lease_until=NULL,refresh_failures=0,cooldown_until=NULL,updated_at=clock_timestamp() WHERE id=$1 AND refresh_attempt_id=$2 AND token_version=$6 AND auth_state_code='refreshing'")
            .bind(id).bind(claim).bind(access.0).bind(refresh.as_ref().map(|s|s.0)).bind(expires.or(material.expires_at.and_then(|v|i64::try_from(v).ok()))).bind(required::<i64>(&row,"token_version")?)
            .bind(id_token.as_ref().map(|s|s.0)).execute(&mut *tx).await.map_err(|_|ManagementBackendError::Unavailable)?;
        if result.rows_affected() != 1 {
            return Err(ManagementBackendError::Precondition);
        }
        tx.commit().await.map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(())
    }
}
fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX)
}
