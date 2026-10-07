//! `OpenAI` management operations, using the shared authorization boundary.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenAiAccountCreateCommand {
    replace_account_id: Option<Uuid>,
    name: String,
    group_id: Uuid,
    auth_kind: gateway_domain::OpenAiAuthKind,
    api_key: Option<String>,
    credentials: Option<Value>,
    proxy_id: Option<Uuid>,
}

impl PgManagementBackend {
    pub(super) async fn openai_group_policy(
        &self,
        _principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let id = path_uuid(request, "id")?;
        if request.method == axum::http::Method::GET {
            let row=sqlx::query("SELECT g.revision,p.max_reasoning_effort,COALESCE(p.reasoning_over_limit,'reject') AS reasoning_over_limit FROM gateway.credential_group g LEFT JOIN gateway.openai_group_policy p ON p.group_id=g.id WHERE g.id=$1 AND g.provider_code='openai'")
                .bind(id).fetch_optional(&self.storage.pool()).await.map_err(|_|ManagementBackendError::Unavailable)?.ok_or(ManagementBackendError::Precondition)?;
            let revision = required::<i64>(&row, "revision")?;
            return Ok(single_response(
                &json!({"group_id":id,"revision":revision,"max_reasoning_effort":required::<Option<String>>(&row,"max_reasoning_effort")?,"reasoning_over_limit":required::<String>(&row,"reasoning_over_limit")?}),
                revision,
            ));
        }
        let body = request.body.as_ref().ok_or(ManagementBackendError::InvalidInput)?;
        let maximum = body
            .get("max_reasoning_effort")
            .filter(|v| !v.is_null())
            .map(|v| v.as_str().ok_or(ManagementBackendError::InvalidInput))
            .transpose()?;
        let action = body
            .get("reasoning_over_limit")
            .and_then(Value::as_str)
            .ok_or(ManagementBackendError::InvalidInput)?;
        if maximum.is_some_and(|v| !["none", "minimal", "low", "medium", "high", "xhigh"].contains(&v))
            || !["reject", "downgrade"].contains(&action)
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let mut tx = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let next:i64=sqlx::query_scalar("UPDATE gateway.credential_group SET revision=revision+1 WHERE id=$1 AND revision=$2 AND provider_code='openai' RETURNING revision").bind(id).bind(request_revision(request)?).fetch_optional(&mut *tx).await.map_err(|_|ManagementBackendError::Unavailable)?.ok_or(ManagementBackendError::Precondition)?;
        sqlx::query("INSERT INTO gateway.openai_group_policy(group_id,max_reasoning_effort,reasoning_over_limit) VALUES($1,$2,$3) ON CONFLICT(group_id) DO UPDATE SET max_reasoning_effort=$2,reasoning_over_limit=$3").bind(id).bind(maximum).bind(action).execute(&mut *tx).await.map_err(|_|ManagementBackendError::Unavailable)?;

        tx.commit().await.map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(
            &json!({"group_id":id,"revision":next,"max_reasoning_effort":maximum,"reasoning_over_limit":action}),
            next,
        ))
    }
    pub(super) async fn test_openai_account(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        self.probe_openai_account(Some(principal), request).await
    }

    pub(super) async fn probe_openai_account(
        &self,
        _principal: Option<&ManagementPrincipal>,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        use gateway_domain::{EgressRouteSnapshot, Socks5DnsMode};
        use gateway_transport::{
            ProviderHttpsClient, ProviderHttpsHeader, ProviderHttpsRequest, ProviderHttpsTimeouts,
        };
        let id = path_uuid(request, "id")?;
        let revision = request_revision(request)?;
        let row = sqlx::query("SELECT a.auth_kind_code,a.account_id,a.access_secret_id,a.token_version,a.refresh_secret_id,a.proxy_id, \
            p.host,p.port,p.auth_secret_id,p.proxy_type_code,p.lifecycle_code, \
            s.connect_timeout_seconds,s.response_timeout_seconds,gc.proxy_policy_code \
            FROM gateway.openai_account a LEFT JOIN gateway.proxy_endpoint p ON p.id=a.proxy_id \
            JOIN gateway.group_active_config active ON active.group_id=a.group_id JOIN gateway.group_config gc ON gc.id=active.config_id \
            CROSS JOIN gateway.openai_settings s WHERE a.id=$1 AND a.revision=$2")
            .bind(id).bind(revision).fetch_optional(&self.storage.pool()).await.map_err(|_| ManagementBackendError::Unavailable)?
            .ok_or(ManagementBackendError::Precondition)?;
        let proxy_id = required::<Option<Uuid>>(&row, "proxy_id")?;
        let policy = required::<String>(&row, "proxy_policy_code")?;
        if (policy == "proxy_required" && proxy_id.is_none()) || (policy == "direct" && proxy_id.is_some()) {
            return Err(ManagementBackendError::Precondition);
        }
        let egress = if required::<Option<Uuid>>(&row, "proxy_id")?.is_some() {
            if required::<Option<String>>(&row, "lifecycle_code")?.as_deref() != Some("active") {
                return Err(ManagementBackendError::Precondition);
            }
            let credentials = if let Some(secret_id) = required::<Option<Uuid>>(&row, "auth_secret_id")? {
                let secret = crate::production_dispatcher::decrypt_secret(&self.storage, secret_id)
                    .await
                    .map_err(|_| ManagementBackendError::Unavailable)?;
                Some(Arc::new(
                    crate::production_dispatcher::parse_proxy_credentials(&secret)
                        .map_err(|_| ManagementBackendError::Precondition)?,
                ))
            } else {
                None
            };
            let host = required::<String>(&row, "host")?.into_boxed_str();
            let port =
                u16::try_from(required::<i32>(&row, "port")?).map_err(|_| ManagementBackendError::Precondition)?;
            match required::<String>(&row, "proxy_type_code")?.as_str() {
                "connect" => EgressRouteSnapshot::HttpConnect {
                    host,
                    port,
                    credentials,
                },
                "socks5" => EgressRouteSnapshot::Socks5 {
                    host,
                    port,
                    credentials,
                    dns: Socks5DnsMode::Remote,
                },
                _ => return Err(ManagementBackendError::Precondition),
            }
        } else {
            EgressRouteSnapshot::Direct
        };
        let token = crate::production_dispatcher::decrypt_secret(&self.storage, required(&row, "access_secret_id")?)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let mut bearer = b"Bearer ".to_vec();
        bearer.extend_from_slice(token.expose());
        let mut headers = vec![ProviderHttpsHeader {
            name: "authorization",
            value: SecretBytes::new(bearer),
        }];
        let oauth = required::<String>(&row, "auth_kind_code")? == "oauth";
        let account_id = required::<Option<String>>(&row, "account_id")?;
        if oauth {
            headers.push(ProviderHttpsHeader {
                name: "chatgpt-account-id",
                value: SecretBytes::new(
                    account_id
                        .as_deref()
                        .ok_or(ManagementBackendError::Precondition)?
                        .as_bytes()
                        .to_vec(),
                ),
            });
        }
        let (host, path) = if oauth {
            ("chatgpt.com", "/backend-api/wham/usage")
        } else {
            ("api.openai.com", "/v1/models")
        };
        let seconds = |column| -> Result<std::time::Duration, ManagementBackendError> {
            Ok(std::time::Duration::from_secs(
                u64::try_from(required::<i32>(&row, column)?).map_err(|_| ManagementBackendError::Unavailable)?,
            ))
        };
        let model_headers = headers
            .iter()
            .map(|header| ProviderHttpsHeader {
                name: header.name,
                value: SecretBytes::new(header.value.expose().to_vec()),
            })
            .collect::<Vec<_>>();
        let client = ProviderHttpsClient::new(ProviderHttpsTimeouts {
            connect: seconds("connect_timeout_seconds")?,
            tls: seconds("connect_timeout_seconds")?,
            write: seconds("connect_timeout_seconds")?,
            response: seconds("response_timeout_seconds")?,
        });
        let response = client
            .execute(ProviderHttpsRequest {
                method: http::Method::GET,
                host: host.into(),
                port: 443,
                host_header: host.into(),
                path_and_query: SecretValue::new(path.into()),
                headers,
                body: SecretBytes::new(Vec::new()),
                response_limit: 1024 * 1024,
                egress: egress.clone(),
                cancellation: tokio_util::sync::CancellationToken::new(),
            })
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if response.status != 200 {
            return Err(ManagementBackendError::Precondition);
        }
        let document: Value =
            serde_json::from_slice(response.body.expose()).map_err(|_| ManagementBackendError::Precondition)?;
        let quota = verified_openai_probe(&document, account_id.as_deref(), oauth)?;
        // Model discovery is independent of quota verification. A failed sync preserves the published catalog.
        let models_document = if oauth {
            let mut headers = model_headers;
            headers.push(ProviderHttpsHeader {
                name: "originator",
                value: SecretBytes::new(b"codex_cli_rs".to_vec()),
            });
            match client
                .execute(ProviderHttpsRequest {
                    method: http::Method::GET,
                    host: "chatgpt.com".into(),
                    host_header: "chatgpt.com".into(),
                    port: 443,
                    path_and_query: SecretValue::new("/backend-api/codex/models?client_version=0.147.0".into()),
                    headers,
                    body: SecretBytes::new(Vec::new()),
                    response_limit: 1024 * 1024,
                    egress,
                    cancellation: tokio_util::sync::CancellationToken::new(),
                })
                .await
            {
                Ok(response) if response.status == 200 => serde_json::from_slice::<Value>(response.body.expose()).ok(),
                _ => None,
            }
        } else {
            Some(document.clone())
        };
        let state = if oauth && required::<Option<Uuid>>(&row, "refresh_secret_id")?.is_none() {
            "manual_update"
        } else {
            "healthy"
        };
        let mut tx = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let next: i64 = sqlx::query_scalar("UPDATE gateway.openai_account SET verified_at=clock_timestamp(),auth_state_code=$1,cooldown_until=NULL, \
            quota_snapshot=COALESCE($2,quota_snapshot),quota_observed_at=CASE WHEN $2::jsonb IS NULL THEN quota_observed_at ELSE clock_timestamp() END, \
            plan_label=COALESCE($3,plan_label),revision=revision+1,updated_at=clock_timestamp() \
            WHERE id=$4 AND revision=$5 AND token_version=$6 AND auth_state_code<>'refreshing' RETURNING revision")
            .bind(state).bind(quota).bind(if oauth {document.get("plan_type").and_then(Value::as_str)} else {None})
            .bind(id).bind(revision).bind(required::<i64>(&row,"token_version")?)
            .fetch_optional(&mut *tx).await.map_err(|_| ManagementBackendError::Unavailable)?.ok_or(ManagementBackendError::Precondition)?;
        if let Some(models_document) = models_document {
            for model in models_document
                .get(if oauth { "models" } else { "data" })
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(name) = model
                    .get(if oauth { "slug" } else { "id" })
                    .and_then(Value::as_str)
                    .filter(|id| {
                        id.len() <= 256
                            && !id.chars().any(char::is_control)
                            && (id.starts_with("gpt-")
                                || id.starts_with("o1")
                                || id.starts_with("o3")
                                || id.starts_with("o4"))
                    })
                else {
                    continue;
                };
                sqlx::query("INSERT INTO catalog.model_definition(id,upstream_model_id,display_name,lifecycle_code,provider_code,first_seen_at,last_seen_at,openai_metadata) VALUES($1,$2,$2,'published','openai',clock_timestamp(),clock_timestamp(),$3) ON CONFLICT(provider_code,upstream_model_id) DO UPDATE SET last_seen_at=clock_timestamp(),openai_metadata=COALESCE(EXCLUDED.openai_metadata,model_definition.openai_metadata)")
                    .bind(Uuid::now_v7()).bind(name).bind(if oauth {Some(model)} else {None}).execute(&mut *tx).await.map_err(|_|ManagementBackendError::Unavailable)?;
            }
        }
        tx.commit().await.map_err(|_| ManagementBackendError::Unavailable)?;
        self.reload_management_runtime().await?;
        Ok(single_response(
            &json!({"id":id,"verified":true,"auth_state":state,"revision":next}),
            next,
        ))
    }

    pub(super) async fn patch_openai_account(
        &self,
        _principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: OpenAiAccountSettings = deserialize_body(request)?;
        if command.name.trim().is_empty()
            || command.name.len() > 128
            || !(1..=1000).contains(&command.max_concurrency)
            || command.models.len() > 256
            || command
                .models
                .iter()
                .any(|m| m.is_empty() || m.len() > 256 || m.chars().any(char::is_control))
        {
            return Err(ManagementBackendError::InvalidInput);
        }
        let id = path_uuid(request, "id")?;
        let revision = request_revision(request)?;
        let mut tx = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let set_proxy = request.body.as_ref().is_some_and(|body| body.get("proxy_id").is_some());
        let row = sqlx::query("UPDATE gateway.openai_account a SET name=$1,enabled=CASE WHEN ($9 AND proxy_id IS DISTINCT FROM $10) OR ($11::uuid IS NOT NULL AND group_id<>$11) THEN false ELSE $2 END,max_concurrency=$3,priority=$4,websocket_enabled=$5,models=$6,revision=revision+1,updated_at=clock_timestamp(),verified_at=CASE WHEN ($9 AND proxy_id IS DISTINCT FROM $10) OR ($11::uuid IS NOT NULL AND group_id<>$11) THEN NULL ELSE verified_at END,proxy_id=CASE WHEN $9 THEN $10 ELSE proxy_id END,group_id=COALESCE($11,group_id) \
            WHERE id=$7 AND revision=$8 AND auth_state_code<>'refreshing' AND (NOT $2 OR ($9 AND proxy_id IS DISTINCT FROM $10) OR ($11::uuid IS NOT NULL AND group_id<>$11) OR (verified_at IS NOT NULL AND auth_state_code IN ('healthy','manual_update') AND (expires_at IS NULL OR expires_at>clock_timestamp()))) \
            RETURNING revision,enabled")
            .bind(command.name.trim()).bind(command.enabled).bind(command.max_concurrency).bind(command.priority)
            .bind(command.websocket_enabled).bind(json!(command.models)).bind(id).bind(revision).bind(set_proxy).bind(command.proxy_id).bind(command.group_id)
            .fetch_optional(&mut *tx).await.map_err(|_| ManagementBackendError::Unavailable)?
            .ok_or(ManagementBackendError::Precondition)?;
        let revision: i64 = required(&row, "revision")?;

        tx.commit().await.map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(
            &json!({"id":id,"enabled":required::<bool>(&row,"enabled")?,"revision":revision}),
            revision,
        ))
    }

    pub(super) async fn list_openai_accounts(
        &self,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let query: UpgradeCheckQuery = serde_urlencoded::from_str(request.query.as_deref().unwrap_or(""))
            .map_err(|_| ManagementBackendError::InvalidInput)?;
        let page_size = query.page_size.unwrap_or(100);
        if !(1..=100).contains(&page_size) {
            return Err(ManagementBackendError::InvalidInput);
        }
        let after = query.page_after.as_deref().map(parse_input_uuid).transpose()?;
        // Explicit public projection: secret references and token material never leave this boundary.
        let rows = sqlx::query(
            "SELECT jsonb_build_object('id',id,'name',name,'provider','openai', \
            'group_id',group_id,'proxy_id',proxy_id,'auth_kind',auth_kind_code,'enabled',enabled,'auth_state',auth_state_code, \
            'refreshable',refresh_secret_id IS NOT NULL,'expires_at',expires_at,'revision',revision, \
            'verified_at',verified_at,'max_concurrency',max_concurrency,'priority',priority, \
            'websocket_enabled',websocket_enabled,'models',models,'plan',plan_label, \
            'quota',quota_snapshot,'quota_observed_at',quota_observed_at, \
            'cooldown_until',cooldown_until,'last_error_code',last_error_code, \
            'last_error_message',last_error_message,'last_error_at',last_error_at) AS data \
            FROM gateway.openai_account WHERE ($1::uuid IS NULL OR id<$1) ORDER BY id DESC LIMIT $2",
        )
        .bind(after)
        .bind(i64::try_from(page_size + 1).map_err(|_| ManagementBackendError::InvalidInput)?)
        .fetch_all(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        let data = rows
            .iter()
            .take(page_size)
            .map(|row| required::<Value>(row, "data"))
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = rows.len() > page_size;
        let next_cursor = if has_more {
            data.last().and_then(|v| v.get("id")).cloned()
        } else {
            None
        };
        Ok(ManagementBackendResponse::ok(
            json!({"data":data,"page":{"next_cursor":next_cursor},"meta":{"has_more":has_more,"page_size":page_size}}),
        ))
    }

    pub(super) async fn openai_secret(
        &self,
        owner: Uuid,
        kind: &str,
        purpose: &str,
        value: &str,
    ) -> Result<(Uuid, EnvelopeAad, SecretEnvelope), ManagementBackendError> {
        let version: i64 = sqlx::query_scalar("SELECT key_version FROM security.business_key_material WHERE provider_code='database' AND state_code='active'")
            .fetch_one(&self.storage.pool()).await.map_err(|_| ManagementBackendError::Unavailable)?;
        let key = self
            .storage
            .load_database_business_key(version)
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let version = u64::try_from(version).map_err(|_| ManagementBackendError::Unavailable)?;
        let id = Uuid::now_v7();
        let aad = EnvelopeAad {
            schema_version: 1,
            secret_id: id,
            secret_kind: kind.into(),
            provider_role: "business".into(),
            owner_type: "openai_account".into(),
            owner_id: owner.to_string(),
            purpose: purpose.into(),
            key_version: version,
        };
        let provider = LocalAesKeyProvider::new("business", version, key.expose().to_vec())
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let envelope = EnvelopeService::new(provider)
            .encrypt(&SecretBytes::new(value.as_bytes().to_vec()), aad.clone())
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok((id, aad, envelope))
    }

    pub(super) async fn create_openai_account(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        self.import_openai_account(principal, request, None).await
    }

    pub(super) async fn import_openai_account(
        &self,
        principal: &ManagementPrincipal,
        request: &ManagementRequest,
        oauth_session: Option<Uuid>,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: OpenAiAccountCreateCommand = deserialize_body(request)?;
        if command.name.trim().is_empty() || command.name.len() > 128 {
            return Err(ManagementBackendError::InvalidInput);
        }
        let id = command.replace_account_id.unwrap_or_else(Uuid::now_v7);
        let replacement_revision = command
            .replace_account_id
            .map(|_| request_revision(request))
            .transpose()?;
        let mut secrets = Vec::new();
        let (kind, account, user, expiry, state) = match command.auth_kind {
            gateway_domain::OpenAiAuthKind::ApiKey => {
                if command.credentials.is_some() {
                    return Err(ManagementBackendError::InvalidInput);
                }
                let key = SecretValue::new(command.api_key.ok_or(ManagementBackendError::InvalidInput)?);
                if key.is_empty() || key.expose().len() > 65536 || key.expose().chars().any(char::is_whitespace) {
                    return Err(ManagementBackendError::InvalidInput);
                }
                secrets.push(
                    self.openai_secret(id, "console_api_key", "openai_api_key", key.expose())
                        .await?,
                );
                ("api_key", None, None, None, "pending_verify")
            }
            gateway_domain::OpenAiAuthKind::Oauth => {
                if command.api_key.is_some() {
                    return Err(ManagementBackendError::InvalidInput);
                }
                let bytes = SecretBytes::new(
                    serde_json::to_vec(&command.credentials.ok_or(ManagementBackendError::InvalidInput)?)
                        .map_err(|_| ManagementBackendError::InvalidInput)?,
                );
                let material = gateway_services::openai::account::OAuthMaterial::import(bytes.expose())
                    .map_err(|_| ManagementBackendError::InvalidInput)?;
                secrets.push(
                    self.openai_secret(
                        id,
                        "oauth_access_token",
                        "openai_access_token",
                        material.access_token.expose(),
                    )
                    .await?,
                );
                if let Some(refresh) = &material.refresh_token {
                    secrets.push(
                        self.openai_secret(id, "oauth_refresh_token", "openai_refresh_token", refresh.expose())
                            .await?,
                    );
                }
                if let Some(token) = &material.id_token {
                    secrets.push(
                        self.openai_secret(id, "oauth_callback_material", "openai_id_token", token.expose())
                            .await?,
                    );
                }
                let state = if material.refreshable() {
                    "pending_verify"
                } else {
                    "manual_update"
                };
                (
                    "oauth",
                    Some(material.account_id),
                    material.user_id,
                    material.expires_at.and_then(|v| i64::try_from(v).ok()),
                    state,
                )
            }
        };
        let refresh = secrets
            .iter()
            .find(|(_, a, _)| a.purpose == "openai_refresh_token")
            .map(|(id, _, _)| *id);
        let id_token = secrets
            .iter()
            .find(|(_, a, _)| a.purpose == "openai_id_token")
            .map(|(id, _, _)| *id);
        let mut tx = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        if let Some(session) = oauth_session {
            // The row lock serializes checkpoint imports. Account creation and session completion
            // commit together, so a restart can resume without redeeming the authorization code.
            let claimed = sqlx::query("UPDATE gateway.openai_oauth_session SET state_code='completed' WHERE id=$1 AND actor_id=$2 AND group_id=$3 AND state_code IN ('exchanged','importing') AND response_secret_id IS NOT NULL AND expires_at>clock_timestamp()")
                .bind(session).bind(parse_uuid(&principal.user_id)?).bind(command.group_id)
                .execute(&mut *tx).await.map_err(|_|ManagementBackendError::Unavailable)?;
            if claimed.rows_affected() != 1 {
                return Err(ManagementBackendError::Precondition);
            }
        }
        for (secret_id, aad, envelope) in &secrets {
            insert_secret(&mut tx, *secret_id, aad, envelope).await?;
        }
        let next_revision = if let Some(expected) = replacement_revision {
            sqlx::query_scalar::<_, i64>("UPDATE gateway.openai_account SET proxy_id=CASE WHEN $12 THEN $11 ELSE proxy_id END,access_secret_id=$3,refresh_secret_id=$4,id_token_secret_id=$5,expires_at=to_timestamp($6::bigint::double precision),auth_state_code=$7,verified_at=NULL,enabled=false,cooldown_until=NULL,refresh_failures=0,token_version=token_version+1,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 AND revision=$2 AND group_id=$8 AND auth_kind_code=$9 AND account_id IS NOT DISTINCT FROM $10 AND auth_state_code<>'refreshing' RETURNING revision")
                .bind(id).bind(expected).bind(secrets[0].0).bind(refresh).bind(id_token).bind(expiry).bind(state).bind(command.group_id).bind(kind).bind(&account).bind(command.proxy_id).bind(request.body.as_ref().is_some_and(|v|v.get("proxy_id").is_some()))
                .fetch_optional(&mut *tx).await.map_err(|_|ManagementBackendError::Precondition)?.ok_or(ManagementBackendError::Precondition)?
        } else {
            sqlx::query("INSERT INTO gateway.openai_account (id,group_id,name,auth_kind_code,account_id,user_id,access_secret_id,refresh_secret_id,id_token_secret_id,expires_at,auth_state_code,proxy_id) \
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,to_timestamp($10::bigint::double precision),$11,$12)")
            .bind(id).bind(command.group_id).bind(command.name.trim()).bind(kind).bind(account).bind(user)
            .bind(secrets[0].0).bind(refresh).bind(id_token).bind(expiry).bind(state).bind(command.proxy_id)
            .execute(&mut *tx).await.map_err(|_| ManagementBackendError::Precondition)?;
            1
        };

        tx.commit().await.map_err(|_| ManagementBackendError::Unavailable)?;
        let mut response = single_response(
            &json!({"id":id,"provider":"openai","auth_kind":kind,"enabled":false,"auth_state":state,"revision":next_revision}),
            next_revision,
        );
        response.status = axum::http::StatusCode::CREATED;
        response.no_store = true;
        Ok(response)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OpenAiSettingsCommand {
    enabled: bool,
    websocket_enabled: bool,
    connect_timeout_seconds: i32,
    response_timeout_seconds: i32,
    websocket_idle_seconds: i32,
    refresh_interval_seconds: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenAiAccountSettings {
    group_id: Option<Uuid>,
    proxy_id: Option<Uuid>,
    name: String,
    enabled: bool,
    max_concurrency: i32,
    priority: i32,
    websocket_enabled: bool,
    models: Vec<String>,
}

fn verified_openai_probe(
    document: &Value,
    account_id: Option<&str>,
    oauth: bool,
) -> Result<Option<Value>, ManagementBackendError> {
    if oauth {
        if account_id.is_none()
            || document.get("account_id").and_then(Value::as_str) != account_id
            || !document.get("rate_limit").is_some_and(Value::is_object)
        {
            return Err(ManagementBackendError::Precondition);
        }
        Ok(Some(
            json!({"rate_limit":document["rate_limit"],"additional_rate_limits":document.get("additional_rate_limits")}),
        ))
    } else if document.get("object").and_then(Value::as_str) == Some("list")
        && document.get("data").is_some_and(Value::is_array)
    {
        Ok(None)
    } else {
        Err(ManagementBackendError::Precondition)
    }
}

impl OpenAiSettingsCommand {
    fn valid(&self) -> bool {
        (1..=120).contains(&self.connect_timeout_seconds)
            && (1..=3600).contains(&self.response_timeout_seconds)
            && (1..=3600).contains(&self.websocket_idle_seconds)
            && (10..=3600).contains(&self.refresh_interval_seconds)
    }
}

impl PgManagementBackend {
    pub(super) async fn get_openai_settings(&self) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let row = sqlx::query(
            "SELECT to_jsonb(s)-'singleton' AS data,revision FROM gateway.openai_settings s WHERE singleton",
        )
        .fetch_one(&self.storage.pool())
        .await
        .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(
            &required::<Value>(&row, "data")?,
            required(&row, "revision")?,
        ))
    }

    pub(super) async fn update_openai_settings(
        &self,
        _principal: &ManagementPrincipal,
        request: &ManagementRequest,
    ) -> Result<ManagementBackendResponse, ManagementBackendError> {
        let command: OpenAiSettingsCommand = deserialize_body(request)?;
        if !command.valid() {
            return Err(ManagementBackendError::InvalidInput);
        }
        let revision = request_revision(request)?;
        let mut transaction = self
            .storage
            .pool()
            .begin()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        let row = sqlx::query(
            "UPDATE gateway.openai_settings s SET enabled=$1,websocket_enabled=$2,connect_timeout_seconds=$3, \
             response_timeout_seconds=$4,websocket_idle_seconds=$5,refresh_interval_seconds=$6,revision=revision+1 \
             WHERE singleton AND revision=$7 AND (NOT $1 OR EXISTS \
               (SELECT 1 FROM gateway.openai_account WHERE enabled AND verified_at IS NOT NULL \
                AND auth_state_code IN ('healthy','manual_update') AND (expires_at IS NULL OR expires_at>clock_timestamp()) \
                AND (cooldown_until IS NULL OR cooldown_until<=clock_timestamp()))) RETURNING to_jsonb(s)-'singleton' AS data,revision")
            .bind(command.enabled).bind(command.websocket_enabled).bind(command.connect_timeout_seconds)
            .bind(command.response_timeout_seconds).bind(command.websocket_idle_seconds)
            .bind(command.refresh_interval_seconds).bind(revision)
            .fetch_optional(&mut *transaction).await.map_err(|_| ManagementBackendError::Unavailable)?
            .ok_or(ManagementBackendError::Precondition)?;
        let next_revision: i64 = required(&row, "revision")?;

        transaction
            .commit()
            .await
            .map_err(|_| ManagementBackendError::Unavailable)?;
        Ok(single_response(&required::<Value>(&row, "data")?, next_revision))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_probe_requires_upstream_identity_and_sanitizes_quota() -> Result<(), Box<dyn std::error::Error>> {
        assert!(verified_openai_probe(&json!({"account_id":"other","rate_limit":{}}), Some("expected"), true).is_err());
        assert!(verified_openai_probe(&json!({"rate_limit":{}}), Some("expected"), true).is_err());
        let snapshot = verified_openai_probe(&json!({"account_id":"expected","rate_limit":{"allowed":true},"email":"private@example.test","access_token":"secret"}),Some("expected"),true)?.ok_or("quota snapshot missing")?;
        assert_eq!(snapshot["rate_limit"]["allowed"], true);
        assert!(snapshot.get("email").is_none());
        assert!(snapshot.get("access_token").is_none());
        assert!(verified_openai_probe(&json!({"object":"list","data":[]}), None, false).is_ok());
        assert!(verified_openai_probe(&json!({"error":"invalid"}), None, false).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn openai_management_postgres_import_and_settings() -> Result<(), Box<dyn std::error::Error>> {
        let Ok(url) = std::env::var("TEST_OPENAI_DATABASE_URL") else {
            return Ok(());
        };
        let url = SecretValue::new(url);
        PgStorage::migrate(&url).await?;
        let storage =
            Arc::new(PgStorage::connect(&url, gateway_storage::RuntimeRolePolicy::AllowPrivilegedTest).await?);
        storage.ensure_database_business_key().await?;
        let actor = Uuid::now_v7();
        sqlx::query("INSERT INTO iam.user_account(id,username,username_normalized,role_code,status_code,created_at,updated_at) VALUES ($1,$2,$2,'platform_admin','active',now(),now())")
            .bind(actor).bind(actor.to_string()).execute(&storage.pool()).await?;
        let backend = PgManagementBackend::new(
            storage.clone(),
            SecretBytes::new(vec![1; 32]),
            ReadinessCoordinator::new(gateway_domain::InternalReadiness::default()),
            DataPlaneObservability::default(),
            Arc::new(ExportArtifactStore::new(PathBuf::from("target/openai-management-test"))),
            ManagementRuntimeBridge::new(
                Arc::new(gateway_api::DenyAllAccessResolver),
                Arc::new(gateway_api::StaticModelCatalog::new(Vec::new())),
            ),
            None,
            None,
            ManagementAuthMode::Strict,
            false,
        )?;
        let principal = ManagementPrincipal {
            user_id: actor.to_string().into(),
            session_id: Uuid::now_v7().to_string().into(),
            role: ManagementRole::PlatformAdmin,
            csrf_token: SecretValue::new("fixture".into()),
            mfa_verified: true,
            password_change_required: false,
        };
        let request = |body| ManagementRequest {
            operation_id: "fixture".into(),
            method: axum::http::Method::POST,
            path: "/admin/v1/openai/accounts".into(),
            query: None,
            path_parameters: std::collections::BTreeMap::default(),
            body: Some(body),
            idempotency_key: None,
            if_match: None,
        };
        let group = backend
            .create_group(
                &principal,
                &request(json!({"name":format!("openai-{actor}"),"provider":"openai"})),
            )
            .await?;
        let group_id = group.body["data"]["id"].as_str().ok_or("group id")?;
        assert_eq!(group.body["data"]["provider"], "openai");
        let api = backend
            .create_openai_account(
                &principal,
                &request(
                    json!({"name":"API","group_id":group_id,"auth_kind":"api_key","api_key":"fixture-openai-secret"}),
                ),
            )
            .await?;
        assert_eq!(api.body["data"]["enabled"], false);
        let mut settings_request = request(
            json!({"name":"Updated","enabled":true,"max_concurrency":3,"priority":9,"websocket_enabled":false,"models":["fixture-model"]}),
        );
        settings_request
            .path_parameters
            .insert("id".into(), api.body["data"]["id"].as_str().ok_or("id")?.into());
        settings_request.if_match = Some("\"rev-1\"".into());
        assert!(matches!(
            backend.patch_openai_account(&principal, &settings_request).await,
            Err(ManagementBackendError::Precondition)
        ));
        settings_request.body.as_mut().ok_or("body")?["enabled"] = json!(false);
        backend.patch_openai_account(&principal, &settings_request).await?;
        assert!(matches!(
            backend.patch_openai_account(&principal, &settings_request).await,
            Err(ManagementBackendError::Precondition)
        ));
        let oauth = json!({"name":"OAuth","group_id":group_id,"auth_kind":"oauth","credentials":{"tokens":{"access_token":"fixture-access-secret","account_id":actor.to_string()}}});
        let imported = backend
            .create_openai_account(&principal, &request(oauth.clone()))
            .await?;
        assert_eq!(imported.body["data"]["auth_state"], "manual_update");
        assert!(matches!(
            backend.create_openai_account(&principal, &request(oauth)).await,
            Err(ManagementBackendError::Precondition)
        ));
        // Simulate restart after token exchange, including a failed duplicate import.
        for duplicate in [true, false] {
            let session = Uuid::now_v7();
            let identity = if duplicate { actor } else { Uuid::now_v7() };
            let checkpoint = backend
                .openai_secret(
                    session,
                    "oauth_callback_material",
                    "openai_oauth_checkpoint",
                    &json!({"access_token":"fixture-checkpoint-token","account_id":identity.to_string()}).to_string(),
                )
                .await?;
            let digest = oauth_callback_digest(
                &backend.session_digest_key,
                OAuthCallbackDigestDomain::State,
                &SecretValue::new("fixture-state".into()),
            )?;
            let mut tx = storage.pool().begin().await?;
            insert_secret(&mut tx, checkpoint.0, &checkpoint.1, &checkpoint.2).await?;
            sqlx::query("INSERT INTO gateway.openai_oauth_session(id,actor_id,group_id,name,state_digest,verifier_secret_id,response_secret_id,state_code,expires_at) VALUES($1,$2,$3,'Resumed OAuth',$4,$5,$5,'importing',clock_timestamp()+interval '5 minutes')")
                .bind(session).bind(actor).bind(Uuid::parse_str(group_id)?).bind(digest.as_slice()).bind(checkpoint.0).execute(&mut *tx).await?;
            tx.commit().await?;
            let mut callback = request(json!({"code":"already-exchanged","state":"fixture-state"}));
            callback.path_parameters.insert("id".into(), session.to_string().into());
            let result = backend.finish_openai_oauth(&principal, &callback).await;
            let state: String = sqlx::query_scalar("SELECT state_code FROM gateway.openai_oauth_session WHERE id=$1")
                .bind(session)
                .fetch_one(&storage.pool())
                .await?;
            if duplicate {
                assert!(result.is_err());
                assert_eq!(state, "exchanged");
            } else {
                let response = result?;
                assert_eq!(response.body["data"]["auth_state"], "manual_update");
                assert_eq!(state, "completed");
                assert!(backend.finish_openai_oauth(&principal, &callback).await.is_err());
                let count: i64 = sqlx::query_scalar("SELECT count(*) FROM gateway.openai_account WHERE account_id=$1")
                    .bind(identity.to_string())
                    .fetch_one(&storage.pool())
                    .await?;
                assert_eq!(count, 1);
            }
        }
        let legacy = backend
            .create_group(&principal, &request(json!({"name":format!("legacy-{actor}")})))
            .await?;
        assert!(matches!(backend.create_openai_account(&principal,&request(json!({"name":"wrong","group_id":legacy.body["data"]["id"],"auth_kind":"api_key","api_key":"fixture"}))).await,Err(ManagementBackendError::Precondition)));
        let list = backend
            .list_openai_accounts(&request(json!({})))
            .await?
            .body
            .to_string();
        assert!(!list.contains("fixture-openai-secret"));
        assert!(!list.contains("fixture-access-secret"));
        assert!(!list.contains("secret_id"));
        let mut paged = request(json!({}));
        paged.query = Some("page_size=1".into());
        let first = backend.list_openai_accounts(&paged).await?;
        assert_eq!(first.body["data"].as_array().ok_or("page")?.len(), 1);
        let cursor = first.body["page"]["next_cursor"].as_str().ok_or("cursor")?;
        paged.query = Some(format!("page_size=1&page_after={cursor}").into());
        let second = backend.list_openai_accounts(&paged).await?;
        assert_ne!(first.body["data"][0]["id"], second.body["data"][0]["id"]);
        let groups = backend.list_groups().await?;
        let public_group = groups.body["data"]
            .as_array()
            .ok_or("groups")?
            .iter()
            .find(|g| g["id"] == group_id)
            .ok_or("public group")?;
        assert_eq!(public_group["credential_count"], 3);
        let row = sqlx::query("SELECT s.* FROM security.encrypted_secret s JOIN gateway.openai_account a ON a.access_secret_id=s.id WHERE a.id=$1")
            .bind(Uuid::parse_str(api.body["data"]["id"].as_str().ok_or("account id")?)?).fetch_one(&storage.pool()).await?;
        let version: i64 = required(&row, "key_version")?;
        let root = storage.load_database_business_key(version).await?;
        let envelope = row_envelope(&row, 1, u64::try_from(version)?)?;
        let aad = EnvelopeAad {
            schema_version: 1,
            secret_id: required(&row, "id")?,
            secret_kind: required(&row, "secret_kind_code")?,
            provider_role: "business".into(),
            owner_type: required(&row, "owner_type_code")?,
            owner_id: required(&row, "owner_id")?,
            purpose: required(&row, "purpose_code")?,
            key_version: u64::try_from(version)?,
        };
        let plaintext = EnvelopeService::new(LocalAesKeyProvider::new(
            "business",
            u64::try_from(version)?,
            root.expose().to_vec(),
        )?)
        .decrypt(&envelope, &aad)?;
        assert_eq!(plaintext.expose(), b"fixture-openai-secret");
        let mut replacement = request(
            json!({"name":"OAuth","group_id":group_id,"auth_kind":"oauth","replace_account_id":imported.body["data"]["id"],"credentials":{"access_token":"replacement-access","account_id":actor.to_string()}}),
        );
        replacement.if_match = Some("\"rev-1\"".into());
        let updated = backend.create_openai_account(&principal, &replacement).await?;
        assert_eq!(updated.body["data"]["id"], imported.body["data"]["id"]);
        assert_eq!(updated.body["data"]["revision"], 2);
        assert!(backend.create_openai_account(&principal, &replacement).await.is_err());
        let authorization = backend
            .begin_openai_oauth(&principal, &request(json!({"name":"Browser","group_id":group_id})))
            .await?;
        assert!(
            authorization.body["data"]["authorization_url"]
                .as_str()
                .ok_or("url")?
                .contains("code_challenge_method=S256")
        );
        let mut wrong_callback = request(json!({"code":"fixture","state":"wrong-state"}));
        wrong_callback.path_parameters.insert(
            "id".into(),
            authorization.body["data"]["id"].as_str().ok_or("session")?.into(),
        );
        assert!(backend.finish_openai_oauth(&principal, &wrong_callback).await.is_err());
        let current = backend.get_openai_settings().await?;
        let mut body = current.body["data"].clone();
        body.as_object_mut().ok_or("settings")?.remove("revision");
        body["enabled"] = json!(true);
        let mut update = request(body.clone());
        update.if_match = current.etag.clone();
        assert!(matches!(
            backend.update_openai_settings(&principal, &update).await,
            Err(ManagementBackendError::Precondition)
        ));
        body["enabled"] = json!(false);
        update.body = Some(body);
        backend.update_openai_settings(&principal, &update).await?;
        assert!(matches!(
            backend.update_openai_settings(&principal, &update).await,
            Err(ManagementBackendError::Precondition)
        ));
        Ok(())
    }
    #[test]
    fn settings_enforce_bounded_timeouts() {
        let mut command = OpenAiSettingsCommand {
            enabled: false,
            websocket_enabled: false,
            connect_timeout_seconds: 15,
            response_timeout_seconds: 300,
            websocket_idle_seconds: 120,
            refresh_interval_seconds: 60,
        };
        assert!(command.valid());
        command.refresh_interval_seconds = 0;
        assert!(!command.valid());
        command.refresh_interval_seconds = 60;
        command.connect_timeout_seconds = 121;
        assert!(!command.valid());
    }
    #[test]
    fn old_group_commands_default_to_anthropic() -> Result<(), Box<dyn std::error::Error>> {
        let command: GroupCreateCommand = serde_json::from_value(json!({"name":"legacy"}))?;
        assert_eq!(command.provider, gateway_domain::Provider::Anthropic);
        assert!(serde_json::from_value::<GroupCreateCommand>(json!({"name":"bad","provider":"other"})).is_err());
        Ok(())
    }
}
