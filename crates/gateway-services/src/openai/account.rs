//! Secret-redacting Codex credential imports and refresh rotation.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use gateway_domain::SecretValue;
use serde::Deserialize;
use serde_json::Value;

use super::OpenAiError;

/// OAuth credential material. Never serialize this structure into management responses.
#[derive(Debug)]
pub struct OAuthMaterial {
    /// Bearer token.
    pub access_token: SecretValue,
    /// Absent for manually maintained access-token imports.
    pub refresh_token: Option<SecretValue>,
    /// ID token, when supplied by the authorization server.
    pub id_token: Option<SecretValue>,
    /// Workspace/account identity; distinct from a person or email address.
    pub account_id: String,
    /// User identity extracted as an untrusted hint until upstream verification.
    pub user_id: Option<String>,
    /// Unix expiry hint; upstream verification remains authoritative.
    pub expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct ImportDocument {
    tokens: Option<Value>,
    #[serde(flatten)]
    fields: serde_json::Map<String, Value>,
}

impl OAuthMaterial {
    /// Import Codex auth.json or a flat token document without treating JWT claims as verified.
    ///
    /// # Errors
    /// Rejects malformed material and conflicting explicit versus token identities.
    pub fn import(bytes: &[u8]) -> Result<Self, OpenAiError> {
        if bytes.len() > 1024 * 1024 {
            return Err(OpenAiError::InvalidCredential);
        }
        let document: ImportDocument = serde_json::from_slice(bytes).map_err(|_| OpenAiError::InvalidCredential)?;
        let value = document.tokens.unwrap_or(Value::Object(document.fields));
        let access = nonempty(&value, "access_token").ok_or(OpenAiError::InvalidCredential)?;
        let claims = decode_claims(access);
        let id_claims = nonempty(&value, "id_token").and_then(decode_claims);
        if let (Some(access_id), Some(id_id)) = (
            claims.as_ref().and_then(account_claim),
            id_claims.as_ref().and_then(account_claim),
        ) && access_id != id_id
        {
            return Err(OpenAiError::IdentityConflict);
        }
        let claim_identity = claims
            .as_ref()
            .and_then(account_claim)
            .or_else(|| id_claims.as_ref().and_then(account_claim));
        let explicit = nonempty(&value, "account_id").or_else(|| nonempty(&value, "chatgpt_account_id"));
        if let (Some(explicit), Some(claim)) = (explicit, claim_identity)
            && explicit != claim
        {
            return Err(OpenAiError::IdentityConflict);
        }
        let account_id = explicit.or(claim_identity).ok_or(OpenAiError::InvalidCredential)?;
        if account_id.len() > 256 || account_id.chars().any(char::is_control) {
            return Err(OpenAiError::InvalidCredential);
        }
        Ok(Self {
            access_token: SecretValue::new(access.to_owned()),
            refresh_token: nonempty(&value, "refresh_token").map(|s| SecretValue::new(s.to_owned())),
            id_token: nonempty(&value, "id_token").map(|s| SecretValue::new(s.to_owned())),
            account_id: account_id.to_owned(),
            user_id: claims
                .as_ref()
                .and_then(|v| v.pointer("/https:~1~1api.openai.com~1auth/chatgpt_user_id"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            expires_at: claims.as_ref().and_then(|v| v.get("exp")).and_then(Value::as_u64),
        })
    }

    /// Whether maintenance can renew the access token automatically.
    #[must_use]
    pub fn refreshable(&self) -> bool {
        self.refresh_token.as_ref().is_some_and(|token| !token.is_empty())
    }

    /// Apply a token response after upstream identity verification and persistent version CAS.
    ///
    /// # Errors
    /// Rejects empty tokens or identity changes. Missing refresh tokens preserve the old token.
    pub fn rotate(&mut self, response: &Value, verified_account_id: &str) -> Result<(), OpenAiError> {
        if verified_account_id != self.account_id {
            return Err(OpenAiError::IdentityConflict);
        }
        let access = nonempty(response, "access_token").ok_or(OpenAiError::InvalidCredential)?;
        let claims = decode_claims(access);
        if nonempty(response, "id_token")
            .and_then(decode_claims)
            .as_ref()
            .and_then(account_claim)
            .is_some_and(|id| id != self.account_id)
        {
            return Err(OpenAiError::IdentityConflict);
        }
        if claims
            .as_ref()
            .and_then(account_claim)
            .is_some_and(|id| id != self.account_id)
        {
            return Err(OpenAiError::IdentityConflict);
        }
        self.access_token = SecretValue::new(access.to_owned());
        if let Some(refresh) = nonempty(response, "refresh_token") {
            self.refresh_token = Some(SecretValue::new(refresh.to_owned()));
        }
        if let Some(id) = nonempty(response, "id_token") {
            self.id_token = Some(SecretValue::new(id.to_owned()));
        }
        self.expires_at = claims.as_ref().and_then(|v| v.get("exp")).and_then(Value::as_u64);
        Ok(())
    }
}

fn nonempty<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
}

fn decode_claims(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    parts.next()?;
    let payload = parts.next()?;
    if payload.len() > 64 * 1024 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn account_claim(value: &Value) -> Option<&str> {
    value
        .pointer("/https:~1~1api.openai.com~1auth/chatgpt_account_id")?
        .as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn import_and_rotation_preserve_refresh_secret() -> Result<(), OpenAiError> {
        let mut material = OAuthMaterial::import(
            br#"{"tokens":{"access_token":"old","refresh_token":"refresh-secret","account_id":"workspace"}}"#,
        )?;
        material.rotate(&json!({"access_token":"new"}), "workspace")?;
        assert_eq!(
            material.refresh_token.as_ref().map(SecretValue::expose),
            Some("refresh-secret")
        );
        assert!(!format!("{material:?}").contains("refresh-secret"));
        assert_eq!(
            material.rotate(&json!({"access_token":"other"}), "other"),
            Err(OpenAiError::IdentityConflict)
        );
        assert_eq!(material.access_token.expose(), "new");
        Ok(())
    }

    #[test]
    fn access_only_requires_manual_maintenance() -> Result<(), OpenAiError> {
        let material = OAuthMaterial::import(br#"{"access_token":"token","account_id":"workspace"}"#)?;
        assert!(!material.refreshable());
        Ok(())
    }
}
