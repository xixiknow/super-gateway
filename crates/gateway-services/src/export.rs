//! Encrypted, bounded usage-export encoding and artifact storage.
#![allow(missing_docs, clippy::missing_errors_doc)]

use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gateway_domain::SecretBytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt as _,
};
use uuid::Uuid;

use crate::security::{EnvelopeAad, EnvelopeService, LocalAesKeyProvider, SecretEnvelope};

pub const MAX_EXPORT_ROWS: usize = 10_000;
pub const MAX_USAGE_EXPORT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_EXPORT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Jsonl,
    Csv,
    Raw,
}

impl ExportFormat {
    #[must_use]
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::Csv => "csv",
            Self::Raw => "raw",
        }
    }

    #[must_use]
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Jsonl => "application/x-ndjson",
            Self::Csv => "text/csv; charset=utf-8",
            Self::Raw => "application/octet-stream",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UsageExportRow {
    pub request_id: Uuid,
    pub created_at: String,
    pub owner_user_id: Uuid,
    pub platform_key_id: Uuid,
    pub platform_key_name: String,
    pub group_id: Uuid,
    pub group_name: String,
    pub model_id: Option<Uuid>,
    pub upstream_model_id: Option<String>,
    pub endpoint: String,
    pub outcome: Option<String>,
    pub http_status: Option<i32>,
    pub usage_source: Option<String>,
    pub usage_completeness: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub cache_creation_input_tokens: Option<i64>,
    pub cache_read_input_tokens: Option<i64>,
    pub amount: Option<String>,
    pub currency: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ExportArtifactContext {
    pub export_id: Uuid,
    pub requested_by: Uuid,
    pub dataset: Box<str>,
    pub format: ExportFormat,
    pub query_sha256_hex: Box<str>,
}

#[derive(Clone, Debug)]
pub struct ExportArtifactManifest {
    pub object_uri: Box<str>,
    pub cipher_suite: Box<str>,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub key_version: i64,
    pub content_sha256: Vec<u8>,
    pub content_length: i64,
}

#[derive(Clone, Debug)]
pub struct ExportArtifactStore {
    root: Arc<PathBuf>,
}

impl ExportArtifactStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root: Arc::new(root) }
    }

    pub async fn preflight(&self) -> Result<(), ExportError> {
        fs::create_dir_all(self.root.as_ref())
            .await
            .map_err(|_| ExportError::Io)?;
        let probe = self.root.join(format!(".preflight-{}", Uuid::now_v7().simple()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&probe)
            .await
            .map_err(|_| ExportError::Io)?;
        file.write_all(b"usage-export-preflight-v1")
            .await
            .map_err(|_| ExportError::Io)?;
        file.sync_data().await.map_err(|_| ExportError::Io)?;
        drop(file);
        fs::remove_file(probe).await.map_err(|_| ExportError::Io)
    }

    pub async fn put(
        &self,
        context: &ExportArtifactContext,
        plaintext: &[u8],
        root_key: &SecretBytes,
        key_version: i64,
    ) -> Result<ExportArtifactManifest, ExportError> {
        if plaintext.len() > MAX_EXPORT_BYTES {
            return Err(ExportError::TooLarge);
        }
        let key_version_u64 = u64::try_from(key_version).map_err(|_| ExportError::Integrity)?;
        let service = EnvelopeService::new(
            LocalAesKeyProvider::new("business", key_version_u64, root_key.expose().to_vec())
                .map_err(|_| ExportError::Crypto)?,
        );
        let aad = export_aad(context, key_version_u64);
        let envelope = service
            .encrypt(&SecretBytes::new(plaintext.to_vec()), aad)
            .map_err(|_| ExportError::Crypto)?;
        let ciphertext = STANDARD
            .decode(&envelope.ciphertext_base64)
            .map_err(|_| ExportError::Integrity)?;
        let nonce = STANDARD
            .decode(&envelope.nonce_base64)
            .map_err(|_| ExportError::Integrity)?;
        let wrapped_dek = STANDARD
            .decode(&envelope.wrapped_dek_base64)
            .map_err(|_| ExportError::Integrity)?;
        let staged = self.root.join(format!("{}.stage", context.export_id.simple()));
        let finalized = self.root.join(format!("{}.export", context.export_id.simple()));
        // A prior worker may have lost its generation after finalizing the
        // ciphertext but before committing the database manifest. Only
        // non-terminal jobs call `put`, so replacing that orphan is safe.
        let _ = fs::remove_file(&staged).await;
        let _ = fs::remove_file(&finalized).await;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staged)
            .await
            .map_err(|_| ExportError::Io)?;
        file.write_all(&ciphertext).await.map_err(|_| ExportError::Io)?;
        file.sync_data().await.map_err(|_| ExportError::Io)?;
        drop(file);
        fs::rename(&staged, &finalized)
            .await
            .map_err(|_| ExportError::Finalize)?;
        Ok(ExportArtifactManifest {
            object_uri: finalized.to_string_lossy().into_owned().into_boxed_str(),
            cipher_suite: envelope.cipher_suite.into_boxed_str(),
            nonce,
            wrapped_dek,
            key_version,
            content_sha256: Sha256::digest(&ciphertext).to_vec(),
            content_length: i64::try_from(plaintext.len()).map_err(|_| ExportError::TooLarge)?,
        })
    }

    pub async fn read(
        &self,
        context: &ExportArtifactContext,
        manifest: &ExportArtifactManifest,
        root_key: &SecretBytes,
    ) -> Result<SecretBytes, ExportError> {
        let path = self.confined_path(&manifest.object_uri)?;
        let ciphertext = fs::read(path).await.map_err(|_| ExportError::Io)?;
        if Sha256::digest(&ciphertext).as_slice() != manifest.content_sha256.as_slice() {
            return Err(ExportError::Integrity);
        }
        let key_version_u64 = u64::try_from(manifest.key_version).map_err(|_| ExportError::Integrity)?;
        let service = EnvelopeService::new(
            LocalAesKeyProvider::new("business", key_version_u64, root_key.expose().to_vec())
                .map_err(|_| ExportError::Crypto)?,
        );
        let envelope = SecretEnvelope {
            schema_version: 1,
            cipher_suite: manifest.cipher_suite.to_string(),
            provider_role: "business".to_owned(),
            key_version: key_version_u64,
            ciphertext_base64: STANDARD.encode(ciphertext),
            nonce_base64: STANDARD.encode(&manifest.nonce),
            wrapped_dek_base64: STANDARD.encode(&manifest.wrapped_dek),
        };
        let plaintext = service
            .decrypt(&envelope, &export_aad(context, key_version_u64))
            .map_err(|_| ExportError::Integrity)?;
        if i64::try_from(plaintext.expose().len()).ok() != Some(manifest.content_length) {
            return Err(ExportError::Integrity);
        }
        Ok(plaintext)
    }

    pub async fn remove_uri(&self, object_uri: &str) -> Result<(), ExportError> {
        let path = self.confined_path(object_uri)?;
        match fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ExportError::Io),
        }
    }

    pub async fn sweep_staged(&self) -> Result<usize, ExportError> {
        fs::create_dir_all(self.root.as_ref())
            .await
            .map_err(|_| ExportError::Io)?;
        let mut entries = fs::read_dir(self.root.as_ref()).await.map_err(|_| ExportError::Io)?;
        let mut removed = 0_usize;
        while let Some(entry) = entries.next_entry().await.map_err(|_| ExportError::Io)? {
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "stage") {
                fs::remove_file(path).await.map_err(|_| ExportError::Io)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    pub async fn sweep_unreferenced_finalized(&self, referenced: &BTreeSet<Box<str>>) -> Result<usize, ExportError> {
        fs::create_dir_all(self.root.as_ref())
            .await
            .map_err(|_| ExportError::Io)?;
        let mut entries = fs::read_dir(self.root.as_ref()).await.map_err(|_| ExportError::Io)?;
        let mut removed = 0_usize;
        while let Some(entry) = entries.next_entry().await.map_err(|_| ExportError::Io)? {
            let path = entry.path();
            let old_enough = entry
                .metadata()
                .await
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age >= Duration::from_mins(10));
            if path.extension().is_some_and(|extension| extension == "export")
                && old_enough
                && !referenced.contains(path.to_string_lossy().as_ref())
            {
                fs::remove_file(path).await.map_err(|_| ExportError::Io)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    fn confined_path(&self, object_uri: &str) -> Result<PathBuf, ExportError> {
        let path = PathBuf::from(object_uri);
        if path.parent() != Some(self.root.as_path()) || path.extension().is_none_or(|extension| extension != "export")
        {
            return Err(ExportError::Integrity);
        }
        Ok(path)
    }
}

pub fn encode_usage_export(format: ExportFormat, rows: &[UsageExportRow]) -> Result<Vec<u8>, ExportError> {
    if rows.len() > MAX_EXPORT_ROWS {
        return Err(ExportError::TooManyRows);
    }
    let mut output = Vec::new();
    if format == ExportFormat::Csv {
        output.extend_from_slice(
            b"request_id,created_at,owner_user_id,platform_key_id,platform_key_name,group_id,group_name,model_id,upstream_model_id,endpoint,outcome,http_status,usage_source,usage_completeness,input_tokens,output_tokens,cache_creation_input_tokens,cache_read_input_tokens,amount,currency\r\n",
        );
    }
    for row in rows {
        match format {
            ExportFormat::Jsonl => {
                serde_json::to_writer(&mut output, row).map_err(|_| ExportError::Encoding)?;
                output.push(b'\n');
            }
            ExportFormat::Csv => encode_csv_row(&mut output, row),
            ExportFormat::Raw => return Err(ExportError::Encoding),
        }
        if output.len() > MAX_USAGE_EXPORT_BYTES {
            return Err(ExportError::TooLarge);
        }
    }
    Ok(output)
}

#[must_use]
pub fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn export_aad(context: &ExportArtifactContext, key_version: u64) -> EnvelopeAad {
    EnvelopeAad {
        schema_version: 1,
        secret_id: context.export_id,
        secret_kind: "usage_export".to_owned(),
        provider_role: "business".to_owned(),
        owner_type: "usage_export".to_owned(),
        owner_id: format!("{}:{}", context.export_id, context.requested_by),
        purpose: format!(
            "download:{}:{}:{}",
            context.dataset,
            context.format.as_code(),
            context.query_sha256_hex
        ),
        key_version,
    }
}

fn encode_csv_row(output: &mut Vec<u8>, row: &UsageExportRow) {
    let fields = [
        Some(row.request_id.to_string()),
        Some(row.created_at.clone()),
        Some(row.owner_user_id.to_string()),
        Some(row.platform_key_id.to_string()),
        Some(row.platform_key_name.clone()),
        Some(row.group_id.to_string()),
        Some(row.group_name.clone()),
        row.model_id.map(|value| value.to_string()),
        row.upstream_model_id.clone(),
        Some(row.endpoint.clone()),
        row.outcome.clone(),
        row.http_status.map(|value| value.to_string()),
        row.usage_source.clone(),
        row.usage_completeness.clone(),
        row.input_tokens.map(|value| value.to_string()),
        row.output_tokens.map(|value| value.to_string()),
        row.cache_creation_input_tokens.map(|value| value.to_string()),
        row.cache_read_input_tokens.map(|value| value.to_string()),
        row.amount.clone(),
        row.currency.clone(),
    ];
    for (index, value) in fields.iter().enumerate() {
        if index > 0 {
            output.push(b',');
        }
        write_csv_cell(output, value.as_deref().unwrap_or(""));
    }
    output.extend_from_slice(b"\r\n");
}

fn write_csv_cell(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        output.push(b'\'');
    }
    for byte in value.as_bytes() {
        if *byte == b'"' {
            output.extend_from_slice(b"\"\"");
        } else {
            output.push(*byte);
        }
    }
    output.push(b'"');
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExportError {
    #[error("export has too many rows")]
    TooManyRows,
    #[error("export is too large")]
    TooLarge,
    #[error("export encoding failed")]
    Encoding,
    #[error("export cryptography failed")]
    Crypto,
    #[error("export integrity check failed")]
    Integrity,
    #[error("export storage I/O failed")]
    Io,
    #[error("export finalize failed")]
    Finalize,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn row() -> UsageExportRow {
        UsageExportRow {
            request_id: Uuid::now_v7(),
            created_at: "2026-08-25T00:00:00Z".to_owned(),
            owner_user_id: Uuid::now_v7(),
            platform_key_id: Uuid::now_v7(),
            platform_key_name: "=unsafe,key\"".to_owned(),
            group_id: Uuid::now_v7(),
            group_name: "group".to_owned(),
            model_id: None,
            upstream_model_id: Some("claude-fixture".to_owned()),
            endpoint: "messages".to_owned(),
            outcome: Some("completed".to_owned()),
            http_status: Some(200),
            usage_source: Some("official".to_owned()),
            usage_completeness: Some("partial".to_owned()),
            input_tokens: Some(7),
            output_tokens: None,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            amount: Some("0.000001".to_owned()),
            currency: Some("USD".to_owned()),
        }
    }

    #[test]
    fn jsonl_preserves_unknown_usage_as_null() -> Result<(), ExportError> {
        let bytes = encode_usage_export(ExportFormat::Jsonl, &[row()])?;
        let document: serde_json::Value =
            serde_json::from_slice(bytes.strip_suffix(b"\n").ok_or(ExportError::Encoding)?)
                .map_err(|_| ExportError::Encoding)?;
        assert!(document["output_tokens"].is_null());
        Ok(())
    }

    #[test]
    fn csv_quotes_fields_and_neutralizes_formula_prefixes() -> Result<(), ExportError> {
        let bytes = encode_usage_export(ExportFormat::Csv, &[row()])?;
        let text = String::from_utf8(bytes).map_err(|_| ExportError::Encoding)?;
        assert!(text.contains("\"'=unsafe,key\"\"\""));
        assert!(text.contains(",\"\","));
        Ok(())
    }

    #[test]
    fn raw_format_is_reserved_for_prebuilt_content_audit_bytes() {
        assert_eq!(
            encode_usage_export(ExportFormat::Raw, &[row()]),
            Err(ExportError::Encoding)
        );
        assert_eq!(ExportFormat::Raw.content_type(), "application/octet-stream");
    }

    #[tokio::test]
    async fn artifact_round_trip_is_aad_bound_and_path_confined() -> Result<(), ExportError> {
        let root = std::env::temp_dir().join(format!("gateway-export-test-{}", Uuid::now_v7().simple()));
        let store = ExportArtifactStore::new(root);
        store.preflight().await?;
        let context = ExportArtifactContext {
            export_id: Uuid::now_v7(),
            requested_by: Uuid::now_v7(),
            dataset: "usage_requests_v1".into(),
            format: ExportFormat::Jsonl,
            query_sha256_hex: "11".repeat(32).into_boxed_str(),
        };
        let key = SecretBytes::new(vec![0x55; 32]);
        let plaintext = b"{\"request_id\":\"fixture\"}\n";
        let manifest = store.put(&context, plaintext, &key, 1).await?;
        let ciphertext = fs::read(manifest.object_uri.as_ref())
            .await
            .map_err(|_| ExportError::Io)?;
        assert!(!ciphertext.windows(7).any(|window| window == b"fixture"));
        assert_eq!(store.read(&context, &manifest, &key).await?.expose(), plaintext);
        let mut wrong_context = context.clone();
        wrong_context.requested_by = Uuid::now_v7();
        assert_eq!(
            store
                .read(&wrong_context, &manifest, &key)
                .await
                .expect_err("AAD must bind requester"),
            ExportError::Integrity
        );
        let mut escaped = manifest.clone();
        escaped.object_uri = std::env::temp_dir()
            .join("outside.export")
            .to_string_lossy()
            .into_owned()
            .into_boxed_str();
        assert_eq!(
            store
                .read(&context, &escaped, &key)
                .await
                .expect_err("path must remain confined"),
            ExportError::Integrity
        );
        store.remove_uri(&manifest.object_uri).await?;
        Ok(())
    }
}
