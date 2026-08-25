//! Encrypted Content Audit object store and first-upstream-byte latch.
#![allow(missing_docs, clippy::missing_errors_doc, clippy::struct_excessive_bools)]

use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use gateway_domain::SecretBytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncReadExt as _, AsyncWriteExt as _},
};
use uuid::Uuid;

const FRAME_PLAINTEXT: usize = 1024 * 1024;
const DEFAULT_OBJECT_LIMIT: usize = 64 * 1024 * 1024;
const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditCaptureKind {
    OriginalRequest,
    FinalRequest,
    Response,
}

impl AuditCaptureKind {
    #[must_use]
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::OriginalRequest => "original_request",
            Self::FinalRequest => "final_request",
            Self::Response => "response",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuditObjectContext {
    pub object_id: Uuid,
    pub request_id: Uuid,
    pub attempt_id: Option<Uuid>,
    pub kind: AuditCaptureKind,
    pub policy_version: Box<str>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditObjectManifest {
    pub object_id: Uuid,
    pub object_uri: Box<str>,
    pub schema_version: u32,
    pub cipher_suite: Box<str>,
    pub nonce_prefix_base64: Box<str>,
    pub wrapped_dek_base64: Box<str>,
    pub wrapping_nonce_base64: Box<str>,
    pub frame_count: u32,
    pub plaintext_length: u64,
    pub ciphertext_sha256: Box<str>,
    pub truncated: bool,
}

#[derive(Clone, Debug)]
pub struct ContentAuditStore {
    root: Arc<PathBuf>,
    root_key: Arc<SecretBytes>,
    object_limit: usize,
}

impl ContentAuditStore {
    pub fn new(root: PathBuf, root_key: SecretBytes) -> Result<Self, ContentAuditError> {
        if root_key.expose().len() != 32 {
            return Err(ContentAuditError::InvalidConfiguration);
        }
        Ok(Self {
            root: Arc::new(root),
            root_key: Arc::new(root_key),
            object_limit: DEFAULT_OBJECT_LIMIT,
        })
    }

    #[must_use]
    pub fn with_object_limit(mut self, object_limit: usize) -> Self {
        self.object_limit = object_limit.max(1);
        self
    }

    pub async fn preflight(&self) -> Result<(), ContentAuditError> {
        fs::create_dir_all(self.root.as_ref())
            .await
            .map_err(|_| ContentAuditError::Io)?;
        let probe = self.root.join(format!(".preflight-{}", Uuid::now_v7().simple()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&probe)
            .await
            .map_err(|_| ContentAuditError::Io)?;
        file.write_all(b"content-audit-preflight-v1")
            .await
            .map_err(|_| ContentAuditError::Io)?;
        file.sync_data().await.map_err(|_| ContentAuditError::Io)?;
        drop(file);
        fs::remove_file(probe).await.map_err(|_| ContentAuditError::Io)
    }

    pub async fn put(
        &self,
        context: &AuditObjectContext,
        plaintext: &[u8],
    ) -> Result<AuditObjectManifest, ContentAuditError> {
        self.preflight().await?;
        let truncated = plaintext.len() > self.object_limit;
        let plaintext = &plaintext[..plaintext.len().min(self.object_limit)];
        let mut dek = [0_u8; 32];
        let mut prefix = [0_u8; 8];
        getrandom::fill(&mut dek).map_err(|_| ContentAuditError::Crypto)?;
        getrandom::fill(&mut prefix).map_err(|_| ContentAuditError::Crypto)?;
        let object_cipher = Aes256Gcm::new_from_slice(&dek).map_err(|_| ContentAuditError::Crypto)?;
        let staged = self.root.join(format!("{}.stage", context.object_id.simple()));
        let finalized = self.root.join(format!("{}.audit", context.object_id.simple()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staged)
            .await
            .map_err(|_| ContentAuditError::Io)?;
        let mut ciphertext_hash = Sha256::new();
        let mut frame_count = 0_u32;
        for (index, frame) in plaintext.chunks(FRAME_PLAINTEXT).enumerate() {
            let index = u32::try_from(index).map_err(|_| ContentAuditError::TooLarge)?;
            let nonce = frame_nonce(prefix, index);
            let aad = frame_aad(context, index);
            let ciphertext = object_cipher
                .encrypt(Nonce::from_slice(&nonce), Payload { msg: frame, aad: &aad })
                .map_err(|_| ContentAuditError::Crypto)?;
            let length = u32::try_from(ciphertext.len()).map_err(|_| ContentAuditError::TooLarge)?;
            file.write_u32(length).await.map_err(|_| ContentAuditError::Io)?;
            file.write_all(&ciphertext).await.map_err(|_| ContentAuditError::Io)?;
            ciphertext_hash.update(length.to_be_bytes());
            ciphertext_hash.update(&ciphertext);
            frame_count = frame_count.checked_add(1).ok_or(ContentAuditError::TooLarge)?;
        }
        file.flush().await.map_err(|_| ContentAuditError::Io)?;
        file.sync_data().await.map_err(|_| ContentAuditError::Io)?;
        drop(file);
        fs::rename(&staged, &finalized)
            .await
            .map_err(|_| ContentAuditError::Finalize)?;
        let (wrapped_dek, wrapping_nonce) = self.wrap_dek(context, &dek)?;
        dek.fill(0);
        Ok(AuditObjectManifest {
            object_id: context.object_id,
            object_uri: finalized.to_string_lossy().into_owned().into_boxed_str(),
            schema_version: 1,
            cipher_suite: "aes_256_gcm_framed".into(),
            nonce_prefix_base64: encode(prefix).into_boxed_str(),
            wrapped_dek_base64: encode(wrapped_dek).into_boxed_str(),
            wrapping_nonce_base64: encode(wrapping_nonce).into_boxed_str(),
            frame_count,
            plaintext_length: u64::try_from(plaintext.len()).map_err(|_| ContentAuditError::TooLarge)?,
            ciphertext_sha256: format!("{:x}", ciphertext_hash.finalize()).into_boxed_str(),
            truncated,
        })
    }

    pub async fn read(
        &self,
        context: &AuditObjectContext,
        manifest: &AuditObjectManifest,
    ) -> Result<Vec<u8>, ContentAuditError> {
        let plaintext_length = usize::try_from(manifest.plaintext_length).map_err(|_| ContentAuditError::TooLarge)?;
        let expected_frames = plaintext_length.div_ceil(FRAME_PLAINTEXT);
        if context.object_id != manifest.object_id
            || manifest.schema_version != 1
            || plaintext_length > self.object_limit
            || usize::try_from(manifest.frame_count).ok() != Some(expected_frames)
        {
            return Err(ContentAuditError::Integrity);
        }
        let object_path = PathBuf::from(manifest.object_uri.as_ref());
        if object_path.parent() != Some(self.root.as_path())
            || object_path.extension().is_none_or(|extension| extension != "audit")
        {
            return Err(ContentAuditError::Integrity);
        }
        let prefix: [u8; 8] = decode(&manifest.nonce_prefix_base64)?
            .try_into()
            .map_err(|_| ContentAuditError::Integrity)?;
        let wrapping_nonce: [u8; 12] = decode(&manifest.wrapping_nonce_base64)?
            .try_into()
            .map_err(|_| ContentAuditError::Integrity)?;
        let wrapped_dek = decode(&manifest.wrapped_dek_base64)?;
        let root_cipher = Aes256Gcm::new_from_slice(self.root_key.expose()).map_err(|_| ContentAuditError::Crypto)?;
        let dek = SecretBytes::new(
            root_cipher
                .decrypt(
                    Nonce::from_slice(&wrapping_nonce),
                    Payload {
                        msg: &wrapped_dek,
                        aad: &wrap_aad(context),
                    },
                )
                .map_err(|_| ContentAuditError::Integrity)?,
        );
        let object_cipher = Aes256Gcm::new_from_slice(dek.expose()).map_err(|_| ContentAuditError::Integrity)?;
        let mut file = fs::File::open(object_path).await.map_err(|_| ContentAuditError::Io)?;
        let mut output = Vec::with_capacity(plaintext_length);
        let mut hash = Sha256::new();
        for index in 0..manifest.frame_count {
            let length = file.read_u32().await.map_err(|_| ContentAuditError::Integrity)?;
            let length_usize = usize::try_from(length).map_err(|_| ContentAuditError::TooLarge)?;
            if length_usize > FRAME_PLAINTEXT + TAG_LEN {
                return Err(ContentAuditError::Integrity);
            }
            let mut ciphertext = vec![0_u8; length_usize];
            file.read_exact(&mut ciphertext)
                .await
                .map_err(|_| ContentAuditError::Integrity)?;
            hash.update(length.to_be_bytes());
            hash.update(&ciphertext);
            let frame = object_cipher
                .decrypt(
                    Nonce::from_slice(&frame_nonce(prefix, index)),
                    Payload {
                        msg: &ciphertext,
                        aad: &frame_aad(context, index),
                    },
                )
                .map_err(|_| ContentAuditError::Integrity)?;
            output.extend_from_slice(&frame);
        }
        let mut residual = [0_u8; 1];
        if file.read(&mut residual).await.map_err(|_| ContentAuditError::Io)? != 0
            || format!("{:x}", hash.finalize()) != manifest.ciphertext_sha256.as_ref()
            || output.len() != usize::try_from(manifest.plaintext_length).map_err(|_| ContentAuditError::TooLarge)?
        {
            return Err(ContentAuditError::Integrity);
        }
        Ok(output)
    }

    pub async fn sweep_staged(&self) -> Result<usize, ContentAuditError> {
        fs::create_dir_all(self.root.as_ref())
            .await
            .map_err(|_| ContentAuditError::Io)?;
        let mut entries = fs::read_dir(self.root.as_ref())
            .await
            .map_err(|_| ContentAuditError::Io)?;
        let mut removed = 0_usize;
        while let Some(entry) = entries.next_entry().await.map_err(|_| ContentAuditError::Io)? {
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "stage") {
                fs::remove_file(path).await.map_err(|_| ContentAuditError::Io)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    /// Remove one finalized object after its database manifest transaction
    /// failed. The path must be a direct `.audit` child of this store.
    pub async fn remove_finalized(&self, manifest: &AuditObjectManifest) -> Result<(), ContentAuditError> {
        self.remove_uri(manifest.object_uri.as_ref()).await
    }

    /// Destroy a finalized ciphertext object selected from a durable database
    /// manifest. Path confinement prevents a forged URI from escaping the
    /// configured store root.
    pub async fn remove_uri(&self, object_uri: &str) -> Result<(), ContentAuditError> {
        let path = PathBuf::from(object_uri);
        if path.parent() != Some(self.root.as_path()) || path.extension().is_none_or(|extension| extension != "audit") {
            return Err(ContentAuditError::Integrity);
        }
        match fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ContentAuditError::Io),
        }
    }

    /// Reconcile crash-window finalized files against durable database object
    /// URIs before readiness. Only direct `.audit` children are considered.
    pub async fn sweep_unreferenced_finalized(
        &self,
        referenced: &BTreeSet<Box<str>>,
    ) -> Result<usize, ContentAuditError> {
        fs::create_dir_all(self.root.as_ref())
            .await
            .map_err(|_| ContentAuditError::Io)?;
        let mut entries = fs::read_dir(self.root.as_ref())
            .await
            .map_err(|_| ContentAuditError::Io)?;
        let mut removed = 0_usize;
        while let Some(entry) = entries.next_entry().await.map_err(|_| ContentAuditError::Io)? {
            let path = entry.path();
            let old_enough = entry
                .metadata()
                .await
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age >= Duration::from_mins(10));
            if path.is_file()
                && path.extension().is_some_and(|extension| extension == "audit")
                && old_enough
                && !referenced.contains(path.to_string_lossy().as_ref())
            {
                fs::remove_file(path).await.map_err(|_| ContentAuditError::Io)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    fn wrap_dek(&self, context: &AuditObjectContext, dek: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12]), ContentAuditError> {
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| ContentAuditError::Crypto)?;
        let cipher = Aes256Gcm::new_from_slice(self.root_key.expose()).map_err(|_| ContentAuditError::Crypto)?;
        let wrapped = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: dek,
                    aad: &wrap_aad(context),
                },
            )
            .map_err(|_| ContentAuditError::Crypto)?;
        Ok((wrapped, nonce))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ContentAuditLatch {
    original_durable: bool,
    first_final_durable: bool,
    upstream_started: bool,
    audit_gap: bool,
}

impl ContentAuditLatch {
    pub fn original_durable(&mut self) -> Result<(), ContentAuditError> {
        if self.upstream_started {
            return Err(ContentAuditError::LatchOrder);
        }
        self.original_durable = true;
        Ok(())
    }

    pub fn first_final_durable(&mut self) -> Result<(), ContentAuditError> {
        if self.upstream_started || !self.original_durable {
            return Err(ContentAuditError::LatchOrder);
        }
        self.first_final_durable = true;
        Ok(())
    }

    pub fn start_upstream(&mut self) -> Result<(), ContentAuditError> {
        if !self.original_durable || !self.first_final_durable || self.upstream_started {
            return Err(ContentAuditError::LatchOrder);
        }
        self.upstream_started = true;
        Ok(())
    }

    pub fn side_writer_failed(&mut self) -> Result<(), ContentAuditError> {
        if !self.upstream_started {
            return Err(ContentAuditError::LatchOrder);
        }
        self.audit_gap = true;
        Ok(())
    }

    #[must_use]
    pub const fn upstream_started(self) -> bool {
        self.upstream_started
    }

    #[must_use]
    pub const fn audit_gap(self) -> bool {
        self.audit_gap
    }
}

fn frame_nonce(prefix: [u8; 8], index: u32) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..8].copy_from_slice(&prefix);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn frame_aad(context: &AuditObjectContext, index: u32) -> Vec<u8> {
    format!(
        "gateway-content-audit-frame-v1:{}:{}:{}:{}:{}:{}",
        context.object_id,
        context.request_id,
        context
            .attempt_id
            .map_or_else(|| "none".to_owned(), |value| value.to_string()),
        context.kind.as_code(),
        context.policy_version,
        index
    )
    .into_bytes()
}

fn wrap_aad(context: &AuditObjectContext) -> Vec<u8> {
    format!(
        "gateway-content-audit-dek-v1:{}:{}:{}:{}",
        context.object_id,
        context.request_id,
        context.kind.as_code(),
        context.policy_version
    )
    .into_bytes()
}

fn encode(value: impl AsRef<[u8]>) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(value)
}

fn decode(value: &str) -> Result<Vec<u8>, ContentAuditError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| ContentAuditError::Integrity)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContentAuditError {
    #[error("content audit configuration is invalid")]
    InvalidConfiguration,
    #[error("content audit object I/O failed")]
    Io,
    #[error("content audit cryptography failed")]
    Crypto,
    #[error("content audit object is too large")]
    TooLarge,
    #[error("content audit object finalization failed")]
    Finalize,
    #[error("content audit object integrity failed")]
    Integrity,
    #[error("content audit latch order is invalid")]
    LatchOrder,
}

#[cfg(test)]
mod tests {
    use gateway_domain::SecretBytes;

    use super::{AuditCaptureKind, AuditObjectContext, ContentAuditError, ContentAuditLatch, ContentAuditStore};

    #[tokio::test]
    async fn framed_object_round_trips_and_truncates_without_mutating_source() -> Result<(), ContentAuditError> {
        let directory = std::env::temp_dir().join(format!("gateway-content-audit-{}", uuid::Uuid::now_v7()));
        let store = ContentAuditStore::new(directory.clone(), SecretBytes::new(vec![7; 32]))?.with_object_limit(5);
        let context = AuditObjectContext {
            object_id: uuid::Uuid::now_v7(),
            request_id: uuid::Uuid::now_v7(),
            attempt_id: None,
            kind: AuditCaptureKind::OriginalRequest,
            policy_version: "policy-v1".into(),
        };
        let source = b"0123456789";
        let manifest = store.put(&context, source).await?;
        assert!(manifest.truncated);
        assert_eq!(store.read(&context, &manifest).await?, b"01234");
        assert_eq!(source, b"0123456789");
        tokio::fs::remove_dir_all(directory)
            .await
            .map_err(|_| ContentAuditError::Io)?;
        Ok(())
    }

    #[tokio::test]
    async fn read_rejects_manifest_length_and_path_before_allocating_or_opening() -> Result<(), ContentAuditError> {
        let directory = std::env::temp_dir().join(format!("gateway-content-audit-{}", uuid::Uuid::now_v7()));
        let store = ContentAuditStore::new(directory.clone(), SecretBytes::new(vec![9; 32]))?.with_object_limit(8);
        let context = AuditObjectContext {
            object_id: uuid::Uuid::now_v7(),
            request_id: uuid::Uuid::now_v7(),
            attempt_id: None,
            kind: AuditCaptureKind::Response,
            policy_version: "policy-v2".into(),
        };
        let manifest = store.put(&context, b"12345678").await?;
        let mut oversized = manifest.clone();
        oversized.plaintext_length = 9;
        assert_eq!(
            store.read(&context, &oversized).await,
            Err(ContentAuditError::Integrity)
        );
        let mut escaped = manifest.clone();
        escaped.object_uri = directory
            .join("nested")
            .join("object.audit")
            .to_string_lossy()
            .into_owned()
            .into();
        assert_eq!(store.read(&context, &escaped).await, Err(ContentAuditError::Integrity));
        tokio::fs::remove_dir_all(directory)
            .await
            .map_err(|_| ContentAuditError::Io)?;
        Ok(())
    }

    #[test]
    fn first_byte_latch_fails_closed_then_records_post_start_gap() -> Result<(), ContentAuditError> {
        let mut latch = ContentAuditLatch::default();
        assert_eq!(latch.start_upstream(), Err(ContentAuditError::LatchOrder));
        latch.original_durable()?;
        latch.first_final_durable()?;
        latch.start_upstream()?;
        latch.side_writer_failed()?;
        assert!(latch.upstream_started());
        assert!(latch.audit_gap());
        Ok(())
    }
}
