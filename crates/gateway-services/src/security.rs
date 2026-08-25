//! Secret-envelope, password hashing and audit-integrity services.

#![allow(
    clippy::missing_errors_doc,
    reason = "all cryptographic entry points use the documented SecurityError taxonomy"
)]

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use gateway_domain::{SecretBytes, SecretValue};
use gateway_storage::{PgStorage, StorageError};
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Security service ABI version.
pub const ABI_VERSION: &str = "security-service-r2-v1";
const DEK_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// OAuth PKCE material. Secret-bearing fields redact their `Debug` representation.
pub struct OAuthPkceMaterial {
    /// One-time authorization state sent on the front channel.
    pub state: SecretValue,
    /// RFC 7636 verifier encrypted by the persistence adapter.
    pub verifier: SecretValue,
    /// S256 challenge safe for the authorization URL.
    pub challenge: String,
    /// One-time callback binding nonce.
    pub callback_nonce: SecretValue,
    /// Keyed digest persisted instead of plaintext state.
    pub state_digest: [u8; 32],
    /// Keyed digest persisted instead of plaintext callback nonce.
    pub callback_nonce_digest: [u8; 32],
}

impl std::fmt::Debug for OAuthPkceMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthPkceMaterial")
            .field("state", &"[REDACTED]")
            .field("verifier", &"[REDACTED]")
            .field("challenge", &self.challenge)
            .field("callback_nonce", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Generate state, callback nonce, and an RFC 7636 S256 verifier/challenge pair.
pub fn generate_oauth_pkce(digest_key: &SecretBytes) -> Result<OAuthPkceMaterial, SecurityError> {
    if digest_key.expose().len() < 32 {
        return Err(SecurityError::InvalidKeyMaterial);
    }
    let mut state_bytes = [0_u8; 32];
    let mut verifier_bytes = [0_u8; 32];
    let mut nonce_bytes = [0_u8; 32];
    getrandom::fill(&mut state_bytes).map_err(|_| SecurityError::RandomnessUnavailable)?;
    getrandom::fill(&mut verifier_bytes).map_err(|_| SecurityError::RandomnessUnavailable)?;
    getrandom::fill(&mut nonce_bytes).map_err(|_| SecurityError::RandomnessUnavailable)?;
    let state = URL_SAFE_NO_PAD.encode(state_bytes);
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let callback_nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state_digest = oauth_binding_digest(digest_key, b"state", state.as_bytes())?;
    let callback_nonce_digest = oauth_binding_digest(digest_key, b"callback-nonce", callback_nonce.as_bytes())?;
    state_bytes.zeroize();
    verifier_bytes.zeroize();
    nonce_bytes.zeroize();
    Ok(OAuthPkceMaterial {
        state: SecretValue::new(state),
        verifier: SecretValue::new(verifier),
        challenge,
        callback_nonce: SecretValue::new(callback_nonce),
        state_digest,
        callback_nonce_digest,
    })
}

/// Recompute a domain-separated callback binding digest for constant-time comparison at the API edge.
pub fn oauth_callback_digest(
    digest_key: &SecretBytes,
    domain: OAuthCallbackDigestDomain,
    value: &SecretValue,
) -> Result<[u8; 32], SecurityError> {
    let label = match domain {
        OAuthCallbackDigestDomain::State => b"state".as_slice(),
        OAuthCallbackDigestDomain::CallbackNonce => b"callback-nonce".as_slice(),
    };
    oauth_binding_digest(digest_key, label, value.expose().as_bytes())
}

/// Domain of an OAuth callback lookup digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthCallbackDigestDomain {
    /// OAuth state.
    State,
    /// Gateway callback nonce.
    CallbackNonce,
}

fn oauth_binding_digest(key: &SecretBytes, domain: &[u8], value: &[u8]) -> Result<[u8; 32], SecurityError> {
    let mut hmac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(key.expose())
        .map_err(|_| SecurityError::InvalidKeyMaterial)?;
    hmac.update(b"gateway-oauth-pkce-v1");
    hmac.update(domain);
    hmac.update(value);
    Ok(hmac.finalize().into_bytes().into())
}

/// Stable AAD identity. Changing owner, kind, purpose or key version invalidates decryption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeAad {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Secret row identity.
    pub secret_id: Uuid,
    /// Closed secret kind code.
    pub secret_kind: String,
    /// `KeyProvider` purpose domain.
    pub provider_role: String,
    /// Aggregate owner type.
    pub owner_type: String,
    /// Aggregate owner reference.
    pub owner_id: String,
    /// Narrow use-site purpose.
    pub purpose: String,
    /// Provider key version.
    pub key_version: u64,
}

impl EnvelopeAad {
    fn payload_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(b"gateway-secret-payload-aad-v1");
        push_field(&mut bytes, &self.schema_version.to_be_bytes());
        push_field(&mut bytes, self.secret_id.as_bytes());
        for field in [
            self.secret_kind.as_bytes(),
            self.provider_role.as_bytes(),
            self.owner_type.as_bytes(),
            self.owner_id.as_bytes(),
            self.purpose.as_bytes(),
        ] {
            push_field(&mut bytes, field);
        }
        bytes
    }

    fn wrap_bytes(&self) -> Vec<u8> {
        let mut bytes = self.payload_bytes();
        bytes.extend_from_slice(b"gateway-secret-wrap-aad-v1");
        push_field(&mut bytes, &self.key_version.to_be_bytes());
        bytes
    }
}

fn push_field(buffer: &mut Vec<u8>, field: &[u8]) {
    buffer.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buffer.extend_from_slice(field);
}

/// Non-secret persistence form for an AES-256-GCM secret envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Fixed cipher suite identifier.
    pub cipher_suite: String,
    /// Provider role.
    pub provider_role: String,
    /// Provider key version used to wrap the DEK.
    pub key_version: u64,
    /// Base64 ciphertext including the GCM tag.
    pub ciphertext_base64: String,
    /// Base64 12-byte content nonce.
    pub nonce_base64: String,
    /// Provider-specific wrapped DEK.
    pub wrapped_dek_base64: String,
}

/// `KeyProvider` operations required by the envelope service.
pub trait KeyProvider: Send + Sync {
    /// Role served by this provider.
    fn role(&self) -> &'static str;
    /// Active version for new writes.
    fn active_key_version(&self) -> Result<u64, SecurityError>;
    /// Wrap a fresh data-encryption key under a provider key version.
    fn wrap_dek(&self, key_version: u64, dek: &[u8], aad: &[u8]) -> Result<Vec<u8>, SecurityError>;
    /// Unwrap a data-encryption key. Historical decrypt-only versions remain readable.
    fn unwrap_dek(&self, key_version: u64, wrapped: &[u8], aad: &[u8]) -> Result<SecretBytes, SecurityError>;
}

/// Encrypt and decrypt ordinary business secrets.
pub struct EnvelopeService<P> {
    provider: P,
}

impl<P: KeyProvider> EnvelopeService<P> {
    /// Bind a service to one purpose-domain provider.
    #[must_use]
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Encrypt a plaintext with a fresh per-record DEK and nonce.
    pub fn encrypt(&self, plaintext: &SecretBytes, mut aad: EnvelopeAad) -> Result<SecretEnvelope, SecurityError> {
        let key_version = self.provider.active_key_version()?;
        aad.key_version = key_version;
        if aad.provider_role != self.provider.role() {
            return Err(SecurityError::ProviderRoleMismatch);
        }
        let payload_aad = aad.payload_bytes();
        let wrap_aad = aad.wrap_bytes();
        let mut dek = Zeroizing::new(vec![0_u8; DEK_BYTES]);
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(dek.as_mut_slice()).map_err(|_| SecurityError::RandomnessUnavailable)?;
        getrandom::fill(&mut nonce).map_err(|_| SecurityError::RandomnessUnavailable)?;
        let cipher = Aes256Gcm::new_from_slice(dek.as_slice()).map_err(|_| SecurityError::InvalidKeyMaterial)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.expose(),
                    aad: &payload_aad,
                },
            )
            .map_err(|_| SecurityError::EncryptionFailed)?;
        let wrapped_dek = self.provider.wrap_dek(key_version, dek.as_slice(), &wrap_aad)?;
        Ok(SecretEnvelope {
            schema_version: aad.schema_version,
            cipher_suite: "aes_256_gcm".to_owned(),
            provider_role: aad.provider_role,
            key_version,
            ciphertext_base64: BASE64.encode(ciphertext),
            nonce_base64: BASE64.encode(nonce),
            wrapped_dek_base64: BASE64.encode(wrapped_dek),
        })
    }

    /// Decrypt after authenticating envelope metadata and AAD.
    pub fn decrypt(&self, envelope: &SecretEnvelope, aad: &EnvelopeAad) -> Result<SecretBytes, SecurityError> {
        if envelope.cipher_suite != "aes_256_gcm"
            || envelope.provider_role != self.provider.role()
            || aad.provider_role != self.provider.role()
            || envelope.key_version != aad.key_version
            || envelope.schema_version != aad.schema_version
        {
            return Err(SecurityError::EnvelopeMismatch);
        }
        let payload_aad = aad.payload_bytes();
        let wrap_aad = aad.wrap_bytes();
        let wrapped = BASE64
            .decode(&envelope.wrapped_dek_base64)
            .map_err(|_| SecurityError::EnvelopeMalformed)?;
        let dek = self.provider.unwrap_dek(envelope.key_version, &wrapped, &wrap_aad)?;
        let nonce = BASE64
            .decode(&envelope.nonce_base64)
            .map_err(|_| SecurityError::EnvelopeMalformed)?;
        if nonce.len() != NONCE_BYTES {
            return Err(SecurityError::EnvelopeMalformed);
        }
        let ciphertext = BASE64
            .decode(&envelope.ciphertext_base64)
            .map_err(|_| SecurityError::EnvelopeMalformed)?;
        let cipher = Aes256Gcm::new_from_slice(dek.expose()).map_err(|_| SecurityError::InvalidKeyMaterial)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &payload_aad,
                },
            )
            .map_err(|_| SecurityError::AuthenticationFailed)?;
        Ok(SecretBytes::new(plaintext))
    }
}

/// Local AES key provider used by the file adapter and deterministic integration harness.
pub struct LocalAesKeyProvider {
    role: &'static str,
    key_version: u64,
    root_key: SecretBytes,
}

impl LocalAesKeyProvider {
    /// Create a provider from an exact 32-byte root key.
    pub fn new(role: &'static str, key_version: u64, root_key: Vec<u8>) -> Result<Self, SecurityError> {
        if root_key.len() != DEK_BYTES || key_version == 0 {
            return Err(SecurityError::InvalidKeyMaterial);
        }
        Ok(Self {
            role,
            key_version,
            root_key: SecretBytes::new(root_key),
        })
    }
}

impl KeyProvider for LocalAesKeyProvider {
    fn role(&self) -> &'static str {
        self.role
    }

    fn active_key_version(&self) -> Result<u64, SecurityError> {
        Ok(self.key_version)
    }

    fn wrap_dek(&self, key_version: u64, dek: &[u8], aad: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if key_version != self.key_version {
            return Err(SecurityError::HistoricalKeyUnavailable);
        }
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| SecurityError::RandomnessUnavailable)?;
        let cipher =
            Aes256Gcm::new_from_slice(self.root_key.expose()).map_err(|_| SecurityError::InvalidKeyMaterial)?;
        let wrapped = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: dek, aad })
            .map_err(|_| SecurityError::EncryptionFailed)?;
        let mut result = Vec::with_capacity(NONCE_BYTES + wrapped.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&wrapped);
        Ok(result)
    }

    fn unwrap_dek(&self, key_version: u64, wrapped: &[u8], aad: &[u8]) -> Result<SecretBytes, SecurityError> {
        if key_version != self.key_version {
            return Err(SecurityError::HistoricalKeyUnavailable);
        }
        if wrapped.len() <= NONCE_BYTES {
            return Err(SecurityError::EnvelopeMalformed);
        }
        let (nonce, ciphertext) = wrapped.split_at(NONCE_BYTES);
        let cipher =
            Aes256Gcm::new_from_slice(self.root_key.expose()).map_err(|_| SecurityError::InvalidKeyMaterial)?;
        let dek = cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
            .map_err(|_| SecurityError::AuthenticationFailed)?;
        Ok(SecretBytes::new(dek))
    }
}

/// HMAC-SHA-256 lookup digest used instead of storing Platform Key/token plaintext.
pub fn lookup_digest(key: &SecretBytes, secret: &SecretBytes) -> Result<[u8; 32], SecurityError> {
    let mut hmac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(key.expose())
        .map_err(|_| SecurityError::InvalidKeyMaterial)?;
    hmac.update(b"gateway-secret-lookup-v1");
    hmac.update(secret.expose());
    Ok(hmac.finalize().into_bytes().into())
}

/// Rewrap an existing DEK under the active version of another provider without decrypting payload ciphertext.
pub fn rewrap_dek<O: KeyProvider, N: KeyProvider>(
    old_provider: &O,
    new_provider: &N,
    wrapped_dek_base64: &str,
    mut aad: EnvelopeAad,
) -> Result<(u64, String), SecurityError> {
    if old_provider.role() != new_provider.role() || aad.provider_role != old_provider.role() {
        return Err(SecurityError::ProviderRoleMismatch);
    }
    let wrapped = BASE64
        .decode(wrapped_dek_base64)
        .map_err(|_| SecurityError::EnvelopeMalformed)?;
    let old_wrap_aad = aad.wrap_bytes();
    let dek = old_provider.unwrap_dek(aad.key_version, &wrapped, &old_wrap_aad)?;
    let new_version = new_provider.active_key_version()?;
    aad.key_version = new_version;
    let new_wrapped = new_provider.wrap_dek(new_version, dek.expose(), &aad.wrap_bytes())?;
    Ok((new_version, BASE64.encode(new_wrapped)))
}

/// Checkpoint returned by one restart-safe business-key rewrap batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationBatchReport {
    /// Successfully CAS-updated Secret rows.
    pub rewrapped: usize,
    /// Rows changed by another worker before this batch committed.
    pub cas_conflicts: usize,
    /// Last observed `UUIDv7` checkpoint.
    pub next_checkpoint: Option<Uuid>,
    /// No additional rows from the old version were visible in this batch.
    pub complete: bool,
}

/// Rewrap one ordered batch of database-provider Secret DEKs without exposing payload plaintext.
pub async fn rewrap_database_business_batch(
    storage: &PgStorage,
    old_key_version: i64,
    new_key_version: i64,
    after_secret_id: Option<Uuid>,
    limit: i64,
) -> Result<RotationBatchReport, RotationError> {
    let old_root = storage.load_database_business_key(old_key_version).await?;
    let new_root = storage.load_database_business_key(new_key_version).await?;
    let old_provider = LocalAesKeyProvider::new(
        "business",
        u64::try_from(old_key_version).map_err(|_| SecurityError::InvalidKeyMaterial)?,
        old_root.expose().to_vec(),
    )?;
    let new_provider = LocalAesKeyProvider::new(
        "business",
        u64::try_from(new_key_version).map_err(|_| SecurityError::InvalidKeyMaterial)?,
        new_root.expose().to_vec(),
    )?;
    let candidates = storage
        .load_secret_rewrap_batch(old_key_version, after_secret_id, limit)
        .await?;
    let complete = i64::try_from(candidates.len()).map_or(true, |count| count < limit);
    let mut report = RotationBatchReport {
        rewrapped: 0,
        cas_conflicts: 0,
        next_checkpoint: after_secret_id,
        complete,
    };
    for candidate in candidates {
        report.next_checkpoint = Some(candidate.secret_id);
        let aad = EnvelopeAad {
            schema_version: candidate.aad_schema_version,
            secret_id: candidate.secret_id,
            secret_kind: candidate.secret_kind,
            provider_role: candidate.provider_role,
            owner_type: candidate.owner_type,
            owner_id: candidate.owner_id,
            purpose: candidate.purpose,
            key_version: u64::try_from(candidate.key_version).map_err(|_| SecurityError::InvalidKeyMaterial)?,
        };
        let (_, wrapped_base64) = rewrap_dek(
            &old_provider,
            &new_provider,
            &BASE64.encode(candidate.wrapped_dek.expose()),
            aad,
        )?;
        let wrapped = SecretBytes::new(
            BASE64
                .decode(wrapped_base64)
                .map_err(|_| SecurityError::EnvelopeMalformed)?,
        );
        match storage
            .commit_rewrapped_dek(candidate.secret_id, old_key_version, new_key_version, &wrapped)
            .await
        {
            Ok(()) => report.rewrapped += 1,
            Err(StorageError::RevisionConflict) => report.cas_conflicts += 1,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(report)
}

/// Argon2id bootstrap password hashing: 64 MiB, three iterations, one lane, 32-byte output.
pub fn hash_bootstrap_password(password: &SecretValue) -> Result<SecretValue, SecurityError> {
    let params = Params::new(65_536, 3, 1, Some(32)).map_err(|_| SecurityError::PasswordHashFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt_bytes = [0_u8; 16];
    getrandom::fill(&mut salt_bytes).map_err(|_| SecurityError::RandomnessUnavailable)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| SecurityError::PasswordHashFailed)?;
    salt_bytes.zeroize();
    let phc = argon2
        .hash_password(password.expose().as_bytes(), &salt)
        .map_err(|_| SecurityError::PasswordHashFailed)?
        .to_string();
    Ok(SecretValue::new(phc))
}

/// Verify a password against a stored Argon2 PHC string without exposing either value.
pub fn verify_password(password: &SecretValue, password_phc: &SecretValue) -> Result<bool, SecurityError> {
    let parsed = PasswordHash::new(password_phc.expose()).map_err(|_| SecurityError::PasswordHashFailed)?;
    Ok(Argon2::default()
        .verify_password(password.expose().as_bytes(), &parsed)
        .is_ok())
}

/// Generate a 160-bit TOTP seed and its RFC 4648 base32 enrollment representation.
pub fn generate_totp_seed() -> Result<(SecretBytes, SecretValue), SecurityError> {
    let mut seed = vec![0_u8; 20];
    getrandom::fill(&mut seed).map_err(|_| SecurityError::RandomnessUnavailable)?;
    let encoded = base32_no_pad(&seed);
    Ok((SecretBytes::new(seed), SecretValue::new(encoded)))
}

/// Verify a six-digit SHA-1 TOTP in the current 30-second step plus one adjacent step.
/// Returns the accepted monotonic step, allowing storage to reject replay atomically.
pub fn verify_totp(
    seed: &SecretBytes,
    submitted: &SecretValue,
    unix_seconds: u64,
    last_accepted_step: Option<u64>,
) -> Result<Option<u64>, SecurityError> {
    if submitted.expose().len() != 6 || !submitted.expose().bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let current = unix_seconds / 30;
    let start = current.saturating_sub(1);
    let end = current.saturating_add(1);
    for step in start..=end {
        if last_accepted_step.is_some_and(|last| step <= last) {
            continue;
        }
        let expected = totp_code(seed, step)?;
        if bool::from(expected.as_bytes().ct_eq(submitted.expose().as_bytes())) {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

fn totp_code(seed: &SecretBytes, step: u64) -> Result<String, SecurityError> {
    let mut hmac = <HmacSha1 as hmac::digest::KeyInit>::new_from_slice(seed.expose())
        .map_err(|_| SecurityError::InvalidKeyMaterial)?;
    hmac.update(&step.to_be_bytes());
    let digest = hmac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(format!("{:06}", binary % 1_000_000))
}

fn base32_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits -= 5;
            let index = ((accumulator >> bits) & 0x1f) as usize;
            output.push(char::from(ALPHABET[index]));
        }
    }
    if bits > 0 {
        let index = ((accumulator << (5 - bits)) & 0x1f) as usize;
        output.push(char::from(ALPHABET[index]));
    }
    output
}

/// Cryptographic/service failures with no secret-bearing payload.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecurityError {
    /// Operating-system randomness failed.
    #[error("cryptographic randomness unavailable")]
    RandomnessUnavailable,
    /// Key bytes or version are invalid.
    #[error("invalid key material")]
    InvalidKeyMaterial,
    /// The provider role and AAD role differ.
    #[error("key provider role mismatch")]
    ProviderRoleMismatch,
    /// Envelope metadata and requested AAD differ.
    #[error("secret envelope metadata mismatch")]
    EnvelopeMismatch,
    /// Base64, nonce, or wrapped-DEK framing is invalid.
    #[error("secret envelope is malformed")]
    EnvelopeMalformed,
    /// Authenticated encryption failed.
    #[error("secret encryption failed")]
    EncryptionFailed,
    /// GCM authentication failed.
    #[error("secret authentication failed")]
    AuthenticationFailed,
    /// A referenced decrypt-only key version is absent.
    #[error("historical key version unavailable")]
    HistoricalKeyUnavailable,
    /// Argon2id hashing failed.
    #[error("password hashing failed")]
    PasswordHashFailed,
}

#[cfg(test)]
mod tests {
    use gateway_domain::SecretValue;
    use uuid::Uuid;

    use super::{
        EnvelopeAad, EnvelopeService, LocalAesKeyProvider, OAuthCallbackDigestDomain, SecretBytes, SecurityError,
        generate_oauth_pkce, generate_totp_seed, hash_bootstrap_password, lookup_digest, oauth_callback_digest,
        rewrap_dek, totp_code, verify_password, verify_totp,
    };

    fn aad() -> EnvelopeAad {
        EnvelopeAad {
            schema_version: 1,
            secret_id: Uuid::nil(),
            secret_kind: "oauth_refresh_token".to_owned(),
            provider_role: "business".to_owned(),
            owner_type: "credential".to_owned(),
            owner_id: "credential-01".to_owned(),
            purpose: "anthropic_auth".to_owned(),
            key_version: 0,
        }
    }

    #[test]
    fn envelope_round_trip_and_aad_swap_rejection() -> Result<(), Box<dyn std::error::Error>> {
        let provider = LocalAesKeyProvider::new("business", 7, vec![0x44; 32])?;
        let service = EnvelopeService::new(provider);
        let plaintext = SecretBytes::new(b"secret-canary-r2".to_vec());
        let mut bound = aad();
        let envelope = service.encrypt(&plaintext, bound.clone())?;
        bound.key_version = envelope.key_version;
        let decrypted = service.decrypt(&envelope, &bound)?;
        assert_eq!(decrypted.expose(), b"secret-canary-r2");
        bound.owner_id = "credential-02".to_owned();
        assert_eq!(
            service.decrypt(&envelope, &bound).err(),
            Some(SecurityError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn lookup_digest_is_deterministic_and_domain_separated() -> Result<(), Box<dyn std::error::Error>> {
        let key = SecretBytes::new(vec![9; 32]);
        let first = lookup_digest(&key, &SecretBytes::new(b"value-a".to_vec()))?;
        let second = lookup_digest(&key, &SecretBytes::new(b"value-a".to_vec()))?;
        let third = lookup_digest(&key, &SecretBytes::new(b"value-b".to_vec()))?;
        assert_eq!(first, second);
        assert_ne!(first, third);
        Ok(())
    }

    #[test]
    fn bootstrap_password_uses_frozen_argon2id_parameters() -> Result<(), Box<dyn std::error::Error>> {
        let password = SecretValue::new("secret-canary-password".to_owned());
        let phc = hash_bootstrap_password(&password)?;
        assert!(phc.expose().starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        assert!(!phc.expose().contains("secret-canary-password"));
        assert!(verify_password(&password, &phc)?);
        assert!(!verify_password(&SecretValue::new("wrong-password".to_owned()), &phc)?);
        Ok(())
    }

    #[test]
    fn totp_is_six_digits_windowed_and_replay_fenced() -> Result<(), Box<dyn std::error::Error>> {
        let (seed, enrollment) = generate_totp_seed()?;
        assert_eq!(seed.expose().len(), 20);
        assert_eq!(enrollment.expose().len(), 32);
        let step = 1_900_000_000_u64 / 30;
        let code = SecretValue::new(totp_code(&seed, step)?);
        assert_eq!(verify_totp(&seed, &code, 1_900_000_000, None)?, Some(step));
        assert_eq!(verify_totp(&seed, &code, 1_900_000_000, Some(step))?, None);
        Ok(())
    }

    #[test]
    fn rewrap_changes_only_provider_version_and_wrapped_dek() -> Result<(), Box<dyn std::error::Error>> {
        let old_service = EnvelopeService::new(LocalAesKeyProvider::new("business", 1, vec![1; 32])?);
        let plaintext = SecretBytes::new(b"rotation-fixture".to_vec());
        let mut old_aad = aad();
        let mut envelope = old_service.encrypt(&plaintext, old_aad.clone())?;
        old_aad.key_version = 1;
        let (new_version, wrapped) = rewrap_dek(
            &LocalAesKeyProvider::new("business", 1, vec![1; 32])?,
            &LocalAesKeyProvider::new("business", 2, vec![2; 32])?,
            &envelope.wrapped_dek_base64,
            old_aad.clone(),
        )?;
        envelope.key_version = new_version;
        envelope.wrapped_dek_base64 = wrapped;
        old_aad.key_version = new_version;
        let new_service = EnvelopeService::new(LocalAesKeyProvider::new("business", 2, vec![2; 32])?);
        assert_eq!(new_service.decrypt(&envelope, &old_aad)?.expose(), b"rotation-fixture");
        Ok(())
    }

    #[test]
    fn oauth_pkce_uses_s256_and_keyed_callback_bindings() -> Result<(), Box<dyn std::error::Error>> {
        let key = SecretBytes::new(vec![0x42; 32]);
        let material = generate_oauth_pkce(&key)?;
        assert_eq!(material.verifier.expose().len(), 43);
        assert_eq!(material.challenge.len(), 43);
        assert_eq!(
            oauth_callback_digest(&key, OAuthCallbackDigestDomain::State, &material.state)?,
            material.state_digest
        );
        assert_eq!(
            oauth_callback_digest(&key, OAuthCallbackDigestDomain::CallbackNonce, &material.callback_nonce,)?,
            material.callback_nonce_digest
        );
        assert!(!format!("{material:?}").contains(material.verifier.expose()));
        Ok(())
    }
}

/// Resumable rotation combines sanitized storage and cryptographic failures.
#[derive(Debug, Error)]
pub enum RotationError {
    /// Storage operation failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Cryptographic rewrap failed.
    #[error(transparent)]
    Security(#[from] SecurityError),
}
