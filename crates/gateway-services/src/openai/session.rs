//! Tenant-isolated upstream sessions and account-bound continuation ownership.

use super::OpenAiError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use gateway_domain::SecretBytes;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use std::{collections::HashMap, time::Duration};

/// Derive an opaque identity using length-delimited fields to avoid ambiguous concatenation.
///
/// # Errors
/// Rejects short HMAC keys.
pub fn isolate_session(
    key: &SecretBytes,
    platform_key: &str,
    account: &str,
    session: &str,
) -> Result<String, OpenAiError> {
    if key.expose().len() < 32 {
        return Err(OpenAiError::InvalidCredential);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.expose()).map_err(|_| OpenAiError::InvalidCredential)?;
    mac.update(b"openai-session-v1");
    for part in [platform_key, account, session] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

/// Process-local bounded ownership index. Unknown/expired continuations fail closed.
#[derive(Debug)]
pub struct ContinuationIndex {
    entries: HashMap<(String, String), (String, Duration)>,
    capacity: usize,
    ttl: Duration,
}

impl ContinuationIndex {
    /// Configure capacity and monotonic expiry; the caller owns synchronization.
    #[must_use]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            ttl,
        }
    }

    /// Remember an upstream response for this platform key only.
    ///
    /// # Errors
    /// Rejects ownership changes and capacity exhaustion instead of silently rebinding.
    pub fn bind(&mut self, key: &str, response: &str, credential: &str, now: Duration) -> Result<(), OpenAiError> {
        self.entries.retain(|_, (_, expiry)| *expiry > now);
        let id = (key.to_owned(), response.to_owned());
        if let Some((existing, _)) = self.entries.get(&id) {
            if existing != credential {
                return Err(OpenAiError::IdentityConflict);
            }
        } else if self.entries.len() >= self.capacity {
            return Err(OpenAiError::ContinuationUnavailable);
        }
        self.entries
            .insert(id, (credential.to_owned(), now.saturating_add(self.ttl)));
        Ok(())
    }

    /// Resolve a continuation, scoped to the current platform key.
    ///
    /// # Errors
    /// Unknown, expired, and cross-key IDs are all unavailable.
    pub fn resolve(&self, key: &str, response: &str, now: Duration) -> Result<&str, OpenAiError> {
        self.entries
            .get(&(key.to_owned(), response.to_owned()))
            .filter(|(_, expiry)| *expiry > now)
            .map(|(credential, _)| credential.as_str())
            .ok_or(OpenAiError::ContinuationUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_never_crosses_key_or_account() -> Result<(), OpenAiError> {
        let mut index = ContinuationIndex::new(2, Duration::from_mins(1));
        index.bind("key-a", "resp", "account-a", Duration::ZERO)?;
        assert_eq!(
            index.resolve("key-b", "resp", Duration::ZERO),
            Err(OpenAiError::ContinuationUnavailable)
        );
        assert_eq!(
            index.bind("key-a", "resp", "account-b", Duration::ZERO),
            Err(OpenAiError::IdentityConflict)
        );
        assert_eq!(
            index.resolve("key-a", "resp", Duration::from_mins(1)),
            Err(OpenAiError::ContinuationUnavailable)
        );
        let key = SecretBytes::new(vec![7; 32]);
        assert_ne!(
            isolate_session(&key, "a", "bc", "s")?,
            isolate_session(&key, "ab", "c", "s")?
        );
        assert_ne!(
            isolate_session(&key, "a", "c", "s")?,
            isolate_session(&key, "b", "c", "s")?
        );
        Ok(())
    }
}
