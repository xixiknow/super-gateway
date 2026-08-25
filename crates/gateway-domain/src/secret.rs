//! Secret container with redacted formatting and zeroization.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// An owned secret that is redacted from formatting and zeroized on drop.
pub struct SecretValue(String);

impl SecretValue {
    /// Wrap an owned plaintext value as close as possible to its source.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Explicitly expose plaintext at the final adapter boundary.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Return whether the secret contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Owned binary secret with redacted formatting and automatic zeroization.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Wrap binary plaintext as close as possible to its source.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Explicitly expose bytes at the final adapter or cryptographic boundary.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Return whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretBytes, SecretValue};

    #[test]
    fn debug_never_contains_plaintext() {
        let secret = SecretValue::new("secret-canary-r1".to_owned());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("secret-canary-r1"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn binary_debug_never_contains_plaintext() {
        let secret = SecretBytes::new(b"secret-canary-r2-bytes".to_vec());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("secret-canary-r2-bytes"));
        assert!(rendered.contains("REDACTED"));
    }
}
