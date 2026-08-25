//! Static deployment configuration and secret-reference parsing.

use std::{collections::HashMap, fmt, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use gateway_domain::SecretValue;
use thiserror::Error;

const DATA_BIND: &str = "GATEWAY_DATA_BIND";
const ADMIN_BIND: &str = "GATEWAY_ADMIN_BIND";
const DATABASE_URL_FILE: &str = "GATEWAY_DATABASE_URL_FILE";
const MIGRATOR_DATABASE_URL_FILE: &str = "GATEWAY_MIGRATOR_DATABASE_URL_FILE";
const BUSINESS_KEY_PROVIDER: &str = "GATEWAY_BUSINESS_KEY_PROVIDER";
const KEY_PROVIDER_URI: &str = "GATEWAY_KEY_PROVIDER_URI";
const APP_KEY_FILE: &str = "GATEWAY_APP_KEY_FILE";
const DIGEST_KEY_FILE: &str = "GATEWAY_DIGEST_KEY_FILE";
const AUDIT_INTEGRITY_KEY_FILE: &str = "GATEWAY_AUDIT_INTEGRITY_KEY_FILE";
const BUNDLE_TRUST_STORE: &str = "GATEWAY_BUNDLE_TRUST_STORE";
const BUNDLE_DIR: &str = "GATEWAY_BUNDLE_DIR";
const RESPONSE_TMP_DIR: &str = "GATEWAY_RESPONSE_TMP_DIR";
const CONTENT_AUDIT_KEY_FILE: &str = "GATEWAY_CONTENT_AUDIT_KEY_FILE";
const CONTENT_AUDIT_DIR: &str = "GATEWAY_CONTENT_AUDIT_DIR";
const BACKUP_KEY_FILE: &str = "GATEWAY_BACKUP_KEY_FILE";
const BACKUP_REPOSITORY: &str = "GATEWAY_BACKUP_REPOSITORY";
const EGRESS_OBSERVER_HOST: &str = "GATEWAY_EGRESS_OBSERVER_HOST";
const EGRESS_OBSERVER_PATH: &str = "GATEWAY_EGRESS_OBSERVER_PATH";
const MANAGED_BROWSER_TOOL: &str = "GATEWAY_MANAGED_BROWSER_TOOL";
const MANAGED_BROWSER_TIMEOUT: &str = "GATEWAY_MANAGED_BROWSER_TIMEOUT";
const DRAIN_DEADLINE: &str = "GATEWAY_DRAIN_DEADLINE";
const BOOTSTRAP_USERNAME: &str = "GATEWAY_BOOTSTRAP_ADMIN_USERNAME";
const BOOTSTRAP_PASSWORD: &str = "GATEWAY_BOOTSTRAP_ADMIN_PASSWORD";
const BOOTSTRAP_EMAIL: &str = "GATEWAY_BOOTSTRAP_ADMIN_EMAIL";
const BOOTSTRAP_DISPLAY_NAME: &str = "GATEWAY_BOOTSTRAP_ADMIN_DISPLAY_NAME";

/// Static process configuration. Dynamic policy remains in `PostgreSQL` snapshots.
pub struct GatewayConfig {
    pub data_bind: SocketAddr,
    pub admin_bind: SocketAddr,
    pub database_url_file: PathBuf,
    pub business_key_provider: BusinessKeyProvider,
    pub digest_key_file: PathBuf,
    pub audit_integrity_key_file: PathBuf,
    pub bundle_trust_store: PathBuf,
    pub bundle_dir: PathBuf,
    pub response_tmp_dir: PathBuf,
    pub content_audit: Option<ContentAuditConfig>,
    pub backup: Option<BackupConfig>,
    pub proxy_probe: ProxyProbeConfig,
    pub managed_browser: Option<ManagedBrowserConfig>,
    pub drain_deadline: Duration,
    pub bootstrap_admin: Option<BootstrapAdmin>,
}

impl fmt::Debug for GatewayConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayConfig")
            .field("data_bind", &self.data_bind)
            .field("admin_bind", &self.admin_bind)
            .field("database_url_file", &self.database_url_file)
            .field("business_key_provider", &self.business_key_provider)
            .field("digest_key_file", &self.digest_key_file)
            .field("audit_integrity_key_file", &self.audit_integrity_key_file)
            .field("bundle_trust_store", &self.bundle_trust_store)
            .field("bundle_dir", &self.bundle_dir)
            .field("response_tmp_dir", &self.response_tmp_dir)
            .field("content_audit", &self.content_audit)
            .field("backup", &self.backup)
            .field("proxy_probe", &self.proxy_probe)
            .field("managed_browser", &self.managed_browser)
            .field("drain_deadline", &self.drain_deadline)
            .field("bootstrap_admin", &self.bootstrap_admin.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Business key provider selection.
pub enum BusinessKeyProvider {
    /// Key versions and restricted key material are managed by `PostgreSQL`.
    Database,
    /// External provider URI; credentials are resolved outside this value.
    ExternalUri(String),
    /// Local root-key file reference.
    LocalFile(PathBuf),
}

impl fmt::Debug for BusinessKeyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let provider = match self {
            Self::Database => "database",
            Self::ExternalUri(_) => "external_uri",
            Self::LocalFile(_) => "local_file",
        };
        formatter.debug_tuple("BusinessKeyProvider").field(&provider).finish()
    }
}

/// Optional Content Audit dependencies.
#[derive(Debug)]
pub struct ContentAuditConfig {
    pub key_file: PathBuf,
    pub directory: PathBuf,
}

/// Optional backup configuration. Its runtime failure raises a critical alert without revoking readiness.
pub struct BackupConfig {
    pub tool: PathBuf,
    pub key_file: PathBuf,
    pub repository: String,
}

/// Non-secret HTTPS endpoint that returns the caller's plain IP address.
#[derive(Debug)]
pub struct ProxyProbeConfig {
    pub observer_host: String,
    pub observer_path: String,
}

#[derive(Debug)]
pub struct ManagedBrowserConfig {
    pub tool: PathBuf,
    pub timeout: Duration,
}

impl fmt::Debug for BackupConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupConfig")
            .field("configured", &true)
            .finish()
    }
}

/// Empty-database bootstrap material. Password formatting is always redacted.
pub struct BootstrapAdmin {
    pub username: String,
    pub password: SecretValue,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

impl GatewayConfig {
    /// Load `.env` when present, then read the process environment.
    pub fn load() -> Result<Self, ConfigError> {
        let _dotenv_result = dotenvy::dotenv();
        let values = std::env::vars().collect();
        Self::from_map(&values)
    }

    /// Parse from an explicit map for deterministic tests and configuration tooling.
    pub fn from_map(values: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let data_bind = parse_socket(values, DATA_BIND)?;
        let admin_bind = parse_socket(values, ADMIN_BIND)?;
        let database_url_file = required_path(values, DATABASE_URL_FILE)?;
        let business_key_provider = parse_business_key_provider(values)?;
        let digest_key_file = required_path(values, DIGEST_KEY_FILE)?;
        let audit_integrity_key_file = required_path(values, AUDIT_INTEGRITY_KEY_FILE)?;
        let bundle_trust_store = required_path(values, BUNDLE_TRUST_STORE)?;
        let bundle_dir = required_path(values, BUNDLE_DIR)?;
        let response_tmp_dir = required_path(values, RESPONSE_TMP_DIR)?;
        let content_audit =
            optional_pair(values, CONTENT_AUDIT_KEY_FILE, CONTENT_AUDIT_DIR)?.map(|(key_file, directory)| {
                ContentAuditConfig {
                    key_file: PathBuf::from(key_file),
                    directory: PathBuf::from(directory),
                }
            });
        let backup =
            optional_pair(values, BACKUP_KEY_FILE, BACKUP_REPOSITORY)?.map(|(key_file, repository)| BackupConfig {
                tool: PathBuf::from("super-gateway-backup"),
                key_file: PathBuf::from(key_file),
                repository,
            });
        let proxy_probe = ProxyProbeConfig {
            observer_host: non_empty(values, EGRESS_OBSERVER_HOST)
                .unwrap_or("api64.ipify.org")
                .to_owned(),
            observer_path: non_empty(values, EGRESS_OBSERVER_PATH).unwrap_or("/").to_owned(),
        };
        let managed_browser = if let Some(tool) = non_empty(values, MANAGED_BROWSER_TOOL) {
            Some(ManagedBrowserConfig {
                tool: PathBuf::from(tool),
                timeout: values
                    .get(MANAGED_BROWSER_TIMEOUT)
                    .map_or(Ok(Duration::from_mins(5)), |value| parse_duration(value))?,
            })
        } else {
            None
        };
        if managed_browser
            .as_ref()
            .is_some_and(|config| config.tool.as_os_str().is_empty() || config.timeout < Duration::from_secs(30))
        {
            return Err(ConfigError::Invalid(MANAGED_BROWSER_TOOL));
        }
        if proxy_probe.observer_host.len() > 253
            || proxy_probe.observer_host.starts_with('.')
            || proxy_probe.observer_host.ends_with('.')
            || proxy_probe.observer_host.contains("..")
            || proxy_probe
                .observer_host
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, '/' | '\\' | '@' | '[' | ']'))
            || !proxy_probe.observer_path.starts_with('/')
            || proxy_probe.observer_path.len() > 2_048
            || proxy_probe.observer_path.contains(['\r', '\n', ' '])
        {
            return Err(ConfigError::Invalid(EGRESS_OBSERVER_HOST));
        }
        let drain_deadline = values
            .get(DRAIN_DEADLINE)
            .map_or(Ok(Duration::from_mins(5)), |value| parse_duration(value))?;
        let bootstrap_admin = parse_bootstrap(values)?;
        Ok(Self {
            data_bind,
            admin_bind,
            database_url_file,
            business_key_provider,
            digest_key_file,
            audit_integrity_key_file,
            bundle_trust_store,
            bundle_dir,
            response_tmp_dir,
            content_audit,
            backup,
            proxy_probe,
            managed_browser,
            drain_deadline,
            bootstrap_admin,
        })
    }

    /// Confirm that every parsed static reference remains structurally usable.
    #[must_use]
    pub fn invariants_hold(&self) -> bool {
        let business_key_provider_ready = match &self.business_key_provider {
            BusinessKeyProvider::Database => true,
            BusinessKeyProvider::ExternalUri(uri) => !uri.trim().is_empty(),
            BusinessKeyProvider::LocalFile(path) => !path.as_os_str().is_empty(),
        };
        let content_audit_ready = self
            .content_audit
            .as_ref()
            .is_none_or(|config| !config.key_file.as_os_str().is_empty() && !config.directory.as_os_str().is_empty());
        let backup_ready = self.backup.as_ref().is_none_or(|config| {
            !config.tool.as_os_str().is_empty()
                && !config.key_file.as_os_str().is_empty()
                && !config.repository.trim().is_empty()
        });
        let bootstrap_ready = self.bootstrap_admin.as_ref().is_none_or(|admin| {
            !admin.username.trim().is_empty()
                && !admin.password.is_empty()
                && admin.email.as_ref().is_none_or(|value| !value.trim().is_empty())
                && admin.display_name.as_ref().is_none_or(|value| !value.trim().is_empty())
        });
        let proxy_probe_ready =
            !self.proxy_probe.observer_host.is_empty() && self.proxy_probe.observer_path.starts_with('/');
        let managed_browser_ready = self
            .managed_browser
            .as_ref()
            .is_none_or(|config| !config.tool.as_os_str().is_empty() && config.timeout >= Duration::from_secs(30));
        business_key_provider_ready
            && content_audit_ready
            && backup_ready
            && proxy_probe_ready
            && managed_browser_ready
            && bootstrap_ready
    }

    /// Reject provider modes that are part of the configuration contract but do not yet have a
    /// production composition-root adapter. Configuration probes must use the same gate as serve.
    pub fn ensure_runtime_supported(&self) -> Result<(), ConfigError> {
        match &self.business_key_provider {
            BusinessKeyProvider::Database => Ok(()),
            BusinessKeyProvider::ExternalUri(_) | BusinessKeyProvider::LocalFile(_) => {
                Err(ConfigError::BusinessKeyProviderNotWired)
            }
        }
    }
}

/// Load the migration-only DSN file without requiring serving configuration.
pub fn load_migrator_database_url() -> Result<SecretValue, ConfigError> {
    let _dotenv_result = dotenvy::dotenv();
    let path = std::env::var(MIGRATOR_DATABASE_URL_FILE)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .ok_or(ConfigError::Missing(MIGRATOR_DATABASE_URL_FILE))?;
    read_secret_file(&path)
}

/// Load the runtime DSN file without requiring listener or provider configuration.
pub fn load_runtime_database_url() -> Result<SecretValue, ConfigError> {
    let _dotenv_result = dotenvy::dotenv();
    let path = std::env::var(DATABASE_URL_FILE)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .ok_or(ConfigError::Missing(DATABASE_URL_FILE))?;
    read_secret_file(&path)
}

/// Read and trim a secret reference without ever formatting its value.
pub fn read_secret_file(path: &std::path::Path) -> Result<SecretValue, ConfigError> {
    let value = std::fs::read_to_string(path).map_err(|_| ConfigError::SecretFileUnreadable)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::SecretFileUnreadable);
    }
    Ok(SecretValue::new(trimmed.to_owned()))
}

fn parse_business_key_provider(values: &HashMap<String, String>) -> Result<BusinessKeyProvider, ConfigError> {
    let mode = non_empty(values, BUSINESS_KEY_PROVIDER).unwrap_or("database");
    let uri = non_empty(values, KEY_PROVIDER_URI);
    let file = non_empty(values, APP_KEY_FILE);
    match (mode, uri, file) {
        ("database", None, None) => Ok(BusinessKeyProvider::Database),
        ("uri", Some(value), None) => Ok(BusinessKeyProvider::ExternalUri(value.to_owned())),
        ("file", None, Some(value)) => Ok(BusinessKeyProvider::LocalFile(PathBuf::from(value))),
        ("database" | "uri" | "file", _, _) => Err(ConfigError::BusinessKeyProviderInputs),
        _ => Err(ConfigError::Invalid(BUSINESS_KEY_PROVIDER)),
    }
}

fn non_empty<'a>(values: &'a HashMap<String, String>, name: &'static str) -> Option<&'a str> {
    values
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn required_path(values: &HashMap<String, String>, name: &'static str) -> Result<PathBuf, ConfigError> {
    non_empty(values, name)
        .map(PathBuf::from)
        .ok_or(ConfigError::Missing(name))
}

fn parse_socket(values: &HashMap<String, String>, name: &'static str) -> Result<SocketAddr, ConfigError> {
    let value = non_empty(values, name).ok_or(ConfigError::Missing(name))?;
    SocketAddr::from_str(value).map_err(|_| ConfigError::Invalid(name))
}

fn optional_pair(
    values: &HashMap<String, String>,
    first_name: &'static str,
    second_name: &'static str,
) -> Result<Option<(String, String)>, ConfigError> {
    match (non_empty(values, first_name), non_empty(values, second_name)) {
        (None, None) => Ok(None),
        (Some(first), Some(second)) => Ok(Some((first.to_owned(), second.to_owned()))),
        _ => Err(ConfigError::IncompletePair(first_name, second_name)),
    }
}

fn parse_bootstrap(values: &HashMap<String, String>) -> Result<Option<BootstrapAdmin>, ConfigError> {
    match (
        non_empty(values, BOOTSTRAP_USERNAME),
        non_empty(values, BOOTSTRAP_PASSWORD),
    ) {
        (None, None) => Ok(None),
        (Some(username), Some(password)) => {
            let normalized = password.trim().to_ascii_lowercase();
            if !(14..=128).contains(&password.chars().count())
                || matches!(
                    normalized.as_str(),
                    "admin" | "password" | "changeme" | "change-me" | "replace-me" | "replace_this_password"
                )
            {
                return Err(ConfigError::Invalid(BOOTSTRAP_PASSWORD));
            }
            Ok(Some(BootstrapAdmin {
                username: username.to_owned(),
                password: SecretValue::new(password.to_owned()),
                email: non_empty(values, BOOTSTRAP_EMAIL).map(str::to_owned),
                display_name: non_empty(values, BOOTSTRAP_DISPLAY_NAME).map(str::to_owned),
            }))
        }
        _ => Err(ConfigError::IncompleteBootstrap),
    }
}

fn parse_duration(value: &str) -> Result<Duration, ConfigError> {
    let (number, multiplier) = if let Some(seconds) = value.strip_suffix('s') {
        (seconds, 1)
    } else if let Some(minutes) = value.strip_suffix('m') {
        (minutes, 60)
    } else {
        (value, 1)
    };
    let seconds = number
        .parse::<u64>()
        .map_err(|_| ConfigError::Invalid(DRAIN_DEADLINE))?
        .checked_mul(multiplier)
        .ok_or(ConfigError::Invalid(DRAIN_DEADLINE))?;
    if seconds == 0 {
        return Err(ConfigError::Invalid(DRAIN_DEADLINE));
    }
    Ok(Duration::from_secs(seconds))
}

/// Sanitized static configuration errors. Values are intentionally omitted.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for environment variable {0}")]
    Invalid(&'static str),
    #[error("business key provider inputs do not match the selected mode")]
    BusinessKeyProviderInputs,
    #[error("selected business key provider has no production runtime adapter")]
    BusinessKeyProviderNotWired,
    #[error("configuration variables {0} and {1} must be supplied together")]
    IncompletePair(&'static str, &'static str),
    #[error("bootstrap admin username and password must be supplied together")]
    IncompleteBootstrap,
    #[error("secret reference file is unreadable or empty")]
    SecretFileUnreadable,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{ConfigError, GatewayConfig};

    fn complete() -> HashMap<String, String> {
        HashMap::from([
            ("GATEWAY_DATA_BIND".to_owned(), "127.0.0.1:8080".to_owned()),
            ("GATEWAY_ADMIN_BIND".to_owned(), "127.0.0.1:8081".to_owned()),
            ("GATEWAY_DATABASE_URL_FILE".to_owned(), "db.secret".to_owned()),
            ("GATEWAY_BUSINESS_KEY_PROVIDER".to_owned(), "database".to_owned()),
            ("GATEWAY_DIGEST_KEY_FILE".to_owned(), "digest.secret".to_owned()),
            ("GATEWAY_AUDIT_INTEGRITY_KEY_FILE".to_owned(), "audit.secret".to_owned()),
            ("GATEWAY_BUNDLE_TRUST_STORE".to_owned(), "trust.json".to_owned()),
            ("GATEWAY_BUNDLE_DIR".to_owned(), "bundles".to_owned()),
            ("GATEWAY_RESPONSE_TMP_DIR".to_owned(), "tmp".to_owned()),
        ])
    }

    #[test]
    fn rejects_partial_bootstrap() {
        let mut values = complete();
        values.insert("GATEWAY_BOOTSTRAP_ADMIN_USERNAME".to_owned(), "admin".to_owned());
        assert_eq!(
            GatewayConfig::from_map(&values).err(),
            Some(ConfigError::IncompleteBootstrap)
        );
    }

    #[test]
    fn debug_redacts_bootstrap_password() -> Result<(), Box<dyn std::error::Error>> {
        let mut values = complete();
        values.insert("GATEWAY_BOOTSTRAP_ADMIN_USERNAME".to_owned(), "admin".to_owned());
        values.insert(
            "GATEWAY_BOOTSTRAP_ADMIN_PASSWORD".to_owned(),
            "secret-canary-bootstrap".to_owned(),
        );
        let config = GatewayConfig::from_map(&values)?;
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("secret-canary-bootstrap"));
        assert!(rendered.contains("REDACTED"));
        Ok(())
    }

    #[test]
    fn rejects_weak_bootstrap_password() {
        let mut values = complete();
        values.insert("GATEWAY_BOOTSTRAP_ADMIN_USERNAME".to_owned(), "admin".to_owned());
        values.insert("GATEWAY_BOOTSTRAP_ADMIN_PASSWORD".to_owned(), "changeme".to_owned());
        assert_eq!(
            GatewayConfig::from_map(&values).err(),
            Some(ConfigError::Invalid("GATEWAY_BOOTSTRAP_ADMIN_PASSWORD"))
        );
    }

    #[test]
    fn debug_redacts_external_provider_uri() -> Result<(), Box<dyn std::error::Error>> {
        let mut values = complete();
        values.insert("GATEWAY_BUSINESS_KEY_PROVIDER".to_owned(), "uri".to_owned());
        values.insert(
            "GATEWAY_KEY_PROVIDER_URI".to_owned(),
            "vault://secret-canary-provider".to_owned(),
        );
        let config = GatewayConfig::from_map(&values)?;
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("secret-canary-provider"));
        assert!(rendered.contains("external_uri"));
        assert_eq!(
            config.ensure_runtime_supported(),
            Err(ConfigError::BusinessKeyProviderNotWired)
        );
        Ok(())
    }

    #[test]
    fn defaults_drain_deadline_to_five_minutes() -> Result<(), Box<dyn std::error::Error>> {
        let values = complete();
        let config = GatewayConfig::from_map(&values)?;
        assert_eq!(config.drain_deadline.as_secs(), 300);
        Ok(())
    }

    #[test]
    fn debug_redacts_backup_references() -> Result<(), Box<dyn std::error::Error>> {
        let mut values = complete();
        values.insert(
            "GATEWAY_BACKUP_KEY_FILE".to_owned(),
            "secret-canary-backup-key-file".to_owned(),
        );
        values.insert(
            "GATEWAY_BACKUP_REPOSITORY".to_owned(),
            "s3://secret-canary-backup-repository".to_owned(),
        );
        let config = GatewayConfig::from_map(&values)?;
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("secret-canary"));
        assert!(rendered.contains("BackupConfig"));
        Ok(())
    }

    #[test]
    fn managed_browser_defaults_to_five_minutes_and_rejects_short_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let mut values = complete();
        values.insert(
            "GATEWAY_MANAGED_BROWSER_TOOL".to_owned(),
            "managed-browser-helper".to_owned(),
        );
        let config = GatewayConfig::from_map(&values)?;
        assert_eq!(
            config.managed_browser.as_ref().map(|browser| browser.timeout.as_secs()),
            Some(300)
        );
        values.insert("GATEWAY_MANAGED_BROWSER_TIMEOUT".to_owned(), "29s".to_owned());
        assert_eq!(
            GatewayConfig::from_map(&values).err(),
            Some(ConfigError::Invalid("GATEWAY_MANAGED_BROWSER_TOOL"))
        );
        Ok(())
    }
}
