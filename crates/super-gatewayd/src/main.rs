#![forbid(unsafe_code)]
//! Production composition root for the single-process gateway.

mod admin_backend;
mod app;
mod config;
mod managed_browser;
mod observability;
mod operations;
mod production_dispatcher;
#[cfg(target_os = "linux")]
mod provider_http;

use anyhow::Context as _;
use config::GatewayConfig;
use gateway_storage::{PgStorage, RuntimeRolePolicy};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    observability::install_redacted_panic_hook();
    observability::initialize()?;

    let command = std::env::args().nth(1);
    if command.as_deref() == Some("--version") {
        println!("super-gatewayd {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if command.as_deref() == Some("migrate") {
        let database_url = config::load_migrator_database_url().context("migration configuration is invalid")?;
        let report = PgStorage::migrate(&database_url)
            .await
            .context("database migration did not complete")?;
        println!(
            r#"{{"status":"ok","schema_version":{},"applied_migrations":{}}}"#,
            report.current_version, report.applied_count
        );
        return Ok(());
    }

    if command.as_deref() == Some("check-schema") {
        let database_url = config::load_runtime_database_url().context("runtime database configuration is invalid")?;
        let storage = PgStorage::connect(&database_url, RuntimeRolePolicy::Enforce)
            .await
            .context("runtime database schema is incompatible")?;
        let report = storage
            .validate_schema()
            .await
            .context("runtime database schema is incompatible")?;
        println!(
            r#"{{"status":"ok","schema_version":{},"applied_migrations":{}}}"#,
            report.current_version, report.applied_count
        );
        return Ok(());
    }

    let config = GatewayConfig::load().context("static gateway configuration is invalid")?;
    config
        .ensure_runtime_supported()
        .context("static gateway configuration selects an unavailable runtime adapter")?;
    if command.as_deref() == Some("--check-config") {
        println!(r#"{{"status":"ok"}}"#);
        return Ok(());
    }

    app::run(config).await
}
