//! Metadata-only structured logging bootstrap.

use anyhow::Context as _;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

/// Install a panic hook that records location without formatting the panic payload.
pub fn install_redacted_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        if let Some(location) = info.location() {
            tracing::error!(
                event = "process_panic",
                file = location.file(),
                line = location.line(),
                column = location.column(),
                "component panicked; payload redacted"
            );
        } else {
            tracing::error!(
                event = "process_panic",
                "component panicked; payload and location redacted"
            );
        }
    }));
}

/// Initialize JSON logs with a bounded environment filter.
pub fn initialize() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .with_target(true),
        )
        .try_init()
        .context("structured logging subscriber initialization failed")
}
