#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use capture_endpoint::{AppState, CaptureAuth, CaptureStore, app};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(about = "Isolated normalized wire-evidence capture endpoint")]
struct Args {
    #[arg(long, env = "CAPTURE_ENDPOINT_BIND", default_value = "127.0.0.1:9443")]
    bind: SocketAddr,

    #[arg(long, env = "CAPTURE_ENDPOINT_STORE", default_value = "var/captures")]
    store: PathBuf,

    #[arg(long, env = "CAPTURE_ENDPOINT_TOKEN", hide_env_values = true)]
    token: Option<String>,

    #[arg(long, default_value_t = false)]
    allow_unauthenticated_loopback: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args = Args::parse();
    if !args.bind.ip().is_loopback() {
        bail!("this spike build is loopback-only until the mTLS listener is implemented");
    }
    let auth = match args.token {
        Some(token) if !token.is_empty() => CaptureAuth::required(&token),
        Some(_) => bail!("CAPTURE_ENDPOINT_TOKEN must not be empty"),
        None if args.allow_unauthenticated_loopback && args.bind.ip().is_loopback() => {
            CaptureAuth::DisabledLoopback
        }
        None => bail!(
            "a capture endpoint token is required; unauthenticated mode is restricted to an explicit loopback-only opt-in"
        ),
    };
    let store = CaptureStore::open(args.store)
        .await
        .context("initialize normalized capture store")?;
    let listener = TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("bind capture endpoint to {}", args.bind))?;
    info!(bind = %args.bind, "capture endpoint listening");
    axum::serve(listener, app(AppState::new(auth, store)))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve capture endpoint")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
