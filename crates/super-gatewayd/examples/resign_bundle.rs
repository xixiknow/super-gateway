//! One-off maintenance tool: re-sign a Bundle artifact at the current payload
//! schema version with the local release signing key. State-directory
//! artifacts are machine-local, so local-key signing is appropriate for them;
//! the built-in Windows Bundle keeps its own dedicated key and flow
//! (`resign_builtin_bundle`). Run from the repo root:
//! `cargo run -p super-gatewayd --example resign_bundle -- <path-to-bundle.json> [more paths…]`

use std::collections::BTreeSet;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use gateway_transport::{BundleLoadContext, BundleTrustStore, SignedBundleEnvelope};

const LOCAL_RELEASE_KEY_ID: &str = "local-release-signing-v1";
const STATE_DIR: &str = ".super-gateway-local";

fn runtime_target() -> &'static str {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "windows") => "x86_64-pc-windows-msvc",
        ("aarch64", "windows") => "aarch64-pc-windows-msvc",
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("aarch64", "macos") => "aarch64-apple-darwin",
        _ => "unsupported-target",
    }
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.len() % 2 != 0 {
        anyhow::bail!("hex value has an odd length");
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&trimmed[index..index + 2], 16).map_err(|error| anyhow::anyhow!("{error}")))
        .collect()
}

fn main() -> anyhow::Result<()> {
    let mut arguments = std::env::args().skip(1);
    let Some(first) = arguments.next() else {
        anyhow::bail!("usage: resign_bundle <bundle.json> [more…]");
    };
    let mut paths = vec![PathBuf::from(first)];
    paths.extend(arguments.map(PathBuf::from));

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let key_path = std::path::Path::new(manifest_dir).join(format!("../../{STATE_DIR}/bundle-signing-key"));
    let trust_path = std::path::Path::new(manifest_dir).join(format!("../../{STATE_DIR}/bundle-trust-store.json"));
    let key_bytes: [u8; 32] = decode_hex(&std::fs::read_to_string(&key_path)?)?
        .try_into()
        .map_err(|error: Vec<u8>| anyhow::anyhow!("signing key must be 32 bytes, got {}", error.len()))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let trust_store: BundleTrustStore = serde_json::from_slice(&std::fs::read(&trust_path)?)?;

    for path in paths {
        let envelope: SignedBundleEnvelope = serde_json::from_slice(&std::fs::read(&path)?)?;
        let mut payload = envelope.payload.clone();
        let previous_schema = payload.schema_version.clone();
        payload.schema_version = gateway_transport::current_payload_schema_version().into();
        let signed = SignedBundleEnvelope::sign(payload, LOCAL_RELEASE_KEY_ID, &signing_key)?;
        let context = BundleLoadContext {
            engine_abi_version: "1.0".into(),
            engine_build: env!("CARGO_PKG_VERSION").into(),
            target: runtime_target().into(),
            supported_capabilities: BTreeSet::from(["tls_client_hello".into(), "ordered_http1".into()]),
            now_unix_seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            for_new_activation: true,
        };
        let verified = signed
            .clone()
            .verify(&trust_store, &context)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let mut bytes = serde_json::to_vec_pretty(&signed)?;
        bytes.push(b'\n');
        std::fs::write(&path, bytes)?;
        println!(
            "re-signed {}: bundle_id={} schema {} -> {} hash {}",
            path.display(),
            verified.payload.bundle_id,
            previous_schema,
            verified.payload.schema_version,
            verified.canonical_hash
        );
    }
    Ok(())
}
