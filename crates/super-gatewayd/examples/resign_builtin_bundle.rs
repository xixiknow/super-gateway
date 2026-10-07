//! One-off maintenance tool: re-sign the built-in Windows Bundle at the current
//! payload schema version. Run from the repo root:
//! `cargo run -p super-gatewayd --example resign_builtin_bundle`

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use gateway_transport::{BundleLoadContext, BundleTrustStore, SignedBundleEnvelope};

const KEY_ID: &str = "builtin-windows-claude-code-2.1.241-v1";
const TARGET: &str = "x86_64-pc-windows-msvc";

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
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let asset_path = std::path::Path::new(manifest_dir).join("assets/windows-claude-code-2.1.241-h1.signed.json");
    let trust_path = std::path::Path::new(manifest_dir).join("assets/windows-claude-code-2.1.241.trust-store.json");
    let key_path =
        std::path::Path::new(manifest_dir).join("../../.super-gateway-local/builtin-windows-2.1.241-signing-key");

    let envelope: SignedBundleEnvelope = serde_json::from_slice(&std::fs::read(&asset_path)?)?;
    let mut payload = envelope.payload.clone();
    let previous_schema = payload.schema_version.clone();
    payload.schema_version = gateway_transport::current_payload_schema_version().into();

    let key_bytes: [u8; 32] = decode_hex(&std::fs::read_to_string(&key_path)?)?
        .try_into()
        .map_err(|error: Vec<u8>| anyhow::anyhow!("signing key must be 32 bytes, got {}", error.len()))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let signed = SignedBundleEnvelope::sign(payload, KEY_ID, &signing_key)?;
    let trust_store: BundleTrustStore = serde_json::from_slice(&std::fs::read(&trust_path)?)?;
    let context = BundleLoadContext {
        engine_abi_version: "1.0".into(),
        engine_build: env!("CARGO_PKG_VERSION").into(),
        target: TARGET.into(),
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
    println!(
        "verified: bundle_id={} schema {} -> {} hash {}",
        verified.payload.bundle_id, previous_schema, verified.payload.schema_version, verified.canonical_hash
    );

    let mut bytes = serde_json::to_vec_pretty(&signed)?;
    bytes.push(b'\n');
    std::fs::write(&asset_path, bytes)?;
    println!("written {}", asset_path.display());
    Ok(())
}
