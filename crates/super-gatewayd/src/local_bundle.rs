//! Idempotent installation of the verified Windows Claude Code 2.1.241 Bundle.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use gateway_transport::{
    BundleLoadContext, BundleTrustStore, CompiledTransportEngine, SignedBundleEnvelope, TrustKey, TrustKeyStatus,
    VerifiedBundle,
};
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::config::ensure_local_secret;

const BUILTIN_BUNDLE_BYTES: &[u8] = include_bytes!("../assets/windows-claude-code-2.1.241-h1.signed.json");
const BUILTIN_TRUST_STORE_BYTES: &[u8] = include_bytes!("../assets/windows-claude-code-2.1.241.trust-store.json");

const BUILTIN_TARGET: &str = "x86_64-pc-windows-msvc";
const BUILTIN_BUNDLE_FILE: &str = "windows-claude-code-2.1.241-h1.json";
const BUILTIN_CLIENT_VERSION: &str = "2.1.241";
const BUILTIN_ARCHETYPE_NAME: &str = "Claude Code 2.1.241（Windows 内置）";
const BUILTIN_CAPTURE_COHORT: &str = "windows-x86_64-claude-code-native-2.1.241-c49a05922a787c33";
const LOCAL_RELEASE_KEY_ID: &str = "local-release-signing-v1";

const BUILTIN_ARCHETYPE_ID: &str = "019c8a24-1000-7000-8000-000000000001";
const BUILTIN_EVIDENCE_SET_ID: &str = "019c8a24-1000-7000-8000-000000000002";
const BUILTIN_ARCHETYPE_VERSION_ID: &str = "019c8a24-1000-7000-8000-000000000003";
const BUILTIN_CAPACITY_ID: &str = "019c8a24-1000-7000-8000-000000000004";
const BUILTIN_BUNDLE_ROW_ID: &str = "019c8a24-1000-7000-8000-000000000005";
const BUILTIN_REPLAY_ID: &str = "019c8a24-1000-7000-8000-000000000006";
const BUILTIN_CAPTURE_RUN_ID: &str = "019c8a24-1000-7000-8000-000000000007";
const BUILTIN_TLS_EVIDENCE_ID: &str = "019c8a24-1000-7000-8000-000000000008";
const BUILTIN_HEADERS_EVIDENCE_ID: &str = "019c8a24-1000-7000-8000-000000000009";
const BUILTIN_REPLAY_EVIDENCE_ID: &str = "019c8a24-1000-7000-8000-00000000000a";
const BUILTIN_PRIVACY_EVIDENCE_ID: &str = "019c8a24-1000-7000-8000-00000000000b";

const SYNTHETIC_ARCHETYPE_ID: &str = "019c8a00-0000-7000-8000-000000000001";
const SYNTHETIC_EVIDENCE_SET_ID: &str = "019c8a00-0000-7000-8000-000000000002";
const SYNTHETIC_ARCHETYPE_VERSION_ID: &str = "019c8a00-0000-7000-8000-000000000003";
const SYNTHETIC_BUNDLE_ROW_ID: &str = "019c8a00-0000-7000-8000-000000000005";

pub(crate) async fn ensure_local_bundle(state_dir: &Path, pool: &PgPool) -> anyhow::Result<()> {
    let target = crate::app::runtime_target();
    ensure!(
        target == BUILTIN_TARGET,
        "the built-in Claude Code 2.1.241 Bundle supports Windows x86_64 only"
    );
    let envelope: SignedBundleEnvelope =
        serde_json::from_slice(BUILTIN_BUNDLE_BYTES).context("built-in Bundle schema is invalid")?;
    ensure!(
        envelope.payload.source_archetype_version_id.as_ref() == BUILTIN_ARCHETYPE_VERSION_ID,
        "built-in Bundle source Archetype binding is invalid"
    );
    ensure!(
        envelope.payload.capture_cohort.as_ref() == BUILTIN_CAPTURE_COHORT,
        "built-in Bundle capture cohort is invalid"
    );
    let trust_store = load_combined_trust_store(state_dir)?;
    let verified = verify_and_compile(envelope.clone(), &trust_store, target)?;
    let bundle_path = persist_builtin_resources(state_dir, &trust_store)?;
    seed_catalog(
        pool,
        &CatalogSeed {
            envelope: &envelope,
            verified: &verified,
            bundle_path: &bundle_path,
        },
    )
    .await
}

fn load_combined_trust_store(state_dir: &Path) -> anyhow::Result<BundleTrustStore> {
    let mut trust_store: BundleTrustStore =
        serde_json::from_slice(BUILTIN_TRUST_STORE_BYTES).context("built-in Bundle Trust Store schema is invalid")?;
    let local_key = load_local_release_key(state_dir)?;
    trust_store
        .keys
        .retain(|key| key.key_id.as_ref() != LOCAL_RELEASE_KEY_ID);
    trust_store.keys.push(TrustKey {
        key_id: LOCAL_RELEASE_KEY_ID.into(),
        status: TrustKeyStatus::Current,
        public_key_base64: STANDARD.encode(local_key.verifying_key().to_bytes()).into_boxed_str(),
        valid_from_unix_seconds: None,
        valid_until_unix_seconds: None,
    });
    Ok(trust_store)
}

fn load_local_release_key(state_dir: &Path) -> anyhow::Result<SigningKey> {
    let key_secret = ensure_local_secret(&state_dir.join("bundle-signing-key"))
        .context("local release Bundle signing key initialization failed")?;
    Ok(SigningKey::from_bytes(&decode_hex_key(key_secret.expose())?))
}

fn verify_and_compile(
    envelope: SignedBundleEnvelope,
    trust_store: &BundleTrustStore,
    target: &str,
) -> anyhow::Result<VerifiedBundle> {
    let now_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let verified = envelope
        .verify(
            trust_store,
            &BundleLoadContext {
                engine_abi_version: "1.0".into(),
                engine_build: env!("CARGO_PKG_VERSION").into(),
                target: target.into(),
                supported_capabilities: BTreeSet::from(["tls_client_hello".into(), "ordered_http1".into()]),
                now_unix_seconds,
                for_new_activation: true,
            },
        )
        .context("built-in Bundle verification failed")?;
    CompiledTransportEngine::compile(verified.clone()).context("built-in Bundle production compilation failed")?;
    Ok(verified)
}

fn persist_builtin_resources(state_dir: &Path, trust_store: &BundleTrustStore) -> anyhow::Result<PathBuf> {
    let bundle_dir = state_dir.join("bundles");
    std::fs::create_dir_all(&bundle_dir).context("local Bundle directory initialization failed")?;
    let obsolete = bundle_dir.join("local-default-h1.json");
    if obsolete.exists() {
        std::fs::remove_file(&obsolete).context("obsolete synthetic Bundle removal failed")?;
    }
    let bundle_path = bundle_dir.join(BUILTIN_BUNDLE_FILE);
    write_if_changed(&bundle_path, BUILTIN_BUNDLE_BYTES)?;
    let trust_store_bytes =
        serde_json::to_vec_pretty(trust_store).context("combined local Trust Store serialization failed")?;
    write_if_changed(&state_dir.join("bundle-trust-store.json"), &trust_store_bytes)?;
    Ok(bundle_path)
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if std::fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

struct CatalogSeed<'a> {
    envelope: &'a SignedBundleEnvelope,
    verified: &'a VerifiedBundle,
    bundle_path: &'a Path,
}

struct CatalogIds {
    archetype: Uuid,
    evidence_set: Uuid,
    version: Uuid,
    capacity: Uuid,
    bundle: Uuid,
    replay: Uuid,
    capture_run: Uuid,
    tls_evidence: Uuid,
    headers_evidence: Uuid,
    replay_evidence: Uuid,
    privacy_evidence: Uuid,
}

impl CatalogIds {
    fn builtin() -> anyhow::Result<Self> {
        Ok(Self {
            archetype: uuid(BUILTIN_ARCHETYPE_ID)?,
            evidence_set: uuid(BUILTIN_EVIDENCE_SET_ID)?,
            version: uuid(BUILTIN_ARCHETYPE_VERSION_ID)?,
            capacity: uuid(BUILTIN_CAPACITY_ID)?,
            bundle: uuid(BUILTIN_BUNDLE_ROW_ID)?,
            replay: uuid(BUILTIN_REPLAY_ID)?,
            capture_run: uuid(BUILTIN_CAPTURE_RUN_ID)?,
            tls_evidence: uuid(BUILTIN_TLS_EVIDENCE_ID)?,
            headers_evidence: uuid(BUILTIN_HEADERS_EVIDENCE_ID)?,
            replay_evidence: uuid(BUILTIN_REPLAY_EVIDENCE_ID)?,
            privacy_evidence: uuid(BUILTIN_PRIVACY_EVIDENCE_ID)?,
        })
    }
}

async fn seed_catalog(pool: &PgPool, seed: &CatalogSeed<'_>) -> anyhow::Result<()> {
    let ids = CatalogIds::builtin()?;
    let mut transaction = pool
        .begin()
        .await
        .context("built-in catalog transaction could not start")?;
    upsert_evidence(&mut transaction, seed, &ids).await?;
    upsert_archetype(&mut transaction, seed, &ids).await?;
    upsert_bundle(&mut transaction, seed, &ids).await?;
    replace_synthetic_catalog(&mut transaction, &ids).await?;
    transaction
        .commit()
        .await
        .context("built-in Bundle catalog commit failed")?;
    Ok(())
}

async fn upsert_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    seed: &CatalogSeed<'_>,
    ids: &CatalogIds,
) -> anyhow::Result<()> {
    let evidence_hash = decode_sha256(
        seed.envelope
            .payload
            .evidence_hashes
            .first()
            .context("built-in evidence hash is missing")?,
    )?;
    sqlx::query(
        "INSERT INTO catalog.evidence_set (id,name,source_code,state_code,capture_cohort,content_hash,created_at) \
         VALUES ($1,'Claude Code 2.1.241 Windows 真实采集证据','official_capture','complete',$2,$3,clock_timestamp()) \
         ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,source_code='official_capture',state_code='complete', \
           capture_cohort=EXCLUDED.capture_cohort,content_hash=EXCLUDED.content_hash",
    )
    .bind(ids.evidence_set)
    .bind(BUILTIN_CAPTURE_COHORT)
    .bind(&evidence_hash)
    .execute(&mut **transaction)
    .await
    .context("built-in evidence set initialization failed")?;
    sqlx::query(
        "INSERT INTO catalog.capture_run \
           (id,evidence_set_id,os_family_code,runner_version,client_version,state_code,privacy_scan_code,started_at,completed_at,detail) \
         VALUES ($1,$2,'windows','transport-poc/schema-v2',$3,'succeeded','passed',clock_timestamp(),clock_timestamp(),$4) \
         ON CONFLICT (id) DO UPDATE SET evidence_set_id=EXCLUDED.evidence_set_id,client_version=EXCLUDED.client_version, \
           state_code='succeeded',privacy_scan_code='passed',detail=EXCLUDED.detail",
    )
    .bind(ids.capture_run)
    .bind(ids.evidence_set)
    .bind(BUILTIN_CLIENT_VERSION)
    .bind(json!({
        "source_capture_run_id":"da9cbfe6-6610-4dc9-8e23-c573accd91cc",
        "manifest_id":"0f929de5-82a1-4ccb-8583-6a7d5d6bdf43",
        "claude_binary_sha256":"c49a05922a787c33478067a5164002932235f6611948523b55ae1fbdb303ac1f",
        "capture_mode":"reused_verified_reference",
        "model_usage":false
    }))
    .execute(&mut **transaction)
    .await
    .context("built-in capture run initialization failed")?;
    let items = [
        (
            ids.tls_evidence,
            "tls",
            "4a1daa2597ba151dab84caa72ea96c17f5cf295846f6ec19a8c26b512eb24b75",
            json!({"lane":"reference_official_tls","client_hello_len":512,"alpn":["http/1.1"]}),
        ),
        (
            ids.headers_evidence,
            "headers",
            "510101a4add04a5412e20edc8e8f85f994637ab3e7d5d674278984c5e29ef6a4",
            json!({"lane":"reference_controlled_endpoint","ordered_headers":21,"protocol":"http1"}),
        ),
        (
            ids.replay_evidence,
            "replay",
            "478d00018c76b966e51cbf23a8dbdaa0114e892ff257b78f0e5171b90ee38aa7",
            json!({"iterations":20,"passed":20,"decision":"pass","formal_runtime_replay":true}),
        ),
        (
            ids.privacy_evidence,
            "privacy_scan",
            "4f5470b9cecad370a1f3e60d4dae0d63c324aa54857838fe9a05c649b2e2763a",
            json!({"decision":"passed","credentials_saved":false,"prompt_saved":false,"body_saved":false,"output_saved":false}),
        ),
    ];
    for (id, kind, hash, payload) in items {
        sqlx::query(
            "INSERT INTO catalog.evidence_item (id,evidence_set_id,kind_code,payload,content_hash,captured_at) \
             VALUES ($1,$2,$3,$4,$5,clock_timestamp()) ON CONFLICT (id) DO UPDATE SET \
             evidence_set_id=EXCLUDED.evidence_set_id,kind_code=EXCLUDED.kind_code,payload=EXCLUDED.payload,content_hash=EXCLUDED.content_hash",
        )
        .bind(id)
        .bind(ids.evidence_set)
        .bind(kind)
        .bind(payload)
        .bind(decode_sha256(hash)?)
        .execute(&mut **transaction)
        .await
        .context("built-in evidence item initialization failed")?;
    }
    Ok(())
}

async fn upsert_archetype(
    transaction: &mut Transaction<'_, Postgres>,
    seed: &CatalogSeed<'_>,
    ids: &CatalogIds,
) -> anyhow::Result<()> {
    let version_hash = decode_sha256(&seed.verified.canonical_hash)?;
    sqlx::query(
        "INSERT INTO catalog.environment_archetype \
           (id,name,os_family_code,architecture_code,lifecycle_code,created_at,updated_at,revision,os_build,client_family_code) \
         VALUES ($1,$2,'windows','x86_64','active',clock_timestamp(),clock_timestamp(),1,'10.0.26200.9168','claude_code_cli') \
         ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,lifecycle_code='active',updated_at=clock_timestamp(), \
           os_build=EXCLUDED.os_build,client_family_code=EXCLUDED.client_family_code",
    )
    .bind(ids.archetype)
    .bind(BUILTIN_ARCHETYPE_NAME)
    .execute(&mut **transaction)
    .await
    .context("built-in environment Archetype initialization failed")?;
    sqlx::query(
        "INSERT INTO catalog.environment_archetype_version \
           (id,archetype_id,version,lifecycle_code,runtime_code,runtime_version,client_version,protocol_profile, \
            evidence_set_id,content_hash,created_at,activated_at,os_build,architecture_code,client_family_code,capture_cohort,profile_schema_version,shell) \
         VALUES ($1,$2,1,'active','native','claude-code-native',$3,$4,$5,$6,clock_timestamp(),clock_timestamp(), \
            '10.0.26200.9168','x86_64','claude_code_cli',$7,2,'PowerShell') \
         ON CONFLICT (id) DO UPDATE SET lifecycle_code='active',runtime_code='native',runtime_version='claude-code-native', \
           client_version=EXCLUDED.client_version,protocol_profile=EXCLUDED.protocol_profile,evidence_set_id=EXCLUDED.evidence_set_id, \
           content_hash=EXCLUDED.content_hash,activated_at=COALESCE(catalog.environment_archetype_version.activated_at,clock_timestamp()), \
           os_build=EXCLUDED.os_build,architecture_code='x86_64',client_family_code='claude_code_cli',capture_cohort=EXCLUDED.capture_cohort,profile_schema_version=2,shell='PowerShell'",
    )
    .bind(ids.version)
    .bind(ids.archetype)
    .bind(BUILTIN_CLIENT_VERSION)
    .bind(json!({"protocol":"h1","source":"verified_transport_poc_schema_v2","claude_code_version":"2.1.241","manifest_id":"0f929de5-82a1-4ccb-8583-6a7d5d6bdf43"}))
    .bind(ids.evidence_set)
    .bind(version_hash)
    .bind(BUILTIN_CAPTURE_COHORT)
    .execute(&mut **transaction)
    .await
    .context("built-in Archetype version initialization failed")?;
    sqlx::query(
        "INSERT INTO catalog.archetype_capacity_policy \
           (id,archetype_version_id,max_credentials,revision,created_at,updated_at,allocation_weight,allocation_cohort) \
         VALUES ($1,$2,100,1,clock_timestamp(),clock_timestamp(),1,'builtin-2.1.241') \
         ON CONFLICT (archetype_version_id) DO UPDATE SET max_credentials=100,updated_at=clock_timestamp(),allocation_weight=1,allocation_cohort='builtin-2.1.241'",
    )
    .bind(ids.capacity)
    .bind(ids.version)
    .execute(&mut **transaction)
    .await
    .context("built-in Archetype capacity initialization failed")?;
    Ok(())
}

async fn upsert_bundle(
    transaction: &mut Transaction<'_, Postgres>,
    seed: &CatalogSeed<'_>,
    ids: &CatalogIds,
) -> anyhow::Result<()> {
    let signature = STANDARD
        .decode(seed.envelope.signature.detached_signature_base64.as_bytes())
        .context("built-in Bundle signature encoding is invalid")?;
    let manifest = serde_json::to_value(seed.envelope).context("built-in Bundle serialization failed")?;
    let artifact_version =
        i64::try_from(seed.envelope.payload.artifact_version).context("built-in artifact version is invalid")?;
    sqlx::query(
        "INSERT INTO catalog.transport_bundle \
           (id,artifact_version,engine_abi_version,lifecycle_code,manifest,manifest_hash,signature,signing_key_id,object_uri, \
            created_at,activated_at,source_archetype_version_id,capture_cohort,protocol_code,backend_id,canonicalization_algorithm, \
            signature_domain,signature_algorithm,evidence_gate_code,runtime_state_code,min_engine_build,max_engine_build,engine_activation_generation) \
         VALUES ($1,$2,'1.0','active',$3,$4,$5,$6,$7,clock_timestamp(),clock_timestamp(),$8,$9,'h1',$10, \
            'jcs_rfc8785','transport_bundle_v1','ed25519','passed','loadable',$11,$12,1) \
         ON CONFLICT (id) DO UPDATE SET lifecycle_code='active',manifest=EXCLUDED.manifest,manifest_hash=EXCLUDED.manifest_hash, \
           signature=EXCLUDED.signature,signing_key_id=EXCLUDED.signing_key_id,object_uri=EXCLUDED.object_uri, \
           activated_at=COALESCE(catalog.transport_bundle.activated_at,clock_timestamp()),source_archetype_version_id=EXCLUDED.source_archetype_version_id, \
           capture_cohort=EXCLUDED.capture_cohort,protocol_code='h1',backend_id=EXCLUDED.backend_id,evidence_gate_code='passed', \
           runtime_state_code='loadable',min_engine_build=EXCLUDED.min_engine_build,max_engine_build=EXCLUDED.max_engine_build",
    )
    .bind(ids.bundle)
    .bind(artifact_version)
    .bind(manifest)
    .bind(decode_sha256(&seed.verified.canonical_hash)?)
    .bind(signature)
    .bind(seed.envelope.signature.key_id.as_ref())
    .bind(seed.bundle_path.to_string_lossy().as_ref())
    .bind(ids.version)
    .bind(BUILTIN_CAPTURE_COHORT)
    .bind(seed.envelope.payload.backend_id.as_ref())
    .bind(seed.envelope.payload.min_engine_build.as_ref())
    .bind(seed.envelope.payload.max_engine_build.as_deref())
    .execute(&mut **transaction)
    .await
    .context("built-in Transport Bundle initialization failed")?;
    sqlx::query(
        "INSERT INTO catalog.archetype_bundle_binding (archetype_version_id,transport_bundle_id,state_code,created_at,activated_at,protocol_code) \
         VALUES ($1,$2,'active',clock_timestamp(),clock_timestamp(),'h1') ON CONFLICT (archetype_version_id,transport_bundle_id) \
         DO UPDATE SET state_code='active',activated_at=COALESCE(catalog.archetype_bundle_binding.activated_at,clock_timestamp()),protocol_code='h1'",
    )
    .bind(ids.version)
    .bind(ids.bundle)
    .execute(&mut **transaction)
    .await
    .context("built-in Bundle binding initialization failed")?;
    sqlx::query(
        "INSERT INTO catalog.replay_verification (id,archetype_version_id,transport_bundle_id,evidence_set_id,state_code,result,verified_at) \
         VALUES ($1,$2,$3,$4,'passed',$5,clock_timestamp()) ON CONFLICT (id) DO UPDATE SET state_code='passed',result=EXCLUDED.result,verified_at=clock_timestamp()",
    )
    .bind(ids.replay)
    .bind(ids.version)
    .bind(ids.bundle)
    .bind(ids.evidence_set)
    .bind(json!({"source":"formal_windows_transport_replay","iterations":20,"passed":20,"tls":"passed","http1":"passed","cancellation":"passed","canary_audit":"ready_for_canary"}))
    .execute(&mut **transaction)
    .await
    .context("built-in replay verification initialization failed")?;
    Ok(())
}

async fn replace_synthetic_catalog(
    transaction: &mut Transaction<'_, Postgres>,
    ids: &CatalogIds,
) -> anyhow::Result<()> {
    let old_version = uuid(SYNTHETIC_ARCHETYPE_VERSION_ID)?;
    let old_bundle = uuid(SYNTHETIC_BUNDLE_ROW_ID)?;
    sqlx::query("UPDATE gateway.credential_profile SET archetype_version_id=$1,capture_cohort=$2,updated_at=clock_timestamp(),revision=revision+1 WHERE archetype_version_id=$3")
        .bind(ids.version).bind(BUILTIN_CAPTURE_COHORT).bind(old_version)
        .execute(&mut **transaction).await.context("synthetic Credential profile replacement failed")?;
    sqlx::query(
        "UPDATE gateway.credential_profile_change SET from_archetype_version_id=$1 WHERE from_archetype_version_id=$2",
    )
    .bind(ids.version)
    .bind(old_version)
    .execute(&mut **transaction)
    .await
    .context("synthetic profile history replacement failed")?;
    sqlx::query(
        "UPDATE gateway.credential_profile_change SET to_archetype_version_id=$1 WHERE to_archetype_version_id=$2",
    )
    .bind(ids.version)
    .bind(old_version)
    .execute(&mut **transaction)
    .await
    .context("synthetic profile target replacement failed")?;
    for table in [
        "telemetry.attempt_record",
        "telemetry.connection_attempt_record",
        "telemetry.attempt_submission_intent",
    ] {
        let statement = format!("UPDATE {table} SET transport_bundle_id=$1 WHERE transport_bundle_id=$2");
        sqlx::query(&statement)
            .bind(ids.bundle)
            .bind(old_bundle)
            .execute(&mut **transaction)
            .await
            .with_context(|| format!("synthetic Bundle reference replacement failed in {table}"))?;
    }
    sqlx::query("UPDATE catalog.bundle_runtime_incident SET transport_bundle_id=$1,archetype_version_id=CASE WHEN archetype_version_id=$2 THEN $3 ELSE archetype_version_id END WHERE transport_bundle_id=$4 OR archetype_version_id=$2")
        .bind(ids.bundle).bind(old_version).bind(ids.version).bind(old_bundle)
        .execute(&mut **transaction).await.context("synthetic Bundle incident replacement failed")?;
    sqlx::query(
        "DELETE FROM catalog.replay_verification WHERE id=$1 OR transport_bundle_id=$2 OR archetype_version_id=$3",
    )
    .bind(uuid("019c8a00-0000-7000-8000-000000000006")?)
    .bind(old_bundle)
    .bind(old_version)
    .execute(&mut **transaction)
    .await
    .context("synthetic replay removal failed")?;
    sqlx::query("DELETE FROM catalog.archetype_bundle_binding WHERE transport_bundle_id=$1 OR archetype_version_id=$2")
        .bind(old_bundle)
        .bind(old_version)
        .execute(&mut **transaction)
        .await
        .context("synthetic binding removal failed")?;
    sqlx::query("DELETE FROM catalog.archetype_capacity_policy WHERE archetype_version_id=$1")
        .bind(old_version)
        .execute(&mut **transaction)
        .await
        .context("synthetic capacity removal failed")?;
    sqlx::query("DELETE FROM catalog.transport_bundle WHERE id=$1")
        .bind(old_bundle)
        .execute(&mut **transaction)
        .await
        .context("synthetic Bundle row removal failed")?;
    sqlx::query("DELETE FROM catalog.environment_archetype_version WHERE id=$1")
        .bind(old_version)
        .execute(&mut **transaction)
        .await
        .context("synthetic Archetype version removal failed")?;
    sqlx::query("DELETE FROM catalog.environment_archetype WHERE id=$1")
        .bind(uuid(SYNTHETIC_ARCHETYPE_ID)?)
        .execute(&mut **transaction)
        .await
        .context("synthetic Archetype removal failed")?;
    let old_evidence = uuid(SYNTHETIC_EVIDENCE_SET_ID)?;
    sqlx::query("DELETE FROM catalog.capture_run WHERE evidence_set_id=$1")
        .bind(old_evidence)
        .execute(&mut **transaction)
        .await
        .context("synthetic capture removal failed")?;
    sqlx::query("DELETE FROM catalog.evidence_set WHERE id=$1")
        .bind(old_evidence)
        .execute(&mut **transaction)
        .await
        .context("synthetic evidence removal failed")?;
    Ok(())
}

fn uuid(value: &str) -> anyhow::Result<Uuid> {
    Uuid::parse_str(value).context("built-in catalog UUID is invalid")
}

fn decode_hex_key(value: &str) -> anyhow::Result<[u8; 32]> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("local release signing key must contain 32 bytes"))
}

fn decode_sha256(value: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = decode_hex(value)?;
    if bytes.len() != 32 {
        bail!("evidence hash must contain 32 bytes");
    }
    Ok(bytes)
}

fn decode_hex(value: &str) -> anyhow::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        bail!("hex value has an odd length");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).context("hex value contains invalid digits"))
        .collect()
}
