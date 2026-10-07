use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{Context, Result, bail, ensure};
use capture_schema::CaptureLane;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::process::Command;
use uuid::Uuid;
use wire_normalizer::{NormalizedCapture, verify_normalized_capture};

use crate::release_bundle::{PromoteRequest, PublishLifecycle, promote};

#[derive(Debug)]
pub(crate) struct ReleaseRequest {
    pub interactive: bool,
    pub expected_version: String,
    pub target: Option<String>,
    pub evidence_only: bool,
    pub preflight: bool,
    pub claude_bin: PathBuf,
    pub iterations: usize,
    pub output_dir: PathBuf,
    pub signing_key: Option<PathBuf>,
    pub engine_artifact: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Checkpoint {
    interactive: bool,
    schema_version: u32,
    expected_version: String,
    claude_binary_sha256: String,
    tool_sha256: String,
    os: String,
    arch: String,
    target: String,
    iterations: usize,
    evidence_only: bool,
    engine_sha256: Option<String>,
    signing_key_fingerprint: Option<String>,
    environment_sha256: String,
}

fn checkpoint(request: &ReleaseRequest) -> Result<Checkpoint> {
    ensure!(
        request.iterations >= 20,
        "release-bundle requires at least 20 iterations"
    );
    super::release_bundle::encode_artifact_version(&request.expected_version)?;
    let native = super::capture_platform::target_for(std::env::consts::OS, std::env::consts::ARCH)?;
    let target = request.target.as_deref().unwrap_or(native);
    ensure!(target == native, "target must match this capture host ({native})");
    ensure!(
        request.evidence_only || target == "x86_64-pc-windows-msvc",
        "formal signing and gateway auto-import currently support Windows x64 H1; use --evidence-only for this host"
    );
    let engine_sha256 = if request.evidence_only {
        None
    } else {
        Some(file_sha256(
            request
                .engine_artifact
                .as_deref()
                .context("engine artifact is required")?,
        )?)
    };
    let signing_key_fingerprint = if request.evidence_only {
        None
    } else {
        let path = request.signing_key.as_deref().context("signing key path is required")?;
        if path.exists() {
            let bytes = hex::decode(fs::read_to_string(path)?.trim()).context("invalid signing key encoding")?;
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("signing key must have 32 bytes"))?;
            Some(hex::encode(Sha256::digest(
                ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
            )))
        } else {
            None
        }
    };
    // Store a digest only, since proxy and authentication environment values can contain secrets.
    let mut environment = std::env::vars()
        .filter(|(key, _)| {
            let key = key.to_ascii_uppercase();
            key.starts_with("CLAUDE")
                || key.starts_with("ANTHROPIC")
                || key.contains("PROXY")
                || matches!(
                    key.as_str(),
                    "NODE_OPTIONS" | "NODE_EXTRA_CA_CERTS" | "SSL_CERT_FILE" | "SSL_CERT_DIR"
                )
        })
        .collect::<Vec<_>>();
    environment.sort();
    Ok(Checkpoint {
        interactive: request.interactive,
        schema_version: 2,
        expected_version: request.expected_version.clone(),
        claude_binary_sha256: file_sha256(&request.claude_bin)?,
        tool_sha256: file_sha256(&std::env::current_exe()?)?,
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        target: target.to_owned(),
        iterations: request.iterations,
        evidence_only: request.evidence_only,
        engine_sha256,
        signing_key_fingerprint,
        environment_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&environment)?)),
    })
}

fn validate_output(path: &Path, identity: &Checkpoint) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "output directory must not be a symlink"
    );
    let marker = path.join(".release-bundle-in-progress");
    if marker.is_file() {
        let saved: Checkpoint =
            read_json(&marker).context("legacy or invalid checkpoint; use a new output directory")?;
        ensure!(
            &saved == identity,
            "resume parameters, executable, environment, or engine changed; use a new output directory"
        );
        return Ok(true);
    }
    ensure!(
        fs::read_dir(path)?.next().is_none(),
        "output directory must be empty or have a matching checkpoint"
    );
    Ok(false)
}

#[derive(Debug, Serialize)]
struct ReleasePackage {
    schema_version: u32,
    decision: &'static str,
    claude_code_version: String,
    claude_binary_sha256: String,
    iterations: usize,
    capture_pairs: usize,
    model_usage: bool,
    credentials_saved: bool,
    prompts_saved: bool,
    request_bodies_saved: bool,
    claude_outputs_saved: bool,
    manifest: String,
    candidate: String,
    stability_report: String,
    canary_audit: String,
    formal_replay_report: String,
    signed_bundle: String,
    trust_store: String,
    source_archetype_version_id: Uuid,
}

pub(crate) async fn release(request: ReleaseRequest) -> Result<()> {
    let invocation_directory = std::env::current_dir().context("read release invocation directory")?;
    let output_dir = if request.output_dir.is_absolute() {
        request.output_dir.clone()
    } else {
        invocation_directory.join(&request.output_dir)
    };
    let claude_bin = if request.claude_bin.is_absolute() {
        request.claude_bin.clone()
    } else {
        invocation_directory.join(&request.claude_bin)
    };
    let poc_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .context("locate transport-poc workspace")?
        .to_path_buf();
    let repository_root = poc_root.parent().context("locate repository root")?.to_path_buf();
    let absolute = |path: PathBuf| {
        if path.is_absolute() {
            path
        } else {
            invocation_directory.join(path)
        }
    };
    let engine_name = format!("super-gatewayd{}", std::env::consts::EXE_SUFFIX);
    let sibling = std::env::current_exe()?
        .parent()
        .context("executable parent")?
        .join(&engine_name);
    let engine_artifact = request
        .engine_artifact
        .clone()
        .or_else(|| std::env::var_os("SUPER_GATEWAY_ENGINE_ARTIFACT").map(PathBuf::from))
        .or_else(|| sibling.is_file().then_some(sibling))
        .unwrap_or_else(|| repository_root.join("target/debug").join(engine_name));
    let request = ReleaseRequest {
        claude_bin,
        output_dir,
        signing_key: Some(absolute(
            request
                .signing_key
                .clone()
                .unwrap_or_else(|| repository_root.join(".super-gateway-local/bundle-signing-key")),
        )),
        engine_artifact: Some(absolute(engine_artifact)),
        ..request
    };
    let identity = checkpoint(&request)?;
    let resume_interrupted_release = validate_output(&request.output_dir, &identity)?;
    if request.preflight {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "decision":"ready_for_capture", "capture_started":false, "external_requests":false,
                "client_executed":false, "installed_version_verified":false,
                "identity":identity, "resume":resume_interrupted_release,
                "output_dir":request.output_dir,
                "mode":if request.evidence_only {"evidence_only"} else {"formal_windows_h1"},
                "artifacts":["reference/*-official.normalized.json","reference/*-controlled.normalized.json",
                    "reference/*-system-template.json","system_template.json","evidence-package.json"],
                "real_oauth_baseline_verified":false,
                "entrypoint":if request.interactive {"cli (interactive PTY)"} else {"sdk-cli (print mode)"},
            }))?
        );
        return Ok(());
    }
    let version = inspect_claude_version(&request.claude_bin).await?;
    ensure!(
        version == format!("{} (Claude Code)", request.expected_version),
        "installed Claude version differs from --expected-version"
    );
    let claude_hash = file_sha256(&request.claude_bin)?;
    ensure!(
        claude_hash == identity.claude_binary_sha256,
        "Claude executable changed during preflight"
    );
    if !request.evidence_only {
        super::release_bundle::load_or_create_signing_key(
            request.signing_key.as_deref().context("signing key path is required")?,
        )?;
    }
    let identity = checkpoint(&request)?;
    let in_progress_marker = request.output_dir.join(".release-bundle-in-progress");
    fs::create_dir_all(&request.output_dir)
        .with_context(|| format!("create release output directory {}", request.output_dir.display()))?;
    if !resume_interrupted_release {
        write_json(&in_progress_marker, &identity)?;
    }
    let references = request.output_dir.join("reference");
    fs::create_dir_all(&references).context("create release reference directory")?;
    let mut static_template = None;
    for iteration in 1..=request.iterations {
        let official = references.join(format!("{iteration:02}-official.normalized.json"));
        let controlled = references.join(format!("{iteration:02}-controlled.normalized.json"));
        let template = references.join(format!("{iteration:02}-system-template.json"));
        if resume_interrupted_release && official.is_file() && controlled.is_file() && template.is_file() {
            let existing: NormalizedCapture = read_json(&official)?;
            verify_pair(&official, &controlled, existing.capture_run_id, &version, &claude_hash)?;
            verify_template(&template, &controlled, &mut static_template)?;
            println!("release reference pair {iteration}/{}: resumed", request.iterations);
            continue;
        }
        if official.is_file() {
            fs::remove_file(&official).context("remove incomplete official reference")?;
        }
        if controlled.is_file() {
            fs::remove_file(&controlled).context("remove incomplete controlled reference")?;
        }
        if template.is_file() {
            fs::remove_file(&template).context("remove incomplete template evidence")?;
        }
        let capture_run_id = Uuid::new_v4();
        let mode_args: Vec<OsString> = if request.interactive {
            vec!["--interactive".into()]
        } else {
            vec![]
        };
        run_cargo_tool(
            &poc_root,
            "claude-capture-runner",
            &[
                mode_args.clone(),
                vec![
                    "--claude-bin".into(),
                    request.claude_bin.as_os_str().to_owned(),
                    "--output".into(),
                    official.as_os_str().to_owned(),
                    "--capture-run-id".into(),
                    capture_run_id.to_string().into(),
                    "official-tls".into(),
                    "--synthetic-auth".into(),
                ],
            ]
            .concat(),
        )
        .await
        .with_context(|| format!("capture privacy-safe official TLS reference {iteration}"))?;
        run_cargo_tool(
            &poc_root,
            "claude-capture-runner",
            &[
                mode_args,
                vec![
                    "--claude-bin".into(),
                    request.claude_bin.as_os_str().to_owned(),
                    "--output".into(),
                    controlled.as_os_str().to_owned(),
                    "--capture-run-id".into(),
                    capture_run_id.to_string().into(),
                    "controlled".into(),
                    "--system-template-output".into(),
                    template.as_os_str().to_owned(),
                ],
            ]
            .concat(),
        )
        .await
        .with_context(|| format!("capture controlled Messages reference {iteration}"))?;
        verify_pair(&official, &controlled, capture_run_id, &version, &claude_hash)?;
        verify_template(&template, &controlled, &mut static_template)?;
        println!("release reference pair {iteration}/{}: passed", request.iterations);
    }

    let template = static_template.context("no resolved static template")?;
    write_json(&request.output_dir.join("system_template.json"), &template)?;
    write_json(
        &request.output_dir.join("evidence-package.json"),
        &serde_json::json!({
            "schema_version":1, "decision":"captured_not_release_verified", "identity":identity,
            "capture_pairs":request.iterations, "system_template":"system_template.json",
            "system_template_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&template)?)),
            "template_source":"isolated_controlled_capture", "real_oauth_baseline_verified":false,
            "model_usage":false, "raw_request_bodies_saved":false,
        }),
    )?;
    if request.evidence_only {
        fs::remove_file(&in_progress_marker)?;
        println!("paired evidence and static template complete; formal release not performed");
        return Ok(());
    }

    let executable = std::env::current_exe().context("locate spike-cli executable")?;
    let first_official = references.join("01-official.normalized.json");
    let first_controlled = references.join("01-controlled.normalized.json");
    let manifest = request.output_dir.join("capture.manifest.json");
    let candidate = request.output_dir.join("bundle.candidate.json");
    let official_plan = request.output_dir.join("official.replay-plan.json");
    let controlled_plan = request.output_dir.join("controlled.replay-plan.json");
    run_self(
        &executable,
        &[
            "manifest".into(),
            "--passive-tls".into(),
            first_official.as_os_str().to_owned(),
            "--controlled-http2".into(),
            first_controlled.as_os_str().to_owned(),
            "--output".into(),
            manifest.as_os_str().to_owned(),
        ],
    )
    .await?;
    run_self(
        &executable,
        &[
            "bundle".into(),
            "--manifest".into(),
            manifest.as_os_str().to_owned(),
            "--passive-tls".into(),
            first_official.as_os_str().to_owned(),
            "--controlled-http2".into(),
            first_controlled.as_os_str().to_owned(),
            "--bundle-version".into(),
            "1".into(),
            "--output".into(),
            candidate.as_os_str().to_owned(),
        ],
    )
    .await?;
    run_self(
        &executable,
        &[
            "plan".into(),
            "--bundle".into(),
            candidate.as_os_str().to_owned(),
            "--target-kind".into(),
            "anthropic-official".into(),
            "--authority".into(),
            "api.anthropic.com".into(),
            "--port".into(),
            "443".into(),
            "--mode".into(),
            "probe".into(),
            "--output".into(),
            official_plan.as_os_str().to_owned(),
        ],
    )
    .await?;
    run_self(
        &executable,
        &[
            "plan".into(),
            "--bundle".into(),
            candidate.as_os_str().to_owned(),
            "--target-kind".into(),
            "controlled-capture".into(),
            "--authority".into(),
            "capture.invalid".into(),
            "--port".into(),
            "9443".into(),
            "--mode".into(),
            "probe".into(),
            "--output".into(),
            controlled_plan.as_os_str().to_owned(),
        ],
    )
    .await?;

    let replay_dir = request.output_dir.join(format!("replay-{}", Uuid::new_v4()));
    let stability = request.output_dir.join("fresh-stability.report.json");
    run_self(
        &executable,
        &[
            "fresh-stability-matrix".into(),
            "--official-plan".into(),
            official_plan.as_os_str().to_owned(),
            "--controlled-plan".into(),
            controlled_plan.as_os_str().to_owned(),
            "--reference-directory".into(),
            references.as_os_str().to_owned(),
            "--iterations".into(),
            request.iterations.to_string().into(),
            "--reference-collection-attempts".into(),
            request.iterations.to_string().into(),
            "--output-directory".into(),
            replay_dir.as_os_str().to_owned(),
            "--output-report".into(),
            stability.as_os_str().to_owned(),
        ],
    )
    .await?;

    let tls_capture = request.output_dir.join("formal-canary.tls.normalized.json");
    let tls_diff = request.output_dir.join("formal-canary.tls.diff.json");
    let tls_evidence = request.output_dir.join("formal-canary.tls-handshake.json");
    let tls_canary = request.output_dir.join("formal-canary.tls-evidence.json");
    run_self(
        &executable,
        &[
            "capture-tls-diff".into(),
            "--plan".into(),
            official_plan.as_os_str().to_owned(),
            "--reference".into(),
            first_official.as_os_str().to_owned(),
            "--output-capture".into(),
            tls_capture.as_os_str().to_owned(),
            "--output-diff".into(),
            tls_diff.as_os_str().to_owned(),
            "--output-evidence".into(),
            tls_evidence.as_os_str().to_owned(),
            "--output-canary-evidence".into(),
            tls_canary.as_os_str().to_owned(),
        ],
    )
    .await?;
    let cancellation = request.output_dir.join("formal-canary.h1-cancellation.json");
    run_self(
        &executable,
        &[
            "capture-h1-cancellation".into(),
            "--plan".into(),
            controlled_plan.as_os_str().to_owned(),
            "--output-evidence".into(),
            cancellation.as_os_str().to_owned(),
        ],
    )
    .await?;
    let audit = request.output_dir.join("canary.audit.json");
    run_self(
        &executable,
        &[
            "audit-bundle".into(),
            "--input".into(),
            candidate.as_os_str().to_owned(),
            "--mode".into(),
            "canary".into(),
            "--probe-plan".into(),
            official_plan.as_os_str().to_owned(),
            "--probe-plan".into(),
            controlled_plan.as_os_str().to_owned(),
            "--tls-evidence".into(),
            tls_canary.as_os_str().to_owned(),
            "--cancellation-evidence".into(),
            cancellation.as_os_str().to_owned(),
            "--output".into(),
            audit.as_os_str().to_owned(),
        ],
    )
    .await?;

    let signing_key = request.signing_key.context("signing key path is required")?;
    let engine_artifact = request.engine_artifact.context("engine artifact is required")?;
    ensure!(
        Some(file_sha256(&engine_artifact)?) == identity.engine_sha256,
        "production engine artifact changed during capture"
    );
    let source_archetype_version_id = read_manifest_id(&manifest)?;
    let signed_bundle = request.output_dir.join(format!(
        "claude-code-{}-{}.signed-bundle.json",
        identity.os, request.expected_version
    ));
    let trust_store = request.output_dir.join(format!(
        "claude-code-{}-{}.trust-store.json",
        identity.os, request.expected_version
    ));
    let formal_replay = request.output_dir.join("formal-production-replay.json");
    promote(PromoteRequest {
        candidate: candidate.clone(),
        manifest: manifest.clone(),
        audit: audit.clone(),
        stability_report: stability.clone(),
        signing_key,
        key_id: "local-release-signing-v1".to_owned(),
        target: identity.target,
        source_archetype_version_id: source_archetype_version_id.to_string(),
        engine_artifact,
        lifecycle: PublishLifecycle::Verified,
        output: signed_bundle.clone(),
        trust_store_output: trust_store.clone(),
        replay_report_output: formal_replay.clone(),
    })
    .await?;
    let package = ReleasePackage {
        schema_version: 1,
        decision: "passed",
        claude_code_version: version,
        claude_binary_sha256: claude_hash,
        iterations: request.iterations,
        capture_pairs: request.iterations,
        model_usage: false,
        credentials_saved: false,
        prompts_saved: false,
        request_bodies_saved: false,
        claude_outputs_saved: false,
        manifest: relative_name(&manifest),
        candidate: relative_name(&candidate),
        stability_report: relative_name(&stability),
        canary_audit: relative_name(&audit),
        formal_replay_report: relative_name(&formal_replay),
        signed_bundle: relative_name(&signed_bundle),
        trust_store: relative_name(&trust_store),
        source_archetype_version_id,
    };
    write_json(&request.output_dir.join("release-package.json"), &package)?;
    fs::remove_file(&in_progress_marker).context("remove interrupted-release marker")?;
    println!("release-bundle completed: {}", request.output_dir.display());
    Ok(())
}

async fn inspect_claude_version(claude_bin: &Path) -> Result<String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        Command::new(claude_bin)
            .arg("--version")
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .context("Claude version check timed out")?
    .with_context(|| format!("run {} --version", claude_bin.display()))?;
    ensure!(output.status.success(), "Claude Code version command failed");
    Ok(String::from_utf8(output.stdout)
        .context("Claude Code version is not UTF-8")?
        .trim()
        .to_owned())
}

fn verify_pair(official: &Path, controlled: &Path, run_id: Uuid, version: &str, binary_hash: &str) -> Result<()> {
    let official: NormalizedCapture = read_json(official)?;
    let controlled: NormalizedCapture = read_json(controlled)?;
    verify_normalized_capture(&official).context("verify official normalized capture")?;
    verify_normalized_capture(&controlled).context("verify controlled normalized capture")?;
    for capture in [&official, &controlled] {
        ensure!(
            capture.environment.os_name.eq_ignore_ascii_case(std::env::consts::OS)
                && capture.environment.arch == std::env::consts::ARCH,
            "capture host OS or architecture drifted"
        );
        ensure!(
            capture.scenario.id == "T01-real-claude-minimal-message"
                && capture.scenario.fresh_connection
                && capture.scenario.concurrent_streams == 1,
            "capture scenario drifted"
        );
    }
    ensure!(
        official.lane == CaptureLane::ReferenceOfficialTls
            && controlled.lane == CaptureLane::ReferenceControlledEndpoint,
        "capture pair has incorrect lanes"
    );
    ensure!(
        official.capture_run_id == run_id && controlled.capture_run_id == run_id,
        "capture pair does not share its run ID"
    );
    ensure!(
        official.environment.claude_code_version == version && controlled.environment.claude_code_version == version,
        "capture pair Claude Code version drifted"
    );
    ensure!(
        official.environment.binary_sha256.as_deref() == Some(binary_hash)
            && controlled.environment.binary_sha256.as_deref() == Some(binary_hash),
        "capture pair Claude executable hash drifted"
    );
    Ok(())
}

fn verify_template(path: &Path, controlled_path: &Path, previous: &mut Option<serde_json::Value>) -> Result<()> {
    let value: serde_json::Value = read_json(path)?;
    let capture: NormalizedCapture = read_json(controlled_path)?;
    ensure!(
        value["schema_version"] == 1 && value["source"] == "isolated_controlled_capture",
        "template evidence format mismatch"
    );
    ensure!(
        value["capture_run_id"] == capture.capture_run_id.to_string()
            && value["normalized_sha256"] == capture.normalized_sha256
            && value["environment"] == serde_json::to_value(&capture.environment)?,
        "template is not bound to controlled evidence"
    );
    let template = value
        .get("system_template")
        .filter(|v| v.as_array().is_some_and(|a| !a.is_empty()))
        .context("static template is missing or empty")?;
    let hash = hex::encode(Sha256::digest(serde_json::to_vec(template)?));
    ensure!(value["system_template_sha256"] == hash, "template checksum mismatch");
    if let Some(previous) = previous {
        ensure!(
            previous == template,
            "static system template drifted between iterations"
        );
    } else {
        *previous = Some(template.clone());
    }
    Ok(())
}

async fn run_cargo_tool(root: &Path, package: &str, args: &[OsString]) -> Result<()> {
    let status = Command::new("cargo")
        .current_dir(root)
        .arg("run")
        .arg("--quiet")
        .arg("--locked")
        .arg("-p")
        .arg(package)
        .arg("--all-features")
        .arg("--")
        .args(args)
        .stdin(Stdio::null())
        .status()
        .await
        .with_context(|| format!("run Cargo package {package}"))?;
    if !status.success() {
        bail!("Cargo package {package} exited with {status}");
    }
    Ok(())
}

async fn run_self(executable: &Path, args: &[OsString]) -> Result<()> {
    let status = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .status()
        .await
        .with_context(|| format!("run {}", executable.display()))?;
    if !status.success() {
        bail!("spike-cli release stage exited with {status}");
    }
    Ok(())
}

fn read_manifest_id(path: &Path) -> Result<Uuid> {
    let value: serde_json::Value = read_json(path)?;
    let value = value
        .get("manifest_id")
        .and_then(serde_json::Value::as_str)
        .context("Manifest ID is missing")?;
    Uuid::parse_str(value).context("Manifest ID is invalid")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).context("serialize release package")?,
    )
    .with_context(|| format!("write {}", path.display()))
}

fn file_sha256(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )))
}

fn relative_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("capture-preflight-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn request(&self) -> ReleaseRequest {
            let claude_bin = self.0.join("not-an-executable");
            fs::write(&claude_bin, b"invalid executable; preflight must never run this").unwrap();
            ReleaseRequest {
                interactive: false,
                expected_version: "2.1.245".into(),
                target: None,
                evidence_only: true,
                preflight: true,
                claude_bin,
                iterations: 20,
                output_dir: self.0.join("output"),
                signing_key: Some(self.0.join("signing-key")),
                engine_artifact: None,
            }
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn preflight_never_executes_client_or_creates_outputs() {
        let scratch = Scratch::new();
        let request = scratch.request();
        let output = request.output_dir.clone();
        let key = request.signing_key.clone().unwrap();
        release(request).await.unwrap();
        assert!(!output.exists());
        assert!(!key.exists());
    }

    #[test]
    fn resume_requires_matching_identity_and_rejects_legacy_marker() {
        let scratch = Scratch::new();
        let mut request = scratch.request();
        let identity = checkpoint(&request).unwrap();
        assert!(!validate_output(&request.output_dir, &identity).unwrap());
        fs::create_dir(&request.output_dir).unwrap();
        let marker = request.output_dir.join(".release-bundle-in-progress");
        fs::write(&marker, "release-bundle\n").unwrap();
        assert!(validate_output(&request.output_dir, &identity).is_err());
        write_json(&marker, &identity).unwrap();
        assert!(validate_output(&request.output_dir, &identity).unwrap());
        request.iterations = 21;
        assert!(validate_output(&request.output_dir, &checkpoint(&request).unwrap()).is_err());
        request.iterations = 20;
        fs::write(&request.claude_bin, "changed").unwrap();
        assert!(validate_output(&request.output_dir, &checkpoint(&request).unwrap()).is_err());
        fs::remove_file(&marker).unwrap();
        fs::write(request.output_dir.join("unrelated"), "keep").unwrap();
        assert!(validate_output(&request.output_dir, &identity).is_err());
    }

    #[test]
    fn preflight_rejects_wrong_target_and_too_few_iterations() {
        let scratch = Scratch::new();
        let mut request = scratch.request();
        request.target = Some("unsupported-target".into());
        assert!(checkpoint(&request).is_err());
        request.target = None;
        request.iterations = 19;
        assert!(checkpoint(&request).is_err());
    }

    #[test]
    fn template_evidence_rejects_wrong_binding_checksum_and_drift() {
        let scratch = Scratch::new();
        let batch = crate::sample_batch(CaptureLane::ReferenceControlledEndpoint, Uuid::new_v4());
        let capture = wire_normalizer::normalize_capture(&batch).unwrap();
        let controlled = scratch.0.join("controlled.json");
        let path = scratch.0.join("template.json");
        write_json(&controlled, &capture).unwrap();
        let template = serde_json::json!([{"type":"text", "text":"# Tone and style\nstatic"}]);
        let evidence = serde_json::json!({
            "schema_version":1, "source":"isolated_controlled_capture",
            "capture_run_id":capture.capture_run_id, "normalized_sha256":capture.normalized_sha256,
            "environment":capture.environment, "system_template":template,
            "system_template_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&template).unwrap())),
        });
        write_json(&path, &evidence).unwrap();
        let mut previous = None;
        verify_template(&path, &controlled, &mut previous).unwrap();
        assert_eq!(previous, Some(template));
        for field in [
            "capture_run_id",
            "normalized_sha256",
            "system_template_sha256",
            "environment",
        ] {
            let mut invalid = evidence.clone();
            invalid[field] = serde_json::json!("changed");
            write_json(&path, &invalid).unwrap();
            assert!(verify_template(&path, &controlled, &mut previous).is_err(), "{field}");
        }
        write_json(&path, &evidence).unwrap();
        previous = Some(serde_json::json!([{"type":"text", "text":"different"}]));
        assert!(verify_template(&path, &controlled, &mut previous).is_err());
    }
}
