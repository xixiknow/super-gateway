use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{Context, Result, bail, ensure};
use capture_schema::CaptureLane;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use uuid::Uuid;
use wire_normalizer::{NormalizedCapture, verify_normalized_capture};

use crate::release_bundle::{PromoteRequest, PublishLifecycle, promote};

#[derive(Debug)]
pub(crate) struct ReleaseRequest {
    pub claude_bin: PathBuf,
    pub iterations: usize,
    pub output_dir: PathBuf,
    pub signing_key: Option<PathBuf>,
    pub engine_artifact: Option<PathBuf>,
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
    let request = ReleaseRequest {
        claude_bin,
        output_dir,
        ..request
    };
    ensure!(
        request.iterations >= 20,
        "release-bundle requires at least 20 iterations"
    );
    ensure!(
        request.claude_bin.is_file(),
        "Claude Code executable does not exist: {}",
        request.claude_bin.display()
    );
    let in_progress_marker = request.output_dir.join(".release-bundle-in-progress");
    let resume_interrupted_release = in_progress_marker.is_file();
    ensure!(
        resume_interrupted_release
            || !request.output_dir.exists()
            || fs::read_dir(&request.output_dir)
                .with_context(|| format!("read output directory {}", request.output_dir.display()))?
                .next()
                .is_none(),
        "release output directory must be empty or contain its interrupted-run marker: {}",
        request.output_dir.display()
    );
    fs::create_dir_all(&request.output_dir)
        .with_context(|| format!("create release output directory {}", request.output_dir.display()))?;
    fs::write(&in_progress_marker, b"release-bundle\n").context("write interrupted-release marker")?;
    let version = inspect_claude_version(&request.claude_bin).await?;
    ensure!(
        version == "2.1.245 (Claude Code)",
        "release-bundle expected Claude Code 2.1.245, found {version}"
    );
    let claude_hash = file_sha256(&request.claude_bin)?;
    let poc_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .context("locate transport-poc workspace")?
        .to_path_buf();
    let repository_root = poc_root.parent().context("locate repository root")?.to_path_buf();
    let references = request.output_dir.join("reference");
    fs::create_dir_all(&references).context("create release reference directory")?;
    for iteration in 1..=request.iterations {
        let official = references.join(format!("{iteration:02}-official.normalized.json"));
        let controlled = references.join(format!("{iteration:02}-controlled.normalized.json"));
        if resume_interrupted_release && official.is_file() && controlled.is_file() {
            let existing: NormalizedCapture = read_json(&official)?;
            verify_pair(&official, &controlled, existing.capture_run_id, &version, &claude_hash)?;
            println!("release reference pair {iteration}/{}: resumed", request.iterations);
            continue;
        }
        if official.is_file() {
            fs::remove_file(&official).context("remove incomplete official reference")?;
        }
        if controlled.is_file() {
            fs::remove_file(&controlled).context("remove incomplete controlled reference")?;
        }
        let capture_run_id = Uuid::new_v4();
        run_cargo_tool(
            &poc_root,
            "claude-capture-runner",
            &[
                "--claude-bin".into(),
                request.claude_bin.as_os_str().to_owned(),
                "--output".into(),
                official.as_os_str().to_owned(),
                "--capture-run-id".into(),
                capture_run_id.to_string().into(),
                "official-tls".into(),
                "--synthetic-auth".into(),
            ],
        )
        .await
        .with_context(|| format!("capture privacy-safe official TLS reference {iteration}"))?;
        run_cargo_tool(
            &poc_root,
            "claude-capture-runner",
            &[
                "--claude-bin".into(),
                request.claude_bin.as_os_str().to_owned(),
                "--output".into(),
                controlled.as_os_str().to_owned(),
                "--capture-run-id".into(),
                capture_run_id.to_string().into(),
                "controlled".into(),
            ],
        )
        .await
        .with_context(|| format!("capture controlled Messages reference {iteration}"))?;
        verify_pair(&official, &controlled, capture_run_id, &version, &claude_hash)?;
        println!("release reference pair {iteration}/{}: passed", request.iterations);
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

    let replay_dir = request.output_dir.join("replay");
    if replay_dir.exists() {
        fs::remove_dir_all(&replay_dir).context("replace interrupted derived replay directory")?;
    }
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

    let signing_key = request
        .signing_key
        .unwrap_or_else(|| repository_root.join(".super-gateway-local/bundle-signing-key"));
    let sibling_engine_artifact = std::env::current_exe().ok().and_then(|executable| {
        executable
            .parent()
            .map(|directory| directory.join("super-gatewayd.exe"))
    });
    let engine_artifact = request
        .engine_artifact
        .or_else(|| std::env::var_os("SUPER_GATEWAY_ENGINE_ARTIFACT").map(PathBuf::from))
        .or_else(|| sibling_engine_artifact.filter(|path| path.is_file()))
        .unwrap_or_else(|| repository_root.join("target/debug/super-gatewayd.exe"));
    ensure!(
        engine_artifact.is_file(),
        "production engine artifact is missing: {}; build super-gatewayd or set SUPER_GATEWAY_ENGINE_ARTIFACT",
        engine_artifact.display()
    );
    let source_archetype_version_id = read_manifest_id(&manifest)?;
    let signed_bundle = request
        .output_dir
        .join("claude-code-windows-2.1.245.signed-bundle.json");
    let trust_store = request.output_dir.join("claude-code-windows-2.1.245.trust-store.json");
    let formal_replay = request.output_dir.join("formal-production-replay.json");
    promote(PromoteRequest {
        candidate: candidate.clone(),
        manifest: manifest.clone(),
        audit: audit.clone(),
        stability_report: stability.clone(),
        signing_key,
        key_id: "local-release-signing-v1".to_owned(),
        target: "x86_64-pc-windows-msvc".to_owned(),
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
    let output = Command::new(claude_bin)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .await
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

async fn run_cargo_tool(root: &Path, package: &str, args: &[OsString]) -> Result<()> {
    let status = Command::new("cargo")
        .current_dir(root)
        .arg("run")
        .arg("--quiet")
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
