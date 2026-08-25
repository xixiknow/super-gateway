#!/usr/bin/env python3
"""Build a deterministic R1 release bundle, CycloneDX SBOM and provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
VERIFICATION_STATES = {"passed", "failed", "not_run"}
R1_REQUIRED_GATES = {"format", "clippy", "tests", "contracts", "workspace"}
R10_REQUIRED_GATES = R1_REQUIRED_GATES | {
    "edge_policy", "postgres", "backup_restore_fixture", "admin_console", "windows_compatibility", "secret_canary",
    "transport_linux_native", "reproducible_build",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_digest(paths: Iterable[Path], root: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total_size = 0
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content_digest = sha256_file(path).encode("ascii")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(content_digest)
        digest.update(b"\n")
        total_size += path.stat().st_size
    return digest.hexdigest(), total_size


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def artifact(name: str, path: str, disk_path: Path) -> dict[str, Any]:
    return {"name": name, "path": path, "sha256": sha256_file(disk_path), "size_bytes": disk_path.stat().st_size}


def created_at() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    moment = datetime.fromtimestamp(int(epoch), tz=UTC) if epoch else datetime.now(tz=UTC)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def cargo_metadata() -> dict[str, Any]:
    process = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if process.returncode != 0:
        raise RuntimeError(process.stderr.strip() or "cargo metadata failed")
    return json.loads(process.stdout)


def build_sbom(metadata: dict[str, Any], target: str, timestamp: str, seed: str) -> dict[str, Any]:
    components = []
    for package in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"], item["id"])):
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": package["id"],
            "name": package["name"],
            "version": package["version"],
            "purl": f"pkg:cargo/{package['name']}@{package['version']}",
        }
        if package.get("license"):
            component["licenses"] = [{"expression": package["license"]}]
        components.append(component)
    serial = uuid.UUID(seed[:32])
    application = next(package for package in metadata["packages"] if package["name"] == "super-gatewayd")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "build_release_evidence.py", "version": "1.0.0"}]},
            "component": {
                "type": "application",
                "name": "super-gatewayd",
                "version": application["version"],
                "properties": [{"name": "super-gateway:target", "value": target}],
            },
        },
        "components": components,
    }


def parse_gates(values: list[str], profile: str) -> dict[str, str]:
    required = R10_REQUIRED_GATES if profile == "r10-local" else R1_REQUIRED_GATES
    gates = {name: "not_run" for name in required}
    seen: set[str] = set()
    for value in values:
        name, separator, state = value.partition("=")
        if not separator or name not in required or state not in VERIFICATION_STATES or name in seen:
            raise ValueError(f"invalid --gate {value!r}; expected NAME=passed|failed|not_run")
        seen.add(name)
        gates[name] = state
    return dict(sorted(gates.items()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-revision", default=os.environ.get("GITHUB_SHA", "local-working-tree"))
    parser.add_argument("--builder", default=os.environ.get("GITHUB_WORKFLOW", "local"))
    parser.add_argument("--gate", action="append", default=[])
    parser.add_argument("--profile", choices=["r1", "r10-local"], default="r1")
    parser.add_argument("--restore-evidence-dir", type=Path)
    parser.add_argument("--critical-findings", type=int)
    args = parser.parse_args()

    binary = args.binary.resolve()
    if not binary.is_file():
        print(f"release binary is missing: {binary}", file=sys.stderr)
        return 2
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    artifact_dir = output / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    copied_binary = output / binary.name
    shutil.copy2(binary, copied_binary)

    timestamp = created_at()
    lock_path = ROOT / "Cargo.lock"
    contract_files = sorted((ROOT / "contracts").rglob("*.json"))
    contract_hash, contract_size = tree_digest(contract_files, ROOT)
    migration_files = sorted((ROOT / "crates" / "gateway-storage" / "migrations").glob("*.sql"))
    migration_checksums = {path.name: sha256_file(path) for path in migration_files}
    migration_versions = [int(path.name[:14]) for path in migration_files]
    if not migration_versions:
        print("release migration set is empty", file=sys.stderr)
        return 2
    metadata = cargo_metadata()
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    app_package = next(package for package in metadata["packages"] if package["name"] == "super-gatewayd")
    binary_artifact = artifact("super-gatewayd", copied_binary.name, copied_binary)
    release_artifacts = [binary_artifact]
    deploy_target = output / "systemd"
    deploy_target.mkdir(exist_ok=True)
    for source in sorted((ROOT / "deploy" / "systemd").iterdir()):
        if source.is_file():
            target = deploy_target / source.name
            shutil.copy2(source, target)
            release_artifacts.append(artifact(source.name, f"systemd/{source.name}", target))
    packaged_tools = output / "tools"
    packaged_tools.mkdir(exist_ok=True)
    for name in ("verify_release_evidence.py", "verify_migration_compatibility.py", "validate_contracts.py"):
        source = ROOT / "tools" / name
        target = packaged_tools / name
        shutil.copy2(source, target)
        release_artifacts.append(artifact(name, f"tools/{name}", target))
    shutil.copy2(lock_path, output / "Cargo.lock")
    shutil.copytree(ROOT / "contracts", output / "contracts", dirs_exist_ok=True)
    packaged_migrations = output / "crates" / "gateway-storage" / "migrations"
    packaged_migrations.mkdir(parents=True, exist_ok=True)
    for source in migration_files:
        shutil.copy2(source, packaged_migrations / source.name)

    release = {
        "schema_version": "1.0.0",
        "application": "super-gatewayd",
        "application_version": app_package["version"],
        "target": args.target,
        "created_at": timestamp,
        "source_revision": args.source_revision,
        "rust_toolchain": toolchain,
        "runtime_abi_version": "r2-v1",
        "testkit_abi_version": "gateway-testkit-r1-v1",
        "schema_compatibility": {"minimum": migration_versions[0], "maximum": migration_versions[-1]},
        "cargo_lock_sha256": sha256_file(lock_path),
        "contract_tree_sha256": contract_hash,
        "migration_checksums": migration_checksums,
        "artifacts": release_artifacts,
    }
    release_path = output / "release-manifest.json"
    write_json(release_path, release)

    materials = [
        artifact("Cargo.lock", "Cargo.lock", lock_path),
        {"name": "contracts", "path": "contracts", "sha256": contract_hash, "size_bytes": contract_size},
    ]
    provenance = {
        "schema_version": "1.0.0",
        "builder": args.builder,
        "build_type": "super-gateway/rust-release-v1",
        "created_at": timestamp,
        "target": args.target,
        "command": ["cargo", "build", "--release", "--locked", "--target", args.target, "-p", "super-gatewayd"],
        "materials": materials,
        "subjects": release_artifacts,
    }
    provenance_path = output / "provenance.json"
    write_json(provenance_path, provenance)

    sbom_seed = hashlib.sha256(f"{contract_hash}:{sha256_file(lock_path)}:{args.target}".encode("utf-8")).hexdigest()
    sbom_path = output / "sbom.cdx.json"
    write_json(sbom_path, build_sbom(metadata, args.target, timestamp, sbom_seed))

    gates = parse_gates(args.gate, args.profile)
    evidence = {
        "schema_version": "1.0.0",
        "release_manifest": artifact("release-manifest.json", "release-manifest.json", release_path),
        "provenance": artifact("provenance.json", "provenance.json", provenance_path),
        "sbom": artifact("sbom.cdx.json", "sbom.cdx.json", sbom_path),
        "verification": gates,
    }
    if args.profile == "r10-local":
        if args.restore_evidence_dir is None or args.critical_findings is None or args.critical_findings < 0:
            raise ValueError("r10-local requires --restore-evidence-dir and --critical-findings")
        restore_dir = args.restore_evidence_dir.resolve()
        backup_source = restore_dir / "backup-restore-manifest.json"
        restore_source = restore_dir / "restore-evidence.json"
        if not backup_source.is_file() or not restore_source.is_file():
            raise ValueError("r10-local restore evidence is incomplete")
        backup_target = output / backup_source.name
        restore_target = output / restore_source.name
        shutil.copy2(backup_source, backup_target)
        shutil.copy2(restore_source, restore_target)
        backup_manifest = json.loads(backup_source.read_text(encoding="utf-8"))
        backup_artifact_dir = artifact_dir / "backup"
        backup_artifact_dir.mkdir(exist_ok=True)
        for item in backup_manifest.get("objects", []):
            source = restore_dir / item["uri"]
            if not source.is_file() or sha256_file(source) != item["sha256"]:
                raise ValueError(f"backup object is missing or drifted: {item['uri']}")
            shutil.copy2(source, backup_artifact_dir / source.name)
        ledger_source = ROOT / "contracts" / "traceability" / "requirements.json"
        ledger_target = output / "requirements.json"
        shutil.copy2(ledger_source, ledger_target)
        ledger = json.loads(ledger_source.read_text(encoding="utf-8"))
        modules = sorted(
            item["requirement_id"] for item in ledger["requirements"] if item.get("kind") == "functional_module"
        )
        evidence.update({
            "schema_version": "2.0.0",
            "profile": "r10-local",
            "requirement_ledger": artifact("requirements.json", "requirements.json", ledger_target),
            "backup_restore_manifest": artifact(backup_target.name, backup_target.name, backup_target),
            "restore_drill": artifact(restore_target.name, restore_target.name, restore_target),
            "functional_modules": modules,
            "critical_findings": args.critical_findings,
        })
    write_json(output / "evidence-manifest.json", evidence)
    print(f"Release evidence written to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
