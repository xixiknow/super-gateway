#!/usr/bin/env python3
"""Verify R1 release evidence hashes and source-tree bindings."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterable

from validate_contracts import ContractValidator


ROOT = Path(__file__).resolve().parents[1]
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


def tree_digest(paths: Iterable[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def resolve_inside(base: Path, relative: str) -> Path:
    target = (base / relative).resolve()
    if target != base and base not in target.parents:
        raise ValueError(f"artifact path leaves evidence directory: {relative}")
    return target


def verify_artifact(base: Path, item: dict) -> list[str]:
    errors: list[str] = []
    try:
        path = resolve_inside(base, item["path"])
    except ValueError as exc:
        return [str(exc)]
    if not path.is_file():
        return [f"artifact missing: {item['path']}"]
    if sha256_file(path) != item["sha256"]:
        errors.append(f"artifact digest mismatch: {item['path']}")
    if path.stat().st_size != item["size_bytes"]:
        errors.append(f"artifact size mismatch: {item['path']}")
    return errors


def gate_findings(verification: object, profile: str) -> list[str]:
    required = R10_REQUIRED_GATES if profile == "r10-local" else R1_REQUIRED_GATES
    if not isinstance(verification, dict) or set(verification) != required:
        return ["verification gate set differs from the fixed profile"]
    if any(state != "passed" for state in verification.values()):
        return ["every required verification gate must be passed"]
    return []


def module_findings(requirements: list[dict], projected: object) -> list[str]:
    findings: list[str] = []
    modules = [item for item in requirements if item.get("kind") == "functional_module"]
    expected = {f"REQ-F{index:02d}" for index in range(1, 19)}
    module_ids = [item.get("requirement_id") for item in modules]
    if len(module_ids) != 18 or set(module_ids) != expected or len(set(module_ids)) != 18:
        findings.append("functional module set is not exactly REQ-F01..REQ-F18")
    if any(item.get("status") not in {"implemented", "verified"} or not item.get("test_ids") for item in modules):
        findings.append("every functional module must be implemented and linked to a test")
    if projected != sorted(module_ids):
        findings.append("evidence functional module projection differs from ledger")
    return findings


def ga_requirement_findings(requirements: list[dict]) -> list[str]:
    """Require every GA-bound ledger row to carry verified evidence."""
    ga = [item for item in requirements if item.get("release_gate") == "ga"]
    findings: list[str] = []
    if not ga:
        return ["GA requirement ledger is empty"]
    incomplete = [item.get("requirement_id") for item in ga if item.get("status") != "verified"]
    untested = [item.get("requirement_id") for item in ga if not item.get("test_ids")]
    if incomplete:
        findings.append(f"GA requirements are not verified: {len(incomplete)}")
    if untested:
        findings.append(f"GA requirements lack test bindings: {len(untested)}")
    return findings


def restore_findings(restore: dict, backup_manifest_sha256: str, now: datetime) -> list[str]:
    findings: list[str] = []
    if restore.get("outcome") != "passed" or restore.get("source_snapshot") != restore.get("restored_snapshot"):
        findings.append("restore drill outcome or snapshot equality failed")
    if restore.get("backup_manifest_sha256") != backup_manifest_sha256:
        findings.append("restore drill is not bound to the backup manifest")
    completed = parse_time(restore.get("completed_at"))
    age = now - completed
    if age < timedelta(0) or age > timedelta(days=45):
        findings.append("restore drill evidence is future-dated or older than 45 days")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_dir", type=Path)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--profile", choices=["auto", "r1", "r10-local"], default="auto")
    parser.add_argument("--now", help="RFC3339 verification time for deterministic tests")
    parser.add_argument("--expected-revision")
    parser.add_argument("--expected-target")
    parser.add_argument(
        "--require-ga-ledger",
        action="store_true",
        help="fail unless every release_gate=ga requirement is verified; mandatory for RC/GA promotion",
    )
    args = parser.parse_args()
    evidence_dir = args.evidence_dir.resolve()
    source_root = args.source_root.resolve()
    errors: list[str] = []

    required = ["evidence-manifest.json", "release-manifest.json", "provenance.json", "sbom.cdx.json"]
    for name in required:
        if not (evidence_dir / name).is_file():
            errors.append(f"required evidence file missing: {name}")
    if errors:
        print("Release evidence verification FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    try:
        evidence = json.loads((evidence_dir / "evidence-manifest.json").read_text(encoding="utf-8"))
        release = json.loads((evidence_dir / "release-manifest.json").read_text(encoding="utf-8"))
        provenance = json.loads((evidence_dir / "provenance.json").read_text(encoding="utf-8"))
        sbom = json.loads((evidence_dir / "sbom.cdx.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"Release evidence verification FAILED: malformed JSON: {error}")
        return 1
    profile = args.profile
    if profile == "auto":
        profile = "r10-local" if evidence.get("schema_version") == "2.0.0" else "r1"
    contract_validator = ContractValidator()
    contract_validator.load_documents()
    evidence_schema_path = (
        source_root
        / "contracts"
        / "schemas"
        / ("r10-release-evidence.schema.json" if profile == "r10-local" else "release-evidence.schema.json")
    ).resolve()
    evidence_schema = contract_validator.documents.get(evidence_schema_path)
    if evidence_schema is None:
        errors.append("release evidence schema is missing")
    else:
        definitions = [("evidence-manifest.json", evidence, "R10EvidenceManifest")] if profile == "r10-local" else [
            ("evidence-manifest.json", evidence, "EvidenceManifest")
        ]
        release_schema_path = (source_root / "contracts" / "schemas" / "release-evidence.schema.json").resolve()
        release_schema = contract_validator.documents.get(release_schema_path)
        for name, instance, definition in definitions:
            errors.extend(
                contract_validator.validate_instance(
                    instance, evidence_schema["$defs"][definition], evidence_schema_path, name
                )
            )
        if release_schema is None:
            errors.append("release/provenance schema is missing")
        else:
            for name, instance, definition in [
                ("release-manifest.json", release, "ReleaseManifest"),
                ("provenance.json", provenance, "BuildProvenance"),
            ]:
                errors.extend(contract_validator.validate_instance(
                    instance, release_schema["$defs"][definition], release_schema_path, name
                ))
    for key in ["release_manifest", "provenance", "sbom"]:
        if isinstance(evidence.get(key), dict):
            errors.extend(verify_artifact(evidence_dir, evidence[key]))
        else:
            errors.append(f"evidence artifact descriptor missing: {key}")
    for item in release.get("artifacts", []):
        errors.extend(verify_artifact(evidence_dir, item))
    if release.get("artifacts") != provenance.get("subjects"):
        errors.append("release artifacts and provenance subjects differ")
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6":
        errors.append("SBOM format is not CycloneDX 1.6")
    errors.extend(gate_findings(evidence.get("verification"), profile))
    contract_hash = tree_digest(sorted((source_root / "contracts").rglob("*.json")), source_root)
    if contract_hash != release.get("contract_tree_sha256"):
        errors.append("contract tree digest mismatch")
    if sha256_file(source_root / "Cargo.lock") != release.get("cargo_lock_sha256"):
        errors.append("Cargo.lock digest mismatch")
    migration_dir = source_root / "crates" / "gateway-storage" / "migrations"
    actual_migrations = {path.name: sha256_file(path) for path in sorted(migration_dir.glob("*.sql"))}
    if actual_migrations != release.get("migration_checksums"):
        errors.append("migration checksum set mismatch")
    if provenance.get("target") != release.get("target") or provenance.get("created_at") != release.get("created_at"):
        errors.append("provenance target/timestamp differs from release")
    materials = {item.get("name"): item for item in provenance.get("materials", []) if isinstance(item, dict)}
    if materials.get("Cargo.lock", {}).get("sha256") != release.get("cargo_lock_sha256"):
        errors.append("provenance Cargo.lock material differs from release")
    if materials.get("contracts", {}).get("sha256") != release.get("contract_tree_sha256"):
        errors.append("provenance contracts material differs from release")
    if args.expected_revision and release.get("source_revision") != args.expected_revision:
        errors.append("source revision differs from expected candidate")
    if args.expected_target and release.get("target") != args.expected_target:
        errors.append("release target differs from expected candidate")

    if profile == "r10-local":
        for key in ["requirement_ledger", "backup_restore_manifest", "restore_drill"]:
            if isinstance(evidence.get(key), dict):
                errors.extend(verify_artifact(evidence_dir, evidence[key]))
            else:
                errors.append(f"R10 artifact descriptor missing: {key}")
        try:
            ledger = json.loads((evidence_dir / evidence["requirement_ledger"]["path"]).read_text(encoding="utf-8"))
            requirements = ledger["requirements"]
            errors.extend(module_findings(requirements, evidence.get("functional_modules")))
            if args.require_ga_ledger:
                errors.extend(ga_requirement_findings(requirements))
            restore = json.loads((evidence_dir / evidence["restore_drill"]["path"]).read_text(encoding="utf-8"))
            backup_path = evidence_dir / evidence["backup_restore_manifest"]["path"]
            backup = json.loads(backup_path.read_text(encoding="utf-8"))
            now = parse_time(args.now) if args.now else datetime.now(tz=UTC)
            errors.extend(restore_findings(restore, sha256_file(backup_path), now))
            for item in backup.get("objects", []):
                object_path = evidence_dir / "artifacts" / "backup" / Path(item["uri"]).name
                if not object_path.is_file() or sha256_file(object_path) != item.get("sha256"):
                    errors.append(f"backup object missing or drifted: {item.get('uri')}")
            if evidence.get("critical_findings") != 0:
                errors.append("critical findings must be zero")
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as error:
            errors.append(f"R10 evidence parse failed: {error}")

    if errors:
        print(f"Release evidence verification FAILED: {len(errors)} finding(s)")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"Release evidence verification PASSED: {len(release.get('artifacts', []))} artifact(s)")
    return 0


def parse_time(value: str | None) -> datetime:
    if not value:
        raise ValueError("date-time is missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("date-time lacks timezone")
    return parsed.astimezone(UTC)


if __name__ == "__main__":
    sys.exit(main())
