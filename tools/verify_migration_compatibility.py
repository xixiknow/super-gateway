#!/usr/bin/env python3
"""Fail-closed expand-migration compatibility preflight for two release manifests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid release manifest: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"release manifest must be an object: {path}")
    return value


def ordered_migrations(manifest: dict[str, Any]) -> list[tuple[int, str, str]]:
    raw = manifest.get("migration_checksums")
    if not isinstance(raw, dict) or not raw:
        raise ValueError("migration_checksums must be a non-empty object")
    migrations: list[tuple[int, str, str]] = []
    for name, digest in raw.items():
        if not isinstance(name, str) or len(name) < 15 or not name[:14].isdigit() or not name.endswith(".sql"):
            raise ValueError(f"invalid migration name: {name!r}")
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"invalid migration digest: {name}")
        migrations.append((int(name[:14]), name, digest))
    migrations.sort()
    if len({version for version, _, _ in migrations}) != len(migrations):
        raise ValueError("duplicate migration version")
    return migrations


def verify(current: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    for field in ("application", "target", "runtime_abi_version"):
        if current.get(field) != candidate.get(field):
            raise ValueError(f"release field changed incompatibly: {field}")
    current_migrations = ordered_migrations(current)
    candidate_migrations = ordered_migrations(candidate)
    if len(candidate_migrations) < len(current_migrations):
        raise ValueError("candidate migration history is shorter than current")
    if candidate_migrations[: len(current_migrations)] != current_migrations:
        raise ValueError("candidate rewrites or reorders an existing migration")
    for manifest, migrations, label in (
        (current, current_migrations, "current"),
        (candidate, candidate_migrations, "candidate"),
    ):
        compatibility = manifest.get("schema_compatibility")
        if not isinstance(compatibility, dict):
            raise ValueError(f"{label} schema_compatibility is missing")
        if compatibility.get("minimum") != migrations[0][0] or compatibility.get("maximum") != migrations[-1][0]:
            raise ValueError(f"{label} schema_compatibility does not match its migration set")
    return {
        "status": "passed",
        "current_schema": current_migrations[-1][0],
        "candidate_schema": candidate_migrations[-1][0],
        "new_migration_count": len(candidate_migrations) - len(current_migrations),
        "rollback_binary_check_required": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    try:
        report = verify(load_manifest(args.current), load_manifest(args.candidate))
    except ValueError as error:
        print(f"migration compatibility FAILED: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
