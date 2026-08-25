#!/usr/bin/env python3
"""Create an encrypted PostgreSQL fixture backup and prove isolated restore integrity."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def database_url(base: str, database: str) -> str:
    parsed = urlsplit(base)
    return urlunsplit((parsed.scheme, parsed.netloc, f"/{database}", parsed.query, parsed.fragment))


def command_path(pg_bin: Path | None, name: str) -> str:
    if pg_bin is not None:
        candidate = pg_bin / (f"{name}.exe" if os.name == "nt" else name)
        if candidate.is_file():
            return str(candidate)
    resolved = shutil.which(name)
    if resolved is None:
        raise RuntimeError(f"required PostgreSQL command is missing: {name}")
    return resolved


def run(command: list[str], *, capture: bool = False) -> str:
    process = subprocess.run(
        command,
        check=False,
        capture_output=capture,
        text=True,
        encoding="utf-8",
    )
    if process.returncode != 0:
        detail = process.stderr.strip().splitlines()[-1] if capture and process.stderr else "command failed"
        raise RuntimeError(f"{Path(command[0]).name}: {detail}")
    return process.stdout.strip() if capture else ""


def query(psql: str, url: str, sql: str) -> str:
    return run([psql, "-X", "-v", "ON_ERROR_STOP=1", "-At", "--dbname", url, "-c", sql], capture=True)


def snapshot(psql: str, url: str) -> dict[str, int]:
    values = query(
        psql,
        url,
        "SELECT "
        "(SELECT count(*) FROM pg_tables WHERE schemaname IN ('iam','gateway','catalog','telemetry','security','ops')),"
        "(SELECT count(*) FROM iam.user_account),"
        "(SELECT count(*) FROM security.audit_event),"
        "(SELECT count(*) FROM ops.outbox_message),"
        "(SELECT count(*) FROM _sqlx_migrations WHERE success)",
    ).split("|")
    if len(values) != 5:
        raise RuntimeError("PostgreSQL snapshot shape drifted")
    return {
        "physical_tables": int(values[0]),
        "users": int(values[1]),
        "audit_events": int(values[2]),
        "outbox_messages": int(values[3]),
        "migrations": int(values[4]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--key-file", required=True, type=Path)
    parser.add_argument("--pg-bin", type=Path)
    parser.add_argument("--openssl", type=Path)
    parser.add_argument("--restore-database", default="gateway_r2_restore_fixture")
    parser.add_argument("--key-version", type=int, default=1)
    parser.add_argument("--release-version", default="0.1.0-r9")
    args = parser.parse_args()

    if not args.key_file.is_file() or args.key_file.stat().st_size < 32:
        print("backup fixture key file is missing or too short", file=sys.stderr)
        return 2
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    psql = command_path(args.pg_bin, "psql")
    pg_dump = command_path(args.pg_bin, "pg_dump")
    pg_restore = command_path(args.pg_bin, "pg_restore")
    createdb = command_path(args.pg_bin, "createdb")
    dropdb = command_path(args.pg_bin, "dropdb")
    openssl = str(args.openssl.resolve()) if args.openssl and args.openssl.is_file() else shutil.which("openssl")
    if openssl is None:
        print("OpenSSL command is missing", file=sys.stderr)
        return 2

    started_at = datetime.now(tz=UTC)
    started_monotonic = time.monotonic()
    source = snapshot(psql, args.database_url)
    parsed = urlsplit(args.database_url)
    maintenance_url = database_url(args.database_url, "postgres")
    restore_url = database_url(args.database_url, args.restore_database)
    migration_fixture = ROOT / "contracts" / "fixtures" / "migration-manifest.valid.json"
    migration_manifest = json.loads(migration_fixture.read_text(encoding="utf-8"))
    system_id, timeline, lsn = query(
        psql,
        args.database_url,
        "SELECT s.system_identifier,c.timeline_id,c.checkpoint_lsn "
        "FROM pg_control_system() s CROSS JOIN pg_control_checkpoint() c",
    ).split("|")
    audit_watermark = query(
        psql,
        args.database_url,
        "SELECT COALESCE(max(event_day)::text,'none') FROM security.audit_daily_seal",
    )
    ledger_watermark = int(
        query(psql, args.database_url, "SELECT COALESCE(max(ledger_sequence),0) FROM security.deletion_ledger")
    )
    audit_seal_digest = query(
        psql,
        args.database_url,
        "SELECT encode(seal_digest,'hex') FROM security.audit_daily_seal ORDER BY event_day DESC LIMIT 1",
    ) or None
    deletion_entry_hash = query(
        psql,
        args.database_url,
        "SELECT encode(entry_hash,'hex') FROM security.deletion_ledger ORDER BY ledger_sequence DESC LIMIT 1",
    ) or None

    encrypted_dump = output / "gateway-r2.pgdump.enc"
    with tempfile.TemporaryDirectory(prefix="gateway-r2-backup-") as temporary:
        plain_dump = Path(temporary) / "gateway-r2.pgdump"
        restored_dump = Path(temporary) / "gateway-r2-restored.pgdump"
        run([pg_dump, "--format=custom", "--no-owner", "--file", str(plain_dump), args.database_url])
        run([
            openssl, "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-in", str(plain_dump),
            "-out", str(encrypted_dump), "-pass", f"file:{args.key_file.resolve()}",
        ])
        run([
            openssl, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-in", str(encrypted_dump),
            "-out", str(restored_dump), "-pass", f"file:{args.key_file.resolve()}",
        ])
        run([dropdb, "--if-exists", "--force", "--maintenance-db", maintenance_url, args.restore_database])
        run([createdb, "--maintenance-db", maintenance_url, args.restore_database])
        try:
            run([pg_restore, "--exit-on-error", "--no-owner", "--dbname", restore_url, str(restored_dump)])
            restored = snapshot(psql, restore_url)
            if restored != source:
                raise RuntimeError("isolated restore row/schema snapshot differs from source")
        finally:
            run([dropdb, "--if-exists", "--force", "--maintenance-db", maintenance_url, args.restore_database])

    migration_version = int(query(psql, args.database_url, "SELECT max(version) FROM _sqlx_migrations WHERE success"))
    if migration_version != migration_manifest["current_version"]:
        raise RuntimeError("database schema and migration manifest differ")
    created_at = datetime.now(tz=UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    manifest = {
        "schema_version": "2.0.0",
        "backup_id": str(uuid.uuid4()),
        "created_at_utc": created_at,
        "scope": "local_fixture",
        "backup_key_version": args.key_version,
        "database_system_id": system_id,
        "timeline": int(timeline),
        "base_backup_lsn": lsn,
        "wal_end_lsn": lsn,
        "release_version": args.release_version,
        "schema_version_value": migration_version,
        "migration_manifest_sha256": sha256_file(migration_fixture),
        "audit_seal_watermark": audit_watermark,
        "deletion_ledger_watermark": ledger_watermark,
        "audit": {"sealed_through": audit_watermark, "seal_digest": audit_seal_digest},
        "deletion_ledger": {"sequence": ledger_watermark, "entry_hash": deletion_entry_hash},
        "lineage": {
            "release_version": args.release_version,
            "schema_version": migration_version,
            "migration_manifest_sha256": sha256_file(migration_fixture),
            "parent_manifest_sha256": None,
        },
        "objects": [{
            "kind": "postgres_dump",
            "uri": encrypted_dump.name,
            "size_bytes": encrypted_dump.stat().st_size,
            "sha256": sha256_file(encrypted_dump),
        }],
        "included_categories": ["database", "audit_chain", "deletion_ledger", "migration_lineage"],
        "excluded_categories": ["production_wal", "content_audit_objects", "offsite_copy"],
        "encrypted": True,
    }
    canonical = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest["manifest_hmac_sha256"] = hmac.new(args.key_file.read_bytes(), canonical, hashlib.sha256).hexdigest()
    from validate_contracts import ContractValidator

    validator = ContractValidator()
    validator.load_documents()
    schema_path = (ROOT / "contracts" / "schemas" / "backup-restore-manifest.schema.json").resolve()
    schema = validator.documents[schema_path]
    schema_errors = validator.validate_instance(manifest, schema, schema_path, "backup-restore-manifest")
    if schema_errors:
        raise RuntimeError(schema_errors[0])
    manifest_path = output / "backup-restore-manifest.json"
    write_json(manifest_path, manifest)
    completed_at = datetime.now(tz=UTC)
    write_json(output / "restore-evidence.json", {
        "schema_version": "2.0.0",
        "started_at": started_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "completed_at": completed_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "duration_seconds": round(time.monotonic() - started_monotonic, 3),
        "backup_manifest_sha256": sha256_file(manifest_path),
        "source_database": parsed.path.removeprefix("/"),
        "restore_database": args.restore_database,
        "source_snapshot": source,
        "restored_snapshot": source,
        "outcome": "passed",
    })
    print(f"R2 backup/restore evidence written to {output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"R2 backup/restore FAILED: {error}", file=sys.stderr)
        sys.exit(1)
