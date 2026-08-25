#!/usr/bin/env python3
"""Negative policy tests for the fail-closed R10 verifier."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from verify_release_evidence import (
    R10_REQUIRED_GATES,
    ga_requirement_findings,
    gate_findings,
    module_findings,
    restore_findings,
)


def modules() -> list[dict]:
    return [
        {
            "requirement_id": f"REQ-F{index:02d}",
            "kind": "functional_module",
            "status": "implemented",
            "test_ids": [f"CT-F{index:02d}-001"],
        }
        for index in range(1, 19)
    ]


def main() -> int:
    passed = {gate: "passed" for gate in R10_REQUIRED_GATES}
    assert not gate_findings(passed, "r10-local")
    for state in ("failed", "not_run"):
        mutated = dict(passed)
        mutated["tests"] = state
        assert gate_findings(mutated, "r10-local")
    missing = dict(passed)
    missing.pop("postgres")
    assert gate_findings(missing, "r10-local")
    extra = dict(passed)
    extra["invented_gate"] = "passed"
    assert gate_findings(extra, "r10-local")

    valid_modules = modules()
    projected = sorted(item["requirement_id"] for item in valid_modules)
    assert not module_findings(valid_modules, projected)
    assert module_findings(valid_modules[:-1], projected[:-1])
    planned = modules()
    planned[0]["status"] = "planned"
    assert module_findings(planned, projected)

    ga = modules()
    for item in ga:
        item["release_gate"] = "ga"
        item["status"] = "verified"
    assert not ga_requirement_findings(ga)
    ga[0]["status"] = "implemented"
    assert ga_requirement_findings(ga)

    now = datetime(2026, 8, 24, tzinfo=UTC)
    restore = {
        "outcome": "passed",
        "source_snapshot": {"rows": 1},
        "restored_snapshot": {"rows": 1},
        "backup_manifest_sha256": "a" * 64,
        "completed_at": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
    }
    assert not restore_findings(restore, "a" * 64, now)
    stale = dict(restore)
    stale["completed_at"] = (now - timedelta(days=46)).isoformat().replace("+00:00", "Z")
    assert restore_findings(stale, "a" * 64, now)
    assert restore_findings(restore, "b" * 64, now)
    print("R10 verifier negative policy tests: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
