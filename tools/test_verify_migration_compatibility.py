#!/usr/bin/env python3
"""Dependency-free unit coverage for migration compatibility preflight."""

from __future__ import annotations

from copy import deepcopy

from verify_migration_compatibility import verify


def manifest(migrations: dict[str, str]) -> dict[str, object]:
    versions = sorted(int(name[:14]) for name in migrations)
    return {
        "application": "super-gatewayd",
        "target": "x86_64-unknown-linux-gnu",
        "runtime_abi_version": "r2-v1",
        "schema_compatibility": {"minimum": versions[0], "maximum": versions[-1]},
        "migration_checksums": migrations,
    }


def must_fail(current: dict[str, object], candidate: dict[str, object]) -> None:
    try:
        verify(current, candidate)
    except ValueError:
        return
    raise AssertionError("compatibility verification unexpectedly passed")


def main() -> int:
    first = "1" * 64
    second = "2" * 64
    current = manifest({"20260824000100_foundation.sql": first})
    candidate = manifest(
        {
            "20260824000100_foundation.sql": first,
            "20260824000200_expand.sql": second,
        }
    )
    report = verify(current, candidate)
    assert report["new_migration_count"] == 1

    rewritten = deepcopy(candidate)
    rewritten_checksums = rewritten["migration_checksums"]
    assert isinstance(rewritten_checksums, dict)
    rewritten_checksums["20260824000100_foundation.sql"] = "f" * 64
    must_fail(current, rewritten)

    shortened = manifest({"20260824000100_foundation.sql": first})
    must_fail(candidate, shortened)

    wrong_target = deepcopy(candidate)
    wrong_target["target"] = "aarch64-unknown-linux-gnu"
    must_fail(current, wrong_target)

    wrong_range = deepcopy(candidate)
    compatibility = wrong_range["schema_compatibility"]
    assert isinstance(compatibility, dict)
    compatibility["maximum"] = 20260824000999
    must_fail(current, wrong_range)
    print("migration compatibility policy tests: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
