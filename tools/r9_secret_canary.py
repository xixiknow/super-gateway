#!/usr/bin/env python3
"""Scan generated sink artifacts for synthetic secret canaries."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--canary", action="append", default=[])
    parser.add_argument("--canary-file", action="append", type=Path, default=[])
    parser.add_argument("--path", action="append", type=Path, required=True)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    canaries = [value.encode() for value in args.canary if value]
    for path in args.canary_file:
        value = path.read_bytes().strip()
        if value:
            canaries.append(value)
    if not canaries:
        print("at least one non-empty canary is required", file=sys.stderr)
        return 2
    files: list[Path] = []
    for root in args.path:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(path for path in root.rglob("*") if path.is_file())
    findings = []
    for path in sorted(set(files)):
        data = path.read_bytes()
        for index, canary in enumerate(canaries, start=1):
            if canary in data:
                findings.append({"path": str(path), "canary_index": index})
    report = {
        "schema_version": "1.0.0",
        "scanned_files": len(set(files)),
        "canary_count": len(canaries),
        "plaintext_findings": findings,
        "status": "passed" if not findings else "failed",
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
