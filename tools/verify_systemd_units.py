#!/usr/bin/env python3
"""Static, dependency-free verification for packaged systemd artifacts."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
UNITS = ROOT / "deploy" / "systemd"


def main() -> int:
    findings: list[str] = []
    service = (UNITS / "super-gateway.service").read_text(encoding="utf-8")
    migrate = (UNITS / "super-gateway-migrate.service").read_text(encoding="utf-8")
    upgrade = (UNITS / "super-gateway-upgrade.sh").read_text(encoding="utf-8")
    required_service = {
        "KillSignal=SIGTERM",
        "TimeoutStopSec=330s",
        "Restart=on-failure",
        "UMask=0077",
        "LimitNOFILE=262144",
        "LimitCORE=0",
        "ProtectSystem=strict",
        "NoNewPrivileges=true",
    }
    for value in sorted(required_service):
        if value not in service:
            findings.append(f"service missing {value}")
    if "Type=oneshot" not in migrate or "super-gatewayd migrate" not in migrate:
        findings.append("migration oneshot contract is incomplete")
    if "User=super-gateway-migrate" not in migrate or "EnvironmentFile=/etc/super-gateway/migrate.env" not in migrate:
        findings.append("migration identity/credential isolation is incomplete")
    if "User=super-gateway\n" not in service or "EnvironmentFile=/etc/super-gateway/runtime.env" not in service:
        findings.append("runtime identity/credential isolation is incomplete")
    for value in (
        "verify_release_evidence.py",
        "verify_migration_compatibility.py",
        'candidate_evidence="${candidate_dir}"',
        "--check-config",
        "check-schema",
        " migrate",
        "systemctl stop",
        "mv -Tf",
    ):
        if value not in upgrade:
            findings.append(f"upgrade script missing {value.strip()}")
    for value in ("runtime.env", "migrate.env", "rollback_deadline", "exit 2"):
        if value not in upgrade:
            findings.append(f"upgrade script missing {value}")
    if findings:
        for finding in findings:
            print(f"[systemd] {finding}", file=sys.stderr)
        return 1
    print("systemd/upgrade artifacts: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
