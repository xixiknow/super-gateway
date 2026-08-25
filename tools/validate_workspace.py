#!/usr/bin/env python3
"""Validate the R1 Rust workspace, dependency boundaries and secret hygiene."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PACKAGES = {
    "gateway-domain",
    "gateway-policy",
    "gateway-scheduler",
    "gateway-transport",
    "gateway-storage",
    "gateway-services",
    "gateway-api",
    "gateway-testkit",
    "super-gatewayd",
}
DOMAIN_FORBIDDEN_DEPENDENCIES = {
    "anyhow",
    "axum",
    "boring",
    "postgres",
    "reqwest",
    "sqlx",
    "tokio",
    "tracing",
}
PRODUCTION_PACKAGES = EXPECTED_PACKAGES - {"gateway-testkit"}
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Anthropic key": re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}"),
    "OAuth bearer": re.compile(r"(?i)bearer\s+[A-Za-z0-9._~-]{32,}"),
}


@dataclass(frozen=True)
class Finding:
    location: str
    message: str


class WorkspaceValidator:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.checks = 0

    def check(self, condition: bool, location: str, message: str) -> None:
        self.checks += 1
        if not condition:
            self.findings.append(Finding(location, message))

    def load_metadata(self) -> dict:
        process = subprocess.run(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.check(process.returncode == 0, "cargo metadata", process.stderr.strip() or "command failed")
        if process.returncode != 0:
            return {"packages": [], "workspace_members": []}
        try:
            return json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            self.check(False, "cargo metadata", f"invalid JSON: {exc}")
            return {"packages": [], "workspace_members": []}

    def validate_metadata(self, metadata: dict) -> None:
        members = set(metadata.get("workspace_members", []))
        packages = [package for package in metadata.get("packages", []) if package.get("id") in members]
        names = {package["name"] for package in packages}
        self.check(names == EXPECTED_PACKAGES, "Cargo.toml/workspace.members", "canonical package set drifted")
        binaries = [
            (package["name"], target["name"])
            for package in packages
            for target in package.get("targets", [])
            if "bin" in target.get("kind", [])
        ]
        self.check(binaries == [("super-gatewayd", "super-gatewayd")], "Cargo.toml/targets", "binary target set drifted")
        package_by_name = {package["name"]: package for package in packages}
        domain_dependencies = {item["name"] for item in package_by_name.get("gateway-domain", {}).get("dependencies", [])}
        self.check(
            not (domain_dependencies & DOMAIN_FORBIDDEN_DEPENDENCIES),
            "gateway-domain/dependencies",
            "pure domain crate depends on an adapter/runtime crate",
        )
        for package in packages:
            manifest = Path(package["manifest_path"]).resolve()
            self.check(ROOT.resolve() in manifest.parents, package["name"], "workspace manifest is outside the repository")
            self.check("transport-poc" not in manifest.parts, package["name"], "transport POC entered the production workspace")
            for dependency in package.get("dependencies", []):
                dep_path = dependency.get("path")
                if dep_path:
                    resolved = Path(dep_path).resolve()
                    self.check("transport-poc" not in resolved.parts, package["name"], "production crate has a path dependency on the POC")
                if dependency["name"] == "gateway-testkit" and package["name"] in PRODUCTION_PACKAGES:
                    self.check(
                        dependency.get("kind") == "dev",
                        package["name"],
                        "gateway-testkit is linked into a production dependency set",
                    )

    def validate_toolchain(self) -> None:
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
        workspace_package = cargo["workspace"]["package"]
        self.check(workspace_package["edition"] == "2024", "Cargo.toml/workspace.package.edition", "edition drifted")
        self.check(workspace_package["rust-version"] == "1.94", "Cargo.toml/workspace.package.rust-version", "MSRV drifted")
        self.check(toolchain["toolchain"]["channel"] == "1.95.0", "rust-toolchain.toml", "pinned toolchain drifted")
        self.check((ROOT / "Cargo.lock").is_file(), "Cargo.lock", "release lockfile is missing")
        excludes = set(cargo["workspace"].get("exclude", []))
        self.check(
            {"transport-poc", "open-project", "claude-code-decompiler"}.issubset(excludes),
            "Cargo.toml/workspace.exclude",
            "research workspaces are not explicitly excluded",
        )

    def validate_runtime_contract(self) -> None:
        fixture = json.loads((ROOT / "contracts" / "fixtures" / "runtime-config.valid.json").read_text(encoding="utf-8"))
        contracted = {item["name"] for item in fixture["variables"]}
        source = (ROOT / "crates" / "super-gatewayd" / "src" / "config.rs").read_text(encoding="utf-8")
        implemented = set(re.findall(r'const\s+[A-Z0-9_]+:\s*&str\s*=\s*"(GATEWAY_[A-Z0-9_]+)";', source))
        self.check(implemented == contracted, "runtime-config.valid.json", "runtime configuration source and contract drifted")

    def validate_migrations(self) -> None:
        migration_dir = ROOT / "crates" / "gateway-storage" / "migrations"
        self.check(migration_dir.is_dir(), str(migration_dir.relative_to(ROOT)), "migration directory is missing")
        migration_pattern = re.compile(r"^[0-9]{14}_[a-z0-9_]+\.sql$")
        for path in sorted(migration_dir.glob("*.sql")):
            self.check(bool(migration_pattern.fullmatch(path.name)), str(path.relative_to(ROOT)), "migration name is not deterministic")

    def validate_secret_hygiene(self) -> None:
        candidates = [ROOT / ".env.example", ROOT / "Cargo.toml", ROOT / "rust-toolchain.toml"]
        for base in [ROOT / "crates", ROOT / ".github"]:
            if base.exists():
                candidates.extend(path for path in base.rglob("*") if path.suffix in {".rs", ".toml", ".yml", ".yaml"})
        for path in candidates:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for label, pattern in SECRET_PATTERNS.items():
                self.check(pattern.search(text) is None, str(path.relative_to(ROOT)), f"possible {label} material is checked in")
        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.check("REPLACE_AT_DEPLOYMENT" in example, ".env.example", "bootstrap password must remain an explicit placeholder")

    def run(self) -> int:
        metadata = self.load_metadata()
        self.validate_metadata(metadata)
        self.validate_toolchain()
        self.validate_runtime_contract()
        self.validate_migrations()
        self.validate_secret_hygiene()
        if self.findings:
            print(f"Workspace validation FAILED: {len(self.findings)} finding(s), {self.checks} checks")
            for finding in self.findings:
                print(f"- {finding.location}: {finding.message}")
            return 1
        print(f"Workspace validation PASSED: {len(EXPECTED_PACKAGES)} packages, {self.checks} checks")
        return 0


if __name__ == "__main__":
    sys.exit(WorkspaceValidator().run())
