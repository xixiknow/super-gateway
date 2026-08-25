#!/usr/bin/env python3
"""Validate OpenAPI, JSON Schema, fixtures and source traceability without third-party packages."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
JSON_FILES = sorted(CONTRACTS.rglob("*.json"))


@dataclass
class Finding:
    location: str
    message: str


class ContractValidator:
    def __init__(self) -> None:
        self.documents: dict[Path, Any] = {}
        self.findings: list[Finding] = []
        self.check_count = 0

    def fail(self, location: str, message: str) -> None:
        self.findings.append(Finding(location, message))

    def check(self, condition: bool, location: str, message: str) -> None:
        self.check_count += 1
        if not condition:
            self.fail(location, message)

    def load_documents(self) -> None:
        self.check(bool(JSON_FILES), "contracts", "no JSON contract files found")
        for path in JSON_FILES:
            try:
                self.documents[path.resolve()] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                self.fail(str(path), f"JSON parse failed: {exc}")

    @staticmethod
    def pointer(document: Any, fragment: str) -> Any:
        if fragment in {"", "#"}:
            return document
        pointer = fragment.removeprefix("#")
        current = document
        for raw in pointer.split("/")[1:]:
            key = raw.replace("~1", "/").replace("~0", "~")
            current = current[int(key)] if isinstance(current, list) else current[key]
        return current

    def resolve_ref(self, current_path: Path, ref: str) -> tuple[Path, Any]:
        file_part, separator, fragment = ref.partition("#")
        target_path = current_path if not file_part else (current_path.parent / file_part).resolve()
        if target_path not in self.documents:
            raise KeyError(f"referenced file not loaded: {target_path}")
        return target_path, self.pointer(self.documents[target_path], f"#{fragment}" if separator else "")

    def walk_refs(self) -> None:
        def visit(value: Any, current_path: Path, location: str) -> None:
            if isinstance(value, dict):
                ref = value.get("$ref")
                if isinstance(ref, str):
                    if ref.startswith("http://") or ref.startswith("https://"):
                        if not ref.startswith("https://super-gateway.local/"):
                            return
                    else:
                        try:
                            self.resolve_ref(current_path, ref)
                        except (KeyError, IndexError, TypeError) as exc:
                            self.fail(location, f"unresolved $ref {ref}: {exc}")
                for key, child in value.items():
                    visit(child, current_path, f"{location}/{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, current_path, f"{location}/{index}")

        for path, document in self.documents.items():
            visit(document, path, str(path.relative_to(ROOT)))

    @staticmethod
    def type_matches(instance: Any, expected: str) -> bool:
        if expected == "null":
            return instance is None
        if expected == "object":
            return isinstance(instance, dict)
        if expected == "array":
            return isinstance(instance, list)
        if expected == "string":
            return isinstance(instance, str)
        if expected == "boolean":
            return isinstance(instance, bool)
        if expected == "integer":
            return isinstance(instance, int) and not isinstance(instance, bool)
        if expected == "number":
            return isinstance(instance, (int, float)) and not isinstance(instance, bool)
        return True

    def validate_instance(self, instance: Any, schema: Any, schema_path: Path, location: str) -> list[str]:
        errors: list[str] = []
        if isinstance(schema, bool):
            return [] if schema else [f"{location}: rejected by false schema"]
        if not isinstance(schema, dict):
            return [f"{location}: schema is not an object"]
        if "$ref" in schema:
            target_path, target = self.resolve_ref(schema_path, schema["$ref"])
            errors.extend(self.validate_instance(instance, target, target_path, location))
            if errors:
                return errors
        if "allOf" in schema:
            for child in schema["allOf"]:
                errors.extend(self.validate_instance(instance, child, schema_path, location))
        if "anyOf" in schema:
            branches = [self.validate_instance(instance, child, schema_path, location) for child in schema["anyOf"]]
            if not any(not branch for branch in branches):
                errors.append(f"{location}: no anyOf branch matched")
                return errors
        if "oneOf" in schema:
            branches = [self.validate_instance(instance, child, schema_path, location) for child in schema["oneOf"]]
            if sum(1 for branch in branches if not branch) != 1:
                errors.append(f"{location}: expected exactly one oneOf match")
                return errors
        if "const" in schema and instance != schema["const"]:
            errors.append(f"{location}: expected const {schema['const']!r}")
        if "enum" in schema and instance not in schema["enum"]:
            errors.append(f"{location}: {instance!r} is outside enum")
        expected_type = schema.get("type")
        if expected_type:
            types = expected_type if isinstance(expected_type, list) else [expected_type]
            if not any(self.type_matches(instance, item) for item in types):
                errors.append(f"{location}: expected type {types}, got {type(instance).__name__}")
                return errors
        if isinstance(instance, dict):
            required = schema.get("required", [])
            for key in required:
                if key not in instance:
                    errors.append(f"{location}: missing required property {key}")
            properties = schema.get("properties", {})
            for key, value in instance.items():
                if key in properties:
                    errors.extend(self.validate_instance(value, properties[key], schema_path, f"{location}/{key}"))
                elif schema.get("additionalProperties") is False:
                    errors.append(f"{location}: unexpected property {key}")
                elif isinstance(schema.get("additionalProperties"), dict):
                    errors.extend(self.validate_instance(value, schema["additionalProperties"], schema_path, f"{location}/{key}"))
        if isinstance(instance, list):
            if len(instance) < schema.get("minItems", 0):
                errors.append(f"{location}: fewer than minItems")
            if "maxItems" in schema and len(instance) > schema["maxItems"]:
                errors.append(f"{location}: more than maxItems")
            if schema.get("uniqueItems"):
                canonical = [json.dumps(item, sort_keys=True, ensure_ascii=False) for item in instance]
                if len(canonical) != len(set(canonical)):
                    errors.append(f"{location}: items are not unique")
            if "items" in schema:
                for index, value in enumerate(instance):
                    errors.extend(self.validate_instance(value, schema["items"], schema_path, f"{location}/{index}"))
        if isinstance(instance, str):
            if len(instance) < schema.get("minLength", 0):
                errors.append(f"{location}: shorter than minLength")
            if "maxLength" in schema and len(instance) > schema["maxLength"]:
                errors.append(f"{location}: longer than maxLength")
            if "pattern" in schema and re.search(schema["pattern"], instance) is None:
                errors.append(f"{location}: does not match pattern {schema['pattern']}")
        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if "minimum" in schema and instance < schema["minimum"]:
                errors.append(f"{location}: below minimum")
            if "maximum" in schema and instance > schema["maximum"]:
                errors.append(f"{location}: above maximum")
        return errors

    def validate_fixtures(self) -> None:
        trace_path = (CONTRACTS / "schemas" / "trace-event.schema.json").resolve()
        trace_schema = self.documents[trace_path]
        events_path = (CONTRACTS / "fixtures" / "trace-events.valid.json").resolve()
        for index, event in enumerate(self.documents[events_path]):
            errors = self.validate_instance(event, trace_schema, trace_path, f"trace-events[{index}]")
            for error in errors:
                self.fail(str(events_path.relative_to(ROOT)), error)
        bundle_schema_path = (CONTRACTS / "schemas" / "transport-bundle-manifest.schema.json").resolve()
        bundle_fixture_path = (CONTRACTS / "fixtures" / "transport-bundle.valid.json").resolve()
        for error in self.validate_instance(
            self.documents[bundle_fixture_path], self.documents[bundle_schema_path], bundle_schema_path, "transport-bundle"
        ):
            self.fail(str(bundle_fixture_path.relative_to(ROOT)), error)
        trust_schema_path = (CONTRACTS / "schemas" / "bundle-trust-store.schema.json").resolve()
        trust_fixture_path = (CONTRACTS / "fixtures" / "bundle-trust-store.valid.json").resolve()
        for error in self.validate_instance(
            self.documents[trust_fixture_path], self.documents[trust_schema_path], trust_schema_path, "bundle-trust-store"
        ):
            self.fail(str(trust_fixture_path.relative_to(ROOT)), error)
        ledger_schema_path = (CONTRACTS / "schemas" / "requirement-trace-ledger.schema.json").resolve()
        ledger_path = (CONTRACTS / "traceability" / "requirements.json").resolve()
        for error in self.validate_instance(
            self.documents[ledger_path], self.documents[ledger_schema_path], ledger_schema_path, "requirements"
        ):
            self.fail(str(ledger_path.relative_to(ROOT)), error)
        runtime_schema_path = (CONTRACTS / "schemas" / "runtime-config.schema.json").resolve()
        runtime_fixture_path = (CONTRACTS / "fixtures" / "runtime-config.valid.json").resolve()
        for error in self.validate_instance(
            self.documents[runtime_fixture_path], self.documents[runtime_schema_path], runtime_schema_path, "runtime-config"
        ):
            self.fail(str(runtime_fixture_path.relative_to(ROOT)), error)
        evidence_schema_path = (CONTRACTS / "schemas" / "release-evidence.schema.json").resolve()
        evidence_schema = self.documents[evidence_schema_path]
        for fixture_name, definition in [
            ("fixture-manifest.valid.json", "FixtureManifest"),
            ("release-manifest.valid.json", "ReleaseManifest"),
            ("provenance.valid.json", "BuildProvenance"),
            ("evidence-manifest.valid.json", "EvidenceManifest"),
        ]:
            fixture_path = (CONTRACTS / "fixtures" / fixture_name).resolve()
            for error in self.validate_instance(
                self.documents[fixture_path], evidence_schema["$defs"][definition], evidence_schema_path, fixture_name
            ):
                self.fail(str(fixture_path.relative_to(ROOT)), error)

    def validate_enum_registry(self) -> None:
        registry = self.documents[(CONTRACTS / "registries" / "enums.json").resolve()]["enums"]

        def visit(value: Any, location: str) -> None:
            if isinstance(value, dict):
                registry_name = value.get("x-enum-registry")
                if registry_name:
                    self.check(registry_name in registry, location, f"unknown enum registry {registry_name}")
                    if registry_name in registry:
                        self.check(value.get("enum") == registry[registry_name], location, f"enum {registry_name} drifted")
                for key, child in value.items():
                    visit(child, f"{location}/{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, f"{location}/{index}")

        for path, document in self.documents.items():
            visit(document, str(path.relative_to(ROOT)))

    def validate_openapi(self) -> None:
        data_path = (CONTRACTS / "openapi" / "data-plane.openapi.json").resolve()
        admin_path = (CONTRACTS / "openapi" / "admin.openapi.json").resolve()
        data = self.documents[data_path]
        admin = self.documents[admin_path]
        expected_data_paths = {"/v1/messages", "/v1/models", "/healthz", "/readyz"}
        self.check(data.get("openapi", "").startswith("3.1."), "data-plane.openapi", "OpenAPI must be 3.1")
        self.check(set(data.get("paths", {})) == expected_data_paths, "data-plane.openapi/paths", "public path set drifted")
        self.check(set(data["paths"]["/v1/messages"]) == {"post"}, "data-plane.openapi/v1/messages", "Messages method set drifted")
        self.check(set(data["paths"]["/v1/models"]) == {"get"}, "data-plane.openapi/v1/models", "Models method set drifted")
        policy = data.get("x-public-route-policy", {})
        self.check(policy.get("count_tokens_public") is False, "data-plane.openapi/x-public-route-policy", "Count Tokens must remain internal")
        self.check(policy.get("websocket") is False, "data-plane.openapi/x-public-route-policy", "WebSocket is outside the public contract")
        self.check(policy.get("providers") == ["anthropic_official"], "data-plane.openapi/x-public-route-policy", "upstream provider set drifted")
        response_200 = data["paths"]["/v1/messages"]["post"]["responses"]["200"]["content"]
        self.check(response_200["application/json"].get("x-opaque-passthrough") is True, "data-plane.openapi/v1/messages", "JSON passthrough marker missing")
        self.check(response_200["text/event-stream"].get("x-opaque-passthrough") is True, "data-plane.openapi/v1/messages", "SSE passthrough marker missing")
        common = self.documents[(CONTRACTS / "schemas" / "common.schema.json").resolve()]
        public_ready = common["$defs"]["PublicReadiness"]
        self.check(set(public_ready["properties"]) == {"status"}, "common.schema/PublicReadiness", "public readiness must expose only status")
        ready_200_ref = data["paths"]["/readyz"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        ready_503_ref = data["paths"]["/readyz"]["get"]["responses"]["503"]["content"]["application/json"]["schema"]["$ref"]
        self.check(ready_200_ref.endswith("#/$defs/PublicReadiness"), "data-plane.openapi/readyz/200", "public ready response uses an internal schema")
        self.check(ready_503_ref.endswith("#/$defs/PublicReadiness"), "data-plane.openapi/readyz/503", "public not-ready response uses an internal schema")
        for path, expected_statuses in [("/healthz", {"200", "429"}), ("/readyz", {"200", "429", "503"})]:
            responses = data["paths"][path]["get"]["responses"]
            self.check(set(responses) == expected_statuses, f"data-plane.openapi{path}", "probe response set drifted")
            for status, response in responses.items():
                headers = response.get("headers", {})
                source = headers.get("x-gateway-response-source", {}).get("schema", {})
                self.check(source.get("const") == "gateway", f"data-plane.openapi{path}/{status}", "probe source header missing")
            rate_limited = responses["429"]
            rate_ref = rate_limited["content"]["application/json"]["schema"]["$ref"]
            self.check(rate_ref.endswith("#/$defs/PublicProbeRateLimited"), f"data-plane.openapi{path}/429", "probe 429 schema drifted")
            retry = rate_limited["headers"].get("retry-after", {}).get("schema", {})
            self.check(retry.get("minimum") == 1, f"data-plane.openapi{path}/429", "probe Retry-After contract drifted")
        self.check(admin.get("openapi", "").startswith("3.1."), "admin.openapi", "OpenAPI must be 3.1")
        operation_ids: list[str] = []
        actual_routes: set[tuple[str, str]] = set()
        for path, path_item in admin.get("paths", {}).items():
            self.check(path.startswith("/admin/v1/"), f"admin.openapi{path}", "admin path prefix drifted")
            for method, operation in path_item.items():
                if method not in {"get", "post", "patch", "put", "delete"}:
                    continue
                actual_routes.add((path, method))
                operation_ids.append(operation.get("operationId", ""))
                param_refs = {p.get("$ref") for p in operation.get("parameters", []) if isinstance(p, dict)}
                if method not in {"get", "head"}:
                    self.check("#/components/parameters/CsrfToken" in param_refs, f"admin.openapi{path}:{method}", "CSRF parameter missing")
                if path != "/admin/v1/content-audit/records/{id}:export" and "{" in path and (
                    method in {"patch", "delete"} or (method == "post" and ":" in path)
                ):
                    self.check("#/components/parameters/IfMatch" in param_refs, f"admin.openapi{path}:{method}", "If-Match parameter missing")
                if method == "post" and not any(token in path for token in ["/auth/login", "/auth/mfa/", "/auth/step-up", ":validate", ":simulate", "/content-audit/search-sessions"]):
                    self.check("#/components/parameters/IdempotencyKey" in param_refs, f"admin.openapi{path}:{method}", "Idempotency-Key parameter missing")
        self.check(len(operation_ids) == len(set(operation_ids)), "admin.openapi/operationIds", "operationId collision")
        self.check(all(operation_ids), "admin.openapi/operationIds", "empty operationId")
        route_registry = self.documents[(CONTRACTS / "registries" / "admin-routes.json").resolve()]["routes"]
        expected_routes = {(item["path"], item["method"]) for item in route_registry}
        self.check(actual_routes == expected_routes, "admin.openapi/paths", "OpenAPI routes differ from the extracted route registry")
        self.check(admin.get("x-route-count") == len(expected_routes) == 196, "admin.openapi/x-route-count", "admin operation count drifted")

    def validate_source_traceability(self) -> None:
        ledger = self.documents[(CONTRACTS / "traceability" / "requirements.json").resolve()]
        requirements = ledger["requirements"]
        ids = [item["requirement_id"] for item in requirements]
        self.check(len(ids) == len(set(ids)), "requirements.json", "duplicate requirement_id")
        self.check({f"REQ-F{i:02d}" for i in range(1, 19)}.issubset(ids), "requirements.json", "18 functional modules are incomplete")
        self.check({f"DEC-{i:03d}" for i in range(1, 133)}.issubset(ids), "requirements.json", "DEC-001..DEC-132 are incomplete")
        self.check({f"REQ-R1-{i:03d}" for i in range(1, 7)}.issubset(ids), "requirements.json", "R1 foundation requirements are incomplete")
        self.check({f"REQ-R2-{i:03d}" for i in range(1, 19)}.issubset(ids), "requirements.json", "R2 foundation requirements are incomplete")
        self.check({f"REQ-R3-{i:03d}" for i in range(1, 13)}.issubset(ids), "requirements.json", "R3 edge/policy requirements are incomplete")
        self.check({f"REQ-R4-{i:03d}" for i in range(1, 21)}.issubset(ids), "requirements.json", "R4 scheduler requirements are incomplete")
        self.check({f"REQ-R5-{i:03d}" for i in range(1, 19)}.issubset(ids), "requirements.json", "R5 credential requirements are incomplete")
        test_ids = {item["test_id"] for item in ledger["tests"]}
        r3_fixture_ids = {
            item["fixture_id"]
            for item in self.documents[(CONTRACTS / "fixtures" / "r3-fixture-manifests.valid.json").resolve()]
        }
        r4_fixture_ids = {
            item["fixture_id"]
            for item in self.documents[(CONTRACTS / "fixtures" / "r4-fixture-manifests.valid.json").resolve()]
        }
        r5_fixture_ids = {
            item["fixture_id"]
            for item in self.documents[(CONTRACTS / "fixtures" / "r5-fixture-manifests.valid.json").resolve()]
        }
        for item in requirements:
            source = item["source"]
            path = ROOT / source["file"]
            self.check(path.exists(), item["requirement_id"], f"source file missing: {source['file']}")
            if not path.exists():
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
            self.check(source["line"] <= len(lines), item["requirement_id"], "source line is outside file")
            if source["line"] <= len(lines):
                actual_hash = hashlib.sha256(lines[source["line"] - 1].encode("utf-8")).hexdigest()
                self.check(actual_hash == source["text_sha256"], item["requirement_id"], "source text hash drifted; regenerate contracts")
            self.check(bool(item["owner"]), item["requirement_id"], "owner missing")
            self.check(bool(item["phase"]), item["requirement_id"], "phase missing")
            self.check(bool(item["test_ids"]), item["requirement_id"], "test_ids missing")
            self.check(set(item["test_ids"]).issubset(test_ids), item["requirement_id"], "referenced test is missing")
            if item["phase"] == "R3":
                self.check(
                    set(item["fixture_ids"]).issubset(r3_fixture_ids),
                    item["requirement_id"],
                    "referenced R3 fixture manifest is missing",
                )
            if item["phase"] == "R4":
                self.check(
                    set(item["fixture_ids"]).issubset(r4_fixture_ids),
                    item["requirement_id"],
                    "referenced R4 fixture manifest is missing",
                )
            if item["phase"] == "R5":
                self.check(
                    set(item["fixture_ids"]).issubset(r5_fixture_ids),
                    item["requirement_id"],
                    "referenced R5 fixture manifest is missing",
                )

    def validate_domain_invariants(self) -> None:
        registry = self.documents[(CONTRACTS / "registries" / "enums.json").resolve()]["enums"]
        self.check(registry["credential_lifecycle"][:4] == ["pending_verify", "pending_profile", "pending_egress", "pending_reauth_strategy"], "enum:credential_lifecycle", "pending lifecycle codes drifted")
        self.check("archived" in registry["proxy_lifecycle"], "enum:proxy_lifecycle", "Proxy archived state missing")
        self.check(registry["proxy_type"] == ["http_connect", "socks5"], "enum:proxy_type", "Proxy type names drifted")
        self.check(registry["usage_source"] == ["official", "local_estimate", "console_count", "cancel_estimate"], "enum:usage_source", "Usage source drifted")
        self.check(registry["usage_completeness"] == ["complete", "partial", "unknown"], "enum:usage_completeness", "Usage completeness drifted")
        self.check(
            registry["credential_purpose"] == ["business", "verification_only", "count_tokens"],
            "enum:credential_purpose",
            "Credential purpose contract drifted",
        )
        self.check(
            registry["credential_management_class"]
            == ["fully_managed", "non_managed", "pending_reauth_strategy", "manual_recovery_required"],
            "enum:credential_management_class",
            "Credential management projection drifted",
        )
        credential_schema = self.documents[(CONTRACTS / "schemas" / "credential.schema.json").resolve()]
        self.check(
            credential_schema["$defs"]["AutoReauthStrategy"]["properties"]["state"]["enum"]
            == ["pending", "healthy", "degraded", "invalid", "disabled"],
            "credential.schema/AutoReauthStrategy",
            "managed Browser strategy state drifted",
        )
        session = self.documents[(CONTRACTS / "schemas" / "session.schema.json").resolve()]
        derivation = session["$defs"]["SessionDerivationInput"]
        self.check("agent_id" not in derivation["properties"], "session.schema/SessionDerivationInput", "AgentId must stay outside upstream Session derivation")
        bundle = self.documents[(CONTRACTS / "fixtures" / "transport-bundle.valid.json").resolve()]
        payload = bundle["payload"]
        pool_fields = payload["application"]["connection"]["pool_key_fields"]
        expected_pool = {
            "credential_id", "profile_epoch", "bundle_id", "bundle_version", "egress_binding_id",
            "egress_epoch", "authority", "sni", "protocol",
        }
        self.check(len(pool_fields) == 9 and set(pool_fields) == expected_pool, "transport-bundle.fixture/pool_key_fields", "complete isolation pool key drifted")
        self.check(payload["application"]["tls"]["session_resumption"] is False, "transport-bundle.fixture/session_resumption", "R0 fixture must default resumption off")
        self.check(payload["application"]["protocol"] == "h1" and "http2" not in payload["application"], "transport-bundle.fixture/protocol_union", "Windows verified fixture must remain H1-only")
        self.check("controlled_http2" not in payload["required_capabilities"], "transport-bundle.fixture/h2_evidence", "schema fixture must not claim unverified H2 evidence")
        self.check("canonical_hash" not in payload, "transport-bundle.fixture/hash_preimage", "canonical hash must stay outside its payload preimage")
        trust = self.documents[(CONTRACTS / "fixtures" / "bundle-trust-store.valid.json").resolve()]
        key_ids = [key["key_id"] for key in trust["keys"]]
        self.check(len(key_ids) == len(set(key_ids)), "bundle-trust-store.fixture/key_ids", "TrustStore key IDs must be unique")
        self.check(sum(key["status"] == "current" for key in trust["keys"]) == 1, "bundle-trust-store.fixture/current", "TrustStore must have exactly one current Bundle key")
        functional_text = (ROOT / "planning" / "functional-modules.md").read_text(encoding="utf-8")
        self.check("130. 生产实现必须采用 Linux Rust 单体" in functional_text, "planning/functional-modules.md", "Rust technology decision missing")
        self.check("132. TLS Session Resumption" in functional_text, "planning/functional-modules.md", "decision 132 missing")

    def validate_r1_foundation(self) -> None:
        runtime = self.documents[(CONTRACTS / "fixtures" / "runtime-config.valid.json").resolve()]
        variables = {item["name"]: item for item in runtime["variables"]}
        expected = {
            "GATEWAY_DATA_BIND", "GATEWAY_ADMIN_BIND", "GATEWAY_DATABASE_URL_FILE", "GATEWAY_MIGRATOR_DATABASE_URL_FILE",
            "GATEWAY_BUSINESS_KEY_PROVIDER", "GATEWAY_KEY_PROVIDER_URI",
            "GATEWAY_APP_KEY_FILE", "GATEWAY_DIGEST_KEY_FILE", "GATEWAY_AUDIT_INTEGRITY_KEY_FILE", "GATEWAY_BUNDLE_TRUST_STORE",
            "GATEWAY_BUNDLE_DIR", "GATEWAY_RESPONSE_TMP_DIR", "GATEWAY_CONTENT_AUDIT_KEY_FILE",
            "GATEWAY_CONTENT_AUDIT_DIR", "GATEWAY_BACKUP_KEY_FILE", "GATEWAY_BACKUP_REPOSITORY",
            "GATEWAY_DRAIN_DEADLINE", "GATEWAY_BOOTSTRAP_ADMIN_USERNAME", "GATEWAY_BOOTSTRAP_ADMIN_PASSWORD",
            "GATEWAY_BOOTSTRAP_ADMIN_EMAIL", "GATEWAY_BOOTSTRAP_ADMIN_DISPLAY_NAME",
            "GATEWAY_EGRESS_OBSERVER_HOST", "GATEWAY_EGRESS_OBSERVER_PATH",
            "GATEWAY_MANAGED_BROWSER_TOOL", "GATEWAY_MANAGED_BROWSER_TIMEOUT",
        }
        self.check(set(variables) == expected, "runtime-config.valid.json", "runtime variable registry drifted")
        for name, item in variables.items():
            if item["secret"]:
                self.check(item["default"] is None, f"runtime-config/{name}", "secret configuration must not have a default")
            relationship = item["relationship"]
            related_to = item["related_to"]
            if relationship == "independent":
                self.check(related_to is None, f"runtime-config/{name}", "independent variable has a relationship target")
            elif relationship == "conditional":
                target = related_to.split("=", 1)[0] if isinstance(related_to, str) else ""
                self.check(target in variables, f"runtime-config/{name}", "conditional selector is missing")
            else:
                self.check(related_to in variables, f"runtime-config/{name}", "relationship target is missing")
                if related_to in variables:
                    peer = variables[related_to]
                    self.check(peer["related_to"] == name, f"runtime-config/{name}", "relationship is not reciprocal")
                    self.check(peer["relationship"] == relationship, f"runtime-config/{name}", "relationship kind differs from peer")
        self.check(
            variables["GATEWAY_DRAIN_DEADLINE"]["default"] == "300s",
            "runtime-config/GATEWAY_DRAIN_DEADLINE",
            "drain default drifted",
        )
        workspace_text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.check('"crates/gateway-testkit"' in workspace_text, "Cargo.toml", "gateway-testkit workspace member missing")
        self.check('"crates/super-gatewayd"' in workspace_text, "Cargo.toml", "composition root workspace member missing")

    def validate_r2_foundation(self) -> None:
        fixtures = [
            ("migration-manifest.valid.json", "migration-manifest.schema.json"),
            ("database-schema-manifest.valid.json", "database-schema-manifest.schema.json"),
            ("secret-envelope.valid.json", "secret-envelope.schema.json"),
            ("audit-integrity.valid.json", "audit-integrity.schema.json"),
            ("backup-restore-manifest.valid.json", "backup-restore-manifest.schema.json"),
            ("postgres-test-evidence.valid.json", "postgres-test-evidence.schema.json"),
        ]
        for fixture_name, schema_name in fixtures:
            fixture_path = (CONTRACTS / "fixtures" / fixture_name).resolve()
            schema_path = (CONTRACTS / "schemas" / schema_name).resolve()
            for error in self.validate_instance(
                self.documents[fixture_path], self.documents[schema_path], schema_path, fixture_name
            ):
                self.fail(str(fixture_path.relative_to(ROOT)), error)
        migration = self.documents[(CONTRACTS / "fixtures" / "migration-manifest.valid.json").resolve()]
        migration_dir = ROOT / "crates" / "gateway-storage" / "migrations"
        actual_files = sorted(migration_dir.glob("*.sql"))
        self.check(len(actual_files) == len(migration["migrations"]), "migration-manifest", "migration file count drifted")
        for item, path in zip(migration["migrations"], actual_files, strict=False):
            self.check(item["name"] == path.name, "migration-manifest", "migration ordering/name drifted")
            self.check(item["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest(), path.name, "published migration checksum drifted")
        database = self.documents[(CONTRACTS / "fixtures" / "database-schema-manifest.valid.json").resolve()]
        self.check(len(database["required_tables"]) == 116, "database-schema-manifest", "116-table baseline drifted")
        self.check(
            set(database["logical_schemas"]) == {"iam", "gateway", "catalog", "telemetry", "security", "ops"},
            "database-schema-manifest", "logical schema set drifted",
        )
        self.check(
            database["database_roles"] == ["gateway_migrator", "gateway_runtime", "gateway_readonly", "gateway_backup"],
            "database-schema-manifest", "database role contract drifted",
        )

    def validate_r3_foundation(self) -> None:
        evidence_schema_path = (CONTRACTS / "schemas" / "release-evidence.schema.json").resolve()
        evidence_schema = self.documents[evidence_schema_path]
        manifests_path = (CONTRACTS / "fixtures" / "r3-fixture-manifests.valid.json").resolve()
        corpus_path = (CONTRACTS / "fixtures" / "r3-corpus.valid.json").resolve()
        manifests = self.documents[manifests_path]
        corpus = self.documents[corpus_path]
        self.check(len(manifests) == len(corpus) == 12, "r3-fixtures", "R3 fixture set must contain 12 scenarios")
        corpus_by_id = {item["fixture_id"]: item for item in corpus}
        self.check(len(corpus_by_id) == len(corpus), "r3-corpus", "duplicate fixture_id")
        for manifest in manifests:
            fixture_id = manifest.get("fixture_id", "missing")
            for error in self.validate_instance(
                manifest,
                evidence_schema["$defs"]["FixtureManifest"],
                evidence_schema_path,
                fixture_id,
            ):
                self.fail(str(manifests_path.relative_to(ROOT)), error)
            item = corpus_by_id.get(fixture_id)
            self.check(item is not None, fixture_id, "corpus entry is missing")
            if item is None:
                continue
            content_hash = hashlib.sha256(
                json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            self.check(content_hash == manifest["content_sha256"], fixture_id, "fixture content hash drifted")
            self.check(manifest["privacy_scan"].endswith(":passed"), fixture_id, "fixture privacy scan is not passed")
            for source, expected_hash in item["source_sha256"].items():
                path = ROOT / source
                self.check(path.exists(), fixture_id, f"fixture source missing: {source}")
                if path.exists():
                    self.check(
                        hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash,
                        fixture_id,
                        f"fixture source hash drifted: {source}",
                    )

    def validate_r4_foundation(self) -> None:
        evidence_schema_path = (CONTRACTS / "schemas" / "release-evidence.schema.json").resolve()
        evidence_schema = self.documents[evidence_schema_path]
        manifests_path = (CONTRACTS / "fixtures" / "r4-fixture-manifests.valid.json").resolve()
        corpus_path = (CONTRACTS / "fixtures" / "r4-corpus.valid.json").resolve()
        manifests = self.documents[manifests_path]
        corpus = self.documents[corpus_path]
        self.check(len(manifests) == len(corpus) == 20, "r4-fixtures", "R4 fixture set must contain 20 scenarios")
        corpus_by_id = {item["fixture_id"]: item for item in corpus}
        self.check(len(corpus_by_id) == len(corpus), "r4-corpus", "duplicate fixture_id")
        for manifest in manifests:
            fixture_id = manifest.get("fixture_id", "missing")
            for error in self.validate_instance(
                manifest,
                evidence_schema["$defs"]["FixtureManifest"],
                evidence_schema_path,
                fixture_id,
            ):
                self.fail(str(manifests_path.relative_to(ROOT)), error)
            item = corpus_by_id.get(fixture_id)
            self.check(item is not None, fixture_id, "corpus entry is missing")
            if item is None:
                continue
            content_hash = hashlib.sha256(
                json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            self.check(content_hash == manifest["content_sha256"], fixture_id, "fixture content hash drifted")
            self.check(manifest["privacy_scan"].endswith(":passed"), fixture_id, "fixture privacy scan is not passed")
            for source, expected_hash in item["source_sha256"].items():
                path = ROOT / source
                self.check(path.exists(), fixture_id, f"fixture source missing: {source}")
                if path.exists():
                    self.check(
                        hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash,
                        fixture_id,
                        f"fixture source hash drifted: {source}",
                    )

    def validate_r5_foundation(self) -> None:
        evidence_schema_path = (CONTRACTS / "schemas" / "release-evidence.schema.json").resolve()
        evidence_schema = self.documents[evidence_schema_path]
        manifests_path = (CONTRACTS / "fixtures" / "r5-fixture-manifests.valid.json").resolve()
        corpus_path = (CONTRACTS / "fixtures" / "r5-corpus.valid.json").resolve()
        manifests = self.documents[manifests_path]
        corpus = self.documents[corpus_path]
        self.check(len(manifests) == len(corpus) == 18, "r5-fixtures", "R5 fixture set must contain 18 scenarios")
        corpus_by_id = {item["fixture_id"]: item for item in corpus}
        self.check(len(corpus_by_id) == len(corpus), "r5-corpus", "duplicate fixture_id")
        for manifest in manifests:
            fixture_id = manifest.get("fixture_id", "missing")
            for error in self.validate_instance(
                manifest,
                evidence_schema["$defs"]["FixtureManifest"],
                evidence_schema_path,
                fixture_id,
            ):
                self.fail(str(manifests_path.relative_to(ROOT)), error)
            item = corpus_by_id.get(fixture_id)
            self.check(item is not None, fixture_id, "corpus entry is missing")
            if item is None:
                continue
            content_hash = hashlib.sha256(
                json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            self.check(content_hash == manifest["content_sha256"], fixture_id, "fixture content hash drifted")
            self.check(manifest["privacy_scan"] == "builtin-r5:passed", fixture_id, "R5 secret scan is not passed")
            self.check(
                item.get("external_adapter_activation") == "evidence_pending",
                fixture_id,
                "synthetic R5 evidence must not claim production adapter activation",
            )
            for source, expected_hash in item["source_sha256"].items():
                path = ROOT / source
                self.check(path.exists(), fixture_id, f"fixture source missing: {source}")
                if path.exists():
                    self.check(
                        hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash,
                        fixture_id,
                        f"fixture source hash drifted: {source}",
                    )

    def run(self) -> int:
        self.load_documents()
        if self.findings:
            return self.report()
        self.walk_refs()
        self.validate_enum_registry()
        self.validate_fixtures()
        self.validate_openapi()
        self.validate_source_traceability()
        self.validate_domain_invariants()
        self.validate_r1_foundation()
        self.validate_r2_foundation()
        self.validate_r3_foundation()
        self.validate_r4_foundation()
        self.validate_r5_foundation()
        return self.report()

    def report(self) -> int:
        if self.findings:
            print(f"Contract validation FAILED: {len(self.findings)} finding(s), {self.check_count} checks")
            for finding in self.findings:
                print(f"- {finding.location}: {finding.message}")
            return 1
        print(f"Contract validation PASSED: {len(JSON_FILES)} JSON files, {self.check_count} consistency checks")
        return 0


if __name__ == "__main__":
    sys.exit(ContractValidator().run())
