#!/usr/bin/env python3
"""Generate the R0 machine-readable contracts from the frozen planning sources."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
SCHEMAS = CONTRACTS / "schemas"
OPENAPI = CONTRACTS / "openapi"
TRACEABILITY = CONTRACTS / "traceability"
FIXTURES = CONTRACTS / "fixtures"


ENUMS: dict[str, list[str]] = {
    "credential_auth_kind": ["oauth_subscription", "setup_token_subscription", "console_api_key"],
    "credential_purpose": ["business", "verification_only", "count_tokens"],
    "credential_lifecycle": [
        "pending_verify", "pending_profile", "pending_egress", "pending_reauth_strategy",
        "active", "disabled", "revoked", "archived",
    ],
    "credential_attachment": ["attached", "draining", "detached", "attaching"],
    "credential_auth_state": [
        "healthy", "expiring", "refreshing", "reauth_retrying", "reauth_waiting_egress",
        "manual_recovery_required", "needs_admin_reauth", "auth_broken",
    ],
    "credential_capacity": ["available", "limited", "cooldown", "half_open"],
    "credential_transport": ["ready", "transport_unavailable"],
    "credential_management_class": [
        "fully_managed", "non_managed", "pending_reauth_strategy", "manual_recovery_required",
    ],
    "enrollment_mode": ["create", "recover"],
    "enrollment_auth_method": ["oauth_pkce", "setup_token", "existing_oauth_material", "console_api_key"],
    "enrollment_state": [
        "created", "resolving_egress", "awaiting_user_action", "exchanging_material",
        "verifying_account", "deduplicating", "provisioning_identity", "configuring_reauth",
        "activation_check", "recovering_existing", "succeeded", "cancelled", "expired", "failed",
    ],
    "enrollment_next_action": [
        "wait_for_egress", "open_authorization_url", "submit_setup_material",
        "submit_existing_oauth_material", "complete_oauth_callback", "complete_browser_login",
        "retry", "manual_recovery", "none",
    ],
    "maintenance_kind": [
        "verify", "refresh", "reauthenticate", "manual_recovery", "auth_method_migration",
        "plan_collect", "browser_health",
    ],
    "maintenance_trigger": [
        "enrollment", "scheduled", "expiry_guard", "upstream_401", "admin",
        "manual_recovery", "strategy_health",
    ],
    "maintenance_conflict_class": ["auth_material_write", "plan_collect", "browser_health"],
    "maintenance_state": [
        "planned", "leased", "running", "verifying_account", "committing", "waiting_backoff",
        "waiting_egress", "needs_attention", "succeeded", "failed", "cancelled", "expired",
    ],
    "proxy_type": ["http_connect", "socks5"],
    "proxy_lifecycle": ["active", "draining", "disabled", "archived"],
    "proxy_health": [
        "unknown", "probing", "healthy", "unhealthy_dns", "unhealthy_connect", "unhealthy_auth",
        "unhealthy_tunnel", "unhealthy_tls_passthrough",
    ],
    "egress_mode": ["direct", "proxy"],
    "egress_stability": ["static", "dynamic"],
    "egress_binding_stability": ["pending", "stable", "drifted", "unavailable"],
    "egress_binding_lifecycle": ["pending", "active", "transport_unavailable", "rebinding", "disabled"],
    "client_class": ["claude_code_cli", "non_claude_code_cli"],
    "base_session_kind": ["explicit", "anonymous_reuse"],
    "portability": ["portable", "credential_bound", "unknown"],
    "usage_source": ["official", "local_estimate", "console_count", "cancel_estimate"],
    "usage_completeness": ["complete", "partial", "unknown"],
    "plan_adapter": ["oauth_profile", "claude_cli_bootstrap", "not_applicable"],
    "plan_freshness": ["fresh", "stale", "unknown", "not_applicable"],
    "step_up_purpose": [
        "key_secret_reveal", "irreversible_lifecycle", "content_audit_access", "approval_decision",
        "key_provider_change", "backup_restore_security", "bundle_activation", "device_rebuild",
    ],
    "approval_kind": [
        "key_full_audit", "group_audit_policy", "content_read", "content_export", "device_rebuild",
        "key_provider_change", "legal_hold", "manual_delete", "background_catalog_activate",
        "background_catalog_risk_acceptance", "enforcement_activate",
    ],
    "approval_state": ["pending", "approved", "rejected", "expired", "revoked"],
    "content_audit_requested_mode": ["metadata_only", "full_encrypted"],
    "content_audit_group_policy": ["allow", "require", "forbid"],
    "content_audit_effective_mode": ["metadata_only", "full_encrypted"],
    "content_audit_object_kind": ["original_request", "final_upstream_request", "upstream_response"],
    "job_status": ["queued", "running", "succeeded", "partially_succeeded", "failed", "cancelled"],
    "request_state": ["accepted", "queued", "executing", "delivering", "completed", "failed", "cancelled"],
    "response_mode": ["stream", "non_stream"],
    "delivery_status": ["not_started", "delivering", "delivered", "cancelled_by_client", "client_delivery_failed"],
    "cancel_phase": [
        "buffer_admission_queue", "pre_upstream_with_lease", "upstream_request_upload",
        "awaiting_upstream_response", "receiving_upstream_response",
        "pre_client_commit_after_upstream_complete", "client_response_delivery",
    ],
    "connection_attempt_state": [
        "planned", "pool_lookup", "resolving", "tcp_connecting", "proxy_tunneling",
        "tls_handshaking", "alpn_negotiating", "protocol_ready", "promoted_on_first_byte",
        "failed_before_first_byte", "cancelled_before_first_byte",
    ],
    "messages_attempt_reason": [
        "initial", "oauth_refresh_replay", "network_retry", "rate_limit_retry",
        "overload_retry", "credential_switch",
    ],
    "messages_attempt_state": ["planned", "submitting", "receiving", "completed", "failed", "cancelled"],
    "trace_event_type": [
        "request", "connection_attempt", "transport", "messages_attempt", "usage", "resource_ledger", "delivery",
    ],
    "trace_outcome": ["pending", "success", "failure", "cancelled", "unknown"],
    "resource_kind": [
        "key_concurrency", "group_queue", "session_slot", "credential_lease", "reservation",
        "socket", "pool_entry", "tls_ticket", "h2_stream", "buffer", "temporary_file", "timer",
    ],
    "resource_action": ["acquire", "release"],
    "bundle_lifecycle": ["draft", "verified", "canary", "active", "retired"],
    "bundle_protocol": ["h1", "h2"],
    "bundle_evidence_gate": ["pending", "passed", "failed"],
    "bundle_runtime_state": ["loadable", "quarantined"],
    "requirement_phase": ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10"],
    "requirement_status": ["planned", "implemented", "verified", "blocked", "retired"],
}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def normalized_text_bytes(path: Path) -> bytes:
    """Return platform-independent bytes for text evidence hashing."""
    return path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def text_sha256(path: Path) -> str:
    return hashlib.sha256(normalized_text_bytes(path)).hexdigest()


def schema_id(name: str) -> str:
    return f"https://super-gateway.local/contracts/schemas/{name}"


def enum_schema(name: str, description: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "string", "enum": ENUMS[name], "x-enum-registry": name}
    if description:
        result["description"] = description
    return result


def object_schema(
    properties: dict[str, Any],
    required: list[str] | None = None,
    *,
    additional: bool | dict[str, Any] = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": additional,
    }
    if required:
        result["required"] = required
    return result


def base_schema(name: str, title: str, defs: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": schema_id(name),
        "title": title,
        "$defs": defs,
    }


def generate_registries() -> None:
    write_json(CONTRACTS / "registries" / "enums.json", {
        "schema_version": "1.0.0",
        "source": [
            "planning/domain-model.md", "planning/database-schema.md",
            "planning/credential-lifecycle.md", "planning/api-contract.md",
        ],
        "enums": ENUMS,
    })


def generate_common_schema() -> None:
    defs = {
        "Uuid": {"type": "string", "format": "uuid"},
        "Identifier": {"type": "string", "pattern": "^[a-z][a-z0-9_:-]{2,127}$"},
        "Timestamp": {"type": "string", "format": "date-time"},
        "Revision": {"type": "integer", "minimum": 1},
        "Epoch": {"type": "integer", "minimum": 1},
        "Sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "RequestId": {"type": "string", "minLength": 1, "maxLength": 128},
        "SecretReference": {"type": "string", "pattern": "^secret:[a-zA-Z0-9_./:-]+$"},
        "ErrorDetail": object_schema({
            "code": {"type": "string"}, "message": {"type": "string"},
            "field": {"type": ["string", "null"]}, "details": {"type": "array", "items": {}},
        }, ["code", "message", "field", "details"]),
        "ErrorEnvelope": object_schema({
            "error": {"$ref": "#/$defs/ErrorDetail"},
            "request_id": {"$ref": "#/$defs/RequestId"},
        }, ["error", "request_id"]),
        "Meta": object_schema({"request_id": {"$ref": "#/$defs/RequestId"}}, ["request_id"]),
        "Page": object_schema({
            "size": {"type": "integer", "minimum": 1, "maximum": 100},
            "has_more": {"type": "boolean"},
            "next_cursor": {"type": ["string", "null"]},
        }, ["size", "has_more", "next_cursor"]),
        "AdminResource": object_schema({
            "id": {"type": "string"}, "revision": {"$ref": "#/$defs/Revision"},
        }, ["id"], additional=True),
        "SingleEnvelope": object_schema({
            "data": {"$ref": "#/$defs/AdminResource"}, "meta": {"$ref": "#/$defs/Meta"},
        }, ["data", "meta"]),
        "ListEnvelope": object_schema({
            "data": {"type": "array", "items": {"$ref": "#/$defs/AdminResource"}},
            "page": {"$ref": "#/$defs/Page"}, "meta": {"$ref": "#/$defs/Meta"},
        }, ["data", "page", "meta"]),
        "ActionCommand": object_schema({
            "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            "expected_revision": {"type": "integer", "minimum": 1},
            "approval_case_id": {"type": ["string", "null"]},
            "payload": {"type": "object", "additionalProperties": True},
        }),
        "ArtifactCandidate": object_schema({
            "name": {"type": "string", "minLength": 1},
            "schema_version": {"type": "string", "minLength": 1},
            "payload": {"type": "object", "additionalProperties": True},
            "source_refs": {"type": "array", "items": {"type": "string"}},
        }, ["name", "schema_version", "payload"]),
        "JobStatus": enum_schema("job_status"),
        "Job": object_schema({
            "id": {"type": "string"}, "type": {"type": "string"},
            "status": {"$ref": "#/$defs/JobStatus"},
            "progress": object_schema({
                "completed": {"type": "integer", "minimum": 0},
                "total": {"type": "integer", "minimum": 0},
            }, ["completed", "total"]),
            "created_at": {"$ref": "#/$defs/Timestamp"},
            "expires_at": {"anyOf": [{"$ref": "#/$defs/Timestamp"}, {"type": "null"}]},
        }, ["id", "type", "status", "progress", "created_at", "expires_at"]),
        "JobEnvelope": object_schema({
            "data": {"$ref": "#/$defs/Job"}, "meta": {"$ref": "#/$defs/Meta"},
        }, ["data", "meta"]),
        "PublicReadiness": object_schema({
            "status": {"type": "string", "enum": ["ready", "not_ready"]},
        }, ["status"]),
        "PublicProbeRateLimited": object_schema({
            "status": {"type": "string", "const": "rate_limited"},
        }, ["status"]),
        "ReadinessReport": object_schema({
            "status": {"type": "string", "enum": ["ready", "not_ready"]},
            "schema_ready": {"type": "boolean"},
            "bootstrap_ready": {"type": "boolean"},
            "audit_chain_ready": {"type": "boolean"},
            "active_groups": {"type": "integer", "minimum": 0},
            "blockers": {"type": "array", "items": {"type": "string"}},
        }, ["status", "schema_ready", "bootstrap_ready", "audit_chain_ready", "active_groups", "blockers"]),
    }
    write_json(SCHEMAS / "common.schema.json", base_schema("common.schema.json", "Common Contract Types", defs))


def generate_credential_schema() -> None:
    defs = {name.title().replace("_", ""): enum_schema(name) for name in [
        "credential_auth_kind", "credential_purpose", "credential_lifecycle", "credential_attachment",
        "credential_auth_state", "credential_capacity", "credential_transport", "credential_management_class",
        "enrollment_mode", "enrollment_auth_method", "enrollment_state", "enrollment_next_action",
    ]}
    defs["CredentialStatus"] = object_schema({
        "lifecycle": {"$ref": "#/$defs/CredentialLifecycle"},
        "attachment": {"$ref": "#/$defs/CredentialAttachment"},
        "auth": {"$ref": "#/$defs/CredentialAuthState"},
        "capacity": {"$ref": "#/$defs/CredentialCapacity"},
        "transport": {"$ref": "#/$defs/CredentialTransport"},
        "canonical_status": {"type": "string"},
        "blockers": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
    }, ["lifecycle", "attachment", "auth", "capacity", "transport", "canonical_status", "blockers"])
    defs["Credential"] = object_schema({
        "id": {"type": "string"}, "group_id": {"type": "string"},
        "account_uuid_digest": {"type": "string"},
        "purpose": {"$ref": "#/$defs/CredentialPurpose"},
        "auth_kind": {"$ref": "#/$defs/CredentialAuthKind"},
        "status": {"$ref": "#/$defs/CredentialStatus"},
        "management_class": {"$ref": "#/$defs/CredentialManagementClass"},
        "token_version": {"type": "integer", "minimum": 1},
        "profile_id": {"type": "string"}, "egress_binding_id": {"type": "string"},
        "revision": {"type": "integer", "minimum": 1},
    }, ["id", "group_id", "purpose", "auth_kind", "status", "management_class", "token_version", "profile_id", "egress_binding_id", "revision"])
    defs["CredentialEnrollment"] = object_schema({
        "id": {"type": "string"}, "mode": {"$ref": "#/$defs/EnrollmentMode"},
        "target_group_id": {"type": "string"}, "auth_method": {"$ref": "#/$defs/EnrollmentAuthMethod"},
        "pending_credential_id": {"type": ["string", "null"]},
        "recovery_credential_id": {"type": ["string", "null"]},
        "expected_credential_revision": {"type": ["integer", "null"], "minimum": 1},
        "state": {"$ref": "#/$defs/EnrollmentState"},
        "next_action": {"$ref": "#/$defs/EnrollmentNextAction"},
        "egress_binding_snapshot": {"type": "object", "additionalProperties": True},
        "authorization_uri": {"type": ["string", "null"], "format": "uri"},
        "oauth_callback_nonce": {"type": ["string", "null"], "writeOnly": True, "x-sensitive-once": True},
        "pkce_challenge_digest": {"type": ["string", "null"]},
        "pkce_verifier_secret_ref": {"type": ["string", "null"]},
        "account_uuid_digest": {"type": ["string", "null"]},
        "material_secret_refs": {"type": "array", "items": {"type": "string"}},
        "attempt_count": {"type": "integer", "minimum": 0},
        "expires_at": {"type": "string", "format": "date-time"},
        "revision": {"type": "integer", "minimum": 1},
    }, ["id", "mode", "target_group_id", "auth_method", "state", "next_action", "egress_binding_snapshot", "attempt_count", "expires_at", "revision"])
    defs["EnrollmentCreateCommand"] = object_schema({
        "mode": {"$ref": "#/$defs/EnrollmentMode"},
        "target_group_id": {"type": "string"},
        "auth_method": {"$ref": "#/$defs/EnrollmentAuthMethod"},
        "recovery_credential_id": {"type": ["string", "null"]},
        "expected_credential_revision": {"type": ["integer", "null"], "minimum": 1},
    }, ["mode", "target_group_id", "auth_method"])
    defs["AutoReauthStrategy"] = object_schema({
        "id": {"type": "string"}, "credential_id": {"type": "string"},
        "kind": {"type": "string", "const": "managed_browser_session"},
        "state": {"type": "string", "enum": ["pending", "healthy", "degraded", "invalid", "disabled"]},
        "priority": {"type": "integer", "minimum": 1},
        "browser_material_version": {"type": ["integer", "null"], "minimum": 1},
        "revision": {"type": "integer", "minimum": 1},
    }, ["id", "credential_id", "kind", "state", "priority", "revision"])
    write_json(SCHEMAS / "credential.schema.json", base_schema("credential.schema.json", "Credential and Enrollment Contracts", defs))


def generate_maintenance_schema() -> None:
    defs = {
        "MaintenanceKind": enum_schema("maintenance_kind"),
        "MaintenanceTrigger": enum_schema("maintenance_trigger"),
        "MaintenanceConflictClass": enum_schema("maintenance_conflict_class"),
        "MaintenanceState": enum_schema("maintenance_state"),
    }
    defs["CredentialMaintenanceOperation"] = object_schema({
        "id": {"type": "string"}, "credential_id": {"type": "string"},
        "kind": {"$ref": "#/$defs/MaintenanceKind"},
        "trigger": {"$ref": "#/$defs/MaintenanceTrigger"},
        "conflict_class": {"$ref": "#/$defs/MaintenanceConflictClass"},
        "state": {"$ref": "#/$defs/MaintenanceState"},
        "expected_credential_revision": {"type": "integer", "minimum": 1},
        "expected_token_version": {"type": "integer", "minimum": 1},
        "egress_epoch_snapshot": {"type": "integer", "minimum": 1},
        "generation": {"type": "integer", "minimum": 1},
        "attempt_count": {"type": "integer", "minimum": 0},
        "next_retry_at": {"type": ["string", "null"], "format": "date-time"},
        "outcome_code": {"type": ["string", "null"]},
        "created_at": {"type": "string", "format": "date-time"},
        "updated_at": {"type": "string", "format": "date-time"},
    }, ["id", "credential_id", "kind", "trigger", "conflict_class", "state", "expected_credential_revision", "expected_token_version", "egress_epoch_snapshot", "generation", "attempt_count", "created_at", "updated_at"])
    write_json(SCHEMAS / "maintenance.schema.json", base_schema("maintenance.schema.json", "Credential Maintenance Contracts", defs))


def generate_session_schema() -> None:
    defs = {
        "ClientClass": enum_schema("client_class"),
        "BaseSessionKind": enum_schema("base_session_kind"),
        "Portability": enum_schema("portability"),
        "BaseSessionIdentity": object_schema({
            "kind": {"$ref": "#/$defs/BaseSessionKind"},
            "stable_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "client_class": {"$ref": "#/$defs/ClientClass"},
        }, ["kind", "stable_digest", "client_class"]),
        "AgentIdentity": object_schema({
            "agent_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "base_session_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        }, ["agent_digest", "base_session_digest"]),
        "SessionDerivationInput": object_schema({
            "derivation_version": {"type": "string"},
            "credential_id": {"type": "string"}, "platform_key_id": {"type": "string"},
            "base_session_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "field_purpose": {"type": "string"},
        }, ["derivation_version", "credential_id", "platform_key_id", "base_session_digest", "field_purpose"]),
        "AffinityRecord": object_schema({
            "platform_key_id": {"type": "string"}, "base_session_digest": {"type": "string"},
            "agent_digest": {"type": "string"}, "credential_id": {"type": "string"},
            "expires_at": {"type": "string", "format": "date-time"},
        }, ["platform_key_id", "base_session_digest", "agent_digest", "credential_id", "expires_at"]),
    }
    write_json(SCHEMAS / "session.schema.json", base_schema("session.schema.json", "Session and Affinity Contracts", defs))


def generate_egress_profile_schema() -> None:
    defs = {
        "ProxyType": enum_schema("proxy_type"), "ProxyLifecycle": enum_schema("proxy_lifecycle"),
        "ProxyHealth": enum_schema("proxy_health"), "EgressMode": enum_schema("egress_mode"),
        "EgressStability": enum_schema("egress_stability"),
        "EgressBindingStability": enum_schema("egress_binding_stability"),
        "EgressBindingLifecycle": enum_schema("egress_binding_lifecycle"),
    }
    defs["Proxy"] = object_schema({
        "id": {"type": "string"}, "name": {"type": "string"}, "type": {"$ref": "#/$defs/ProxyType"},
        "host": {"type": "string"}, "port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "lifecycle": {"$ref": "#/$defs/ProxyLifecycle"},
        "health": {"$ref": "#/$defs/ProxyHealth"},
        "stability": {"$ref": "#/$defs/EgressStability"},
        "max_active_credentials": {"type": "integer", "minimum": 1, "default": 5},
        "revision": {"type": "integer", "minimum": 1},
    }, ["id", "name", "type", "host", "port", "lifecycle", "health", "stability", "max_active_credentials", "revision"])
    defs["CredentialEgressBinding"] = object_schema({
        "id": {"type": "string"}, "credential_id": {"type": "string"},
        "mode": {"$ref": "#/$defs/EgressMode"}, "proxy_id": {"type": ["string", "null"]},
        "stability": {"$ref": "#/$defs/EgressBindingStability"},
        "lifecycle": {"$ref": "#/$defs/EgressBindingLifecycle"},
        "egress_epoch": {"type": "integer", "minimum": 1},
        "expected_exit_ip_digest": {"type": ["string", "null"]},
        "observed_exit_ip_digest": {"type": ["string", "null"]},
    }, ["id", "credential_id", "mode", "stability", "lifecycle", "egress_epoch"])
    defs["CredentialDeviceIdentity"] = object_schema({
        "id": {"type": "string"}, "credential_id": {"type": "string"},
        "device_id_digest": {"type": "string"}, "client_id_digest": {"type": "string"},
        "profile_seed_secret_ref": {"type": "string"}, "session_hmac_secret_ref": {"type": "string"},
        "device_epoch": {"type": "integer", "minimum": 1},
    }, ["id", "credential_id", "device_id_digest", "client_id_digest", "profile_seed_secret_ref", "session_hmac_secret_ref", "device_epoch"])
    defs["CredentialProfile"] = object_schema({
        "id": {"type": "string"}, "credential_id": {"type": "string"},
        "archetype_version_id": {"type": "string"}, "device_identity_id": {"type": "string"},
        "egress_binding_id": {"type": "string"}, "profile_epoch": {"type": "integer", "minimum": 1},
        "capture_cohort": {"type": "string"}, "bundle_id": {"type": "string"},
    }, ["id", "credential_id", "archetype_version_id", "device_identity_id", "egress_binding_id", "profile_epoch", "capture_cohort", "bundle_id"])
    write_json(SCHEMAS / "egress-profile.schema.json", base_schema("egress-profile.schema.json", "Egress and Credential Profile Contracts", defs))


def generate_usage_plan_schema() -> None:
    defs = {
        "UsageSource": enum_schema("usage_source"), "UsageCompleteness": enum_schema("usage_completeness"),
        "PlanAdapter": enum_schema("plan_adapter"), "PlanFreshness": enum_schema("plan_freshness"),
    }
    defs["TokenCounts"] = object_schema({
        "input_tokens": {"type": ["integer", "null"], "minimum": 0},
        "output_tokens": {"type": ["integer", "null"], "minimum": 0},
        "cache_creation_input_tokens": {"type": ["integer", "null"], "minimum": 0},
        "cache_read_input_tokens": {"type": ["integer", "null"], "minimum": 0},
    }, ["input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"])
    defs["UsageObservation"] = object_schema({
        "request_id": {"type": "string"}, "attempt_id": {"type": ["string", "null"]},
        "source": {"$ref": "#/$defs/UsageSource"},
        "completeness": {"$ref": "#/$defs/UsageCompleteness"},
        "tokens": {"$ref": "#/$defs/TokenCounts"},
        "model_id": {"type": "string"}, "price_snapshot_id": {"type": ["string", "null"]},
        "estimated_amount": {"type": ["number", "null"], "minimum": 0},
        "currency": {"type": ["string", "null"], "pattern": "^[A-Z]{3}$"},
        "algorithm_version": {"type": ["string", "null"]},
        "observed_at": {"type": "string", "format": "date-time"},
    }, ["request_id", "source", "completeness", "tokens", "model_id", "observed_at"])
    defs["PlanObservation"] = object_schema({
        "credential_id": {"type": "string"}, "adapter": {"$ref": "#/$defs/PlanAdapter"},
        "freshness": {"$ref": "#/$defs/PlanFreshness"},
        "raw": {"type": ["object", "null"], "additionalProperties": True},
        "normalized_plan": {"type": "string"}, "mapping_version": {"type": ["string", "null"]},
        "observed_at": {"type": ["string", "null"], "format": "date-time"},
        "last_attempt_at": {"type": ["string", "null"], "format": "date-time"},
        "last_refresh_failed": {"type": "boolean"}, "failure_category": {"type": ["string", "null"]},
    }, ["credential_id", "adapter", "freshness", "normalized_plan", "last_refresh_failed"])
    defs["PlanMappingVersion"] = object_schema({
        "id": {"type": "string"}, "version": {"type": "integer", "minimum": 1},
        "state": {"type": "string", "enum": ["candidate", "active", "retired"]},
        "mapping": {"type": "object", "additionalProperties": {"type": "string"}},
        "content_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "created_at": {"type": "string", "format": "date-time"},
    }, ["id", "version", "state", "mapping", "content_hash", "created_at"])
    write_json(SCHEMAS / "usage-plan.schema.json", base_schema("usage-plan.schema.json", "Usage and PLAN Contracts", defs))


def generate_audit_schema() -> None:
    defs = {
        "StepUpPurpose": enum_schema("step_up_purpose"), "ApprovalKind": enum_schema("approval_kind"),
        "ApprovalState": enum_schema("approval_state"),
        "ContentAuditRequestedMode": enum_schema("content_audit_requested_mode"),
        "ContentAuditGroupPolicy": enum_schema("content_audit_group_policy"),
        "ContentAuditEffectiveMode": enum_schema("content_audit_effective_mode"),
        "ContentAuditObjectKind": enum_schema("content_audit_object_kind"),
    }
    defs["StepUpGrant"] = object_schema({
        "id": {"type": "string"}, "purpose": {"$ref": "#/$defs/StepUpPurpose"},
        "actor_user_id": {"type": "string"}, "expires_at": {"type": "string", "format": "date-time"},
        "consumed_at": {"type": ["string", "null"], "format": "date-time"},
    }, ["id", "purpose", "actor_user_id", "expires_at"])
    defs["ApprovalCase"] = object_schema({
        "id": {"type": "string"}, "kind": {"$ref": "#/$defs/ApprovalKind"},
        "scope": {"type": "object", "additionalProperties": True},
        "requested_by": {"type": "string"}, "request_step_up_grant_id": {"type": "string"},
        "reason": {"type": "string", "minLength": 1}, "action_snapshot_digest": {"type": "string"},
        "requested_at": {"type": "string", "format": "date-time"},
        "expires_at": {"type": "string", "format": "date-time"},
        "state": {"$ref": "#/$defs/ApprovalState"}, "decided_by": {"type": ["string", "null"]},
        "decision_step_up_grant_id": {"type": ["string", "null"]},
        "decided_at": {"type": ["string", "null"], "format": "date-time"},
        "revision": {"type": "integer", "minimum": 1},
    }, ["id", "kind", "scope", "requested_by", "request_step_up_grant_id", "reason", "action_snapshot_digest", "requested_at", "expires_at", "state", "revision"])
    defs["ContentAuditObject"] = object_schema({
        "id": {"type": "string"}, "request_id": {"type": "string"},
        "attempt_id": {"type": ["string", "null"]},
        "kind": {"$ref": "#/$defs/ContentAuditObjectKind"},
        "ciphertext_location": {"type": "string"}, "wrapped_dek": {"type": "string"},
        "aead_algorithm": {"type": "string"}, "plaintext_digest": {"type": "string"},
        "retention_until": {"type": "string", "format": "date-time"},
        "legal_hold_ids": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
        "created_at": {"type": "string", "format": "date-time"},
    }, ["id", "request_id", "kind", "ciphertext_location", "wrapped_dek", "aead_algorithm", "plaintext_digest", "retention_until", "legal_hold_ids", "created_at"])
    write_json(SCHEMAS / "audit-approval.schema.json", base_schema("audit-approval.schema.json", "Approval and Content Audit Contracts", defs))


def trace_base_properties() -> dict[str, Any]:
    return {
        "schema_version": {"type": "string", "const": "1.0.0"},
        "event_id": {"type": "string"}, "event_type": enum_schema("trace_event_type"),
        "event_seq": {"type": "integer", "minimum": 1}, "trace_id": {"type": "string"},
        "request_id": {"type": "string"}, "parent_event_id": {"type": ["string", "null"]},
        "occurred_at_utc": {"type": "string", "format": "date-time"},
        "monotonic_ns": {"type": "integer", "minimum": 0}, "runtime_generation": {"type": "integer", "minimum": 1},
        "actor": object_schema({"kind": {"type": "string"}, "id_digest": {"type": "string"}}, ["kind", "id_digest"]),
        "executor": object_schema({"instance_id": {"type": "string"}, "owner_partition": {"type": "string"}}, ["instance_id", "owner_partition"]),
        "phase": {"type": "string"}, "outcome": enum_schema("trace_outcome"),
    }


def generate_trace_schema() -> None:
    base_required = [
        "schema_version", "event_id", "event_type", "event_seq", "trace_id", "request_id",
        "occurred_at_utc", "monotonic_ns", "runtime_generation", "actor", "executor", "phase", "outcome",
    ]
    defs: dict[str, Any] = {
        "RequestState": enum_schema("request_state"), "ResponseMode": enum_schema("response_mode"),
        "Portability": enum_schema("portability"), "DeliveryStatus": enum_schema("delivery_status"),
        "CancelPhase": enum_schema("cancel_phase"), "ConnectionAttemptState": enum_schema("connection_attempt_state"),
        "MessagesAttemptReason": enum_schema("messages_attempt_reason"),
        "MessagesAttemptState": enum_schema("messages_attempt_state"),
        "UsageSource": enum_schema("usage_source"), "UsageCompleteness": enum_schema("usage_completeness"),
        "ResourceKind": enum_schema("resource_kind"), "ResourceAction": enum_schema("resource_action"),
        "Protocol": enum_schema("bundle_protocol"),
    }
    defs["TraceEventBase"] = object_schema(trace_base_properties(), base_required)
    defs["RequestEvent"] = object_schema({
        **trace_base_properties(), "event_type": {"const": "request"},
        "payload": object_schema({
            "response_mode": {"$ref": "#/$defs/ResponseMode"}, "state": {"$ref": "#/$defs/RequestState"},
            "client_class": {"type": "string"}, "platform_key_id_digest": {"type": "string"},
            "group_id": {"type": "string"}, "base_session_digest": {"type": "string"},
            "agent_digest": {"type": "string"}, "portability": {"$ref": "#/$defs/Portability"},
            "generic_request_digest": {"type": "string"}, "snapshot_refs": {"type": "object", "additionalProperties": {"type": "string"}},
            "pre_upstream_queue_deadline_utc": {"type": ["string", "null"], "format": "date-time"},
            "upstream_total_deadline_utc": {"type": ["string", "null"], "format": "date-time"},
            "connection_attempt_count": {"type": "integer", "minimum": 0, "maximum": 3},
            "messages_attempt_count": {"type": "integer", "minimum": 0, "maximum": 3},
            "final_attempt_id": {"type": ["string", "null"]}, "response_committed": {"type": "boolean"},
            "terminal_reason": {"type": ["string", "null"]},
        }, ["response_mode", "state", "client_class", "platform_key_id_digest", "group_id", "base_session_digest", "agent_digest", "portability", "generic_request_digest", "snapshot_refs", "connection_attempt_count", "messages_attempt_count", "response_committed"]),
    }, base_required + ["payload"])
    defs["ConnectionAttemptEvent"] = object_schema({
        **trace_base_properties(), "event_type": {"const": "connection_attempt"},
        "payload": object_schema({
            "attempt_id": {"type": "string"}, "ordinal": {"type": "integer", "minimum": 1, "maximum": 3},
            "credential_id_digest": {"type": "string"}, "profile_epoch": {"type": "integer", "minimum": 1},
            "archetype_version_id": {"type": "string"}, "capture_cohort": {"type": "string"},
            "bundle_id": {"type": "string"}, "bundle_version": {"type": "integer", "minimum": 1},
            "bundle_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "egress_binding_id": {"type": "string"}, "proxy_id_digest": {"type": ["string", "null"]},
            "egress_epoch": {"type": "integer", "minimum": 1}, "state": {"$ref": "#/$defs/ConnectionAttemptState"},
            "authority": {"type": "string"}, "sni": {"type": "string"},
            "protocol": {"$ref": "#/$defs/Protocol"}, "pool_key_digest": {"type": "string"},
            "activation_generation": {"type": "integer", "minimum": 1},
            "connect_timeout_ms": {"type": "integer", "minimum": 1}, "pool_reused": {"type": "boolean"},
            "request_bytes_written": {"type": "integer", "minimum": 0},
            "failure_domain": {"type": ["string", "null"]}, "connection_disposition": {"type": ["string", "null"]},
            "retry_safe": {"type": "boolean"}, "health_effect": {"type": ["string", "null"]},
        }, ["attempt_id", "ordinal", "credential_id_digest", "profile_epoch", "archetype_version_id", "capture_cohort", "bundle_id", "bundle_version", "bundle_hash", "egress_binding_id", "egress_epoch", "authority", "sni", "protocol", "pool_key_digest", "activation_generation", "state", "connect_timeout_ms", "pool_reused", "request_bytes_written", "retry_safe"]),
    }, base_required + ["payload"])
    defs["TransportEvent"] = object_schema({
        **trace_base_properties(), "event_type": {"const": "transport"},
        "payload": object_schema({
            "connection_attempt_id": {"type": "string"},
            "attempt_id": {"type": ["string", "null"]},
            "transport_seq": {"type": "integer", "minimum": 1},
            "kind": {"type": "string", "enum": [
                "connection_ready", "first_upstream_request_byte", "request_body_complete",
                "response_headers", "first_response_body_byte", "response_complete",
                "cancel_requested", "cancel_confirmed", "connection_disposition",
            ]},
            "connection_id_digest": {"type": "string"},
            "request_bytes_written": {"type": "integer", "minimum": 0},
            "response_bytes_read": {"type": "integer", "minimum": 0},
            "upstream_submission_complete": {"type": "boolean"},
            "connection_disposition": {"type": ["string", "null"]},
            "diagnostic_code": {"type": ["string", "null"]},
        }, ["connection_attempt_id", "transport_seq", "kind", "connection_id_digest", "request_bytes_written", "response_bytes_read", "upstream_submission_complete"]),
    }, base_required + ["payload"])
    defs["MessagesAttemptEvent"] = object_schema({
        **trace_base_properties(), "event_type": {"const": "messages_attempt"},
        "payload": object_schema({
            "attempt_id": {"type": "string"}, "ordinal": {"type": "integer", "minimum": 1, "maximum": 3},
            "reason": {"$ref": "#/$defs/MessagesAttemptReason"}, "state": {"$ref": "#/$defs/MessagesAttemptState"},
            "credential_id_digest": {"type": "string"}, "token_version": {"type": "integer", "minimum": 1},
            "profile_epoch": {"type": "integer", "minimum": 1}, "archetype_version_id": {"type": "string"},
            "capture_cohort": {"type": "string"}, "bundle_id": {"type": "string"},
            "egress_epoch": {"type": "integer", "minimum": 1}, "upstream_request_id": {"type": ["string", "null"]},
            "submitted": {"type": "boolean"}, "response_committed": {"type": "boolean"},
            "retry_decision": {"type": ["string", "null"]}, "is_final": {"type": "boolean"},
        }, ["attempt_id", "ordinal", "reason", "state", "credential_id_digest", "token_version", "profile_epoch", "archetype_version_id", "capture_cohort", "bundle_id", "egress_epoch", "submitted", "response_committed", "is_final"]),
    }, base_required + ["payload"])
    defs["UsageEvent"] = object_schema({
        **trace_base_properties(), "event_type": {"const": "usage"},
        "payload": object_schema({
            "attempt_id": {"type": ["string", "null"]}, "source": {"$ref": "#/$defs/UsageSource"},
            "completeness": {"$ref": "#/$defs/UsageCompleteness"},
            "input_tokens": {"type": ["integer", "null"], "minimum": 0},
            "output_tokens": {"type": ["integer", "null"], "minimum": 0},
            "cache_creation_input_tokens": {"type": ["integer", "null"], "minimum": 0},
            "cache_read_input_tokens": {"type": ["integer", "null"], "minimum": 0},
            "estimated_amount": {"type": ["number", "null"], "minimum": 0},
            "currency": {"type": ["string", "null"]}, "algorithm_version": {"type": ["string", "null"]},
        }, ["source", "completeness", "input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"]),
    }, base_required + ["payload"])
    defs["ResourceLedgerEvent"] = object_schema({
        **trace_base_properties(), "event_type": {"const": "resource_ledger"},
        "payload": object_schema({
            "resource_kind": {"$ref": "#/$defs/ResourceKind"}, "action": {"$ref": "#/$defs/ResourceAction"},
            "resource_id_digest": {"type": "string"}, "units": {"type": "integer", "minimum": 1},
            "balance_after": {"type": "integer", "minimum": 0}, "reason": {"type": "string"},
        }, ["resource_kind", "action", "resource_id_digest", "units", "balance_after", "reason"]),
    }, base_required + ["payload"])
    defs["DeliveryEvent"] = object_schema({
        **trace_base_properties(), "event_type": {"const": "delivery"},
        "payload": object_schema({
            "status": {"$ref": "#/$defs/DeliveryStatus"}, "cancel_phase": {"anyOf": [{"$ref": "#/$defs/CancelPhase"}, {"type": "null"}]},
            "response_committed": {"type": "boolean"}, "delivered_bytes": {"type": "integer", "minimum": 0},
            "total_bytes": {"type": ["integer", "null"], "minimum": 0},
        }, ["status", "response_committed", "delivered_bytes"]),
    }, base_required + ["payload"])
    root = base_schema("trace-event.schema.json", "Request and Attempt Trace Events", defs)
    root["oneOf"] = [{"$ref": f"#/$defs/{name}"} for name in [
        "RequestEvent", "ConnectionAttemptEvent", "TransportEvent", "MessagesAttemptEvent", "UsageEvent", "ResourceLedgerEvent", "DeliveryEvent",
    ]]
    write_json(SCHEMAS / "trace-event.schema.json", root)


def generate_bundle_schema() -> None:
    defs = {
        "BundleLifecycle": enum_schema("bundle_lifecycle"), "Protocol": enum_schema("bundle_protocol"),
        "EvidenceGate": enum_schema("bundle_evidence_gate"), "RuntimeState": enum_schema("bundle_runtime_state"),
        "OrderedHeader": object_schema({
            "name": {"type": "string", "pattern": "^[A-Za-z0-9-]+$"},
            "value_template": {"type": "string"}, "sensitive": {"type": "boolean"},
        }, ["name", "value_template", "sensitive"]),
        "EngineBuild": object_schema({
            "target": {"type": "string"}, "artifact_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "boringssl_revision": {"type": "string"}, "compiler": {"type": "string"},
        }, ["target", "artifact_digest", "boringssl_revision", "compiler"]),
    }
    common_application = {
        "authority": {"type": "string"},
        "tls": object_schema({
            "client_hello_profile": {"type": "string"}, "alpn": {"type": "array", "items": {"type": "string"}},
            "cipher_suite_ids": {"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 65535}},
            "supported_group_ids": {"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 65535}},
            "key_share_group_ids": {"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 65535}},
            "extension_order": {"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 65535}},
            "grease_enabled": {"type": "boolean"}, "permute_extensions": {"type": "boolean"},
            "session_resumption": {"type": "boolean"},
        }, ["client_hello_profile", "alpn", "cipher_suite_ids", "supported_group_ids", "key_share_group_ids", "extension_order", "grease_enabled", "permute_extensions", "session_resumption"]),
        "connection": object_schema({
            "pool_key_fields": {
                "type": "array", "items": {"type": "string"}, "minItems": 9, "maxItems": 9, "uniqueItems": True,
            },
            "reuse_policy": {"type": "string"}, "resumption_cache_scope": {"type": "string"},
        }, ["pool_key_fields", "reuse_policy", "resumption_cache_scope"]),
    }
    defs["Http1Application"] = object_schema({
        **common_application,
        "protocol": {"const": "h1"},
        "http1": object_schema({
            "request_line_form": {"type": "string"}, "header_order": {"type": "array", "items": {"$ref": "#/$defs/OrderedHeader"}},
            "framing": {"type": "string"},
        }, ["request_line_form", "header_order", "framing"]),
    }, ["protocol", "authority", "tls", "http1", "connection"])
    defs["Http2Application"] = object_schema({
        **common_application,
        "protocol": {"const": "h2"},
        "http2": object_schema({
            "settings_order": {"type": "array", "items": {"type": "string"}},
            "initial_window_size": {"type": "integer", "minimum": 0},
            "pseudo_header_order": {"type": "array", "items": {"type": "string"}},
            "header_order": {"type": "array", "items": {"$ref": "#/$defs/OrderedHeader"}},
        }, ["settings_order", "initial_window_size", "pseudo_header_order", "header_order"]),
    }, ["protocol", "authority", "tls", "http2", "connection"])
    defs["TransportBundlePayload"] = object_schema({
        "schema_version": {"type": "string", "const": "1.0.0"},
        "engine_abi_version": {"type": "string"}, "bundle_id": {"type": "string"},
        "artifact_version": {"type": "integer", "minimum": 1},
        "lifecycle": {"$ref": "#/$defs/BundleLifecycle"}, "evidence_gate": {"$ref": "#/$defs/EvidenceGate"},
        "runtime_state": {"$ref": "#/$defs/RuntimeState"}, "backend_id": {"type": "string"},
        "required_capabilities": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
        "source_archetype_version_id": {"type": "string"}, "capture_cohort": {"type": "string"},
        "application": {"oneOf": [{"$ref": "#/$defs/Http1Application"}, {"$ref": "#/$defs/Http2Application"}]},
        "min_engine_build": {"type": "string", "minLength": 1},
        "max_engine_build": {"type": ["string", "null"]},
        "engine_builds": {"type": "array", "items": {"$ref": "#/$defs/EngineBuild"}, "minItems": 1},
        "supported_targets": {"type": "array", "items": {"type": "string"}, "minItems": 1, "uniqueItems": True},
        "evidence_hashes": {"type": "array", "items": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "minItems": 1, "uniqueItems": True},
        "created_at": {"type": "string", "format": "date-time"},
    }, [
        "schema_version", "engine_abi_version", "bundle_id", "artifact_version", "lifecycle", "evidence_gate",
        "runtime_state", "backend_id", "required_capabilities", "source_archetype_version_id", "capture_cohort",
        "application", "min_engine_build", "max_engine_build", "engine_builds", "supported_targets", "evidence_hashes", "created_at",
    ])
    defs["TransportBundleManifest"] = object_schema({
        "envelope_version": {"type": "string", "const": "1.0.0"},
        "payload": {"$ref": "#/$defs/TransportBundlePayload"},
        "canonicalization": object_schema({
            "algorithm": {"type": "string", "const": "jcs_rfc8785"},
            "hash_algorithm": {"type": "string", "const": "sha256"},
            "canonical_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        }, ["algorithm", "hash_algorithm", "canonical_hash"]),
        "signature": object_schema({
            "domain": {"type": "string", "const": "transport_bundle_v1"},
            "algorithm": {"type": "string", "const": "ed25519"}, "key_id": {"type": "string"},
            "detached_signature_base64": {"type": "string", "minLength": 40},
        }, ["domain", "algorithm", "key_id", "detached_signature_base64"]),
    }, ["envelope_version", "payload", "canonicalization", "signature"])
    root = base_schema("transport-bundle-manifest.schema.json", "Transport Bundle Manifest", defs)
    root["$ref"] = "#/$defs/TransportBundleManifest"
    write_json(SCHEMAS / "transport-bundle-manifest.schema.json", root)
    trust_defs = {
        "TrustKey": object_schema({
            "key_id": {"type": "string", "minLength": 1},
            "status": {"type": "string", "enum": ["current", "historical", "revoked"]},
            "public_key_base64": {"type": "string", "minLength": 40},
            "valid_from_unix_seconds": {"type": ["integer", "null"], "minimum": 0},
            "valid_until_unix_seconds": {"type": ["integer", "null"], "minimum": 1},
        }, ["key_id", "status", "public_key_base64", "valid_from_unix_seconds", "valid_until_unix_seconds"]),
        "BundleTrustStore": object_schema({
            "format_version": {"type": "string", "const": "1.0.0"},
            "domain": {"type": "string", "const": "transport_bundle_v1"},
            "keys": {"type": "array", "items": {"$ref": "#/$defs/TrustKey"}, "minItems": 1},
        }, ["format_version", "domain", "keys"]),
    }
    trust_root = base_schema("bundle-trust-store.schema.json", "Transport Bundle TrustStore", trust_defs)
    trust_root["$ref"] = "#/$defs/BundleTrustStore"
    write_json(SCHEMAS / "bundle-trust-store.schema.json", trust_root)


def generate_r1_foundation_schemas() -> None:
    runtime_defs = {
        "RuntimeVariable": object_schema({
            "name": {"type": "string", "pattern": "^GATEWAY_[A-Z0-9_]+$"},
            "kind": {"type": "string", "enum": [
                "socket_address", "path", "secret_file", "provider_uri", "duration", "secret_value", "string", "enum",
            ]},
            "required": {"type": "boolean"},
            "secret": {"type": "boolean"},
            "readiness_gate": {"type": "boolean"},
            "relationship": {"type": "string", "enum": ["independent", "pair", "exactly_one", "conditional"]},
            "related_to": {"type": ["string", "null"]},
            "default": {"type": ["string", "null"]},
        }, ["name", "kind", "required", "secret", "readiness_gate", "relationship", "related_to", "default"]),
        "RuntimeConfigContract": object_schema({
            "schema_version": {"type": "string", "const": "2.0.0"},
            "environment_prefix": {"type": "string", "const": "GATEWAY_"},
            "dotenv_supported": {"type": "boolean", "const": True},
            "unknown_variable_policy": {"type": "string", "const": "ignore"},
            "variables": {"type": "array", "items": {"$ref": "#/$defs/RuntimeVariable"}, "minItems": 15},
        }, ["schema_version", "environment_prefix", "dotenv_supported", "unknown_variable_policy", "variables"]),
    }
    runtime_root = base_schema("runtime-config.schema.json", "R1 Runtime Configuration Contract", runtime_defs)
    runtime_root["$ref"] = "#/$defs/RuntimeConfigContract"
    write_json(SCHEMAS / "runtime-config.schema.json", runtime_root)

    evidence_defs = {
        "DigestArtifact": object_schema({
            "name": {"type": "string", "minLength": 1},
            "path": {"type": "string", "minLength": 1},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "size_bytes": {"type": "integer", "minimum": 0},
        }, ["name", "path", "sha256", "size_bytes"]),
        "SchemaCompatibility": object_schema({
            "minimum": {"type": "integer", "minimum": 0},
            "maximum": {"type": "integer", "minimum": 0},
        }, ["minimum", "maximum"]),
        "ReleaseManifest": object_schema({
            "schema_version": {"type": "string", "const": "1.0.0"},
            "application": {"type": "string", "const": "super-gatewayd"},
            "application_version": {"type": "string", "minLength": 1},
            "target": {"type": "string", "minLength": 1},
            "created_at": {"type": "string", "format": "date-time"},
            "source_revision": {"type": "string", "minLength": 1},
            "rust_toolchain": {"type": "string", "minLength": 1},
            "runtime_abi_version": {"type": "string", "const": "r2-v1"},
            "testkit_abi_version": {"type": "string", "const": "gateway-testkit-r1-v1"},
            "schema_compatibility": {"$ref": "#/$defs/SchemaCompatibility"},
            "cargo_lock_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "contract_tree_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "migration_checksums": {"type": "object", "additionalProperties": {"type": "string", "pattern": "^[0-9a-f]{64}$"}},
            "artifacts": {"type": "array", "items": {"$ref": "#/$defs/DigestArtifact"}, "minItems": 1},
        }, [
            "schema_version", "application", "application_version", "target", "created_at", "source_revision",
            "rust_toolchain", "runtime_abi_version", "testkit_abi_version", "schema_compatibility",
            "cargo_lock_sha256", "contract_tree_sha256", "migration_checksums", "artifacts",
        ]),
        "BuildProvenance": object_schema({
            "schema_version": {"type": "string", "const": "1.0.0"},
            "builder": {"type": "string", "minLength": 1},
            "build_type": {"type": "string", "const": "super-gateway/rust-release-v1"},
            "created_at": {"type": "string", "format": "date-time"},
            "target": {"type": "string", "minLength": 1},
            "command": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "materials": {"type": "array", "items": {"$ref": "#/$defs/DigestArtifact"}, "minItems": 2},
            "subjects": {"type": "array", "items": {"$ref": "#/$defs/DigestArtifact"}, "minItems": 1},
        }, ["schema_version", "builder", "build_type", "created_at", "target", "command", "materials", "subjects"]),
        "EvidenceManifest": object_schema({
            "schema_version": {"type": "string", "const": "1.0.0"},
            "release_manifest": {"$ref": "#/$defs/DigestArtifact"},
            "provenance": {"$ref": "#/$defs/DigestArtifact"},
            "sbom": {"$ref": "#/$defs/DigestArtifact"},
            "verification": {"type": "object", "additionalProperties": {"type": "string", "enum": ["passed", "failed", "not_run"]}},
        }, ["schema_version", "release_manifest", "provenance", "sbom", "verification"]),
        "FixtureManifest": object_schema({
            "fixture_id": {"type": "string", "minLength": 1},
            "source": {"type": "string", "enum": ["synthetic", "normalized_capture", "regression"]},
            "scenario": {"type": "string", "minLength": 1},
            "schema_version": {"type": "string", "minLength": 1},
            "normalizer_version": {"type": ["string", "null"]},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "privacy_scan": {"type": "string", "minLength": 1},
            "generation_command": {"type": "string", "minLength": 1},
            "compatibility": {"type": "array", "items": {"type": "string"}},
            "expiration_policy": {"type": "string", "minLength": 1},
            "os_family": {"type": ["string", "null"]},
            "runtime_version": {"type": ["string", "null"]},
            "client_version": {"type": ["string", "null"]},
            "architecture": {"type": ["string", "null"]},
            "capture_cohort": {"type": ["string", "null"]},
        }, [
            "fixture_id", "source", "scenario", "schema_version", "normalizer_version", "content_sha256",
            "privacy_scan", "generation_command", "compatibility", "expiration_policy", "os_family",
            "runtime_version", "client_version", "architecture", "capture_cohort",
        ]),
    }
    write_json(
        SCHEMAS / "release-evidence.schema.json",
        base_schema("release-evidence.schema.json", "R1 Release and Evidence Contracts", evidence_defs),
    )


def generate_r2_foundation_schemas() -> None:
    sha256 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    migration_defs = {
        "Migration": object_schema({
            "version": {"type": "integer", "minimum": 1},
            "name": {"type": "string", "pattern": "^[0-9]{14}_[a-z0-9_]+\\.sql$"},
            "sha256": sha256,
            "direction": {"type": "string", "const": "forward_only"},
            "transactional": {"type": "boolean"},
        }, ["version", "name", "sha256", "direction", "transactional"]),
        "MigrationManifest": object_schema({
            "schema_version": {"type": "string", "const": "1.0.0"},
            "postgres_minimum_major": {"type": "integer", "const": 16},
            "minimum_compatible_version": {"type": "integer", "minimum": 1},
            "current_version": {"type": "integer", "minimum": 1},
            "migrations": {"type": "array", "items": {"$ref": "#/$defs/Migration"}, "minItems": 1, "uniqueItems": True},
        }, ["schema_version", "postgres_minimum_major", "minimum_compatible_version", "current_version", "migrations"]),
    }
    root = base_schema("migration-manifest.schema.json", "R2 Forward-only Migration Manifest", migration_defs)
    root["$ref"] = "#/$defs/MigrationManifest"
    write_json(SCHEMAS / "migration-manifest.schema.json", root)

    database_defs = {
        "DatabaseSchemaManifest": object_schema({
            "schema_version": {"type": "string", "const": "1.0.0"},
            "postgres_minimum_major": {"type": "integer", "const": 16},
            "logical_schemas": {"type": "array", "items": {"type": "string"}, "minItems": 6, "uniqueItems": True},
            "required_tables": {"type": "array", "items": {"type": "string", "pattern": "^[a-z_]+\\.[a-z0-9_]+$"}, "minItems": 116, "maxItems": 116, "uniqueItems": True},
            "database_roles": {"type": "array", "items": {"type": "string"}, "minItems": 4, "maxItems": 4, "uniqueItems": True},
            "uuid_generation": {"type": "string", "const": "application_uuid_v7"},
            "enum_storage": {"type": "string", "const": "text_check_fail_closed"},
        }, ["schema_version", "postgres_minimum_major", "logical_schemas", "required_tables", "database_roles", "uuid_generation", "enum_storage"]),
    }
    root = base_schema("database-schema-manifest.schema.json", "R2 PostgreSQL Physical Contract", database_defs)
    root["$ref"] = "#/$defs/DatabaseSchemaManifest"
    write_json(SCHEMAS / "database-schema-manifest.schema.json", root)

    envelope_defs = {
        "SecretEnvelope": object_schema({
            "schema_version": {"type": "integer", "const": 1},
            "cipher_suite": {"type": "string", "const": "aes_256_gcm"},
            "provider_role": {"type": "string", "enum": ["business", "content_audit", "backup", "audit_integrity"]},
            "key_version": {"type": "integer", "minimum": 1},
            "ciphertext_base64": {"type": "string", "minLength": 1},
            "nonce_base64": {"type": "string", "minLength": 16},
            "wrapped_dek_base64": {"type": "string", "minLength": 1},
            "aad_fields": {"type": "array", "items": {"type": "string"}, "minItems": 8, "uniqueItems": True},
        }, ["schema_version", "cipher_suite", "provider_role", "key_version", "ciphertext_base64", "nonce_base64", "wrapped_dek_base64", "aad_fields"]),
    }
    root = base_schema("secret-envelope.schema.json", "R2 Secret Envelope Contract", envelope_defs)
    root["$ref"] = "#/$defs/SecretEnvelope"
    write_json(SCHEMAS / "secret-envelope.schema.json", root)

    audit_defs = {
        "AuditIntegrityVector": object_schema({
            "schema_version": {"type": "string", "const": "1.0.0"},
            "event_domain": {"type": "string", "const": "gateway-audit-event-v1"},
            "seal_domain": {"type": "string", "const": "gateway-audit-day-v1"},
            "hash_algorithm": {"type": "string", "const": "sha256"},
            "seal_algorithm": {"type": "string", "const": "hmac_sha256"},
            "event_day": {"type": "string"},
            "daily_sequence": {"type": "integer", "minimum": 1},
            "canonical_event": {"type": "string"},
            "event_hash": sha256,
        }, ["schema_version", "event_domain", "seal_domain", "hash_algorithm", "seal_algorithm", "event_day", "daily_sequence", "canonical_event", "event_hash"]),
    }
    root = base_schema("audit-integrity.schema.json", "R2 Audit Chain and Daily Seal Contract", audit_defs)
    root["$ref"] = "#/$defs/AuditIntegrityVector"
    write_json(SCHEMAS / "audit-integrity.schema.json", root)

    backup_defs = {
        "BackupRestoreManifest": object_schema({
            "schema_version": {"type": "string", "const": "2.0.0"},
            "backup_id": {"type": "string", "format": "uuid"},
            "created_at_utc": {"type": "string", "format": "date-time"},
            "scope": {"type": "string", "const": "local_fixture"},
            "backup_key_version": {"type": "integer", "minimum": 1},
            "database_system_id": {"type": "string", "minLength": 1},
            "timeline": {"type": "integer", "minimum": 1},
            "base_backup_lsn": {"type": "string", "minLength": 1},
            "wal_end_lsn": {"type": "string", "minLength": 1},
            "release_version": {"type": "string", "minLength": 1},
            "schema_version_value": {"type": "integer", "minimum": 1},
            "migration_manifest_sha256": sha256,
            "audit_seal_watermark": {"type": "string", "minLength": 1},
            "deletion_ledger_watermark": {"type": "integer", "minimum": 0},
            "audit": object_schema({"sealed_through": {"type": "string"}, "seal_digest": {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"}}, ["sealed_through", "seal_digest"]),
            "deletion_ledger": object_schema({"sequence": {"type": "integer", "minimum": 0}, "entry_hash": {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"}}, ["sequence", "entry_hash"]),
            "lineage": object_schema({"release_version": {"type": "string"}, "schema_version": {"type": "integer", "minimum": 1}, "migration_manifest_sha256": sha256, "parent_manifest_sha256": {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"}}, ["release_version", "schema_version", "migration_manifest_sha256", "parent_manifest_sha256"]),
            "objects": {"type": "array", "items": object_schema({"kind": {"type": "string"}, "uri": {"type": "string"}, "size_bytes": {"type": "integer", "minimum": 1}, "sha256": sha256}, ["kind", "uri", "size_bytes", "sha256"]), "minItems": 1},
            "included_categories": {"type": "array", "items": {"type": "string"}, "minItems": 1, "uniqueItems": True},
            "excluded_categories": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
            "manifest_hmac_sha256": sha256,
            "encrypted": {"type": "boolean", "const": True},
        }, ["schema_version", "backup_id", "created_at_utc", "scope", "backup_key_version", "database_system_id", "timeline", "base_backup_lsn", "wal_end_lsn", "release_version", "schema_version_value", "migration_manifest_sha256", "audit_seal_watermark", "deletion_ledger_watermark", "audit", "deletion_ledger", "lineage", "objects", "included_categories", "excluded_categories", "manifest_hmac_sha256", "encrypted"]),
    }
    root = base_schema("backup-restore-manifest.schema.json", "R2 Backup and Restore Manifest", backup_defs)
    root["$ref"] = "#/$defs/BackupRestoreManifest"
    write_json(SCHEMAS / "backup-restore-manifest.schema.json", root)

    evidence_defs = {
        "PostgresTestEvidence": object_schema({
            "schema_version": {"type": "string", "const": "1.0.0"},
            "postgres_major": {"type": "integer", "minimum": 16},
            "schema_version_value": {"type": "integer", "minimum": 1},
            "migration_manifest_sha256": sha256,
            "required_table_count": {"type": "integer", "const": 116},
            "partition_count": {"type": "integer", "minimum": 1},
            "fixture_id": {"type": "string", "minLength": 1},
            "automation": {"type": "string", "minLength": 1},
            "status": {"type": "string", "enum": ["not_run", "passed", "failed"]},
        }, ["schema_version", "postgres_major", "schema_version_value", "migration_manifest_sha256", "required_table_count", "partition_count", "fixture_id", "automation", "status"]),
    }
    root = base_schema("postgres-test-evidence.schema.json", "R2 PostgreSQL Test Evidence", evidence_defs)
    root["$ref"] = "#/$defs/PostgresTestEvidence"
    write_json(SCHEMAS / "postgres-test-evidence.schema.json", root)


def generate_ledger_schema() -> None:
    defs = {
        "Phase": enum_schema("requirement_phase"), "Status": enum_schema("requirement_status"),
        "SourceRef": object_schema({
            "file": {"type": "string"}, "line": {"type": "integer", "minimum": 1},
            "text_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        }, ["file", "line", "text_sha256"]),
        "Requirement": object_schema({
            "requirement_id": {"type": "string", "pattern": "^(REQ-F(0[1-9]|1[0-8])|REQ-R(1-[0-9]{3}|[2-9]-[0-9]{3}|10-[0-9]{3})|DEC-(00[1-9]|0[1-9][0-9]|1[0-2][0-9]|13[0-2]))$"},
            "kind": {"type": "string", "enum": ["functional_module", "product_decision", "phase_requirement"]},
            "title": {"type": "string", "minLength": 1}, "source": {"$ref": "#/$defs/SourceRef"},
            "owner": {"type": "string", "minLength": 1}, "phase": {"$ref": "#/$defs/Phase"},
            "release_gate": {"type": "string", "enum": ["r0", "canary", "ga"]},
            "test_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1, "uniqueItems": True},
            "fixture_ids": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
            "status": {"$ref": "#/$defs/Status"},
        }, ["requirement_id", "kind", "title", "source", "owner", "phase", "release_gate", "test_ids", "fixture_ids", "status"]),
        "TestCase": object_schema({
            "test_id": {"type": "string"}, "kind": {"type": "string"}, "owner": {"type": "string"},
            "phase": {"$ref": "#/$defs/Phase"}, "requirement_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "automation": {"type": "string"},
        }, ["test_id", "kind", "owner", "phase", "requirement_ids", "automation"]),
        "RequirementTraceLedger": object_schema({
            "schema_version": {"type": "string", "const": "1.0.0"}, "generated_at": {"type": "string", "format": "date-time"},
            "source_revision": {"type": "string"}, "requirements": {"type": "array", "items": {"$ref": "#/$defs/Requirement"}, "minItems": 150},
            "tests": {"type": "array", "items": {"$ref": "#/$defs/TestCase"}, "minItems": 150},
        }, ["schema_version", "generated_at", "source_revision", "requirements", "tests"]),
    }
    root = base_schema("requirement-trace-ledger.schema.json", "Requirement Trace Ledger", defs)
    root["$ref"] = "#/$defs/RequirementTraceLedger"
    write_json(SCHEMAS / "requirement-trace-ledger.schema.json", root)


def camel_operation(method: str, path: str) -> str:
    clean = path.removeprefix("/admin/v1/")
    tokens = re.findall(r"[A-Za-z0-9]+|\{[^}]+\}", clean)
    parts = []
    for token in tokens:
        if token.startswith("{"):
            parts.append("By" + "".join(x.title() for x in re.split(r"[_-]", token[1:-1])))
        else:
            parts.append("".join(x.title() for x in re.split(r"[_-]", token)))
    return method.lower() + "".join(parts)


def parse_admin_routes() -> list[dict[str, Any]]:
    source = (ROOT / "planning" / "api-contract.md").read_text(encoding="utf-8").splitlines()
    routes: list[dict[str, Any]] = []
    heading = "admin"
    route_pattern = re.compile(r"^\|\s*((?:GET|POST|PATCH|PUT|DELETE)(?:、(?:GET|POST|PATCH|PUT|DELETE))*)\s*\|\s*`(/admin/v1/[^`]+)`\s*\|(.+)$")
    for line in source:
        if line.startswith("## ") or line.startswith("### "):
            heading = re.sub(r"^#+\s*(?:\d+(?:\.\d+)?\.?\s*)?", "", line).strip()
        match = route_pattern.match(line)
        if not match:
            continue
        methods, path, tail = match.groups()
        cells = [c.strip() for c in tail.split("|") if c.strip()]
        description = cells[-1] if cells else heading
        explicit_role = cells[-2] if len(cells) >= 2 else ""
        for method in methods.split("、"):
            routes.append({
                "method": method.lower(), "path": path, "description": description,
                "tag": heading, "explicit_role": explicit_role,
            })
    unique: dict[tuple[str, str], dict[str, Any]] = {(r["path"], r["method"]): r for r in routes}
    return [unique[key] for key in sorted(unique)]


def roles_for(path: str, method: str, explicit: str) -> list[str]:
    if path == "/admin/v1/auth/login":
        return ["anonymous"]
    if path.startswith("/admin/v1/auth/"):
        return ["platform_admin", "key_owner"]
    if path == "/admin/v1/platform-keys" and method == "post":
        return ["platform_admin"]
    if any(path.startswith(prefix) for prefix in [
        "/admin/v1/platform-keys", "/admin/v1/requests", "/admin/v1/usage/", "/admin/v1/exports",
        "/admin/v1/notifications", "/admin/v1/dashboard/summary", "/admin/v1/audit-events",
    ]):
        return ["platform_admin", "key_owner"]
    if "本人" in explicit:
        return ["platform_admin", "key_owner"]
    return ["platform_admin"]


def request_ref(path: str, method: str) -> str:
    if path == "/admin/v1/auth/login":
        return "#/components/schemas/LoginCommand"
    if path == "/admin/v1/auth/mfa/enrollments" and method == "post":
        return "#/components/schemas/EmptyCommand"
    if path == "/admin/v1/auth/mfa/verify" or (path.endswith(":confirm") and "/auth/mfa/enrollments/" in path):
        return "#/components/schemas/TotpCommand"
    if path == "/admin/v1/auth/password:change":
        return "#/components/schemas/PasswordChangeCommand"
    if path == "/admin/v1/auth/step-up":
        return "#/components/schemas/StepUpCommand"
    if path == "/admin/v1/users" and method == "post":
        return "#/components/schemas/UserCreateCommand"
    if path == "/admin/v1/platform-keys" and method == "post":
        return "#/components/schemas/PlatformKeyCreateCommand"
    if path == "/admin/v1/platform-keys/{id}:reveal" and method == "post":
        return "#/components/schemas/PlatformKeyRevealCommand"
    if path == "/admin/v1/platform-keys/{id}:revoke" and method == "post":
        return "#/components/schemas/PlatformKeyRevokeCommand"
    if path == "/admin/v1/groups" and method == "post":
        return "#/components/schemas/GroupCreateCommand"
    if path.endswith("/config-versions") and method == "post":
        return "#/components/schemas/GroupConfigCandidate"
    if path == "/admin/v1/groups/{id}:rollback-config" and method == "post":
        return "#/components/schemas/GroupConfigRollbackCommand"
    if path == "/admin/v1/credential-enrollments" and method == "post":
        return "../schemas/credential.schema.json#/$defs/EnrollmentCreateCommand"
    if path == "/admin/v1/credential-enrollments/{id}:submit-material" and method == "post":
        return "#/components/schemas/EnrollmentMaterialCommand"
    if path == "/admin/v1/credential-enrollments/{id}:complete-callback" and method == "post":
        return "#/components/schemas/OAuthCallbackCommand"
    if path == "/admin/v1/proxies" and method == "post":
        return "#/components/schemas/ProxyCreateCommand"
    if path == "/admin/v1/proxies/{id}" and method == "patch":
        return "#/components/schemas/ProxyPatchCommand"
    if path == "/admin/v1/proxies/{id}:replace-secret" and method == "post":
        return "#/components/schemas/ProxyReplaceSecretCommand"
    if path == "/admin/v1/plan-mapping-versions" and method == "post":
        return "#/components/schemas/PlanMappingCreateCommand"
    if path == "/admin/v1/capability-versions" and method == "post":
        return "#/components/schemas/CapabilityCreateCommand"
    if path.startswith("/admin/v1/capability-versions/{id}:") and method == "post":
        return "#/components/schemas/CapabilityActionCommand"
    if path.startswith("/admin/v1/models/{id}:") and method == "post":
        return "#/components/schemas/ModelLifecycleCommand"
    if path == "/admin/v1/models:refresh" and method == "post":
        return "#/components/schemas/ModelRefreshCommand"
    if path == "/admin/v1/price-versions" and method == "post":
        return "#/components/schemas/PriceVersionCreateCommand"
    if path in {"/admin/v1/background-catalog-versions", "/admin/v1/enforcement-versions"} and method == "post":
        return "#/components/schemas/TypedArtifactCreateCommand"
    if (
        path.startswith("/admin/v1/background-catalog-versions/{id}:")
        or path.startswith("/admin/v1/enforcement-versions/{id}:")
    ) and method == "post":
        return "#/components/schemas/PolicyArtifactActionCommand"
    if path == "/admin/v1/rulesets" and method == "post":
        return "#/components/schemas/RuleSetCreateCommand"
    if path == "/admin/v1/rulesets/{id}:simulate" and method == "post":
        return "#/components/schemas/RuleSetSimulationCommand"
    if path.startswith("/admin/v1/rulesets/{id}:") and method == "post":
        return "#/components/schemas/RuleSetActionCommand"
    if path == "/admin/v1/environment-archetypes" and method == "post":
        return "#/components/schemas/EnvironmentArchetypeCreateCommand"
    if path.startswith("/admin/v1/environment-archetypes/{id}:") and method == "post":
        return "#/components/schemas/ReasonActionCommand"
    if path == "/admin/v1/transport-bundles" and method == "post":
        return "#/components/schemas/TransportBundleCreateCommand"
    if path in {"/admin/v1/transport-bundles/{id}:verify", "/admin/v1/transport-bundles/{id}:promote-canary"} and method == "post":
        return "#/components/schemas/ReasonActionCommand"
    if path in {"/admin/v1/transport-bundles/{id}:activate", "/admin/v1/transport-bundles/{id}:rollback"} and method == "post":
        return "#/components/schemas/TransportBundleActivateCommand"
    if path == "/admin/v1/approval-cases" and method == "post":
        return "#/components/schemas/ApprovalCreateCommand"
    if path.startswith("/admin/v1/approval-cases/{id}:") and path.rsplit(":", 1)[-1] in {"approve", "reject"}:
        return "#/components/schemas/ApprovalDecisionCommand"
    if path == "/admin/v1/content-audit/search-sessions" and method == "post":
        return "#/components/schemas/ContentAuditSearchCommand"
    if path == "/admin/v1/content-audit/records/{id}:export" and method == "post":
        return "#/components/schemas/ContentAuditExportCommand"
    if path == "/admin/v1/content-audit/legal-holds" and method == "post":
        return "#/components/schemas/LegalHoldCreateCommand"
    if path == "/admin/v1/operations/jobs/{id}:cancel" and method == "post":
        return "#/components/schemas/ReasonActionCommand"
    if path.startswith("/admin/v1/content-audit/legal-holds/{id}:"):
        return "#/components/schemas/LegalHoldActionCommand"
    if path == "/admin/v1/content-audit/purge-jobs" and method == "post":
        return "#/components/schemas/ContentPurgeCommand"
    if path == "/admin/v1/operations/key-rotation-jobs" and method == "post":
        return "#/components/schemas/KeyRotationCommand"
    if path == "/admin/v1/operations/key-lifecycle-jobs" and method == "post":
        return "#/components/schemas/KeyLifecycleCommand"
    if path == "/admin/v1/operations/backup-jobs" and method == "post":
        return "#/components/schemas/BackupJobCommand"
    if path == "/admin/v1/operations/upgrade-checks" and method == "post":
        return "#/components/schemas/UpgradeCheckCommand"
    if path in {"/admin/v1/operations/restore-validations", "/admin/v1/operations/drills"} and method == "post":
        return "#/components/schemas/RestoreOperationCommand"
    if path == "/admin/v1/alert-silences" and method == "post":
        return "#/components/schemas/AlertSilenceCreateCommand"
    if path == "/admin/v1/notification-channels" and method == "post":
        return "#/components/schemas/NotificationChannelCreateCommand"
    if path == "/admin/v1/notification-channels/{id}:test" and method == "post":
        return "#/components/schemas/NotificationChannelTestCommand"
    if path == "/admin/v1/exports" and method == "post":
        return "#/components/schemas/UsageExportCreateCommand"
    if method == "post" and (
        path in {"/admin/v1/alerts/{id}:acknowledge", "/admin/v1/alerts/{id}:resolve"}
        or path == "/admin/v1/alert-silences/{id}:end"
        or path == "/admin/v1/credentials/{id}:clear-cooldown"
        or path == "/admin/v1/credentials/{id}:archive"
        or path == "/admin/v1/credentials/{id}:refresh-token"
        or path == "/admin/v1/credentials/{id}:refresh-plan"
        or path == "/admin/v1/credentials/{id}/reauth-strategy:disable"
        or path == "/admin/v1/credentials/{id}/reauth-strategy:initialize"
        or path == "/admin/v1/credentials/{id}/reauth-strategy:reactivate"
        or path == "/admin/v1/credentials/{id}/browser-operations/{operation_id}:cancel"
    ):
        return "#/components/schemas/ReasonActionCommand"
    if path == "/admin/v1/credentials/{id}/scheduling-config" and method == "patch":
        return "#/components/schemas/CredentialSchedulingPatchCommand"
    if path == "/admin/v1/credentials/{id}:migrate-group" and method == "post":
        return "#/components/schemas/CredentialGroupMigrationCommand"
    if path == "/admin/v1/credentials/{id}:rebind-egress" and method == "post":
        return "#/components/schemas/EgressRebindCommand"
    if path == "/admin/v1/credentials/{id}:migrate-profile-cohort" and method == "post":
        return "#/components/schemas/ProfileCohortCommand"
    if path == "/admin/v1/credentials/{id}:rebuild-device-identity" and method == "post":
        return "#/components/schemas/DeviceIdentityRebuildCommand"
    if method == "patch":
        return "#/components/schemas/ResourcePatchCommand"
    if method == "post" and ":" not in path:
        return "../schemas/common.schema.json#/$defs/ArtifactCandidate"
    return "../schemas/common.schema.json#/$defs/ActionCommand"


def response_ref(path: str, method: str) -> str:
    if path.startswith("/admin/v1/exports"):
        return "#/components/schemas/UsageExportEnvelope"
    if path.startswith("/admin/v1/credential-enrollments") and method in {"get", "post"}:
        return "#/components/schemas/CredentialEnrollmentEnvelope"
    if path.endswith("/maintenance-operations") and method == "get":
        return "#/components/schemas/MaintenanceOperationListEnvelope"
    if path.endswith("/reauth-strategy") and method == "get":
        return "#/components/schemas/AutoReauthStrategyEnvelope"
    if path == "/admin/v1/usage/summary" and method == "get":
        return "#/components/schemas/UsageObservationListEnvelope"
    if path == "/admin/v1/system/status" and method == "get":
        return "#/components/schemas/SystemStatusEnvelope"
    if path == "/admin/v1/platform-keys/{id}/client-config" and method == "get":
        return "../schemas/common.schema.json#/$defs/SingleEnvelope"
    if method == "get" and not (path.endswith("/{id}") or re.search(r"\{[^}]+\}$", path)):
        return "../schemas/common.schema.json#/$defs/ListEnvelope"
    return "../schemas/common.schema.json#/$defs/SingleEnvelope"


def is_async(path: str, method: str) -> bool:
    if method != "post":
        return False
    if path == "/admin/v1/credentials/{id}:migrate-profile-cohort":
        return False
    if path in {
        "/admin/v1/plan-mapping-versions/{id}:activate",
        "/admin/v1/plan-mapping-versions/{id}:rollback",
        "/admin/v1/notification-channels/{id}:test",
        "/admin/v1/content-audit/records/{id}:export",
        "/admin/v1/credentials/{id}/reauth-strategy:reactivate",
    }:
        return True
    return any(token in path for token in [
        "refresh", ":probe", ":verify", ":initialize", ":recompute", ":migrate-", ":rebind-",
        "/exports", "/purge-jobs", "/backup-jobs", "/restore-validations", "/key-rotation-jobs",
        "/upgrade-checks", "/operations/drills",
    ])


def needs_idempotency(path: str, method: str) -> bool:
    if method != "post":
        return False
    return not any(token in path for token in [
        "/auth/login", "/auth/mfa/", "/auth/step-up", ":validate", ":simulate",
        "/content-audit/search-sessions",
    ])


def needs_if_match(path: str, method: str) -> bool:
    if path == "/admin/v1/content-audit/records/{id}:export" and method == "post":
        return False
    return "{" in path and (method in {"patch", "delete"} or (method == "post" and ":" in path))


def admin_components() -> dict[str, Any]:
    return {
        "securitySchemes": {
            "adminSession": {"type": "apiKey", "in": "cookie", "name": "gateway_admin_session"},
        },
        "parameters": {
            "CsrfToken": {"name": "X-CSRF-Token", "in": "header", "required": True, "schema": {"type": "string", "minLength": 16}},
            "IfMatch": {"name": "If-Match", "in": "header", "required": True, "schema": {"type": "string", "pattern": '^"rev-[1-9][0-9]*"$'}},
            "IdempotencyKey": {"name": "Idempotency-Key", "in": "header", "required": True, "schema": {"type": "string", "minLength": 8, "maxLength": 128}},
            "PageSize": {"name": "page[size]", "in": "query", "required": False, "schema": {"type": "integer", "default": 20, "minimum": 1, "maximum": 100}},
            "PageAfter": {"name": "page[after]", "in": "query", "required": False, "schema": {"type": "string"}},
        },
        "schemas": {
            "EmptyCommand": object_schema({}),
            "LoginCommand": object_schema({
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "minLength": 1, "maxLength": 128, "writeOnly": True},
            }, ["username", "password"]),
            "TotpCommand": object_schema({
                "code": {"type": "string", "pattern": "^[0-9]{6}$", "writeOnly": True},
            }, ["code"]),
            "PasswordChangeCommand": object_schema({
                "current_password": {"type": "string", "minLength": 1, "maxLength": 128, "writeOnly": True},
                "new_password": {"type": "string", "minLength": 14, "maxLength": 128, "writeOnly": True},
            }, ["current_password", "new_password"]),
            "StepUpCommand": object_schema({
                "purpose": enum_schema("step_up_purpose"),
                "current_password": {"type": "string", "minLength": 1, "maxLength": 128, "writeOnly": True},
                "totp_code": {"type": "string", "pattern": "^[0-9]{6}$", "writeOnly": True},
            }, ["purpose", "current_password", "totp_code"]),
            "UserCreateCommand": object_schema({
                "username": {"type": "string", "minLength": 1}, "display_name": {"type": "string", "minLength": 1},
                "email": {"type": "string", "format": "email"}, "role": {"type": "string", "const": "key_owner"},
                "temporary_password": {"type": "string", "minLength": 14, "maxLength": 128, "writeOnly": True},
            }, ["username", "display_name", "email", "role", "temporary_password"]),
            "PlatformKeyCreateCommand": object_schema({
                "name": {"type": "string"}, "owner_user_id": {"type": "string"}, "group_id": {"type": "string"},
                "expires_at": {"type": ["string", "null"], "format": "date-time"},
                "endpoint_permissions": {"type": "array", "items": {"type": "string", "enum": ["messages", "models"]}, "minItems": 1, "uniqueItems": True},
                "body_limit_bytes": {"type": "integer", "minimum": 1},
                "messages_rate": {"$ref": "#/components/schemas/RateLimit"}, "models_rate": {"$ref": "#/components/schemas/RateLimit"},
                "concurrency": object_schema({"limit": {"type": "integer", "minimum": 1, "default": 5}, "retry_after_ms": {"type": "integer", "minimum": 1}}, ["limit", "retry_after_ms"]),
                "requested_content_audit": enum_schema("content_audit_requested_mode"),
                "content_audit_approval_case_id": {"type": ["string", "null"], "format": "uuid"},
                "content_audit_expires_at": {"type": ["string", "null"], "format": "date-time"},
            }, ["name", "owner_user_id", "group_id", "endpoint_permissions", "body_limit_bytes", "messages_rate", "models_rate", "concurrency", "requested_content_audit"]),
            "PlatformKeyRevealCommand": object_schema({
                "step_up_grant_id": {"type": "string"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["step_up_grant_id", "reason"]),
            "PlatformKeyRevokeCommand": object_schema({
                "step_up_grant_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": "integer", "minimum": 1},
            }, ["step_up_grant_id", "reason"]),
            "GroupCreateCommand": object_schema({
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
            }, ["name"]),
            "RateLimit": object_schema({"rpm": {"type": "integer", "minimum": 1}, "burst": {"type": "integer", "minimum": 1}}, ["rpm", "burst"]),
            "GroupConfigCandidate": object_schema({
                "accepted_client_classes": {"type": "array", "items": enum_schema("client_class"), "minItems": 1, "uniqueItems": True},
                "fully_managed_required": {"type": "boolean", "default": False}, "egress_mode": {"type": "string", "enum": ["auto", "direct_only", "proxy_only"]},
                "limits": object_schema({
                    "concurrency": {"type": ["integer", "null"], "minimum": 1},
                    "messages_rpm": {"type": ["integer", "null"], "minimum": 1},
                    "messages_burst": {"type": ["integer", "null"], "minimum": 1},
                }, ["concurrency", "messages_rpm", "messages_burst"]),
                "credential_defaults": object_schema({"concurrency": {"type": "integer", "minimum": 1, "default": 5}, "messages_rpm": {"type": "integer", "minimum": 1, "default": 60}}, ["concurrency", "messages_rpm"]),
                "queue": object_schema({"pre_upstream_timeout_ms": {"type": "integer", "minimum": 1, "default": 30000}}, ["pre_upstream_timeout_ms"], additional=True),
                "timeouts": object_schema({
                    "upstream_connect_ms": {"type": "integer", "minimum": 1000, "maximum": 30000, "default": 5000},
                    "upstream_non_stream_total_ms": {"type": "integer", "minimum": 1, "default": 300000},
                    "upstream_stream_idle_ms": {"type": "integer", "minimum": 5000, "maximum": 600000, "default": 30000},
                }, ["upstream_connect_ms", "upstream_non_stream_total_ms", "upstream_stream_idle_ms"], additional=True),
                "content_audit": object_schema({"policy": enum_schema("content_audit_group_policy"), "retention_days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 7}}, ["policy", "retention_days"], additional=True),
            }, ["accepted_client_classes", "fully_managed_required", "egress_mode", "limits", "credential_defaults", "queue", "timeouts", "content_audit"], additional=True),
            "GroupConfigRollbackCommand": object_schema({
                "target_version": {"type": "integer", "minimum": 1},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": "integer", "minimum": 1},
                "approval_case_id": {"type": ["string", "null"], "format": "uuid"},
            }, ["target_version", "reason"]),
            "ProxyCreateCommand": object_schema({
                "name": {"type": "string"}, "type": enum_schema("proxy_type"), "host": {"type": "string"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535}, "username": {"type": ["string", "null"]},
                "password": {"type": ["string", "null"], "writeOnly": True}, "stability": {"type": "string", "const": "static"},
                "max_active_credentials": {"type": "integer", "minimum": 1, "default": 5},
            }, ["name", "type", "host", "port", "stability", "max_active_credentials"]),
            "ProxyPatchCommand": object_schema({
                "name": {"type": ["string", "null"], "minLength": 1, "maxLength": 128},
                "max_active_credentials": {"type": ["integer", "null"], "minimum": 1, "maximum": 1000},
            }),
            "CredentialSchedulingPatchCommand": object_schema({
                "priority": {"type": "integer", "minimum": 0, "maximum": 65535},
                "weight": {"type": "integer", "minimum": 1, "maximum": 4294967},
                "concurrency": {"type": ["integer", "null"], "minimum": 1, "maximum": 2147483647},
                "messages_rpm": {"type": ["integer", "null"], "minimum": 1, "maximum": 2147483647},
            }),
            "ProfileCohortCommand": object_schema({
                "target_archetype_version_id": {"type": "string", "format": "uuid"},
                "target_capture_cohort": {"type": "string", "minLength": 1, "maxLength": 128},
                "allow_explicit_rollback": {"type": "boolean", "default": False},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": ["integer", "null"], "minimum": 1},
            }, ["target_archetype_version_id", "target_capture_cohort", "reason"]),
            "DeviceIdentityRebuildCommand": object_schema({
                "approval_case_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": ["integer", "null"], "minimum": 1},
            }, ["approval_case_id", "reason"]),
            "ProxyReplaceSecretCommand": object_schema({
                "username": {"type": "string", "minLength": 1, "maxLength": 1024},
                "password": {"type": "string", "minLength": 1, "maxLength": 4096, "writeOnly": True},
                "step_up_grant_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": "integer", "minimum": 1},
            }, ["username", "password", "step_up_grant_id", "reason"]),
            "CapabilityRule": object_schema({
                "id": {"type": "string", "minLength": 1, "maxLength": 128},
                "path": {"type": "string", "minLength": 1, "maxLength": 1024},
                "action": {"type": "string", "enum": ["required", "allowed", "forbidden"]},
                "types": {"type": "array", "uniqueItems": True, "items": {"type": "string", "enum": ["null", "boolean", "integer", "number", "string", "array", "object"]}},
                "enum_values": {"type": "array", "maxItems": 1024},
                "minimum": {"type": ["number", "null"]}, "maximum": {"type": ["number", "null"]},
                "required_children": {"type": "array", "uniqueItems": True, "maxItems": 32, "items": {"type": "string"}},
                "when": {"type": "object", "required": ["op"], "properties": {"op": {"type": "string"}}, "additionalProperties": True},
            }, ["id", "path", "action", "types", "enum_values", "minimum", "maximum", "required_children", "when"]),
            "CapabilityCreateCommand": object_schema({
                "model_id": {"type": "string", "format": "uuid"},
                "schema_version": {"type": "integer", "const": 1},
                "rules": {"type": "array", "minItems": 1, "maxItems": 4096, "items": {"$ref": "#/components/schemas/CapabilityRule"}},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["model_id", "schema_version", "rules", "reason"]),
            "CapabilityActionCommand": object_schema({
                "reason": {"type": ["string", "null"], "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": ["integer", "null"], "minimum": 1},
            }),
            "ModelLifecycleCommand": object_schema({
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": ["integer", "null"], "minimum": 1},
            }, ["reason"]),
            "PriceEntryCommand": object_schema({
                "model_id": {"type": "string", "format": "uuid"},
                "input_per_million": {"type": "string", "pattern": "^[0-9]+(?:\\.[0-9]{1,12})?$"},
                "output_per_million": {"type": "string", "pattern": "^[0-9]+(?:\\.[0-9]{1,12})?$"},
                "cache_write_per_million": {"type": "string", "pattern": "^[0-9]+(?:\\.[0-9]{1,12})?$"},
                "cache_read_per_million": {"type": "string", "pattern": "^[0-9]+(?:\\.[0-9]{1,12})?$"},
            }, ["model_id", "input_per_million", "output_per_million", "cache_write_per_million", "cache_read_per_million"]),
            "PriceVersionCreateCommand": object_schema({
                "effective_from": {"type": "string", "format": "date-time"},
                "effective_to": {"type": ["string", "null"], "format": "date-time"},
                "currency": {"type": "string", "const": "USD"},
                "source_uri": {"type": ["string", "null"], "maxLength": 2048},
                "entries": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"$ref": "#/components/schemas/PriceEntryCommand"}},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["effective_from", "currency", "entries", "reason"]),
            "TypedArtifactCreateCommand": object_schema({
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "schema_version": {"type": "integer", "const": 1},
                "payload": {"type": "object", "additionalProperties": True},
                "source_refs": {"type": "array", "maxItems": 128, "items": {"type": "string", "minLength": 1, "maxLength": 2048}},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["name", "schema_version", "payload", "reason"]),
            "BackgroundCatalogSample": object_schema({
                "headers": {
                    "type": "object",
                    "maxProperties": 32,
                    "propertyNames": {"pattern": "^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$"},
                    "additionalProperties": {"type": "string", "maxLength": 1024},
                },
                "body": {"type": "object", "additionalProperties": True},
                "client_class": enum_schema("client_class"),
                "expected_entry_id": {"type": "string", "minLength": 1, "maxLength": 128},
            }, ["body", "client_class", "expected_entry_id"]),
            "PolicyArtifactActionCommand": object_schema({
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": ["integer", "null"], "minimum": 1},
                "approval_case_id": {"type": ["string", "null"], "format": "uuid"},
                "samples": {
                    "type": "array",
                    "maxItems": 10000,
                    "items": {"$ref": "#/components/schemas/BackgroundCatalogSample"},
                },
            }, ["reason"]),
            "RuleAction": {
                "oneOf": [
                    object_schema({
                        "action": {"type": "string", "const": "set_default"},
                        "path": {"type": "string", "pattern": "^body:/"},
                        "value": {},
                    }, ["action", "path", "value"]),
                    object_schema({
                        "action": {"type": "string", "const": "set"},
                        "path": {"type": "string", "pattern": "^body:/"},
                        "value": {},
                    }, ["action", "path", "value"]),
                    object_schema({
                        "action": {"type": "string", "const": "remove"},
                        "path": {"type": "string", "pattern": "^body:/"},
                    }, ["action", "path"]),
                    object_schema({
                        "action": {"type": "string", "const": "clamp_number"},
                        "path": {"type": "string", "pattern": "^body:/"},
                        "minimum": {"type": ["number", "null"]},
                        "maximum": {"type": ["number", "null"]},
                    }, ["action", "path", "minimum", "maximum"]),
                ]
            },
            "RuleDefinition": object_schema({
                "id": {"type": "string", "minLength": 1, "maxLength": 256},
                "phase": {"type": "string", "enum": ["structure_repair", "default", "range", "system", "tools", "thinking_cache", "beta_metadata"]},
                "action": {"$ref": "#/components/schemas/RuleAction"},
                "when": {"type": "object", "required": ["op"], "properties": {"op": {"type": "string"}}, "additionalProperties": True},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "risk": {"type": "string", "enum": ["low", "medium", "high"]},
            }, ["id", "phase", "action", "when", "reason", "risk"]),
            "RuleSetCreateCommand": object_schema({
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "schema_version": {"type": "integer", "const": 1},
                "scope_type": {"type": "string", "enum": ["group", "platform_key"]},
                "scope_id": {"type": "string", "format": "uuid"},
                "rules": {"type": "array", "minItems": 1, "maxItems": 1024, "items": {"$ref": "#/components/schemas/RuleDefinition"}},
                "source_refs": {"type": "array", "maxItems": 128, "items": {"type": "string", "minLength": 1, "maxLength": 2048}},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["name", "schema_version", "scope_type", "scope_id", "rules", "reason"]),
            "RuleSetActionCommand": object_schema({
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": ["integer", "null"], "minimum": 1},
            }, ["reason"]),
            "RuleSetSimulationCommand": object_schema({
                "request": {"type": "object", "additionalProperties": True},
                "client_class": enum_schema("client_class"),
                "traffic_class": {"type": "object", "required": ["kind"], "properties": {"kind": {"type": "string", "enum": ["normal", "explicit_probe", "suspected_probe", "internal_upstream_probe"]}}, "additionalProperties": True},
                "protocol_headers": {"type": "object", "propertyNames": {"enum": ["anthropic-version", "anthropic-beta"]}, "additionalProperties": {"type": "string", "minLength": 1, "maxLength": 1024}, "maxProperties": 2},
            }, ["request", "client_class", "traffic_class"]),
            "EnvironmentArchetypeCapacity": object_schema({
                "max_credentials": {"type": "integer", "minimum": 1},
                "max_connections": {"type": "integer", "minimum": 1},
                "allocation_weight": {"type": "integer", "minimum": 1},
                "allocation_cohort": {"type": "string", "minLength": 1, "maxLength": 256},
            }, ["max_credentials", "max_connections", "allocation_weight", "allocation_cohort"]),
            "EnvironmentArchetypePayload": object_schema({
                "os_family": {"type": "string", "enum": ["windows", "macos", "linux"]},
                "architecture": {"type": "string", "enum": ["x86_64", "aarch64"]},
                "os_build": {"type": "string", "minLength": 1, "maxLength": 256},
                "client_family": {"type": "string", "const": "claude_code_cli"},
                "runtime": {"type": "string", "minLength": 1, "maxLength": 256},
                "runtime_version": {"type": "string", "minLength": 1, "maxLength": 256},
                "client_version": {"type": "string", "minLength": 1, "maxLength": 256},
                "profile_schema_version": {"type": "integer", "minimum": 1},
                "capture_cohort": {"type": "string", "minLength": 1, "maxLength": 256},
                "protocol_profile": {"type": "object", "additionalProperties": True},
                "evidence_set_id": {"type": ["string", "null"], "format": "uuid"},
                "capacity": {"$ref": "#/components/schemas/EnvironmentArchetypeCapacity"},
            }, ["os_family", "architecture", "os_build", "client_family", "runtime", "runtime_version", "client_version", "profile_schema_version", "capture_cohort", "protocol_profile", "evidence_set_id", "capacity"]),
            "EnvironmentArchetypeCreateCommand": object_schema({
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "schema_version": {"type": "integer", "const": 1},
                "archetype_id": {"type": ["string", "null"], "format": "uuid"},
                "payload": {"$ref": "#/components/schemas/EnvironmentArchetypePayload"},
                "source_refs": {"type": "array", "maxItems": 128, "items": {"type": "string", "minLength": 1, "maxLength": 2048}},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["name", "schema_version", "payload", "reason"]),
            "TransportBundleCreateCommand": object_schema({
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "schema_version": {"type": "integer", "const": 1},
                "signed_envelope": {"type": "object", "additionalProperties": True},
                "source_refs": {"type": "array", "maxItems": 128, "items": {"type": "string", "minLength": 1, "maxLength": 2048}},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["name", "schema_version", "signed_envelope", "reason"]),
            "TransportBundleActivateCommand": object_schema({
                "approval_case_id": {"type": "string", "format": "uuid"},
                "step_up_grant_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": ["integer", "null"], "minimum": 1},
            }, ["approval_case_id", "step_up_grant_id", "reason"]),
            "PlanMappingCreateCommand": object_schema({"mapping": {"type": "object", "additionalProperties": {"type": "string"}}, "reason": {"type": "string"}}, ["mapping", "reason"]),
            "ApprovalCreateCommand": object_schema({
                "kind": enum_schema("approval_kind"), "scope": {"type": "object", "additionalProperties": True},
                "reason": {"type": "string", "minLength": 1},
                "action_snapshot_digest": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$",
                    "description": "SHA-256 of versioned UTF-8 canonical JSON; object keys sorted recursively and array order preserved.",
                },
                "step_up_grant_id": {"type": "string"},
            }, ["kind", "scope", "reason", "action_snapshot_digest", "step_up_grant_id"]),
            "ApprovalDecisionCommand": object_schema({
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "step_up_grant_id": {"type": "string"},
            }, ["reason", "step_up_grant_id"]),
            "ContentAuditSearchFilters": object_schema({
                "request_id": {"type": ["string", "null"], "format": "uuid"},
                "owner_user_id": {"type": ["string", "null"], "format": "uuid"},
                "platform_key_id": {"type": ["string", "null"], "format": "uuid"},
                "group_id": {"type": ["string", "null"], "format": "uuid"},
                "attempt_id": {"type": ["string", "null"], "format": "uuid"},
                "object_kind": {"type": ["string", "null"], "enum": ["original_request", "final_upstream_request", "upstream_response", None]},
                "created_from": {"type": ["string", "null"], "format": "date-time"},
                "created_to": {"type": ["string", "null"], "format": "date-time"},
            }),
            "ModelRefreshCommand": object_schema({
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["reason"]),
            "ContentAuditSearchCommand": object_schema({
                "approval_case_id": {"type": "string", "format": "uuid"},
                "step_up_grant_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "filters": {"$ref": "#/components/schemas/ContentAuditSearchFilters"},
            }, ["approval_case_id", "step_up_grant_id", "reason", "filters"]),
            "ContentAuditExportCommand": object_schema({
                "search_session_id": {"type": "string", "format": "uuid"},
                "approval_case_id": {"type": "string", "format": "uuid"},
                "step_up_grant_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["search_session_id", "approval_case_id", "step_up_grant_id", "reason"]),
            "ContentAuditExportEnvelope": object_schema({
                "data": object_schema({
                    "id": {"type": "string", "format": "uuid"},
                    "job_id": {"type": "string", "format": "uuid"},
                    "dataset": {"type": "string", "const": "content_audit_record_v1"},
                    "format": {"type": "string", "const": "raw"},
                    "state": {"type": "string", "const": "queued"},
                    "revision": {"type": "integer", "minimum": 1},
                    "created_at": {"type": "string", "format": "date-time"},
                }, ["id", "job_id", "dataset", "format", "state", "revision", "created_at"]),
                "meta": {"$ref": "../schemas/common.schema.json#/$defs/Meta"},
            }, ["data", "meta"]),
            "LegalHoldCreateCommand": object_schema({
                "name": {"type": "string", "minLength": 1, "maxLength": 256},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "approval_case_id": {"type": "string", "format": "uuid"},
                "review_due_at": {"type": ["string", "null"], "format": "date-time"},
                "objects": {"type": "array", "minItems": 1, "maxItems": 10000, "items": object_schema({
                    "content_audit_object_id": {"type": "string", "format": "uuid"},
                }, ["content_audit_object_id"])},
            }, ["name", "reason", "approval_case_id", "objects"]),
            "LegalHoldActionCommand": object_schema({
                "approval_case_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": "integer", "minimum": 1},
            }, ["approval_case_id", "reason", "expected_revision"]),
            "ContentPurgeCommand": object_schema({
                "approval_case_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "object_ids": {"type": "array", "minItems": 1, "maxItems": 10000, "uniqueItems": True,
                               "items": {"type": "string", "format": "uuid"}},
            }, ["approval_case_id", "reason", "object_ids"]),
            "KeyRotationCommand": object_schema({
                "approval_case_id": {"type": "string", "format": "uuid"},
                "step_up_grant_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_key_version": {"type": "integer", "minimum": 1},
                "batch_size": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 256},
            }, ["approval_case_id", "step_up_grant_id", "reason", "expected_key_version", "batch_size"]),
            "KeyLifecycleCommand": object_schema({
                "approval_case_id": {"type": "string", "format": "uuid"},
                "step_up_grant_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "key_version": {"type": "integer", "minimum": 1},
                "target_state": {"type": "string", "enum": ["retired", "destroyed"]},
                "rotation_job_id": {"type": "string", "format": "uuid"},
                "backup_run_id": {"type": "string", "format": "uuid"},
                "restore_drill_id": {"type": "string", "format": "uuid"},
            }, ["approval_case_id", "step_up_grant_id", "reason", "key_version", "target_state",
                "rotation_job_id", "backup_run_id", "restore_drill_id"]),
            "BackupJobCommand": object_schema({
                "step_up_grant_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["step_up_grant_id", "reason"]),
            "UpgradeCheckCommand": object_schema({
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "release_manifest": {"$ref": "../schemas/release-evidence.schema.json#/$defs/ReleaseManifest"},
            }, ["reason", "release_manifest"]),
            "RestoreOperationCommand": object_schema({
                "backup_run_id": {"type": "string", "format": "uuid"},
                "recovery_point": {"type": ["string", "null"], "format": "date-time"},
                "step_up_grant_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
            }, ["backup_run_id", "step_up_grant_id", "reason"]),
            "AlertSilenceCreateCommand": object_schema({
                "fingerprint_pattern": {"type": "string", "minLength": 1, "maxLength": 512},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "starts_at": {"type": ["string", "null"], "format": "date-time"},
                "expires_at": {"type": "string", "format": "date-time"},
            }, ["fingerprint_pattern", "reason", "expires_at"]),
            "NotificationChannelCreateCommand": object_schema({
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "enabled": {"type": "boolean", "default": True},
                "severities": {"type": "array", "minItems": 1, "maxItems": 3, "uniqueItems": True,
                               "items": {"type": "string", "enum": ["info", "warning", "critical"]}},
                "alert_types": {"type": "array", "maxItems": 100, "uniqueItems": True,
                                "items": {"type": "string", "minLength": 1, "maxLength": 128}},
                "group_ids": {"type": "array", "maxItems": 100, "uniqueItems": True,
                              "items": {"type": "string", "format": "uuid"}},
                "send_recovery": {"type": "boolean", "default": True},
                "provider": object_schema({
                    "kind": {"type": "string", "const": "serverchan3"},
                    "send_key": {"type": "string", "minLength": 8, "maxLength": 512, "writeOnly": True},
                }, ["kind", "send_key"]),
            }, ["name", "enabled", "severities", "alert_types", "group_ids", "send_recovery", "provider"]),
            "NotificationChannelTestCommand": object_schema({
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": "integer", "minimum": 1},
            }, ["reason", "expected_revision"]),
            "ReasonActionCommand": object_schema({
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": "integer", "minimum": 1},
            }, ["reason"]),
            "CredentialGroupMigrationCommand": object_schema({
                "target_group_id": {"type": "string", "format": "uuid"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_revision": {"type": "integer", "minimum": 1},
            }, ["target_group_id", "reason"]),
            "EgressRebindCommand": object_schema({
                "target": {"oneOf": [
                    object_schema({"mode": {"const": "direct"}}, ["mode"]),
                    object_schema({
                        "mode": {"const": "proxy"},
                        "proxy_id": {"type": "string", "format": "uuid"},
                    }, ["mode", "proxy_id"]),
                ]},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2048},
                "expected_profile_epoch": {"type": "integer", "minimum": 1},
                "expected_egress_epoch": {"type": "integer", "minimum": 1},
            }, ["target", "reason", "expected_profile_epoch", "expected_egress_epoch"]),
            "UsageExportCreateCommand": object_schema({
                "dataset": {"type": "string", "const": "usage_requests_v1"},
                "format": {"type": "string", "enum": ["jsonl", "csv"]},
                "scope": {"type": "string", "enum": ["own", "all"]},
                "from": {"type": "string", "format": "date-time"},
                "to": {"type": "string", "format": "date-time"},
                "filters": object_schema({
                    "platform_key_id": {"type": ["string", "null"], "format": "uuid"},
                    "group_id": {"type": ["string", "null"], "format": "uuid"},
                    "model_id": {"type": ["string", "null"], "format": "uuid"},
                    "completeness": {"type": ["string", "null"], "enum": ["complete", "partial", "unknown", None]},
                }),
            }, ["dataset", "format", "scope", "from", "to"]),
            "UsageExportEnvelope": object_schema({
                "data": object_schema({
                    "id": {"type": "string", "format": "uuid"},
                    "job_id": {"type": ["string", "null"], "format": "uuid"},
                    "dataset": {"type": "string", "const": "usage_requests_v1"},
                    "format": {"type": "string", "enum": ["jsonl", "csv"]},
                    "scope": {"type": "string", "enum": ["own", "all"]},
                    "state": {"type": "string", "enum": ["queued", "running", "succeeded", "failed", "expired"]},
                    "row_count": {"type": ["integer", "null"], "minimum": 0, "maximum": 10000},
                    "content_length": {"type": ["integer", "null"], "minimum": 0, "maximum": 33554432},
                    "created_at": {"type": "string", "format": "date-time"},
                    "completed_at": {"type": ["string", "null"], "format": "date-time"},
                    "expires_at": {"type": ["string", "null"], "format": "date-time"},
                    "download_count": {"type": "integer", "minimum": 0, "maximum": 1},
                    "downloaded_at": {"type": ["string", "null"], "format": "date-time"},
                    "error_code": {"type": ["string", "null"]},
                    "download_available": {"type": "boolean"},
                    "revision": {"type": "integer", "minimum": 1},
                }, ["id", "dataset", "format", "scope", "state", "revision"]),
                "meta": {"$ref": "../schemas/common.schema.json#/$defs/Meta"},
            }, ["data", "meta"]),
            "ResourcePatchCommand": object_schema({
                "name": {"type": "string"}, "display_name": {"type": "string"}, "email": {"type": "string", "format": "email"},
                "expires_at": {"type": ["string", "null"], "format": "date-time"},
                "priority": {"type": "integer"}, "weight": {"type": "integer", "minimum": 1},
                "concurrency": {"type": ["integer", "null"], "minimum": 1}, "messages_rpm": {"type": ["integer", "null"], "minimum": 1},
            }),
            "CredentialEnrollmentEnvelope": object_schema({"data": {"$ref": "../schemas/credential.schema.json#/$defs/CredentialEnrollment"}, "meta": {"$ref": "../schemas/common.schema.json#/$defs/Meta"}}, ["data", "meta"]),
            "EnrollmentMaterialCommand": object_schema({
                "setup_token": {"type": "string", "minLength": 1, "maxLength": 32768, "writeOnly": True},
                "access_token": {"type": "string", "minLength": 1, "maxLength": 32768, "writeOnly": True},
                "refresh_token": {"type": "string", "minLength": 1, "maxLength": 32768, "writeOnly": True},
                "console_api_key": {"type": "string", "minLength": 1, "maxLength": 32768, "writeOnly": True},
            }),
            "OAuthCallbackCommand": object_schema({
                "authorization_code": {"type": "string", "minLength": 1, "maxLength": 32768, "writeOnly": True},
                "state": {"type": "string", "minLength": 1, "maxLength": 1024, "writeOnly": True},
                "callback_nonce": {"type": "string", "minLength": 1, "maxLength": 1024, "writeOnly": True},
            }, ["authorization_code", "state", "callback_nonce"]),
            "MaintenanceOperationListEnvelope": object_schema({"data": {"type": "array", "items": {"$ref": "../schemas/maintenance.schema.json#/$defs/CredentialMaintenanceOperation"}}, "page": {"$ref": "../schemas/common.schema.json#/$defs/Page"}, "meta": {"$ref": "../schemas/common.schema.json#/$defs/Meta"}}, ["data", "page", "meta"]),
            "AutoReauthStrategyEnvelope": object_schema({"data": {"$ref": "../schemas/credential.schema.json#/$defs/AutoReauthStrategy"}, "meta": {"$ref": "../schemas/common.schema.json#/$defs/Meta"}}, ["data", "meta"]),
            "UsageObservationListEnvelope": object_schema({"data": {"type": "array", "items": {"$ref": "../schemas/usage-plan.schema.json#/$defs/UsageObservation"}}, "page": {"$ref": "../schemas/common.schema.json#/$defs/Page"}, "meta": {"$ref": "../schemas/common.schema.json#/$defs/Meta"}}, ["data", "page", "meta"]),
            "SystemStatusEnvelope": object_schema({"data": {"$ref": "../schemas/common.schema.json#/$defs/ReadinessReport"}, "meta": {"$ref": "../schemas/common.schema.json#/$defs/Meta"}}, ["data", "meta"]),
        },
        "responses": {
            "BadRequest": {"description": "Invalid request", "content": {"application/json": {"schema": {"$ref": "../schemas/common.schema.json#/$defs/ErrorEnvelope"}}}},
            "Unauthorized": {"description": "Invalid admin session", "content": {"application/json": {"schema": {"$ref": "../schemas/common.schema.json#/$defs/ErrorEnvelope"}}}},
            "Forbidden": {"description": "Role, step-up or approval rejected", "content": {"application/json": {"schema": {"$ref": "../schemas/common.schema.json#/$defs/ErrorEnvelope"}}}},
            "NotFound": {"description": "Resource is outside the actor scope or absent", "content": {"application/json": {"schema": {"$ref": "../schemas/common.schema.json#/$defs/ErrorEnvelope"}}}},
            "Conflict": {"description": "Revision, uniqueness or idempotency conflict", "content": {"application/json": {"schema": {"$ref": "../schemas/common.schema.json#/$defs/ErrorEnvelope"}}}},
            "PreconditionRequired": {"description": "If-Match is required", "content": {"application/json": {"schema": {"$ref": "../schemas/common.schema.json#/$defs/ErrorEnvelope"}}}},
        },
    }


def generate_admin_openapi() -> list[dict[str, Any]]:
    routes = parse_admin_routes()
    paths: dict[str, Any] = {}
    for route in routes:
        method, path = route["method"], route["path"]
        parameters: list[dict[str, Any]] = []
        for name in re.findall(r"\{([^}]+)\}", path):
            parameters.append({"name": name, "in": "path", "required": True, "schema": {"type": "string"}})
        if method == "get" and path == "/admin/v1/content-audit/records/{id}":
            parameters.append({
                "name": "search_session_id", "in": "query", "required": True,
                "schema": {"type": "string", "format": "uuid"},
                "description": "Approval-bound Content Audit search session containing this record.",
            })
        elif method == "get" and path != "/admin/v1/exports/{id}/download":
            parameters.extend([{"$ref": "#/components/parameters/PageSize"}, {"$ref": "#/components/parameters/PageAfter"}])
        if method not in {"get", "head"}:
            parameters.append({"$ref": "#/components/parameters/CsrfToken"})
        if needs_if_match(path, method):
            parameters.append({"$ref": "#/components/parameters/IfMatch"})
        if needs_idempotency(path, method):
            parameters.append({"$ref": "#/components/parameters/IdempotencyKey"})
        status = "202" if is_async(path, method) else ("201" if method == "post" and ":" not in path else ("204" if method == "delete" else "200"))
        success_schema = ({"$ref": "#/components/schemas/UsageExportEnvelope"}
                          if path == "/admin/v1/exports"
                          else ({"$ref": "#/components/schemas/ContentAuditExportEnvelope"}
                                if path == "/admin/v1/content-audit/records/{id}:export"
                          else ({"$ref": "../schemas/common.schema.json#/$defs/JobEnvelope"}
                                if status == "202" else {"$ref": response_ref(path, method)})))
        operation: dict[str, Any] = {
            "operationId": camel_operation(method, path), "tags": [route["tag"]],
            "summary": route["description"], "x-roles": roles_for(path, method, route["explicit_role"]),
            "parameters": parameters,
            "responses": {
                status: ({"description": "Success"} if status == "204" else {"description": "Success", "content": {"application/json": {"schema": success_schema}}}),
                "400": {"$ref": "#/components/responses/BadRequest"}, "401": {"$ref": "#/components/responses/Unauthorized"},
                "403": {"$ref": "#/components/responses/Forbidden"}, "404": {"$ref": "#/components/responses/NotFound"},
                "409": {"$ref": "#/components/responses/Conflict"},
            },
        }
        if needs_if_match(path, method):
            operation["responses"]["428"] = {"$ref": "#/components/responses/PreconditionRequired"}
        if method not in {"get", "head", "delete"}:
            operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": {"$ref": request_ref(path, method)}}}}
        if path == "/admin/v1/auth/login":
            operation["security"] = []
        if path == "/admin/v1/exports/{id}/download" and method == "get":
            operation["responses"][status] = {
                "description": "One-shot encrypted export download",
                "headers": {
                    "Cache-Control": {"schema": {"type": "string", "const": "no-store"}},
                    "Content-Disposition": {"schema": {"type": "string"}},
                    "X-Content-Type-Options": {"schema": {"type": "string", "const": "nosniff"}},
                },
                "content": {
                    "application/x-ndjson": {"schema": {"type": "string", "format": "binary"}},
                    "text/csv": {"schema": {"type": "string", "format": "binary"}},
                },
            }
        paths.setdefault(path, {})[method] = operation
    document = {
        "openapi": "3.1.0", "info": {"title": "Super Gateway Admin API", "version": "1.0.0-r0"},
        "servers": [{"url": "/"}], "security": [{"adminSession": []}], "paths": paths,
        "components": admin_components(),
        "x-generated-from": "planning/api-contract.md", "x-route-count": len(routes),
    }
    write_json(OPENAPI / "admin.openapi.json", document)
    write_json(CONTRACTS / "registries" / "admin-routes.json", {"schema_version": "1.0.0", "routes": routes})
    return routes


def generate_data_openapi() -> None:
    anthropic_error = object_schema({
        "type": {"type": "string", "const": "error"},
        "error": object_schema({"type": {"type": "string"}, "message": {"type": "string"}}, ["type", "message"]),
        "request_id": {"type": "string"},
    }, ["type", "error", "request_id"])
    message_request = object_schema({
        "model": {"type": "string", "minLength": 1}, "max_tokens": {"type": "integer", "minimum": 1},
        "messages": {"type": "array", "minItems": 1, "items": {"type": "object", "required": ["role", "content"], "properties": {"role": {"type": "string", "enum": ["user", "assistant"]}, "content": {}}, "additionalProperties": True}},
        "system": {}, "stream": {"type": "boolean", "default": False},
        "temperature": {"type": "number"}, "top_p": {"type": "number"}, "top_k": {"type": "integer"},
        "stop_sequences": {"type": "array", "items": {"type": "string"}}, "tools": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "tool_choice": {}, "thinking": {}, "metadata": {"type": "object", "additionalProperties": True},
        "output_config": {}, "context_management": {},
    }, ["model", "max_tokens", "messages"], additional=True)
    model = object_schema({
        "id": {"type": "string"}, "type": {"type": "string", "const": "model"},
        "display_name": {"type": "string"}, "created_at": {"type": "string", "format": "date-time"},
    }, ["id", "type", "display_name", "created_at"])
    source_header = {
        "description": "Declares that the probe response was generated by the gateway.",
        "required": True,
        "schema": {"type": "string", "const": "gateway"},
    }
    retry_after_header = {
        "description": "Whole seconds until the source-IP probe bucket can accept another request.",
        "required": True,
        "schema": {"type": "integer", "minimum": 1},
    }
    probe_rate_limited = {
        "description": "The isolated source-IP probe bucket is exhausted.",
        "headers": {
            "x-gateway-response-source": source_header,
            "retry-after": retry_after_header,
        },
        "content": {
            "application/json": {
                "schema": {"$ref": "../schemas/common.schema.json#/$defs/PublicProbeRateLimited"}
            }
        },
    }
    document = {
        "openapi": "3.1.0", "info": {"title": "Super Gateway Data Plane", "version": "1.0.0-r0"},
        "servers": [{"url": "/"}],
        "security": [{"xApiKey": []}, {"bearerApiKey": []}],
        "paths": {
            "/v1/messages": {"post": {
                "operationId": "createMessage", "summary": "Validate and forward an Anthropic Messages request",
                "x-request-adjustment": "explicit-policy-only", "x-response-body-passthrough": "byte-exact",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/MessageRequest"}}}},
                "responses": {
                    "200": {"description": "Opaque Anthropic response; JSON or SSE is forwarded without body rewriting", "content": {
                        "application/json": {"schema": {}, "x-opaque-passthrough": True},
                        "text/event-stream": {"schema": {"type": "string"}, "x-opaque-passthrough": True},
                    }},
                    "400": {"$ref": "#/components/responses/DataError"}, "401": {"$ref": "#/components/responses/DataError"},
                    "403": {"$ref": "#/components/responses/DataError"}, "404": {"$ref": "#/components/responses/DataError"},
                    "429": {"$ref": "#/components/responses/DataError"}, "500": {"$ref": "#/components/responses/DataError"},
                    "503": {"$ref": "#/components/responses/DataError"}, "504": {"$ref": "#/components/responses/DataError"},
                },
            }},
            "/v1/models": {"get": {
                "operationId": "listModels", "summary": "List the Group published model snapshot",
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
                    {"name": "after_id", "in": "query", "schema": {"type": "string"}},
                    {"name": "before_id", "in": "query", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "Published models", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ModelList"}}}}, "401": {"$ref": "#/components/responses/DataError"}, "429": {"$ref": "#/components/responses/DataError"}},
            }},
            "/healthz": {
                "get": {
                    "operationId": "health",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Process is alive",
                            "headers": {"x-gateway-response-source": source_header},
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"status": {"const": "ok"}},
                                        "required": ["status"],
                                        "additionalProperties": False,
                                    }
                                }
                            },
                        },
                        "429": probe_rate_limited,
                    },
                }
            },
            "/readyz": {
                "get": {
                    "operationId": "readiness",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Ready",
                            "headers": {"x-gateway-response-source": source_header},
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "../schemas/common.schema.json#/$defs/PublicReadiness"}
                                }
                            },
                        },
                        "503": {
                            "description": "Not ready",
                            "headers": {"x-gateway-response-source": source_header},
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "../schemas/common.schema.json#/$defs/PublicReadiness"}
                                }
                            },
                        },
                        "429": probe_rate_limited,
                    },
                }
            },
        },
        "components": {
            "securitySchemes": {
                "xApiKey": {"type": "apiKey", "in": "header", "name": "x-api-key"},
                "bearerApiKey": {"type": "http", "scheme": "bearer"},
            },
            "schemas": {"MessageRequest": message_request, "Model": model,
                "ModelList": object_schema({"data": {"type": "array", "items": {"$ref": "#/components/schemas/Model"}}, "has_more": {"type": "boolean"}, "first_id": {"type": ["string", "null"]}, "last_id": {"type": ["string", "null"]}}, ["data", "has_more", "first_id", "last_id"]),
                "AnthropicError": anthropic_error,
            },
            "responses": {"DataError": {"description": "Anthropic-shaped platform error or transparent upstream error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AnthropicError"}}}}},
        },
        "x-public-route-policy": {"unknown_v1_requires_auth": True, "count_tokens_public": False, "websocket": False, "providers": ["anthropic_official"]},
    }
    write_json(OPENAPI / "data-plane.openapi.json", document)


def locate_line(lines: list[str], needle: str) -> int:
    for index, line in enumerate(lines, 1):
        if needle in line:
            return index
    raise ValueError(f"Source text not found: {needle}")


def source_ref(file: str, line: int, text: str) -> dict[str, Any]:
    return {"file": file, "line": line, "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def classify_decision(text: str) -> tuple[str, str]:
    checks = [
        (("TLS", "Transport", "Bundle", "Archetype", "ClientHello", "HTTP/2", "H2", "H1", "ALPN", "连接池"), ("transport", "R6")),
        (("Credential", "token", "Token", "Profile", "Egress", "代理", "PLAN", "重认证", "Browser", "OAuth", "账号"), ("credential", "R5")),
        (("队列", "并发", "RPM", "affinity", "Session", "session", "调度", "cooldown", "Reservation", "Lease"), ("scheduler", "R4")),
        (("SSE", "响应", "usage", "Usage", "成本", "attempt", "Attempt", "取消", "透传"), ("response-observability", "R7")),
        (("管理", "审批", "Content Audit", "Key Owner", "导出", "通知", "告警", "User"), ("admin", "R8")),
        (("备份", "WAL", "审计链", "KeyProvider", "RPO", "RTO", "恢复演练"), ("security-operations", "R9")),
        (("模型", "Capability", "RuleSet", "Enforcement", "请求校验", "客户端类型"), ("edge-policy", "R3")),
    ]
    for words, result in checks:
        if any(word in text for word in words):
            return result
    return "architecture", "R0"


def generate_ledger() -> None:
    functional_path = ROOT / "planning" / "functional-modules.md"
    functional_lines = functional_path.read_text(encoding="utf-8").splitlines()
    roadmap_path = ROOT / "planning" / "implementation-roadmap.md"
    roadmap_lines = roadmap_path.read_text(encoding="utf-8").splitlines()
    scheduler_path = ROOT / "planning" / "scheduler-design.md"
    scheduler_lines = scheduler_path.read_text(encoding="utf-8").splitlines()
    lifecycle_path = ROOT / "planning" / "credential-lifecycle.md"
    lifecycle_lines = lifecycle_path.read_text(encoding="utf-8").splitlines()
    transport_path = ROOT / "planning" / "transport-engine.md"
    transport_lines = transport_path.read_text(encoding="utf-8").splitlines()
    module_pattern = re.compile(r"^\|\s*(\d{2})\s+([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$")
    modules: list[tuple[int, str, str, str, int, str]] = []
    for line_no, line in enumerate(roadmap_lines, 1):
        match = module_pattern.match(line)
        if match:
            number, name, owner, _test_package, phase_expression = match.groups()
            phase_match = re.search(r"R\d+", phase_expression)
            if 1 <= int(number) <= 18 and phase_match:
                modules.append((int(number), name.strip(), owner.strip(), phase_match.group(0), line_no, line))
    if len(modules) != 18:
        raise ValueError(f"Expected 18 module rows, got {len(modules)}")
    start = next(i for i, line in enumerate(functional_lines) if line.startswith("## 12."))
    end = next(i for i, line in enumerate(functional_lines[start + 1:], start + 1) if line.startswith("## 13."))
    decisions: list[tuple[int, str, int, str]] = []
    for index in range(start + 1, end):
        match = re.match(r"^(\d+)\.\s+(.+)$", functional_lines[index])
        if match:
            decisions.append((int(match.group(1)), match.group(2).strip(), index + 1, functional_lines[index]))
    if [d[0] for d in decisions] != list(range(1, 133)):
        raise ValueError("Functional decisions must be exactly DEC-001..DEC-132")
    requirements: list[dict[str, Any]] = []
    tests: list[dict[str, Any]] = []
    for number, name, owner, phase, line_no, source_line in modules:
        rid, tid = f"REQ-F{number:02d}", f"CT-F{number:02d}-001"
        requirements.append({
            "requirement_id": rid, "kind": "functional_module", "title": name,
            "source": source_ref("planning/implementation-roadmap.md", line_no, source_line),
            "owner": owner, "phase": phase, "release_gate": "ga", "test_ids": [tid], "fixture_ids": [], "status": "implemented",
        })
        tests.append({"test_id": tid, "kind": "contract", "owner": owner, "phase": phase, "requirement_ids": [rid], "automation": "tools/validate_contracts.py"})
    for number, text, line_no, source_line in decisions:
        owner, phase = classify_decision(text)
        rid, tid = f"DEC-{number:03d}", f"CT-DEC-{number:03d}"
        requirements.append({
            "requirement_id": rid, "kind": "product_decision", "title": text,
            "source": source_ref("planning/functional-modules.md", line_no, source_line),
            "owner": owner, "phase": phase, "release_gate": "ga", "test_ids": [tid], "fixture_ids": [], "status": "planned",
        })
        tests.append({"test_id": tid, "kind": "decision_contract", "owner": owner, "phase": phase, "requirement_ids": [rid], "automation": "tools/validate_contracts.py"})
    r1_items = [
        ("REQ-R1-001", "Canonical Rust workspace and dependency boundaries", "生产 crate 结构以技术架构为准", "architecture", "tools/validate_workspace.py"),
        ("REQ-R1-002", "Composition root and strict static configuration", "范围：Cargo workspace、composition root、配置", "architecture", "cargo test -p super-gatewayd"),
        ("REQ-R1-003", "Privacy-safe health and readiness contracts", "范围：Cargo workspace、composition root、配置", "edge-policy", "cargo test -p gateway-api"),
        ("REQ-R1-004", "Deterministic testkit and synthetic Anthropic fixture", "并行：CI/reproducible build、testkit", "verification", "cargo test -p gateway-testkit"),
        ("REQ-R1-005", "CI quality gates and multi-target build lanes", "Exit：空业务骨架在Linux x86_64/arm64构建", "verification", ".github/workflows/ci.yml"),
        ("REQ-R1-006", "Release hashes, SBOM, provenance and evidence manifest", "每个artifact有hash/SBOM/provenance", "security-operations", "tools/build_release_evidence.py"),
    ]
    for rid, title, needle, owner, automation in r1_items:
        line_no = locate_line(roadmap_lines, needle)
        source_line = roadmap_lines[line_no - 1]
        tid = rid.replace("REQ-", "CT-")
        requirements.append({
            "requirement_id": rid, "kind": "phase_requirement", "title": title,
            "source": source_ref("planning/implementation-roadmap.md", line_no, source_line),
            "owner": owner, "phase": "R1", "release_gate": "ga", "test_ids": [tid],
            "fixture_ids": [], "status": "implemented",
        })
        tests.append({
            "test_id": tid, "kind": "phase_gate", "owner": owner, "phase": "R1",
            "requirement_ids": [rid], "automation": automation,
        })
    r2_items = [
        ("PostgreSQL 16 physical schema and role grants", "第一批：User/Session", "storage", "cargo test --locked -p gateway-storage --test postgres_r2", "FIX-R2-POSTGRES-001", "implemented"),
        ("Deterministic forward-only migration manifest", "并行：Schema/migration", "storage", "python -B tools/validate_contracts.py", "FIX-R2-MIGRATION-001", "implemented"),
        ("Empty database migration path", "Exit：空库与前两个release升级", "storage", "cargo test --locked -p gateway-storage --test postgres_r2", "FIX-R2-POSTGRES-001", "implemented"),
        ("N-1 and N-2 migration compatibility", "Exit：空库与前两个release升级", "storage", "cargo test --locked -p gateway-storage --test postgres_r2", "FIX-R2-UPGRADE-001", "planned"),
        ("Repository ports and transaction boundaries", "并行：Schema/migration", "storage", "cargo test --locked -p gateway-storage", "FIX-R2-POSTGRES-001", "implemented"),
        ("Database constraints and cross-table invariants", "Exit：空库与前两个release升级", "storage", "cargo test --locked -p gateway-storage --test postgres_r2", "FIX-R2-POSTGRES-001", "implemented"),
        ("Revision CAS and fixed lock order", "Exit：空库与前两个release升级", "storage", "cargo test --locked -p gateway-storage --test postgres_r2", "FIX-R2-CONCURRENCY-001", "implemented"),
        ("Secret envelope, lookup digest and AAD isolation", "并行：Schema/migration", "security-operations", "cargo test --locked -p gateway-services security", "FIX-R2-SECRET-001", "implemented"),
        ("Resumable business-key rotation", "Exit：空库与前两个release升级", "security-operations", "cargo test --locked -p gateway-services --test security_rotation_pg", "FIX-R2-ROTATION-001", "implemented"),
        ("Audit chain and daily seal verification", "并行：Schema/migration", "security-operations", "cargo test --locked -p gateway-storage", "FIX-R2-AUDIT-001", "implemented"),
        ("Business mutation, Audit and Outbox atomicity", "Exit：空库与前两个release升级", "storage", "cargo test --locked -p gateway-storage --test postgres_r2", "FIX-R2-POSTGRES-001", "implemented"),
        ("Durable Job lease generation and Outbox replay", "第一批：User/Session", "operations", "cargo test --locked -p gateway-storage --test postgres_r2", "FIX-R2-JOB-001", "implemented"),
        ("Credential Enrollment restart persistence", "第一批：User/Session", "credential", "cargo test --locked -p gateway-storage", "FIX-R2-ENROLLMENT-001", "implemented"),
        ("Empty-database bootstrap and existing-user ignore", "第一批：User/Session", "security-operations", "cargo test --locked -p gateway-storage --test postgres_r2", "FIX-R2-POSTGRES-001", "implemented"),
        ("Partition and cross-month integrity", "第一批：User/Session", "storage", "cargo test --locked -p gateway-storage", "FIX-R2-PARTITION-001", "implemented"),
        ("Backup manifest and isolated recoverability", "并行：Schema/migration", "security-operations", "python -B tools/r2_backup_restore.py", "FIX-R2-BACKUP-001", "implemented"),
        ("Schema, bootstrap and audit readiness composition", "Exit：空库与前两个release升级", "architecture", "cargo test --locked -p super-gatewayd", "FIX-R2-STARTUP-001", "implemented"),
        ("PostgreSQL CI evidence and fixture provenance", "Exit：空库与前两个release升级", "verification", ".github/workflows/ci.yml", "FIX-R2-POSTGRES-001", "implemented"),
    ]
    for index, (title, needle, owner, automation, fixture_id, status) in enumerate(r2_items, 1):
        rid = f"REQ-R2-{index:03d}"
        tid = f"CT-R2-{index:03d}"
        line_no = locate_line(roadmap_lines, needle)
        source_line = roadmap_lines[line_no - 1]
        requirements.append({
            "requirement_id": rid, "kind": "phase_requirement", "title": title,
            "source": source_ref("planning/implementation-roadmap.md", line_no, source_line),
            "owner": owner, "phase": "R2", "release_gate": "ga", "test_ids": [tid],
            "fixture_ids": [fixture_id], "status": status,
        })
        tests.append({
            "test_id": tid, "kind": "phase_gate", "owner": owner, "phase": "R2",
            "requirement_ids": [rid], "automation": automation,
        })
    r3_items = [
        ("Auth-first route/method matrix and hidden Count Tokens", "覆盖模块01–08", "edge-policy", "cargo test --locked -p gateway-api route_and_method", "FIX-R3-ROUTE-MATRIX-001"),
        ("Platform Key authentication, permission and source-IP access gates", "覆盖模块01–08", "edge-policy", "cargo test --locked -p gateway-api dual_auth", "FIX-R3-AUTH-ACCESS-001"),
        ("Messages media type, framing, body and lossless JSON contract", "覆盖模块01–08", "edge-policy", "cargo test --locked -p gateway-api framing_and_duplicate_json", "FIX-R3-MESSAGES-CORPUS-001"),
        ("Deterministic client/session/traffic classification", "覆盖模块01–08", "edge-policy", "cargo test --locked -p gateway-api", "FIX-R3-CLIENT-CORPUS-001"),
        ("Typed bounded Capability compilation and exact-model validation", "覆盖模块01–08", "edge-policy", "cargo test --locked -p gateway-policy capability", "FIX-R3-CAPABILITY-001"),
        ("Non-overridable Group Enforcement and four System modes", "Exit：API contract/golden/fuzz通过", "edge-policy", "cargo test --locked -p gateway-policy all_system_modes", "FIX-R3-SYSTEM-MODES-001"),
        ("Deterministic RuleSet order, change set and model immutability", "覆盖模块01–08", "edge-policy", "cargo test --locked -p gateway-policy rules_are_deterministic", "FIX-R3-RULESET-001"),
        ("Compatible unknown preservation, strict rejection and conservative Pin", "Exit：API contract/golden/fuzz通过", "edge-policy", "cargo test --locked -p gateway-policy", "FIX-R3-UNKNOWN-EXT-001"),
        ("Credential-neutral GenericAdjustedRequest replay invariants", "覆盖模块01–08", "edge-policy", "cargo test --locked -p gateway-policy zero_change_reuses", "FIX-R3-GENERIC-REQUEST-001"),
        ("Stable scoped and paginated published model catalog", "覆盖模块01–08", "edge-policy", "cargo test --locked -p gateway-api models_are_stable", "FIX-R3-MODELS-001"),
        ("Replayable parser, capability and RuleSet mutation corpus", "并行：HTTP handler；pure Policy", "verification", "cargo test --locked -p gateway-policy -p gateway-api", "FIX-R3-FUZZ-CORPUS-001"),
        ("Platform Key, Gateway and original client identity southbound leak gate", "Exit：API contract/golden/fuzz通过", "security-operations", "cargo test --locked -p gateway-api dual_auth", "FIX-R3-SECRET-CANARY-001"),
        ("Published Background Catalog deterministic action and suspected-observe invariant", "Background Catalog 的 `match_all`", "edge-policy", "cargo test --locked -p gateway-api published_background_action_applies_only", "FIX-R3-CLIENT-CORPUS-001"),
        ("Versioned Group Enforcement remains non-overridable by RuleSet", "Group Enforcement 是 Group Config", "edge-policy", "cargo test --locked -p gateway-policy ruleset_cannot_weaken_group_system_enforcement", "FIX-R3-SYSTEM-MODES-001"),
        ("Typed Policy Artifact validation and bounded payload compilation", "Background Catalog 的 `match_all`", "edge-policy", "cargo test --locked -p super-gatewayd policy_artifact_payloads_are_typed", "FIX-R3-CAPABILITY-001"),
    ]
    for index, (title, needle, owner, automation, fixture_id) in enumerate(r3_items, 1):
        rid = f"REQ-R3-{index:03d}"
        tid = f"CT-R3-{index:03d}"
        line_no = locate_line(roadmap_lines, needle)
        source_line = roadmap_lines[line_no - 1]
        requirements.append({
            "requirement_id": rid, "kind": "phase_requirement", "title": title,
            "source": source_ref("planning/implementation-roadmap.md", line_no, source_line),
            "owner": owner, "phase": "R3", "release_gate": "ga", "test_ids": [tid],
            "fixture_ids": [fixture_id], "status": "implemented",
        })
        tests.append({
            "test_id": tid, "kind": "phase_gate", "owner": owner, "phase": "R3",
            "requirement_ids": [rid], "automation": automation,
        })
    r4_items = [
        ("3 Credentials x5 and 10 Keys x4 capacity", "3 个 Credential × 并发 5", "cargo test --locked -p gateway-scheduler forty_requests", "FIX-R4-S01"),
        ("Single Platform Key hard concurrency", "40 个请求共用默认 Key", "cargo test --locked -p gateway-api key_concurrency", "FIX-R4-S02"),
        ("Group queue capacity and 46th rejection", "Group 队列满", "cargo test --locked -p gateway-scheduler queue_cap", "FIX-R4-S03"),
        ("One shared pre-upstream deadline", "共享 deadline", "cargo test --locked -p gateway-scheduler group_rpm_wait", "FIX-R4-S04"),
        ("Group RPM deadline rejection", "Group RPM 超时", "cargo test --locked -p gateway-scheduler", "FIX-R4-S05"),
        ("Deterministic Credential unavailability", "确定性无 Credential", "cargo test --locked -p gateway-scheduler all_deterministic", "FIX-R4-S06"),
        ("Cooldown wait and beyond-deadline rejection", "全部 cooldown", "cargo test --locked -p gateway-scheduler cooldown_inside", "FIX-R4-S07"),
        ("Preferred capacity wait then portable spill", "preferred 仅并发满", "cargo test --locked -p gateway-scheduler preferred", "FIX-R4-S08"),
        ("Persistent blocker affinity migration", "持续故障迁移", "cargo test --locked -p gateway-scheduler affinity_migrates", "FIX-R4-S09"),
        ("Pinned request never spills", "**Pinned**", "cargo test --locked -p gateway-scheduler pinned_request", "FIX-R4-S10"),
        ("Main plus nine subagents run independently", "main + 9 subagent", "cargo test --locked -p gateway-scheduler main_and_nine", "FIX-R4-S11"),
        ("Quota guard and one-shot half-open", "quota 95%", "cargo test --locked -p gateway-scheduler quota_reset", "FIX-R4-S12"),
        ("OAuth 401 same-Credential refresh then switch", "OAuth 401", "cargo test --locked -p gateway-scheduler authentication_retries", "FIX-R4-S13"),
        ("Three connection failures are not Messages attempts", "三次纯建连失败", "cargo test --locked -p gateway-scheduler three_connection", "FIX-R4-S14"),
        ("Grant cancel single-winner resource cleanup", "grant/cancel 竞态", "cargo test --locked -p gateway-scheduler cancellation_holds", "FIX-R4-S15"),
        ("Cancel before first request byte", "Lease 后首字节前取消", "cargo test --locked -p gateway-scheduler cancel_before_first", "FIX-R4-S16"),
        ("Cancel during upload", "上传中取消", "cargo test --locked -p gateway-scheduler upload_cancel", "FIX-R4-S17"),
        ("Cancel after non-stream buffer completion", "非流式完整缓冲后取消", "cargo test --locked -p gateway-scheduler buffered_cancel", "FIX-R4-S18"),
        ("SSE committed interruption is never retried", "SSE committed 后中断", "cargo test --locked -p gateway-scheduler committed_stream", "FIX-R4-S19"),
        ("Group disable drains queued work only", "Group disabled", "cargo test --locked -p gateway-scheduler group_disable", "FIX-R4-S20"),
        ("Dynamic Group owner install, drain and generation-safe reactivation", "动态 Group owner 装配", "cargo test --locked -p super-gatewayd active_group_is_installed_disabled_and_reactivated_without_restart", "FIX-R4-S20"),
    ]
    for index, (title, needle, automation, fixture_id) in enumerate(r4_items, 1):
        rid = f"REQ-R4-{index:03d}"
        tid = f"CT-R4-{index:03d}"
        line_no = locate_line(scheduler_lines, needle)
        source_line = scheduler_lines[line_no - 1]
        requirements.append({
            "requirement_id": rid, "kind": "phase_requirement", "title": title,
            "source": source_ref("planning/scheduler-design.md", line_no, source_line),
            "owner": "scheduler", "phase": "R4", "release_gate": "ga", "test_ids": [tid],
            "fixture_ids": [fixture_id], "status": "implemented",
        })
        tests.append({
            "test_id": tid, "kind": "phase_gate", "owner": "scheduler", "phase": "R4",
            "requirement_ids": [rid], "automation": automation,
        })
    r5_items = [
        ("OAuth PKCE one-time callback and frozen Egress", "生成高强度 `state`", "cargo test --locked -p gateway-storage --test credential_r5_pg", "FIX-R5-C01"),
        ("Setup Token bootstrap and terminal material destruction", "Setup Token 在首版被定义为 bootstrap material", "cargo test --locked -p gateway-domain -p gateway-storage", "FIX-R5-C02"),
        ("Typed existing OAuth and Browser session import", "只接受 typed one-of", "cargo test --locked -p gateway-domain", "FIX-R5-C03"),
        ("Console credential purpose and internal Count Tokens isolation", "`purpose=count_tokens`", "cargo test --locked -p gateway-domain -p gateway-storage", "FIX-R5-C04"),
        ("Deterministic fixed Egress allocation and capacity", "每个 Credential 始终有一条 Binding", "cargo test --locked -p gateway-storage --test credential_r5_pg", "FIX-R5-C05"),
        ("Global account UUID dedupe including archived tombstones", "全平台非空 account UUID 唯一", "cargo test --locked -p gateway-storage --test credential_r5_pg", "FIX-R5-C06"),
        ("Unique Device and Profile automatic provisioning", "生成 Credential 唯一 Device/client ID", "cargo test --locked -p gateway-storage --test credential_r5_pg", "FIX-R5-C07"),
        ("Orthogonal Credential status and canonical projection", "真实领域仍保留 lifecycle", "cargo test --locked -p gateway-domain", "FIX-R5-C08"),
        ("Persistent maintenance conflict domains and singleflight", "同 Credential、同冲突域 singleflight", "cargo test --locked -p gateway-services -p gateway-storage", "FIX-R5-C09"),
        ("Refresh CAS and hard-bounded 401 replay", "401 并发请求共享一次 refresh", "cargo test --locked -p gateway-services", "FIX-R5-C10"),
        ("Managed Browser material isolation and atomic pointer commit", "独占内容包括 browser profile/context", "cargo test --locked -p gateway-storage --test credential_r5_pg", "FIX-R5-C11"),
        ("Same-account recovery and Group migration continuity", "验证为同 account UUID", "cargo test --locked -p gateway-storage --test credential_r5_pg", "FIX-R5-C12"),
        ("PLAN collection freshness and immutable Mapping recompute", "PLAN 页面固定标识", "cargo test --locked -p gateway-storage --test credential_r5_pg", "FIX-R5-C13"),
        ("Quota, usage and internal token estimation boundaries", "内部 Count Tokens 从同一", "cargo test --locked -p gateway-scheduler -p gateway-services", "FIX-R5-C14"),
        ("Cohort, Egress and dual-approved Device continuity epochs", "Device rebuild 还需双人审批", "cargo test --locked -p gateway-storage --test credential_r5_pg", "FIX-R5-C15"),
        ("Disable, Reactivate, Revoke and Archive terminal fences", "Revoke：终态停止新 Lease", "cargo test --locked -p gateway-storage --test credential_r5_pg", "FIX-R5-C16"),
        ("Restart-safe Durable Job lease and heartbeat", "Durable Job 默认 lease 60s", "cargo test --locked -p gateway-storage --test postgres_r2", "FIX-R5-C17"),
        ("All-sink secret references and loser destruction", "终态后临时 secret 已销毁", "cargo test --locked -p gateway-services -p gateway-storage", "FIX-R5-C18"),
    ]
    for index, (title, needle, automation, fixture_id) in enumerate(r5_items, 1):
        rid = f"REQ-R5-{index:03d}"
        tid = f"CT-R5-{index:03d}"
        line_no = locate_line(lifecycle_lines, needle)
        source_line = lifecycle_lines[line_no - 1]
        requirements.append({
            "requirement_id": rid, "kind": "phase_requirement", "title": title,
            "source": source_ref("planning/credential-lifecycle.md", line_no, source_line),
            "owner": "credential", "phase": "R5", "release_gate": "ga", "test_ids": [tid],
            "fixture_ids": [fixture_id], "status": "implemented",
        })
        tests.append({
            "test_id": tid, "kind": "phase_gate", "owner": "credential", "phase": "R5",
            "requirement_ids": [rid], "automation": automation,
        })
    r6_items = [
        ("Async Transport Port and immutable attempt snapshot", "## 6. Transport Port", "cargo test --locked -p gateway-transport", "FIX-R6-T01", "implemented"),
        ("Strict JCS, SHA-256 and Ed25519 Bundle envelope", "## 11. 签名、信任根与供应链", "cargo test --locked -p gateway-transport verifies_jcs", "FIX-R6-T02", "implemented"),
        ("Deterministic Engine compiler and atomic Catalog generation", "## 12. 装载、编译缓存与原子发布", "cargo test --locked -p gateway-transport", "FIX-R6-T03", "implemented"),
        ("Nine-field PoolKey and activation-generation isolation", "## 21. Connection Pool 隔离", "cargo test --locked -p gateway-transport every_pool_field", "FIX-R6-T04", "implemented"),
        ("Ordered H1 writer, strict framing and raw Body relay", "## 16. HTTP/1.1 Engine", "cargo test --locked -p gateway-transport h1", "FIX-R6-T05", "implemented"),
        ("Direct, CONNECT and SOCKS5 TLS pass-through", "## 19. CONNECT 与 SOCKS5 TLS Pass-through", "cargo test --locked -p gateway-transport egress", "FIX-R6-T06", "implemented"),
        ("BoringSSL certificate, SNI and ALPN connector", "## 14. TLS Profile 编译与执行", "cargo test --locked -p gateway-transport --features boring-backend", "FIX-R6-T07", "implemented"),
        ("ConnectionAttempt promotion and monotonic TransportEvent", "## 22. ConnectionAttempt 状态机", "cargo test --locked -p gateway-transport", "FIX-R6-T08", "implemented"),
        ("H1 cancellation, disposition and pool eviction", "## 24. Deadline、Timeout 与 Cancel", "cargo test --locked -p gateway-transport", "FIX-R6-T09", "implemented"),
        ("Evidence-gated H2 stream engine", "## 17. HTTP/2 Engine", "cargo test --locked -p gateway-transport h2", "FIX-R6-T10", "blocked"),
        ("Production-engine Windows H1 exact replay", "Windows 2.1.241 H1 Bundle：可继续", "transport-poc transport-matrix against production engine", "FIX-R6-T11", "blocked"),
        ("Linux x86_64 and arm64 native BoringSSL", "Linux x86_64/arm64 native BoringSSL", "native Linux release CI", "FIX-R6-T12", "blocked"),
        ("Sanitizer, RustSec, license and SBOM", "sanitizer、RustSec/license/SBOM", "R6 security CI", "FIX-R6-T13", "blocked"),
        ("Production RSS, heap and latency gate", "RSS/heap/24h soak", "R6 performance CI", "FIX-R6-T14", "blocked"),
        ("24-hour mixed transport soak", "RSS/heap/24h soak", "R10 24h soak runner", "FIX-R6-T15", "blocked"),
    ]
    for index, (title, needle, automation, fixture_id, status) in enumerate(r6_items, 1):
        rid = f"REQ-R6-{index:03d}"
        tid = f"CT-R6-{index:03d}"
        line_no = locate_line(transport_lines, needle)
        source_line = transport_lines[line_no - 1]
        requirements.append({
            "requirement_id": rid, "kind": "phase_requirement", "title": title,
            "source": source_ref("planning/transport-engine.md", line_no, source_line),
            "owner": "transport", "phase": "R6", "release_gate": "ga", "test_ids": [tid],
            "fixture_ids": [fixture_id], "status": status,
        })
        tests.append({
            "test_id": tid, "kind": "phase_gate", "owner": "transport", "phase": "R6",
            "requirement_ids": [rid], "automation": automation,
        })
    source_revision = hashlib.sha256(
        normalized_text_bytes(functional_path)
        + normalized_text_bytes(roadmap_path)
        + normalized_text_bytes(scheduler_path)
        + normalized_text_bytes(lifecycle_path)
        + normalized_text_bytes(transport_path)
    ).hexdigest()
    ledger = {
        "schema_version": "1.0.0", "generated_at": "2026-08-24T00:00:00Z", "source_revision": source_revision,
        "requirements": requirements, "tests": tests,
    }
    write_json(TRACEABILITY / "requirements.json", ledger)


def generate_fixtures() -> None:
    common = {
        "schema_version": "1.0.0", "event_seq": 1, "trace_id": "trc_01", "request_id": "req_01",
        "parent_event_id": None, "occurred_at_utc": "2026-08-24T00:00:00Z", "monotonic_ns": 100,
        "runtime_generation": 1, "actor": {"kind": "platform_key", "id_digest": "key_digest"},
        "executor": {"instance_id": "gw_01", "owner_partition": "group_01"}, "phase": "accepted", "outcome": "pending",
    }
    events = [
        {**common, "event_id": "evt_req", "event_type": "request", "payload": {
            "response_mode": "stream", "state": "accepted", "client_class": "claude_code_cli",
            "platform_key_id_digest": "key_digest", "group_id": "grp_01", "base_session_digest": "base_digest",
            "agent_digest": "agent_digest", "portability": "portable", "generic_request_digest": "generic_digest",
            "snapshot_refs": {"group_config": "gcv_1"}, "pre_upstream_queue_deadline_utc": "2026-08-24T00:00:30Z",
            "upstream_total_deadline_utc": None, "connection_attempt_count": 0, "messages_attempt_count": 0,
            "final_attempt_id": None, "response_committed": False, "terminal_reason": None,
        }},
        {**common, "event_id": "evt_conn", "event_type": "connection_attempt", "phase": "tls_handshaking", "payload": {
            "attempt_id": "conn_01", "ordinal": 1, "credential_id_digest": "cred_digest", "profile_epoch": 1,
            "archetype_version_id": "archv_01", "capture_cohort": "win-2026-08-a", "bundle_id": "bundle_01",
            "bundle_version": 1, "bundle_hash": "a" * 64,
            "egress_binding_id": "egress_01", "proxy_id_digest": None, "egress_epoch": 1,
            "authority": "api.anthropic.com", "sni": "api.anthropic.com", "protocol": "h1",
            "pool_key_digest": "pool_digest", "activation_generation": 1, "state": "tls_handshaking",
            "connect_timeout_ms": 5000, "pool_reused": False, "request_bytes_written": 0,
            "failure_domain": None, "connection_disposition": None, "retry_safe": True, "health_effect": None,
        }},
        {**common, "event_id": "evt_transport", "event_type": "transport", "phase": "connection_ready", "payload": {
            "connection_attempt_id": "conn_01", "attempt_id": None, "transport_seq": 1,
            "kind": "connection_ready", "connection_id_digest": "connection_digest",
            "request_bytes_written": 0, "response_bytes_read": 0,
            "upstream_submission_complete": False, "connection_disposition": None, "diagnostic_code": None,
        }},
        {**common, "event_id": "evt_attempt", "event_type": "messages_attempt", "phase": "submitting", "payload": {
            "attempt_id": "att_01", "ordinal": 1, "reason": "initial", "state": "submitting",
            "credential_id_digest": "cred_digest", "token_version": 1, "profile_epoch": 1,
            "archetype_version_id": "archv_01", "capture_cohort": "win-2026-08-a", "bundle_id": "bundle_01",
            "egress_epoch": 1, "upstream_request_id": None, "submitted": True, "response_committed": False,
            "retry_decision": None, "is_final": False,
        }},
        {**common, "event_id": "evt_usage", "event_type": "usage", "phase": "completed", "outcome": "success", "payload": {
            "attempt_id": "att_01", "source": "official", "completeness": "complete", "input_tokens": 20,
            "output_tokens": 10, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
            "estimated_amount": 0.001, "currency": "USD", "algorithm_version": None,
        }},
    ]
    write_json(FIXTURES / "trace-events.valid.json", events)
    h = "a" * 64
    bundle_payload = {
        "schema_version": "1.0.0", "engine_abi_version": "1.0", "bundle_id": "bundle_01", "artifact_version": 1,
        "lifecycle": "verified", "evidence_gate": "passed", "runtime_state": "loadable", "backend_id": "boringssl-h1-v1",
        "required_capabilities": ["tls_client_hello", "ordered_http1"],
        "source_archetype_version_id": "archv_01", "capture_cohort": "win-2026-08-a",
        "application": {
            "protocol": "h1", "authority": "api.anthropic.com",
            "tls": {"client_hello_profile": "claude-code-win-2.1.241-a", "alpn": ["http/1.1"], "cipher_suite_ids": [4865, 4866, 4867, 49199], "supported_group_ids": [29, 23], "key_share_group_ids": [29], "extension_order": [0, 11, 10, 16, 5, 18], "grease_enabled": True, "permute_extensions": False, "session_resumption": False},
            "http1": {"request_line_form": "origin", "header_order": [{"name": "host", "value_template": "{authority}", "sensitive": False}], "framing": "content-length"},
            "connection": {"pool_key_fields": ["credential_id", "profile_epoch", "bundle_id", "bundle_version", "egress_binding_id", "egress_epoch", "authority", "sni", "protocol"], "reuse_policy": "exact_pool_key", "resumption_cache_scope": "disabled"},
        },
        "min_engine_build": "0.1.0", "max_engine_build": None,
        "engine_builds": [{"target": "x86_64-unknown-linux-gnu", "artifact_digest": h, "boringssl_revision": "rev-1", "compiler": "rustc-stable"}],
        "supported_targets": ["x86_64-unknown-linux-gnu"], "evidence_hashes": ["b" * 64],
        "created_at": "2026-08-24T00:00:00Z",
    }
    bundle = {
        "envelope_version": "1.0.0", "payload": bundle_payload,
        "canonicalization": {"algorithm": "jcs_rfc8785", "hash_algorithm": "sha256", "canonical_hash": "c" * 64},
        "signature": {"domain": "transport_bundle_v1", "algorithm": "ed25519", "key_id": "bundle-signing-01", "detached_signature_base64": "A" * 88},
    }
    write_json(FIXTURES / "transport-bundle.valid.json", bundle)
    write_json(FIXTURES / "bundle-trust-store.valid.json", {
        "format_version": "1.0.0", "domain": "transport_bundle_v1",
        "keys": [{
            "key_id": "bundle-signing-01", "status": "current", "public_key_base64": "A" * 44,
            "valid_from_unix_seconds": 1_777_161_600, "valid_until_unix_seconds": None,
        }],
    })
    runtime_variables = [
        ("GATEWAY_DATA_BIND", "socket_address", True, False, True, "independent", None, None),
        ("GATEWAY_ADMIN_BIND", "socket_address", True, False, True, "independent", None, None),
        ("GATEWAY_DATABASE_URL_FILE", "secret_file", True, True, True, "independent", None, None),
        ("GATEWAY_MIGRATOR_DATABASE_URL_FILE", "secret_file", False, True, False, "independent", None, None),
        ("GATEWAY_BUSINESS_KEY_PROVIDER", "enum", False, False, True, "independent", None, "database"),
        ("GATEWAY_KEY_PROVIDER_URI", "provider_uri", False, True, True, "conditional", "GATEWAY_BUSINESS_KEY_PROVIDER=uri", None),
        ("GATEWAY_APP_KEY_FILE", "secret_file", False, True, True, "conditional", "GATEWAY_BUSINESS_KEY_PROVIDER=file", None),
        ("GATEWAY_DIGEST_KEY_FILE", "secret_file", True, True, True, "independent", None, None),
        ("GATEWAY_AUDIT_INTEGRITY_KEY_FILE", "secret_file", True, True, True, "independent", None, None),
        ("GATEWAY_BUNDLE_TRUST_STORE", "path", True, False, True, "independent", None, None),
        ("GATEWAY_BUNDLE_DIR", "path", True, False, True, "independent", None, None),
        ("GATEWAY_RESPONSE_TMP_DIR", "path", True, False, True, "independent", None, None),
        ("GATEWAY_CONTENT_AUDIT_KEY_FILE", "secret_file", False, True, True, "pair", "GATEWAY_CONTENT_AUDIT_DIR", None),
        ("GATEWAY_CONTENT_AUDIT_DIR", "path", False, False, True, "pair", "GATEWAY_CONTENT_AUDIT_KEY_FILE", None),
        ("GATEWAY_BACKUP_KEY_FILE", "secret_file", False, True, False, "pair", "GATEWAY_BACKUP_REPOSITORY", None),
        ("GATEWAY_BACKUP_REPOSITORY", "string", False, False, False, "pair", "GATEWAY_BACKUP_KEY_FILE", None),
        ("GATEWAY_DRAIN_DEADLINE", "duration", False, False, False, "independent", None, "300s"),
        ("GATEWAY_EGRESS_OBSERVER_HOST", "string", False, False, True, "independent", None, "api64.ipify.org"),
        ("GATEWAY_EGRESS_OBSERVER_PATH", "string", False, False, True, "independent", None, "/"),
        ("GATEWAY_MANAGED_BROWSER_TOOL", "path", False, False, True, "independent", None, None),
        ("GATEWAY_MANAGED_BROWSER_TIMEOUT", "duration", False, False, True, "conditional", "GATEWAY_MANAGED_BROWSER_TOOL", "300s"),
        ("GATEWAY_BOOTSTRAP_ADMIN_USERNAME", "string", False, False, True, "pair", "GATEWAY_BOOTSTRAP_ADMIN_PASSWORD", None),
        ("GATEWAY_BOOTSTRAP_ADMIN_PASSWORD", "secret_value", False, True, True, "pair", "GATEWAY_BOOTSTRAP_ADMIN_USERNAME", None),
        ("GATEWAY_BOOTSTRAP_ADMIN_EMAIL", "string", False, False, False, "independent", None, None),
        ("GATEWAY_BOOTSTRAP_ADMIN_DISPLAY_NAME", "string", False, False, False, "independent", None, None),
    ]
    write_json(FIXTURES / "runtime-config.valid.json", {
        "schema_version": "2.0.0", "environment_prefix": "GATEWAY_", "dotenv_supported": True,
        "unknown_variable_policy": "ignore",
        "variables": [
            {
                "name": name, "kind": kind, "required": required, "secret": secret,
                "readiness_gate": readiness_gate, "relationship": relationship,
                "related_to": related_to, "default": default,
            }
            for name, kind, required, secret, readiness_gate, relationship, related_to, default in runtime_variables
        ],
    })
    fixture_manifest = {
        "fixture_id": "fixture_r1_probe_contract", "source": "synthetic", "scenario": "privacy_safe_probes",
        "schema_version": "1.0.0", "normalizer_version": None, "content_sha256": "d" * 64,
        "privacy_scan": "builtin-r1:passed", "generation_command": "python -B tools/generate_contracts.py",
        "compatibility": ["gateway-testkit-r1-v1"], "expiration_policy": "regenerate_on_contract_change",
        "os_family": None, "runtime_version": None, "client_version": None, "architecture": None,
        "capture_cohort": None,
    }
    write_json(FIXTURES / "fixture-manifest.valid.json", fixture_manifest)
    r3_scenarios = [
        ("FIX-R3-ROUTE-MATRIX-001", "auth_first_route_matrix", ["crates/gateway-api/src/edge.rs"]),
        ("FIX-R3-AUTH-ACCESS-001", "platform_key_and_ingress_access", ["crates/gateway-api/src/data.rs", "crates/gateway-api/src/edge.rs"]),
        ("FIX-R3-MESSAGES-CORPUS-001", "messages_framing_and_lossless_json", ["crates/gateway-policy/src/parser.rs", "crates/gateway-api/src/edge.rs"]),
        ("FIX-R3-CLIENT-CORPUS-001", "client_session_traffic_classification", ["crates/gateway-api/src/edge.rs"]),
        ("FIX-R3-CAPABILITY-001", "bounded_model_capability", ["crates/gateway-policy/src/capability.rs"]),
        ("FIX-R3-SYSTEM-MODES-001", "system_policy_four_modes", ["crates/gateway-policy/src/engine.rs"]),
        ("FIX-R3-RULESET-001", "deterministic_ruleset", ["crates/gateway-policy/src/engine.rs"]),
        ("FIX-R3-UNKNOWN-EXT-001", "unknown_extension_roundtrip_and_pin", ["crates/gateway-policy/src/parser.rs", "crates/gateway-policy/src/engine.rs"]),
        ("FIX-R3-GENERIC-REQUEST-001", "credential_neutral_generic_request", ["crates/gateway-domain/src/request.rs", "crates/gateway-policy/src/engine.rs"]),
        ("FIX-R3-MODELS-001", "published_model_scope_and_pagination", ["crates/gateway-api/src/edge.rs"]),
        ("FIX-R3-FUZZ-CORPUS-001", "bounded_mutation_regression_corpus", ["crates/gateway-policy/src/parser.rs", "crates/gateway-policy/src/capability.rs"]),
        ("FIX-R3-SECRET-CANARY-001", "southbound_identity_canary", ["crates/gateway-api/src/data.rs", "crates/gateway-api/src/edge.rs"]),
    ]
    corpus = []
    manifests = []
    for fixture_id, scenario, sources in r3_scenarios:
        item = {
            "fixture_id": fixture_id,
            "scenario": scenario,
            "sources": sources,
            "source_sha256": {source: text_sha256(ROOT / source) for source in sources},
            "privacy_canaries": ["synthetic-platform-key", "synthetic-client-identity"],
            "privacy_scan": "builtin-r3:passed",
        }
        content_hash = hashlib.sha256(
            json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        corpus.append(item)
        manifests.append({
            "fixture_id": fixture_id, "source": "synthetic", "scenario": scenario,
            "schema_version": "1.0.0", "normalizer_version": "gateway-policy-r3-v1",
            "content_sha256": content_hash, "privacy_scan": "builtin-r3:passed",
            "generation_command": "python -B tools/generate_contracts.py",
            "compatibility": ["gateway-r3-v1", "claude-messages-compatible"],
            "expiration_policy": "regenerate_on_source_or_contract_change", "os_family": None,
            "runtime_version": "rust-1.95", "client_version": None, "architecture": None,
            "capture_cohort": None,
        })
    write_json(FIXTURES / "r3-corpus.valid.json", corpus)
    write_json(FIXTURES / "r3-fixture-manifests.valid.json", manifests)
    r4_scenarios = [
        (f"FIX-R4-S{index:02d}", f"scheduler_scenario_{index:02d}", sources)
        for index, sources in enumerate([
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-api/src/edge.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/retry.rs"],
            ["crates/gateway-scheduler/src/attempt.rs"],
            ["crates/gateway-scheduler/src/actor.rs", "crates/gateway-scheduler/src/engine.rs"],
            ["crates/gateway-scheduler/src/attempt.rs"],
            ["crates/gateway-scheduler/src/attempt.rs"],
            ["crates/gateway-scheduler/src/attempt.rs"],
            ["crates/gateway-scheduler/src/attempt.rs"],
            ["crates/gateway-scheduler/src/engine.rs"],
        ], 1)
    ]
    r4_corpus = []
    r4_manifests = []
    for fixture_id, scenario, sources in r4_scenarios:
        item = {
            "fixture_id": fixture_id, "scenario": scenario, "sources": sources,
            "source_sha256": {source: text_sha256(ROOT / source) for source in sources},
            "privacy_canaries": ["synthetic-platform-key", "synthetic-credential-token"],
            "privacy_scan": "builtin-r4:passed",
        }
        content_hash = hashlib.sha256(
            json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        r4_corpus.append(item)
        r4_manifests.append({
            "fixture_id": fixture_id, "source": "synthetic", "scenario": scenario,
            "schema_version": "1.0.0", "normalizer_version": "gateway-scheduler-r4-v1",
            "content_sha256": content_hash, "privacy_scan": "builtin-r4:passed",
            "generation_command": "python -B tools/generate_contracts.py",
            "compatibility": ["gateway-r4-v1", "scheduler-reference-model-v1"],
            "expiration_policy": "regenerate_on_source_or_contract_change", "os_family": None,
            "runtime_version": "rust-1.95", "client_version": None, "architecture": None,
            "capture_cohort": None,
        })
    write_json(FIXTURES / "r4-corpus.valid.json", r4_corpus)
    write_json(FIXTURES / "r4-fixture-manifests.valid.json", r4_manifests)
    r5_sources = [
        ["crates/gateway-services/src/security.rs", "crates/gateway-storage/src/credential.rs"],
        ["crates/gateway-domain/src/credential.rs", "crates/gateway-storage/src/credential.rs"],
        ["crates/gateway-domain/src/credential.rs"],
        ["crates/gateway-domain/src/credential.rs", "crates/gateway-storage/migrations/20260824000600_r5_contract_alignment.sql"],
        ["crates/gateway-storage/src/credential.rs"],
        ["crates/gateway-storage/src/credential.rs", "crates/gateway-storage/tests/credential_r5_pg.rs"],
        ["crates/gateway-storage/src/credential.rs"],
        ["crates/gateway-domain/src/credential.rs"],
        ["crates/gateway-services/src/credential.rs", "crates/gateway-storage/src/credential.rs"],
        ["crates/gateway-services/src/credential.rs"],
        ["crates/gateway-storage/src/credential.rs"],
        ["crates/gateway-storage/src/credential.rs"],
        ["crates/gateway-services/src/credential.rs", "crates/gateway-storage/src/credential.rs"],
        ["crates/gateway-scheduler/src/engine.rs", "crates/gateway-services/src/credential.rs"],
        ["crates/gateway-domain/src/credential.rs", "crates/gateway-storage/src/credential.rs"],
        ["crates/gateway-domain/src/credential.rs", "crates/gateway-storage/src/credential.rs"],
        ["crates/gateway-services/src/operations.rs", "crates/gateway-storage/src/postgres.rs"],
        ["crates/gateway-services/src/security.rs", "crates/gateway-storage/src/credential.rs"],
    ]
    r5_corpus = []
    r5_manifests = []
    for index, sources in enumerate(r5_sources, 1):
        fixture_id = f"FIX-R5-C{index:02d}"
        scenario = f"credential_lifecycle_{index:02d}"
        item = {
            "fixture_id": fixture_id, "scenario": scenario, "sources": sources,
            "source_sha256": {source: text_sha256(ROOT / source) for source in sources},
            "privacy_canaries": [
                "synthetic-oauth-access-token", "synthetic-refresh-token", "synthetic-browser-cookie",
                "synthetic-pkce-verifier", "synthetic-session-hmac",
            ],
            "privacy_scan": "builtin-r5:passed",
            "external_adapter_activation": "evidence_pending",
        }
        content_hash = hashlib.sha256(
            json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        r5_corpus.append(item)
        r5_manifests.append({
            "fixture_id": fixture_id, "source": "synthetic", "scenario": scenario,
            "schema_version": "1.0.0", "normalizer_version": "gateway-credential-r5-v1",
            "content_sha256": content_hash, "privacy_scan": "builtin-r5:passed",
            "generation_command": "python -B tools/generate_contracts.py",
            "compatibility": ["gateway-r5-v1", "postgresql-16-plus"],
            "expiration_policy": "regenerate_on_source_or_contract_change", "os_family": None,
            "runtime_version": "rust-1.95", "client_version": None, "architecture": None,
            "capture_cohort": None,
        })
    write_json(FIXTURES / "r5-corpus.valid.json", r5_corpus)
    write_json(FIXTURES / "r5-fixture-manifests.valid.json", r5_manifests)
    r6_sources = [
        ["crates/gateway-domain/src/transport.rs", "crates/gateway-transport/src/port.rs"],
        ["crates/gateway-transport/src/bundle.rs", "contracts/schemas/transport-bundle-manifest.schema.json"],
        ["crates/gateway-transport/src/engine.rs"],
        ["crates/gateway-transport/src/pool.rs"],
        ["crates/gateway-transport/src/h1.rs", "crates/gateway-transport/src/production.rs"],
        ["crates/gateway-transport/src/egress.rs"],
        ["crates/gateway-transport/src/tls.rs", "Cargo.lock"],
        ["crates/gateway-transport/src/attempt.rs", "crates/gateway-transport/src/event.rs"],
        ["crates/gateway-transport/src/production.rs"],
        ["planning/transport-engine.md", "crates/gateway-transport/src/production.rs"],
        ["planning/transport-spike-report.md", "transport-poc/var/real-capture/windows-2.1.241-fresh-v1/windows-2.1.241.current.audit-canary.json"],
        ["planning/transport-spike-report.md", ".github/workflows/ci.yml"],
        ["planning/test-strategy.md", ".github/workflows/ci.yml"],
        ["planning/test-strategy.md", "transport-poc/var/e2e-v2/runtime-load-current.json"],
        ["planning/test-strategy.md"],
    ]
    blocked_r6 = {10, 11, 12, 13, 14, 15}
    r6_corpus = []
    r6_manifests = []
    for index, sources in enumerate(r6_sources, 1):
        fixture_id = f"FIX-R6-T{index:02d}"
        scenario = f"transport_production_{index:02d}"
        item = {
            "fixture_id": fixture_id, "scenario": scenario, "sources": sources,
            "source_sha256": {source: text_sha256(ROOT / source) for source in sources},
            "privacy_canaries": [
                "synthetic-oauth-access-token", "synthetic-proxy-password", "synthetic-session-hmac",
                "synthetic-platform-key",
            ],
            "privacy_scan": "builtin-r6:passed",
            "activation": "blocked_external_evidence" if index in blocked_r6 else "implemented_local_gate",
        }
        content_hash = hashlib.sha256(
            json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        r6_corpus.append(item)
        r6_manifests.append({
            "fixture_id": fixture_id, "source": "synthetic", "scenario": scenario,
            "schema_version": "1.0.0", "normalizer_version": "gateway-transport-r6-v1",
            "content_sha256": content_hash, "privacy_scan": "builtin-r6:passed",
            "generation_command": "python -B tools/generate_contracts.py",
            "compatibility": ["gateway-r6-v1", "transport-bundle-v1"],
            "expiration_policy": "regenerate_on_source_or_contract_change", "os_family": None,
            "runtime_version": "rust-1.95", "client_version": None, "architecture": None,
            "capture_cohort": None,
        })
    write_json(FIXTURES / "r6-corpus.valid.json", r6_corpus)
    write_json(FIXTURES / "r6-fixture-manifests.valid.json", r6_manifests)
    artifact = {"name": "super-gatewayd", "path": "bin/super-gatewayd", "sha256": "e" * 64, "size_bytes": 1}
    release_migrations = sorted((ROOT / "crates" / "gateway-storage" / "migrations").glob("*.sql"))
    release_migration_checksums = {path.name: text_sha256(path) for path in release_migrations}
    release_versions = [int(path.name[:14]) for path in release_migrations]
    release_manifest = {
        "schema_version": "1.0.0", "application": "super-gatewayd", "application_version": "0.1.0",
        "target": "x86_64-unknown-linux-gnu", "created_at": "2026-08-24T00:00:00Z",
        "source_revision": "fixture-r2", "rust_toolchain": "1.95.0", "runtime_abi_version": "r2-v1",
        "testkit_abi_version": "gateway-testkit-r1-v1",
        "schema_compatibility": {"minimum": release_versions[0], "maximum": release_versions[-1]},
        "cargo_lock_sha256": "f" * 64, "contract_tree_sha256": "a" * 64,
        "migration_checksums": release_migration_checksums, "artifacts": [artifact],
    }
    provenance = {
        "schema_version": "1.0.0", "builder": "fixture", "build_type": "super-gateway/rust-release-v1",
        "created_at": "2026-08-24T00:00:00Z", "target": "x86_64-unknown-linux-gnu",
        "command": ["cargo", "build", "--release", "--locked"],
        "materials": [
            {"name": "Cargo.lock", "path": "Cargo.lock", "sha256": "f" * 64, "size_bytes": 1},
            {"name": "contracts", "path": "contracts", "sha256": "a" * 64, "size_bytes": 1},
        ],
        "subjects": [artifact],
    }
    evidence_manifest = {
        "schema_version": "1.0.0",
        "release_manifest": {"name": "release-manifest.json", "path": "release-manifest.json", "sha256": "b" * 64, "size_bytes": 1},
        "provenance": {"name": "provenance.json", "path": "provenance.json", "sha256": "c" * 64, "size_bytes": 1},
        "sbom": {"name": "sbom.cdx.json", "path": "sbom.cdx.json", "sha256": "d" * 64, "size_bytes": 1},
        "verification": {"format": "passed", "clippy": "passed", "tests": "passed", "contracts": "passed"},
    }
    write_json(FIXTURES / "release-manifest.valid.json", release_manifest)
    write_json(FIXTURES / "provenance.valid.json", provenance)
    write_json(FIXTURES / "evidence-manifest.valid.json", evidence_manifest)

    migration_dir = ROOT / "crates" / "gateway-storage" / "migrations"
    migration_files = sorted(migration_dir.glob("*.sql"))
    migrations = [
        {
            "version": int(path.name[:14]), "name": path.name,
            "sha256": text_sha256(path),
            "direction": "forward_only", "transactional": True,
        }
        for path in migration_files
    ]
    migration_manifest = {
        "schema_version": "1.0.0", "postgres_minimum_major": 16,
        "minimum_compatible_version": migrations[0]["version"], "current_version": migrations[-1]["version"],
        "migrations": migrations,
    }
    migration_fixture_path = FIXTURES / "migration-manifest.valid.json"
    write_json(migration_fixture_path, migration_manifest)
    migration_manifest_hash = text_sha256(migration_fixture_path)
    sql_text = "\n".join(path.read_text(encoding="utf-8") for path in migration_files)
    all_tables = sorted(set(re.findall(r"CREATE TABLE\s+([a-z_]+\.[a-z0-9_]+)", sql_text)))
    required_tables = [
        name for name in all_tables
        if not re.fullmatch(r"telemetry\.request_record_(?:2026[0-9]{2}|default)", name)
    ]
    write_json(FIXTURES / "database-schema-manifest.valid.json", {
        "schema_version": "1.0.0", "postgres_minimum_major": 16,
        "logical_schemas": ["iam", "gateway", "catalog", "telemetry", "security", "ops"],
        "required_tables": required_tables,
        "database_roles": ["gateway_migrator", "gateway_runtime", "gateway_readonly", "gateway_backup"],
        "uuid_generation": "application_uuid_v7", "enum_storage": "text_check_fail_closed",
    })
    write_json(FIXTURES / "secret-envelope.valid.json", {
        "schema_version": 1, "cipher_suite": "aes_256_gcm", "provider_role": "business", "key_version": 1,
        "ciphertext_base64": "Zml4dHVyZS1jaXBoZXJ0ZXh0", "nonce_base64": "AAAAAAAAAAAAAAAA",
        "wrapped_dek_base64": "Zml4dHVyZS13cmFwcGVkLWRlaw==",
        "aad_fields": ["schema_version", "secret_id", "secret_kind", "provider_role", "owner_type", "owner_id", "purpose", "key_version"],
    })
    audit_day = "2026-08-24"
    canonical_event = '{"action":"fixture"}'
    audit_hash = hashlib.sha256(
        b"gateway-audit-event-v1" + audit_day.encode("utf-8") + (1).to_bytes(8, "big") + canonical_event.encode("utf-8")
    ).hexdigest()
    write_json(FIXTURES / "audit-integrity.valid.json", {
        "schema_version": "1.0.0", "event_domain": "gateway-audit-event-v1", "seal_domain": "gateway-audit-day-v1",
        "hash_algorithm": "sha256", "seal_algorithm": "hmac_sha256", "event_day": audit_day,
        "daily_sequence": 1, "canonical_event": canonical_event, "event_hash": audit_hash,
    })
    write_json(FIXTURES / "backup-restore-manifest.valid.json", {
        "schema_version": "2.0.0", "backup_id": "0198d5d0-0000-7000-8000-000000000001",
        "created_at_utc": "2026-08-24T00:00:00Z", "scope": "local_fixture", "backup_key_version": 1,
        "database_system_id": "fixture-system", "timeline": 1,
        "base_backup_lsn": "0/1000000", "wal_end_lsn": "0/1000100", "release_version": "0.1.0",
        "schema_version_value": migrations[-1]["version"], "migration_manifest_sha256": migration_manifest_hash,
        "audit_seal_watermark": "2026-08-24", "deletion_ledger_watermark": 0,
        "audit": {"sealed_through": "2026-08-24", "seal_digest": "a" * 64},
        "deletion_ledger": {"sequence": 0, "entry_hash": None},
        "lineage": {"release_version": "0.1.0", "schema_version": migrations[-1]["version"], "migration_manifest_sha256": migration_manifest_hash, "parent_manifest_sha256": None},
        "objects": [{"kind": "postgres_dump", "uri": "fixture://database", "size_bytes": 1, "sha256": "a" * 64}],
        "included_categories": ["database"], "excluded_categories": ["production_wal", "offsite_copy"],
        "manifest_hmac_sha256": "b" * 64, "encrypted": True,
    })
    write_json(FIXTURES / "postgres-test-evidence.valid.json", {
        "schema_version": "1.0.0", "postgres_major": 16, "schema_version_value": migrations[-1]["version"],
        "migration_manifest_sha256": migration_manifest_hash, "required_table_count": len(required_tables),
        "partition_count": len(all_tables) - len(required_tables), "fixture_id": "FIX-R2-POSTGRES-001",
        "automation": "cargo test --locked -p gateway-storage --test postgres_r2", "status": "not_run",
    })


def main() -> None:
    for directory in [SCHEMAS, OPENAPI, TRACEABILITY, FIXTURES, CONTRACTS / "registries"]:
        directory.mkdir(parents=True, exist_ok=True)
    generate_registries()
    generate_common_schema()
    generate_credential_schema()
    generate_maintenance_schema()
    generate_session_schema()
    generate_egress_profile_schema()
    generate_usage_plan_schema()
    generate_audit_schema()
    generate_trace_schema()
    generate_bundle_schema()
    generate_r1_foundation_schemas()
    generate_r2_foundation_schemas()
    generate_ledger_schema()
    generate_data_openapi()
    routes = generate_admin_openapi()
    generate_ledger()
    generate_fixtures()
    print(f"Generated contracts: {len(routes)} admin operations, {len(ENUMS)} enum families.")


if __name__ == "__main__":
    main()
