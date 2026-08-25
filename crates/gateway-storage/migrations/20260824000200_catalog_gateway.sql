-- R2 catalog, group, credential, profile, egress and Platform Key schema.

SET LOCAL ROLE gateway_migrator;

CREATE TABLE catalog.environment_archetype (
  id uuid PRIMARY KEY,
  name text NOT NULL UNIQUE,
  os_family_code text NOT NULL CHECK (os_family_code IN ('windows','macos','linux')),
  architecture_code text NOT NULL,
  lifecycle_code text NOT NULL CHECK (lifecycle_code IN ('active','retired')),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1)
);

CREATE TABLE catalog.evidence_set (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  source_code text NOT NULL CHECK (source_code IN ('official_capture','synthetic','manual_import')),
  state_code text NOT NULL CHECK (state_code IN ('collecting','complete','invalidated')),
  capture_cohort text,
  content_hash bytea NOT NULL,
  created_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL
);

CREATE TABLE catalog.environment_archetype_version (
  id uuid PRIMARY KEY,
  archetype_id uuid NOT NULL REFERENCES catalog.environment_archetype(id) ON DELETE RESTRICT,
  version bigint NOT NULL CHECK (version >= 1),
  lifecycle_code text NOT NULL CHECK (lifecycle_code IN ('draft','verified','canary','active','retired','quarantined')),
  runtime_code text NOT NULL,
  runtime_version text NOT NULL,
  client_version text NOT NULL,
  protocol_profile jsonb NOT NULL,
  evidence_set_id uuid REFERENCES catalog.evidence_set(id) ON DELETE RESTRICT,
  content_hash bytea NOT NULL,
  created_at timestamptz NOT NULL,
  activated_at timestamptz,
  retired_at timestamptz,
  UNIQUE (archetype_id, version),
  UNIQUE (archetype_id, content_hash)
);

CREATE TABLE catalog.transport_bundle (
  id uuid PRIMARY KEY,
  artifact_version bigint NOT NULL CHECK (artifact_version >= 1),
  engine_abi_version text NOT NULL,
  lifecycle_code text NOT NULL CHECK (lifecycle_code IN ('draft','verified','canary','active','retired','quarantined')),
  manifest jsonb NOT NULL,
  manifest_hash bytea NOT NULL,
  signature bytea NOT NULL,
  signing_key_id text NOT NULL,
  object_uri text NOT NULL,
  created_at timestamptz NOT NULL,
  activated_at timestamptz,
  UNIQUE (artifact_version),
  UNIQUE (manifest_hash)
);

CREATE TABLE catalog.archetype_bundle_binding (
  archetype_version_id uuid NOT NULL REFERENCES catalog.environment_archetype_version(id) ON DELETE RESTRICT,
  transport_bundle_id uuid NOT NULL REFERENCES catalog.transport_bundle(id) ON DELETE RESTRICT,
  state_code text NOT NULL CHECK (state_code IN ('candidate','active','retired')),
  created_at timestamptz NOT NULL,
  activated_at timestamptz,
  PRIMARY KEY (archetype_version_id, transport_bundle_id)
);
CREATE UNIQUE INDEX archetype_one_active_bundle_uq ON catalog.archetype_bundle_binding (archetype_version_id) WHERE state_code = 'active';

CREATE TABLE catalog.archetype_capacity_policy (
  id uuid PRIMARY KEY,
  archetype_version_id uuid NOT NULL UNIQUE REFERENCES catalog.environment_archetype_version(id) ON DELETE RESTRICT,
  max_credentials integer NOT NULL CHECK (max_credentials >= 1),
  max_connections integer NOT NULL CHECK (max_connections >= 1),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE catalog.evidence_item (
  id uuid PRIMARY KEY,
  evidence_set_id uuid NOT NULL REFERENCES catalog.evidence_set(id) ON DELETE CASCADE,
  kind_code text NOT NULL CHECK (kind_code IN ('headers','metadata','attribution','tls','http2','replay','privacy_scan')),
  object_uri text,
  payload jsonb,
  content_hash bytea NOT NULL,
  captured_at timestamptz NOT NULL,
  CHECK ((object_uri IS NULL) <> (payload IS NULL))
);

CREATE TABLE catalog.capture_run (
  id uuid PRIMARY KEY,
  evidence_set_id uuid NOT NULL REFERENCES catalog.evidence_set(id) ON DELETE RESTRICT,
  os_family_code text NOT NULL CHECK (os_family_code IN ('windows','macos','linux')),
  runner_version text NOT NULL,
  client_version text NOT NULL,
  state_code text NOT NULL CHECK (state_code IN ('queued','running','succeeded','failed')),
  privacy_scan_code text,
  started_at timestamptz,
  completed_at timestamptz,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE catalog.replay_verification (
  id uuid PRIMARY KEY,
  archetype_version_id uuid NOT NULL REFERENCES catalog.environment_archetype_version(id) ON DELETE RESTRICT,
  transport_bundle_id uuid NOT NULL REFERENCES catalog.transport_bundle(id) ON DELETE RESTRICT,
  evidence_set_id uuid NOT NULL REFERENCES catalog.evidence_set(id) ON DELETE RESTRICT,
  state_code text NOT NULL CHECK (state_code IN ('passed','failed','inconclusive')),
  result jsonb NOT NULL,
  verified_at timestamptz NOT NULL
);

CREATE TABLE catalog.bundle_runtime_incident (
  id uuid PRIMARY KEY,
  transport_bundle_id uuid NOT NULL REFERENCES catalog.transport_bundle(id) ON DELETE RESTRICT,
  archetype_version_id uuid REFERENCES catalog.environment_archetype_version(id) ON DELETE RESTRICT,
  severity_code text NOT NULL CHECK (severity_code IN ('warning','critical')),
  state_code text NOT NULL CHECK (state_code IN ('open','resolved')),
  reason_code text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  opened_at timestamptz NOT NULL,
  resolved_at timestamptz
);

CREATE TABLE catalog.versioned_artifact (
  id uuid PRIMARY KEY,
  artifact_kind_code text NOT NULL,
  scope_type_code text,
  scope_id uuid,
  artifact_version bigint NOT NULL CHECK (artifact_version >= 1),
  lifecycle_code text NOT NULL CHECK (lifecycle_code IN ('draft','validating','eligible','shadow','canary','active','retired','quarantined')),
  payload jsonb,
  object_uri text,
  content_hash bytea NOT NULL,
  schema_version bigint NOT NULL CHECK (schema_version >= 1),
  evidence_set_id uuid REFERENCES catalog.evidence_set(id) ON DELETE RESTRICT,
  created_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  retired_at timestamptz,
  quarantined_at timestamptz,
  CHECK ((payload IS NULL) <> (object_uri IS NULL)),
  UNIQUE NULLS NOT DISTINCT (artifact_kind_code, scope_type_code, scope_id, artifact_version),
  UNIQUE NULLS NOT DISTINCT (artifact_kind_code, scope_type_code, scope_id, content_hash)
);

CREATE TABLE catalog.active_artifact_pointer (
  id uuid PRIMARY KEY,
  artifact_kind_code text NOT NULL,
  scope_type_code text,
  scope_id uuid,
  artifact_id uuid NOT NULL UNIQUE REFERENCES catalog.versioned_artifact(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  activated_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  activated_at timestamptz NOT NULL,
  UNIQUE NULLS NOT DISTINCT (artifact_kind_code, scope_type_code, scope_id)
);

CREATE TABLE catalog.artifact_dependency (
  artifact_id uuid NOT NULL REFERENCES catalog.versioned_artifact(id) ON DELETE CASCADE,
  dependency_artifact_id uuid NOT NULL REFERENCES catalog.versioned_artifact(id) ON DELETE RESTRICT,
  dependency_kind_code text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (artifact_id, dependency_artifact_id),
  CHECK (artifact_id <> dependency_artifact_id)
);

CREATE TABLE catalog.compiled_rule_index (
  artifact_id uuid PRIMARY KEY REFERENCES catalog.versioned_artifact(id) ON DELETE CASCADE,
  compiler_version text NOT NULL,
  compiled_payload bytea NOT NULL,
  compiled_hash bytea NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE catalog.model_definition (
  id uuid PRIMARY KEY,
  upstream_model_id text NOT NULL UNIQUE,
  display_name text NOT NULL,
  lifecycle_code text NOT NULL CHECK (lifecycle_code IN ('discovered','reviewing','published','deprecated','disabled')),
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1)
);

CREATE TABLE catalog.model_alias (
  id uuid PRIMARY KEY,
  alias text NOT NULL UNIQUE,
  model_id uuid NOT NULL REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  retired_at timestamptz
);

CREATE TABLE catalog.model_capability (
  id uuid PRIMARY KEY,
  model_id uuid NOT NULL REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  capability_version bigint NOT NULL CHECK (capability_version >= 1),
  lifecycle_code text NOT NULL CHECK (lifecycle_code IN ('candidate','active','retired')),
  schema_payload jsonb NOT NULL,
  content_hash bytea NOT NULL,
  created_at timestamptz NOT NULL,
  activated_at timestamptz,
  UNIQUE (model_id, capability_version),
  UNIQUE (model_id, content_hash)
);
CREATE UNIQUE INDEX model_one_active_capability_uq ON catalog.model_capability (model_id) WHERE lifecycle_code = 'active';

CREATE TABLE catalog.price_entry (
  id uuid PRIMARY KEY,
  model_id uuid NOT NULL REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  price_version bigint NOT NULL CHECK (price_version >= 1),
  currency_code text NOT NULL DEFAULT 'USD',
  input_per_million numeric(38,12) NOT NULL CHECK (input_per_million >= 0),
  output_per_million numeric(38,12) NOT NULL CHECK (output_per_million >= 0),
  cache_write_per_million numeric(38,12) NOT NULL CHECK (cache_write_per_million >= 0),
  cache_read_per_million numeric(38,12) NOT NULL CHECK (cache_read_per_million >= 0),
  effective_from timestamptz NOT NULL,
  effective_to timestamptz,
  source_uri text,
  content_hash bytea NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (model_id, price_version)
);

CREATE TABLE gateway.credential_group (
  id uuid PRIMARY KEY,
  owner_executor_id text,
  owner_generation bigint NOT NULL DEFAULT 1 CHECK (owner_generation >= 1),
  name text NOT NULL UNIQUE,
  status_code text NOT NULL CHECK (status_code IN ('active','disabled','archived','draining')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  archived_at timestamptz,
  CHECK ((status_code = 'archived') = (archived_at IS NOT NULL))
);

CREATE TABLE gateway.group_config (
  id uuid PRIMARY KEY,
  group_id uuid NOT NULL REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  config_version bigint NOT NULL CHECK (config_version >= 1),
  content_hash bytea NOT NULL,
  default_rpm integer NOT NULL CHECK (default_rpm >= 1),
  queue_capacity integer NOT NULL CHECK (queue_capacity >= 0),
  queue_timeout_ms bigint NOT NULL CHECK (queue_timeout_ms >= 0),
  ruleset_artifact_id uuid REFERENCES catalog.versioned_artifact(id) ON DELETE RESTRICT,
  system_prompt_mode_code text NOT NULL CHECK (system_prompt_mode_code IN ('preserve','strip','replace')),
  proxy_policy_code text NOT NULL CHECK (proxy_policy_code IN ('optional','required','disabled')),
  model_scope_code text NOT NULL CHECK (model_scope_code IN ('all_published','allowlist')),
  created_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  UNIQUE (group_id, config_version),
  UNIQUE (group_id, content_hash)
);

CREATE TABLE gateway.group_accepted_client_class (
  group_config_id uuid NOT NULL REFERENCES gateway.group_config(id) ON DELETE CASCADE,
  client_class_code text NOT NULL CHECK (client_class_code IN ('claude_code_cli','non_claude_code_cli')),
  PRIMARY KEY (group_config_id, client_class_code)
);

CREATE TABLE gateway.group_model_allowlist (
  group_config_id uuid NOT NULL REFERENCES gateway.group_config(id) ON DELETE CASCADE,
  model_id uuid NOT NULL REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  PRIMARY KEY (group_config_id, model_id)
);

CREATE TABLE gateway.group_active_config (
  group_id uuid PRIMARY KEY REFERENCES gateway.credential_group(id) ON DELETE CASCADE,
  config_id uuid NOT NULL UNIQUE REFERENCES gateway.group_config(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  activated_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  activated_at timestamptz NOT NULL
);

CREATE TABLE gateway.anthropic_credential (
  id uuid PRIMARY KEY,
  group_id uuid NOT NULL REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  account_uuid uuid,
  purpose_code text NOT NULL CHECK (purpose_code IN ('claude_subscription','console_api')),
  auth_kind_code text NOT NULL CHECK (auth_kind_code IN ('oauth','setup_token','console_api_key')),
  lifecycle_state_code text NOT NULL CHECK (lifecycle_state_code IN ('pending_profile','pending_egress','active','disabled','archived','manual_recovery_required')),
  auth_state_code text NOT NULL CHECK (auth_state_code IN ('pending','healthy','refreshing','invalid')),
  scheduling_state_code text NOT NULL CHECK (scheduling_state_code IN ('eligible','cooldown','blocked','transport_unavailable')),
  quota_state_code text NOT NULL CHECK (quota_state_code IN ('unknown','healthy','pressured','exhausted')),
  transport_state_code text NOT NULL CHECK (transport_state_code IN ('pending','ready','drifted','unavailable')),
  attachment_target_group_id uuid REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  attachment_deadline timestamptz,
  cooldown_until timestamptz,
  half_open_after timestamptz,
  management_class_code text NOT NULL CHECK (management_class_code IN ('fully_managed','non_managed')),
  token_version bigint NOT NULL DEFAULT 1 CHECK (token_version >= 1),
  active_auth_version_id uuid,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  archived_at timestamptz
);
CREATE UNIQUE INDEX anthropic_credential_account_uuid_uq ON gateway.anthropic_credential (account_uuid) WHERE account_uuid IS NOT NULL;
CREATE INDEX anthropic_credential_group_state_idx ON gateway.anthropic_credential (group_id, scheduling_state_code, lifecycle_state_code);

CREATE TABLE gateway.credential_auth_version (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  token_version bigint NOT NULL CHECK (token_version >= 1),
  auth_kind_code text NOT NULL CHECK (auth_kind_code IN ('oauth','setup_token','console_api_key')),
  access_secret_id uuid REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  refresh_secret_id uuid REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  setup_secret_id uuid REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  console_secret_id uuid REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  verified_account_uuid uuid,
  issued_at timestamptz,
  expires_at timestamptz,
  operation_id uuid,
  created_at timestamptz NOT NULL,
  superseded_at timestamptz,
  UNIQUE (credential_id, token_version),
  CHECK (
    (auth_kind_code = 'oauth' AND access_secret_id IS NOT NULL AND refresh_secret_id IS NOT NULL AND setup_secret_id IS NULL AND console_secret_id IS NULL)
    OR (auth_kind_code = 'setup_token' AND setup_secret_id IS NOT NULL AND access_secret_id IS NULL AND refresh_secret_id IS NULL AND console_secret_id IS NULL)
    OR (auth_kind_code = 'console_api_key' AND console_secret_id IS NOT NULL AND access_secret_id IS NULL AND refresh_secret_id IS NULL AND setup_secret_id IS NULL)
  )
);
ALTER TABLE gateway.anthropic_credential ADD CONSTRAINT credential_active_auth_version_fk
  FOREIGN KEY (active_auth_version_id) REFERENCES gateway.credential_auth_version(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE gateway.credential_enrollment (
  id uuid PRIMARY KEY,
  kind_code text NOT NULL CHECK (kind_code IN ('create','recover')),
  state_code text NOT NULL CHECK (state_code IN ('created','awaiting_callback','exchanging','verifying','committing','completed','failed','expired','cancelled')),
  next_action_code text NOT NULL CHECK (next_action_code IN ('open_authorization','submit_callback','wait','none')),
  requested_group_id uuid REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  recover_credential_id uuid REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  expected_credential_revision bigint CHECK (expected_credential_revision >= 1),
  authorization_uri text,
  callback_uri text,
  pkce_state_digest bytea,
  callback_consumed_at timestamptz,
  expires_at timestamptz NOT NULL,
  callback_expires_at timestamptz,
  error_code text,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK ((kind_code = 'create') = (requested_group_id IS NOT NULL)),
  CHECK ((kind_code = 'recover') = (recover_credential_id IS NOT NULL AND expected_credential_revision IS NOT NULL)),
  CHECK (kind_code <> 'create' OR recover_credential_id IS NULL),
  CHECK (state_code NOT IN ('completed','failed','expired','cancelled') OR next_action_code = 'none')
);

CREATE TABLE gateway.credential_scheduling_config (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  config_version bigint NOT NULL CHECK (config_version >= 1),
  max_concurrency integer NOT NULL CHECK (max_concurrency >= 1),
  rpm_limit integer NOT NULL CHECK (rpm_limit >= 1),
  weight numeric(20,9) NOT NULL DEFAULT 1 CHECK (weight > 0),
  enabled boolean NOT NULL DEFAULT true,
  content_hash bytea NOT NULL,
  created_at timestamptz NOT NULL,
  UNIQUE (credential_id, config_version),
  UNIQUE (credential_id, content_hash)
);

CREATE TABLE gateway.credential_active_scheduling_config (
  credential_id uuid PRIMARY KEY REFERENCES gateway.anthropic_credential(id) ON DELETE CASCADE,
  config_id uuid NOT NULL UNIQUE REFERENCES gateway.credential_scheduling_config(id) ON DELETE RESTRICT,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  activated_at timestamptz NOT NULL
);

CREATE TABLE gateway.credential_transport_blocker (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE CASCADE,
  blocker_code text NOT NULL CHECK (blocker_code IN ('profile_missing','egress_missing','bundle_unavailable','egress_drift','proxy_unhealthy','transport_unavailable')),
  state_code text NOT NULL CHECK (state_code IN ('active','cleared')),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at timestamptz NOT NULL,
  cleared_at timestamptz
);
CREATE UNIQUE INDEX credential_active_blocker_uq ON gateway.credential_transport_blocker (credential_id, blocker_code) WHERE state_code = 'active';

CREATE TABLE gateway.credential_group_migration (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  source_group_id uuid NOT NULL REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  target_group_id uuid NOT NULL REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  state_code text NOT NULL CHECK (state_code IN ('planned','draining','committed','cancelled','failed')),
  expected_revision bigint NOT NULL CHECK (expected_revision >= 1),
  requested_by uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  completed_at timestamptz,
  CHECK (source_group_id <> target_group_id)
);

CREATE TABLE gateway.proxy_endpoint (
  id uuid PRIMARY KEY,
  proxy_type_code text NOT NULL CHECK (proxy_type_code IN ('connect','socks5')),
  host text NOT NULL,
  port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
  auth_secret_id uuid REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  lifecycle_code text NOT NULL CHECK (lifecycle_code IN ('active','disabled','archived')),
  health_code text NOT NULL CHECK (health_code IN ('unknown','healthy','unhealthy')),
  stability_code text NOT NULL CHECK (stability_code IN ('unknown','stable','drifted')),
  expected_egress_ip inet,
  observed_egress_ip inet,
  max_active_bindings integer NOT NULL DEFAULT 5 CHECK (max_active_bindings = 5),
  last_probed_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  archived_at timestamptz,
  CHECK ((lifecycle_code = 'archived') = (archived_at IS NOT NULL))
);

CREATE TABLE gateway.credential_egress_binding (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL UNIQUE REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  mode_code text NOT NULL CHECK (mode_code IN ('direct','proxy')),
  proxy_id uuid REFERENCES gateway.proxy_endpoint(id) ON DELETE RESTRICT,
  stability_code text NOT NULL CHECK (stability_code IN ('pending','stable','drifted','unavailable')),
  lifecycle_code text NOT NULL CHECK (lifecycle_code IN ('pending','active','disabled')),
  egress_epoch bigint NOT NULL DEFAULT 1 CHECK (egress_epoch >= 1),
  expected_egress_ip inet,
  observed_egress_ip inet,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK ((mode_code = 'proxy') = (proxy_id IS NOT NULL))
);
CREATE INDEX egress_binding_proxy_active_idx ON gateway.credential_egress_binding (proxy_id) WHERE lifecycle_code = 'active' AND proxy_id IS NOT NULL;

CREATE TABLE gateway.egress_observation (
  id uuid PRIMARY KEY,
  egress_binding_id uuid NOT NULL REFERENCES gateway.credential_egress_binding(id) ON DELETE CASCADE,
  egress_epoch bigint NOT NULL CHECK (egress_epoch >= 1),
  observed_ip inet,
  probe_code text NOT NULL CHECK (probe_code IN ('success','timeout','mismatch','error')),
  latency_ms integer CHECK (latency_ms >= 0),
  observed_at timestamptz NOT NULL
);

CREATE TABLE gateway.device_identity (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL UNIQUE REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  installation_id_secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  client_id_secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  profile_seed_secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  session_hmac_secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  installation_id_digest bytea NOT NULL UNIQUE,
  client_id_digest bytea NOT NULL UNIQUE,
  device_epoch bigint NOT NULL DEFAULT 1 CHECK (device_epoch >= 1),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE gateway.credential_profile (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL UNIQUE REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  archetype_version_id uuid NOT NULL REFERENCES catalog.environment_archetype_version(id) ON DELETE RESTRICT,
  device_identity_id uuid NOT NULL UNIQUE REFERENCES gateway.device_identity(id) ON DELETE RESTRICT,
  egress_binding_id uuid NOT NULL UNIQUE REFERENCES gateway.credential_egress_binding(id) ON DELETE RESTRICT,
  profile_epoch bigint NOT NULL DEFAULT 1 CHECK (profile_epoch >= 1),
  lifecycle_code text NOT NULL CHECK (lifecycle_code IN ('pending','active','upgrading','disabled')),
  capture_cohort text NOT NULL,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE gateway.credential_profile_change (
  id uuid PRIMARY KEY,
  credential_profile_id uuid NOT NULL REFERENCES gateway.credential_profile(id) ON DELETE RESTRICT,
  from_archetype_version_id uuid REFERENCES catalog.environment_archetype_version(id) ON DELETE RESTRICT,
  to_archetype_version_id uuid NOT NULL REFERENCES catalog.environment_archetype_version(id) ON DELETE RESTRICT,
  from_profile_epoch bigint CHECK (from_profile_epoch >= 1),
  to_profile_epoch bigint NOT NULL CHECK (to_profile_epoch >= 1),
  reason_code text NOT NULL,
  cohort_code text NOT NULL,
  approved_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  changed_at timestamptz NOT NULL
);

CREATE TABLE gateway.maintenance_operation (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  kind_code text NOT NULL CHECK (kind_code IN ('refresh','reauth','recover','plan_refresh','profile_upgrade','egress_rebind')),
  trigger_code text NOT NULL CHECK (trigger_code IN ('system','administrator','scheduler','startup')),
  conflict_class_code text NOT NULL CHECK (conflict_class_code IN ('auth','profile','egress','observation')),
  state_code text NOT NULL CHECK (state_code IN ('scheduled','leased','waiting_external','committing','succeeded','failed','cancelled')),
  expected_credential_revision bigint CHECK (expected_credential_revision >= 1),
  expected_token_version bigint CHECK (expected_token_version >= 1),
  egress_epoch_snapshot bigint CHECK (egress_epoch_snapshot >= 1),
  operation_generation bigint NOT NULL DEFAULT 1 CHECK (operation_generation >= 1),
  adapter_code text,
  retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
  retry_after timestamptz,
  outcome_code text,
  durable_job_id uuid REFERENCES ops.durable_job(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  completed_at timestamptz
);
CREATE UNIQUE INDEX maintenance_operation_active_conflict_uq
  ON gateway.maintenance_operation (credential_id, conflict_class_code)
  WHERE state_code IN ('scheduled','leased','waiting_external','committing');

CREATE TABLE gateway.auto_reauth_strategy (
  credential_id uuid PRIMARY KEY REFERENCES gateway.anthropic_credential(id) ON DELETE CASCADE,
  state_code text NOT NULL CHECK (state_code IN ('pending','healthy','degraded','invalid','disabled')),
  browser_provider_code text,
  last_verified_at timestamptz,
  last_error_code text,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE gateway.managed_browser_material_version (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  material_version bigint NOT NULL CHECK (material_version >= 1),
  secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  egress_epoch bigint CHECK (egress_epoch >= 1),
  state_code text NOT NULL CHECK (state_code IN ('active','superseded','invalid')),
  created_at timestamptz NOT NULL,
  superseded_at timestamptz,
  UNIQUE (credential_id, material_version)
);
CREATE UNIQUE INDEX managed_browser_one_active_uq ON gateway.managed_browser_material_version (credential_id) WHERE state_code = 'active';

CREATE OR REPLACE FUNCTION gateway.validate_profile_components() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE device_credential uuid; egress_credential uuid;
BEGIN
  SELECT credential_id INTO device_credential FROM gateway.device_identity WHERE id = NEW.device_identity_id;
  SELECT credential_id INTO egress_credential FROM gateway.credential_egress_binding WHERE id = NEW.egress_binding_id;
  IF device_credential IS DISTINCT FROM NEW.credential_id OR egress_credential IS DISTINCT FROM NEW.credential_id THEN
    RAISE EXCEPTION 'credential profile components must share one credential' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER credential_profile_components_match
  AFTER INSERT OR UPDATE ON gateway.credential_profile DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION gateway.validate_profile_components();

CREATE OR REPLACE FUNCTION catalog.validate_active_artifact_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE candidate catalog.versioned_artifact%ROWTYPE;
BEGIN
  SELECT * INTO candidate FROM catalog.versioned_artifact WHERE id = NEW.artifact_id;
  IF candidate.id IS NULL OR candidate.artifact_kind_code IS DISTINCT FROM NEW.artifact_kind_code
     OR candidate.scope_type_code IS DISTINCT FROM NEW.scope_type_code OR candidate.scope_id IS DISTINCT FROM NEW.scope_id
     OR candidate.lifecycle_code <> 'active' THEN
    RAISE EXCEPTION 'active artifact pointer target mismatch' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER active_artifact_pointer_matches
  AFTER INSERT OR UPDATE ON catalog.active_artifact_pointer DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION catalog.validate_active_artifact_pointer();

CREATE TABLE iam.platform_key (
  id uuid PRIMARY KEY,
  owner_user_id uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  group_id uuid NOT NULL REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  name text NOT NULL,
  secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  status_code text NOT NULL CHECK (status_code IN ('active','disabled','revoked','expired')),
  expires_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  revoked_at timestamptz,
  UNIQUE (owner_user_id, name)
);

CREATE OR REPLACE FUNCTION iam.reject_platform_key_rebind() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id OR NEW.group_id IS DISTINCT FROM OLD.group_id OR NEW.secret_id IS DISTINCT FROM OLD.secret_id THEN
    RAISE EXCEPTION 'platform key binding is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER platform_key_rebind_rejected BEFORE UPDATE ON iam.platform_key
  FOR EACH ROW EXECUTE FUNCTION iam.reject_platform_key_rebind();

CREATE TABLE iam.platform_key_config (
  id uuid PRIMARY KEY,
  platform_key_id uuid NOT NULL REFERENCES iam.platform_key(id) ON DELETE RESTRICT,
  config_version bigint NOT NULL CHECK (config_version >= 1),
  content_hash bytea NOT NULL,
  messages_enabled boolean NOT NULL DEFAULT true,
  models_enabled boolean NOT NULL DEFAULT true,
  max_body_bytes bigint NOT NULL CHECK (max_body_bytes >= 1),
  messages_rpm integer NOT NULL CHECK (messages_rpm >= 1),
  messages_burst integer NOT NULL CHECK (messages_burst >= 1),
  models_rpm integer NOT NULL CHECK (models_rpm >= 1),
  models_burst integer NOT NULL CHECK (models_burst >= 1),
  max_concurrency integer NOT NULL DEFAULT 5 CHECK (max_concurrency >= 1),
  ruleset_artifact_id uuid REFERENCES catalog.versioned_artifact(id) ON DELETE RESTRICT,
  audit_mode_code text NOT NULL CHECK (audit_mode_code IN ('metadata','full_encrypted')),
  created_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  UNIQUE (platform_key_id, config_version),
  UNIQUE (platform_key_id, content_hash)
);

CREATE TABLE iam.platform_key_model_allowlist (
  platform_key_config_id uuid NOT NULL REFERENCES iam.platform_key_config(id) ON DELETE CASCADE,
  model_id uuid NOT NULL REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  PRIMARY KEY (platform_key_config_id, model_id)
);

CREATE TABLE iam.platform_key_ip_allowlist (
  platform_key_config_id uuid NOT NULL REFERENCES iam.platform_key_config(id) ON DELETE CASCADE,
  network cidr NOT NULL,
  PRIMARY KEY (platform_key_config_id, network)
);

CREATE TABLE iam.platform_key_active_config (
  platform_key_id uuid PRIMARY KEY REFERENCES iam.platform_key(id) ON DELETE CASCADE,
  config_id uuid NOT NULL UNIQUE REFERENCES iam.platform_key_config(id) ON DELETE RESTRICT,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  activated_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  activated_at timestamptz NOT NULL
);

CREATE TABLE iam.platform_key_secret_reveal (
  id uuid PRIMARY KEY,
  platform_key_id uuid NOT NULL REFERENCES iam.platform_key(id) ON DELETE RESTRICT,
  requested_by uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  step_up_grant_id uuid NOT NULL REFERENCES iam.management_step_up_grant(id) ON DELETE RESTRICT,
  revealed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (expires_at > revealed_at)
);

CREATE TABLE iam.api_idempotency_record (
  id uuid PRIMARY KEY,
  actor_type_code text NOT NULL,
  actor_id uuid NOT NULL,
  method text NOT NULL,
  normalized_path text NOT NULL,
  idempotency_key text NOT NULL,
  request_digest bytea NOT NULL,
  result_status integer,
  result_reference jsonb,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  UNIQUE (actor_type_code, actor_id, method, normalized_path, idempotency_key),
  CHECK (expires_at > created_at)
);
CREATE INDEX api_idempotency_expiry_idx ON iam.api_idempotency_record (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA iam, gateway, catalog TO gateway_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA iam, gateway, catalog TO gateway_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA iam, gateway, catalog TO gateway_backup;

RESET ROLE;
