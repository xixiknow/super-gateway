-- R2 foundation: schemas, database roles, key material, IAM, audit and durable operations.

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_migrator') THEN CREATE ROLE gateway_migrator NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_runtime') THEN CREATE ROLE gateway_runtime NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_readonly') THEN CREATE ROLE gateway_readonly NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_backup') THEN CREATE ROLE gateway_backup NOLOGIN; END IF;
END
$roles$;

CREATE SCHEMA IF NOT EXISTS iam AUTHORIZATION gateway_migrator;
CREATE SCHEMA IF NOT EXISTS gateway AUTHORIZATION gateway_migrator;
CREATE SCHEMA IF NOT EXISTS catalog AUTHORIZATION gateway_migrator;
CREATE SCHEMA IF NOT EXISTS telemetry AUTHORIZATION gateway_migrator;
CREATE SCHEMA IF NOT EXISTS security AUTHORIZATION gateway_migrator;
CREATE SCHEMA IF NOT EXISTS ops AUTHORIZATION gateway_migrator;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA iam, gateway, catalog, telemetry, security, ops TO gateway_runtime;
GRANT USAGE ON SCHEMA iam, gateway, catalog, telemetry, security, ops TO gateway_readonly;
GRANT USAGE ON SCHEMA iam, gateway, catalog, telemetry, security, ops TO gateway_backup;
GRANT USAGE ON SCHEMA public TO gateway_runtime;
GRANT SELECT ON TABLE public._sqlx_migrations TO gateway_runtime;

SET LOCAL ROLE gateway_migrator;

ALTER DEFAULT PRIVILEGES FOR ROLE gateway_migrator IN SCHEMA iam, gateway, catalog, telemetry, security, ops
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO gateway_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE gateway_migrator IN SCHEMA iam, gateway, catalog, telemetry, security, ops
  GRANT USAGE, SELECT ON SEQUENCES TO gateway_runtime;

CREATE TABLE security.business_key_material (
  key_version bigint PRIMARY KEY CHECK (key_version >= 1),
  provider_code text NOT NULL CHECK (provider_code IN ('database','file','uri')),
  key_material bytea,
  provider_reference text,
  state_code text NOT NULL CHECK (state_code IN ('active','decrypt_only','retired','destroyed')),
  checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
  created_at timestamptz NOT NULL,
  activated_at timestamptz,
  retired_at timestamptz,
  destroyed_at timestamptz,
  CHECK ((provider_code = 'database') = (key_material IS NOT NULL)),
  CHECK ((provider_code = 'database') = (provider_reference IS NULL)),
  CHECK ((state_code = 'destroyed') = (destroyed_at IS NOT NULL)),
  CHECK (state_code <> 'destroyed' OR key_material IS NULL)
);
CREATE UNIQUE INDEX business_key_one_active ON security.business_key_material ((true)) WHERE state_code = 'active';

CREATE TABLE security.encrypted_secret (
  id uuid PRIMARY KEY,
  secret_kind_code text NOT NULL CHECK (secret_kind_code IN ('platform_key','oauth_access_token','oauth_refresh_token','setup_token','console_api_key','proxy_password','device_identity','session_hmac','managed_browser','notification_destination','totp_seed')),
  provider_role_code text NOT NULL CHECK (provider_role_code IN ('business','content_audit','backup','audit_integrity')),
  cipher_suite_code text NOT NULL DEFAULT 'aes_256_gcm' CHECK (cipher_suite_code = 'aes_256_gcm'),
  ciphertext bytea NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  wrapped_dek bytea NOT NULL,
  key_version bigint NOT NULL CHECK (key_version >= 1),
  aad_schema_version integer NOT NULL DEFAULT 1 CHECK (aad_schema_version >= 1),
  owner_type_code text NOT NULL,
  owner_id text NOT NULL,
  purpose_code text NOT NULL,
  lookup_digest bytea,
  digest_key_version bigint CHECK (digest_key_version >= 1),
  display_prefix text,
  created_at timestamptz NOT NULL,
  superseded_at timestamptz,
  destroyed_at timestamptz,
  CHECK ((lookup_digest IS NULL) = (digest_key_version IS NULL)),
  CHECK (destroyed_at IS NULL OR superseded_at IS NOT NULL)
);
CREATE UNIQUE INDEX encrypted_secret_live_lookup_uq
  ON security.encrypted_secret (secret_kind_code, lookup_digest)
  WHERE lookup_digest IS NOT NULL AND superseded_at IS NULL AND destroyed_at IS NULL;

CREATE TABLE iam.user_account (
  id uuid PRIMARY KEY,
  username text NOT NULL,
  username_normalized text NOT NULL UNIQUE,
  display_name text,
  email text,
  email_normalized text UNIQUE,
  role_code text NOT NULL CHECK (role_code IN ('platform_admin','key_owner')),
  status_code text NOT NULL CHECK (status_code IN ('active','disabled','archived','mfa_pending')),
  password_credential_id uuid,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  archived_at timestamptz,
  CHECK ((status_code = 'archived') = (archived_at IS NOT NULL))
);

CREATE TABLE iam.password_credential (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  password_phc text NOT NULL,
  parameters_version bigint NOT NULL CHECK (parameters_version >= 1),
  created_at timestamptz NOT NULL,
  last_changed_at timestamptz NOT NULL,
  force_change boolean NOT NULL DEFAULT false,
  superseded_at timestamptz
);
CREATE UNIQUE INDEX password_credential_live_user_uq ON iam.password_credential (user_id) WHERE superseded_at IS NULL;
ALTER TABLE iam.user_account ADD CONSTRAINT user_password_credential_fk
  FOREIGN KEY (password_credential_id) REFERENCES iam.password_credential(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE iam.mfa_enrollment (
  user_id uuid PRIMARY KEY REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  totp_secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  state_code text NOT NULL CHECK (state_code IN ('pending','verified','disabled','locked')),
  algorithm_code text NOT NULL DEFAULT 'sha1' CHECK (algorithm_code = 'sha1'),
  digits smallint NOT NULL DEFAULT 6 CHECK (digits = 6),
  period_seconds smallint NOT NULL DEFAULT 30 CHECK (period_seconds = 30),
  verified_at timestamptz,
  last_accepted_step bigint,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE iam.management_session (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  token_digest bytea NOT NULL UNIQUE,
  digest_key_version bigint NOT NULL CHECK (digest_key_version >= 1),
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  mfa_verified boolean NOT NULL DEFAULT false,
  source_ip inet,
  user_agent_summary text,
  session_revision bigint NOT NULL DEFAULT 1 CHECK (session_revision >= 1),
  CHECK (expires_at > created_at)
);
CREATE INDEX management_session_active_user_idx ON iam.management_session (user_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE iam.management_step_up_grant (
  id uuid PRIMARY KEY,
  management_session_id uuid NOT NULL REFERENCES iam.management_session(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  purpose_code text NOT NULL,
  auth_context_digest bytea NOT NULL,
  verified_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL,
  CHECK (expires_at > verified_at),
  CHECK (consumed_at IS NULL OR consumed_at >= verified_at)
);
CREATE INDEX management_step_up_lookup_idx ON iam.management_step_up_grant (management_session_id, purpose_code, expires_at);

CREATE TABLE security.audit_chain_head (
  event_day date PRIMARY KEY,
  event_count bigint NOT NULL DEFAULT 0 CHECK (event_count >= 0),
  last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
  last_event_hash bytea CHECK (last_event_hash IS NULL OR octet_length(last_event_hash) = 32),
  updated_at timestamptz NOT NULL,
  CHECK ((event_count = 0) = (last_event_hash IS NULL)),
  CHECK (event_count = last_sequence)
);

CREATE TABLE security.audit_event (
  event_day date NOT NULL,
  event_id uuid NOT NULL,
  daily_sequence bigint NOT NULL CHECK (daily_sequence >= 1),
  actor_type_code text NOT NULL CHECK (actor_type_code IN ('system','platform_admin','key_owner','platform_key')),
  actor_id uuid,
  action_code text NOT NULL,
  object_type_code text NOT NULL,
  object_id text,
  outcome_code text NOT NULL CHECK (outcome_code IN ('success','denied','failed')),
  canonical_redacted_event jsonb NOT NULL,
  previous_hash bytea CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
  event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (event_day, event_id),
  UNIQUE (event_day, daily_sequence)
);
CREATE INDEX audit_event_object_idx ON security.audit_event (object_type_code, object_id, occurred_at DESC);

CREATE TABLE security.audit_daily_seal (
  event_day date PRIMARY KEY,
  event_count bigint NOT NULL CHECK (event_count >= 0),
  first_event_hash bytea,
  last_event_hash bytea,
  previous_day_seal_digest bytea,
  seal_digest bytea NOT NULL CHECK (octet_length(seal_digest) = 32),
  integrity_key_version bigint NOT NULL CHECK (integrity_key_version >= 1),
  sealed_at timestamptz NOT NULL
);

CREATE TABLE security.deletion_ledger (
  ledger_sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  entry_id uuid NOT NULL UNIQUE,
  object_type_code text NOT NULL,
  object_id text NOT NULL,
  object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
  action_code text NOT NULL CHECK (action_code IN ('scheduled','key_destroyed','object_deleted','verified_absent','restored_object_deleted')),
  previous_hash bytea CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
  entry_hash bytea NOT NULL CHECK (octet_length(entry_hash) = 32),
  occurred_at timestamptz NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE UNIQUE INDEX deletion_ledger_object_action_uq ON security.deletion_ledger (object_type_code, object_id, action_code);

CREATE TABLE security.approval_case (
  id uuid PRIMARY KEY,
  operation_code text NOT NULL,
  object_type_code text NOT NULL,
  object_id text NOT NULL,
  requested_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  state_code text NOT NULL CHECK (state_code IN ('pending','approved','rejected','expired','consumed')),
  required_approvals smallint NOT NULL DEFAULT 2 CHECK (required_approvals >= 1),
  request_digest bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1)
);

CREATE TABLE security.approval_grant (
  id uuid PRIMARY KEY,
  approval_case_id uuid NOT NULL REFERENCES security.approval_case(id) ON DELETE CASCADE,
  approver_user_id uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  decision_code text NOT NULL CHECK (decision_code IN ('approve','reject')),
  decided_at timestamptz NOT NULL,
  UNIQUE (approval_case_id, approver_user_id)
);

CREATE TABLE security.platform_key_auth_event (
  id uuid PRIMARY KEY,
  platform_key_id uuid NOT NULL,
  source_ip inet,
  outcome_code text NOT NULL CHECK (outcome_code IN ('accepted','invalid','disabled','expired','rate_limited')),
  occurred_at timestamptz NOT NULL,
  detail_code text
);
CREATE INDEX platform_key_auth_event_key_time_idx ON security.platform_key_auth_event (platform_key_id, occurred_at DESC);

CREATE TABLE security.content_audit_object (
  id uuid PRIMARY KEY,
  request_month date,
  request_id uuid,
  attempt_id uuid,
  owner_user_id uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  scope_code text NOT NULL CHECK (scope_code IN ('metadata','full_encrypted')),
  object_uri text,
  encrypted_dek bytea,
  key_version bigint CHECK (key_version >= 1),
  content_sha256 bytea CHECK (content_sha256 IS NULL OR octet_length(content_sha256) = 32),
  content_length bigint CHECK (content_length IS NULL OR content_length >= 0),
  state_code text NOT NULL CHECK (state_code IN ('active','deletion_pending','deleted','held')),
  expires_at timestamptz,
  created_at timestamptz NOT NULL,
  deleted_at timestamptz,
  CHECK (scope_code <> 'full_encrypted' OR (object_uri IS NOT NULL AND encrypted_dek IS NOT NULL AND key_version IS NOT NULL))
);

CREATE TABLE security.content_audit_access (
  id uuid PRIMARY KEY,
  content_audit_object_id uuid NOT NULL REFERENCES security.content_audit_object(id) ON DELETE RESTRICT,
  actor_user_id uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  approval_case_id uuid REFERENCES security.approval_case(id) ON DELETE RESTRICT,
  action_code text NOT NULL CHECK (action_code IN ('metadata_read','content_read','export','delete')),
  occurred_at timestamptz NOT NULL
);

CREATE TABLE security.legal_hold (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  reason text NOT NULL,
  state_code text NOT NULL CHECK (state_code IN ('active','released')),
  created_by uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  released_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  released_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1)
);

CREATE TABLE security.legal_hold_object (
  legal_hold_id uuid NOT NULL REFERENCES security.legal_hold(id) ON DELETE CASCADE,
  object_type_code text NOT NULL,
  object_id text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (legal_hold_id, object_type_code, object_id)
);

CREATE TABLE ops.schema_migration (
  version bigint PRIMARY KEY CHECK (version >= 1),
  name text NOT NULL UNIQUE,
  checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  release_id text,
  outcome_code text NOT NULL CHECK (outcome_code IN ('running','succeeded','failed'))
);

CREATE TABLE ops.durable_job (
  id uuid PRIMARY KEY,
  kind_code text NOT NULL,
  idempotency_key text NOT NULL,
  state_code text NOT NULL CHECK (state_code IN ('scheduled','leased','retry_wait','succeeded','dead_letter','cancelled')),
  payload_schema_version bigint NOT NULL CHECK (payload_schema_version >= 1),
  payload jsonb NOT NULL,
  checkpoint jsonb,
  run_after timestamptz NOT NULL,
  lease_owner text,
  lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
  lease_expires_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  max_attempts integer NOT NULL CHECK (max_attempts >= 1),
  last_error_code text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  completed_at timestamptz,
  UNIQUE (kind_code, idempotency_key),
  CHECK ((state_code = 'leased') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE INDEX durable_job_claim_idx ON ops.durable_job (run_after, created_at) WHERE state_code IN ('scheduled','retry_wait');

CREATE TABLE ops.durable_job_history (
  id uuid PRIMARY KEY,
  job_id uuid NOT NULL REFERENCES ops.durable_job(id) ON DELETE CASCADE,
  from_state_code text,
  to_state_code text NOT NULL,
  lease_generation bigint NOT NULL CHECK (lease_generation >= 0),
  outcome_code text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL
);

CREATE TABLE ops.outbox_message (
  id uuid PRIMARY KEY,
  event_id uuid NOT NULL UNIQUE,
  topic_code text NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id uuid NOT NULL,
  aggregate_revision bigint NOT NULL CHECK (aggregate_revision >= 1),
  payload_schema_version bigint NOT NULL CHECK (payload_schema_version >= 1),
  payload jsonb NOT NULL,
  state_code text NOT NULL CHECK (state_code IN ('pending','leased','published','dead_letter')),
  lease_owner text,
  lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
  lease_expires_at timestamptz,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  available_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL,
  published_at timestamptz,
  UNIQUE (aggregate_type, aggregate_id, aggregate_revision, topic_code)
);
CREATE INDEX outbox_claim_idx ON ops.outbox_message (available_at, created_at) WHERE state_code = 'pending';

CREATE TABLE ops.outbox_history (
  id uuid PRIMARY KEY,
  outbox_message_id uuid NOT NULL REFERENCES ops.outbox_message(id) ON DELETE CASCADE,
  state_code text NOT NULL,
  lease_generation bigint NOT NULL CHECK (lease_generation >= 0),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL
);

CREATE TABLE ops.event_consumer_checkpoint (
  consumer_code text PRIMARY KEY,
  last_event_id uuid,
  last_event_created_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  updated_at timestamptz NOT NULL
);

CREATE TABLE ops.alert (
  id uuid PRIMARY KEY,
  fingerprint text NOT NULL,
  severity_code text NOT NULL CHECK (severity_code IN ('info','warning','critical')),
  type_code text NOT NULL,
  state_code text NOT NULL CHECK (state_code IN ('open','acknowledged','silenced','resolved')),
  object_type_code text,
  object_id text,
  summary text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  resolved_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1)
);
CREATE UNIQUE INDEX alert_active_fingerprint_uq ON ops.alert (fingerprint) WHERE state_code IN ('open','acknowledged','silenced');

CREATE TABLE ops.notification_destination (
  id uuid PRIMARY KEY,
  kind_code text NOT NULL CHECK (kind_code IN ('inbox','smtp','webhook','serverchan3')),
  name text NOT NULL,
  secret_id uuid REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  configuration jsonb NOT NULL,
  state_code text NOT NULL CHECK (state_code IN ('active','disabled','archived')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE ops.notification_delivery (
  id uuid PRIMARY KEY,
  alert_id uuid REFERENCES ops.alert(id) ON DELETE RESTRICT,
  destination_id uuid NOT NULL REFERENCES ops.notification_destination(id) ON DELETE RESTRICT,
  attempt_ordinal integer NOT NULL CHECK (attempt_ordinal >= 1),
  state_code text NOT NULL CHECK (state_code IN ('pending','delivered','retry_wait','failed')),
  response_code text,
  next_attempt_at timestamptz,
  created_at timestamptz NOT NULL,
  delivered_at timestamptz,
  UNIQUE (alert_id, destination_id, attempt_ordinal)
);

CREATE TABLE ops.export_job (
  id uuid PRIMARY KEY,
  requested_by uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  scope_code text NOT NULL CHECK (scope_code IN ('own','all')),
  query jsonb NOT NULL,
  state_code text NOT NULL CHECK (state_code IN ('queued','running','succeeded','failed','expired')),
  object_uri text,
  content_sha256 bytea,
  expires_at timestamptz,
  created_at timestamptz NOT NULL,
  completed_at timestamptz
);

CREATE TABLE ops.backup_run (
  id uuid PRIMARY KEY,
  state_code text NOT NULL CHECK (state_code IN ('running','succeeded','failed')),
  manifest jsonb,
  manifest_sha256 bytea,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  error_code text
);

CREATE TABLE ops.restore_drill (
  id uuid PRIMARY KEY,
  backup_run_id uuid NOT NULL REFERENCES ops.backup_run(id) ON DELETE RESTRICT,
  state_code text NOT NULL CHECK (state_code IN ('running','succeeded','failed')),
  isolated boolean NOT NULL DEFAULT true,
  rpo_seconds bigint CHECK (rpo_seconds >= 0),
  rto_seconds bigint CHECK (rto_seconds >= 0),
  result jsonb,
  started_at timestamptz NOT NULL,
  completed_at timestamptz
);

CREATE TABLE ops.release_manifest (
  id uuid PRIMARY KEY,
  release_version text NOT NULL UNIQUE,
  source_revision text NOT NULL,
  manifest jsonb NOT NULL,
  manifest_sha256 bytea NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE ops.upgrade_run (
  id uuid PRIMARY KEY,
  from_release_id uuid REFERENCES ops.release_manifest(id) ON DELETE RESTRICT,
  to_release_id uuid NOT NULL REFERENCES ops.release_manifest(id) ON DELETE RESTRICT,
  state_code text NOT NULL CHECK (state_code IN ('planned','running','succeeded','failed','rolled_back')),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL
);

CREATE TABLE ops.retention_policy (
  id uuid PRIMARY KEY,
  object_kind_code text NOT NULL UNIQUE,
  retention_days integer NOT NULL CHECK (retention_days >= 1),
  configuration jsonb NOT NULL DEFAULT '{}'::jsonb,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  updated_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

REVOKE ALL ON ALL TABLES IN SCHEMA security FROM gateway_readonly;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA iam, gateway, catalog, telemetry, security, ops TO gateway_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA iam, gateway, catalog, telemetry, security, ops TO gateway_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA iam, gateway, catalog, telemetry, ops TO gateway_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA iam, gateway, catalog, telemetry, security, ops TO gateway_backup;

RESET ROLE;
