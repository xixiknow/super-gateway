-- R4 owner fencing, scheduler configuration, retry-stage and resource-ledger contracts.

SET LOCAL ROLE gateway_migrator;

UPDATE gateway.credential_group SET status_code = 'disabled' WHERE status_code = 'draining';
ALTER TABLE gateway.credential_group DROP CONSTRAINT credential_group_status_code_check;
ALTER TABLE gateway.credential_group
  ADD CONSTRAINT credential_group_status_code_check
  CHECK (status_code IN ('active','disabled','archived'));

ALTER TABLE gateway.group_config
  ALTER COLUMN default_rpm DROP NOT NULL,
  ALTER COLUMN queue_capacity DROP NOT NULL,
  ADD COLUMN default_rpm_burst integer CHECK (default_rpm_burst >= 1),
  ADD COLUMN max_concurrency integer CHECK (max_concurrency >= 1),
  ADD COLUMN pre_upstream_wait_ms bigint NOT NULL DEFAULT 30000 CHECK (pre_upstream_wait_ms >= 1),
  ADD COLUMN preferred_capacity_wait_ms bigint NOT NULL DEFAULT 2000 CHECK (preferred_capacity_wait_ms >= 0),
  ADD COLUMN affinity_ttl_ms bigint NOT NULL DEFAULT 86400000 CHECK (affinity_ttl_ms >= 1),
  ADD COLUMN affinity_migration_successes integer NOT NULL DEFAULT 3 CHECK (affinity_migration_successes >= 1),
  ADD COLUMN quota_guard_basis_points integer NOT NULL DEFAULT 9500 CHECK (quota_guard_basis_points BETWEEN 1 AND 10000);

COMMENT ON COLUMN gateway.group_config.default_rpm IS 'NULL means no Group-level RPM limit';
COMMENT ON COLUMN gateway.group_config.max_concurrency IS 'NULL means no product cap; runtime still clamps to eligible Credential capacity';
COMMENT ON COLUMN gateway.group_config.queue_capacity IS 'NULL means exactly 2x frozen effective Group concurrency';

ALTER TABLE gateway.credential_scheduling_config
  ADD COLUMN rpm_burst integer NOT NULL DEFAULT 10 CHECK (rpm_burst >= 1),
  ADD COLUMN priority_layer integer NOT NULL DEFAULT 100 CHECK (priority_layer >= 0),
  ADD COLUMN session_capacity_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN max_active_sessions integer CHECK (max_active_sessions >= 1),
  ADD COLUMN session_idle_ttl_ms bigint NOT NULL DEFAULT 1800000 CHECK (session_idle_ttl_ms >= 1),
  ADD COLUMN new_session_wait_ms bigint NOT NULL DEFAULT 5000 CHECK (new_session_wait_ms >= 0),
  ADD CONSTRAINT credential_session_capacity_shape_ck
  CHECK ((session_capacity_enabled AND max_active_sessions IS NOT NULL) OR
         (NOT session_capacity_enabled AND max_active_sessions IS NULL));

ALTER TABLE telemetry.request_stage_timing
  DROP CONSTRAINT request_stage_timing_request_month_request_id_stage_code_key,
  ADD COLUMN stage_ordinal smallint NOT NULL DEFAULT 1 CHECK (stage_ordinal >= 1),
  ADD COLUMN absolute_deadline_at timestamptz,
  ADD COLUMN outcome_code text,
  ADD CONSTRAINT request_stage_timing_request_stage_ordinal_uq
    UNIQUE (request_month, request_id, stage_code, stage_ordinal);

ALTER TABLE telemetry.request_resource_event
  ADD COLUMN action_code text NOT NULL DEFAULT 'acquire'
    CHECK (action_code IN ('acquire','release','forced_release')),
  ADD COLUMN owner_generation bigint NOT NULL DEFAULT 1 CHECK (owner_generation >= 1),
  ADD COLUMN resource_token_id text,
  ADD COLUMN release_reason_code text,
  ADD COLUMN event_sequence bigint CHECK (event_sequence >= 1);

CREATE UNIQUE INDEX request_resource_event_token_action_uq
  ON telemetry.request_resource_event (request_month, request_id, resource_kind_code, resource_token_id, action_code)
  WHERE resource_token_id IS NOT NULL;
CREATE UNIQUE INDEX request_resource_event_request_sequence_uq
  ON telemetry.request_resource_event (request_month, request_id, event_sequence)
  WHERE event_sequence IS NOT NULL;

ALTER TABLE telemetry.credential_quota_current
  DROP CONSTRAINT credential_quota_current_pkey,
  ALTER COLUMN model_id DROP NOT NULL;
CREATE UNIQUE INDEX credential_quota_current_global_uq
  ON telemetry.credential_quota_current (credential_id, window_kind_code)
  WHERE model_id IS NULL;
CREATE UNIQUE INDEX credential_quota_current_model_uq
  ON telemetry.credential_quota_current (credential_id, window_kind_code, model_id)
  WHERE model_id IS NOT NULL;

CREATE INDEX credential_group_owner_idx
  ON gateway.credential_group (owner_executor_id, owner_generation)
  WHERE status_code = 'active';

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA gateway, telemetry TO gateway_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA gateway, telemetry TO gateway_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA gateway, telemetry TO gateway_backup;

RESET ROLE;
