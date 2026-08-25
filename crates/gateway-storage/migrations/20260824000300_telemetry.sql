-- R2 request, attempt, usage, quota and subscription-plan records.

SET LOCAL ROLE gateway_migrator;

CREATE TABLE telemetry.request_record (
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  platform_key_id uuid NOT NULL REFERENCES iam.platform_key(id) ON DELETE RESTRICT,
  group_id uuid NOT NULL REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  owner_executor_id text NOT NULL,
  owner_generation bigint NOT NULL CHECK (owner_generation >= 1),
  endpoint_code text NOT NULL CHECK (endpoint_code IN ('messages','models','model_detail')),
  client_class_code text NOT NULL CHECK (client_class_code IN ('claude_code_cli','non_claude_code_cli')),
  client_session_digest bytea,
  client_request_id_digest bytea,
  model_id uuid REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  phase_code text NOT NULL CHECK (phase_code IN ('accepted','validated','queued','reserved','submitting','response_committed','streaming','completed','failed','cancelled')),
  outcome_code text,
  http_status integer CHECK (http_status BETWEEN 100 AND 599),
  request_body_bytes bigint NOT NULL CHECK (request_body_bytes >= 0),
  response_body_bytes bigint CHECK (response_body_bytes >= 0),
  generic_adjusted_request_hash bytea,
  policy_snapshot_id uuid REFERENCES catalog.versioned_artifact(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  queued_at timestamptz,
  first_submitted_at timestamptz,
  response_committed_at timestamptz,
  completed_at timestamptz,
  PRIMARY KEY (request_month, request_id),
  CHECK (request_month = date_trunc('month', created_at)::date)
) PARTITION BY RANGE (request_month);

CREATE TABLE telemetry.request_record_202608 PARTITION OF telemetry.request_record FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE telemetry.request_record_202609 PARTITION OF telemetry.request_record FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE telemetry.request_record_202610 PARTITION OF telemetry.request_record FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE telemetry.request_record_202611 PARTITION OF telemetry.request_record FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE telemetry.request_record_default PARTITION OF telemetry.request_record DEFAULT;
CREATE INDEX request_record_key_time_idx ON telemetry.request_record (platform_key_id, created_at DESC);
CREATE INDEX request_record_group_time_idx ON telemetry.request_record (group_id, created_at DESC);
CREATE INDEX request_record_created_brin ON telemetry.request_record USING brin (created_at);

CREATE TABLE telemetry.request_stage_timing (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  stage_code text NOT NULL,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  duration_ms bigint CHECK (duration_ms >= 0),
  FOREIGN KEY (request_month, request_id) REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE,
  UNIQUE (request_month, request_id, stage_code)
);

CREATE TABLE telemetry.request_decision_event (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  decision_code text NOT NULL,
  reason_code text,
  artifact_id uuid REFERENCES catalog.versioned_artifact(id) ON DELETE RESTRICT,
  redacted_detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL,
  FOREIGN KEY (request_month, request_id) REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE
);

CREATE TABLE telemetry.request_resource_event (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  resource_kind_code text NOT NULL,
  resource_id_digest bytea,
  portability_code text NOT NULL CHECK (portability_code IN ('portable','account_bound','unknown')),
  observed_at timestamptz NOT NULL,
  FOREIGN KEY (request_month, request_id) REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE
);

CREATE TABLE telemetry.endpoint_access_event (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid,
  platform_key_id uuid REFERENCES iam.platform_key(id) ON DELETE RESTRICT,
  endpoint_code text NOT NULL,
  outcome_code text NOT NULL,
  source_ip_digest bytea,
  occurred_at timestamptz NOT NULL
);
CREATE INDEX endpoint_access_key_time_idx ON telemetry.endpoint_access_event (platform_key_id, occurred_at DESC);

CREATE TABLE telemetry.attempt_submission_intent (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 3),
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  token_version bigint NOT NULL CHECK (token_version >= 1),
  profile_epoch bigint NOT NULL CHECK (profile_epoch >= 1),
  egress_epoch bigint NOT NULL CHECK (egress_epoch >= 1),
  transport_bundle_id uuid NOT NULL REFERENCES catalog.transport_bundle(id) ON DELETE RESTRICT,
  generic_adjusted_request_hash bytea NOT NULL,
  state_code text NOT NULL CHECK (state_code IN ('created','promoted','cancelled')),
  created_at timestamptz NOT NULL,
  FOREIGN KEY (request_month, request_id) REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE,
  UNIQUE (request_month, request_id, ordinal)
);

CREATE TABLE telemetry.connection_attempt_record (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 3),
  submission_intent_id uuid NOT NULL UNIQUE REFERENCES telemetry.attempt_submission_intent(id) ON DELETE RESTRICT,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  profile_epoch bigint NOT NULL CHECK (profile_epoch >= 1),
  egress_epoch bigint NOT NULL CHECK (egress_epoch >= 1),
  transport_bundle_id uuid NOT NULL REFERENCES catalog.transport_bundle(id) ON DELETE RESTRICT,
  state_code text NOT NULL CHECK (state_code IN ('connecting','tls_handshaking','connected','failed','cancelled')),
  pool_reused boolean NOT NULL DEFAULT false,
  request_bytes_written bigint NOT NULL DEFAULT 0 CHECK (request_bytes_written >= 0),
  failure_domain_code text,
  retry_safe boolean NOT NULL DEFAULT true,
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  FOREIGN KEY (request_month, request_id) REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE,
  UNIQUE (request_month, request_id, ordinal)
);

CREATE TABLE telemetry.attempt_record (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 3),
  submission_intent_id uuid NOT NULL UNIQUE REFERENCES telemetry.attempt_submission_intent(id) ON DELETE RESTRICT,
  connection_attempt_id uuid UNIQUE REFERENCES telemetry.connection_attempt_record(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  token_version bigint NOT NULL CHECK (token_version >= 1),
  profile_epoch bigint NOT NULL CHECK (profile_epoch >= 1),
  egress_epoch bigint NOT NULL CHECK (egress_epoch >= 1),
  transport_bundle_id uuid NOT NULL REFERENCES catalog.transport_bundle(id) ON DELETE RESTRICT,
  reason_code text NOT NULL CHECK (reason_code IN ('initial','retry','credential_switch')),
  state_code text NOT NULL CHECK (state_code IN ('submitting','submitted','response_committed','completed','failed','cancelled')),
  upstream_request_id text,
  submitted_at timestamptz,
  response_committed_at timestamptz,
  completed_at timestamptz,
  http_status integer CHECK (http_status BETWEEN 100 AND 599),
  retry_decision_code text,
  is_final boolean NOT NULL DEFAULT false,
  FOREIGN KEY (request_month, request_id) REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE,
  UNIQUE (request_month, request_id, ordinal)
);
CREATE UNIQUE INDEX attempt_one_final_uq ON telemetry.attempt_record (request_month, request_id) WHERE is_final;

CREATE TABLE telemetry.transport_event (
  id uuid PRIMARY KEY,
  attempt_id uuid NOT NULL REFERENCES telemetry.attempt_record(id) ON DELETE CASCADE,
  event_code text NOT NULL,
  redacted_detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL
);

CREATE TABLE telemetry.response_delivery_record (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  attempt_id uuid REFERENCES telemetry.attempt_record(id) ON DELETE RESTRICT,
  streaming boolean NOT NULL,
  response_committed boolean NOT NULL,
  first_byte_at timestamptz,
  completed_at timestamptz,
  bytes_delivered bigint NOT NULL DEFAULT 0 CHECK (bytes_delivered >= 0),
  client_disconnect_code text,
  FOREIGN KEY (request_month, request_id) REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE,
  UNIQUE (request_month, request_id)
);

CREATE TABLE telemetry.usage_observation (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  attempt_id uuid REFERENCES telemetry.attempt_record(id) ON DELETE RESTRICT,
  source_code text NOT NULL CHECK (source_code IN ('official','local_estimate','console_count','cancel_estimate')),
  completeness_code text NOT NULL CHECK (completeness_code IN ('complete','partial','unknown')),
  model_id uuid REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  input_tokens bigint CHECK (input_tokens >= 0),
  output_tokens bigint CHECK (output_tokens >= 0),
  cache_creation_input_tokens bigint CHECK (cache_creation_input_tokens >= 0),
  cache_read_input_tokens bigint CHECK (cache_read_input_tokens >= 0),
  algorithm_version text,
  observed_at timestamptz NOT NULL,
  is_final_basis boolean NOT NULL DEFAULT false,
  FOREIGN KEY (request_month, request_id) REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX usage_one_final_basis_uq ON telemetry.usage_observation (request_month, request_id) WHERE is_final_basis;

CREATE TABLE telemetry.cost_estimate (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  usage_observation_id uuid NOT NULL REFERENCES telemetry.usage_observation(id) ON DELETE RESTRICT,
  price_entry_id uuid REFERENCES catalog.price_entry(id) ON DELETE RESTRICT,
  price_snapshot jsonb NOT NULL,
  usage_completeness_code text NOT NULL CHECK (usage_completeness_code IN ('complete','partial','unknown')),
  algorithm_version text NOT NULL,
  amount numeric(38,12) CHECK (amount >= 0),
  currency_code text NOT NULL DEFAULT 'USD',
  is_current boolean NOT NULL DEFAULT true,
  calculated_at timestamptz NOT NULL,
  FOREIGN KEY (request_month, request_id) REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX cost_one_current_uq ON telemetry.cost_estimate (request_month, request_id) WHERE is_current;

CREATE TABLE telemetry.token_estimate (
  id uuid PRIMARY KEY,
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  source_code text NOT NULL CHECK (source_code IN ('local_estimate','console_api')),
  input_tokens bigint NOT NULL CHECK (input_tokens >= 0),
  algorithm_version text NOT NULL,
  console_request_id text,
  calculated_at timestamptz NOT NULL,
  FOREIGN KEY (request_month, request_id) REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE
);

CREATE TABLE telemetry.usage_hourly (
  bucket_start timestamptz NOT NULL,
  platform_key_id uuid NOT NULL REFERENCES iam.platform_key(id) ON DELETE RESTRICT,
  group_id uuid NOT NULL REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  credential_id uuid REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  model_id uuid REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  request_count bigint NOT NULL DEFAULT 0 CHECK (request_count >= 0),
  input_tokens bigint CHECK (input_tokens >= 0),
  output_tokens bigint CHECK (output_tokens >= 0),
  estimated_amount numeric(38,12) CHECK (estimated_amount >= 0),
  completeness_code text NOT NULL CHECK (completeness_code IN ('complete','partial','unknown')),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (bucket_start, platform_key_id, group_id, credential_id, model_id)
);

CREATE TABLE telemetry.usage_daily (
  bucket_day date NOT NULL,
  platform_key_id uuid NOT NULL REFERENCES iam.platform_key(id) ON DELETE RESTRICT,
  group_id uuid NOT NULL REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  credential_id uuid REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  model_id uuid REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  request_count bigint NOT NULL DEFAULT 0 CHECK (request_count >= 0),
  input_tokens bigint CHECK (input_tokens >= 0),
  output_tokens bigint CHECK (output_tokens >= 0),
  estimated_amount numeric(38,12) CHECK (estimated_amount >= 0),
  completeness_code text NOT NULL CHECK (completeness_code IN ('complete','partial','unknown')),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (bucket_day, platform_key_id, group_id, credential_id, model_id)
);

CREATE TABLE telemetry.credential_quota_observation (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  window_kind_code text NOT NULL CHECK (window_kind_code IN ('five_hour','seven_day')),
  model_id uuid REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  utilization numeric(20,9) CHECK (utilization BETWEEN 0 AND 1),
  resets_at timestamptz,
  source_code text NOT NULL CHECK (source_code IN ('header','oauth_profile','claude_cli_bootstrap')),
  observed_at timestamptz NOT NULL,
  raw_redacted jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE telemetry.credential_quota_current (
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE CASCADE,
  window_kind_code text NOT NULL CHECK (window_kind_code IN ('five_hour','seven_day')),
  model_id uuid REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  observation_id uuid NOT NULL UNIQUE REFERENCES telemetry.credential_quota_observation(id) ON DELETE RESTRICT,
  utilization numeric(20,9) CHECK (utilization BETWEEN 0 AND 1),
  resets_at timestamptz,
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (credential_id, window_kind_code, model_id)
);

CREATE TABLE telemetry.credential_cooldown_event (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  reason_code text NOT NULL CHECK (reason_code IN ('rate_limit','quota_pressure','auth_failure','transport_failure','manual')),
  started_at timestamptz NOT NULL,
  cooldown_until timestamptz NOT NULL,
  source_attempt_id uuid REFERENCES telemetry.attempt_record(id) ON DELETE RESTRICT,
  cleared_at timestamptz,
  CHECK (cooldown_until > started_at)
);

CREATE TABLE telemetry.subscription_plan_observation (
  id uuid PRIMARY KEY,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  source_code text NOT NULL CHECK (source_code IN ('oauth_profile','claude_cli_bootstrap','not_applicable')),
  raw_plan_code text,
  normalized_plan_code text NOT NULL,
  mapping_artifact_id uuid REFERENCES catalog.versioned_artifact(id) ON DELETE RESTRICT,
  freshness_code text NOT NULL CHECK (freshness_code IN ('fresh','stale','unknown','not_applicable')),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz,
  raw_redacted jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE telemetry.subscription_plan_current (
  credential_id uuid PRIMARY KEY REFERENCES gateway.anthropic_credential(id) ON DELETE CASCADE,
  observation_id uuid NOT NULL UNIQUE REFERENCES telemetry.subscription_plan_observation(id) ON DELETE RESTRICT,
  normalized_plan_code text NOT NULL,
  freshness_code text NOT NULL CHECK (freshness_code IN ('fresh','stale','unknown','not_applicable')),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA telemetry TO gateway_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA telemetry TO gateway_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA telemetry TO gateway_backup;

RESET ROLE;
