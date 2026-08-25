-- R7 exact, replacement-safe hourly/daily aggregate contributions.

SET LOCAL ROLE gateway_migrator;

CREATE TABLE telemetry.usage_aggregate_contribution (
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  bucket_start timestamptz NOT NULL,
  bucket_day date NOT NULL,
  platform_key_id uuid NOT NULL REFERENCES iam.platform_key(id) ON DELETE RESTRICT,
  group_id uuid NOT NULL REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  model_id uuid NOT NULL REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  input_tokens bigint CHECK (input_tokens >= 0),
  output_tokens bigint CHECK (output_tokens >= 0),
  estimated_amount numeric(38,12) CHECK (estimated_amount >= 0),
  completeness_code text NOT NULL CHECK (completeness_code IN ('complete','partial','unknown')),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (request_month, request_id),
  FOREIGN KEY (request_month, request_id)
    REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE
);

CREATE INDEX usage_aggregate_contribution_hour_idx
  ON telemetry.usage_aggregate_contribution
  (bucket_start, platform_key_id, group_id, credential_id, model_id);

CREATE INDEX usage_aggregate_contribution_day_idx
  ON telemetry.usage_aggregate_contribution
  (bucket_day, platform_key_id, group_id, credential_id, model_id);

RESET ROLE;
