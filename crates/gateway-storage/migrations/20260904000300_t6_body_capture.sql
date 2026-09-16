-- T6.1: request/response body capture and process-wide capture settings.

SET LOCAL ROLE gateway_migrator;

CREATE TABLE telemetry.request_body (
  request_month date NOT NULL,
  request_id uuid NOT NULL,
  original_request jsonb,
  policy_request jsonb,
  final_upstream_request jsonb,
  upstream_response text,
  upstream_response_final jsonb,
  captured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  body_digest_mismatch boolean NOT NULL DEFAULT false,
  PRIMARY KEY (request_month, request_id),
  FOREIGN KEY (request_month, request_id)
    REFERENCES telemetry.request_record(request_month, request_id) ON DELETE CASCADE
);

CREATE TABLE ops.system_setting (
  key text PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 128),
  value jsonb NOT NULL,
  updated_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO ops.system_setting (key, value)
VALUES
  ('body_capture.enabled', 'false'::jsonb),
  ('body_capture.retention_days', '7'::jsonb),
  ('body_capture.max_bytes', '4194304'::jsonb)
ON CONFLICT (key) DO NOTHING;

CREATE INDEX request_body_captured_at_idx ON telemetry.request_body (captured_at);

GRANT SELECT, INSERT, UPDATE ON telemetry.request_body TO gateway_runtime;
GRANT SELECT ON telemetry.request_body, ops.system_setting TO gateway_readonly;
GRANT SELECT ON telemetry.request_body, ops.system_setting TO gateway_backup;
GRANT SELECT, INSERT, UPDATE ON ops.system_setting TO gateway_runtime;

RESET ROLE;
