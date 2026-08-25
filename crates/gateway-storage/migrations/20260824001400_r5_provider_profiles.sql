-- Versioned, evidence-gated provider endpoint contracts for Credential maintenance.

SET LOCAL ROLE gateway_migrator;

CREATE TABLE gateway.credential_provider_profile (
  id uuid PRIMARY KEY,
  profile_code text NOT NULL,
  profile_version bigint NOT NULL CHECK (profile_version >= 1),
  lifecycle_code text NOT NULL CHECK (lifecycle_code IN ('draft','canary','active','retired')),
  auth_kind_codes jsonb NOT NULL CHECK (
    jsonb_typeof(auth_kind_codes) = 'array'
    AND jsonb_array_length(auth_kind_codes) >= 1
    AND auth_kind_codes <@ '["oauth_subscription","setup_token_subscription"]'::jsonb
    AND NOT jsonb_path_exists(auth_kind_codes, '$[*] ? (@.type() != "string" || @ == "")')
  ),
  token_endpoint text NOT NULL CHECK (
    token_endpoint ~ '^https://[^/@[:space:]]+(/[^#[:space:]]*)?$'
  ),
  client_id text NOT NULL CHECK (length(btrim(client_id)) BETWEEN 1 AND 512),
  scopes jsonb NOT NULL CHECK (
    jsonb_typeof(scopes) = 'array'
    AND NOT jsonb_path_exists(scopes, '$[*] ? (@.type() != "string" || @ == "")')
  ),
  max_response_bytes integer NOT NULL DEFAULT 65536 CHECK (max_response_bytes BETWEEN 1024 AND 1048576),
  response_schema_code text NOT NULL,
  evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
  activated_at timestamptz,
  retired_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (profile_code, profile_version),
  CHECK ((lifecycle_code IN ('canary','active','retired')) = (activated_at IS NOT NULL)),
  CHECK ((lifecycle_code = 'retired') = (retired_at IS NOT NULL))
);

CREATE UNIQUE INDEX credential_provider_profile_active_uq
  ON gateway.credential_provider_profile (profile_code)
  WHERE lifecycle_code = 'active';

ALTER TABLE gateway.anthropic_credential
  ADD COLUMN provider_profile_id uuid REFERENCES gateway.credential_provider_profile(id) ON DELETE RESTRICT;

ALTER TABLE gateway.credential_enrollment
  ADD COLUMN provider_profile_id uuid REFERENCES gateway.credential_provider_profile(id) ON DELETE RESTRICT;

ALTER TABLE gateway.maintenance_operation
  ADD COLUMN provider_profile_id uuid REFERENCES gateway.credential_provider_profile(id) ON DELETE RESTRICT;

CREATE TABLE gateway.credential_auth_secret_stage (
  operation_id uuid NOT NULL REFERENCES gateway.maintenance_operation(id) ON DELETE RESTRICT,
  operation_generation bigint NOT NULL CHECK (operation_generation >= 1),
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  candidate_token_version bigint NOT NULL CHECK (candidate_token_version >= 2),
  access_secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  refresh_secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (operation_id, operation_generation)
);

CREATE UNIQUE INDEX credential_auth_version_one_active_uq
  ON gateway.credential_auth_version (credential_id)
  WHERE material_state_code = 'active';

CREATE UNIQUE INDEX credential_auth_version_operation_uq
  ON gateway.credential_auth_version (operation_id)
  WHERE operation_id IS NOT NULL;

CREATE INDEX anthropic_credential_provider_profile_idx
  ON gateway.anthropic_credential (provider_profile_id)
  WHERE provider_profile_id IS NOT NULL;

CREATE INDEX credential_auth_secret_stage_credential_idx
  ON gateway.credential_auth_secret_stage (credential_id, created_at);

RESET ROLE;
