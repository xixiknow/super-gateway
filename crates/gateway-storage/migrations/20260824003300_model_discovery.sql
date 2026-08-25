CREATE TABLE catalog.model_discovery_run (
  id uuid PRIMARY KEY,
  durable_job_id uuid NOT NULL UNIQUE REFERENCES ops.durable_job(id) ON DELETE RESTRICT,
  source_credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  source_credential_revision bigint NOT NULL CHECK (source_credential_revision >= 1),
  source_token_version bigint NOT NULL CHECK (source_token_version >= 1),
  source_egress_epoch bigint NOT NULL CHECK (source_egress_epoch >= 1),
  source_code text NOT NULL CHECK (source_code = 'anthropic_models_api'),
  source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32),
  item_count integer NOT NULL CHECK (item_count >= 0 AND item_count <= 10000),
  complete boolean NOT NULL,
  sanitized_manifest jsonb NOT NULL,
  fetched_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL
);

ALTER TABLE catalog.model_definition
  ADD COLUMN last_discovery_run_id uuid REFERENCES catalog.model_discovery_run(id) ON DELETE RESTRICT,
  ADD COLUMN missing_streak integer NOT NULL DEFAULT 0 CHECK (missing_streak >= 0),
  ADD COLUMN disable_reason_code text,
  ADD COLUMN disabled_by_system boolean NOT NULL DEFAULT false,
  ADD COLUMN last_verified_at timestamptz;

CREATE TABLE catalog.model_discovery_observation (
  run_id uuid NOT NULL REFERENCES catalog.model_discovery_run(id) ON DELETE CASCADE,
  model_definition_id uuid NOT NULL REFERENCES catalog.model_definition(id) ON DELETE RESTRICT,
  upstream_model_id text NOT NULL,
  display_name text NOT NULL,
  observed_created_at timestamptz,
  content_digest bytea NOT NULL CHECK (octet_length(content_digest) = 32),
  PRIMARY KEY (run_id, upstream_model_id)
);

CREATE INDEX model_discovery_run_fetched_idx ON catalog.model_discovery_run (fetched_at DESC, id DESC);
CREATE INDEX model_definition_missing_idx ON catalog.model_definition (missing_streak, last_seen_at)
  WHERE lifecycle_code <> 'deprecated';

GRANT SELECT, INSERT, UPDATE, DELETE ON catalog.model_discovery_run TO gateway_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON catalog.model_discovery_observation TO gateway_runtime;
GRANT SELECT ON catalog.model_discovery_run, catalog.model_discovery_observation TO gateway_readonly;
GRANT SELECT ON catalog.model_discovery_run, catalog.model_discovery_observation TO gateway_backup;
