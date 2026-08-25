-- R9 upgrade preflight: immutable candidate identity, generation-fenced job projection,
-- and repeatable per-run gate evidence.

ALTER TABLE ops.release_manifest
  ADD CONSTRAINT release_manifest_hash_shape_ck
    CHECK (octet_length(manifest_sha256) = 32),
  ADD CONSTRAINT release_manifest_object_ck
    CHECK (jsonb_typeof(manifest) = 'object');

CREATE UNIQUE INDEX release_manifest_digest_uq
  ON ops.release_manifest (manifest_sha256);

ALTER TABLE ops.upgrade_run
  ADD COLUMN durable_job_id uuid REFERENCES ops.durable_job(id) ON DELETE RESTRICT,
  ADD COLUMN requested_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  ADD COLUMN preflight_state_code text NOT NULL DEFAULT 'queued'
    CHECK (preflight_state_code IN ('queued','running','passed','failed','blocked_external','cancelled')),
  ADD COLUMN preflight_result jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(preflight_result) = 'object'),
  ADD COLUMN preflight_started_at timestamptz,
  ADD COLUMN preflight_completed_at timestamptz,
  ADD COLUMN preflight_valid_until timestamptz,
  ADD COLUMN error_code text,
  ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  ADD CONSTRAINT upgrade_run_distinct_release_ck
    CHECK (from_release_id IS NULL OR from_release_id <> to_release_id),
  ADD CONSTRAINT upgrade_run_preflight_terminal_ck CHECK (
    (preflight_state_code IN ('passed','failed','blocked_external','cancelled'))
      = (preflight_completed_at IS NOT NULL)
  );

CREATE UNIQUE INDEX upgrade_run_job_uq
  ON ops.upgrade_run (durable_job_id) WHERE durable_job_id IS NOT NULL;
CREATE INDEX upgrade_run_requested_by_fk_idx ON ops.upgrade_run (requested_by);
CREATE INDEX upgrade_run_created_idx ON ops.upgrade_run (created_at DESC,id DESC);
CREATE INDEX upgrade_run_preflight_active_idx ON ops.upgrade_run (preflight_state_code,created_at)
  WHERE preflight_state_code IN ('queued','running');

ALTER TABLE ops.release_gate_run
  ADD COLUMN upgrade_run_id uuid REFERENCES ops.upgrade_run(id) ON DELETE RESTRICT;

ALTER TABLE ops.release_gate_run
  DROP CONSTRAINT release_gate_run_release_version_gate_code_key;

CREATE UNIQUE INDEX release_gate_run_run_gate_uq
  ON ops.release_gate_run (upgrade_run_id,gate_code) WHERE upgrade_run_id IS NOT NULL;
CREATE INDEX release_gate_run_upgrade_run_fk_idx ON ops.release_gate_run (upgrade_run_id);
CREATE INDEX release_gate_run_created_idx ON ops.release_gate_run (created_at DESC,id DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON ops.release_manifest, ops.upgrade_run, ops.release_gate_run
  TO gateway_runtime;
GRANT SELECT ON ops.release_manifest, ops.upgrade_run, ops.release_gate_run
  TO gateway_readonly, gateway_backup;
