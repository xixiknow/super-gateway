-- R9 backup/restore control-plane projections.  Execution is delegated to an
-- environment adapter; these rows hold no repository credential or key bytes.

ALTER TABLE ops.backup_run DROP CONSTRAINT backup_run_state_code_check;
ALTER TABLE ops.backup_run ALTER COLUMN started_at DROP NOT NULL;
ALTER TABLE ops.backup_run
  ADD COLUMN durable_job_id uuid REFERENCES ops.durable_job(id) ON DELETE RESTRICT,
  ADD COLUMN requested_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  ADD COLUMN kind_code text NOT NULL DEFAULT 'manifest'
    CHECK (kind_code IN ('manifest','base_backup','wal_archive','object_snapshot')),
  ADD COLUMN database_system_id text,
  ADD COLUMN timeline bigint CHECK (timeline IS NULL OR timeline >= 1),
  ADD COLUMN lsn_start pg_lsn,
  ADD COLUMN lsn_end pg_lsn,
  ADD COLUMN wal_archived_at timestamptz,
  ADD COLUMN watermarks jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN backup_key_version bigint CHECK (backup_key_version IS NULL OR backup_key_version >= 1),
  ADD COLUMN repository_ref text,
  ADD COLUMN bytes_written bigint CHECK (bytes_written IS NULL OR bytes_written >= 0),
  ADD COLUMN requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

-- Legacy fixture rows do not contain enough lineage to qualify as production
-- recoverability evidence. Preserve the row, but classify the outcome honestly.
UPDATE ops.backup_run SET state_code='failed',error_code=COALESCE(error_code,'legacy_backup_unverified')
 WHERE state_code='succeeded';
UPDATE ops.backup_run SET completed_at=COALESCE(completed_at,clock_timestamp()) WHERE state_code='failed';

ALTER TABLE ops.backup_run
  ADD CONSTRAINT backup_run_state_code_check
    CHECK (state_code IN ('queued','running','succeeded','failed','cancelled')),
  ADD CONSTRAINT backup_run_terminal_shape_check CHECK (
    (state_code IN ('queued','running') AND completed_at IS NULL)
    OR (state_code IN ('succeeded','failed','cancelled') AND completed_at IS NOT NULL)
  ),
  ADD CONSTRAINT backup_run_manifest_shape_check CHECK (
    state_code <> 'succeeded'
    OR (manifest IS NOT NULL AND octet_length(manifest_sha256)=32
        AND database_system_id IS NOT NULL AND timeline IS NOT NULL
        AND lsn_start IS NOT NULL AND lsn_end IS NOT NULL
        AND wal_archived_at IS NOT NULL
        AND backup_key_version IS NOT NULL AND repository_ref IS NOT NULL)
  );

CREATE UNIQUE INDEX backup_run_durable_job_uq
  ON ops.backup_run(durable_job_id) WHERE durable_job_id IS NOT NULL;
CREATE INDEX backup_run_state_requested_idx
  ON ops.backup_run(state_code, requested_at DESC, id DESC);
CREATE INDEX backup_run_completed_idx
  ON ops.backup_run(completed_at DESC, id DESC) WHERE completed_at IS NOT NULL;

ALTER TABLE ops.restore_drill DROP CONSTRAINT restore_drill_state_code_check;
ALTER TABLE ops.restore_drill ALTER COLUMN started_at DROP NOT NULL;
ALTER TABLE ops.restore_drill
  ADD COLUMN durable_job_id uuid REFERENCES ops.durable_job(id) ON DELETE RESTRICT,
  ADD COLUMN requested_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  ADD COLUMN kind_code text NOT NULL DEFAULT 'full_restore_drill'
    CHECK (kind_code IN ('manifest_validation','full_restore_drill')),
  ADD COLUMN recovery_point timestamptz,
  ADD COLUMN isolated_environment_id text,
  ADD COLUMN db_recovered boolean,
  ADD COLUMN object_replayed boolean,
  ADD COLUMN ledger_replayed boolean,
  ADD COLUMN checks jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN manifest_sha256 bytea CHECK (manifest_sha256 IS NULL OR octet_length(manifest_sha256)=32),
  ADD COLUMN lineage jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN serving_simulated_at timestamptz,
  ADD COLUMN destroyed_at timestamptz,
  ADD COLUMN requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ADD COLUMN error_code text,
  ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

UPDATE ops.restore_drill SET state_code='failed',error_code=COALESCE(error_code,'legacy_restore_unverified')
 WHERE state_code='succeeded';
UPDATE ops.restore_drill SET completed_at=COALESCE(completed_at,clock_timestamp()) WHERE state_code='failed';

ALTER TABLE ops.restore_drill
  ADD CONSTRAINT restore_drill_state_code_check
    CHECK (state_code IN ('queued','running','succeeded','failed','cancelled')),
  ADD CONSTRAINT restore_drill_terminal_shape_check CHECK (
    (state_code IN ('queued','running') AND completed_at IS NULL)
    OR (state_code IN ('succeeded','failed','cancelled') AND completed_at IS NOT NULL)
  ),
  ADD CONSTRAINT restore_drill_isolation_check CHECK (isolated),
  ADD CONSTRAINT restore_drill_success_shape_check CHECK (
    state_code <> 'succeeded'
    OR (manifest_sha256 IS NOT NULL
        AND (kind_code='manifest_validation'
             OR (db_recovered IS TRUE AND object_replayed IS TRUE AND ledger_replayed IS TRUE
                 AND serving_simulated_at IS NOT NULL AND destroyed_at IS NOT NULL
                 AND rpo_seconds IS NOT NULL AND rto_seconds IS NOT NULL
                 AND rpo_seconds <= 300 AND rto_seconds <= 3600)))
  );

CREATE UNIQUE INDEX restore_drill_durable_job_uq
  ON ops.restore_drill(durable_job_id) WHERE durable_job_id IS NOT NULL;
CREATE INDEX restore_drill_kind_state_requested_idx
  ON ops.restore_drill(kind_code, state_code, requested_at DESC, id DESC);

GRANT SELECT, INSERT, UPDATE ON ops.backup_run, ops.restore_drill TO gateway_runtime;
