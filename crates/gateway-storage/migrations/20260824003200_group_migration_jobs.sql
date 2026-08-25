-- R5 Credential Group migration: durable orchestration and restart-safe drain metadata.

ALTER TABLE gateway.credential_group_migration
  ADD COLUMN durable_job_id uuid REFERENCES ops.durable_job(id) ON DELETE RESTRICT,
  ADD COLUMN drain_deadline timestamptz,
  ADD COLUMN checkpoint jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(checkpoint)='object'),
  ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

CREATE UNIQUE INDEX credential_group_migration_job_uq
  ON gateway.credential_group_migration (durable_job_id) WHERE durable_job_id IS NOT NULL;
CREATE UNIQUE INDEX credential_group_migration_active_uq
  ON gateway.credential_group_migration (credential_id)
  WHERE state_code IN ('planned','draining');
CREATE INDEX credential_group_migration_target_idx
  ON gateway.credential_group_migration (target_group_id,state_code,created_at);

ALTER TABLE gateway.anthropic_credential
  ADD CONSTRAINT anthropic_credential_attachment_shape_ck CHECK (
    (attachment_state_code='attached' AND attachment_target_group_id IS NULL AND attachment_deadline IS NULL)
    OR (attachment_state_code='draining' AND attachment_target_group_id IS NOT NULL AND attachment_deadline IS NOT NULL)
    OR attachment_state_code IN ('detached','attaching')
  );

GRANT SELECT, INSERT, UPDATE, DELETE ON gateway.credential_group_migration TO gateway_runtime;
GRANT SELECT ON gateway.credential_group_migration TO gateway_readonly, gateway_backup;
