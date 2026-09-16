-- T6.1b: retire the encrypted Content Audit subsystem.
--
-- Plaintext body capture (telemetry.request_body governed by the
-- body_capture.* system settings) replaces encrypted objects, approval-bound
-- search sessions, one-shot exports, legal holds and purge jobs. Keys no
-- longer carry an audit mode and Group configs no longer carry a content
-- audit policy. Destructive: all encrypted audit metadata rows are dropped.
SET LOCAL ROLE gateway_migrator;

-- 1) Background jobs that can no longer be processed.
UPDATE ops.durable_job
SET state_code='cancelled', lease_owner=NULL, lease_expires_at=NULL,
    completed_at=clock_timestamp(), updated_at=clock_timestamp()
WHERE kind_code IN ('content_audit_purge','content_audit_export_generate')
  AND state_code IN ('scheduled','leased','retry_wait');

-- 2) Platform Key configs: drop the encrypted-audit grant surface.
ALTER TABLE iam.platform_key_config
  DROP CONSTRAINT IF EXISTS platform_key_content_audit_grant_shape_ck,
  DROP COLUMN content_audit_approval_case_id,
  DROP COLUMN content_audit_expires_at,
  DROP COLUMN audit_mode_code;

-- 3) Group configs: the per-group audit policy is gone; body capture is a
--    system-wide setting. Dropping columns keeps the content-immutability
--    trigger semantics intact (it compares whole-row JSON).
ALTER TABLE gateway.group_config
  DROP COLUMN content_audit_policy_code,
  DROP COLUMN content_audit_retention_days;

-- 4) Approval cases: only the two remaining operational kinds are accepted
--    for new rows; historical rows stay readable.
ALTER TABLE security.approval_case
  DROP CONSTRAINT IF EXISTS approval_key_full_snapshot_required_ck;
ALTER TABLE security.approval_case
  ADD CONSTRAINT approval_case_operation_code_check
    CHECK (operation_code IN ('device_rebuild','key_provider_change')) NOT VALID;

-- 5) Exports: only usage exports remain. Historical content-audit export rows
--    are tolerated (NOT VALID) but can no longer be created.
ALTER TABLE ops.export_job
  DROP CONSTRAINT IF EXISTS export_job_dataset_format_check,
  DROP CONSTRAINT IF EXISTS export_job_content_length_check,
  DROP CONSTRAINT IF EXISTS export_job_format_code_check,
  DROP CONSTRAINT IF EXISTS export_job_dataset_code_check;
ALTER TABLE ops.export_job
  ADD CONSTRAINT export_job_dataset_code_check
    CHECK (dataset_code = 'usage_requests_v1') NOT VALID,
  ADD CONSTRAINT export_job_format_code_check
    CHECK (format_code IN ('jsonl','csv')) NOT VALID,
  ADD CONSTRAINT export_job_content_length_check
    CHECK (content_length IS NULL OR content_length BETWEEN 0 AND 33554432) NOT VALID;

-- 6) Drop the encrypted audit tables in FK order: export bindings and search
--    candidates reference sessions and objects; access rows reference sessions
--    and objects; sessions and holds go before the objects they point at.
DROP TABLE security.content_audit_export_binding;
DROP TABLE security.content_audit_search_candidate;
DROP TABLE security.content_audit_access;
DROP TABLE security.content_audit_search_session;
DROP TABLE security.legal_hold_object;
DROP TABLE security.legal_hold;
DROP TABLE security.content_audit_object;

RESET ROLE;
