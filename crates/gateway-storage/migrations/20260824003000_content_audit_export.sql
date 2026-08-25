-- Approval-bound, one-shot exports of one encrypted Content Audit record.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE ops.export_job
  DROP CONSTRAINT export_job_dataset_code_check,
  ADD CONSTRAINT export_job_dataset_code_check
    CHECK (dataset_code IN ('usage_requests_v1','content_audit_record_v1')),
  DROP CONSTRAINT export_job_format_code_check,
  ADD CONSTRAINT export_job_format_code_check
    CHECK (format_code IN ('jsonl','csv','raw')),
  DROP CONSTRAINT export_job_content_length_check,
  ADD CONSTRAINT export_job_content_length_check CHECK (
    content_length IS NULL OR (
      dataset_code='usage_requests_v1' AND content_length BETWEEN 0 AND 33554432
    ) OR (
      dataset_code='content_audit_record_v1' AND content_length BETWEEN 0 AND 67108864
    )
  ),
  ADD CONSTRAINT export_job_dataset_format_check CHECK (
    (dataset_code='usage_requests_v1' AND format_code IN ('jsonl','csv'))
    OR (dataset_code='content_audit_record_v1' AND format_code='raw')
  );

CREATE TABLE security.content_audit_export_binding (
  export_job_id uuid PRIMARY KEY REFERENCES ops.export_job(id) ON DELETE RESTRICT,
  content_audit_object_id uuid NOT NULL REFERENCES security.content_audit_object(id) ON DELETE RESTRICT,
  search_session_id uuid NOT NULL REFERENCES security.content_audit_search_session(id) ON DELETE RESTRICT,
  execution_approval_case_id uuid NOT NULL UNIQUE REFERENCES security.approval_case(id) ON DELETE RESTRICT,
  actor_user_id uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  management_session_id uuid NOT NULL REFERENCES iam.management_session(id) ON DELETE RESTRICT,
  execution_step_up_grant_id uuid NOT NULL UNIQUE REFERENCES iam.management_step_up_grant(id) ON DELETE RESTRICT,
  action_snapshot_digest bytea NOT NULL CHECK (octet_length(action_snapshot_digest)=32),
  reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2048),
  created_at timestamptz NOT NULL,
  UNIQUE (export_job_id,content_audit_object_id,search_session_id)
);

CREATE INDEX content_audit_export_object_idx
  ON security.content_audit_export_binding (content_audit_object_id,created_at DESC);

GRANT SELECT, INSERT ON security.content_audit_export_binding TO gateway_runtime;
GRANT SELECT ON security.content_audit_export_binding TO gateway_backup;

RESET ROLE;
