-- Approval-bound, immutable Content Audit search sessions and normalized lookup fields.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE security.content_audit_object
  ADD COLUMN platform_key_id uuid REFERENCES iam.platform_key(id) ON DELETE RESTRICT,
  ADD COLUMN group_id uuid REFERENCES gateway.credential_group(id) ON DELETE RESTRICT,
  ADD COLUMN object_kind_code text CHECK (
    object_kind_code IN ('original_request','final_upstream_request','upstream_response')
  ),
  ADD COLUMN attempt_no smallint CHECK (attempt_no BETWEEN 1 AND 3);

UPDATE security.content_audit_object object
SET platform_key_id=request.platform_key_id,
    group_id=request.group_id
FROM telemetry.request_record request
WHERE request.request_month=object.request_month AND request.request_id=object.request_id;

UPDATE security.content_audit_object
SET object_kind_code=CASE frame_manifest->>'capture_kind'
  WHEN 'original_request' THEN 'original_request'
  WHEN 'final_request' THEN 'final_upstream_request'
  WHEN 'final_upstream_request' THEN 'final_upstream_request'
  WHEN 'response' THEN 'upstream_response'
  WHEN 'upstream_response' THEN 'upstream_response'
  ELSE NULL
END
WHERE object_kind_code IS NULL;

UPDATE security.content_audit_object object
SET attempt_no=attempt.ordinal
FROM telemetry.attempt_record attempt
WHERE attempt.id=object.attempt_id;

ALTER TABLE security.content_audit_object
  ADD CONSTRAINT content_audit_search_projection_shape_check CHECK (
    scope_code<>'full_encrypted' OR storage_state_code<>'finalized'
    OR (platform_key_id IS NOT NULL AND group_id IS NOT NULL AND object_kind_code IS NOT NULL)
  ) NOT VALID;

CREATE INDEX content_audit_request_lookup_idx
  ON security.content_audit_object (request_id,created_at DESC,id DESC)
  WHERE scope_code='full_encrypted' AND storage_state_code='finalized' AND state_code IN ('active','held');
CREATE INDEX content_audit_owner_lookup_idx
  ON security.content_audit_object (owner_user_id,created_at DESC,id DESC)
  WHERE scope_code='full_encrypted' AND storage_state_code='finalized' AND state_code IN ('active','held');
CREATE INDEX content_audit_key_lookup_idx
  ON security.content_audit_object (platform_key_id,created_at DESC,id DESC)
  WHERE scope_code='full_encrypted' AND storage_state_code='finalized' AND state_code IN ('active','held');
CREATE INDEX content_audit_group_lookup_idx
  ON security.content_audit_object (group_id,created_at DESC,id DESC)
  WHERE scope_code='full_encrypted' AND storage_state_code='finalized' AND state_code IN ('active','held');
CREATE INDEX content_audit_kind_lookup_idx
  ON security.content_audit_object (object_kind_code,created_at DESC,id DESC)
  WHERE scope_code='full_encrypted' AND storage_state_code='finalized' AND state_code IN ('active','held');

CREATE TABLE security.content_audit_search_session (
  id uuid PRIMARY KEY,
  actor_user_id uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  management_session_id uuid NOT NULL REFERENCES iam.management_session(id) ON DELETE RESTRICT,
  approval_case_id uuid NOT NULL UNIQUE REFERENCES security.approval_case(id) ON DELETE RESTRICT,
  step_up_grant_id uuid NOT NULL UNIQUE REFERENCES iam.management_step_up_grant(id) ON DELETE RESTRICT,
  reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2048),
  filters jsonb NOT NULL,
  action_snapshot_digest bytea NOT NULL CHECK (octet_length(action_snapshot_digest)=32),
  candidate_count integer NOT NULL CHECK (candidate_count BETWEEN 0 AND 1000),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  CHECK (expires_at>created_at AND expires_at<=created_at+interval '4 hours')
);

CREATE INDEX content_audit_search_session_actor_idx
  ON security.content_audit_search_session (actor_user_id,management_session_id,expires_at DESC,id DESC);

CREATE TABLE security.content_audit_search_candidate (
  search_session_id uuid NOT NULL REFERENCES security.content_audit_search_session(id) ON DELETE RESTRICT,
  content_audit_object_id uuid NOT NULL REFERENCES security.content_audit_object(id) ON DELETE RESTRICT,
  ordinal smallint NOT NULL CHECK (ordinal BETWEEN 1 AND 1000),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (search_session_id,content_audit_object_id),
  UNIQUE (search_session_id,ordinal)
);

ALTER TABLE security.content_audit_access
  ADD COLUMN search_session_id uuid REFERENCES security.content_audit_search_session(id) ON DELETE RESTRICT,
  ADD COLUMN management_session_id uuid REFERENCES iam.management_session(id) ON DELETE RESTRICT;

GRANT SELECT, INSERT ON security.content_audit_search_session,
  security.content_audit_search_candidate TO gateway_runtime;
GRANT SELECT ON security.content_audit_search_session,
  security.content_audit_search_candidate TO gateway_backup;

RESET ROLE;
