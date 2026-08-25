-- R8 P0 closure: bind full-content Platform Key grants to an approval snapshot
-- and enforce the bounded grant lifetime at the durable boundary.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE security.approval_case
  ADD CONSTRAINT approval_key_full_snapshot_required_ck
    CHECK (operation_code <> 'key_full_audit' OR action_snapshot_digest IS NOT NULL);

ALTER TABLE iam.platform_key_config
  ADD CONSTRAINT platform_key_content_audit_grant_shape_ck CHECK (
    (audit_mode_code = 'metadata'
      AND content_audit_approval_case_id IS NULL
      AND content_audit_expires_at IS NULL)
    OR
    (audit_mode_code = 'full_encrypted'
      AND content_audit_approval_case_id IS NOT NULL
      AND content_audit_expires_at IS NOT NULL
      AND content_audit_expires_at > created_at
      AND content_audit_expires_at <= created_at + interval '30 days')
  );

COMMENT ON CONSTRAINT approval_key_full_snapshot_required_ck ON security.approval_case IS
  'Full-content grants are executable only when bound to a canonical SHA-256 action snapshot.';

COMMENT ON CONSTRAINT platform_key_content_audit_grant_shape_ck ON iam.platform_key_config IS
  'Metadata mode has no content grant; full encrypted mode requires an approval and expires within 30 days.';

RESET ROLE;
