-- R9 governance and runtime fencing closure. Forward-only and compatible with
-- rows created by the R8/R9 binaries.

ALTER TABLE gateway.credential_group
  ADD COLUMN owner_lease_expires_at timestamptz;

-- A mixed-version rollout must not let a new binary steal a Group from an
-- older process that still has a durable owner but does not heartbeat this
-- column. The grace period gives the deployment controller time to drain the
-- old process; after that the new generation can take over normally.
UPDATE gateway.credential_group
SET owner_lease_expires_at=clock_timestamp()+interval '5 minutes'
WHERE owner_executor_id IS NOT NULL AND owner_lease_expires_at IS NULL;

CREATE INDEX credential_group_owner_lease_idx
  ON gateway.credential_group (owner_lease_expires_at)
  WHERE owner_executor_id IS NOT NULL;

ALTER TABLE gateway.group_config
  ADD COLUMN content_audit_policy_code text NOT NULL DEFAULT 'allow'
    CHECK (content_audit_policy_code IN ('allow','require','forbid')),
  ADD COLUMN content_audit_retention_days integer NOT NULL DEFAULT 7
    CHECK (content_audit_retention_days BETWEEN 1 AND 365);

ALTER TABLE iam.platform_key_config
  ADD COLUMN content_audit_approval_case_id uuid
    REFERENCES security.approval_case(id) ON DELETE RESTRICT,
  ADD COLUMN content_audit_expires_at timestamptz;

ALTER TABLE security.approval_case
  DROP CONSTRAINT approval_case_state_code_check,
  ADD CONSTRAINT approval_case_state_code_check
    CHECK (state_code IN ('pending','approved','rejected','cancelled','expired','consumed'));

ALTER TABLE ops.notification_inbox
  ADD COLUMN source_event_id uuid;

CREATE UNIQUE INDEX notification_inbox_source_event_uq
  ON ops.notification_inbox (user_id,source_event_id)
  WHERE source_event_id IS NOT NULL;

ALTER TABLE security.content_audit_object
  ADD COLUMN legal_hold_count integer NOT NULL DEFAULT 0 CHECK (legal_hold_count >= 0),
  DROP CONSTRAINT content_audit_object_check,
  ADD CONSTRAINT content_audit_object_full_material_check CHECK (
    scope_code <> 'full_encrypted' OR state_code IN ('deletion_pending','deleted')
    OR (object_uri IS NOT NULL AND encrypted_dek IS NOT NULL AND key_version IS NOT NULL)
  ),
  DROP CONSTRAINT content_audit_storage_shape_check,
  ADD CONSTRAINT content_audit_storage_shape_check CHECK (
    scope_code <> 'full_encrypted' OR storage_state_code='destroyed'
    OR (cipher_suite_code='aes_256_gcm_framed' AND frame_manifest <> '{}'::jsonb)
  );

ALTER TABLE security.legal_hold
  ADD COLUMN approval_case_id uuid REFERENCES security.approval_case(id) ON DELETE RESTRICT,
  ADD COLUMN scope_digest bytea CHECK (scope_digest IS NULL OR octet_length(scope_digest)=32),
  ADD COLUMN review_due_at timestamptz,
  ADD COLUMN last_reviewed_at timestamptz;

ALTER TABLE security.legal_hold_object
  ADD COLUMN released_at timestamptz;

COMMENT ON COLUMN gateway.credential_group.owner_lease_expires_at IS
  'Short durable owner lease; generation remains the fencing token.';
COMMENT ON COLUMN gateway.group_config.content_audit_policy_code IS
  'Group policy applied to the request-frozen Key preference: allow, require, or forbid.';
COMMENT ON COLUMN iam.platform_key_config.content_audit_expires_at IS
  'Full encrypted Key preference is effective only while its two-person approval grant is valid.';
