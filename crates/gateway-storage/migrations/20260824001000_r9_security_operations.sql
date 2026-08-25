-- R9 security/operations hardening. Forward-only and compatible with the R8 binary.

CREATE OR REPLACE FUNCTION security.reject_immutable_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'append-only security relation' USING ERRCODE='55000';
END $$;

CREATE TRIGGER audit_event_append_only
  BEFORE UPDATE OR DELETE ON security.audit_event
  FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_mutation();
CREATE TRIGGER audit_daily_seal_append_only
  BEFORE UPDATE OR DELETE ON security.audit_daily_seal
  FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_mutation();
CREATE TRIGGER deletion_ledger_append_only
  BEFORE UPDATE OR DELETE ON security.deletion_ledger
  FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON security.audit_event, security.audit_daily_seal,
  security.deletion_ledger FROM gateway_runtime;
GRANT SELECT, INSERT ON security.audit_event, security.audit_daily_seal,
  security.deletion_ledger TO gateway_runtime;

ALTER TABLE security.content_audit_object
  ADD COLUMN storage_state_code text NOT NULL DEFAULT 'finalized'
    CHECK (storage_state_code IN ('staged','finalized','orphaned','destroyed')),
  ADD COLUMN cipher_suite_code text CHECK (cipher_suite_code IS NULL OR cipher_suite_code='aes_256_gcm_framed'),
  ADD COLUMN frame_manifest jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN finalized_at timestamptz,
  ADD COLUMN last_verified_at timestamptz,
  ADD CONSTRAINT content_audit_storage_shape_check CHECK (
    scope_code <> 'full_encrypted'
    OR (cipher_suite_code='aes_256_gcm_framed' AND frame_manifest <> '{}'::jsonb)
  ) NOT VALID;

CREATE TABLE ops.alert_silence (
  id uuid PRIMARY KEY,
  fingerprint_pattern text NOT NULL,
  reason text NOT NULL,
  starts_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  created_by uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  created_at timestamptz NOT NULL,
  CHECK (expires_at > starts_at)
);
CREATE INDEX alert_silence_active_idx ON ops.alert_silence (expires_at) WHERE expires_at > starts_at;

CREATE TABLE ops.notification_inbox (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES iam.user_account(id) ON DELETE CASCADE,
  alert_id uuid REFERENCES ops.alert(id) ON DELETE RESTRICT,
  severity_code text NOT NULL CHECK (severity_code IN ('info','warning','critical')),
  title text NOT NULL,
  summary text NOT NULL,
  read_at timestamptz,
  created_at timestamptz NOT NULL
);
CREATE INDEX notification_inbox_user_idx ON ops.notification_inbox (user_id,created_at DESC);

CREATE TABLE ops.integrity_check_run (
  id uuid PRIMARY KEY,
  state_code text NOT NULL CHECK (state_code IN ('running','succeeded','failed')),
  audit_event_count bigint CHECK (audit_event_count IS NULL OR audit_event_count >= 0),
  daily_seal_count bigint CHECK (daily_seal_count IS NULL OR daily_seal_count >= 0),
  deletion_ledger_count bigint CHECK (deletion_ledger_count IS NULL OR deletion_ledger_count >= 0),
  error_code text,
  started_at timestamptz NOT NULL,
  completed_at timestamptz
);

CREATE TABLE ops.release_gate_run (
  id uuid PRIMARY KEY,
  release_version text NOT NULL,
  candidate_digest bytea NOT NULL CHECK (octet_length(candidate_digest)=32),
  gate_code text NOT NULL,
  state_code text NOT NULL CHECK (state_code IN ('not_run','running','passed','failed','blocked_external')),
  evidence_uri text,
  evidence_digest bytea CHECK (evidence_digest IS NULL OR octet_length(evidence_digest)=32),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL,
  UNIQUE (release_version,gate_code)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON ops.alert_silence, ops.notification_inbox,
  ops.integrity_check_run, ops.release_gate_run TO gateway_runtime;
GRANT SELECT ON ops.alert_silence, ops.notification_inbox, ops.integrity_check_run,
  ops.release_gate_run TO gateway_readonly, gateway_backup;
