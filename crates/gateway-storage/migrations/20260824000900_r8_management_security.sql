-- R8 management authentication, step-up and two-person approval alignment.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE iam.user_account
  DROP CONSTRAINT IF EXISTS user_account_status_code_check,
  ADD CONSTRAINT user_account_status_code_check
    CHECK (status_code IN ('invited','active','disabled','archived','mfa_pending','locked'));

ALTER TABLE security.approval_case
  ADD COLUMN request_reason text,
  ADD COLUMN requester_step_up_grant_id uuid REFERENCES iam.management_step_up_grant(id) ON DELETE RESTRICT,
  ADD COLUMN action_snapshot_digest bytea,
  ADD COLUMN decided_at timestamptz,
  ADD CONSTRAINT approval_action_snapshot_digest_ck
    CHECK (action_snapshot_digest IS NULL OR octet_length(action_snapshot_digest) = 32);

ALTER TABLE security.approval_grant
  ADD COLUMN step_up_grant_id uuid REFERENCES iam.management_step_up_grant(id) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION security.reject_self_approval() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE requester uuid;
BEGIN
  SELECT requested_by INTO requester FROM security.approval_case WHERE id = NEW.approval_case_id FOR UPDATE;
  IF requester IS NULL OR requester = NEW.approver_user_id THEN
    RAISE EXCEPTION 'approval requester and approver must differ' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER approval_requester_must_differ
  BEFORE INSERT ON security.approval_grant
  FOR EACH ROW EXECUTE FUNCTION security.reject_self_approval();

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA iam, security TO gateway_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA iam TO gateway_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA iam, security TO gateway_backup;

RESET ROLE;
