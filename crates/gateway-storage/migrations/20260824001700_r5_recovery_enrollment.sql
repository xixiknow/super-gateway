-- R5 recovery: preserve historical Enrollment rows while allowing exactly one
-- non-terminal Enrollment to own a Credential at a time.

SET LOCAL ROLE gateway_migrator;

DROP INDEX IF EXISTS gateway.credential_enrollment_pending_credential_uq;

CREATE UNIQUE INDEX credential_enrollment_pending_credential_uq
  ON gateway.credential_enrollment (pending_credential_id)
  WHERE pending_credential_id IS NOT NULL
    AND state_code NOT IN ('succeeded','failed','cancelled','expired');

RESET ROLE;
