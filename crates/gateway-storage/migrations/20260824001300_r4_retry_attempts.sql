-- A ConnectionAttempt is not a Messages Attempt until the first upstream
-- request byte. Multiple pre-byte connections may therefore share the next
-- Messages ordinal; only one of them may ever be promoted.

ALTER TABLE telemetry.attempt_submission_intent
  DROP CONSTRAINT attempt_submission_intent_request_month_request_id_ordinal_key;

CREATE UNIQUE INDEX attempt_submission_intent_one_promoted_ordinal_uq
  ON telemetry.attempt_submission_intent (request_month, request_id, ordinal)
  WHERE state_code = 'promoted';

COMMENT ON INDEX telemetry.attempt_submission_intent_one_promoted_ordinal_uq IS
  'Many armed/aborted connection intents may target one Messages ordinal; exactly one may promote.';
