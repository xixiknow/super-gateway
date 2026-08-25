-- R7 cancellation accounting hardening: bind every estimate to the exact
-- attempt/request pair and make versioned evidence/cost replays deterministic.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE telemetry.attempt_record
  ADD CONSTRAINT attempt_record_request_identity_uq
  UNIQUE (request_month, request_id, id);

ALTER TABLE telemetry.usage_observation
  DROP CONSTRAINT usage_observation_attempt_id_fkey,
  ADD CONSTRAINT usage_observation_attempt_request_fk
    FOREIGN KEY (request_month, request_id, attempt_id)
    REFERENCES telemetry.attempt_record (request_month, request_id, id)
    ON DELETE RESTRICT,
  DROP CONSTRAINT usage_cancel_evidence_shape_ck,
  ADD CONSTRAINT usage_cancel_evidence_shape_ck CHECK (
    (
      source_code='cancel_estimate'
      AND attempt_id IS NOT NULL
      AND completeness_code='partial'
      AND algorithm_version IS NOT NULL
      AND algorithm_version<>''
      AND input_basis_digest IS NOT NULL
      AND octet_length(input_basis_digest)=32
      AND (sse_gap IS DISTINCT FROM TRUE OR output_tokens IS NULL)
      AND (
        sse_complete_event_ordinal IS NULL
        OR sse_content_event_ordinal IS NULL
        OR sse_content_event_ordinal<=sse_complete_event_ordinal
      )
    )
    OR
    (
      source_code<>'cancel_estimate'
      AND input_basis_digest IS NULL
      AND sse_complete_event_ordinal IS NULL
      AND sse_content_event_ordinal IS NULL
      AND sse_decoded_end_offset IS NULL
      AND sse_last_event_type IS NULL
      AND sse_gap IS NULL
    )
  );

CREATE UNIQUE INDEX cost_estimate_usage_observation_uq
  ON telemetry.cost_estimate (usage_observation_id);

RESET ROLE;
