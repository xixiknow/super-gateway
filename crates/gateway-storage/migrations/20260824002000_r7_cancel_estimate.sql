-- R7 cancellation estimate evidence. Only fully committed SSE event boundaries
-- may contribute to the versioned partial-output estimate.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE telemetry.usage_observation
  ADD COLUMN input_basis_digest bytea,
  ADD COLUMN sse_complete_event_ordinal bigint CHECK (sse_complete_event_ordinal >= 0),
  ADD COLUMN sse_content_event_ordinal bigint CHECK (sse_content_event_ordinal >= 0),
  ADD COLUMN sse_decoded_end_offset bigint CHECK (sse_decoded_end_offset >= 0),
  ADD COLUMN sse_last_event_type text,
  ADD COLUMN sse_gap boolean,
  ADD CONSTRAINT usage_cancel_evidence_shape_ck CHECK (
    (source_code='cancel_estimate' AND input_basis_digest IS NOT NULL AND octet_length(input_basis_digest)=32)
    OR
    (source_code<>'cancel_estimate'
      AND input_basis_digest IS NULL
      AND sse_complete_event_ordinal IS NULL
      AND sse_content_event_ordinal IS NULL
      AND sse_decoded_end_offset IS NULL
      AND sse_last_event_type IS NULL
      AND sse_gap IS NULL)
  );

CREATE UNIQUE INDEX usage_cancel_estimate_natural_uq
  ON telemetry.usage_observation
    (request_month,request_id,attempt_id,source_code,algorithm_version) NULLS NOT DISTINCT
  WHERE source_code='cancel_estimate';

COMMENT ON COLUMN telemetry.usage_observation.sse_decoded_end_offset IS
  'Decoded side-channel byte offset at the last fully terminated SSE event; never a relay rewrite offset.';

RESET ROLE;
