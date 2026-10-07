-- Header diagnostics share the optional request body retention lifecycle.
SET LOCAL ROLE gateway_migrator;
ALTER TABLE telemetry.request_body
  ADD COLUMN original_headers jsonb,
  ADD COLUMN final_upstream_headers jsonb,
  ADD COLUMN upstream_response_headers jsonb,
  ADD COLUMN header_attempt_ordinal integer;
RESET ROLE;
