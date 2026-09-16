-- T6.2: expose Count Tokens as a first-class data-plane endpoint.
SET LOCAL ROLE gateway_migrator;

ALTER TABLE telemetry.request_record
  DROP CONSTRAINT IF EXISTS request_record_endpoint_code_check;

ALTER TABLE telemetry.request_record
  ADD CONSTRAINT request_record_endpoint_code_check
  CHECK (endpoint_code IN ('messages','count_tokens','models','model_detail'));

RESET ROLE;
