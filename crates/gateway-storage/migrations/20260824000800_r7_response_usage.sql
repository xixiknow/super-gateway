-- R7 response commit, delivery, usage and resource-accounting contract alignment.

ALTER TABLE telemetry.request_record
  ADD COLUMN response_mode_code text CHECK (response_mode_code IN ('streaming','non_streaming')),
  ADD COLUMN client_commit_state_code text NOT NULL DEFAULT 'uncommitted'
    CHECK (client_commit_state_code IN ('uncommitted','committed')),
  ADD COLUMN terminal_kind_code text CHECK (terminal_kind_code IN (
    'completed','failed_before_commit','client_delivery_failed','cancelled_before_commit','cancelled_after_commit'
  )),
  ADD COLUMN response_header_policy_version text,
  ADD COLUMN usage_completeness_code text CHECK (usage_completeness_code IN ('complete','partial','unknown'));

UPDATE telemetry.attempt_submission_intent
SET state_code = CASE state_code
  WHEN 'created' THEN 'armed'
  WHEN 'cancelled' THEN 'aborted'
  ELSE state_code
END;

ALTER TABLE telemetry.attempt_submission_intent
  DROP CONSTRAINT IF EXISTS attempt_submission_intent_state_code_check,
  ADD CONSTRAINT attempt_submission_intent_state_code_check
    CHECK (state_code IN ('armed','promoted','aborted','commit_unknown')),
  ADD COLUMN armed_at timestamptz,
  ADD COLUMN promoted_at timestamptz,
  ADD COLUMN aborted_at timestamptz,
  ADD COLUMN request_bytes_written bigint NOT NULL DEFAULT 0 CHECK (request_bytes_written >= 0);

ALTER TABLE telemetry.response_delivery_record
  ADD COLUMN buffer_tier_code text CHECK (buffer_tier_code IN ('memory','encrypted_spill')),
  ADD COLUMN outcome_code text CHECK (outcome_code IN (
    'complete','client_disconnected','client_write_timeout','upstream_body_error',
    'buffer_rejected','cancelled_before_commit'
  )),
  ADD COLUMN upstream_bytes_received bigint NOT NULL DEFAULT 0 CHECK (upstream_bytes_received >= 0),
  ADD COLUMN peak_backpressure_bytes bigint NOT NULL DEFAULT 0 CHECK (peak_backpressure_bytes >= 0),
  ADD COLUMN client_write_idle_ms bigint CHECK (client_write_idle_ms > 0),
  ADD COLUMN spill_bytes bigint NOT NULL DEFAULT 0 CHECK (spill_bytes >= 0),
  ADD COLUMN usage_observation_complete boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT response_delivery_buffer_tier_ck CHECK (
    (streaming AND buffer_tier_code IS NULL) OR
    (NOT streaming AND (buffer_tier_code IS NOT NULL OR NOT response_committed))
  );

ALTER TABLE telemetry.usage_observation
  ADD COLUMN selected_at timestamptz,
  ADD COLUMN selection_reason_code text CHECK (selection_reason_code IN (
    'official_complete','official_partial','console_count','local_estimate','cancel_estimate','unknown'
  )),
  ADD CONSTRAINT usage_unknown_has_no_counts_ck CHECK (
    completeness_code <> 'unknown' OR (
      input_tokens IS NULL AND output_tokens IS NULL AND
      cache_creation_input_tokens IS NULL AND cache_read_input_tokens IS NULL
    )
  );

ALTER TABLE telemetry.cost_estimate
  ADD COLUMN amount_pico_usd numeric(38,0) CHECK (amount_pico_usd >= 0),
  ADD COLUMN known_field_mask integer NOT NULL DEFAULT 0 CHECK (known_field_mask BETWEEN 0 AND 15),
  ADD CONSTRAINT cost_amount_agreement_ck CHECK (
    (amount IS NULL) = (amount_pico_usd IS NULL)
  );
