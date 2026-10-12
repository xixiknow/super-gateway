-- Opt-in per-credential request pacing: NULL disables spacing between grants.
ALTER TABLE gateway.credential_scheduling_config
  ADD COLUMN min_request_interval_ms bigint CHECK (min_request_interval_ms IS NULL OR min_request_interval_ms >= 0);
