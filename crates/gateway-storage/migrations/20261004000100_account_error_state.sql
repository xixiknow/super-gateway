SET LOCAL ROLE gateway_migrator;

-- Account-dimension error surface: persist the last upstream rejection on the
-- account row itself so the console can render it without joining event tables.

ALTER TABLE gateway.anthropic_credential
    ADD COLUMN last_error_code text,
    ADD COLUMN last_error_message text,
    ADD COLUMN last_error_at timestamptz;

ALTER TABLE gateway.openai_account
    ADD COLUMN last_error_code text,
    ADD COLUMN last_error_message text,
    ADD COLUMN last_error_at timestamptz;

-- 529 Overloaded reuses the cooldown machinery but is a distinct reason from 429.
ALTER TABLE telemetry.credential_cooldown_event
    DROP CONSTRAINT credential_cooldown_event_reason_code_check;
ALTER TABLE telemetry.credential_cooldown_event
    ADD CONSTRAINT credential_cooldown_event_reason_code_check
    CHECK (reason_code IN ('rate_limit','quota_pressure','auth_failure','transport_failure','manual','overload'));

RESET ROLE;
