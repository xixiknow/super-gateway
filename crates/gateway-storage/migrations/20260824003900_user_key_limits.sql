-- User-owned key ceilings, prepaid balance and per-key lifetime spend limits.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE iam.user_account
  ADD COLUMN key_max_concurrency integer NOT NULL DEFAULT 5
    CHECK (key_max_concurrency >= 1),
  ADD COLUMN key_max_rpm integer NOT NULL DEFAULT 60
    CHECK (key_max_rpm >= 1),
  ADD COLUMN credit_limit_amount numeric(38,12)
    CHECK (credit_limit_amount IS NULL OR credit_limit_amount >= 0);

COMMENT ON COLUMN iam.user_account.key_max_concurrency IS
  'Upper bound applied to every Platform Key owned by this user.';
COMMENT ON COLUMN iam.user_account.key_max_rpm IS
  'Messages RPM upper bound applied to every Platform Key owned by this user.';
COMMENT ON COLUMN iam.user_account.credit_limit_amount IS
  'Nullable lifetime estimated API value credit in USD; remaining balance is credit minus recorded usage.';

ALTER TABLE iam.platform_key
  ADD COLUMN spend_limit_amount numeric(38,12)
    CHECK (spend_limit_amount IS NULL OR spend_limit_amount >= 0);

COMMENT ON COLUMN iam.platform_key.spend_limit_amount IS
  'Nullable lifetime estimated API value limit in USD; requests stop after recorded usage reaches the limit.';

-- Group assignment is now an administrator-managed mutable binding. Owner and
-- secret identity remain immutable.
CREATE OR REPLACE FUNCTION iam.reject_platform_key_rebind() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id OR NEW.secret_id IS DISTINCT FROM OLD.secret_id THEN
    RAISE EXCEPTION 'platform key owner and secret binding are immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE INDEX usage_aggregate_contribution_platform_key_idx
  ON telemetry.usage_aggregate_contribution (platform_key_id);

RESET ROLE;
