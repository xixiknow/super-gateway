-- R8 notification destination and durable delivery release.

ALTER TABLE ops.notification_delivery
  ADD COLUMN delivery_kind_code text NOT NULL DEFAULT 'alert'
    CHECK (delivery_kind_code IN ('alert','recovery','test')),
  ADD COLUMN dedupe_key text,
  ADD COLUMN payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN last_outcome jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  ADD COLUMN updated_at timestamptz;

UPDATE ops.notification_delivery
SET updated_at = created_at
WHERE updated_at IS NULL;

ALTER TABLE ops.notification_delivery
  ALTER COLUMN updated_at SET NOT NULL,
  ALTER COLUMN updated_at SET DEFAULT clock_timestamp();

CREATE UNIQUE INDEX notification_delivery_dedupe_uq
  ON ops.notification_delivery (destination_id, dedupe_key)
  WHERE dedupe_key IS NOT NULL;

CREATE INDEX notification_delivery_state_due_idx
  ON ops.notification_delivery (state_code, next_attempt_at, destination_id);

CREATE OR REPLACE FUNCTION ops.validate_notification_destination_configuration()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF jsonb_typeof(NEW.configuration) <> 'object'
     OR NEW.configuration ?| ARRAY['send_key','password','secret','token','authorization'] THEN
    RAISE EXCEPTION 'notification destination configuration must be a redacted object';
  END IF;
  IF NEW.kind_code = 'inbox' AND NEW.secret_id IS NOT NULL THEN
    RAISE EXCEPTION 'inbox notification destination must not reference a secret';
  END IF;
  IF NEW.kind_code <> 'inbox' AND NEW.secret_id IS NULL THEN
    RAISE EXCEPTION 'external notification destination requires a secret';
  END IF;
  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER notification_destination_configuration_guard
AFTER INSERT OR UPDATE OF kind_code,secret_id,configuration ON ops.notification_destination
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION ops.validate_notification_destination_configuration();
