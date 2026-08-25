-- R9 production Alert/Recovery notification fanout.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE ops.alert
  ADD COLUMN group_id uuid REFERENCES gateway.credential_group(id) ON DELETE RESTRICT;

ALTER TABLE ops.notification_delivery
  DROP CONSTRAINT notification_delivery_alert_id_destination_id_attempt_ordin_key;

CREATE INDEX alert_group_state_idx
  ON ops.alert(group_id,state_code,last_seen_at DESC) WHERE group_id IS NOT NULL;

RESET ROLE;
