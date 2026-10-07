SET LOCAL ROLE gateway_migrator;
-- Independent, stable random identity namespace; never exposed in account projections.
ALTER TABLE gateway.openai_account ADD COLUMN session_namespace uuid NOT NULL DEFAULT gen_random_uuid();
RESET ROLE;
