SET LOCAL ROLE gateway_migrator;

-- Stable provider-neutral identity; retain all pre-existing credential UUIDs.
CREATE TABLE gateway.credential_identity (
 id uuid PRIMARY KEY,
 provider_code text NOT NULL CHECK (provider_code IN ('anthropic','openai')),
 UNIQUE(id,provider_code)
);
INSERT INTO gateway.credential_identity SELECT id,'anthropic' FROM gateway.anthropic_credential;
INSERT INTO gateway.credential_identity SELECT id,'openai' FROM gateway.openai_account;
CREATE FUNCTION gateway.register_credential_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO gateway.credential_identity(id,provider_code) VALUES(NEW.id,NEW.provider_code);
 RETURN NEW;
END $$;
CREATE TRIGGER register_anthropic_identity BEFORE INSERT ON gateway.anthropic_credential
 FOR EACH ROW EXECUTE FUNCTION gateway.register_credential_identity();
CREATE TRIGGER register_openai_identity BEFORE INSERT ON gateway.openai_account
 FOR EACH ROW EXECUTE FUNCTION gateway.register_credential_identity();
ALTER TABLE gateway.anthropic_credential ADD FOREIGN KEY(id,provider_code) REFERENCES gateway.credential_identity(id,provider_code);
ALTER TABLE gateway.openai_account ADD FOREIGN KEY(id,provider_code) REFERENCES gateway.credential_identity(id,provider_code);
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT conrelid::regclass AS tbl,conname FROM pg_constraint
   WHERE contype='f' AND confrelid='gateway.anthropic_credential'::regclass
   AND connamespace='telemetry'::regnamespace LOOP
   EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',r.tbl,r.conname);
   EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY(credential_id) REFERENCES gateway.credential_identity(id) ON DELETE RESTRICT',r.tbl,r.conname);
 END LOOP;
END $$;
ALTER TABLE telemetry.attempt_submission_intent ALTER COLUMN profile_epoch DROP NOT NULL, ALTER COLUMN transport_bundle_id DROP NOT NULL;
ALTER TABLE telemetry.connection_attempt_record ALTER COLUMN profile_epoch DROP NOT NULL, ALTER COLUMN transport_bundle_id DROP NOT NULL;
ALTER TABLE telemetry.attempt_record ALTER COLUMN profile_epoch DROP NOT NULL, ALTER COLUMN transport_bundle_id DROP NOT NULL;
ALTER TABLE telemetry.request_record DROP CONSTRAINT request_record_endpoint_code_check;
ALTER TABLE telemetry.request_record ADD CONSTRAINT request_record_endpoint_code_check
 CHECK(endpoint_code IN ('messages','count_tokens','models','model_detail','responses','chat_completions','responses_compact','responses_websocket'));
ALTER TABLE telemetry.usage_observation ADD COLUMN reasoning_tokens bigint CHECK(reasoning_tokens>=0),
 ADD COLUMN request_model text, ADD COLUMN upstream_model text, ADD COLUMN response_model text;
CREATE TABLE gateway.openai_response_binding (
 platform_key_id uuid NOT NULL REFERENCES iam.platform_key(id),
 response_id text NOT NULL,
 account_id uuid NOT NULL REFERENCES gateway.openai_account(id),
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(platform_key_id,response_id)
);
CREATE INDEX openai_response_expiry ON gateway.openai_response_binding(expires_at);
ALTER TABLE gateway.openai_account ADD COLUMN refresh_attempt_id uuid,
 ADD COLUMN refresh_lease_until timestamptz,
 ADD COLUMN refresh_failures integer NOT NULL DEFAULT 0;
GRANT SELECT,INSERT,UPDATE,DELETE ON gateway.credential_identity,gateway.openai_response_binding TO gateway_runtime;
GRANT SELECT ON gateway.credential_identity,gateway.openai_response_binding TO gateway_readonly,gateway_backup;
GRANT EXECUTE ON FUNCTION gateway.register_credential_identity() TO gateway_runtime;
RESET ROLE;
