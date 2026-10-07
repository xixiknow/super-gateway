SET LOCAL ROLE gateway_migrator;
ALTER TABLE gateway.openai_oauth_session ADD COLUMN response_secret_id uuid REFERENCES security.encrypted_secret(id);
ALTER TABLE gateway.openai_oauth_session ADD COLUMN replace_account_id uuid REFERENCES gateway.openai_account(id);
ALTER TABLE gateway.openai_oauth_session ADD COLUMN account_revision bigint;
ALTER TABLE gateway.openai_oauth_session DROP CONSTRAINT openai_oauth_session_state_code_check;
ALTER TABLE gateway.openai_oauth_session ADD CONSTRAINT openai_oauth_session_state_code_check CHECK(state_code IN ('pending','exchanging','exchanged','importing','completed','failed'));
RESET ROLE;
