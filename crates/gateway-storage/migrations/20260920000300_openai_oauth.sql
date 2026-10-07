SET LOCAL ROLE gateway_migrator;
CREATE TABLE gateway.openai_oauth_session (
 id uuid PRIMARY KEY,
 actor_id uuid NOT NULL REFERENCES iam.user_account(id),
 group_id uuid NOT NULL REFERENCES gateway.credential_group(id),
 name text NOT NULL,
 state_digest bytea NOT NULL,
 verifier_secret_id uuid NOT NULL REFERENCES security.encrypted_secret(id),
 proxy_id uuid REFERENCES gateway.proxy_endpoint(id),
 state_code text NOT NULL DEFAULT 'pending' CHECK(state_code IN ('pending','exchanging','completed','failed')),
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
GRANT SELECT,INSERT,UPDATE,DELETE ON gateway.openai_oauth_session TO gateway_runtime;
GRANT SELECT ON gateway.openai_oauth_session TO gateway_readonly,gateway_backup;
RESET ROLE;
