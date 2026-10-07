-- Additive provider foundation. Existing IDs, auth envelopes and AAD stay untouched.
SET LOCAL ROLE gateway_migrator;

ALTER TABLE gateway.credential_group
  ADD COLUMN provider_code text NOT NULL DEFAULT 'anthropic'
    CHECK (provider_code IN ('anthropic','openai')),
  ADD CONSTRAINT credential_group_id_provider_uq UNIQUE (id, provider_code);

ALTER TABLE gateway.anthropic_credential
  ADD COLUMN provider_code text NOT NULL DEFAULT 'anthropic'
    CHECK (provider_code = 'anthropic'),
  ADD CONSTRAINT anthropic_credential_group_provider_fk
    FOREIGN KEY (group_id,provider_code) REFERENCES gateway.credential_group(id,provider_code),
  ADD CONSTRAINT anthropic_credential_target_provider_fk
    FOREIGN KEY (attachment_target_group_id,provider_code) REFERENCES gateway.credential_group(id,provider_code);

ALTER TABLE catalog.model_definition
  ADD COLUMN provider_code text NOT NULL DEFAULT 'anthropic'
    CHECK (provider_code IN ('anthropic','openai'));

CREATE TABLE gateway.openai_settings (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  enabled boolean NOT NULL DEFAULT false,
  websocket_enabled boolean NOT NULL DEFAULT false,
  connect_timeout_seconds integer NOT NULL DEFAULT 15 CHECK (connect_timeout_seconds BETWEEN 1 AND 120),
  response_timeout_seconds integer NOT NULL DEFAULT 300 CHECK (response_timeout_seconds BETWEEN 1 AND 3600),
  websocket_idle_seconds integer NOT NULL DEFAULT 120 CHECK (websocket_idle_seconds BETWEEN 1 AND 3600),
  refresh_interval_seconds integer NOT NULL DEFAULT 60 CHECK (refresh_interval_seconds BETWEEN 10 AND 3600),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0)
);
INSERT INTO gateway.openai_settings(singleton) VALUES (true);

CREATE TABLE gateway.openai_account (
  id uuid PRIMARY KEY,
  group_id uuid NOT NULL,
  provider_code text NOT NULL DEFAULT 'openai' CHECK (provider_code='openai'),
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 128),
  auth_kind_code text NOT NULL CHECK (auth_kind_code IN ('oauth','api_key')),
  account_id text,
  user_id text,
  access_secret_id uuid NOT NULL REFERENCES security.encrypted_secret(id),
  refresh_secret_id uuid REFERENCES security.encrypted_secret(id),
  id_token_secret_id uuid REFERENCES security.encrypted_secret(id),
  proxy_id uuid REFERENCES gateway.proxy_endpoint(id),
  enabled boolean NOT NULL DEFAULT false,
  verified_at timestamptz,
  auth_state_code text NOT NULL DEFAULT 'pending_verify'
    CHECK (auth_state_code IN ('pending_verify','healthy','refreshing','manual_update','needs_reauth')),
  token_version bigint NOT NULL DEFAULT 1 CHECK (token_version > 0),
  expires_at timestamptz,
  cooldown_until timestamptz,
  max_concurrency integer NOT NULL DEFAULT 5 CHECK (max_concurrency BETWEEN 1 AND 1000),
  priority integer NOT NULL DEFAULT 0,
  websocket_enabled boolean NOT NULL DEFAULT true,
  models jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(models)='array'),
  quota_snapshot jsonb,
  quota_observed_at timestamptz,
  plan_label text,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (group_id,provider_code) REFERENCES gateway.credential_group(id,provider_code),
  CHECK (auth_kind_code <> 'oauth' OR (account_id IS NOT NULL AND length(btrim(account_id)) > 0)),
  CHECK (auth_kind_code <> 'api_key' OR refresh_secret_id IS NULL),
  CHECK (NOT enabled OR verified_at IS NOT NULL)
);
CREATE UNIQUE INDEX openai_account_identity_uq ON gateway.openai_account(account_id)
  WHERE auth_kind_code='oauth';
CREATE INDEX openai_account_group_idx ON gateway.openai_account(group_id,enabled,priority);

CREATE TABLE gateway.openai_group_policy (
  group_id uuid PRIMARY KEY,
  provider_code text NOT NULL DEFAULT 'openai' CHECK (provider_code='openai'),
  max_reasoning_effort text,
  reasoning_over_limit text NOT NULL DEFAULT 'reject' CHECK (reasoning_over_limit IN ('reject','downgrade')),
  FOREIGN KEY (group_id,provider_code) REFERENCES gateway.credential_group(id,provider_code)
);

GRANT SELECT,INSERT,UPDATE,DELETE ON gateway.openai_settings,gateway.openai_account,gateway.openai_group_policy TO gateway_runtime;
GRANT SELECT ON gateway.openai_settings,gateway.openai_account,gateway.openai_group_policy TO gateway_readonly,gateway_backup;
RESET ROLE;
