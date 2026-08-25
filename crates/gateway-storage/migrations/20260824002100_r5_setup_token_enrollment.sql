-- Verify inference-only Claude Code Setup Tokens without inventing refresh
-- material or provider account identity.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE gateway.credential_provider_profile
  ADD COLUMN bootstrap_endpoint text;

UPDATE gateway.credential_provider_profile
SET bootstrap_endpoint = 'https://api.anthropic.com/api/claude_cli/bootstrap'
WHERE profile_code = 'claude_code_subscription'
  AND profile_version = 1;

ALTER TABLE gateway.credential_provider_profile
  ADD CONSTRAINT credential_provider_profile_bootstrap_endpoint_ck CHECK (
    lifecycle_code NOT IN ('canary','active')
    OR bootstrap_endpoint ~ '^https://[^/@[:space:]]+(/[^#[:space:]]*)?$'
  );

ALTER TABLE gateway.credential_auth_secret_stage
  ALTER COLUMN refresh_secret_id DROP NOT NULL;

RESET ROLE;
