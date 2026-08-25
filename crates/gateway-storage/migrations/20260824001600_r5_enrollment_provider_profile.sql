-- Complete the versioned Claude Code enrollment/refresh provider contract.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE gateway.credential_provider_profile
  ADD COLUMN authorize_endpoint text,
  ADD COLUMN profile_endpoint text,
  ADD COLUMN redirect_uri text,
  ADD COLUMN request_encoding_code text NOT NULL DEFAULT 'form_urlencoded'
    CHECK (request_encoding_code IN ('application_json','form_urlencoded')),
  ADD COLUMN evidence_version text;

ALTER TABLE gateway.credential_provider_profile
  ADD CONSTRAINT credential_provider_profile_enrollment_endpoints_ck CHECK (
    lifecycle_code NOT IN ('canary','active') OR (
      authorize_endpoint ~ '^https://[^/@[:space:]]+(/[^#[:space:]]*)?$'
      AND profile_endpoint ~ '^https://[^/@[:space:]]+(/[^#[:space:]]*)?$'
      AND redirect_uri ~ '^https://[^/@[:space:]]+(/[^#[:space:]]*)?$'
      AND length(btrim(evidence_version)) BETWEEN 1 AND 256
    )
  );

INSERT INTO gateway.credential_provider_profile (
  id,profile_code,profile_version,lifecycle_code,auth_kind_codes,token_endpoint,client_id,scopes,
  max_response_bytes,response_schema_code,evidence_digest,activated_at,authorize_endpoint,profile_endpoint,
  redirect_uri,request_encoding_code,evidence_version
) VALUES (
  '0198d888-34a0-7b5d-a4cd-000000000001',
  'claude_code_subscription',
  1,
  'active',
  '["oauth_subscription","setup_token_subscription"]'::jsonb,
  'https://platform.claude.com/v1/oauth/token',
  '9d1c250a-e61b-44d9-88ed-5944d1962f5e',
  '["org:create_api_key","user:profile","user:inference","user:sessions:claude_code","user:mcp_servers","user:file_upload"]'::jsonb,
  65536,
  'oauth_token_v1',
  decode('a328dd6e96ce21a97dfedcbe73b6963091f9c38998e818ade9ba32d796e08dc1','hex'),
  clock_timestamp(),
  'https://claude.com/cai/oauth/authorize',
  'https://api.anthropic.com/api/oauth/profile',
  'https://platform.claude.com/oauth/code/callback',
  'application_json',
  'claude-code-2.1.220-local-source'
) ON CONFLICT (profile_code,profile_version) DO NOTHING;

RESET ROLE;
