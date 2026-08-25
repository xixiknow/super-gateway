-- R5 machine-contract alignment for Credential purpose and Proxy health taxonomies.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE gateway.anthropic_credential
  DROP CONSTRAINT anthropic_credential_purpose_code_check;
ALTER TABLE gateway.anthropic_credential
  ADD CONSTRAINT anthropic_credential_purpose_code_check
  CHECK (purpose_code IN ('business','verification_only','count_tokens'));

ALTER TABLE gateway.proxy_endpoint
  DROP CONSTRAINT proxy_endpoint_health_code_check;
UPDATE gateway.proxy_endpoint SET health_code = CASE health_code
  WHEN 'connect_failed' THEN 'unhealthy_connect'
  WHEN 'auth_failed' THEN 'unhealthy_auth'
  WHEN 'tls_intercepted' THEN 'unhealthy_tls_passthrough'
  WHEN 'egress_mismatch' THEN 'unhealthy_tunnel'
  WHEN 'unhealthy' THEN 'unhealthy_connect'
  ELSE health_code END;
ALTER TABLE gateway.proxy_endpoint
  ADD CONSTRAINT proxy_endpoint_health_code_check CHECK (
    health_code IN (
      'unknown','probing','healthy','unhealthy_dns','unhealthy_connect',
      'unhealthy_auth','unhealthy_tunnel','unhealthy_tls_passthrough'
    )
  );

ALTER TABLE telemetry.subscription_plan_current
  ADD COLUMN mapping_artifact_id uuid REFERENCES catalog.versioned_artifact(id) ON DELETE RESTRICT;

RESET ROLE;
