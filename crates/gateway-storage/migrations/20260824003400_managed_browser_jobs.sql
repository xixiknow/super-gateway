CREATE TABLE gateway.managed_browser_secret_stage (
  operation_id uuid NOT NULL REFERENCES gateway.maintenance_operation(id) ON DELETE RESTRICT,
  operation_generation bigint NOT NULL CHECK (operation_generation >= 1),
  credential_id uuid NOT NULL REFERENCES gateway.anthropic_credential(id) ON DELETE RESTRICT,
  strategy_id uuid NOT NULL REFERENCES gateway.auto_reauth_strategy(id) ON DELETE RESTRICT,
  candidate_material_version bigint NOT NULL CHECK (candidate_material_version >= 1),
  cookie_secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  storage_secret_id uuid UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  profile_secret_id uuid NOT NULL UNIQUE REFERENCES security.encrypted_secret(id) ON DELETE RESTRICT,
  verified_account_uuid uuid NOT NULL,
  adapter_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (operation_id, operation_generation)
);

CREATE UNIQUE INDEX managed_browser_strategy_credential_kind_uq
  ON gateway.auto_reauth_strategy (credential_id, strategy_kind_code);
DROP INDEX gateway.auto_reauth_strategy_active_kind_uq;

GRANT SELECT, INSERT, UPDATE, DELETE ON gateway.managed_browser_secret_stage TO gateway_runtime;
GRANT SELECT ON gateway.managed_browser_secret_stage TO gateway_readonly;
GRANT SELECT ON gateway.managed_browser_secret_stage TO gateway_backup;
