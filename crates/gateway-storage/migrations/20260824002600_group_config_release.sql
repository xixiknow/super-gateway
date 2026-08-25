-- Versioned Group Config release states and defaults used by future Credentials.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE gateway.group_config
  ADD COLUMN lifecycle_code text NOT NULL DEFAULT 'draft',
  ADD COLUMN validation_report jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN validated_at timestamptz,
  ADD COLUMN published_at timestamptz,
  ADD COLUMN default_credential_concurrency integer NOT NULL DEFAULT 5
    CHECK (default_credential_concurrency >= 1),
  ADD COLUMN default_credential_rpm integer NOT NULL DEFAULT 60
    CHECK (default_credential_rpm >= 1);

UPDATE gateway.group_config config
SET lifecycle_code = CASE
  WHEN EXISTS (
    SELECT 1 FROM gateway.group_active_config active
    WHERE active.config_id=config.id
  ) THEN 'active'
  ELSE 'retired'
END,
validated_at = created_at,
published_at = CASE
  WHEN EXISTS (
    SELECT 1 FROM gateway.group_active_config active
    WHERE active.config_id=config.id
  ) THEN created_at
  ELSE NULL
END;

ALTER TABLE gateway.group_config
  ADD CONSTRAINT group_config_lifecycle_code_check
    CHECK (lifecycle_code IN ('draft','validated','shadow','canary','active','retired')),
  ADD CONSTRAINT group_config_validation_shape_check
    CHECK (
      (lifecycle_code='draft' AND validated_at IS NULL)
      OR (lifecycle_code<>'draft' AND validated_at IS NOT NULL)
    );

CREATE UNIQUE INDEX group_config_one_shadow_uq
  ON gateway.group_config (group_id) WHERE lifecycle_code='shadow';
CREATE UNIQUE INDEX group_config_one_canary_uq
  ON gateway.group_config (group_id) WHERE lifecycle_code='canary';
CREATE UNIQUE INDEX group_config_one_active_uq
  ON gateway.group_config (group_id) WHERE lifecycle_code='active';

GRANT SELECT, INSERT, UPDATE, DELETE ON gateway.group_config TO gateway_runtime;
GRANT SELECT ON gateway.group_config TO gateway_readonly, gateway_backup;

RESET ROLE;
