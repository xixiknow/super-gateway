ALTER TABLE catalog.model_discovery_run
  ALTER COLUMN source_credential_id DROP NOT NULL,
  ALTER COLUMN source_credential_revision DROP NOT NULL,
  ALTER COLUMN source_token_version DROP NOT NULL,
  ALTER COLUMN source_egress_epoch DROP NOT NULL;

ALTER TABLE catalog.model_discovery_run
  DROP CONSTRAINT model_discovery_run_source_code_check;

ALTER TABLE catalog.model_discovery_run
  ADD CONSTRAINT model_discovery_run_source_code_check
    CHECK (source_code IN ('anthropic_models_api', 'anthropic_public_docs', 'builtin_snapshot')),
  ADD CONSTRAINT model_discovery_run_source_provenance_check
    CHECK (
      (source_code = 'anthropic_models_api'
        AND source_credential_id IS NOT NULL
        AND source_credential_revision IS NOT NULL
        AND source_token_version IS NOT NULL
        AND source_egress_epoch IS NOT NULL)
      OR
      (source_code IN ('anthropic_public_docs', 'builtin_snapshot')
        AND source_credential_id IS NULL
        AND source_credential_revision IS NULL
        AND source_token_version IS NULL
        AND source_egress_epoch IS NULL)
    );
