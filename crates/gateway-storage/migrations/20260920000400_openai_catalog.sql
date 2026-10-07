SET LOCAL ROLE gateway_migrator;
ALTER TABLE catalog.model_definition DROP CONSTRAINT model_definition_upstream_model_id_key;
ALTER TABLE catalog.model_definition ADD CONSTRAINT model_definition_provider_model_key UNIQUE(provider_code,upstream_model_id);
ALTER TABLE catalog.model_definition ADD COLUMN openai_metadata jsonb;
RESET ROLE;
