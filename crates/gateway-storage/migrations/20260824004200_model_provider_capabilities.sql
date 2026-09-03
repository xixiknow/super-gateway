ALTER TABLE catalog.model_discovery_observation
  ADD COLUMN max_input_tokens bigint CHECK (max_input_tokens IS NULL OR max_input_tokens > 0),
  ADD COLUMN max_output_tokens bigint CHECK (max_output_tokens IS NULL OR max_output_tokens > 0),
  ADD COLUMN provider_capabilities jsonb
    CHECK (provider_capabilities IS NULL OR jsonb_typeof(provider_capabilities) = 'object');
