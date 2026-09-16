-- T5.1: LiteLLM price synchronisation state.
SET LOCAL ROLE gateway_migrator;

CREATE TABLE ops.price_sync_state (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  last_started_at timestamptz,
  last_completed_at timestamptz,
  state_code text NOT NULL DEFAULT 'never' CHECK (state_code IN ('never','running','succeeded','failed')),
  result_code text,
  source_uri text,
  source_hash bytea CHECK (source_hash IS NULL OR octet_length(source_hash) = 32),
  created_price_version bigint,
  mapped_count integer NOT NULL DEFAULT 0 CHECK (mapped_count >= 0),
  missing_models jsonb NOT NULL DEFAULT '[]'::jsonb,
  error_code text,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO ops.price_sync_state (id,source_uri) VALUES (true,'https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json')
ON CONFLICT (id) DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON ops.price_sync_state TO gateway_runtime;
GRANT SELECT ON ops.price_sync_state TO gateway_readonly;
GRANT SELECT ON ops.price_sync_state TO gateway_backup;
GRANT SELECT, INSERT, UPDATE ON catalog.price_version, catalog.price_entry TO gateway_runtime;
GRANT SELECT ON catalog.price_version, catalog.price_entry TO gateway_readonly;
GRANT SELECT ON catalog.price_version, catalog.price_entry TO gateway_backup;

RESET ROLE;
