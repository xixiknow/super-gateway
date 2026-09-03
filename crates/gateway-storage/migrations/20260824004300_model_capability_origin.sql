ALTER TABLE catalog.model_capability
  ADD COLUMN origin_code text NOT NULL DEFAULT 'manual'
    CHECK (origin_code IN ('manual', 'system_discovery')),
  ADD COLUMN source_discovery_run_id uuid
    REFERENCES catalog.model_discovery_run(id) ON DELETE RESTRICT;

ALTER TABLE catalog.model_capability
  ADD CONSTRAINT model_capability_origin_consistency_check
    CHECK (
      (origin_code = 'manual' AND source_discovery_run_id IS NULL)
      OR
      (origin_code = 'system_discovery' AND source_discovery_run_id IS NOT NULL)
    );
