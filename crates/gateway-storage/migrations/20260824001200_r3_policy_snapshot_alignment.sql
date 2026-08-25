-- Expand-only R3 alignment. Older binaries must tolerate this migration so
-- the rollback binary remains startable during the compatibility window.

ALTER TABLE gateway.group_config
  ADD COLUMN system_prompt_ref text,
  ADD COLUMN system_prompt_content jsonb;

UPDATE gateway.group_config
SET system_prompt_mode_code = 'strip_all'
WHERE system_prompt_mode_code = 'strip';

ALTER TABLE gateway.group_config
  DROP CONSTRAINT group_config_system_prompt_mode_code_check;

ALTER TABLE gateway.group_config
  ADD CONSTRAINT group_config_system_prompt_mode_code_check
  CHECK (system_prompt_mode_code IN ('preserve','strip_client','replace','strip_all')),
  ADD CONSTRAINT group_config_system_prompt_replace_shape_check
  CHECK (
    (system_prompt_mode_code = 'replace'
      AND system_prompt_ref IS NOT NULL
      AND length(btrim(system_prompt_ref)) > 0
      AND system_prompt_content IS NOT NULL)
    OR
    (system_prompt_mode_code <> 'replace'
      AND system_prompt_ref IS NULL
      AND system_prompt_content IS NULL)
  );

COMMENT ON COLUMN gateway.group_config.system_prompt_mode_code IS
  'Frozen Group System policy: preserve, strip_client, replace, or strip_all.';
COMMENT ON COLUMN gateway.group_config.system_prompt_ref IS
  'Stable administrator-visible identity for replacement System content.';
COMMENT ON COLUMN gateway.group_config.system_prompt_content IS
  'Exact JSON string or block array used only when mode is replace.';
