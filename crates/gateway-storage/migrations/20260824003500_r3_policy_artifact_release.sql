-- R3 Background Catalog / Group Enforcement publication evidence and runtime binding.

CREATE TABLE catalog.artifact_rollout_evidence (
  artifact_id uuid PRIMARY KEY REFERENCES catalog.versioned_artifact(id) ON DELETE CASCADE,
  validation_report jsonb NOT NULL DEFAULT '{}'::jsonb,
  validated_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  validated_at timestamptz,
  shadow_started_at timestamptz,
  shadow_minimum_until timestamptz,
  deterministic_sample_count integer NOT NULL DEFAULT 0 CHECK (deterministic_sample_count >= 0),
  explicit_match_count integer NOT NULL DEFAULT 0 CHECK (explicit_match_count >= 0),
  suspected_sample_count integer NOT NULL DEFAULT 0 CHECK (suspected_sample_count >= 0),
  risk_acceptance_case_id uuid REFERENCES security.approval_case(id) ON DELETE RESTRICT,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((shadow_started_at IS NULL) = (shadow_minimum_until IS NULL)),
  CHECK (shadow_minimum_until IS NULL OR shadow_minimum_until >= shadow_started_at)
);

ALTER TABLE gateway.group_config
  ADD COLUMN enforcement_artifact_id uuid REFERENCES catalog.versioned_artifact(id) ON DELETE RESTRICT;

-- Existing active Group configs receive a real immutable preserve/strip/replace
-- artifact. Historical inactive configs remain readable and use their frozen
-- legacy columns until explicitly re-published.
UPDATE gateway.group_config config
SET enforcement_artifact_id=pointer.artifact_id
FROM gateway.group_active_config active
JOIN catalog.active_artifact_pointer pointer
  ON pointer.artifact_kind_code='enforcement'
 AND pointer.scope_type_code='group'
 AND pointer.scope_id=active.group_id
WHERE active.config_id=config.id
  AND config.enforcement_artifact_id IS NULL;

WITH active_configs AS (
  SELECT config.id AS config_id, config.group_id, config.config_version, config.created_by,
         config.system_prompt_mode_code, config.system_prompt_ref, config.system_prompt_content,
         md5('r3-enforcement:' || config.id::text)::uuid AS artifact_id,
         jsonb_build_object(
           'name', 'migrated-group-enforcement-v' || config.config_version::text,
           'payload', jsonb_build_object(
             'group_id', config.group_id::text,
             'system', jsonb_strip_nulls(jsonb_build_object(
               'mode', config.system_prompt_mode_code,
               'platform_system_ref', config.system_prompt_ref,
               'content', config.system_prompt_content
             ))
           ),
           'source_refs', jsonb_build_array('migration:20260824003500')
         ) AS envelope,
         COALESCE((
           SELECT max(existing.artifact_version)
           FROM catalog.versioned_artifact existing
           WHERE existing.artifact_kind_code='enforcement'
             AND existing.scope_type_code='group'
             AND existing.scope_id=config.group_id
         ),0)+1 AS artifact_version
  FROM gateway.group_active_config active
  JOIN gateway.group_config config ON config.id=active.config_id
  WHERE config.enforcement_artifact_id IS NULL
)
INSERT INTO catalog.versioned_artifact
  (id,artifact_kind_code,scope_type_code,scope_id,artifact_version,lifecycle_code,payload,content_hash,
   schema_version,created_by,created_at)
SELECT artifact_id,'enforcement','group',group_id,artifact_version,'active',envelope,
       decode(md5(envelope::text) || md5('sha256-width:' || envelope::text),'hex'),1,created_by,clock_timestamp()
FROM active_configs;

WITH migrated AS (
  SELECT config.id AS config_id, config.group_id,
         md5('r3-enforcement:' || config.id::text)::uuid AS artifact_id
  FROM gateway.group_active_config active
  JOIN gateway.group_config config ON config.id=active.config_id
  WHERE config.enforcement_artifact_id IS NULL
)
UPDATE gateway.group_config config
SET enforcement_artifact_id=migrated.artifact_id
FROM migrated
WHERE config.id=migrated.config_id;

INSERT INTO catalog.artifact_rollout_evidence
  (artifact_id,validation_report,validated_at,deterministic_sample_count,revision,updated_at)
SELECT config.enforcement_artifact_id,
       jsonb_build_object('valid',true,'source','migration:20260824003500'),
       clock_timestamp(),0,1,clock_timestamp()
FROM gateway.group_active_config active
JOIN gateway.group_config config ON config.id=active.config_id
WHERE config.enforcement_artifact_id IS NOT NULL
ON CONFLICT (artifact_id) DO NOTHING;

INSERT INTO catalog.active_artifact_pointer
  (id,artifact_kind_code,scope_type_code,scope_id,artifact_id,revision,activated_by,activated_at)
SELECT md5('r3-enforcement-pointer:' || config.group_id::text)::uuid,
       'enforcement','group',config.group_id,config.enforcement_artifact_id,1,config.created_by,clock_timestamp()
FROM gateway.group_active_config active
JOIN gateway.group_config config ON config.id=active.config_id
WHERE config.enforcement_artifact_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM catalog.active_artifact_pointer pointer
    WHERE pointer.artifact_kind_code='enforcement'
      AND pointer.scope_type_code='group'
      AND pointer.scope_id=config.group_id
  );

CREATE OR REPLACE FUNCTION catalog.reject_policy_artifact_content_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.artifact_kind_code IN ('background_catalog','enforcement') AND (
       NEW.artifact_kind_code IS DISTINCT FROM OLD.artifact_kind_code
       OR NEW.scope_type_code IS DISTINCT FROM OLD.scope_type_code
       OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
       OR NEW.artifact_version IS DISTINCT FROM OLD.artifact_version
       OR NEW.payload IS DISTINCT FROM OLD.payload
       OR NEW.object_uri IS DISTINCT FROM OLD.object_uri
       OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
       OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
  ) THEN
    RAISE EXCEPTION 'published policy artifact content is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER policy_artifact_content_immutable
  BEFORE UPDATE ON catalog.versioned_artifact
  FOR EACH ROW EXECUTE FUNCTION catalog.reject_policy_artifact_content_mutation();

CREATE OR REPLACE FUNCTION gateway.reject_group_config_content_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - ARRAY['lifecycle_code','validation_report','validated_at','published_at'])
       IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['lifecycle_code','validation_report','validated_at','published_at']) THEN
    RAISE EXCEPTION 'Group config content is immutable; create a new version' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER group_config_content_immutable
  BEFORE UPDATE ON gateway.group_config
  FOR EACH ROW EXECUTE FUNCTION gateway.reject_group_config_content_mutation();

CREATE OR REPLACE FUNCTION gateway.validate_group_config_enforcement()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE candidate catalog.versioned_artifact%ROWTYPE;
BEGIN
  IF NEW.enforcement_artifact_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT * INTO candidate FROM catalog.versioned_artifact WHERE id = NEW.enforcement_artifact_id;
  IF candidate.id IS NULL
     OR candidate.artifact_kind_code <> 'enforcement'
     OR candidate.scope_type_code <> 'group'
     OR candidate.scope_id IS DISTINCT FROM NEW.group_id
     OR candidate.lifecycle_code <> 'active' THEN
    RAISE EXCEPTION 'group config enforcement artifact mismatch' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE CONSTRAINT TRIGGER group_config_enforcement_matches
  AFTER INSERT OR UPDATE OF enforcement_artifact_id, group_id ON gateway.group_config
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION gateway.validate_group_config_enforcement();

CREATE INDEX artifact_rollout_shadow_due_idx
  ON catalog.artifact_rollout_evidence (shadow_minimum_until)
  WHERE shadow_started_at IS NOT NULL;

CREATE UNIQUE INDEX policy_artifact_one_shadow_uq
  ON catalog.versioned_artifact (artifact_kind_code,scope_type_code,scope_id) NULLS NOT DISTINCT
  WHERE lifecycle_code='shadow' AND artifact_kind_code IN ('background_catalog','enforcement');

CREATE UNIQUE INDEX policy_artifact_one_active_uq
  ON catalog.versioned_artifact (artifact_kind_code,scope_type_code,scope_id) NULLS NOT DISTINCT
  WHERE lifecycle_code='active' AND artifact_kind_code IN ('background_catalog','enforcement');

GRANT SELECT, INSERT, UPDATE, DELETE ON catalog.artifact_rollout_evidence TO gateway_runtime;
GRANT SELECT ON catalog.artifact_rollout_evidence TO gateway_readonly, gateway_backup;
