-- RuleSet artifact immutability and active-config scope fences.

SET LOCAL ROLE gateway_migrator;

CREATE OR REPLACE FUNCTION catalog.reject_versioned_artifact_content_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.artifact_kind_code IS DISTINCT FROM OLD.artifact_kind_code
     OR NEW.scope_type_code IS DISTINCT FROM OLD.scope_type_code
     OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
     OR NEW.artifact_version IS DISTINCT FROM OLD.artifact_version
     OR NEW.payload IS DISTINCT FROM OLD.payload
     OR NEW.object_uri IS DISTINCT FROM OLD.object_uri
     OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
     OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
     OR NEW.evidence_set_id IS DISTINCT FROM OLD.evidence_set_id
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'versioned artifact content is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER versioned_artifact_content_immutable
  BEFORE UPDATE ON catalog.versioned_artifact
  FOR EACH ROW EXECUTE FUNCTION catalog.reject_versioned_artifact_content_mutation();

CREATE OR REPLACE FUNCTION gateway.validate_active_group_ruleset()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE candidate catalog.versioned_artifact%ROWTYPE;
DECLARE ruleset_id uuid;
BEGIN
  SELECT ruleset_artifact_id INTO ruleset_id
  FROM gateway.group_config
  WHERE id=NEW.config_id AND group_id=NEW.group_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active Group config target mismatch' USING ERRCODE='23514';
  END IF;
  IF ruleset_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT * INTO candidate FROM catalog.versioned_artifact WHERE id=ruleset_id;
  IF candidate.id IS NULL OR candidate.artifact_kind_code<>'ruleset'
     OR candidate.scope_type_code<>'group' OR candidate.scope_id IS DISTINCT FROM NEW.group_id
     OR candidate.lifecycle_code<>'active' THEN
    RAISE EXCEPTION 'active Group config RuleSet mismatch' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

CREATE CONSTRAINT TRIGGER group_active_config_ruleset_matches
  AFTER INSERT OR UPDATE ON gateway.group_active_config DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION gateway.validate_active_group_ruleset();

CREATE OR REPLACE FUNCTION iam.validate_active_platform_key_ruleset()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE candidate catalog.versioned_artifact%ROWTYPE;
DECLARE ruleset_id uuid;
BEGIN
  SELECT ruleset_artifact_id INTO ruleset_id
  FROM iam.platform_key_config
  WHERE id=NEW.config_id AND platform_key_id=NEW.platform_key_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active Platform Key config target mismatch' USING ERRCODE='23514';
  END IF;
  IF ruleset_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT * INTO candidate FROM catalog.versioned_artifact WHERE id=ruleset_id;
  IF candidate.id IS NULL OR candidate.artifact_kind_code<>'ruleset'
     OR candidate.scope_type_code<>'platform_key' OR candidate.scope_id IS DISTINCT FROM NEW.platform_key_id
     OR candidate.lifecycle_code<>'active' THEN
    RAISE EXCEPTION 'active Platform Key config RuleSet mismatch' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

CREATE CONSTRAINT TRIGGER platform_key_active_config_ruleset_matches
  AFTER INSERT OR UPDATE ON iam.platform_key_active_config DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION iam.validate_active_platform_key_ruleset();

RESET ROLE;
