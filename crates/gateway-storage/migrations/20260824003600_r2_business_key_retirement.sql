-- R2 Business Key retirement invariants. Forward-only and compatible with the
-- database provider introduced by the foundation migration.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE security.business_key_material
  DROP CONSTRAINT business_key_material_check,
  ADD CONSTRAINT business_key_material_provider_material_shape_ck CHECK (
    (key_material IS NOT NULL)
    = (provider_code = 'database' AND state_code <> 'destroyed')
  );

UPDATE security.business_key_material
SET retired_at = COALESCE(retired_at,destroyed_at,activated_at,created_at)
WHERE state_code IN ('retired','destroyed') AND retired_at IS NULL;

UPDATE security.business_key_material
SET retired_at = NULL
WHERE state_code IN ('active','decrypt_only') AND retired_at IS NOT NULL;

ALTER TABLE security.business_key_material
  ADD CONSTRAINT business_key_material_retired_at_shape_ck CHECK (
    (state_code IN ('retired','destroyed')) = (retired_at IS NOT NULL)
  );

CREATE TRIGGER business_key_material_no_delete
  BEFORE DELETE ON security.business_key_material
  FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_mutation();

CREATE OR REPLACE FUNCTION security.guard_encrypted_secret_business_key_reference()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.provider_role_code <> 'business'
     OR (TG_OP = 'UPDATE'
         AND NEW.provider_role_code IS NOT DISTINCT FROM OLD.provider_role_code
         AND NEW.key_version IS NOT DISTINCT FROM OLD.key_version) THEN
    RETURN NEW;
  END IF;
  PERFORM 1 FROM security.business_key_material
   WHERE key_version=NEW.key_version AND provider_code='database' AND state_code='active'
   FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'business key version is not active' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER encrypted_secret_business_key_reference_guard
  BEFORE INSERT OR UPDATE OF provider_role_code,key_version ON security.encrypted_secret
  FOR EACH ROW EXECUTE FUNCTION security.guard_encrypted_secret_business_key_reference();

CREATE OR REPLACE FUNCTION security.guard_export_job_business_key_reference()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.key_version IS NULL OR NEW.wrapped_dek IS NULL
     OR (TG_OP = 'UPDATE'
         AND NEW.key_version IS NOT DISTINCT FROM OLD.key_version
         AND OLD.wrapped_dek IS NOT NULL) THEN
    RETURN NEW;
  END IF;
  PERFORM 1 FROM security.business_key_material
   WHERE key_version=NEW.key_version AND provider_code='database' AND state_code='active'
   FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'business key version is not active' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER export_job_business_key_reference_guard
  BEFORE INSERT OR UPDATE OF key_version,wrapped_dek ON ops.export_job
  FOR EACH ROW EXECUTE FUNCTION security.guard_export_job_business_key_reference();

REVOKE DELETE,TRUNCATE ON security.business_key_material FROM gateway_runtime;

RESET ROLE;
