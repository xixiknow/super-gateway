-- T4.2 client OS resolution, per-OS Credential profiles and dispatch evidence.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE gateway.group_config
  ADD COLUMN default_os_family text NOT NULL DEFAULT 'windows',
  ADD CONSTRAINT group_config_default_os_family_check
    CHECK (default_os_family IN ('windows','macos','linux'));

ALTER TABLE gateway.credential_enrollment
  ADD COLUMN os_family_code text NOT NULL DEFAULT 'windows',
  ADD CONSTRAINT credential_enrollment_os_family_check
    CHECK (os_family_code IN ('windows','macos','linux'));

ALTER TABLE telemetry.request_record
  ADD COLUMN client_os_family text,
  ADD COLUMN os_resolution_code text,
  ADD COLUMN os_mismatch boolean NOT NULL DEFAULT false,
  ADD COLUMN unknown_os boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT request_record_client_os_family_check
    CHECK (client_os_family IS NULL OR client_os_family IN ('windows','macos','linux')),
  ADD CONSTRAINT request_record_os_resolution_code_check
    CHECK (os_resolution_code IS NULL OR os_resolution_code IN ('header','environment_only','session_sticky','group_default'));

ALTER TABLE gateway.credential_egress_binding
  ADD COLUMN os_family_code text NOT NULL DEFAULT 'windows',
  ADD CONSTRAINT credential_egress_binding_os_family_check
    CHECK (os_family_code IN ('windows','macos','linux')),
  DROP CONSTRAINT IF EXISTS credential_egress_binding_credential_id_key,
  ADD CONSTRAINT credential_egress_binding_credential_os_uq UNIQUE (credential_id,os_family_code);

ALTER TABLE gateway.device_identity
  ADD COLUMN os_family_code text NOT NULL DEFAULT 'windows',
  ADD CONSTRAINT device_identity_os_family_check
    CHECK (os_family_code IN ('windows','macos','linux')),
  DROP CONSTRAINT IF EXISTS device_identity_credential_id_key,
  ADD CONSTRAINT device_identity_credential_os_uq UNIQUE (credential_id,os_family_code);

ALTER TABLE gateway.credential_profile
  ADD COLUMN os_family_code text NOT NULL DEFAULT 'windows',
  ADD CONSTRAINT credential_profile_os_family_check
    CHECK (os_family_code IN ('windows','macos','linux')),
  DROP CONSTRAINT IF EXISTS credential_profile_credential_id_key,
  DROP CONSTRAINT IF EXISTS credential_profile_device_identity_id_key,
  DROP CONSTRAINT IF EXISTS credential_profile_egress_binding_id_key,
  ADD CONSTRAINT credential_profile_credential_os_uq UNIQUE (credential_id,os_family_code),
  ADD CONSTRAINT credential_profile_device_os_uq UNIQUE (device_identity_id,os_family_code),
  ADD CONSTRAINT credential_profile_egress_os_uq UNIQUE (egress_binding_id,os_family_code);

ALTER TABLE gateway.credential_profile_change
  ADD COLUMN os_family_code text NOT NULL DEFAULT 'windows',
  ADD CONSTRAINT credential_profile_change_os_family_check
    CHECK (os_family_code IN ('windows','macos','linux'));

CREATE OR REPLACE FUNCTION gateway.validate_profile_components() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  device_credential uuid;
  egress_credential uuid;
  device_os text;
  egress_os text;
  archetype_os text;
BEGIN
  SELECT credential_id,os_family_code INTO device_credential,device_os
    FROM gateway.device_identity WHERE id = NEW.device_identity_id;
  SELECT credential_id,os_family_code INTO egress_credential,egress_os
    FROM gateway.credential_egress_binding WHERE id = NEW.egress_binding_id;
  SELECT root.os_family_code INTO archetype_os
    FROM catalog.environment_archetype_version version
    JOIN catalog.environment_archetype root ON root.id=version.archetype_id
    WHERE version.id=NEW.archetype_version_id;
  IF device_credential IS DISTINCT FROM NEW.credential_id
     OR egress_credential IS DISTINCT FROM NEW.credential_id
     OR device_os IS DISTINCT FROM NEW.os_family_code
     OR egress_os IS DISTINCT FROM NEW.os_family_code
     OR archetype_os IS DISTINCT FROM NEW.os_family_code THEN
    RAISE EXCEPTION 'credential profile components must share one credential and OS family' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

RESET ROLE;
