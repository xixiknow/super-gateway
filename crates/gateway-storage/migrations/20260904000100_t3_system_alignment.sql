-- T3.3 captured System templates, environment alignment and final upstream body evidence.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE catalog.environment_archetype_version
  ADD COLUMN shell text,
  ADD COLUMN system_template jsonb,
  ADD CONSTRAINT environment_archetype_version_shell_check
    CHECK (shell IS NULL OR (
      length(btrim(shell)) BETWEEN 1 AND 256
      AND position(chr(10) IN shell) = 0
      AND position(chr(13) IN shell) = 0
    )),
  ADD CONSTRAINT environment_archetype_version_system_template_check
    CHECK (system_template IS NULL OR jsonb_typeof(system_template) IN ('string','array'));

ALTER TABLE telemetry.request_record
  ADD COLUMN upstream_body_digest bytea,
  ADD CONSTRAINT request_record_upstream_body_digest_check
    CHECK (upstream_body_digest IS NULL OR octet_length(upstream_body_digest) = 32);

RESET ROLE;
