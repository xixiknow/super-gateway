-- R6 transport Bundle, pool isolation and monotonic event contract alignment.

ALTER TABLE catalog.transport_bundle
  ADD COLUMN source_archetype_version_id uuid REFERENCES catalog.environment_archetype_version(id) ON DELETE RESTRICT,
  ADD COLUMN capture_cohort text,
  ADD COLUMN protocol_code text CHECK (protocol_code IN ('h1','h2')),
  ADD COLUMN backend_id text,
  ADD COLUMN canonicalization_algorithm text NOT NULL DEFAULT 'jcs_rfc8785'
    CHECK (canonicalization_algorithm = 'jcs_rfc8785'),
  ADD COLUMN signature_domain text NOT NULL DEFAULT 'transport_bundle_v1'
    CHECK (signature_domain = 'transport_bundle_v1'),
  ADD COLUMN signature_algorithm text NOT NULL DEFAULT 'ed25519'
    CHECK (signature_algorithm = 'ed25519'),
  ADD COLUMN evidence_gate_code text NOT NULL DEFAULT 'pending'
    CHECK (evidence_gate_code IN ('pending','passed','failed')),
  ADD COLUMN runtime_state_code text NOT NULL DEFAULT 'loadable'
    CHECK (runtime_state_code IN ('loadable','quarantined')),
  ADD COLUMN min_engine_build text,
  ADD COLUMN max_engine_build text,
  ADD COLUMN engine_activation_generation bigint NOT NULL DEFAULT 1
    CHECK (engine_activation_generation >= 1);

UPDATE catalog.transport_bundle
SET source_archetype_version_id = COALESCE(
      NULLIF(manifest #>> '{payload,source_archetype_version_id}', '')::uuid,
      NULLIF(manifest ->> 'source_archetype_version_id', '')::uuid
    ),
    capture_cohort = COALESCE(manifest #>> '{payload,capture_cohort}', manifest ->> 'capture_cohort'),
    protocol_code = COALESCE(manifest #>> '{payload,application,protocol}', manifest #>> '{application,protocol}'),
    backend_id = COALESCE(manifest #>> '{payload,backend_id}', manifest ->> 'backend_id'),
    evidence_gate_code = COALESCE(manifest #>> '{payload,evidence_gate}', manifest ->> 'evidence_gate', 'pending'),
    runtime_state_code = CASE WHEN lifecycle_code = 'quarantined' THEN 'quarantined'
                              ELSE COALESCE(manifest #>> '{payload,runtime_state}', manifest ->> 'runtime_state', 'loadable') END,
    min_engine_build = COALESCE(manifest #>> '{payload,min_engine_build}', manifest ->> 'min_engine_build'),
    max_engine_build = COALESCE(manifest #>> '{payload,max_engine_build}', manifest ->> 'max_engine_build');

UPDATE catalog.transport_bundle
SET lifecycle_code = 'retired'
WHERE lifecycle_code = 'quarantined';

ALTER TABLE catalog.transport_bundle
  DROP CONSTRAINT IF EXISTS transport_bundle_lifecycle_code_check,
  ADD CONSTRAINT transport_bundle_lifecycle_code_check
    CHECK (lifecycle_code IN ('draft','verified','canary','active','retired')),
  ADD CONSTRAINT transport_bundle_activation_fields_ck CHECK (
    lifecycle_code = 'draft' OR (
      source_archetype_version_id IS NOT NULL AND capture_cohort IS NOT NULL AND
      protocol_code IS NOT NULL AND backend_id IS NOT NULL AND min_engine_build IS NOT NULL
    )
  ),
  ADD CONSTRAINT transport_bundle_engine_range_ck CHECK (
    max_engine_build IS NULL OR min_engine_build IS NULL OR max_engine_build >= min_engine_build
  );

ALTER TABLE catalog.archetype_bundle_binding
  ADD COLUMN protocol_code text CHECK (protocol_code IN ('h1','h2'));

UPDATE catalog.archetype_bundle_binding binding
SET protocol_code = bundle.protocol_code
FROM catalog.transport_bundle bundle
WHERE bundle.id = binding.transport_bundle_id;

ALTER TABLE catalog.archetype_bundle_binding
  ALTER COLUMN protocol_code SET NOT NULL,
  ADD CONSTRAINT archetype_bundle_one_owner_uq UNIQUE (transport_bundle_id);

DROP INDEX IF EXISTS catalog.archetype_one_active_bundle_uq;
CREATE UNIQUE INDEX archetype_one_active_bundle_protocol_uq
  ON catalog.archetype_bundle_binding (archetype_version_id, protocol_code)
  WHERE state_code = 'active';

ALTER TABLE telemetry.connection_attempt_record
  DROP CONSTRAINT IF EXISTS connection_attempt_record_state_code_check,
  ADD CONSTRAINT connection_attempt_record_state_code_check CHECK (state_code IN (
    'planned','pool_lookup','resolving','tcp_connecting','proxy_tunneling','tls_handshaking',
    'alpn_negotiating','protocol_ready','promoted_on_first_byte','failed_before_first_byte',
    'cancelled_before_first_byte'
  )),
  ADD COLUMN bundle_version bigint CHECK (bundle_version >= 1),
  ADD COLUMN bundle_hash bytea,
  ADD COLUMN authority text,
  ADD COLUMN sni text,
  ADD COLUMN protocol_code text CHECK (protocol_code IN ('h1','h2')),
  ADD COLUMN proxy_endpoint_id uuid REFERENCES gateway.proxy_endpoint(id) ON DELETE RESTRICT,
  ADD COLUMN pool_key_digest bytea,
  ADD COLUMN activation_generation bigint CHECK (activation_generation >= 1),
  ADD COLUMN connection_disposition_code text CHECK (connection_disposition_code IN (
    'reusable','evict','reset_stream','drain_connection','close_connection'
  )),
  ADD COLUMN health_effect_code text;

ALTER TABLE telemetry.attempt_record
  DROP CONSTRAINT IF EXISTS attempt_record_reason_code_check,
  DROP CONSTRAINT IF EXISTS attempt_record_state_code_check,
  ADD CONSTRAINT attempt_record_reason_code_check CHECK (reason_code IN (
    'initial','oauth_refresh_replay','network_retry','rate_limit_retry','overload_retry','credential_switch'
  )),
  ADD CONSTRAINT attempt_record_state_code_check CHECK (state_code IN (
    'planned','submitting','receiving','completed','failed','cancelled'
  ));

ALTER TABLE telemetry.transport_event
  ALTER COLUMN attempt_id DROP NOT NULL,
  ADD COLUMN connection_attempt_id uuid REFERENCES telemetry.connection_attempt_record(id) ON DELETE CASCADE,
  ADD COLUMN transport_seq bigint CHECK (transport_seq >= 1),
  ADD COLUMN monotonic_ns bigint CHECK (monotonic_ns >= 0),
  ADD COLUMN connection_id_digest bytea,
  ADD COLUMN request_bytes_written bigint NOT NULL DEFAULT 0 CHECK (request_bytes_written >= 0),
  ADD COLUMN response_bytes_read bigint NOT NULL DEFAULT 0 CHECK (response_bytes_read >= 0),
  ADD COLUMN upstream_submission_complete boolean NOT NULL DEFAULT false,
  ADD COLUMN connection_disposition_code text CHECK (connection_disposition_code IN (
    'reusable','evict','reset_stream','drain_connection','close_connection'
  )),
  ADD COLUMN diagnostic_code text,
  ADD CONSTRAINT transport_event_parent_ck CHECK (attempt_id IS NOT NULL OR connection_attempt_id IS NOT NULL);

CREATE UNIQUE INDEX transport_event_connection_seq_uq
  ON telemetry.transport_event (connection_attempt_id, transport_seq)
  WHERE connection_attempt_id IS NOT NULL;

CREATE INDEX transport_bundle_runtime_idx
  ON catalog.transport_bundle (runtime_state_code, lifecycle_code, protocol_code);
