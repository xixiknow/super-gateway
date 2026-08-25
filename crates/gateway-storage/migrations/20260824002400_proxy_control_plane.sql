-- R5/R9 Proxy control-plane projection and durable full-path probe evidence.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE gateway.proxy_endpoint
  ADD COLUMN name text,
  ADD COLUMN probe_generation bigint NOT NULL DEFAULT 0 CHECK (probe_generation >= 0),
  ADD COLUMN last_success_at timestamptz,
  ADD COLUMN failure_window_started_at timestamptz,
  ADD COLUMN last_error_code text,
  ADD COLUMN drain_deadline_at timestamptz;

UPDATE gateway.proxy_endpoint
SET name = 'proxy-' || left(id::text, 8)
WHERE name IS NULL;

ALTER TABLE gateway.proxy_endpoint
  ALTER COLUMN name SET NOT NULL,
  ADD CONSTRAINT proxy_endpoint_name_uq UNIQUE (name),
  ADD CONSTRAINT proxy_endpoint_drain_shape_ck CHECK (
    (lifecycle_code = 'draining') = (drain_deadline_at IS NOT NULL)
  );

CREATE TABLE gateway.proxy_probe_observation (
  id uuid PRIMARY KEY,
  proxy_id uuid NOT NULL REFERENCES gateway.proxy_endpoint(id) ON DELETE RESTRICT,
  durable_job_id uuid NOT NULL UNIQUE REFERENCES ops.durable_job(id) ON DELETE RESTRICT,
  probe_generation bigint NOT NULL CHECK (probe_generation >= 1),
  result_code text NOT NULL CHECK (result_code IN (
    'healthy','dns_failed','connect_failed','auth_failed','tunnel_failed',
    'tls_intercepted','egress_mismatch','cancelled'
  )),
  latency_ms integer CHECK (latency_ms >= 0),
  observed_egress_ip inet,
  negotiated_alpn text CHECK (negotiated_alpn IS NULL OR negotiated_alpn IN ('h1','h2')),
  certificate_sha256 bytea CHECK (certificate_sha256 IS NULL OR octet_length(certificate_sha256)=32),
  redacted_detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at timestamptz NOT NULL,
  UNIQUE (proxy_id, probe_generation)
);

CREATE INDEX proxy_probe_observation_proxy_time_idx
  ON gateway.proxy_probe_observation (proxy_id, observed_at DESC);

RESET ROLE;
