-- Durable, encrypted and one-shot ordinary usage exports.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE ops.export_job
  ADD COLUMN durable_job_id uuid UNIQUE REFERENCES ops.durable_job(id) ON DELETE RESTRICT,
  ADD COLUMN dataset_code text NOT NULL DEFAULT 'usage_requests_v1'
    CHECK (dataset_code = 'usage_requests_v1'),
  ADD COLUMN format_code text NOT NULL DEFAULT 'jsonl'
    CHECK (format_code IN ('jsonl','csv')),
  ADD COLUMN query_sha256 bytea,
  ADD COLUMN row_count bigint CHECK (row_count BETWEEN 0 AND 10000),
  ADD COLUMN content_length bigint CHECK (content_length BETWEEN 0 AND 33554432),
  ADD COLUMN cipher_suite_code text CHECK (cipher_suite_code = 'aes_256_gcm'),
  ADD COLUMN nonce bytea,
  ADD COLUMN wrapped_dek bytea,
  ADD COLUMN key_version bigint CHECK (key_version >= 1),
  ADD COLUMN download_count integer NOT NULL DEFAULT 0 CHECK (download_count BETWEEN 0 AND 1),
  ADD COLUMN downloaded_at timestamptz,
  ADD COLUMN last_error_code text,
  ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1);

UPDATE ops.export_job
SET query_sha256 = decode(repeat('00', 32), 'hex')
WHERE query_sha256 IS NULL;

-- Pre-contract rows have no wrapped DEK or durable generation fence and are
-- therefore not downloadable under the new one-shot security contract.
UPDATE ops.export_job
SET state_code = 'expired',
    object_uri = NULL,
    last_error_code = 'legacy_export_not_recoverable',
    completed_at = COALESCE(completed_at, clock_timestamp()),
    revision = revision + 1
WHERE durable_job_id IS NULL;

ALTER TABLE ops.export_job
  ALTER COLUMN query_sha256 SET NOT NULL,
  ADD CONSTRAINT export_job_query_sha256_ck CHECK (octet_length(query_sha256) = 32),
  ADD CONSTRAINT export_job_content_sha256_ck CHECK (
    content_sha256 IS NULL OR octet_length(content_sha256) = 32
  ),
  ADD CONSTRAINT export_job_nonce_ck CHECK (nonce IS NULL OR octet_length(nonce) = 12),
  ADD CONSTRAINT export_job_artifact_shape_ck CHECK (
    state_code <> 'succeeded' OR (
      durable_job_id IS NOT NULL
      AND object_uri IS NOT NULL
      AND content_sha256 IS NOT NULL
      AND expires_at IS NOT NULL
      AND row_count IS NOT NULL
      AND content_length IS NOT NULL
      AND cipher_suite_code = 'aes_256_gcm'
      AND nonce IS NOT NULL
      AND wrapped_dek IS NOT NULL
      AND key_version IS NOT NULL
      AND download_count = 0
      AND downloaded_at IS NULL
    )
  ),
  ADD CONSTRAINT export_job_download_shape_ck CHECK (
    (download_count = 0 AND downloaded_at IS NULL)
    OR (download_count = 1 AND downloaded_at IS NOT NULL AND state_code = 'expired'
        AND object_uri IS NULL AND nonce IS NULL AND wrapped_dek IS NULL)
  );

CREATE INDEX export_job_requester_created_idx
  ON ops.export_job (requested_by, created_at DESC, id DESC);

CREATE INDEX export_job_expiry_idx
  ON ops.export_job (expires_at)
  WHERE state_code = 'succeeded';

RESET ROLE;
