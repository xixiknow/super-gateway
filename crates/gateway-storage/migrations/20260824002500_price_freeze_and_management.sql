-- Freeze price selection at request acceptance and persist immutable price-version metadata.

SET LOCAL ROLE gateway_migrator;

CREATE TABLE catalog.price_version (
  price_version bigint PRIMARY KEY CHECK (price_version >= 1),
  currency_code text NOT NULL CHECK (currency_code = 'USD'),
  effective_from timestamptz NOT NULL,
  effective_to timestamptz,
  source_uri text,
  content_hash bytea NOT NULL UNIQUE CHECK (octet_length(content_hash) = 32),
  created_by uuid REFERENCES iam.user_account(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL,
  CHECK (effective_to IS NULL OR effective_to > effective_from)
);

ALTER TABLE telemetry.request_record
  ADD COLUMN price_entry_id uuid REFERENCES catalog.price_entry(id) ON DELETE RESTRICT;

CREATE INDEX request_record_price_entry_idx
  ON telemetry.request_record (price_entry_id) WHERE price_entry_id IS NOT NULL;

RESET ROLE;
