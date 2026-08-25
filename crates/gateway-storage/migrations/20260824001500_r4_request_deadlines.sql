-- R4 request-scoped deadline configuration. These values are frozen from the
-- active Group config when a request enters the production dispatcher.

SET LOCAL ROLE gateway_migrator;

ALTER TABLE gateway.group_config
  ADD COLUMN upstream_connect_ms bigint NOT NULL DEFAULT 5000
    CHECK (upstream_connect_ms BETWEEN 1000 AND 30000),
  ADD COLUMN upstream_non_stream_total_ms bigint NOT NULL DEFAULT 300000
    CHECK (upstream_non_stream_total_ms BETWEEN 5000 AND 3600000),
  ADD COLUMN upstream_stream_idle_ms bigint NOT NULL DEFAULT 30000
    CHECK (upstream_stream_idle_ms BETWEEN 5000 AND 600000),
  ADD COLUMN min_retry_budget_ms bigint NOT NULL DEFAULT 5000
    CHECK (min_retry_budget_ms BETWEEN 1 AND 60000),
  ADD COLUMN cancel_grace_ms bigint NOT NULL DEFAULT 2000
    CHECK (cancel_grace_ms BETWEEN 100 AND 30000),
  ADD COLUMN queue_full_retry_after_ms bigint NOT NULL DEFAULT 2000
    CHECK (queue_full_retry_after_ms BETWEEN 1000 AND 60000),
  ADD COLUMN queue_wait_retry_after_ms bigint NOT NULL DEFAULT 5000
    CHECK (queue_wait_retry_after_ms BETWEEN 1000 AND 60000),
  ADD CONSTRAINT group_config_retry_budget_within_upstream_ck
    CHECK (min_retry_budget_ms <= upstream_non_stream_total_ms);

COMMENT ON COLUMN gateway.group_config.upstream_non_stream_total_ms IS
  'One absolute non-stream upstream budget shared by every Messages attempt; starts at the first upstream request byte.';
COMMENT ON COLUMN gateway.group_config.upstream_stream_idle_ms IS
  'Mandatory streaming upstream idle timeout; it is not a total stream lifetime.';
COMMENT ON COLUMN gateway.group_config.min_retry_budget_ms IS
  'A new Messages attempt is forbidden when less than this request-scoped upstream budget remains.';

RESET ROLE;
