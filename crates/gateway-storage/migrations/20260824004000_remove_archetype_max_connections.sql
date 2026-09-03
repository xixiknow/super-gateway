-- Remove the unused per-Archetype connection limit. Runtime connection isolation is
-- enforced by the signed Bundle pool key; Credential allocation remains bounded by
-- max_credentials.

ALTER TABLE catalog.archetype_capacity_policy
  DROP COLUMN max_connections;
