-- Lease renewal updates owner_lease_expires_at every few seconds. This index
-- is not used by claim or heartbeat (both address the group by primary key),
-- and indexing the renewed column disables HOT updates, so each heartbeat
-- dirties an index page and bloats the group row under concurrency.
DO $$
DECLARE
  index_schema text;
BEGIN
  SELECT n.nspname INTO index_schema
  FROM pg_class i
  JOIN pg_namespace n ON n.oid = i.relnamespace
  JOIN pg_index ix ON ix.indexrelid = i.oid
  JOIN pg_class t ON t.oid = ix.indrelid
  JOIN pg_namespace tn ON tn.oid = t.relnamespace
  WHERE i.relkind = 'i'
    AND i.relname = 'credential_group_owner_lease_idx'
    AND tn.nspname = 'gateway'
    AND t.relname = 'credential_group';
  IF index_schema IS NOT NULL THEN
    EXECUTE format('DROP INDEX %I.%I', index_schema, 'credential_group_owner_lease_idx');
  END IF;
END $$;
