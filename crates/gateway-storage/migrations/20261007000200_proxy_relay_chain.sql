SET LOCAL ROLE gateway_migrator;

-- Relay (upstream) proxy chain: an optional parent proxy used as the first hop
-- when the gateway cannot reach a proxy endpoint directly. Cycle prevention and
-- chain depth are enforced in the control plane, not by table constraints.

ALTER TABLE gateway.proxy_endpoint
  ADD COLUMN upstream_proxy_id uuid REFERENCES gateway.proxy_endpoint(id) ON DELETE RESTRICT,
  ADD CONSTRAINT proxy_endpoint_relay_self_ck CHECK (upstream_proxy_id <> id);

CREATE INDEX proxy_endpoint_upstream_idx
  ON gateway.proxy_endpoint (upstream_proxy_id)
  WHERE upstream_proxy_id IS NOT NULL;

RESET ROLE;
