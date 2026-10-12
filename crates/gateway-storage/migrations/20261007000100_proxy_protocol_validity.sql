SET LOCAL ROLE gateway_migrator;

-- Proxy protocol (HTTP / HTTPS / SOCKS5) and validity window with expiry policy and reminders.

ALTER TABLE gateway.proxy_endpoint
  DROP CONSTRAINT proxy_endpoint_proxy_type_code_check;

ALTER TABLE gateway.proxy_endpoint
  ADD CONSTRAINT proxy_endpoint_proxy_type_code_check
    CHECK (proxy_type_code IN ('http_connect','https_connect','socks5')),
  ADD COLUMN starts_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ADD COLUMN validity_days integer CHECK (validity_days IS NULL OR validity_days BETWEEN 1 AND 3650),
  ADD COLUMN expires_at timestamptz,
  ADD COLUMN expiry_policy_code text NOT NULL DEFAULT 'none'
    CHECK (expiry_policy_code IN ('fallback_direct','switch_proxy','none')),
  ADD COLUMN remind_before_hours integer NOT NULL DEFAULT 72
    CHECK (remind_before_hours BETWEEN 0 AND 8760),
  ADD COLUMN expiry_reminded_at timestamptz,
  ADD COLUMN expired_at timestamptz,
  ADD CONSTRAINT proxy_endpoint_validity_shape_ck CHECK (
    (validity_days IS NULL) = (expires_at IS NULL)
    AND (expires_at IS NULL OR expires_at > starts_at)
  );

UPDATE gateway.proxy_endpoint SET starts_at = created_at;

CREATE INDEX proxy_endpoint_pending_expiry_idx
  ON gateway.proxy_endpoint (expires_at)
  WHERE expired_at IS NULL AND expires_at IS NOT NULL;

RESET ROLE;
