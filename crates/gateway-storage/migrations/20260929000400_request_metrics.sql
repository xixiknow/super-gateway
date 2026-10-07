SET LOCAL ROLE gateway_migrator;

ALTER TABLE telemetry.request_record
    ADD COLUMN client_name text,
    ADD COLUMN client_version text,
    ADD COLUMN request_type text CHECK (request_type IN ('streaming', 'sync', 'websocket')),
    ADD COLUMN first_content_ms bigint CHECK (first_content_ms >= 0),
    ADD COLUMN duration_ms bigint CHECK (duration_ms >= 0);

-- Only retained ingress evidence distinguishes historical WebSocket requests.
UPDATE telemetry.request_record r
SET request_type = CASE WHEN b.original_headers->>'transport' = 'websocket_handshake' THEN 'websocket'
                       WHEN b.original_headers->>'transport' = 'http' THEN
                           CASE r.response_mode_code WHEN 'streaming' THEN 'streaming' WHEN 'non_streaming' THEN 'sync' END
                  END
FROM telemetry.request_body b
WHERE b.request_id = r.request_id AND b.request_month = r.request_month;

WITH clients AS (
    SELECT b.request_month, b.request_id,
           regexp_match(h->>'value', '(claude-cli|claude-code|codex_cli_rs|codex-cli|codex)/([0-9A-Za-z_.+-]{1,80})', 'i') AS product
    FROM telemetry.request_body b,
         LATERAL jsonb_array_elements(b.original_headers->'entries') h
    WHERE lower(h->>'name') = 'user-agent'
)
UPDATE telemetry.request_record r
SET client_name = CASE WHEN lower(c.product[1]) IN ('claude-cli', 'claude-code') THEN 'Claude Code' ELSE 'Codex' END,
    client_version = c.product[2]
FROM clients c
WHERE c.product IS NOT NULL AND c.request_id = r.request_id AND c.request_month = r.request_month;

RESET ROLE;
