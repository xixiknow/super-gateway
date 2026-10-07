-- Keep request reasoning metadata after optional body captures expire.
SET LOCAL ROLE gateway_migrator;

ALTER TABLE telemetry.request_record ADD COLUMN reasoning_effort text;

UPDATE telemetry.request_record r
SET reasoning_effort = COALESCE(
  b.body #>> '{reasoning,effort}', b.body ->> 'reasoning_effort',
  b.body #>> '{output_config,effort}',
  CASE WHEN b.body #>> '{thinking,type}' = 'enabled'
    AND b.body #>> '{thinking,budget_tokens}' IS NOT NULL
    THEN 'budget:' || (b.body #>> '{thinking,budget_tokens}')
    ELSE b.body #>> '{thinking,type}' END)
FROM (
  SELECT request_month, request_id,
    COALESCE(final_upstream_request, policy_request, original_request) AS body
  FROM telemetry.request_body
) b
WHERE r.request_month=b.request_month AND r.request_id=b.request_id;

RESET ROLE;
