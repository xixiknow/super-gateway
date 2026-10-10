#!/usr/bin/env bash
set -euo pipefail

color=${1:?usage: switch-color.sh blue|green}
case "$color" in blue|green) ;; *) echo "color must be blue or green" >&2; exit 2 ;; esac

compose=(docker compose --env-file runtime.env -f docker-compose.yml)
service="gateway_${color}"
"${compose[@]}" up -d "$service"
for _ in {1..30}; do
  if "${compose[@]}" exec -T "$service" curl --fail --silent --show-error http://127.0.0.1:8080/readyz >/dev/null; then
    break
  fi
  sleep 2
done
"${compose[@]}" exec -T "$service" curl --fail --silent --show-error http://127.0.0.1:8080/readyz >/dev/null

other=blue
[[ "$color" == blue ]] && other=green
sed -i "s/server gateway_${other}:8080;/server gateway_${other}:8080 down;/; s/server gateway_${color}:8080 down;/server gateway_${color}:8080;/" nginx.conf
sed -i "s/server gateway_${other}:8081;/server gateway_${other}:8081 down;/; s/server gateway_${color}:8081 down;/server gateway_${color}:8081;/" nginx.conf
"${compose[@]}" exec -T proxy nginx -t
"${compose[@]}" exec -T proxy nginx -s reload
echo "active color: $color"
