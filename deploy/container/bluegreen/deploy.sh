#!/usr/bin/env bash
set -euo pipefail

candidate=${1:?usage: deploy.sh IMAGE_DIGEST}
case "$candidate" in
  *@sha256:*) ;;
  *) echo "candidate must be an immutable image reference" >&2; exit 2 ;;
esac

compose=(docker compose --env-file runtime.env -f docker-compose.yml)
export GREEN_IMAGE="$candidate"
echo "staging candidate: $GREEN_IMAGE"
"${compose[@]}" run --rm migrate
"${compose[@]}" up -d gateway_green proxy
"$PWD/switch-color.sh" green
echo "candidate is active; keep gateway_blue running for the observation window"
