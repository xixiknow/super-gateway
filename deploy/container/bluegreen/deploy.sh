#!/usr/bin/env bash
set -euo pipefail

version=${1:?usage: deploy.sh RELEASE_VERSION IMAGE_DIGEST}
candidate=${2:?usage: deploy.sh RELEASE_VERSION IMAGE_DIGEST}
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "release version must match vMAJOR.MINOR.PATCH" >&2
  exit 2
fi
case "$candidate" in
  *@sha256:*) ;;
  *) echo "candidate must be an immutable image reference" >&2; exit 2 ;;
esac

compose=(docker compose --env-file runtime.env -f docker-compose.yml)
export GREEN_IMAGE="$candidate"
export GATEWAY_UPDATE_LATEST_VERSION="${version#v}"
echo "staging release $version: $GREEN_IMAGE"
"${compose[@]}" run --rm migrate
"${compose[@]}" up -d gateway_green proxy
"$PWD/switch-color.sh" green
echo "candidate is active; keep gateway_blue running for the observation window"
