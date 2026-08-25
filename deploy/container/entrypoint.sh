#!/bin/sh
set -eu

command_name="${1:-serve}"

case "$command_name" in
  serve)
    shift || true
    super-gatewayd --check-config
    super-gatewayd check-schema
    exec super-gatewayd "$@"
    ;;
  migrate | check-schema | --check-config | --version)
    exec super-gatewayd "$@"
    ;;
  super-gatewayd)
    exec "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
