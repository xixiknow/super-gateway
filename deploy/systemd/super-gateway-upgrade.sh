#!/usr/bin/env bash
set -euo pipefail

candidate_dir=${1:?candidate release directory is required}
install_root=${2:-/opt/super-gateway}
service_name=${3:-super-gateway.service}
ready_url=${4:-http://127.0.0.1:8081/readyz}
runtime_env=${5:-/etc/super-gateway/runtime.env}
migrate_env=${6:-/etc/super-gateway/migrate.env}

candidate_dir=$(realpath "${candidate_dir}")
install_root=$(realpath "${install_root}")
candidate_bin="${candidate_dir}/super-gatewayd"
candidate_evidence="${candidate_dir}"
current_link="${install_root}/current"
previous_target=$(readlink -f "${current_link}")

test -x "${candidate_bin}"
test -r "${candidate_evidence}/evidence-manifest.json"
test -r "${runtime_env}"
test -r "${migrate_env}"
test -n "${previous_target}"
test -x "${previous_target}/super-gatewayd"
test -r "${previous_target}/release-manifest.json"
python3 "${candidate_dir}/tools/verify_release_evidence.py" "${candidate_evidence}" --profile r10-local
python3 "${candidate_dir}/tools/verify_migration_compatibility.py" \
  --current "${previous_target}/release-manifest.json" \
  --candidate "${candidate_dir}/release-manifest.json" \
  --json-out "${candidate_dir}/migration-compatibility-preflight.json"
(set -a; source "${runtime_env}"; set +a; "${candidate_bin}" --check-config)
(set -a; source "${runtime_env}"; set +a; "${previous_target}/super-gatewayd" check-schema)
(set -a; source "${migrate_env}"; set +a; "${candidate_bin}" migrate)
(set -a; source "${runtime_env}"; set +a; "${candidate_bin}" check-schema)
(set -a; source "${runtime_env}"; set +a; "${previous_target}/super-gatewayd" check-schema)

systemctl stop "${service_name}"
ln -sfn "${candidate_dir}" "${install_root}/.current.next"
mv -Tf "${install_root}/.current.next" "${current_link}"
systemctl start "${service_name}"

deadline=$((SECONDS + 60))
while (( SECONDS < deadline )); do
  if curl --fail --silent --show-error --max-time 2 "${ready_url}" >/dev/null; then
    exit 0
  fi
  sleep 1
done

systemctl stop "${service_name}"
ln -sfn "${previous_target}" "${install_root}/.current.rollback"
mv -Tf "${install_root}/.current.rollback" "${current_link}"
systemctl start "${service_name}"
rollback_deadline=$((SECONDS + 60))
while (( SECONDS < rollback_deadline )); do
  if curl --fail --silent --show-error --max-time 2 "${ready_url}" >/dev/null; then
    echo "candidate readiness failed; rollback restored a ready previous release" >&2
    exit 1
  fi
  sleep 1
done
echo "candidate and rollback readiness both failed" >&2
exit 2
