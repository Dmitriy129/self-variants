#!/usr/bin/env bash
# Run real upstream binaries inside an unprivileged, disposable Linux container.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mounts=(--mount "type=bind,source=${project_dir},target=/workspace,readonly")
test_args=()
if [[ $# -gt 1 ]]; then
    echo "Usage: $0 [directory-containing-release-archives]" >&2
    exit 2
fi
if [[ $# -eq 1 ]]; then
    artifact_dir=$(cd -- "$1" && pwd)
    mounts+=(--mount "type=bind,source=${artifact_dir},target=/artifacts,readonly")
    test_args+=(--artifacts-dir /artifacts)
fi
exec docker run --rm --init --platform linux/amd64 \
    "${mounts[@]}" --workdir /workspace \
    --env PYTHONDONTWRITEBYTECODE=1 --env VPN_INSTALLER_INTEGRATION=1 \
    ubuntu:24.04 bash -euc '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -yqq --no-install-recommends python3 openssl nginx ca-certificates >/dev/null
        exec python3 -u tests/integration.py "$@"
    ' integration "${test_args[@]}"
