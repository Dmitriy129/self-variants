#!/usr/bin/env bash
set -euo pipefail
umask 077
PROJECT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  echo 'Нужен Python 3 (входит в обычную установку Ubuntu 24.04).' >&2
  exit 1
fi
export PYTHONPATH="$PROJECT_DIR${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m vpn_installer.cli "$@"
