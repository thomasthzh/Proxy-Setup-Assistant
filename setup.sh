#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'Python 3.10+ is required. Install it with your operating system package manager.' >&2
  exit 1
fi
python3 -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"'
exec python3 -m vps_proxy_setup "$@"
