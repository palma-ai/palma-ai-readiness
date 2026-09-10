#!/usr/bin/env bash
# One-shot local scan. No dependency installation, account state, or reporting service.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
palma_python=""
if [ -n "${PALMA_PYTHON:-}" ]; then
  candidates=("$PALMA_PYTHON")
else
  candidates=(python3 python3.14 python3.13 python3.12 python3.11 python)
fi
for candidate in "${candidates[@]}"; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -I -S -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    palma_python=$(command -v "$candidate")
    break
  fi
done
if [ -z "$palma_python" ]; then
  echo 'Palma needs Python 3.11 or newer. No Python packages are required.' >&2
  echo 'If it is already installed, set PALMA_PYTHON to its executable path.' >&2
  exit 2
fi
exec "$palma_python" -I -S "$here/palma-scan.py" run --open "$@"
