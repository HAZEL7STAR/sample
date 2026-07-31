#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python3"
fi
cd "$ROOT_DIR/backend"
export PYTHONPATH="$ROOT_DIR:$ROOT_DIR/backend"
exec "$PYTHON_BIN" -m uvicorn app.main:app --host 0.0.0.0 --port 8001
