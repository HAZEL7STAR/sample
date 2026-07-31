#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
printf 'Installation complete. Start the backend with: \n  source .venv/bin/activate && cd backend && uvicorn app.main:app --reload --port 8000\n'
