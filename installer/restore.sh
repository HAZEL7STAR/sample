#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
BACKUP_DIR="${ROOT_DIR}/temp/backup"
if [[ -f "$BACKUP_DIR/offline_cache.db" ]]; then
  cp "$BACKUP_DIR/offline_cache.db" "$ROOT_DIR/offline_cache.db"
fi
if [[ -f "$BACKUP_DIR/backend_offline_cache.db" ]]; then
  cp "$BACKUP_DIR/backend_offline_cache.db" "$ROOT_DIR/backend/offline_cache.db"
fi
printf 'Restore completed.\n'
