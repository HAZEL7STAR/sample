#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
BACKUP_DIR="${ROOT_DIR}/temp/backup"
mkdir -p "$BACKUP_DIR"
cp "$ROOT_DIR/offline_cache.db" "$BACKUP_DIR/offline_cache.db" 2>/dev/null || true
cp "$ROOT_DIR/backend/offline_cache.db" "$BACKUP_DIR/backend_offline_cache.db" 2>/dev/null || true
printf 'Backup created in %s\n' "$BACKUP_DIR"
