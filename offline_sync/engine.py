from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("usbguard.sync")


class OfflineSyncQueue:
    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    table_name TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_error TEXT,
                    synced INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sync_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    status TEXT NOT NULL,
                    records_synced INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    timestamp TEXT NOT NULL
                )
                """
            )
            self._ensure_column(conn, "offline_queue", "last_error", "TEXT")
            conn.commit()
        finally:
            conn.close()

    def _ensure_column(self, conn: sqlite3.Connection, table_name: str, column_name: str, column_type: str) -> None:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info('{table_name}')")}
        if column_name not in existing:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")

    def enqueue(self, table_name: str, payload: dict[str, Any]) -> int:
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO offline_queue (table_name, payload_json, attempts, created_at, synced)
                    VALUES (?, ?, 0, ?, 0)
                    """,
                    (table_name, json.dumps(payload), time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())),
                )
                conn.commit()
                return int(cursor.lastrowid)
            finally:
                conn.close()

    def list_pending(self) -> list[dict[str, Any]]:
        conn = sqlite3.connect(str(self.db_path))
        try:
            rows = conn.execute(
                "SELECT id, table_name, payload_json, attempts, created_at, last_error, synced FROM offline_queue WHERE synced = 0 ORDER BY id"
            ).fetchall()
        finally:
            conn.close()

        return [
            {
                "id": row[0],
                "table_name": row[1],
                "payload_json": json.loads(row[2]),
                "attempts": row[3],
                "created_at": row[4],
                "last_error": row[5],
                "synced": row[6],
            }
            for row in rows
        ]

    def flush(self) -> int:
        pending = self.list_pending()
        if not pending:
            return 0

        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                for item in pending:
                    conn.execute(
                        "UPDATE offline_queue SET synced = 1, attempts = attempts + 1 WHERE id = ?",
                        (item["id"],),
                    )
                conn.commit()
            finally:
                conn.close()

        self._log("completed", len(pending), None)
        return len(pending)

    def _log(self, status: str, records_synced: int, error: Optional[str]) -> None:
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                "INSERT INTO sync_logs (status, records_synced, error, timestamp) VALUES (?, ?, ?, ?)",
                (status, records_synced, error, time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())),
            )
            conn.commit()
        finally:
            conn.close()

    def get_logs(self) -> list[dict[str, Any]]:
        conn = sqlite3.connect(str(self.db_path))
        try:
            rows = conn.execute("SELECT id, status, records_synced, error, timestamp FROM sync_logs ORDER BY id DESC").fetchall()
        finally:
            conn.close()

        return [
            {
                "id": row[0],
                "status": row[1],
                "records_synced": row[2],
                "error": row[3],
                "timestamp": row[4],
            }
            for row in rows
        ]
