from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, List, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from logger import configure_logging, log_activity


configure_logging()
log = logging.getLogger("usbguard.file_monitor")


class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, engine: "FileMonitorEngine") -> None:
        self.engine = engine

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        self.engine.record_event("created", event.src_path, None)

    def on_deleted(self, event) -> None:
        if event.is_directory:
            return
        self.engine.record_event("deleted", event.src_path, None)

    def on_modified(self, event) -> None:
        if event.is_directory:
            return
        self.engine.record_event("modified", event.src_path, None)

    def on_moved(self, event) -> None:
        if event.is_directory:
            return
        self.engine.record_event("moved", event.src_path, event.dest_path)


class FileMonitorEngine:
    def __init__(self, db_path: str | os.PathLike[str], watch_roots: Optional[Iterable[str | os.PathLike[str]]] = None) -> None:
        self.db_path = Path(db_path)
        self.watch_roots = [Path(root) for root in (watch_roots or [])]
        self._observer: Optional[Observer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._recent_events: List[dict[str, Any]] = []
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    destination_path TEXT,
                    size_bytes INTEGER,
                    event_time TEXT NOT NULL,
                    root TEXT,
                    device_name TEXT,
                    metadata TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def add_watch_root(self, root: str | os.PathLike[str]) -> None:
        path = Path(root)
        if path not in self.watch_roots:
            self.watch_roots.append(path)
            if self._observer is not None and self._observer.is_alive():
                self._observer.schedule(FileMonitorHandler(self), str(path), recursive=True)

    def start(self) -> None:
        if self._observer is not None and self._observer.is_alive():
            return
        self._observer = Observer()
        for root in self.watch_roots:
            if not root.exists():
                continue
            self._observer.schedule(FileMonitorHandler(self), str(root), recursive=True)
        self._observer.start()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("File monitoring engine started with roots=%s", [str(root) for root in self.watch_roots])

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=2.0)
            self._observer = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _run(self) -> None:
        while self._observer is not None and self._observer.is_alive():
            time.sleep(0.5)

    def record_event(self, event_type: str, source_path: str | os.PathLike[str], destination_path: Optional[str | os.PathLike[str]]) -> None:
        source_path = str(source_path)
        destination_path = str(destination_path) if destination_path is not None else None
        path = Path(source_path)
        size_bytes = None
        try:
            if path.exists():
                size_bytes = path.stat().st_size
        except OSError:
            size_bytes = None

        event_time = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        normalized_event_type = self._classify_event_type(event_type, source_path, size_bytes)

        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute(
                """
                INSERT INTO file_events (event_type, path, destination_path, size_bytes, event_time, root, device_name, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized_event_type,
                    source_path,
                    destination_path,
                    size_bytes,
                    event_time,
                    str(path.parent),
                    None,
                    None,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        with self._lock:
            self._recent_events.append({"event_type": normalized_event_type, "path": source_path, "size_bytes": size_bytes, "timestamp": time.time()})
            self._recent_events = [item for item in self._recent_events if time.time() - item["timestamp"] < 5.0]

        try:
            if normalized_event_type in {"created", "modified", "moved", "copied"} and Path(source_path).is_file():
                from malware_engine.engine import record_malware_result

                malware_result = record_malware_result(source_path, self.db_path)
                log_activity(
                    f"File event {normalized_event_type} scanned: {source_path} (risk={malware_result.get('risk_score')})",
                    category="malware",
                    db_path=str(self.db_path),
                )

                from dlp.engine import log_transfer_event

                dlp_result = log_transfer_event(
                    {
                        "path": source_path,
                        "size_bytes": Path(source_path).stat().st_size if Path(source_path).exists() else 0,
                        "extension": Path(source_path).suffix.lower(),
                        "mime_type": "application/octet-stream",
                        "direction": "usb_to_computer",
                        "keywords": [Path(source_path).name.lower()],
                    },
                    self.db_path,
                )
                if dlp_result.get("decision") == "block":
                    log_activity(
                        f"Blocked suspicious transfer: {source_path} ({dlp_result.get('reasons', [])})",
                        level="warning",
                        category="dlp",
                        db_path=str(self.db_path),
                    )
        except Exception as exc:  # never block the file watcher on scan failures
            log.warning("Malware scan failed for %s: %s", source_path, exc)
            log_activity(f"File monitoring error for {source_path}: {exc}", level="error", category="system", db_path=str(self.db_path))

        log.info("File event recorded: %s %s", normalized_event_type, source_path)

    def _classify_event_type(self, event_type: str, source_path: str, size_bytes: Optional[int]) -> str:
        if event_type == "created":
            with self._lock:
                for item in reversed(self._recent_events):
                    if item["path"] == source_path:
                        continue
                    if item["event_type"] in {"created", "modified"} and item.get("size_bytes") == size_bytes:
                        return "copied"
            return "created"
        if event_type == "moved":
            return "moved"
        return event_type

    def get_events(self) -> List[dict[str, Any]]:
        conn = sqlite3.connect(str(self.db_path))
        try:
            rows = conn.execute(
                "SELECT id, event_type, path, destination_path, size_bytes, event_time, root, device_name, metadata FROM file_events ORDER BY id"
            ).fetchall()
        finally:
            conn.close()

        return [
            {
                "id": row[0],
                "event_type": row[1],
                "path": row[2],
                "destination_path": row[3],
                "size_bytes": row[4],
                "event_time": row[5],
                "root": row[6],
                "device_name": row[7],
                "metadata": row[8],
            }
            for row in rows
        ]
