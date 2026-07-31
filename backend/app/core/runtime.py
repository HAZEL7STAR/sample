from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fastapi import WebSocket

from app.core.database import ACTIVE_BACKEND, Base, SessionLocal, engine
from app.models import models
from logger import configure_logging, log_activity
from offline_sync.engine import OfflineSyncQueue

BACKEND_ROOT = REPO_ROOT / "backend"
DB_PATH = REPO_ROOT / "backend" / "offline_cache.db"
MONITOR_SCRIPT = REPO_ROOT / "usb_monitor" / "monitor.py"


class RuntimeManager:
    def __init__(self) -> None:
        self.log = logging.getLogger("usbguard.runtime")
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._websockets: set[WebSocket] = set()
        self._monitor_process: Optional[subprocess.Popen[str]] = None
        self._monitor_log_path = REPO_ROOT / "logs" / "usbmonitor.log"
        self._sync_queue = OfflineSyncQueue(DB_PATH)
        self._sync_thread: Optional[threading.Thread] = None
        self._watchdog_thread: Optional[threading.Thread] = None
        self._snapshot: dict[str, Any] = {}

    def start(self) -> None:
        if getattr(self, "_started", False):
            return
        self._started = True
        configure_logging()
        self._loop = asyncio.get_running_loop()
        self._stop_event.clear()
        self._initialize_database()
        self._start_sync_worker()
        self._start_monitor_process()
        self._start_watchdog()
        self._publish_snapshot()
        log_activity("Backend runtime started", category="system", db_path=DB_PATH)
        self.log.info("Backend runtime initialized; USB monitor, sync worker and websocket updates are active")

    def stop(self) -> None:
        if not getattr(self, "_started", False):
            return
        self._stop_event.set()
        self._stop_monitor_process()
        self._publish_snapshot()
        log_activity("Backend runtime stopped", category="system", db_path=DB_PATH)

    def register_websocket(self, websocket: WebSocket) -> None:
        with self._lock:
            self._websockets.add(websocket)
        self._publish_snapshot()

    def unregister_websocket(self, websocket: WebSocket) -> None:
        with self._lock:
            self._websockets.discard(websocket)

    def current_snapshot(self) -> dict[str, Any]:
        if not self._snapshot:
            self._snapshot = self._build_snapshot()
        return self._snapshot

    def status(self) -> dict[str, Any]:
        return {
            "monitor_running": self._monitor_process is not None and self._monitor_process.poll() is None,
            "backend": ACTIVE_BACKEND,
            "watchdog_running": self._watchdog_thread is not None and self._watchdog_thread.is_alive(),
            "sync_running": self._sync_thread is not None and self._sync_thread.is_alive(),
        }

    def _initialize_database(self) -> None:
        Base.metadata.create_all(bind=engine)
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(DB_PATH)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS system_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _start_monitor_process(self) -> None:
        if self._monitor_process is not None and self._monitor_process.poll() is None:
            return

        self._monitor_log_path.parent.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(BACKEND_ROOT) + (os.pathsep + pythonpath if pythonpath else "")
        self._monitor_log_path.touch(exist_ok=True)
        log_handle = self._monitor_log_path.open("a", encoding="utf-8")
        self._monitor_process = subprocess.Popen(
            [sys.executable, str(MONITOR_SCRIPT)],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.log.info("Started USB monitor subprocess with PID %s", self._monitor_process.pid)

    def _stop_monitor_process(self) -> None:
        if self._monitor_process is None:
            return
        if self._monitor_process.poll() is None:
            self._monitor_process.terminate()
            try:
                self._monitor_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._monitor_process.kill()
                self._monitor_process.wait(timeout=5)
        self._monitor_process = None

    def _start_sync_worker(self) -> None:
        if self._sync_thread is not None and self._sync_thread.is_alive():
            return
        self._sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._sync_thread.start()

    def _sync_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._sync_queue.flush()
                self._publish_snapshot()
            except Exception as exc:  # pragma: no cover - runtime resilience
                self.log.warning("Sync worker error: %s", exc)
            self._stop_event.wait(3)

    def _start_watchdog(self) -> None:
        if self._watchdog_thread is not None and self._watchdog_thread.is_alive():
            return
        self._watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True)
        self._watchdog_thread.start()

    def _watchdog_loop(self) -> None:
        while not self._stop_event.is_set():
            if self._monitor_process is not None and self._monitor_process.poll() is not None:
                self.log.warning("USB monitor exited unexpectedly; restarting")
                self._start_monitor_process()
            self._stop_event.wait(2)

    def _publish_snapshot(self) -> None:
        snapshot = self._build_snapshot()
        self._snapshot = snapshot
        if self._loop is None:
            return
        try:
            future = asyncio.run_coroutine_threadsafe(self._broadcast_to_clients(snapshot), self._loop)
            future.result(timeout=1)
        except Exception as exc:  # pragma: no cover - runtime resilience
            self.log.warning("Failed to broadcast snapshot: %s", exc)

    async def _broadcast_to_clients(self, payload: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        with self._lock:
            sockets = list(self._websockets)
        for websocket in sockets:
            try:
                await websocket.send_json({"type": "snapshot", "payload": payload})
            except Exception:
                dead.append(websocket)
        if dead:
            with self._lock:
                for websocket in dead:
                    self._websockets.discard(websocket)

    def _build_snapshot(self) -> dict[str, Any]:
        try:
            with SessionLocal() as db:
                device_count = db.query(models.Device).count()
                authorized_count = db.query(models.Device).filter(models.Device.status.in_(["whitelisted", "temp_allowed"])).count()
                blocked_count = db.query(models.Device).filter(models.Device.status.in_(["blacklisted", "temp_blocked"])).count()
                alert_count = db.query(models.Alert).count()
                malware_count = db.query(models.MalwareLog).count()
                transfer_count = db.query(models.FileTransfer).count()
                recent_devices = db.query(models.Device).order_by(models.Device.last_seen.desc()).limit(6).all()
                recent_alerts = db.query(models.Alert).order_by(models.Alert.timestamp.desc()).limit(6).all()
                recent_transfers = db.query(models.FileTransfer).order_by(models.FileTransfer.timestamp.desc()).limit(6).all()
                recent_logs = db.query(models.SystemLog).order_by(models.SystemLog.timestamp.desc()).limit(8).all()
                recent_usb = db.query(models.USBEvent).order_by(models.USBEvent.timestamp.desc()).limit(8).all()
                suspicious_malware = db.query(models.MalwareLog).filter(models.MalwareLog.risk_score >= 0.4).count()
                risk_score = max((device.risk_score or 0.0) for device in recent_devices) if recent_devices else 0.0
                pending_sync = db.query(models.OfflineQueue).filter(models.OfflineQueue.synced.is_(False)).count()

                summary = {
                    "devices": device_count,
                    "authorized_devices": authorized_count,
                    "blocked_devices": blocked_count,
                    "alerts": alert_count,
                    "malware": malware_count,
                    "threats": suspicious_malware,
                    "transfers": transfer_count,
                    "risk_score": round(risk_score, 2),
                }

                recent = {
                    "devices": [self._serialize_device(device) for device in recent_devices],
                    "alerts": [self._serialize_alert(alert) for alert in recent_alerts],
                    "transfers": [self._serialize_transfer(transfer) for transfer in recent_transfers],
                    "logs": [self._serialize_log(entry) for entry in recent_logs],
                    "usb": [self._serialize_usb_event(event) for event in recent_usb],
                    "usb_activity": db.query(models.USBEvent).count(),
                    "file_activity": self._count_file_events(),
                }

                system = {
                    "healthy": True,
                    "backend": ACTIVE_BACKEND,
                    "monitor_running": self._monitor_process is not None and self._monitor_process.poll() is None,
                }

                sync = {
                    "pending": pending_sync,
                    "backend": ACTIVE_BACKEND,
                    "status": "running" if self._sync_thread and self._sync_thread.is_alive() else "stopped",
                }

                return {"summary": summary, "recent": recent, "system": system, "sync": sync}
        except Exception as exc:  # pragma: no cover - runtime resilience
            self.log.warning("Dashboard snapshot collection failed: %s", exc)
            return {"summary": {}, "recent": {}, "system": {"healthy": False, "backend": ACTIVE_BACKEND}, "sync": {"pending": 0, "backend": ACTIVE_BACKEND, "status": "error"}}

    def _count_file_events(self) -> int:
        try:
            with sqlite3.connect(str(DB_PATH)) as conn:
                row = conn.execute("SELECT COUNT(*) FROM file_events").fetchone()
                return int(row[0] if row else 0)
        except Exception:
            return 0

    def _serialize_device(self, device: models.Device) -> dict[str, Any]:
        return {
            "fingerprint": device.fingerprint,
            "device_name": device.device_name,
            "manufacturer": device.manufacturer,
            "status": device.status,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        }

    def _serialize_alert(self, alert: models.Alert) -> dict[str, Any]:
        return {
            "severity": alert.severity,
            "category": alert.category,
            "message": alert.message,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        }

    def _serialize_transfer(self, transfer: models.FileTransfer) -> dict[str, Any]:
        return {
            "file_name": transfer.file_name,
            "decision": "blocked" if transfer.blocked else "allowed",
            "timestamp": transfer.timestamp.isoformat() if transfer.timestamp else None,
        }

    def _serialize_log(self, entry: models.SystemLog) -> dict[str, Any]:
        return {
            "level": entry.level,
            "message": entry.message,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        }

    def _serialize_usb_event(self, event: models.USBEvent) -> dict[str, Any]:
        return {
            "action": event.action,
            "device_node": event.device_node,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        }


runtime_manager = RuntimeManager()
