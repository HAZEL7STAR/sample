"""
monitor.py

Real-time USB device monitor for Linux (Ubuntu/Kali) using pyudev.
Runs standalone — no MySQL, no backend required. Writes every event to a local
SQLite database (offline-first, per project spec: never lose an event).

Run:
    python3 monitor.py

Requires root or membership in the 'plugdev' group to read block device events
on most distros; run with sudo if you see permission errors.
"""

import logging
import os
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import pyudev  # type: ignore
except Exception as exc:  # pragma: no cover - runtime fallback
    pyudev = None
    PYUDEV_IMPORT_ERROR = exc
else:
    PYUDEV_IMPORT_ERROR = None

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from device_identity import build_identity_from_udev
from file_monitor.engine import FileMonitorEngine
from logger import configure_logging, log_activity
from policy_engine.engine import evaluate_policy_decision

DB_PATH = Path(__file__).resolve().parent.parent / "backend" / "offline_cache.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

configure_logging()
log = logging.getLogger("usb_monitor")


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS usb_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            action TEXT NOT NULL,          -- plugged | removed | mounted | unmounted
            vendor_id TEXT,
            product_id TEXT,
            serial_number TEXT,
            manufacturer TEXT,
            device_name TEXT,
            filesystem TEXT,
            capacity_bytes INTEGER,
            device_node TEXT,
            usb_version TEXT,
            timestamp TEXT NOT NULL,
            synced_to_mysql INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            fingerprint TEXT PRIMARY KEY,
            vendor_id TEXT,
            product_id TEXT,
            serial_number TEXT,
            manufacturer TEXT,
            device_name TEXT,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT NOT NULL DEFAULT 'unknown'  -- unknown | whitelisted | blacklisted | temp_allowed
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_fingerprint TEXT,
            rule_type TEXT NOT NULL,
            expires_at TEXT,
            created_by INTEGER,
            created_at TEXT,
            reason TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            message TEXT NOT NULL,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()


def upsert_device(conn: sqlite3.Connection, identity, now: str) -> None:
    conn.execute("""
        INSERT INTO devices (fingerprint, vendor_id, product_id, serial_number,
                              manufacturer, device_name, first_seen, last_seen, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unknown')
        ON CONFLICT(fingerprint) DO UPDATE SET last_seen = excluded.last_seen
    """, (
        identity.fingerprint, identity.vendor_id, identity.product_id,
        identity.serial_number, identity.manufacturer, identity.device_name,
        now, now,
    ))


def load_policies(conn: sqlite3.Connection):
    rows = conn.execute(
        "SELECT id, device_fingerprint, rule_type, expires_at, created_by, created_at, reason FROM policies"
    ).fetchall()
    return [
        {
            "id": row[0],
            "device_fingerprint": row[1],
            "rule_type": row[2],
            "expires_at": row[3],
            "created_by": row[4],
            "created_at": row[5],
            "reason": row[6],
        }
        for row in rows
    ]


def record_alert(conn: sqlite3.Connection, identity, decision, action: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO alerts (severity, category, message, acknowledged, timestamp) VALUES (?, ?, ?, 0, ?)",
        (
            "warning",
            "device",
            f"{action} event for {identity.device_name} was {decision.action} based on policy: {decision.reason}",
            now,
        ),
    )
    conn.commit()


def enforce_policy_decision(conn: sqlite3.Connection, identity, decision, action: str) -> None:
    conn.execute(
        "UPDATE devices SET status = ? WHERE fingerprint = ?",
        (decision.status, identity.fingerprint),
    )
    conn.commit()

    if decision.action == "block" and identity.device_node:
        try:
            subprocess.run(
                ["umount", identity.device_node],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as exc:
            log.warning("Failed to unmount %s: %s", identity.device_node, exc)
        record_alert(conn, identity, decision, action)


def log_event(conn: sqlite3.Connection, identity, action: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT INTO usb_events (
            fingerprint, action, vendor_id, product_id, serial_number, manufacturer,
            device_name, filesystem, capacity_bytes, device_node, usb_version, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        identity.fingerprint, action, identity.vendor_id, identity.product_id,
        identity.serial_number, identity.manufacturer, identity.device_name,
        identity.filesystem, identity.capacity_bytes, identity.device_node,
        identity.usb_version, now,
    ))
    upsert_device(conn, identity, now)

    policies = load_policies(conn)
    decision = evaluate_policy_decision(policies, identity)
    enforce_policy_decision(conn, identity, decision, action)

    log.info(
        "%s | %s (%s) VID=%s PID=%s SN=%s node=%s status=%s decision=%s",
        action.upper(), identity.device_name, identity.manufacturer,
        identity.vendor_id, identity.product_id, identity.serial_number,
        identity.device_node, decision.status, decision.action.upper(),
    )

    if decision.action == "block":
        log.warning("BLOCKED DEVICE DETECTED (%s): %s", identity.device_name, decision.reason)
    elif action == "plugged":
        log.info("DEVICE AUTHORIZED (%s): %s", identity.device_name, decision.reason)


def main() -> None:
    if pyudev is None:
        log.warning("pyudev is unavailable (%s). USB monitoring will be disabled in this environment.", PYUDEV_IMPORT_ERROR)
        return

    conn = sqlite3.connect(str(DB_PATH))
    init_db(conn)
    log.info("SQLite offline event store: %s", DB_PATH)
    log_activity("USB monitor started", category="system", db_path=str(DB_PATH))

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block")

    monitor_roots = []
    for root in os.getenv("USBGUARD_MONITOR_ROOTS", "/media,/mnt").split(","):
        trimmed = root.strip()
        if trimmed:
            monitor_roots.append(trimmed)

    file_monitor = FileMonitorEngine(
        db_path=str(REPO_ROOT / "backend" / "offline_cache.db"),
        watch_roots=monitor_roots,
    )
    file_monitor.start()

    log.info("USB monitor started. Watching for block devices (subsystem=block)...")
    log_activity("USB monitor is watching for device events", category="device", db_path=str(DB_PATH))
    log.info("Plug in / remove a USB drive to see live events. Ctrl+C to stop.")

    running = {"flag": True}

    def handle_sigint(signum, frame):
        running["flag"] = False

    signal.signal(signal.SIGINT, handle_sigint)

    while running["flag"]:
        device = monitor.poll(timeout=1.0)
        if device is None:
            continue
        if device.get("DEVTYPE") not in ("partition", "disk"):
            continue

        identity = build_identity_from_udev(device)
        if identity is None:
            continue  # not a USB device

        action_map = {"add": "plugged", "remove": "removed", "change": "mounted"}
        action = action_map.get(device.action, device.action)
        try:
            log_event(conn, identity, action)
        except Exception as exc:  # never crash the monitor — log and keep going
            log.error("Failed to log event for %s: %s", identity.device_node, exc)
            log_activity(f"USB monitor error for {identity.device_node}: {exc}", level="error", category="device", db_path=str(DB_PATH))

    conn.close()
    file_monitor.stop()
    log.info("USB monitor stopped cleanly.")


if __name__ == "__main__":
    main()
