# Secure USB Device Access Management System

Offline-first, Linux-native USB device control + malware/DLP scanning platform.
See docs/00_PROJECT_PLAN.md for the phased build plan and what's implemented so far.

## Phase 1 (this batch) — Quickstart

### 1. USB monitor (standalone, works right now)
    cd usb_monitor
    pip install pyudev
    sudo python3 monitor.py
Plug in a USB drive — you'll see live PLUGGED/MOUNTED/REMOVED events, and every
event is written to `backend/offline_cache.db` (SQLite), so nothing is lost even
before the backend/DB is running.

### 2. Backend API
    cd backend
    pip install -r ../requirements.txt
    uvicorn app.main:app --reload --port 8000
Without MySQL configured/running, it automatically falls back to the same SQLite
file the monitor writes to — so `/devices` and `/events` show real data immediately.

### 3. MySQL (optional, for Phase 5 sync)
Set env vars: USBGUARD_DB_USER, USBGUARD_DB_PASSWORD, USBGUARD_DB_HOST,
USBGUARD_DB_PORT, USBGUARD_DB_NAME. If unreachable, backend logs a warning and
keeps running on SQLite — no crash, no blocked startup.

### 4. Policy engine
The policy engine now evaluates device policies at runtime. Unknown devices are
blocked by default, whitelisted devices are allowed, and temporary or permanent
block rules are enforced in the monitor and exposed through the `/policies`
FastAPI endpoint.

### 5. File monitoring
The monitor now also starts a background filesystem watcher for mounted media
roots such as `/media` and `/mnt`. It records create, delete, modify, rename,
move, and copy-style events into the offline SQLite store so transfers are not
lost when a USB device is connected.
