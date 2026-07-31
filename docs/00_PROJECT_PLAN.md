# Secure USB Device Access Management System — Build Plan

## Reality check
An enterprise product (Defender/CrowdStrike-class device control) is normally a multi-person,
multi-month effort. I'm building this as a real, working, offline-first Linux system —
but in **phases**, each one fully functional before the next, per your own build rules.
No file below is a stub; each runs.

## Phases
1. **Core USB monitor (this batch)** — pyudev-based real-time device detection, identity
   fingerprinting (VID/PID/serial/UUID), SQLite event log. Works standalone, no DB server needed.
2. **Backend API (this batch)** — FastAPI skeleton wired to SQLAlchemy models (Users, Devices,
   USBEvents, Policies, FileTransfers, MalwareLogs, AuditLogs, OfflineQueue) + SQLite fallback.
3. **Policy engine** — whitelist/blacklist/temp-allow logic, auto-block on unknown device.
4. **Malware/DLP scan pipeline** — hash (SHA256/MD5), python-magic MIME check, YARA rules,
   ClamAV hook, entropy check, autorun/LNK detection.
5. **MySQL + SQLite offline queue sync** — write-behind queue, retry-forever reconciliation.
6. **React dashboard** — device list, live events, alerts, policy management.
7. **Systemd service, installer scripts, tests, docs.**

## Why phased instead of "everything in one response"
A malware engine that half-works is worse than no malware engine — false negatives create false
security. Each phase below is complete and testable on your actual laptop before we add the next
layer of risk logic on top of it.

## What's in this batch
- `usb_monitor/monitor.py` — real pyudev monitor, run it now, plug in your pen drive, watch it log.
- `usb_monitor/device_identity.py` — VID/PID/serial/UUID fingerprinting + risk-relevant fields.
- `backend/app/models/*.py` — SQLAlchemy models for the full schema (Users, Devices, USBEvents,
  Policies, FileTransfers, MalwareLogs, Alerts, AuditLogs, OfflineQueue, SyncLogs, SystemLogs).
- `backend/app/main.py` — FastAPI app, `/health`, `/devices`, `/events` endpoints reading real DB.
- `requirements.txt`, `README.md`.

## Next batch (say "continue" and I build it)
Policy engine (whitelist/blacklist enforcement + auto-unmount unauthorized devices) and the
YARA/ClamAV malware scan pipeline wired to file-copy events.
