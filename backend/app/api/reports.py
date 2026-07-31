from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    device_count = db.query(models.Device).count()
    event_count = db.query(models.USBEvent).count()
    alert_count = db.query(models.Alert).count()
    transfer_count = db.query(models.FileTransfer).count()
    malware_count = db.query(models.MalwareLog).count()
    pending_sync = db.query(models.OfflineQueue).filter(models.OfflineQueue.synced.is_(False)).count()
    return {
        "devices": device_count,
        "events": event_count,
        "alerts": alert_count,
        "transfers": transfer_count,
        "malware": malware_count,
        "sync_pending": pending_sync,
    }


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    recent_devices = db.query(models.Device).order_by(models.Device.last_seen.desc()).limit(6).all()
    recent_alerts = db.query(models.Alert).order_by(models.Alert.timestamp.desc()).limit(6).all()
    recent_transfers = db.query(models.FileTransfer).order_by(models.FileTransfer.timestamp.desc()).limit(6).all()
    recent_logs = db.query(models.SystemLog).order_by(models.SystemLog.timestamp.desc()).limit(8).all()
    recent_usb = db.query(models.USBEvent).order_by(models.USBEvent.timestamp.desc()).limit(8).all()
    recent_malware = db.query(models.MalwareLog).order_by(models.MalwareLog.timestamp.desc()).limit(6).all()
    pending_sync = db.query(models.OfflineQueue).filter(models.OfflineQueue.synced.is_(False)).count()

    return {
        "summary": {
            "devices": db.query(models.Device).count(),
            "authorized_devices": db.query(models.Device).filter(models.Device.status.in_(["whitelisted", "temp_allowed"])).count(),
            "blocked_devices": db.query(models.Device).filter(models.Device.status.in_(["blacklisted", "temp_blocked"])).count(),
            "alerts": db.query(models.Alert).count(),
            "malware": db.query(models.MalwareLog).count(),
            "threats": db.query(models.MalwareLog).filter(models.MalwareLog.risk_score >= 0.4).count(),
            "transfers": db.query(models.FileTransfer).count(),
            "risk_score": round(max((device.risk_score or 0.0) for device in recent_devices), 2) if recent_devices else 0.0,
        },
        "recent": {
            "devices": [
                {
                    "fingerprint": device.fingerprint,
                    "device_name": device.device_name,
                    "manufacturer": device.manufacturer,
                    "status": device.status,
                    "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                }
                for device in recent_devices
            ],
            "alerts": [
                {
                    "severity": alert.severity,
                    "category": alert.category,
                    "message": alert.message,
                    "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                }
                for alert in recent_alerts
            ],
            "transfers": [
                {
                    "file_name": transfer.file_name,
                    "decision": "blocked" if transfer.blocked else "allowed",
                    "timestamp": transfer.timestamp.isoformat() if transfer.timestamp else None,
                }
                for transfer in recent_transfers
            ],
            "logs": [
                {
                    "level": log_entry.level,
                    "message": log_entry.message,
                    "timestamp": log_entry.timestamp.isoformat() if log_entry.timestamp else None,
                }
                for log_entry in recent_logs
            ],
            "usb": [
                {
                    "action": event.action,
                    "device_node": event.device_node,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                }
                for event in recent_usb
            ],
            "malware": [
                {
                    "threat_name": malware.threat_name,
                    "risk_score": malware.risk_score,
                    "timestamp": malware.timestamp.isoformat() if malware.timestamp else None,
                }
                for malware in recent_malware
            ],
            "usb_activity": db.query(models.USBEvent).count(),
            "file_activity": 0,
        },
        "system": {
            "healthy": True,
            "backend": "sqlite",
            "monitor_running": True,
        },
        "sync": {
            "pending": pending_sync,
            "backend": "sqlite",
            "status": "running",
        },
    }
