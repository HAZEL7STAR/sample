from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("")
def list_devices(db: Session = Depends(get_db)):
    rows = db.query(models.Device).order_by(models.Device.last_seen.desc()).all()
    return [
        {
            "fingerprint": row.fingerprint,
            "device_name": row.device_name,
            "manufacturer": row.manufacturer,
            "vendor_id": row.vendor_id,
            "product_id": row.product_id,
            "serial_number": row.serial_number,
            "status": row.status,
            "risk_score": row.risk_score,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        }
        for row in rows
    ]
