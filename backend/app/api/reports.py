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
    return {
        "devices": device_count,
        "events": event_count,
        "alerts": alert_count,
        "transfers": transfer_count,
    }
