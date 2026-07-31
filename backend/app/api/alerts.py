from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
def list_alerts(db: Session = Depends(get_db)):
    rows = db.query(models.Alert).order_by(models.Alert.timestamp.desc()).all()
    return [
        {
            "id": row.id,
            "severity": row.severity,
            "category": row.category,
            "message": row.message,
            "acknowledged": row.acknowledged,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        }
        for row in rows
    ]
