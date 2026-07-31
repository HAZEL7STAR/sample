from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("")
def list_logs(db: Session = Depends(get_db)):
    rows = db.query(models.SystemLog).order_by(models.SystemLog.timestamp.desc()).all()
    return [
        {
            "id": row.id,
            "level": row.level,
            "category": "system",
            "message": row.message,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        }
        for row in rows
    ]
