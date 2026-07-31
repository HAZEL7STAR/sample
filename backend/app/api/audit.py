from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_audit_logs(db: Session = Depends(get_db)):
    rows = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).all()
    return [
        {
            "id": row.id,
            "user_id": row.user_id,
            "action": row.action,
            "details": row.details,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        }
        for row in rows
    ]
