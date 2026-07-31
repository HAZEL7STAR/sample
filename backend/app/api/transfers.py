from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/transfers", tags=["transfers"])


@router.get("")
def list_transfers(db: Session = Depends(get_db)):
    rows = db.query(models.FileTransfer).order_by(models.FileTransfer.timestamp.desc()).all()
    return [
        {
            "id": row.id,
            "device_fingerprint": row.device_fingerprint,
            "file_name": row.file_name,
            "extension": row.extension,
            "mime_type": row.mime_type,
            "size_bytes": row.size_bytes,
            "sha256": row.sha256,
            "direction": row.direction,
            "blocked": row.blocked,
            "reason": row.reason,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        }
        for row in rows
    ]
