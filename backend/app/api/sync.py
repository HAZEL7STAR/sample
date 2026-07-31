from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/sync", tags=["sync"])


@router.get("/status")
def sync_status(db: Session = Depends(get_db)):
    pending = db.query(models.OfflineQueue).filter(models.OfflineQueue.synced.is_(False)).count()
    return {"pending": pending, "backend": "sqlite"}
