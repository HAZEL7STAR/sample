from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("")
def list_settings(db: Session = Depends(get_db)):
    rows = db.query(models.Setting).order_by(models.Setting.key.asc()).all()
    return [{"id": row.id, "key": row.key, "value": row.value, "description": row.description} for row in rows]


@router.post("")
def upsert_setting(payload: dict[str, str], db: Session = Depends(get_db)):
    key = payload.get("key", "")
    value = payload.get("value", "")
    description = payload.get("description", "")
    if not key:
        raise ValueError("key is required")

    row = db.query(models.Setting).filter(models.Setting.key == key).one_or_none()
    if row is None:
        row = models.Setting(key=key, value=value, description=description)
        db.add(row)
    else:
        row.value = value
        row.description = description
    db.commit()
    db.refresh(row)
    return {"id": row.id, "key": row.key, "value": row.value, "description": row.description}
