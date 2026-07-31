from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/roles", tags=["roles"])


@router.get("")
def list_roles(db: Session = Depends(get_db)):
    rows = db.query(models.Role).order_by(models.Role.created_at.desc()).all()
    return [{"id": row.id, "name": row.name, "permissions": row.permissions} for row in rows]


@router.post("")
def create_role(payload: dict[str, str], db: Session = Depends(get_db)):
    role = models.Role(name=payload.get("name", "viewer"), permissions=payload.get("permissions", "") )
    db.add(role)
    db.commit()
    db.refresh(role)
    return {"id": role.id, "name": role.name, "permissions": role.permissions}
