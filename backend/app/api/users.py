from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.auth import hash_password
from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/users", tags=["users"])


@router.get("")
def list_users(db: Session = Depends(get_db)):
    rows = db.query(models.User).order_by(models.User.created_at.desc()).all()
    return [
        {
            "id": row.id,
            "username": row.username,
            "role": row.role,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "last_login": row.last_login.isoformat() if row.last_login else None,
        }
        for row in rows
    ]


@router.post("")
def create_user(payload: dict[str, str], db: Session = Depends(get_db)):
    username = (payload.get("username") or "").strip().lower()
    password = payload.get("password") or ""
    role = (payload.get("role") or "viewer").strip().lower()
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    allowed_roles = {"admin", "operator", "viewer"}
    if role not in allowed_roles:
        raise HTTPException(status_code=400, detail="role must be one of: admin, operator, viewer")

    existing = db.query(models.User).filter(models.User.username == username).one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="username already exists")

    user = models.User(username=username, password_hash=hash_password(password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role}
