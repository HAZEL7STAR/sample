from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import models

router = APIRouter(prefix="/auth", tags=["auth"])

_RATE_LIMITS: dict[str, list[float]] = {}
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, stored_hash: str | None) -> bool:
    if not password or not stored_hash:
        return False
    if stored_hash.startswith("$2") or stored_hash.startswith("$6$") or stored_hash.startswith("$argon2"):
        try:
            return pwd_context.verify(password, stored_hash)
        except Exception:
            return False
    return hashlib.sha256(password.encode("utf-8")).hexdigest() == stored_hash


def _rate_limited(ip: str) -> bool:
    now = time.time()
    window = _RATE_LIMITS.setdefault(ip, [])
    window[:] = [stamp for stamp in window if now - stamp < 60]
    window.append(now)
    return len(window) > 10


@router.post("/login")
def login(payload: dict[str, str], db: Session = Depends(get_db), request: Request = None):
    ip = request.client.host if request and request.client else "unknown"
    if _rate_limited(ip):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    username = (payload.get("username") or "").strip().lower()
    password = payload.get("password") or ""
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    user = db.query(models.User).filter(models.User.username == username).one_or_none()
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")

    if user.password_hash and not user.password_hash.startswith("$2") and not user.password_hash.startswith("$6$") and not user.password_hash.startswith("$argon2"):
        user.password_hash = hash_password(password)

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    return {
        "access_token": f"token-{user.id}-{int(time.time())}",
        "token_type": "bearer",
        "user": {"id": user.id, "username": user.username, "role": user.role},
    }


@router.post("/logout")
def logout() -> dict[str, str]:
    return {"status": "ok"}
