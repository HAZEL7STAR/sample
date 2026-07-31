from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.core.database import Base, SessionLocal, SQLITE_PATH, create_engine
from app.models import models
from sqlalchemy.orm import Session, sessionmaker

log = logging.getLogger("usbguard.dlp")

SENSITIVE_KEYWORDS = {
    "customer",
    "ssn",
    "password",
    "secret",
    "confidential",
    "private",
    "token",
    "financial",
    "medical",
    "employee",
}

BLOCKED_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".scr", ".js", ".ps1", ".vbs", ".jar", ".apk"}
MAX_SIZE_BYTES = 100 * 1024 * 1024


def evaluate_dlp_policy(payload: dict[str, Any]) -> dict[str, Any]:
    path = str(payload.get("path") or "")
    size_bytes = int(payload.get("size_bytes") or 0)
    extension = str(payload.get("extension") or Path(path).suffix.lower())
    mime_type = str(payload.get("mime_type") or "")
    direction = str(payload.get("direction") or "unknown")
    keywords = payload.get("keywords") or []
    if isinstance(keywords, str):
        keywords = [keywords]

    sensitive = False
    reasons: list[str] = []
    risk_score = 0.0

    if any(keyword.lower() in {item.lower() for item in keywords} for keyword in SENSITIVE_KEYWORDS):
        sensitive = True
        reasons.append("sensitive keyword")
        risk_score += 0.4

    if extension.lower() in BLOCKED_EXTENSIONS:
        reasons.append("blocked extension")
        risk_score += 0.4

    if size_bytes > MAX_SIZE_BYTES:
        reasons.append("file too large")
        risk_score += 0.3

    if mime_type and "script" in mime_type:
        reasons.append("script mime")
        risk_score += 0.2

    if direction == "usb_to_computer":
        risk_score += 0.1

    if sensitive:
        risk_score += 0.2

    decision = "allow"
    if reasons:
        decision = "block"

    return {
        "decision": decision,
        "sensitive": sensitive,
        "risk_score": round(risk_score, 3),
        "reasons": reasons,
        "path": path,
        "direction": direction,
    }


def _get_session(db_path: str | os.PathLike[str] | None = None):
    db_file = Path(db_path) if db_path is not None else SQLITE_PATH
    db_file.parent.mkdir(parents=True, exist_ok=True)
    if str(db_file) != str(SQLITE_PATH):
        engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        return sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    return SessionLocal()


def log_transfer_event(payload: dict[str, Any], db_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    result = evaluate_dlp_policy(payload)
    db_file = Path(db_path) if db_path is not None else SQLITE_PATH
    db_file.parent.mkdir(parents=True, exist_ok=True)
    session = _get_session(db_file)
    try:
        path = Path(result["path"])
        sha256 = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        session.add(
            models.FileTransfer(
                file_name=path.name,
                path=result["path"],
                extension=payload.get("extension") or path.suffix.lower(),
                mime_type=payload.get("mime_type") or "",
                size_bytes=payload.get("size_bytes") or 0,
                sha256=sha256,
                direction=result["direction"],
                decision=result["decision"],
                source_path=result["path"],
                destination_path=None,
                blocked=result["decision"] == "block",
                reason=";".join(result["reasons"]),
                timestamp=datetime.now(timezone.utc),
            )
        )
        session.commit()
    finally:
        session.close()

    return result
