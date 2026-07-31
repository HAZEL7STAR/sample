from __future__ import annotations

import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

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


def log_transfer_event(payload: dict[str, Any], db_path: str | os.PathLike[str]) -> dict[str, Any]:
    result = evaluate_dlp_policy(payload)
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_file))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS file_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                direction TEXT NOT NULL,
                size_bytes INTEGER,
                extension TEXT,
                mime_type TEXT,
                decision TEXT NOT NULL,
                sensitive INTEGER NOT NULL DEFAULT 0,
                risk_score REAL NOT NULL,
                reasons TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO file_transfers (path, direction, size_bytes, extension, mime_type, decision, sensitive, risk_score, reasons, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["path"],
                result["direction"],
                payload.get("size_bytes") or 0,
                payload.get("extension") or Path(result["path"]).suffix.lower(),
                payload.get("mime_type") or "",
                result["decision"],
                1 if result["sensitive"] else 0,
                result["risk_score"],
                ";".join(result["reasons"]),
                time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return result
