from __future__ import annotations

import logging
import sqlite3
import sys
import time
from pathlib import Path
from typing import Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_LOG_FILE = ROOT_DIR / "logs" / "usbguard.log"

_CONFIGURED = False


def configure_logging(log_file: Optional[str | Path] = None) -> Path:
    global _CONFIGURED

    log_path = Path(log_file) if log_file else DEFAULT_LOG_FILE
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if _CONFIGURED and getattr(logging.getLogger(), "_usbguard_log_path", None) == str(log_path):
        return log_path

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    for handler in list(root_logger.handlers):
        handler.close()
        root_logger.removeHandler(handler)

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

    root_logger._usbguard_log_path = str(log_path)  # type: ignore[attr-defined]
    _CONFIGURED = True
    return log_path


def log_activity(message: str, level: str = "info", category: str = "system", db_path: Optional[str | Path] = None) -> None:
    if not getattr(logging.getLogger(), "_usbguard_log_path", None):
        configure_logging()

    log_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger("usbguard")
    logger.log(log_level, "%s", message)

    if db_path is None:
        return

    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        conn = sqlite3.connect(str(db_file))
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    level TEXT NOT NULL,
                    category TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "INSERT INTO system_logs (level, category, message, timestamp) VALUES (?, ?, ?, ?)",
                (level.upper(), category, message, time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        # Never let logging break the main monitoring flow.
        pass
