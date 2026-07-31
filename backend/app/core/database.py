"""
database.py

Primary DB: MySQL (configured via env vars).
Fallback: SQLite offline cache — used automatically if MySQL is unreachable.
Phase 5 will add the write-behind sync queue; for now this gives you a working
DB layer that never blocks the app if MySQL is down.
"""

import logging
import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import OperationalError

log = logging.getLogger("database")

MYSQL_USER = os.getenv("USBGUARD_DB_USER", "usbguard")
MYSQL_PASSWORD = os.getenv("USBGUARD_DB_PASSWORD", "usbguard")
MYSQL_HOST = os.getenv("USBGUARD_DB_HOST", "127.0.0.1")
MYSQL_PORT = os.getenv("USBGUARD_DB_PORT", "3306")
MYSQL_DB = os.getenv("USBGUARD_DB_NAME", "usbguard")

MYSQL_URL = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"

SQLITE_PATH = Path(__file__).resolve().parents[2] / "offline_cache.db"
SQLITE_URL = f"sqlite:///{SQLITE_PATH}"

Base = declarative_base()


def _build_engine():
    try:
        engine = create_engine(MYSQL_URL, pool_pre_ping=True, connect_args={"connect_timeout": 3})
        with engine.connect():
            pass
        log.info("Connected to primary MySQL database at %s:%s", MYSQL_HOST, MYSQL_PORT)
        return engine, "mysql"
    except Exception as exc:
        log.warning("MySQL unavailable (%s). Falling back to SQLite offline cache at %s", exc, SQLITE_PATH)
        engine = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})
        return engine, "sqlite"


engine, ACTIVE_BACKEND = _build_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
