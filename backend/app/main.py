"""
main.py — FastAPI backend entrypoint.

Run:
    cd backend
    uvicorn app.main:app --reload --port 8000

Then:
    curl http://127.0.0.1:8000/health
    curl http://127.0.0.1:8000/devices
    curl http://127.0.0.1:8000/events
"""

import logging

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.api.alerts import router as alerts_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.devices import router as devices_router
from app.api.logs import router as logs_router
from app.api.malware import router as malware_router
from app.api.policies import router as policies_router
from app.api.reports import router as reports_router
from app.api.roles import router as roles_router
from app.api.settings import router as settings_router
from app.api.sync import router as sync_router
from app.api.transfers import router as transfers_router
from app.api.users import router as users_router
from app.core.database import Base, engine, get_db, ACTIVE_BACKEND
from app.models import models  # noqa: F401 — registers tables on Base

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("usbguard.api")

app = FastAPI(title="Secure USB Device Access Management System", version="0.1.0-phase1")
app.include_router(auth_router)
app.include_router(devices_router)
app.include_router(policies_router)
app.include_router(malware_router)
app.include_router(transfers_router)
app.include_router(alerts_router)
app.include_router(audit_router)
app.include_router(logs_router)
app.include_router(reports_router)
app.include_router(sync_router)
app.include_router(users_router)
app.include_router(roles_router)
app.include_router(settings_router)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    log.info("Database schema ready. Active backend: %s", ACTIVE_BACKEND)


@app.get("/health")
def health():
    return {"status": "ok", "db_backend": ACTIVE_BACKEND}


@app.get("/events")
def list_events(limit: int = 100, db: Session = Depends(get_db)):
    rows = (
        db.query(models.USBEvent)
        .order_by(models.USBEvent.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": e.id,
            "device_fingerprint": e.device_fingerprint,
            "action": e.action,
            "device_node": e.device_node,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in rows
    ]
