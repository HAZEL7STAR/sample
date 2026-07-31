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
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
from app.core.database import ACTIVE_BACKEND, Base, engine, get_db
from app.core.runtime import runtime_manager
from app.models import models  # noqa: F401 — registers tables on Base

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("usbguard.api")
REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_DIR = REPO_ROOT / "dashboard"

@asynccontextmanager
async def lifespan(app: FastAPI):
    runtime_manager.start()
    try:
        yield
    finally:
        runtime_manager.stop()


app = FastAPI(title="Secure USB Device Access Management System", version="0.1.0-phase1", lifespan=lifespan)
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


def _dashboard_file(filename: str) -> FileResponse:
    return FileResponse(DASHBOARD_DIR / filename)


@app.get("/", include_in_schema=False)
def dashboard_root():
    return _dashboard_file("index.html")


@app.get("/index.html", include_in_schema=False)
def dashboard_index():
    return _dashboard_file("index.html")


@app.get("/app.js", include_in_schema=False)
def dashboard_app_js():
    return _dashboard_file("app.js")


@app.get("/styles.css", include_in_schema=False)
def dashboard_styles_css():
    return _dashboard_file("styles.css")


@app.get("/health")
def health():
    return {"status": "ok", "db_backend": ACTIVE_BACKEND, "services": runtime_manager.status()}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    runtime_manager.register_websocket(websocket)
    try:
        await websocket.send_json({"type": "snapshot", "payload": runtime_manager.current_snapshot()})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        runtime_manager.unregister_websocket(websocket)


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
