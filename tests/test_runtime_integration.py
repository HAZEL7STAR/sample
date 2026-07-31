import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base
from dlp.engine import log_transfer_event
from malware_engine.engine import record_malware_result
from sqlalchemy import create_engine


def test_dashboard_metrics_endpoint():
    client = TestClient(app)
    response = client.get("/reports/dashboard")

    assert response.status_code == 200
    body = response.json()
    assert "summary" in body
    assert "recent" in body
    assert "system" in body
    assert "sync" in body


def test_root_serves_dashboard_html():
    client = TestClient(app)
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "USB Guard Dashboard" in response.text


def test_malware_and_transfer_flow_writes_database_rows(tmp_path):
    sample_path = tmp_path / "test-malware.exe"
    sample_path.write_bytes(b"MZtest")
    db_path = tmp_path / "runtime.sqlite"

    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=engine)

    result = record_malware_result(sample_path, db_path)
    transfer_result = log_transfer_event(
        {
            "path": str(sample_path),
            "size_bytes": sample_path.stat().st_size,
            "extension": sample_path.suffix.lower(),
            "mime_type": "application/octet-stream",
            "direction": "usb_to_computer",
            "keywords": [sample_path.name.lower()],
        },
        db_path,
    )

    assert result["risk_score"] >= 0.4
    assert transfer_result["decision"] == "block"

    with sqlite3.connect(db_path) as conn:
        malware_rows = conn.execute("SELECT id, file_name, threat_name, risk_score FROM malware_logs").fetchall()
        alert_rows = conn.execute("SELECT id, category, message FROM alerts").fetchall()
        transfer_rows = conn.execute("SELECT id, path, decision FROM file_transfers").fetchall()

    assert malware_rows
    assert any(row[2] == "suspicious executable" for row in malware_rows)
    assert alert_rows
    assert transfer_rows
