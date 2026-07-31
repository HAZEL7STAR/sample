import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from fastapi.testclient import TestClient

from app.main import app


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
