from __future__ import annotations

from fastapi.testclient import TestClient

from securescan.api.main import app


def test_health():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
