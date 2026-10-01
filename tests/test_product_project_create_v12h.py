from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescan.api.project_routes import router as project_router
from securescan.config import Settings
from securescan.persistence.database import create_session_factory, initialize_database
from securescan.product_core import SourceProjectService


def test_project_create_api_uses_frozen_service_and_never_accepts_repository_path(tmp_path) -> None:
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'projects.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, sessions = create_session_factory(settings)
    try:
        application = FastAPI()
        application.include_router(project_router)
        application.state.source_project_service = SourceProjectService(sessions)
        client = TestClient(application)

        created = client.post("/v1/projects", json={"name": "SecureScan <script>"})
        assert created.status_code == 201
        payload = created.json()
        assert payload["name"] == "SecureScan <script>"
        assert set(payload) == {"project_id", "name", "created_at"}
        assert client.get(f"/v1/projects/{payload['project_id']}").json() == payload

        invalid = client.post("/v1/projects", json={"name": " unsafe "})
        assert invalid.status_code == 422
        assert invalid.json()["detail"]["code"] == "INVALID_PROJECT_NAME"
        control = client.post("/v1/projects", json={"name": "unsafe\nname"})
        assert control.status_code == 422
        assert control.json()["detail"]["code"] == "INVALID_PROJECT_NAME"
        path = client.post("/v1/projects", json={"name": "safe", "repository_path": "/etc"})
        assert path.status_code == 422
        assert client.get("/v1/projects").json()["total"] == 1
    finally:
        engine.dispose()


def test_project_create_browser_mutation_is_narrow_and_escapes_server_text() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "securescan" / "web"
    mutation = (root / "project_mutations.js").read_text(encoding="utf-8")
    form = (root / "project_create.js").read_text(encoding="utf-8")
    assert 'fetch("/v1/projects"' in mutation
    assert 'method: "POST"' in mutation
    assert "JSON.stringify({ name })" in mutation
    assert "repository_path" not in mutation
    assert "repository_path" not in form
    assert "message.textContent" in form
    assert "isCanonicalUuid(project.project_id)" in form
    assert "beginRequest()" in form
