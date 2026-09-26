from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

from securescan.cli import main as cli_main
from securescan.cli.source import SourceCliServices
from securescan.config import Settings
from securescan.persistence.database import create_session_factory, initialize_database
from securescan.product_core import (
    SourceProject,
    SourceProjectError,
    SourceProjectPage,
    SourceProjectService,
)

_NOW = datetime(2026, 9, 21, 12, tzinfo=UTC)
_PROJECT_ID = "11111111-1111-4111-8111-111111111111"


def test_project_service_creates_and_lists_bounded_identities(tmp_path) -> None:
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'projects.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, sessions = create_session_factory(settings)
    try:
        service = SourceProjectService(sessions, clock=lambda: _NOW)
        first = service.create(name="Release acceptance")
        second = service.create(name="Second project")

        assert first.name == "Release acceptance"
        assert first.created_at == _NOW
        listed = service.list(limit=2)
        assert {item.name for item in listed} == {first.name, second.name}
        assert tuple(item.project_id for item in listed) == tuple(
            sorted((first.project_id, second.project_id))
        )
        assert service.list(limit=1) == listed[:1]
    finally:
        engine.dispose()


@pytest.mark.parametrize("name", ["", " padded", "line\nbreak", "x" * 201])
def test_project_service_rejects_unsafe_names(tmp_path, name: str) -> None:
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'invalid-project.db'}",
        artifact_root=tmp_path / "artifacts",
    )
    initialize_database(settings)
    engine, sessions = create_session_factory(settings)
    try:
        with pytest.raises(SourceProjectError):
            SourceProjectService(sessions, clock=lambda: _NOW).create(name=name)
    finally:
        engine.dispose()


class _Projects:
    def create(self, *, name: str) -> SourceProject:
        return SourceProject(_PROJECT_ID, name, _NOW)

    def list_page(self, *, limit: int, offset: int) -> SourceProjectPage:
        assert limit == 10
        assert offset == 0
        return SourceProjectPage(
            (SourceProject(_PROJECT_ID, "Release acceptance", _NOW),),
            1,
            limit,
            offset,
        )


def _services() -> SourceCliServices:
    placeholder = object()
    return SourceCliServices(
        workspace_manager=placeholder,
        submissions=placeholder,
        queries=placeholder,
        profile_planner=placeholder,
        default_deadline_seconds=1_800,
        projects=_Projects(),  # type: ignore[arg-type]
    )


def test_project_cli_create_and_list_use_application_service(monkeypatch) -> None:
    @contextmanager
    def factory():
        yield _services()

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
    runner = CliRunner()

    created = runner.invoke(cli_main.app, ["project", "create", "Release", "--json"])
    listed = runner.invoke(cli_main.app, ["project", "list", "--limit", "10", "--json"])

    assert created.exit_code == 0
    assert json.loads(created.stdout) == {
        "created_at": _NOW.isoformat(),
        "name": "Release",
        "project_id": _PROJECT_ID,
    }
    assert listed.exit_code == 0
    assert json.loads(listed.stdout) == {
        "items": [
            {
                "created_at": _NOW.isoformat(),
                "name": "Release acceptance",
                "project_id": _PROJECT_ID,
            }
        ],
        "limit": 10,
        "offset": 0,
        "total": 1,
    }
