from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from postgres_test_guard import validated_postgres_test_url

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import Settings
from securescan.orchestration.models import OrchestrationLifecycleState
from securescan.persistence.database import create_session_factory, initialize_database
from securescan.product_core import SourceProjectService, SourceScanQueryService
from tests.test_postgres_source_product_core_pc1 import _reset
from tests.test_source_navigation_v11b1 import (
    _BASE,
    _add_non_source_run,
    _add_project,
    _add_scan,
    _uuid,
)

pytestmark = pytest.mark.postgres


def test_postgres_project_and_scan_navigation_match_sqlite_contract(
    tmp_path: Path,
) -> None:
    database_url = validated_postgres_test_url()
    _reset(database_url)
    settings = Settings(
        _env_file=None,
        database_url=database_url,
        artifact_root=tmp_path / "artifacts",
    )
    engine = None
    try:
        initialize_database(settings)
        engine, sessions = create_session_factory(settings)
        projects = SourceProjectService(sessions)
        scans = SourceScanQueryService(
            sessions, ContentAddressedArtifactStore(settings.artifact_root)
        )
        with sessions.begin() as session:
            older = _add_project(session, 101, "Older", _BASE)
            newer = _add_project(session, 102, "Newer", _BASE + timedelta(seconds=1))
            empty = _add_project(session, 103, "Empty", _BASE + timedelta(seconds=2))
            newer_lineage = _uuid(7_102)
            older_run = _add_scan(
                session,
                project_id=older.id,
                number=101,
                created_at=_BASE,
                lifecycle=OrchestrationLifecycleState.PREPARED,
            )
            newer_run = _add_scan(
                session,
                project_id=newer.id,
                number=102,
                created_at=_BASE + timedelta(seconds=1),
                lifecycle=OrchestrationLifecycleState.ACTIVE,
                lineage_id=newer_lineage,
            )
            newest_run = _add_scan(
                session,
                project_id=newer.id,
                number=103,
                created_at=_BASE + timedelta(seconds=1),
                lifecycle=OrchestrationLifecycleState.ACTIVE,
                lineage_id=newer_lineage,
                sequence_number=2,
                predecessor_run_id=newer_run,
                predecessor_sequence_number=1,
            )
            unrelated_run = _add_non_source_run(
                session,
                project_id=newer.id,
                number=101,
                created_at=_BASE + timedelta(seconds=10),
            )

        project_page = projects.list_page(limit=2, offset=0)
        assert project_page.total == 3
        assert tuple(item.project_id for item in project_page.items) == (
            empty.id,
            newer.id,
        )

        scan_page = scans.list_scans(limit=2, offset=0)
        assert scan_page.total == 3
        assert tuple(item.run_id for item in scan_page.items) == (
            newest_run,
            newer_run,
        )
        tail = scans.list_scans(limit=2, offset=2)
        assert tail.total == 3
        assert tuple(item.run_id for item in tail.items) == (older_run,)
        assert unrelated_run not in {item.run_id for item in (*scan_page.items, *tail.items)}
        filtered = scans.list_scans(project_id=newer.id, limit=2, offset=0)
        assert filtered.total == 2
        assert tuple(item.run_id for item in filtered.items) == (
            newest_run,
            newer_run,
        )
        empty_page = scans.list_scans(project_id=empty.id)
        assert empty_page.total == 0
        assert empty_page.items == ()
    finally:
        if engine is not None:
            engine.dispose()
        _reset(database_url)
