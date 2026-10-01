from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from securescan.api.project_routes import router as project_router
from securescan.api.source_scan_routes import router as scan_router
from securescan.orchestration.models import OrchestrationLifecycleState
from securescan.product_core import (
    InvalidProjectPaginationError,
    InvalidScanPaginationError,
    SourceProductStatus,
    SourceProject,
    SourceProjectNotFoundError,
    SourceProjectPage,
    SourceProjectPersistenceError,
    SourceScanListItem,
    SourceScanPage,
    SourceScanQueryPersistenceError,
)
from tests.test_source_navigation_v11b1 import (
    _BASE,
    _add_project,
    _add_scan,
    _database,
)

_NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
_PROJECT_ID = "11111111-1111-4111-8111-111111111111"
_EMPTY_PROJECT_ID = "22222222-2222-4222-8222-222222222222"
_UNKNOWN_PROJECT_ID = "99999999-9999-4999-8999-999999999999"
_RUN_ID = "33333333-3333-4333-8333-333333333333"


class _Projects:
    def __init__(self) -> None:
        self.list_arguments: list[tuple[int, int]] = []
        self.fail = False

    def list_page(self, *, limit: int, offset: int) -> SourceProjectPage:
        self.list_arguments.append((limit, offset))
        if self.fail:
            raise SourceProjectPersistenceError
        if not 1 <= limit <= 200 or offset < 0:
            raise InvalidProjectPaginationError
        return SourceProjectPage(
            (SourceProject(_PROJECT_ID, "Navigation", _NOW),), 1, limit, offset
        )

    def get(self, project_id: str) -> SourceProject:
        if self.fail:
            raise SourceProjectPersistenceError
        if project_id == _UNKNOWN_PROJECT_ID:
            raise SourceProjectNotFoundError
        if project_id not in {_PROJECT_ID, _EMPTY_PROJECT_ID}:
            raise SourceProjectPersistenceError
        return SourceProject(project_id, "Navigation", _NOW)


class _Scans:
    def __init__(self) -> None:
        self.list_arguments: list[dict[str, object]] = []
        self.fail = False

    def list_scans(
        self,
        *,
        project_id: str | None = None,
        limit: int,
        offset: int,
    ) -> SourceScanPage[SourceScanListItem]:
        self.list_arguments.append({"project_id": project_id, "limit": limit, "offset": offset})
        if self.fail:
            raise SourceScanQueryPersistenceError
        if not 1 <= limit <= 200 or offset < 0:
            raise InvalidScanPaginationError
        if project_id == _UNKNOWN_PROJECT_ID:
            raise SourceProjectNotFoundError
        items = (
            ()
            if project_id == _EMPTY_PROJECT_ID
            else (
                SourceScanListItem(
                    run_id=_RUN_ID,
                    target_id="44444444-4444-4444-8444-444444444444",
                    project_id=_PROJECT_ID,
                    lineage_id="55555555-5555-4555-8555-555555555555",
                    submission_sequence_number=1,
                    predecessor_run_id=None,
                    product_status=SourceProductStatus.RUNNING,
                    created_at=_NOW,
                    published_at=None,
                    finalized_at=None,
                    indexed=False,
                    lifecycle_evaluated=False,
                ),
            )
        )
        return SourceScanPage(items, len(items), limit, offset)


def _client() -> tuple[TestClient, _Projects, _Scans]:
    application = FastAPI()
    application.include_router(project_router)
    application.include_router(scan_router)
    projects = _Projects()
    scans = _Scans()
    application.state.source_project_service = projects
    application.state.source_scan_query_service = scans
    return TestClient(application), projects, scans


def test_project_and_scan_navigation_routes_return_safe_bounded_pages() -> None:
    client, projects, scans = _client()

    project_page = client.get("/v1/projects?limit=10&offset=2")
    project = client.get(f"/v1/projects/{_PROJECT_ID}")
    global_scans = client.get("/v1/scans?limit=20&offset=1")
    project_scans = client.get(f"/v1/projects/{_PROJECT_ID}/scans?limit=5&offset=0")
    empty_scans = client.get(f"/v1/projects/{_EMPTY_PROJECT_ID}/scans")

    assert project_page.status_code == 200
    assert project_page.json() == {
        "items": [
            {
                "project_id": _PROJECT_ID,
                "name": "Navigation",
                "created_at": _NOW.isoformat().replace("+00:00", "Z"),
            }
        ],
        "total": 1,
        "limit": 10,
        "offset": 2,
    }
    assert project.status_code == 200
    assert project.json() == {
        "project_id": _PROJECT_ID,
        "name": "Navigation",
        "created_at": _NOW.isoformat().replace("+00:00", "Z"),
    }
    assert global_scans.status_code == 200
    global_item = global_scans.json()["items"][0]
    assert global_item["product_status"] == "RUNNING"
    assert set(global_item) == {
        "run_id",
        "target_id",
        "project_id",
        "lineage_id",
        "submission_sequence_number",
        "predecessor_run_id",
        "product_status",
        "created_at",
        "published_at",
        "finalized_at",
        "indexed",
        "lifecycle_evaluated",
    }
    assert project_scans.status_code == 200
    assert project_scans.json()["items"][0]["project_id"] == _PROJECT_ID
    assert empty_scans.status_code == 200
    assert empty_scans.json()["items"] == []
    assert empty_scans.json()["total"] == 0
    assert projects.list_arguments == [(10, 2)]
    assert scans.list_arguments == [
        {"project_id": None, "limit": 20, "offset": 1},
        {"project_id": _PROJECT_ID, "limit": 5, "offset": 0},
        {"project_id": _EMPTY_PROJECT_ID, "limit": 50, "offset": 0},
    ]


def test_navigation_routes_map_404_422_and_503_without_internal_details() -> None:
    client, projects, scans = _client()

    unknown = client.get(f"/v1/projects/{_UNKNOWN_PROJECT_ID}")
    unknown_history = client.get(f"/v1/projects/{_UNKNOWN_PROJECT_ID}/scans")
    invalid_uuid = client.get("/v1/projects/not-a-uuid")
    invalid_page = client.get("/v1/projects?limit=0")
    invalid_project_max = client.get("/v1/projects?limit=201")
    invalid_project_offset = client.get("/v1/projects?offset=-1")
    invalid_scan_min = client.get("/v1/scans?limit=0")
    invalid_scan_max = client.get("/v1/scans?limit=201")
    invalid_scan_offset = client.get("/v1/scans?offset=-1")
    invalid_run_uuid = client.get("/v1/scans/not-a-uuid")
    scans.fail = True
    unavailable = client.get("/v1/scans")
    scans.fail = False
    projects.fail = True
    unavailable_projects = client.get("/v1/projects")

    assert unknown.status_code == unknown_history.status_code == 404
    assert unknown.json()["detail"] == {
        "code": "PROJECT_NOT_FOUND",
        "message": "Source project was not found",
    }
    assert invalid_uuid.status_code == 422
    assert invalid_page.status_code == 422
    assert invalid_page.json()["detail"]["code"] == "INVALID_PROJECT_QUERY"
    assert invalid_project_max.status_code == 422
    assert invalid_project_offset.status_code == 422
    assert invalid_scan_min.status_code == 422
    assert invalid_scan_max.status_code == 422
    assert invalid_scan_offset.status_code == 422
    assert invalid_run_uuid.status_code == 422
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"] == {
        "code": "QUERY_UNAVAILABLE",
        "message": "Source scan query is unavailable",
    }
    assert unavailable_projects.status_code == 503
    assert unavailable_projects.json()["detail"] == {
        "code": "PROJECT_QUERY_UNAVAILABLE",
        "message": "Source project query is unavailable",
    }
    rendered = str(
        (
            unknown.json(),
            unknown_history.json(),
            invalid_uuid.json(),
            invalid_page.json(),
            invalid_project_max.json(),
            invalid_project_offset.json(),
            invalid_scan_min.json(),
            invalid_scan_max.json(),
            invalid_scan_offset.json(),
            invalid_run_uuid.json(),
            unavailable.json(),
            unavailable_projects.json(),
        )
    )
    for forbidden in (
        "Traceback",
        "SQLAlchemy",
        "postgresql://",
        "database_url",
        "/private/",
        "HMAC",
    ):
        assert forbidden not in rendered
    assert projects.list_arguments == [(0, 0), (201, 0), (50, -1), (50, 0)]


def test_main_application_registers_exact_navigation_get_routes() -> None:
    from securescan.api.main import app

    paths = app.openapi()["paths"]
    assert set(paths["/v1/projects"]) == {"get", "post"}
    assert set(paths["/v1/projects/{project_id}"]) == {"get"}
    assert set(paths["/v1/projects/{project_id}/scans"]) == {"get"}
    assert set(paths["/v1/scans"]) == {"get", "post"}
    assert "post" in paths["/v1/projects"]
    operation_ids = tuple(
        operation["operationId"]
        for path in paths.values()
        for method, operation in path.items()
        if method in {"get", "post", "put", "patch", "delete"}
    )
    assert len(operation_ids) == len(set(operation_ids))


def test_isolated_navigation_api_acceptance_uses_real_product_core(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    try:
        with database.sessions.begin() as session:
            project_many = _add_project(session, 31, "Multiple scans", _BASE)
            project_one = _add_project(session, 32, "One scan", _BASE + timedelta(seconds=1))
            project_empty = _add_project(session, 33, "No scans", _BASE + timedelta(seconds=2))
            oldest = _add_scan(
                session,
                project_id=project_one.id,
                number=31,
                created_at=_BASE,
                lifecycle=OrchestrationLifecycleState.PREPARED,
            )
            middle = _add_scan(
                session,
                project_id=project_many.id,
                number=32,
                created_at=_BASE + timedelta(seconds=1),
                lifecycle=OrchestrationLifecycleState.ACTIVE,
            )
            newest = _add_scan(
                session,
                project_id=project_many.id,
                number=33,
                created_at=_BASE + timedelta(seconds=1),
                lifecycle=OrchestrationLifecycleState.ACTIVE,
            )

        application = FastAPI()
        application.include_router(project_router)
        application.include_router(scan_router)
        application.state.source_project_service = database.projects
        application.state.source_scan_query_service = database.scans
        client = TestClient(application)

        projects = client.get("/v1/projects?limit=2&offset=0")
        assert projects.status_code == 200
        assert projects.json()["total"] == 3
        assert [item["project_id"] for item in projects.json()["items"]] == [
            project_empty.id,
            project_one.id,
        ]

        adjacent = [
            client.get(f"/v1/scans?limit=1&offset={offset}").json()["items"][0]["run_id"]
            for offset in range(3)
        ]
        assert adjacent == [newest, middle, oldest]
        assert len(set(adjacent)) == 3

        filtered = client.get(f"/v1/projects/{project_many.id}/scans")
        assert filtered.status_code == 200
        assert filtered.json()["total"] == 2
        assert {item["project_id"] for item in filtered.json()["items"]} == {project_many.id}
        empty = client.get(f"/v1/projects/{project_empty.id}/scans")
        assert empty.status_code == 200
        assert empty.json()["items"] == []
        assert empty.json()["total"] == 0
        detail = client.get(f"/v1/scans/{newest}")
        assert detail.status_code == 200
        assert detail.json()["run_id"] == newest
    finally:
        database.close()
