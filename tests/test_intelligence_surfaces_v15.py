from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from typer.testing import CliRunner

from securescan.api.intelligence_routes import router
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.cli import intelligence as cli_intelligence
from securescan.cli import main as cli_main
from securescan.intelligence import AssuranceService, IntelligenceService
from securescan.intelligence import feeds as feed_module
from securescan.intelligence.feeds import FeedClientError, SnapshotFeedClient
from securescan.intelligence.nvd import NvdClientError, NvdExactCveClient
from securescan.persistence.database import Base
from tests.test_intelligence_v15 import NOW, kev_payload, nvd_payload


@pytest.fixture
def surface(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'surface.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    artifacts = ContentAddressedArtifactStore(tmp_path / "artifacts")
    intelligence = IntelligenceService(sessions, artifacts, clock=lambda: NOW)
    assurance = AssuranceService(sessions, artifacts, clock=lambda: NOW)
    app = FastAPI()
    app.state.intelligence_service = intelligence
    app.state.assurance_service = assurance
    app.include_router(router)
    try:
        yield engine, intelligence, assurance, TestClient(app)
    finally:
        engine.dispose()


def test_api_import_list_and_bundle_are_bounded_json_surfaces(surface) -> None:
    _, _, _, client = surface
    response = client.post(
        "/v1/intelligence/imports",
        json={
            "source": "CISA_KEV",
            "content_base64": base64.b64encode(kev_payload()).decode(),
        },
    )
    assert response.status_code == 200
    imported = response.json()
    assert imported["record_count"] == 1
    assert "records" not in imported

    listed = client.get("/v1/intelligence/snapshots").json()
    assert listed == [imported]
    bundle = client.post(
        "/v1/intelligence/bundles",
        json={"kev_snapshot_id": imported["snapshot_id"]},
    )
    assert bundle.status_code == 200
    assert bundle.json()["kev_snapshot_id"] == imported["snapshot_id"]


def test_api_rejects_malformed_base64_without_partial_snapshot(surface) -> None:
    _, _, _, client = surface
    response = client.post(
        "/v1/intelligence/imports",
        json={"source": "CISA_KEV", "content_base64": "%%%"},
    )
    assert response.status_code == 422
    assert client.get("/v1/intelligence/snapshots").json() == []


def test_cli_import_and_list_emit_same_bounded_snapshot_truth(
    surface, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, intelligence, assurance, _ = surface
    monkeypatch.setattr(
        cli_intelligence,
        "_services",
        lambda: (SimpleEngine(engine), intelligence, assurance),
    )
    fixture = tmp_path / "kev.json"
    fixture.write_bytes(kev_payload())
    runner = CliRunner()
    imported = runner.invoke(
        cli_main.app,
        ["intel", "import", "--source", "kev", "--file", str(fixture)],
    )
    assert imported.exit_code == 0, imported.output
    imported_data = json.loads(imported.stdout)
    assert "records" not in imported_data
    listed = runner.invoke(cli_main.app, ["intel", "snapshots"])
    assert listed.exit_code == 0, listed.output
    assert json.loads(listed.stdout) == [imported_data]


class SimpleEngine:
    def __init__(self, engine) -> None:
        self._engine = engine

    def dispose(self) -> None:
        # The fixture owns the real engine lifetime.
        pass


def test_nvd_client_sends_only_exact_cve_and_optional_key_in_header() -> None:
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=nvd_payload(), request=request)

    with NvdExactCveClient(
        api_key="controlled-secret-key",
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
    ) as client:
        assert client.fetch("CVE-2025-12345") == nvd_payload()
    assert len(requests) == 1
    assert dict(requests[0].url.params) == {"cveId": "CVE-2025-12345"}
    assert requests[0].headers["apiKey"] == "controlled-secret-key"
    assert "controlled-secret-key" not in str(requests[0].url)


@pytest.mark.parametrize("status", [302, 404])
def test_nvd_client_rejects_redirects_and_non_success(status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status, headers={"Location": "https://elsewhere.test"}, request=request
        )

    with (
        NvdExactCveClient(transport=httpx.MockTransport(handler), sleep=lambda _: None) as client,
        pytest.raises(NvdClientError),
    ):
        client.fetch("CVE-2025-12345")


def test_nvd_client_retries_bounded_transient_failures() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, request=request)

    with (
        NvdExactCveClient(transport=httpx.MockTransport(handler), sleep=lambda _: None) as client,
        pytest.raises(NvdClientError),
    ):
        client.fetch("CVE-2025-12345")
    assert attempts == 3


def test_feed_client_follows_only_allowlisted_https_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        feed_module._SOURCES,
        "kev",
        ("https://feed.test/kev.json", 1024, frozenset({"feed.test"})),
    )

    def accepted(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/kev.json":
            return httpx.Response(302, headers={"Location": "/current.json"}, request=request)
        return httpx.Response(200, content=b"{}", request=request)

    with SnapshotFeedClient(
        transport=httpx.MockTransport(accepted), sleep=lambda _: None
    ) as client:
        assert client.fetch("kev") == b"{}"

    def rejected(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302, headers={"Location": "https://attacker.test/feed"}, request=request
        )

    with (
        SnapshotFeedClient(transport=httpx.MockTransport(rejected), sleep=lambda _: None) as client,
        pytest.raises(FeedClientError),
    ):
        client.fetch("kev")


def test_feed_client_enforces_byte_limit_and_bounded_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        feed_module._SOURCES,
        "kev",
        ("https://feed.test/kev.json", 3, frozenset({"feed.test"})),
    )

    def oversized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"four", request=request)

    with (
        SnapshotFeedClient(
            transport=httpx.MockTransport(oversized), sleep=lambda _: None
        ) as client,
        pytest.raises(FeedClientError),
    ):
        client.fetch("kev")

    attempts = 0

    def unavailable(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, request=request)

    with (
        SnapshotFeedClient(
            transport=httpx.MockTransport(unavailable), sleep=lambda _: None
        ) as client,
        pytest.raises(FeedClientError),
    ):
        client.fetch("kev")
    assert attempts == 3
