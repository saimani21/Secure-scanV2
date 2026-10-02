from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import get_settings
from securescan.intelligence import IntelligenceService
from securescan.persistence.database import (
    SourceIntelligenceBundleRow,
    SourceIntelligenceSnapshotRow,
)
from tests.postgres_test_guard import validated_postgres_test_url
from tests.test_intelligence_v15 import epss_payload, kev_payload

pytestmark = pytest.mark.postgres
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 2, 12, tzinfo=UTC)


@pytest.fixture
def postgres_intelligence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_url = validated_postgres_test_url()
    config = Config(str(REPOSITORY_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPOSITORY_ROOT / "migrations"))
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    try:
        yield IntelligenceService(factory, store, clock=lambda: NOW), factory
    finally:
        engine.dispose()
        try:
            command.downgrade(config, "base")
        finally:
            get_settings.cache_clear()


@pytest.mark.parametrize("kind", ["kev", "epss"])
def test_concurrent_identical_imports_converge_to_one_snapshot(
    postgres_intelligence, kind: str
) -> None:
    service, factory = postgres_intelligence
    barrier = Barrier(2)
    payload = kev_payload() if kind == "kev" else epss_payload()

    def operation():
        barrier.wait(timeout=10)
        return service.import_kev(payload) if kind == "kev" else service.import_epss(payload)

    with ThreadPoolExecutor(max_workers=2) as pool:
        snapshots = tuple(pool.map(lambda _: operation(), range(2)))
    assert snapshots[0].snapshot_id == snapshots[1].snapshot_id
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceIntelligenceSnapshotRow)) == 1


def test_distinct_epss_content_remains_immutable_history(postgres_intelligence) -> None:
    service, factory = postgres_intelligence
    first = service.import_epss(epss_payload(score="0.12"))
    second = service.import_epss(epss_payload(score="0.73"))
    assert first.snapshot_id != second.snapshot_id
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceIntelligenceSnapshotRow)) == 2


def test_concurrent_bundle_selection_is_idempotent(postgres_intelligence) -> None:
    service, factory = postgres_intelligence
    kev = service.import_kev(kev_payload())
    epss = service.import_epss(epss_payload())
    barrier = Barrier(2)

    def operation():
        barrier.wait(timeout=10)
        return service.create_bundle(
            kev_snapshot_id=kev.snapshot_id,
            epss_snapshot_id=epss.snapshot_id,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        bundles = tuple(pool.map(lambda _: operation(), range(2)))
    assert bundles[0] == bundles[1]
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(SourceIntelligenceBundleRow)) == 1


def test_refresh_cannot_retarget_existing_bundle(postgres_intelligence) -> None:
    service, _ = postgres_intelligence
    first = service.import_epss(epss_payload(score="0.12"))
    bundle = service.create_bundle(kev_snapshot_id=None, epss_snapshot_id=first.snapshot_id)
    second = service.import_epss(epss_payload(score="0.73"))
    assert second.snapshot_id != first.snapshot_id
    assert service.get_bundle(bundle.bundle_id).epss_snapshot_id == first.snapshot_id
