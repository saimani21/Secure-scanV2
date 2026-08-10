from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from securescan.config import get_settings
from securescan.observability.readiness import DatabaseReadinessService, ReadinessReason

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS_PATH = REPOSITORY_ROOT / "migrations"
INITIAL_REVISION = "9eba1941b4ac"
CHECKED_AT = datetime(2050, 2, 3, 4, 5, 6, tzinfo=UTC)


def _alembic_config(database_url: str) -> Config:
    config = Config(str(ALEMBIC_INI_PATH))
    config.set_main_option("script_location", str(MIGRATIONS_PATH))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def _configure_migration_url(
    monkeypatch: pytest.MonkeyPatch,
    database_url: str,
) -> None:
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()


def test_readiness_reports_ready_when_database_matches_alembic_heads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'ready.db'}"
    _configure_migration_url(monkeypatch, database_url)
    engine = create_engine(database_url)
    try:
        command.upgrade(_alembic_config(database_url), "head")

        snapshot = DatabaseReadinessService(engine, ALEMBIC_INI_PATH).check()

        assert snapshot.ready is True
        assert snapshot.database_reachable is True
        assert snapshot.schema_at_head is True
        assert snapshot.reason is ReadinessReason.READY
        assert snapshot.current_head_count == snapshot.expected_head_count == 1
    finally:
        engine.dispose()
        get_settings.cache_clear()


def test_readiness_reports_unversioned_schema_without_alembic_revision(
    tmp_path: Path,
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'unversioned.db'}")
    try:
        snapshot = DatabaseReadinessService(engine, ALEMBIC_INI_PATH).check()
    finally:
        engine.dispose()

    assert snapshot.ready is False
    assert snapshot.database_reachable is True
    assert snapshot.schema_at_head is False
    assert snapshot.reason is ReadinessReason.SCHEMA_UNVERSIONED
    assert snapshot.current_head_count == 0
    assert snapshot.expected_head_count == 1


def test_readiness_reports_outdated_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'outdated.db'}"
    _configure_migration_url(monkeypatch, database_url)
    engine = create_engine(database_url)
    try:
        command.upgrade(_alembic_config(database_url), INITIAL_REVISION)

        snapshot = DatabaseReadinessService(engine, ALEMBIC_INI_PATH).check()

        assert snapshot.ready is False
        assert snapshot.database_reachable is True
        assert snapshot.reason is ReadinessReason.SCHEMA_OUTDATED
        assert snapshot.current_head_count == 1
    finally:
        engine.dispose()
        get_settings.cache_clear()


def test_readiness_reports_database_unreachable_without_leaking_error() -> None:
    sensitive_error = RuntimeError(
        "postgresql://admin:secret@database/private SQL SELECT credentials"
    )

    class _UnavailableEngine:
        def connect(self):
            raise sensitive_error

    snapshot = DatabaseReadinessService(
        _UnavailableEngine(),
        ALEMBIC_INI_PATH,
    ).check()

    assert snapshot.ready is False
    assert snapshot.database_reachable is False
    assert snapshot.reason is ReadinessReason.DATABASE_UNREACHABLE
    serialized = repr(snapshot)
    assert "postgresql://" not in serialized
    assert "secret" not in serialized
    assert "SELECT" not in serialized


def test_readiness_detects_diverged_revision(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'diverged.db'}")
    try:
        with engine.begin() as connection:
            connection.execute(
                text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)")
            )
            connection.execute(
                text("INSERT INTO alembic_version (version_num) VALUES ('unexpected_revision')")
            )

        snapshot = DatabaseReadinessService(engine, ALEMBIC_INI_PATH).check()
    finally:
        engine.dispose()

    assert snapshot.ready is False
    assert snapshot.database_reachable is True
    assert snapshot.reason is ReadinessReason.SCHEMA_DIVERGED
    assert snapshot.current_head_count == 1


def test_readiness_timestamp_is_timezone_aware_utc(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'timestamp.db'}")
    try:
        snapshot = DatabaseReadinessService(
            engine,
            ALEMBIC_INI_PATH,
            clock=lambda: CHECKED_AT,
        ).check()
    finally:
        engine.dispose()

    assert snapshot.checked_at == CHECKED_AT
    assert snapshot.checked_at.tzinfo is not None
    assert snapshot.checked_at.utcoffset() is not None
    assert snapshot.checked_at.utcoffset().total_seconds() == 0
