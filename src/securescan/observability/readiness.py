from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import Engine

from securescan.persistence.database import Base


class ReadinessReason(StrEnum):
    READY = "ready"
    DATABASE_UNREACHABLE = "database_unreachable"
    SCHEMA_UNVERSIONED = "schema_unversioned"
    SCHEMA_OUTDATED = "schema_outdated"
    SCHEMA_DIVERGED = "schema_diverged"
    READINESS_CHECK_FAILED = "readiness_check_failed"


class DatabaseReadinessError(RuntimeError):
    """Raised when database readiness cannot be configured safely."""


class DatabaseReadinessConfigurationError(DatabaseReadinessError):
    """Raised when the readiness service configuration is invalid."""


def _utc_timestamp(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Readiness timestamp must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class DatabaseReadinessSnapshot:
    ready: bool
    database_reachable: bool
    schema_at_head: bool
    reason: ReadinessReason
    current_head_count: int
    expected_head_count: int
    checked_at: datetime

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, bool)
            for value in (
                self.ready,
                self.database_reachable,
                self.schema_at_head,
            )
        ):
            raise ValueError("Readiness boolean state is invalid")
        if not isinstance(self.reason, ReadinessReason):
            raise ValueError("Readiness reason is invalid")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.current_head_count, self.expected_head_count)
        ):
            raise ValueError("Readiness revision counts must be non-negative")
        object.__setattr__(self, "checked_at", _utc_timestamp(self.checked_at))


def _bootstrap_database_schema(
    engine: Engine,
    *,
    allow_sqlite_schema_bootstrap: bool,
) -> bool:
    if engine.dialect.name != "sqlite" or not allow_sqlite_schema_bootstrap:
        return False
    Base.metadata.create_all(engine)
    return True


class DatabaseReadinessService:
    def __init__(
        self,
        engine: Engine,
        alembic_config_path: Path,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not hasattr(engine, "connect"):
            raise DatabaseReadinessConfigurationError("Database readiness engine is invalid.")
        if not isinstance(alembic_config_path, Path) or not alembic_config_path.is_file():
            raise DatabaseReadinessConfigurationError(
                "Database readiness migration configuration is invalid."
            )
        if not callable(clock):
            raise DatabaseReadinessConfigurationError("Database readiness clock is invalid.")
        self._engine = engine
        self._alembic_config_path = alembic_config_path.resolve()
        self._clock = clock
        self._load_script_directory()

    def _load_script_directory(self) -> ScriptDirectory:
        try:
            config = Config(str(self._alembic_config_path))
            script_location = config.get_main_option("script_location")
            if not script_location:
                raise ValueError
            script_path = Path(script_location)
            if not script_path.is_absolute():
                script_path = self._alembic_config_path.parent / script_path
            config.set_main_option("script_location", str(script_path.resolve()))
            return ScriptDirectory.from_config(config)
        except Exception as exc:
            raise DatabaseReadinessConfigurationError(
                "Database readiness migration configuration is invalid."
            ) from exc

    @staticmethod
    def _is_ancestor(
        script_directory: ScriptDirectory,
        current_head: str,
        expected_head: str,
    ) -> bool:
        try:
            script_directory.get_revision(current_head)
            script_directory.get_revision(expected_head)
            list(
                script_directory.iterate_revisions(
                    expected_head,
                    current_head,
                )
            )
        except Exception:
            return False
        return True

    def _snapshot(
        self,
        *,
        ready: bool,
        database_reachable: bool,
        reason: ReadinessReason,
        current_head_count: int,
        expected_head_count: int,
    ) -> DatabaseReadinessSnapshot:
        return DatabaseReadinessSnapshot(
            ready=ready,
            database_reachable=database_reachable,
            schema_at_head=ready,
            reason=reason,
            current_head_count=current_head_count,
            expected_head_count=expected_head_count,
            checked_at=self._clock(),
        )

    def check(self) -> DatabaseReadinessSnapshot:
        database_reachable = False
        expected_head_count = 0
        try:
            with self._engine.connect() as connection:
                connection.execute(text("SELECT 1"))
                database_reachable = True

                script_directory = self._load_script_directory()
                expected_heads = frozenset(script_directory.get_heads())
                expected_head_count = len(expected_heads)
                migration_context = MigrationContext.configure(connection)
                current_heads = frozenset(migration_context.get_current_heads())

            if not current_heads and expected_heads:
                reason = ReadinessReason.SCHEMA_UNVERSIONED
            elif current_heads == expected_heads:
                reason = ReadinessReason.READY
            elif current_heads and all(
                any(
                    self._is_ancestor(script_directory, current_head, expected_head)
                    for expected_head in expected_heads
                )
                for current_head in current_heads
            ):
                reason = ReadinessReason.SCHEMA_OUTDATED
            else:
                reason = ReadinessReason.SCHEMA_DIVERGED

            return self._snapshot(
                ready=reason is ReadinessReason.READY,
                database_reachable=True,
                reason=reason,
                current_head_count=len(current_heads),
                expected_head_count=expected_head_count,
            )
        except DatabaseReadinessConfigurationError:
            return self._snapshot(
                ready=False,
                database_reachable=database_reachable,
                reason=ReadinessReason.READINESS_CHECK_FAILED,
                current_head_count=0,
                expected_head_count=expected_head_count,
            )
        except Exception:
            reason = (
                ReadinessReason.READINESS_CHECK_FAILED
                if database_reachable
                else ReadinessReason.DATABASE_UNREACHABLE
            )
            return self._snapshot(
                ready=False,
                database_reachable=database_reachable,
                reason=reason,
                current_head_count=0,
                expected_head_count=expected_head_count,
            )
