from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.persistence.database import ProjectRow, utc_now

MAX_PROJECT_LIST_LIMIT = 200


class SourceProjectError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Source project operation failed")


@dataclass(frozen=True, slots=True)
class SourceProject:
    project_id: str
    name: str
    created_at: datetime


class SourceProjectService:
    """Small Product Core boundary for durable project identities."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        clock=utc_now,
    ) -> None:
        self._sessions = session_factory
        self._clock = clock

    def create(self, *, name: str) -> SourceProject:
        normalized = self._name(name)
        created_at = self._now()
        try:
            with self._sessions.begin() as session:
                row = ProjectRow(name=normalized, created_at=created_at)
                session.add(row)
                session.flush()
                return self._record(row)
        except SQLAlchemyError:
            raise SourceProjectError from None

    def list(self, *, limit: int = 100) -> tuple[SourceProject, ...]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_PROJECT_LIST_LIMIT
        ):
            raise SourceProjectError
        try:
            with self._sessions() as session:
                rows = tuple(
                    session.scalars(
                        select(ProjectRow)
                        .order_by(ProjectRow.created_at, ProjectRow.id)
                        .limit(limit)
                    )
                )
                return tuple(self._record(row) for row in rows)
        except SQLAlchemyError:
            raise SourceProjectError from None

    @staticmethod
    def _name(value: str) -> str:
        if (
            not isinstance(value, str)
            or value != value.strip()
            or not value
            or len(value.encode("utf-8")) > 200
            or any(unicodedata.category(character).startswith("C") for character in value)
        ):
            raise SourceProjectError
        return value

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise SourceProjectError
        return value.astimezone(UTC)

    @staticmethod
    def _record(row: ProjectRow) -> SourceProject:
        created_at = row.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        return SourceProject(row.id, row.name, created_at.astimezone(UTC))
