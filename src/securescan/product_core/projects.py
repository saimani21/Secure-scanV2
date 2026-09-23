from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.persistence.database import ProjectRow, utc_now

MAX_PROJECT_LIST_LIMIT = 200


class SourceProjectError(RuntimeError):
    def __init__(self, message: str = "Source project operation failed") -> None:
        super().__init__(message)


class SourceProjectNotFoundError(SourceProjectError):
    def __init__(self) -> None:
        super().__init__("Source project was not found")


class InvalidProjectIdentifierError(SourceProjectError):
    def __init__(self) -> None:
        super().__init__("Source project identifier is invalid")


class InvalidProjectPaginationError(SourceProjectError):
    def __init__(self) -> None:
        super().__init__("Source project pagination is invalid")


class SourceProjectPersistenceError(SourceProjectError):
    def __init__(self) -> None:
        super().__init__("Source project query is unavailable")


@dataclass(frozen=True, slots=True)
class SourceProject:
    project_id: str
    name: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class SourceProjectPage:
    items: tuple[SourceProject, ...]
    total: int
    limit: int
    offset: int


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

    def get(self, project_id: str) -> SourceProject:
        normalized = self._project_id(project_id)
        try:
            with self._sessions() as session:
                row = session.get(ProjectRow, normalized)
                if row is None:
                    raise SourceProjectNotFoundError
                return self._record(row)
        except SourceProjectError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise SourceProjectPersistenceError from None

    def list_page(self, *, limit: int = 50, offset: int = 0) -> SourceProjectPage:
        self._pagination(limit, offset)
        try:
            with self._sessions() as session:
                total = session.scalar(select(func.count()).select_from(ProjectRow))
                rows = tuple(
                    session.scalars(
                        select(ProjectRow)
                        .order_by(ProjectRow.created_at.desc(), ProjectRow.id.desc())
                        .limit(limit)
                        .offset(offset)
                    )
                )
            return SourceProjectPage(
                tuple(self._record(row) for row in rows),
                int(total or 0),
                limit,
                offset,
            )
        except SourceProjectError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise SourceProjectPersistenceError from None

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

    @staticmethod
    def _project_id(value: object) -> str:
        try:
            valid = isinstance(value, str) and str(UUID(value)) == value
        except ValueError:
            valid = False
        if not valid:
            raise InvalidProjectIdentifierError
        return value

    @staticmethod
    def _pagination(limit: int, offset: int) -> None:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_PROJECT_LIST_LIMIT
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise InvalidProjectPaginationError

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
