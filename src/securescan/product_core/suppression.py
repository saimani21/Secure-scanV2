from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.persistence.database import (
    SourceFindingLifecycleRow,
    SourceFindingSuppressionEventRow,
    SourceFindingSuppressionRow,
    SourceTargetLineageRow,
    utc_now,
)

MAX_SUPPRESSION_REASON_LENGTH = 1000
MAX_SUPPRESSION_EVENT_LIMIT = 200
LOCAL_OPERATOR = "LOCAL_OPERATOR"
_FINDING_ID = re.compile(r"^[0-9a-f]{64}$")


class SuppressionOperation(StrEnum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    REVOKE = "REVOKE"


class FindingSuppressionError(Exception):
    pass


class FindingSuppressionNotFoundError(FindingSuppressionError):
    pass


class FindingSuppressionConflictError(FindingSuppressionError):
    pass


class FindingSuppressionStateError(FindingSuppressionError):
    pass


class FindingSuppressionValidationError(FindingSuppressionError):
    pass


class FindingSuppressionPersistenceError(FindingSuppressionError):
    pass


@dataclass(frozen=True, slots=True)
class FindingSuppression:
    lineage_id: str
    finding_id: str
    suppression_id: str | None
    reason: str | None
    expires_at: datetime | None
    revoked_at: datetime | None
    revision: int
    active: bool
    actor_type: str | None
    created_at: datetime | None
    updated_at: datetime | None


@dataclass(frozen=True, slots=True)
class FindingSuppressionEvent:
    event_id: str
    lineage_id: str
    finding_id: str
    suppression_id: str
    operation: SuppressionOperation
    previous_reason: str | None
    new_reason: str
    previous_expires_at: datetime | None
    new_expires_at: datetime
    previous_revoked_at: datetime | None
    new_revoked_at: datetime | None
    actor_type: str
    occurred_at: datetime
    resulting_revision: int


@dataclass(frozen=True, slots=True)
class FindingSuppressionEventPage:
    items: tuple[FindingSuppressionEvent, ...]
    total: int
    limit: int
    offset: int


class SourceFindingSuppressionService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        clock: Callable[[], datetime] = utc_now,
        suppression_id_factory: Callable[[], UUID] = uuid4,
        event_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._sessions = session_factory
        self._clock = clock
        self._suppression_id_factory = suppression_id_factory
        self._event_id_factory = event_id_factory

    def get(self, *, project_id: str, lineage_id: str, finding_id: str) -> FindingSuppression:
        self._validate_identifiers(project_id, lineage_id, finding_id)
        evaluated_at = self._now()
        try:
            with self._sessions() as session:
                self._require_target(session, project_id, lineage_id, finding_id)
                row = session.get(SourceFindingSuppressionRow, (lineage_id, finding_id))
                return self._state(lineage_id, finding_id, row, evaluated_at)
        except FindingSuppressionError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise FindingSuppressionPersistenceError from None

    def suppress(
        self,
        *,
        project_id: str,
        lineage_id: str,
        finding_id: str,
        reason: str,
        expires_at: datetime,
        expected_revision: int,
    ) -> FindingSuppression:
        self._validate_identifiers(project_id, lineage_id, finding_id)
        reason, expires_at = self._validate_material(reason, expires_at, expected_revision)
        now = self._now()
        if expires_at <= now:
            raise FindingSuppressionValidationError("expires_at must be in the future")
        try:
            with self._sessions.begin() as session:
                self._require_target(session, project_id, lineage_id, finding_id, lock_lineage=True)
                row = self._locked_row(session, lineage_id, finding_id)
                current_revision = 0 if row is None else row.revision
                if current_revision != expected_revision:
                    raise FindingSuppressionConflictError

                previous_reason = None if row is None else row.reason
                previous_expires_at = None if row is None else self._as_utc(row.expires_at)
                previous_revoked_at = (
                    None if row is None else self._optional_utc(row.revoked_at)
                )
                revision = current_revision + 1
                creates_episode = row is None or not self._is_active(row, now)
                if creates_episode:
                    suppression_id = str(self._suppression_id_factory())
                    operation = SuppressionOperation.CREATE
                    if row is None:
                        row = SourceFindingSuppressionRow(
                            lineage_id=lineage_id,
                            finding_id=finding_id,
                            suppression_id=suppression_id,
                            reason=reason,
                            expires_at=expires_at,
                            revoked_at=None,
                            revision=revision,
                            actor_type=LOCAL_OPERATOR,
                            created_at=now,
                            updated_at=now,
                        )
                        session.add(row)
                    else:
                        row.suppression_id = suppression_id
                        row.reason = reason
                        row.expires_at = expires_at
                        row.revoked_at = None
                        row.revision = revision
                        row.actor_type = LOCAL_OPERATOR
                        row.created_at = now
                        row.updated_at = now
                else:
                    suppression_id = row.suppression_id
                    operation = SuppressionOperation.UPDATE
                    row.reason = reason
                    row.expires_at = expires_at
                    row.revision = revision
                    row.actor_type = LOCAL_OPERATOR
                    row.updated_at = now

                session.flush()
                self._append_event(
                    session,
                    row=row,
                    operation=operation,
                    previous_reason=previous_reason,
                    previous_expires_at=previous_expires_at,
                    previous_revoked_at=previous_revoked_at,
                    occurred_at=now,
                )
                session.flush()
                return self._state(lineage_id, finding_id, row, now)
        except (
            FindingSuppressionNotFoundError,
            FindingSuppressionConflictError,
            FindingSuppressionValidationError,
        ):
            raise
        except IntegrityError:
            raise FindingSuppressionConflictError from None
        except (SQLAlchemyError, TypeError, ValueError):
            raise FindingSuppressionPersistenceError from None

    def revoke(
        self,
        *,
        project_id: str,
        lineage_id: str,
        finding_id: str,
        expected_revision: int,
    ) -> FindingSuppression:
        self._validate_identifiers(project_id, lineage_id, finding_id)
        self._validate_revision(expected_revision)
        now = self._now()
        try:
            with self._sessions.begin() as session:
                self._require_target(session, project_id, lineage_id, finding_id, lock_lineage=True)
                row = self._locked_row(session, lineage_id, finding_id)
                current_revision = 0 if row is None else row.revision
                if current_revision != expected_revision:
                    raise FindingSuppressionConflictError
                if row is None or not self._is_active(row, now):
                    raise FindingSuppressionStateError("only an active suppression may be revoked")

                previous_reason = row.reason
                previous_expires_at = self._as_utc(row.expires_at)
                previous_revoked_at = self._optional_utc(row.revoked_at)
                row.revoked_at = now
                row.revision += 1
                row.actor_type = LOCAL_OPERATOR
                row.updated_at = now
                session.flush()
                self._append_event(
                    session,
                    row=row,
                    operation=SuppressionOperation.REVOKE,
                    previous_reason=previous_reason,
                    previous_expires_at=previous_expires_at,
                    previous_revoked_at=previous_revoked_at,
                    occurred_at=now,
                )
                session.flush()
                return self._state(lineage_id, finding_id, row, now)
        except (
            FindingSuppressionNotFoundError,
            FindingSuppressionConflictError,
            FindingSuppressionStateError,
            FindingSuppressionValidationError,
        ):
            raise
        except IntegrityError:
            raise FindingSuppressionConflictError from None
        except (SQLAlchemyError, TypeError, ValueError):
            raise FindingSuppressionPersistenceError from None

    def list_events(
        self,
        *,
        project_id: str,
        lineage_id: str,
        finding_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> FindingSuppressionEventPage:
        self._validate_identifiers(project_id, lineage_id, finding_id)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
            raise FindingSuppressionValidationError("limit must be between 1 and 200")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise FindingSuppressionValidationError("offset must be nonnegative")
        try:
            with self._sessions() as session:
                self._require_target(session, project_id, lineage_id, finding_id)
                filters = (
                    SourceFindingSuppressionEventRow.lineage_id == lineage_id,
                    SourceFindingSuppressionEventRow.finding_id == finding_id,
                )
                total = session.scalar(
                    select(func.count()).select_from(SourceFindingSuppressionEventRow).where(*filters)
                )
                rows = tuple(
                    session.scalars(
                        select(SourceFindingSuppressionEventRow)
                        .where(*filters)
                        .order_by(SourceFindingSuppressionEventRow.resulting_revision)
                        .limit(limit)
                        .offset(offset)
                    )
                )
                return FindingSuppressionEventPage(
                    items=tuple(self._event(item) for item in rows),
                    total=total,
                    limit=limit,
                    offset=offset,
                )
        except FindingSuppressionError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise FindingSuppressionPersistenceError from None

    @staticmethod
    def _locked_row(
        session: Session, lineage_id: str, finding_id: str
    ) -> SourceFindingSuppressionRow | None:
        return session.scalar(
            select(SourceFindingSuppressionRow)
            .where(
                SourceFindingSuppressionRow.lineage_id == lineage_id,
                SourceFindingSuppressionRow.finding_id == finding_id,
            )
            .with_for_update()
        )

    @staticmethod
    def _require_target(
        session: Session,
        project_id: str,
        lineage_id: str,
        finding_id: str,
        *,
        lock_lineage: bool = False,
    ) -> None:
        statement = select(SourceTargetLineageRow).where(
            SourceTargetLineageRow.lineage_id == lineage_id
        )
        if lock_lineage:
            statement = statement.with_for_update()
        lineage = session.scalar(statement)
        lifecycle = session.get(SourceFindingLifecycleRow, (lineage_id, finding_id))
        if lineage is None or lineage.project_id != project_id or lifecycle is None:
            raise FindingSuppressionNotFoundError

    def _append_event(
        self,
        session: Session,
        *,
        row: SourceFindingSuppressionRow,
        operation: SuppressionOperation,
        previous_reason: str | None,
        previous_expires_at: datetime | None,
        previous_revoked_at: datetime | None,
        occurred_at: datetime,
    ) -> None:
        session.add(
            SourceFindingSuppressionEventRow(
                event_id=str(self._event_id_factory()),
                lineage_id=row.lineage_id,
                finding_id=row.finding_id,
                suppression_id=row.suppression_id,
                operation=operation.value,
                previous_reason=previous_reason,
                new_reason=row.reason,
                previous_expires_at=previous_expires_at,
                new_expires_at=row.expires_at,
                previous_revoked_at=previous_revoked_at,
                new_revoked_at=row.revoked_at,
                actor_type=LOCAL_OPERATOR,
                occurred_at=occurred_at,
                resulting_revision=row.revision,
            )
        )

    def _validate_material(self, reason, expires_at, expected_revision):
        self._validate_revision(expected_revision)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            raise FindingSuppressionValidationError("reason is required and bounded")
        if expires_at is None or expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise FindingSuppressionValidationError("suppression requires an aware expiry")
        return reason, expires_at.astimezone(UTC)

    @staticmethod
    def _validate_revision(expected_revision) -> None:
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 0
        ):
            raise FindingSuppressionValidationError("expected_revision must be nonnegative")

    @staticmethod
    def _validate_identifiers(project_id: str, lineage_id: str, finding_id: str) -> None:
        try:
            valid = (
                isinstance(project_id, str)
                and str(UUID(project_id)) == project_id
                and isinstance(lineage_id, str)
                and str(UUID(lineage_id)) == lineage_id
                and isinstance(finding_id, str)
                and _FINDING_ID.fullmatch(finding_id) is not None
            )
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            raise FindingSuppressionValidationError("invalid suppression identifier")

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise FindingSuppressionPersistenceError
        return value.astimezone(UTC)

    @staticmethod
    def _is_active(row: SourceFindingSuppressionRow, evaluated_at: datetime) -> bool:
        return row.revoked_at is None and SourceFindingSuppressionService._as_utc(
            row.expires_at
        ) > evaluated_at

    @staticmethod
    def _state(lineage_id, finding_id, row, evaluated_at) -> FindingSuppression:
        if row is None:
            return FindingSuppression(
                lineage_id,
                finding_id,
                None,
                None,
                None,
                None,
                0,
                False,
                None,
                None,
                None,
            )
        return FindingSuppression(
            row.lineage_id,
            row.finding_id,
            row.suppression_id,
            row.reason,
            SourceFindingSuppressionService._as_utc(row.expires_at),
            SourceFindingSuppressionService._optional_utc(row.revoked_at),
            row.revision,
            SourceFindingSuppressionService._is_active(row, evaluated_at),
            row.actor_type,
            SourceFindingSuppressionService._as_utc(row.created_at),
            SourceFindingSuppressionService._as_utc(row.updated_at),
        )

    @staticmethod
    def _event(row) -> FindingSuppressionEvent:
        return FindingSuppressionEvent(
            row.event_id,
            row.lineage_id,
            row.finding_id,
            row.suppression_id,
            SuppressionOperation(row.operation),
            row.previous_reason,
            row.new_reason,
            SourceFindingSuppressionService._optional_utc(row.previous_expires_at),
            SourceFindingSuppressionService._as_utc(row.new_expires_at),
            SourceFindingSuppressionService._optional_utc(row.previous_revoked_at),
            SourceFindingSuppressionService._optional_utc(row.new_revoked_at),
            row.actor_type,
            SourceFindingSuppressionService._as_utc(row.occurred_at),
            row.resulting_revision,
        )

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _optional_utc(value: datetime | None) -> datetime | None:
        return None if value is None else SourceFindingSuppressionService._as_utc(value)
