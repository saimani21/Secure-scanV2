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
    SourceFindingGovernanceEventRow,
    SourceFindingGovernanceRow,
    SourceFindingLifecycleRow,
    SourceTargetLineageRow,
    utc_now,
)

MAX_GOVERNANCE_REASON_LENGTH = 1000
MAX_GOVERNANCE_EVENT_LIMIT = 200
LOCAL_OPERATOR = "LOCAL_OPERATOR"
_FINDING_ID = re.compile(r"^[0-9a-f]{64}$")


class AnalystDisposition(StrEnum):
    UNREVIEWED = "UNREVIEWED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class GovernanceOperation(StrEnum):
    SET = "SET"
    CLEAR = "CLEAR"


class FindingGovernanceError(Exception):
    pass


class FindingGovernanceNotFoundError(FindingGovernanceError):
    pass


class FindingGovernanceConflictError(FindingGovernanceError):
    pass


class FindingGovernanceValidationError(FindingGovernanceError):
    pass


class FindingGovernancePersistenceError(FindingGovernanceError):
    pass


@dataclass(frozen=True, slots=True)
class FindingGovernance:
    lineage_id: str
    finding_id: str
    disposition: AnalystDisposition
    reason: str | None
    expires_at: datetime | None
    revision: int
    last_changed_by_type: str | None
    created_at: datetime | None
    updated_at: datetime | None


@dataclass(frozen=True, slots=True)
class FindingGovernanceEvent:
    event_id: str
    lineage_id: str
    finding_id: str
    operation: GovernanceOperation
    previous_disposition: AnalystDisposition
    new_disposition: AnalystDisposition
    previous_reason: str | None
    new_reason: str | None
    previous_expires_at: datetime | None
    new_expires_at: datetime | None
    actor_type: str
    occurred_at: datetime
    resulting_revision: int


@dataclass(frozen=True, slots=True)
class FindingGovernanceEventPage:
    items: tuple[FindingGovernanceEvent, ...]
    total: int
    limit: int
    offset: int


class SourceFindingGovernanceService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        clock: Callable[[], datetime] = utc_now,
        event_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._sessions = session_factory
        self._clock = clock
        self._event_id_factory = event_id_factory

    def get(self, *, project_id: str, lineage_id: str, finding_id: str) -> FindingGovernance:
        self._validate_identifiers(project_id, lineage_id, finding_id)
        try:
            with self._sessions() as session:
                self._require_target(session, project_id, lineage_id, finding_id)
                row = session.get(SourceFindingGovernanceRow, (lineage_id, finding_id))
                return self._state(lineage_id, finding_id, row)
        except FindingGovernanceError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise FindingGovernancePersistenceError from None

    def mutate(
        self,
        *,
        project_id: str,
        lineage_id: str,
        finding_id: str,
        disposition: AnalystDisposition,
        reason: str | None,
        expires_at: datetime | None,
        expected_revision: int,
    ) -> FindingGovernance:
        self._validate_identifiers(project_id, lineage_id, finding_id)
        disposition, reason, expires_at = self._validate_mutation(
            disposition, reason, expires_at, expected_revision
        )
        now = self._now()
        if disposition is AnalystDisposition.ACCEPTED_RISK and expires_at <= now:
            raise FindingGovernanceValidationError("expires_at must be in the future")
        try:
            with self._sessions.begin() as session:
                self._require_target(session, project_id, lineage_id, finding_id, lock_lineage=True)
                row = session.scalar(
                    select(SourceFindingGovernanceRow)
                    .where(
                        SourceFindingGovernanceRow.lineage_id == lineage_id,
                        SourceFindingGovernanceRow.finding_id == finding_id,
                    )
                    .with_for_update()
                )
                current_revision = 0 if row is None else row.revision
                if current_revision != expected_revision:
                    raise FindingGovernanceConflictError
                previous = self._state(lineage_id, finding_id, row)
                revision = current_revision + 1
                operation = (
                    GovernanceOperation.CLEAR
                    if disposition is AnalystDisposition.UNREVIEWED
                    else GovernanceOperation.SET
                )
                if row is None:
                    row = SourceFindingGovernanceRow(
                        lineage_id=lineage_id,
                        finding_id=finding_id,
                        disposition=disposition.value,
                        reason=reason,
                        expires_at=expires_at,
                        revision=revision,
                        actor_type=LOCAL_OPERATOR,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(row)
                else:
                    row.disposition = disposition.value
                    row.reason = reason
                    row.expires_at = expires_at
                    row.revision = revision
                    row.actor_type = LOCAL_OPERATOR
                    row.updated_at = now
                session.flush()
                session.add(
                    SourceFindingGovernanceEventRow(
                        event_id=str(self._event_id_factory()),
                        lineage_id=lineage_id,
                        finding_id=finding_id,
                        operation=operation.value,
                        previous_disposition=previous.disposition.value,
                        new_disposition=disposition.value,
                        previous_reason=previous.reason,
                        new_reason=reason,
                        previous_expires_at=previous.expires_at,
                        new_expires_at=expires_at,
                        actor_type=LOCAL_OPERATOR,
                        occurred_at=now,
                        resulting_revision=revision,
                    )
                )
                session.flush()
                return self._state(lineage_id, finding_id, row)
        except (FindingGovernanceNotFoundError, FindingGovernanceConflictError):
            raise
        except FindingGovernanceValidationError:
            raise
        except IntegrityError:
            raise FindingGovernanceConflictError from None
        except (SQLAlchemyError, TypeError, ValueError):
            raise FindingGovernancePersistenceError from None

    def list_events(
        self,
        *,
        project_id: str,
        lineage_id: str,
        finding_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> FindingGovernanceEventPage:
        self._validate_identifiers(project_id, lineage_id, finding_id)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
            raise FindingGovernanceValidationError("limit must be between 1 and 200")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise FindingGovernanceValidationError("offset must be nonnegative")
        try:
            with self._sessions() as session:
                self._require_target(session, project_id, lineage_id, finding_id)
                total = session.scalar(
                    select(func.count())
                    .select_from(SourceFindingGovernanceEventRow)
                    .where(
                        SourceFindingGovernanceEventRow.lineage_id == lineage_id,
                        SourceFindingGovernanceEventRow.finding_id == finding_id,
                    )
                )
                rows = tuple(
                    session.scalars(
                        select(SourceFindingGovernanceEventRow)
                        .where(
                            SourceFindingGovernanceEventRow.lineage_id == lineage_id,
                            SourceFindingGovernanceEventRow.finding_id == finding_id,
                        )
                        .order_by(SourceFindingGovernanceEventRow.resulting_revision)
                        .limit(limit)
                        .offset(offset)
                    )
                )
                return FindingGovernanceEventPage(
                    items=tuple(self._event(item) for item in rows),
                    total=total,
                    limit=limit,
                    offset=offset,
                )
        except FindingGovernanceError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise FindingGovernancePersistenceError from None

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
            raise FindingGovernanceNotFoundError

    def _validate_mutation(self, disposition, reason, expires_at, expected_revision):
        if not isinstance(disposition, AnalystDisposition):
            raise FindingGovernanceValidationError("invalid disposition")
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 0
        ):
            raise FindingGovernanceValidationError("expected_revision must be nonnegative")
        if disposition is AnalystDisposition.UNREVIEWED:
            if reason is not None or expires_at is not None:
                raise FindingGovernanceValidationError("UNREVIEWED carries no reason or expiry")
            return disposition, None, None
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            raise FindingGovernanceValidationError("reason is required and bounded")
        if disposition is AnalystDisposition.FALSE_POSITIVE:
            if expires_at is not None:
                raise FindingGovernanceValidationError("FALSE_POSITIVE carries no expiry")
            return disposition, reason, None
        if expires_at is None or expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise FindingGovernanceValidationError("ACCEPTED_RISK requires an aware expiry")
        return disposition, reason, expires_at.astimezone(UTC)

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
            raise FindingGovernanceValidationError("invalid governance identifier")

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise FindingGovernancePersistenceError
        return value.astimezone(UTC)

    @staticmethod
    def _state(lineage_id, finding_id, row) -> FindingGovernance:
        if row is None:
            return FindingGovernance(
                lineage_id,
                finding_id,
                AnalystDisposition.UNREVIEWED,
                None,
                None,
                0,
                None,
                None,
                None,
            )
        return FindingGovernance(
            row.lineage_id,
            row.finding_id,
            AnalystDisposition(row.disposition),
            row.reason,
            SourceFindingGovernanceService._optional_utc(row.expires_at),
            row.revision,
            row.actor_type,
            SourceFindingGovernanceService._optional_utc(row.created_at),
            SourceFindingGovernanceService._optional_utc(row.updated_at),
        )

    @staticmethod
    def _event(row) -> FindingGovernanceEvent:
        return FindingGovernanceEvent(
            row.event_id,
            row.lineage_id,
            row.finding_id,
            GovernanceOperation(row.operation),
            AnalystDisposition(row.previous_disposition),
            AnalystDisposition(row.new_disposition),
            row.previous_reason,
            row.new_reason,
            SourceFindingGovernanceService._optional_utc(row.previous_expires_at),
            SourceFindingGovernanceService._optional_utc(row.new_expires_at),
            row.actor_type,
            SourceFindingGovernanceService._as_utc(row.occurred_at),
            row.resulting_revision,
        )

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _optional_utc(value: datetime | None) -> datetime | None:
        return None if value is None else SourceFindingGovernanceService._as_utc(value)
