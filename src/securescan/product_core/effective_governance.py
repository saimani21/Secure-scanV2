from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.persistence.database import (
    SourceFindingGovernanceEventRow,
    SourceFindingGovernanceRow,
    SourceFindingLifecycleEventRow,
    SourceFindingLifecycleRow,
    SourceFindingSuppressionEventRow,
    SourceFindingSuppressionRow,
    SourceTargetLineageRow,
    utc_now,
)
from securescan.product_core.governance import AnalystDisposition
from securescan.product_core.lifecycle import FindingLifecycleState

_FINDING_ID = re.compile(r"^[0-9a-f]{64}$")
_BULK_QUERY_SIZE = 200


class EffectiveGovernanceReasonCode(StrEnum):
    ACCEPTED_RISK_EFFECTIVE = "ACCEPTED_RISK_EFFECTIVE"
    ACCEPTED_RISK_EXPIRED = "ACCEPTED_RISK_EXPIRED"
    FALSE_POSITIVE_EFFECTIVE = "FALSE_POSITIVE_EFFECTIVE"
    FINDING_RESOLVED = "FINDING_RESOLVED"
    NO_GOVERNANCE = "NO_GOVERNANCE"
    PRE_REOPEN_GOVERNANCE_DORMANT = "PRE_REOPEN_GOVERNANCE_DORMANT"
    PRE_REOPEN_SUPPRESSION_DORMANT = "PRE_REOPEN_SUPPRESSION_DORMANT"
    REOPENED_REVIEW_REQUIRED = "REOPENED_REVIEW_REQUIRED"
    SUPPRESSION_EFFECTIVE = "SUPPRESSION_EFFECTIVE"
    SUPPRESSION_EXPIRED = "SUPPRESSION_EXPIRED"
    SUPPRESSION_REVOKED = "SUPPRESSION_REVOKED"


class EffectiveGovernanceError(Exception):
    pass


class EffectiveGovernanceNotFoundError(EffectiveGovernanceError):
    pass


class EffectiveGovernanceValidationError(EffectiveGovernanceError):
    pass


class EffectiveGovernancePersistenceError(EffectiveGovernanceError):
    pass


@dataclass(frozen=True, slots=True)
class EffectiveGovernance:
    lineage_id: str
    finding_id: str
    lifecycle_state: FindingLifecycleState
    current_episode_transition_version: int
    disposition: AnalystDisposition
    disposition_revision: int
    governance_lifecycle_transition_version: int | None
    false_positive_effective: bool
    accepted_risk_effective: bool
    accepted_risk_expires_at: datetime | None
    governance_last_changed_at: datetime | None
    suppression_present: bool
    suppression_effective: bool
    suppression_id: str | None
    suppression_revision: int
    suppression_lifecycle_transition_version: int | None
    suppression_expires_at: datetime | None
    suppression_revoked_at: datetime | None
    suppression_last_changed_at: datetime | None
    review_required: bool
    reason_codes: tuple[EffectiveGovernanceReasonCode, ...]
    evaluated_at: datetime


class EffectiveGovernanceService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._sessions = session_factory
        self._clock = clock

    def get(self, *, project_id: str, lineage_id: str, finding_id: str) -> EffectiveGovernance:
        self._validate_identifiers(project_id, lineage_id, finding_id)
        evaluated_at = self._now()
        try:
            with self._sessions() as session:
                return self.get_many_in_session(
                    session,
                    project_id=project_id,
                    lineage_id=lineage_id,
                    finding_ids=(finding_id,),
                    evaluated_at=evaluated_at,
                )[0]
        except EffectiveGovernanceError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise EffectiveGovernancePersistenceError from None

    def get_many(
        self,
        *,
        project_id: str,
        lineage_id: str,
        finding_ids: tuple[str, ...],
        evaluated_at: datetime | None = None,
    ) -> tuple[EffectiveGovernance, ...]:
        """Project a bounded finding set without one query per finding."""

        at = self._now() if evaluated_at is None else self._explicit_evaluated_at(evaluated_at)
        try:
            with self._sessions() as session:
                return self.get_many_in_session(
                    session,
                    project_id=project_id,
                    lineage_id=lineage_id,
                    finding_ids=finding_ids,
                    evaluated_at=at,
                )
        except EffectiveGovernanceError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise EffectiveGovernancePersistenceError from None

    def get_many_in_session(
        self,
        session: Session,
        *,
        project_id: str,
        lineage_id: str,
        finding_ids: tuple[str, ...],
        evaluated_at: datetime,
    ) -> tuple[EffectiveGovernance, ...]:
        """Project a bounded finding set in the caller's transaction and time domain."""
        self._validate_scope(project_id, lineage_id)
        evaluated_at = self._explicit_evaluated_at(evaluated_at)
        if not isinstance(finding_ids, tuple):
            raise EffectiveGovernanceValidationError("finding_ids must be a tuple")
        ordered_ids = tuple(sorted(finding_ids))
        if len(set(ordered_ids)) != len(ordered_ids):
            raise EffectiveGovernanceValidationError("duplicate effective-governance finding")
        for finding_id in ordered_ids:
            if not isinstance(finding_id, str) or _FINDING_ID.fullmatch(finding_id) is None:
                raise EffectiveGovernanceValidationError("invalid effective-governance identifier")
        if not ordered_ids:
            return ()

        try:
            rows_by_id = {}
            for offset in range(0, len(ordered_ids), _BULK_QUERY_SIZE):
                chunk = ordered_ids[offset : offset + _BULK_QUERY_SIZE]
                rows = (
                    session.execute(self._statement(lineage_id, project_id, chunk)).mappings().all()
                )
                for row in rows:
                    finding_id = row["finding_id"]
                    if finding_id in rows_by_id:
                        raise EffectiveGovernancePersistenceError
                    rows_by_id[finding_id] = row
            if set(rows_by_id) != set(ordered_ids):
                raise EffectiveGovernanceNotFoundError
            return tuple(
                self._project(lineage_id, finding_id, rows_by_id[finding_id], evaluated_at)
                for finding_id in ordered_ids
            )
        except EffectiveGovernanceError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise EffectiveGovernancePersistenceError from None

    @staticmethod
    def _statement(lineage_id: str, project_id: str, finding_ids: tuple[str, ...]):
        latest_reopen = (
            select(
                SourceFindingLifecycleEventRow.lineage_id.label("lineage_id"),
                SourceFindingLifecycleEventRow.finding_id.label("finding_id"),
                func.max(SourceFindingLifecycleEventRow.transition_version).label(
                    "transition_version"
                ),
            )
            .where(
                SourceFindingLifecycleEventRow.lineage_id == lineage_id,
                SourceFindingLifecycleEventRow.finding_id.in_(finding_ids),
                SourceFindingLifecycleEventRow.event_kind == "TRANSITION",
                SourceFindingLifecycleEventRow.resulting_state == "REOPENED",
            )
            .group_by(
                SourceFindingLifecycleEventRow.lineage_id,
                SourceFindingLifecycleEventRow.finding_id,
            )
            .subquery()
        )
        statement = (
            select(
                SourceFindingLifecycleRow.finding_id.label("finding_id"),
                SourceFindingLifecycleRow.current_state.label("lifecycle_state"),
                SourceFindingLifecycleRow.transition_version.label("lifecycle_version"),
                latest_reopen.c.transition_version.label("latest_reopen_version"),
                SourceFindingGovernanceRow.disposition.label("disposition"),
                SourceFindingGovernanceRow.expires_at.label("governance_expires_at"),
                SourceFindingGovernanceRow.revision.label("governance_revision"),
                SourceFindingGovernanceRow.updated_at.label("governance_updated_at"),
                SourceFindingGovernanceEventRow.event_id.label("governance_event_id"),
                SourceFindingGovernanceEventRow.lifecycle_transition_version.label(
                    "governance_lifecycle_version"
                ),
                SourceFindingSuppressionRow.suppression_id.label("suppression_id"),
                SourceFindingSuppressionRow.expires_at.label("suppression_expires_at"),
                SourceFindingSuppressionRow.revoked_at.label("suppression_revoked_at"),
                SourceFindingSuppressionRow.revision.label("suppression_revision"),
                SourceFindingSuppressionRow.updated_at.label("suppression_updated_at"),
                SourceFindingSuppressionEventRow.event_id.label("suppression_event_id"),
                SourceFindingSuppressionEventRow.lifecycle_transition_version.label(
                    "suppression_lifecycle_version"
                ),
            )
            .select_from(SourceTargetLineageRow)
            .join(
                SourceFindingLifecycleRow,
                SourceFindingLifecycleRow.lineage_id == SourceTargetLineageRow.lineage_id,
            )
            .outerjoin(
                latest_reopen,
                and_(
                    latest_reopen.c.lineage_id == SourceFindingLifecycleRow.lineage_id,
                    latest_reopen.c.finding_id == SourceFindingLifecycleRow.finding_id,
                ),
            )
            .outerjoin(
                SourceFindingGovernanceRow,
                and_(
                    SourceFindingGovernanceRow.lineage_id == SourceFindingLifecycleRow.lineage_id,
                    SourceFindingGovernanceRow.finding_id == SourceFindingLifecycleRow.finding_id,
                ),
            )
            .outerjoin(
                SourceFindingGovernanceEventRow,
                and_(
                    SourceFindingGovernanceEventRow.lineage_id
                    == SourceFindingGovernanceRow.lineage_id,
                    SourceFindingGovernanceEventRow.finding_id
                    == SourceFindingGovernanceRow.finding_id,
                    SourceFindingGovernanceEventRow.resulting_revision
                    == SourceFindingGovernanceRow.revision,
                ),
            )
            .outerjoin(
                SourceFindingSuppressionRow,
                and_(
                    SourceFindingSuppressionRow.lineage_id == SourceFindingLifecycleRow.lineage_id,
                    SourceFindingSuppressionRow.finding_id == SourceFindingLifecycleRow.finding_id,
                ),
            )
            .outerjoin(
                SourceFindingSuppressionEventRow,
                and_(
                    SourceFindingSuppressionEventRow.lineage_id
                    == SourceFindingSuppressionRow.lineage_id,
                    SourceFindingSuppressionEventRow.finding_id
                    == SourceFindingSuppressionRow.finding_id,
                    SourceFindingSuppressionEventRow.resulting_revision
                    == SourceFindingSuppressionRow.revision,
                ),
            )
            .where(
                SourceTargetLineageRow.lineage_id == lineage_id,
                SourceTargetLineageRow.project_id == project_id,
                SourceFindingLifecycleRow.finding_id.in_(finding_ids),
            )
        )
        return statement

    def _project(self, lineage_id, finding_id, row, evaluated_at) -> EffectiveGovernance:
        lifecycle_state = FindingLifecycleState(row["lifecycle_state"])
        lifecycle_version = row["lifecycle_version"]
        latest_reopen = row["latest_reopen_version"]
        if (
            not isinstance(lifecycle_version, int)
            or lifecycle_version < 1
            or latest_reopen is not None
            and (not isinstance(latest_reopen, int) or latest_reopen > lifecycle_version)
        ):
            raise EffectiveGovernancePersistenceError

        governance_present = row["governance_revision"] is not None
        suppression_present = row["suppression_revision"] is not None
        if governance_present != (row["governance_event_id"] is not None):
            raise EffectiveGovernancePersistenceError
        if suppression_present != (row["suppression_event_id"] is not None):
            raise EffectiveGovernancePersistenceError

        disposition = (
            AnalystDisposition(row["disposition"])
            if governance_present
            else AnalystDisposition.UNREVIEWED
        )
        governance_version = row["governance_lifecycle_version"]
        suppression_version = row["suppression_lifecycle_version"]
        if governance_present and (
            not isinstance(row["governance_revision"], int)
            or row["governance_revision"] < 1
            or governance_version is not None
            and (
                not isinstance(governance_version, int)
                or not 1 <= governance_version <= lifecycle_version
            )
        ):
            raise EffectiveGovernancePersistenceError
        if suppression_present and (
            not isinstance(row["suppression_revision"], int)
            or row["suppression_revision"] < 1
            or row["suppression_id"] is None
            or row["suppression_expires_at"] is None
            or suppression_version is not None
            and (
                not isinstance(suppression_version, int)
                or not 1 <= suppression_version <= lifecycle_version
            )
        ):
            raise EffectiveGovernancePersistenceError
        governance_current_episode = latest_reopen is None or (
            governance_version is not None and governance_version >= latest_reopen
        )
        suppression_current_episode = latest_reopen is None or (
            suppression_version is not None and suppression_version >= latest_reopen
        )
        lifecycle_active = lifecycle_state is not FindingLifecycleState.RESOLVED

        accepted_risk_expires_at = self._optional_utc(row["governance_expires_at"])
        if (
            disposition is AnalystDisposition.ACCEPTED_RISK and accepted_risk_expires_at is None
        ) or (
            disposition is not AnalystDisposition.ACCEPTED_RISK
            and accepted_risk_expires_at is not None
        ):
            raise EffectiveGovernancePersistenceError
        accepted_risk_temporally_active = (
            disposition is AnalystDisposition.ACCEPTED_RISK
            and accepted_risk_expires_at is not None
            and accepted_risk_expires_at > evaluated_at
        )
        false_positive_effective = (
            disposition is AnalystDisposition.FALSE_POSITIVE
            and lifecycle_active
            and governance_current_episode
        )
        accepted_risk_effective = (
            accepted_risk_temporally_active and lifecycle_active and governance_current_episode
        )

        suppression_expires_at = self._optional_utc(row["suppression_expires_at"])
        suppression_revoked_at = self._optional_utc(row["suppression_revoked_at"])
        suppression_temporally_active = (
            suppression_present
            and suppression_revoked_at is None
            and suppression_expires_at is not None
            and suppression_expires_at > evaluated_at
        )
        suppression_effective = (
            suppression_temporally_active and lifecycle_active and suppression_current_episode
        )

        pre_reopen_governance = (
            governance_present
            and latest_reopen is not None
            and not governance_current_episode
            and disposition in {AnalystDisposition.FALSE_POSITIVE, AnalystDisposition.ACCEPTED_RISK}
        )
        pre_reopen_suppression = (
            suppression_present and latest_reopen is not None and not suppression_current_episode
        )
        review_required = lifecycle_state is FindingLifecycleState.REOPENED and (
            (
                pre_reopen_governance
                and (
                    disposition is AnalystDisposition.FALSE_POSITIVE
                    or accepted_risk_temporally_active
                )
            )
            or (pre_reopen_suppression and suppression_temporally_active)
        )

        reasons: set[EffectiveGovernanceReasonCode] = set()
        if lifecycle_state is FindingLifecycleState.RESOLVED:
            reasons.add(EffectiveGovernanceReasonCode.FINDING_RESOLVED)
        if false_positive_effective:
            reasons.add(EffectiveGovernanceReasonCode.FALSE_POSITIVE_EFFECTIVE)
        if accepted_risk_effective:
            reasons.add(EffectiveGovernanceReasonCode.ACCEPTED_RISK_EFFECTIVE)
        if (
            disposition is AnalystDisposition.ACCEPTED_RISK
            and accepted_risk_expires_at is not None
            and accepted_risk_expires_at <= evaluated_at
        ):
            reasons.add(EffectiveGovernanceReasonCode.ACCEPTED_RISK_EXPIRED)
        if suppression_effective:
            reasons.add(EffectiveGovernanceReasonCode.SUPPRESSION_EFFECTIVE)
        if (
            suppression_present
            and suppression_expires_at is not None
            and suppression_expires_at <= evaluated_at
        ):
            reasons.add(EffectiveGovernanceReasonCode.SUPPRESSION_EXPIRED)
        if suppression_present and suppression_revoked_at is not None:
            reasons.add(EffectiveGovernanceReasonCode.SUPPRESSION_REVOKED)
        if pre_reopen_governance:
            reasons.add(EffectiveGovernanceReasonCode.PRE_REOPEN_GOVERNANCE_DORMANT)
        if pre_reopen_suppression:
            reasons.add(EffectiveGovernanceReasonCode.PRE_REOPEN_SUPPRESSION_DORMANT)
        if review_required:
            reasons.add(EffectiveGovernanceReasonCode.REOPENED_REVIEW_REQUIRED)
        if disposition is AnalystDisposition.UNREVIEWED and not suppression_present:
            reasons.add(EffectiveGovernanceReasonCode.NO_GOVERNANCE)

        current_episode_version = 1 if latest_reopen is None else latest_reopen
        return EffectiveGovernance(
            lineage_id=lineage_id,
            finding_id=finding_id,
            lifecycle_state=lifecycle_state,
            current_episode_transition_version=current_episode_version,
            disposition=disposition,
            disposition_revision=0 if not governance_present else row["governance_revision"],
            governance_lifecycle_transition_version=governance_version,
            false_positive_effective=false_positive_effective,
            accepted_risk_effective=accepted_risk_effective,
            accepted_risk_expires_at=accepted_risk_expires_at,
            governance_last_changed_at=self._optional_utc(row["governance_updated_at"]),
            suppression_present=suppression_present,
            suppression_effective=suppression_effective,
            suppression_id=row["suppression_id"],
            suppression_revision=0 if not suppression_present else row["suppression_revision"],
            suppression_lifecycle_transition_version=suppression_version,
            suppression_expires_at=suppression_expires_at,
            suppression_revoked_at=suppression_revoked_at,
            suppression_last_changed_at=self._optional_utc(row["suppression_updated_at"]),
            review_required=review_required,
            reason_codes=tuple(sorted(reasons, key=lambda item: item.value)),
            evaluated_at=evaluated_at,
        )

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
            raise EffectiveGovernanceValidationError("invalid effective-governance identifier")

    @staticmethod
    def _validate_scope(project_id: str, lineage_id: str) -> None:
        try:
            valid = (
                isinstance(project_id, str)
                and str(UUID(project_id)) == project_id
                and isinstance(lineage_id, str)
                and str(UUID(lineage_id)) == lineage_id
            )
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            raise EffectiveGovernanceValidationError("invalid effective-governance identifier")

    @staticmethod
    def _explicit_evaluated_at(value: datetime) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise EffectiveGovernanceValidationError("evaluated_at must be timezone-aware")
        return value.astimezone(UTC)

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise EffectiveGovernancePersistenceError
        return value.astimezone(UTC)

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _optional_utc(value: datetime | None) -> datetime | None:
        return None if value is None else EffectiveGovernanceService._as_utc(value)
