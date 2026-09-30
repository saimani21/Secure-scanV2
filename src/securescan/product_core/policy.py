"""Trusted, typed security policy over one candidate/baseline snapshot."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, StrictBool, ValidationError, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.persistence.database import (
    SourceLineageRunRow,
    SourcePolicyDefinitionRow,
    SourcePolicyEvaluationRow,
    SourceTargetLineageRow,
    utc_now,
)

from .effective_governance import (
    EffectiveGovernance,
    EffectiveGovernanceError,
    EffectiveGovernanceService,
)
from .lifecycle import (
    CandidateFindingFact,
    PriorityBand,
    ProductCoreLifecycleError,
    SourceFindingLifecycleService,
)
from .security_delta import (
    SecurityDelta,
    SecurityDeltaComparisonStatus,
    SecurityDeltaError,
    SecurityDeltaFinding,
    SecurityDeltaNotFoundError,
    SecurityDeltaState,
    SourceSecurityDeltaService,
)

POLICY_SCHEMA_VERSION = "securescan-source-policy-v1"
_POLICY_NAMESPACE = UUID("4e44b525-7831-4d62-8663-a09668417095")
_AUTHORITIES = frozenset({"checkov", "gitleaks", "osv.dev", "semgrep-ce"})


class PolicyAction(StrEnum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    FAIL = "FAIL"


class PolicyResult(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class PolicyDecisionKind(StrEnum):
    VIOLATION = "VIOLATION"
    WARNING = "WARNING"
    ERROR = "ERROR"
    EXCLUSION = "EXCLUSION"


class PolicyError(Exception):
    pass


class PolicyNotFoundError(PolicyError):
    pass


class PolicyConflictError(PolicyError):
    pass


class PolicyValidationError(PolicyError):
    pass


class PolicyPersistenceError(PolicyError):
    pass


class PriorityActions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    CRITICAL: PolicyAction
    HIGH: PolicyAction
    MEDIUM: PolicyAction
    LOW: PolicyAction
    INFO: PolicyAction
    UNRANKED: PolicyAction

    def for_band(self, band: PriorityBand) -> PolicyAction:
        return getattr(self, band.value)


class PolicySpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["securescan-source-policy-v1"]
    required_authorities: tuple[str, ...]
    introduced: PriorityActions
    present: PriorityActions
    reopened: PriorityActions
    secret_introduced_fail: StrictBool
    exclude_false_positive: StrictBool
    exclude_accepted_risk: StrictBool
    exclude_suppression: StrictBool

    @field_validator("required_authorities", mode="before")
    @classmethod
    def validate_authorities(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, (list, tuple)) or not value:
            raise ValueError("required_authorities must be a nonempty list")
        if any(type(item) is not str or item not in _AUTHORITIES for item in value):
            raise ValueError("unknown required authority")
        if len(set(value)) != len(value):
            raise ValueError("duplicate required authority")
        return tuple(sorted(value))


DEFAULT_POLICY = PolicySpec.model_validate(
    {
        "schema_version": POLICY_SCHEMA_VERSION,
        "required_authorities": sorted(_AUTHORITIES),
        "introduced": {
            "CRITICAL": "FAIL",
            "HIGH": "FAIL",
            "MEDIUM": "WARN",
            "LOW": "ALLOW",
            "INFO": "ALLOW",
            "UNRANKED": "ALLOW",
        },
        "present": {band.value: "ALLOW" for band in PriorityBand},
        "reopened": {
            "CRITICAL": "FAIL",
            "HIGH": "FAIL",
            "MEDIUM": "WARN",
            "LOW": "ALLOW",
            "INFO": "ALLOW",
            "UNRANKED": "ALLOW",
        },
        "secret_introduced_fail": True,
        "exclude_false_positive": True,
        "exclude_accepted_risk": True,
        "exclude_suppression": True,
    }
)


def _canonical_definition(spec: PolicySpec) -> dict:
    return spec.model_dump(mode="json")


def _digest(spec: PolicySpec) -> str:
    data = json.dumps(
        _canonical_definition(spec),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedPolicy:
    policy_id: str
    lineage_id: str
    version: int
    digest: str
    definition: PolicySpec
    actor_type: str
    created_at: datetime | None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    kind: PolicyDecisionKind
    rule_id: str
    reason_code: str
    finding_id: str | None = None
    authority: str | None = None
    category: str | None = None
    delta_state: SecurityDeltaState | None = None
    priority: PriorityBand | None = None
    source_reason_codes: tuple[str, ...] = ()

    def canonical_data(self) -> dict:
        return {
            "kind": self.kind.value,
            "rule_id": self.rule_id,
            "reason_code": self.reason_code,
            "finding_id": self.finding_id,
            "authority": self.authority,
            "category": self.category,
            "delta_state": None if self.delta_state is None else self.delta_state.value,
            "priority": None if self.priority is None else self.priority.value,
            "source_reason_codes": list(self.source_reason_codes),
        }


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    evaluation_id: str
    lineage_id: str
    candidate_run_id: str
    baseline_id: str | None
    baseline_revision: int | None
    policy_id: str
    policy_version: int
    policy_digest: str
    result: PolicyResult
    decisions: tuple[PolicyDecision, ...]
    evaluated_at: datetime


class SourcePolicyService:
    """Read trusted policy and persist decisions from a single RR transaction."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        *,
        clock: Callable[[], datetime] = utc_now,
        evaluation_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._sessions = session_factory
        self._delta = SourceSecurityDeltaService(session_factory, artifact_store)
        self._lifecycle = SourceFindingLifecycleService(session_factory, artifact_store)
        self._governance = EffectiveGovernanceService(session_factory)
        self._clock = clock
        self._evaluation_id_factory = evaluation_id_factory

    def get_policy(self, *, project_id: str, lineage_id: str) -> TrustedPolicy:
        self._validate_ids(project_id, lineage_id)
        try:
            with self._sessions() as session:
                self._require_lineage(session, project_id, lineage_id)
                return self._current_policy(session, lineage_id)
        except PolicyError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise PolicyPersistenceError from None

    def update_policy(
        self,
        *,
        project_id: str,
        lineage_id: str,
        expected_version: int,
        definition: Mapping[str, object],
    ) -> TrustedPolicy:
        self._validate_ids(project_id, lineage_id)
        if type(expected_version) is not int or expected_version < 1:
            raise PolicyValidationError("expected_version must be positive")
        spec = self._parse_spec(definition)
        now = self._now()
        try:
            with self._sessions.begin() as session:
                self._require_lineage(session, project_id, lineage_id, lock=True)
                current = self._current_policy(session, lineage_id)
                if current.version != expected_version:
                    raise PolicyConflictError
                row = SourcePolicyDefinitionRow(
                    lineage_id=lineage_id,
                    version=current.version + 1,
                    policy_id=current.policy_id,
                    digest=_digest(spec),
                    definition_json=_canonical_definition(spec),
                    actor_type="LOCAL_OPERATOR",
                    created_at=now,
                )
                session.add(row)
                session.flush()
                return self._policy_record(row)
        except PolicyError:
            raise
        except IntegrityError:
            raise PolicyConflictError from None
        except (SQLAlchemyError, TypeError, ValueError):
            raise PolicyPersistenceError from None

    def evaluate(
        self, *, project_id: str, lineage_id: str, candidate_run_id: str
    ) -> PolicyEvaluation:
        self._validate_ids(project_id, lineage_id, candidate_run_id)
        evaluated_at = self._now()
        try:
            with self._sessions.begin() as session:
                if session.get_bind().dialect.name == "postgresql":
                    session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                self._require_lineage(session, project_id, lineage_id)
                candidate = session.get(SourceLineageRunRow, candidate_run_id)
                if candidate is None or candidate.lineage_id != lineage_id:
                    raise PolicyNotFoundError
                policy = self._current_policy(session, lineage_id)
                baseline_id: str | None = None
                baseline_revision: int | None = None
                try:
                    delta = self._delta.evaluate_in_session(
                        session,
                        project_id=project_id,
                        lineage_id=lineage_id,
                        candidate_run_id=candidate_run_id,
                    )
                    baseline_id = delta.baseline_id
                    baseline_revision = delta.baseline_revision
                    facts = self._lifecycle.load_candidate_facts_in_session(
                        session,
                        project_id=project_id,
                        lineage_id=lineage_id,
                        run_id=candidate_run_id,
                    )
                    required_facts = tuple(
                        item
                        for item in facts
                        if item.authority in policy.definition.required_authorities
                    )
                    governance = self._governance.get_many_in_session(
                        session,
                        project_id=project_id,
                        lineage_id=lineage_id,
                        finding_ids=tuple(item.finding_id for item in required_facts),
                        evaluated_at=evaluated_at,
                    )
                    decisions = self._decide(policy.definition, delta, facts, governance)
                except SecurityDeltaNotFoundError:
                    decisions = (self._error("BASELINE_UNAVAILABLE"),)
                except (SecurityDeltaError, ProductCoreLifecycleError, EffectiveGovernanceError):
                    decisions = (self._error("REQUIRED_FACTS_UNAVAILABLE"),)

                result = (
                    PolicyResult.ERROR
                    if any(item.kind is PolicyDecisionKind.ERROR for item in decisions)
                    else PolicyResult.FAIL
                    if any(item.kind is PolicyDecisionKind.VIOLATION for item in decisions)
                    else PolicyResult.PASS
                )
                row = SourcePolicyEvaluationRow(
                    evaluation_id=str(self._evaluation_id_factory()),
                    lineage_id=lineage_id,
                    candidate_run_id=candidate_run_id,
                    baseline_id=baseline_id,
                    baseline_revision=baseline_revision,
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    policy_digest=policy.digest,
                    result=result.value,
                    decisions_json=[item.canonical_data() for item in decisions],
                    evaluated_at=evaluated_at,
                )
                session.add(row)
                session.flush()
                return self._evaluation_record(row)
        except PolicyError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise PolicyPersistenceError from None

    def get_evaluation(
        self, *, project_id: str, lineage_id: str, evaluation_id: str
    ) -> PolicyEvaluation:
        self._validate_ids(project_id, lineage_id, evaluation_id)
        try:
            with self._sessions() as session:
                self._require_lineage(session, project_id, lineage_id)
                row = session.get(SourcePolicyEvaluationRow, evaluation_id)
                if row is None or row.lineage_id != lineage_id:
                    raise PolicyNotFoundError
                return self._evaluation_record(row)
        except PolicyError:
            raise
        except (SQLAlchemyError, TypeError, ValueError):
            raise PolicyPersistenceError from None

    @staticmethod
    def _decide(
        spec: PolicySpec,
        delta: SecurityDelta,
        facts: tuple[CandidateFindingFact, ...],
        governance: tuple[EffectiveGovernance, ...],
    ) -> tuple[PolicyDecision, ...]:
        facts_by_id = {item.finding_id: item for item in facts}
        governance_by_id = {item.finding_id: item for item in governance}
        if len(facts_by_id) != len(facts) or len(governance_by_id) != len(governance):
            return (SourcePolicyService._error("REQUIRED_FACTS_UNAVAILABLE"),)
        required = set(spec.required_authorities)
        summaries = {item.authority: item for item in delta.authority_summaries}
        decisions: list[PolicyDecision] = []
        for authority in sorted(required):
            summary = summaries.get(authority)
            if summary is None:
                decisions.append(
                    SourcePolicyService._error("REQUIRED_AUTHORITY_MISSING", authority=authority)
                )
            elif summary.comparison_status is not SecurityDeltaComparisonStatus.COMPLETE:
                code = (
                    "REQUIRED_AUTHORITY_NOT_COMPARABLE"
                    if summary.comparison_status is SecurityDeltaComparisonStatus.NOT_COMPARABLE
                    else "REQUIRED_COVERAGE_INCOMPLETE"
                )
                decisions.append(
                    SourcePolicyService._error(
                        code, authority=authority, source_reason_codes=summary.reason_codes
                    )
                )
        for finding in sorted(delta.findings, key=lambda item: item.finding_id):
            if finding.authority not in required:
                continue
            if finding.state is SecurityDeltaState.NOT_COMPARABLE:
                decisions.append(
                    SourcePolicyService._error(
                        "REQUIRED_FINDING_NOT_COMPARABLE",
                        finding=finding,
                        source_reason_codes=finding.reason_codes,
                    )
                )
                continue
            if finding.state is SecurityDeltaState.REMOVED:
                continue
            fact = facts_by_id.get(finding.finding_id)
            effective = governance_by_id.get(finding.finding_id)
            if (
                fact is None
                or effective is None
                or fact.authority != finding.authority
                or fact.category != finding.category
            ):
                decisions.append(
                    SourcePolicyService._error("REQUIRED_FACTS_UNAVAILABLE", finding=finding)
                )
                continue
            rules: list[tuple[str, PolicyAction]] = []
            if finding.state is SecurityDeltaState.INTRODUCED:
                rules.append(
                    (
                        "INTRODUCED_" + fact.priority_band.value,
                        spec.introduced.for_band(fact.priority_band),
                    )
                )
                if (
                    fact.category == "SECRET_EXPOSURE"
                    and fact.authority == "gitleaks"
                    and spec.secret_introduced_fail
                ):
                    rules.append(("SECRET_INTRODUCED", PolicyAction.FAIL))
            elif finding.state is SecurityDeltaState.PRESENT:
                rules.append(
                    (
                        "PRESENT_" + fact.priority_band.value,
                        spec.present.for_band(fact.priority_band),
                    )
                )
            if fact.lifecycle_state.value == "REOPENED":
                rules.append(
                    (
                        "REOPENED_" + fact.priority_band.value,
                        spec.reopened.for_band(fact.priority_band),
                    )
                )
            for rule_id, action in rules:
                if action is PolicyAction.ALLOW:
                    continue
                exclusion = SourcePolicyService._exclusion(spec, effective)
                kind = (
                    PolicyDecisionKind.EXCLUSION
                    if action is PolicyAction.FAIL and exclusion
                    else PolicyDecisionKind.VIOLATION
                    if action is PolicyAction.FAIL
                    else PolicyDecisionKind.WARNING
                )
                decisions.append(
                    PolicyDecision(
                        kind=kind,
                        rule_id=rule_id,
                        reason_code=exclusion if kind is PolicyDecisionKind.EXCLUSION else rule_id,
                        finding_id=finding.finding_id,
                        authority=finding.authority,
                        category=finding.category,
                        delta_state=finding.state,
                        priority=fact.priority_band,
                    )
                )
        return tuple(
            sorted(
                decisions,
                key=lambda item: (
                    item.kind.value,
                    item.authority or "",
                    item.finding_id or "",
                    item.rule_id,
                ),
            )
        )

    @staticmethod
    def _exclusion(spec: PolicySpec, effective: EffectiveGovernance) -> str | None:
        if spec.exclude_false_positive and effective.false_positive_effective:
            return "EXCLUDED_EFFECTIVE_FALSE_POSITIVE"
        if spec.exclude_accepted_risk and effective.accepted_risk_effective:
            return "EXCLUDED_EFFECTIVE_ACCEPTED_RISK"
        if spec.exclude_suppression and effective.suppression_effective:
            return "EXCLUDED_EFFECTIVE_SUPPRESSION"
        return None

    @staticmethod
    def _error(
        code: str,
        *,
        authority: str | None = None,
        finding: SecurityDeltaFinding | None = None,
        source_reason_codes: tuple[str, ...] = (),
    ) -> PolicyDecision:
        return PolicyDecision(
            kind=PolicyDecisionKind.ERROR,
            rule_id="REQUIRED_EVIDENCE",
            reason_code=code,
            finding_id=None if finding is None else finding.finding_id,
            authority=authority if finding is None else finding.authority,
            category=None if finding is None else finding.category,
            delta_state=None if finding is None else finding.state,
            source_reason_codes=tuple(sorted(source_reason_codes)),
        )

    @staticmethod
    def _policy_id(lineage_id: str) -> str:
        return str(uuid5(_POLICY_NAMESPACE, lineage_id))

    @staticmethod
    def _parse_spec(definition: Mapping[str, object]) -> PolicySpec:
        if not isinstance(definition, Mapping):
            raise PolicyValidationError("policy definition must be an object")
        try:
            return PolicySpec.model_validate(dict(definition))
        except ValidationError:
            raise PolicyValidationError("invalid typed policy definition") from None

    @staticmethod
    def _policy_record(row: SourcePolicyDefinitionRow) -> TrustedPolicy:
        try:
            spec = SourcePolicyService._parse_spec(row.definition_json)
        except PolicyValidationError:
            raise PolicyPersistenceError from None
        if (
            row.version < 2
            or row.actor_type != "LOCAL_OPERATOR"
            or row.policy_id != SourcePolicyService._policy_id(row.lineage_id)
            or row.digest != _digest(spec)
            or row.definition_json != _canonical_definition(spec)
        ):
            raise PolicyPersistenceError
        return TrustedPolicy(
            policy_id=row.policy_id,
            lineage_id=row.lineage_id,
            version=row.version,
            digest=row.digest,
            definition=spec,
            actor_type=row.actor_type,
            created_at=SourcePolicyService._as_utc(row.created_at),
        )

    @staticmethod
    def _current_policy(session: Session, lineage_id: str) -> TrustedPolicy:
        row = session.scalar(
            select(SourcePolicyDefinitionRow)
            .where(SourcePolicyDefinitionRow.lineage_id == lineage_id)
            .order_by(SourcePolicyDefinitionRow.version.desc())
            .limit(1)
        )
        if row is not None:
            return SourcePolicyService._policy_record(row)
        return TrustedPolicy(
            policy_id=SourcePolicyService._policy_id(lineage_id),
            lineage_id=lineage_id,
            version=1,
            digest=_digest(DEFAULT_POLICY),
            definition=DEFAULT_POLICY,
            actor_type="BUILTIN",
            created_at=None,
        )

    @staticmethod
    def _evaluation_record(row: SourcePolicyEvaluationRow) -> PolicyEvaluation:
        try:
            decisions = tuple(
                PolicyDecision(
                    kind=PolicyDecisionKind(item["kind"]),
                    rule_id=item["rule_id"],
                    reason_code=item["reason_code"],
                    finding_id=item["finding_id"],
                    authority=item["authority"],
                    category=item["category"],
                    delta_state=None
                    if item["delta_state"] is None
                    else SecurityDeltaState(item["delta_state"]),
                    priority=None if item["priority"] is None else PriorityBand(item["priority"]),
                    source_reason_codes=tuple(item["source_reason_codes"]),
                )
                for item in row.decisions_json
            )
            result = PolicyResult(row.result)
        except (KeyError, TypeError, ValueError):
            raise PolicyPersistenceError from None
        if (
            any(
                item.canonical_data() != raw
                for item, raw in zip(decisions, row.decisions_json, strict=True)
            )
            or (row.baseline_id is None) != (row.baseline_revision is None)
            or row.policy_version < 1
        ):
            raise PolicyPersistenceError
        return PolicyEvaluation(
            evaluation_id=row.evaluation_id,
            lineage_id=row.lineage_id,
            candidate_run_id=row.candidate_run_id,
            baseline_id=row.baseline_id,
            baseline_revision=row.baseline_revision,
            policy_id=row.policy_id,
            policy_version=row.policy_version,
            policy_digest=row.policy_digest,
            result=result,
            decisions=decisions,
            evaluated_at=SourcePolicyService._as_utc(row.evaluated_at),
        )

    @staticmethod
    def _require_lineage(
        session: Session, project_id: str, lineage_id: str, *, lock: bool = False
    ) -> None:
        statement = select(SourceTargetLineageRow).where(
            SourceTargetLineageRow.lineage_id == lineage_id,
            SourceTargetLineageRow.project_id == project_id,
        )
        if lock:
            statement = statement.with_for_update()
        if session.scalar(statement) is None:
            raise PolicyNotFoundError

    @staticmethod
    def _validate_ids(*values: str) -> None:
        try:
            valid = all(type(value) is str and str(UUID(value)) == value for value in values)
        except (TypeError, ValueError, AttributeError):
            valid = False
        if not valid:
            raise PolicyValidationError("invalid policy identifier")

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise PolicyPersistenceError
        return value.astimezone(UTC)

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
