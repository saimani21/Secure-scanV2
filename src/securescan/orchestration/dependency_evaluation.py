from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.advisories.osv.models import OsvPackageGap, build_osv_query_candidates
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ArtifactKind, ExecutionOutcome, JobStatus
from securescan.persistence.database import (
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationDependencyEvaluationRow,
    SourceOrchestrationDependencyRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    ToolExecutionRow,
    utc_now,
)
from securescan.scanners.syft.parser import (
    PackageObservation,
    SyftParseResult,
)
from securescan.source.enums import AnalysisCapability
from securescan.source.planning import SourcePlanAction

from .execution_models import (
    SAFE_NATIVE_RESULT_MEDIA_TYPE,
    SAFE_NATIVE_RESULT_SCHEMA_VERSION,
    SafeSourceNativeResult,
    SourceScannerExecutionIntegrityError,
)
from .models import (
    OrchestrationContainmentState,
    OrchestrationLifecycleState,
    OrchestrationNodeDisposition,
    OrchestrationNodeLifecycleState,
    PlannedSourceNode,
    SourceAuthority,
    SourceOrchestrationIntegrityError,
    SourcePlanningSnapshot,
)
from .service import SourcePlanningSnapshotStore

DEPENDENCY_EVALUATION_SCHEMA_VERSION = "securescan-source-dependency-evaluation-s6c-v1"
DEPENDENCY_EVALUATION_MEDIA_TYPE = "application/vnd.securescan.source-dependency-evaluation+json"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z", re.ASCII)
_OSV_ANALYZER_ID = "osv-dependency-advisory-v1"


class SourceDependencyEvaluationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Source dependency evaluation failed")


class SourceDependencyEvaluationConflictError(SourceDependencyEvaluationError):
    pass


class PackageScopeClassification(StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUTSIDE_SCOPE = "OUTSIDE_SCOPE"
    MIXED_SCOPE = "MIXED_SCOPE"


class DependencyEvaluationDecision(StrEnum):
    OSV_RUN_REQUIRED = "OSV_RUN_REQUIRED"
    NOT_APPLICABLE_NO_PACKAGES = "NOT_APPLICABLE_NO_PACKAGES"
    NOT_APPLICABLE_NO_PACKAGES_IN_SCOPE = "NOT_APPLICABLE_NO_PACKAGES_IN_SCOPE"
    PARTIAL_NO_SUPPORTED_COORDINATES = "PARTIAL_NO_SUPPORTED_COORDINATES"
    PARTIAL_PREREQUISITE_INCOMPLETE = "PARTIAL_PREREQUISITE_INCOMPLETE"


@dataclass(frozen=True, slots=True)
class DependencyScopeEvidence:
    selected_paths: tuple[str, ...]
    scope_digest: str

    def __post_init__(self) -> None:
        if (
            not self.selected_paths
            or self.selected_paths != tuple(sorted(set(self.selected_paths)))
            or any(not _valid_relative_path(item) for item in self.selected_paths)
            or _SHA256.fullmatch(self.scope_digest) is None
        ):
            raise SourceDependencyEvaluationError

    def canonical_data(self) -> dict[str, Any]:
        return {"scope_digest": self.scope_digest, "selected_paths": list(self.selected_paths)}


@dataclass(frozen=True, slots=True)
class SyftPrerequisiteEvidence:
    node_id: str
    job_id: str
    selected_attempt_number: int
    native_result_sha256: str
    prerequisite_complete: bool

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.node_id) is None
            or not _valid_uuid(self.job_id)
            or type(self.selected_attempt_number) is not int
            or self.selected_attempt_number < 1
            or _SHA256.fullmatch(self.native_result_sha256) is None
            or type(self.prerequisite_complete) is not bool
        ):
            raise SourceDependencyEvaluationError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "native_result_sha256": self.native_result_sha256,
            "node_id": self.node_id,
            "prerequisite_complete": self.prerequisite_complete,
            "selected_attempt_number": self.selected_attempt_number,
        }


@dataclass(frozen=True, slots=True)
class PackageScopeEvidence:
    package_observation_id: str
    package_key: str
    locations: tuple[str, ...]
    classification: PackageScopeClassification

    def __post_init__(self) -> None:
        if (
            _SHA256.fullmatch(self.package_observation_id) is None
            or _SHA256.fullmatch(self.package_key) is None
            or not self.locations
            or self.locations != tuple(sorted(set(self.locations)))
            or any(not _valid_relative_path(item) for item in self.locations)
            or not isinstance(self.classification, PackageScopeClassification)
        ):
            raise SourceDependencyEvaluationError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "locations": list(self.locations),
            "package_key": self.package_key,
            "package_observation_id": self.package_observation_id,
        }


@dataclass(frozen=True, slots=True)
class DependencyGapEvidence:
    reason_code: str
    package_key: str
    package_observation_ids: tuple[str, ...]
    locations: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            _REASON.fullmatch(self.reason_code) is None
            or _SHA256.fullmatch(self.package_key) is None
            or not self.package_observation_ids
            or self.package_observation_ids != tuple(sorted(set(self.package_observation_ids)))
            or any(_SHA256.fullmatch(item) is None for item in self.package_observation_ids)
            or not self.locations
            or self.locations != tuple(sorted(set(self.locations)))
            or any(not _valid_relative_path(item) for item in self.locations)
        ):
            raise SourceDependencyEvaluationError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "locations": list(self.locations),
            "package_key": self.package_key,
            "package_observation_ids": list(self.package_observation_ids),
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class SourceDependencyEvaluation:
    run_id: str
    osv_node_id: str
    scope: DependencyScopeEvidence
    syft_prerequisite: SyftPrerequisiteEvidence
    observations: tuple[PackageScopeEvidence, ...]
    mixed_scope_gaps: tuple[DependencyGapEvidence, ...]
    eligible_package_observation_ids: tuple[str, ...]
    candidate_ids: tuple[str, ...]
    coordinate_gaps: tuple[DependencyGapEvidence, ...]
    decision: DependencyEvaluationDecision
    coverage_limited: bool
    schema_version: str = DEPENDENCY_EVALUATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        observation_ids = tuple(item.package_observation_id for item in self.observations)
        mixed_ids = {
            item.package_observation_id
            for item in self.observations
            if item.classification is PackageScopeClassification.MIXED_SCOPE
        }
        gap_mixed_ids = {
            identity for gap in self.mixed_scope_gaps for identity in gap.package_observation_ids
        }
        in_scope_ids = {
            item.package_observation_id
            for item in self.observations
            if item.classification is PackageScopeClassification.IN_SCOPE
        }
        expected_decision = _expected_decision(
            prerequisite_complete=self.syft_prerequisite.prerequisite_complete,
            observation_count=len(self.observations),
            in_scope_count=len(in_scope_ids),
            mixed_count=len(mixed_ids),
            candidate_count=len(self.candidate_ids),
        )
        expected_coverage_limited = bool(
            self.mixed_scope_gaps
            or self.coordinate_gaps
            or not self.syft_prerequisite.prerequisite_complete
        )
        if (
            self.schema_version != DEPENDENCY_EVALUATION_SCHEMA_VERSION
            or not _valid_uuid(self.run_id)
            or _SHA256.fullmatch(self.osv_node_id) is None
            or not isinstance(self.scope, DependencyScopeEvidence)
            or not isinstance(self.syft_prerequisite, SyftPrerequisiteEvidence)
            or self.observations
            != tuple(sorted(self.observations, key=lambda item: item.package_observation_id))
            or len(set(observation_ids)) != len(observation_ids)
            or self.mixed_scope_gaps
            != tuple(
                sorted(
                    self.mixed_scope_gaps,
                    key=lambda item: (item.package_key, item.package_observation_ids),
                )
            )
            or gap_mixed_ids != mixed_ids
            or any(
                gap.reason_code != "MIXED_SCOPE_PACKAGE_OBSERVATION"
                for gap in self.mixed_scope_gaps
            )
            or self.eligible_package_observation_ids
            != tuple(sorted(set(self.eligible_package_observation_ids)))
            or set(self.eligible_package_observation_ids) != in_scope_ids
            or self.candidate_ids != tuple(sorted(set(self.candidate_ids)))
            or any(_SHA256.fullmatch(item) is None for item in self.candidate_ids)
            or self.coordinate_gaps
            != tuple(
                sorted(
                    self.coordinate_gaps,
                    key=lambda item: (item.package_key, item.package_observation_ids),
                )
            )
            or any(
                not set(gap.package_observation_ids).issubset(in_scope_ids)
                for gap in self.coordinate_gaps
            )
            or not isinstance(self.decision, DependencyEvaluationDecision)
            or type(self.coverage_limited) is not bool
            or self.decision is not expected_decision
            or self.coverage_limited is not expected_coverage_limited
        ):
            raise SourceDependencyEvaluationError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "candidate_ids": list(self.candidate_ids),
            "coordinate_gaps": [item.canonical_data() for item in self.coordinate_gaps],
            "coverage_limited": self.coverage_limited,
            "decision": self.decision.value,
            "eligible_package_observation_ids": list(self.eligible_package_observation_ids),
            "mixed_scope_gaps": [item.canonical_data() for item in self.mixed_scope_gaps],
            "observations": [item.canonical_data() for item in self.observations],
            "osv_node_id": self.osv_node_id,
            "run_id": self.run_id,
            "schema_version": self.schema_version,
            "scope": self.scope.canonical_data(),
            "syft_prerequisite": self.syft_prerequisite.canonical_data(),
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.canonical_data())

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json()).hexdigest()

    @classmethod
    def from_json(cls, payload: bytes) -> SourceDependencyEvaluation:
        try:
            root = _load_json(payload)
            if set(root) != {
                "candidate_ids",
                "coordinate_gaps",
                "coverage_limited",
                "decision",
                "eligible_package_observation_ids",
                "mixed_scope_gaps",
                "observations",
                "osv_node_id",
                "run_id",
                "schema_version",
                "scope",
                "syft_prerequisite",
            }:
                raise ValueError
            scope = _require_dict(root["scope"], {"scope_digest", "selected_paths"})
            prerequisite = _require_dict(
                root["syft_prerequisite"],
                {
                    "job_id",
                    "native_result_sha256",
                    "node_id",
                    "prerequisite_complete",
                    "selected_attempt_number",
                },
            )
            result = cls(
                run_id=root["run_id"],
                osv_node_id=root["osv_node_id"],
                scope=DependencyScopeEvidence(
                    selected_paths=tuple(scope["selected_paths"]),
                    scope_digest=scope["scope_digest"],
                ),
                syft_prerequisite=SyftPrerequisiteEvidence(
                    node_id=prerequisite["node_id"],
                    job_id=prerequisite["job_id"],
                    selected_attempt_number=prerequisite["selected_attempt_number"],
                    native_result_sha256=prerequisite["native_result_sha256"],
                    prerequisite_complete=prerequisite["prerequisite_complete"],
                ),
                observations=tuple(_parse_observation(item) for item in root["observations"]),
                mixed_scope_gaps=tuple(_parse_gap(item) for item in root["mixed_scope_gaps"]),
                eligible_package_observation_ids=tuple(root["eligible_package_observation_ids"]),
                candidate_ids=tuple(root["candidate_ids"]),
                coordinate_gaps=tuple(_parse_gap(item) for item in root["coordinate_gaps"]),
                decision=DependencyEvaluationDecision(root["decision"]),
                coverage_limited=root["coverage_limited"],
                schema_version=root["schema_version"],
            )
            if result.canonical_json() != payload:
                raise ValueError
            return result
        except (KeyError, TypeError, ValueError, UnicodeError, SourceDependencyEvaluationError):
            raise SourceDependencyEvaluationError from None


@dataclass(frozen=True, slots=True)
class SourceDependencyEvaluationRecord:
    evaluation: SourceDependencyEvaluation
    artifact_sha256: str
    artifact_size_bytes: int
    storage_path: str
    created: bool


class SourceDependencyEvaluationService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        *,
        clock: Any = utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._artifacts = artifact_store
        self._snapshots = SourcePlanningSnapshotStore(artifact_store)
        self._clock = clock

    def evaluate(self, *, run_id: str, osv_node_id: str) -> SourceDependencyEvaluationRecord:
        if not _valid_uuid(run_id) or _SHA256.fullmatch(osv_node_id or "") is None:
            raise SourceDependencyEvaluationError
        try:
            with self._session_factory.begin() as session:
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == run_id)
                    .with_for_update()
                )
                if parent is None:
                    raise SourceDependencyEvaluationError
                snapshot = self._load_snapshot(parent)
                expected_osv, expected_syft, selected_paths = _scope_from_snapshot(
                    snapshot, osv_node_id
                )
                nodes = tuple(
                    session.scalars(
                        select(SourceOrchestrationNodeRow)
                        .where(
                            SourceOrchestrationNodeRow.run_id == run_id,
                            SourceOrchestrationNodeRow.node_id.in_(
                                sorted((expected_osv.node_id, expected_syft.node_id))
                            ),
                        )
                        .order_by(SourceOrchestrationNodeRow.node_id)
                        .with_for_update()
                    )
                )
                by_id = {item.node_id: item for item in nodes}
                osv_node = by_id.get(expected_osv.node_id)
                syft_node = by_id.get(expected_syft.node_id)
                dependency = session.get(
                    SourceOrchestrationDependencyRow,
                    (run_id, expected_osv.node_id, expected_syft.node_id),
                )
                mapping = session.scalar(
                    select(SourceOrchestrationScannerJobRow)
                    .where(
                        SourceOrchestrationScannerJobRow.run_id == run_id,
                        SourceOrchestrationScannerJobRow.node_id == expected_syft.node_id,
                    )
                    .with_for_update()
                )
                if mapping is None or mapping.selected_attempt_number is None:
                    raise SourceDependencyEvaluationError
                attempt = session.scalar(
                    select(SourceOrchestrationAttemptRow)
                    .where(
                        SourceOrchestrationAttemptRow.job_id == mapping.job_id,
                        SourceOrchestrationAttemptRow.attempt_number
                        == mapping.selected_attempt_number,
                    )
                    .with_for_update()
                )
                job = session.scalar(
                    select(JobRow).where(JobRow.id == mapping.job_id).with_for_update()
                )
                tool = (
                    None
                    if attempt is None or attempt.tool_execution_id is None
                    else session.get(ToolExecutionRow, attempt.tool_execution_id)
                )
                existing = session.get(
                    SourceOrchestrationDependencyEvaluationRow,
                    (run_id, osv_node_id),
                )
                if not _valid_prerequisite_rows(
                    parent=parent,
                    osv_node=osv_node,
                    syft_node=syft_node,
                    dependency=dependency,
                    mapping=mapping,
                    attempt=attempt,
                    job=job,
                    tool=tool,
                    expected_osv=expected_osv,
                    expected_syft=expected_syft,
                    snapshot=snapshot,
                    selected_paths=selected_paths,
                ):
                    raise SourceDependencyEvaluationError
                if existing is None and not _release_is_authorized(parent, self._now()):
                    raise SourceDependencyEvaluationError
                assert attempt is not None and syft_node is not None and osv_node is not None
                result = self._read_syft_result(attempt, mapping, snapshot)
                parsed = _syft_parse_result(result.native_data)
                evaluation = _build_evaluation(
                    run_id=run_id,
                    osv_node_id=osv_node_id,
                    selected_paths=selected_paths,
                    scope_digest=osv_node.scope_digest,
                    syft_result=result,
                    parsed=parsed,
                    prerequisite_complete=(
                        syft_node.terminal_disposition
                        == OrchestrationNodeDisposition.COMPLETE.value
                    ),
                )
                payload = evaluation.canonical_json()
                artifact = self._artifacts.put(
                    payload,
                    kind=ArtifactKind.SOURCE_DEPENDENCY_EVALUATION,
                    media_type=DEPENDENCY_EVALUATION_MEDIA_TYPE,
                    sanitized=True,
                )
                expected_path = f"sha256/{artifact.sha256[:2]}/{artifact.sha256}"
                reloaded = self._artifacts.read_by_sha256(
                    artifact.sha256, expected_size_bytes=artifact.size_bytes
                )
                if (
                    artifact.storage_path != expected_path
                    or reloaded != payload
                    or SourceDependencyEvaluation.from_json(reloaded) != evaluation
                ):
                    raise SourceDependencyEvaluationError
                if existing is not None:
                    if not _node_matches_evaluation(osv_node, evaluation):
                        raise SourceDependencyEvaluationConflictError
                    return self._existing_record(existing, evaluation, artifact.storage_path)
                if (
                    osv_node.lifecycle_state
                    != OrchestrationNodeLifecycleState.WAITING_DEPENDENCY.value
                ):
                    raise SourceDependencyEvaluationConflictError
                disposition, reason = _transition_for(evaluation)
                if disposition is None:
                    osv_node.lifecycle_state = OrchestrationNodeLifecycleState.READY.value
                    osv_node.terminal_disposition = None
                    osv_node.terminal_reason_code = None
                else:
                    osv_node.lifecycle_state = OrchestrationNodeLifecycleState.TERMINAL.value
                    osv_node.terminal_disposition = disposition.value
                    osv_node.terminal_reason_code = reason
                osv_node.state_version += 1
                session.add(
                    SourceOrchestrationDependencyEvaluationRow(
                        run_id=run_id,
                        osv_node_id=osv_node_id,
                        syft_node_id=syft_node.node_id,
                        syft_job_id=mapping.job_id,
                        syft_selected_attempt_number=mapping.selected_attempt_number,
                        syft_native_result_sha256=attempt.native_result_sha256,
                        scope_digest=osv_node.scope_digest,
                        evaluation_artifact_sha256=artifact.sha256,
                        evaluation_artifact_size_bytes=artifact.size_bytes,
                        evaluation_artifact_media_type=DEPENDENCY_EVALUATION_MEDIA_TYPE,
                        evaluation_schema_version=DEPENDENCY_EVALUATION_SCHEMA_VERSION,
                        created_at=self._now(),
                    )
                )
                session.flush()
                return SourceDependencyEvaluationRecord(
                    evaluation=evaluation,
                    artifact_sha256=artifact.sha256,
                    artifact_size_bytes=artifact.size_bytes,
                    storage_path=artifact.storage_path,
                    created=True,
                )
        except SourceDependencyEvaluationError:
            raise
        except (
            IntegrityError,
            OSError,
            SQLAlchemyError,
            SourceOrchestrationIntegrityError,
            ValueError,
        ):
            raise SourceDependencyEvaluationError from None

    def load(self, *, run_id: str, osv_node_id: str) -> SourceDependencyEvaluationRecord:
        try:
            with self._session_factory() as session:
                row = session.get(SourceOrchestrationDependencyEvaluationRow, (run_id, osv_node_id))
                if row is None:
                    raise SourceDependencyEvaluationError
                return self._load_record(row, created=False)
        except SourceDependencyEvaluationError:
            raise
        except (OSError, ValueError, SQLAlchemyError):
            raise SourceDependencyEvaluationError from None

    def _existing_record(
        self,
        row: SourceOrchestrationDependencyEvaluationRow,
        expected: SourceDependencyEvaluation,
        storage_path: str,
    ) -> SourceDependencyEvaluationRecord:
        record = self._load_record(row, created=False)
        if record.evaluation != expected or record.storage_path != storage_path:
            raise SourceDependencyEvaluationConflictError
        return record

    def _load_record(
        self, row: SourceOrchestrationDependencyEvaluationRow, *, created: bool
    ) -> SourceDependencyEvaluationRecord:
        expected_path = (
            f"sha256/{row.evaluation_artifact_sha256[:2]}/{row.evaluation_artifact_sha256}"
        )
        if (
            row.evaluation_artifact_media_type != DEPENDENCY_EVALUATION_MEDIA_TYPE
            or row.evaluation_schema_version != DEPENDENCY_EVALUATION_SCHEMA_VERSION
            or row.evaluation_artifact_size_bytes < 1
            or _SHA256.fullmatch(row.evaluation_artifact_sha256) is None
        ):
            raise SourceDependencyEvaluationError
        payload = self._artifacts.read_by_sha256(
            row.evaluation_artifact_sha256,
            expected_size_bytes=row.evaluation_artifact_size_bytes,
        )
        evaluation = SourceDependencyEvaluation.from_json(payload)
        if (
            evaluation.sha256() != row.evaluation_artifact_sha256
            or evaluation.run_id != row.run_id
            or evaluation.osv_node_id != row.osv_node_id
            or evaluation.scope.scope_digest != row.scope_digest
            or evaluation.syft_prerequisite.node_id != row.syft_node_id
            or evaluation.syft_prerequisite.job_id != row.syft_job_id
            or evaluation.syft_prerequisite.selected_attempt_number
            != row.syft_selected_attempt_number
            or evaluation.syft_prerequisite.native_result_sha256 != row.syft_native_result_sha256
        ):
            raise SourceDependencyEvaluationError
        return SourceDependencyEvaluationRecord(
            evaluation=evaluation,
            artifact_sha256=row.evaluation_artifact_sha256,
            artifact_size_bytes=row.evaluation_artifact_size_bytes,
            storage_path=expected_path,
            created=created,
        )

    def _load_snapshot(self, parent: SourceOrchestrationRow) -> SourcePlanningSnapshot:
        snapshot = self._snapshots.read(
            parent.planning_snapshot_sha256,
            parent.snapshot_size_bytes,
            parent.snapshot_storage_path,
        )
        if (
            snapshot.run_id != parent.run_id
            or snapshot.profile.repository_digest != parent.repository_digest
            or snapshot.profile.profile_digest() != parent.profile_digest
            or snapshot.plan.plan_digest() != parent.plan_digest
            or snapshot.roster.roster_digest() != parent.roster_digest
        ):
            raise SourceDependencyEvaluationError
        return snapshot

    def _read_syft_result(
        self,
        attempt: SourceOrchestrationAttemptRow,
        mapping: SourceOrchestrationScannerJobRow,
        snapshot: SourcePlanningSnapshot,
    ) -> SafeSourceNativeResult:
        if attempt.native_result_sha256 is None or attempt.native_result_size_bytes is None:
            raise SourceDependencyEvaluationError
        payload = self._artifacts.read_by_sha256(
            attempt.native_result_sha256,
            expected_size_bytes=attempt.native_result_size_bytes,
        )
        try:
            result = SafeSourceNativeResult.from_json(payload)
        except SourceScannerExecutionIntegrityError:
            raise SourceDependencyEvaluationError from None
        if (
            result.sha256() != attempt.native_result_sha256
            or result.node_id != mapping.node_id
            or result.job_id != mapping.job_id
            or result.attempt_number != mapping.selected_attempt_number
            or result.authority != SourceAuthority.SYFT.value
            or result.scanner_id != SourceAuthority.SYFT.value
            or result.analyzer_id != mapping.analyzer_id
            or result.binding_digest != mapping.contract_digest
            or result.context_digest != mapping.context_digest
            or result.projection_id != mapping.projection_id
            or result.projection_digest != mapping.projection_digest
            or result.repository_digest != snapshot.profile.repository_digest
            or result.profile_digest != snapshot.profile.profile_digest()
            or result.plan_digest != snapshot.plan.plan_digest()
        ):
            raise SourceDependencyEvaluationError
        return result

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise SourceDependencyEvaluationError
        return value.astimezone(UTC)


def _scope_from_snapshot(
    snapshot: SourcePlanningSnapshot, osv_node_id: str
) -> tuple[PlannedSourceNode, PlannedSourceNode, tuple[str, ...]]:
    osv_nodes = tuple(
        node
        for node in snapshot.nodes
        if node.authority is SourceAuthority.OSV
        and node.capability is AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING
        and node.analyzer_id == _OSV_ANALYZER_ID
    )
    if len(osv_nodes) != 1 or osv_nodes[0].node_id != osv_node_id:
        raise SourceDependencyEvaluationError
    osv_node = osv_nodes[0]
    syft_nodes = tuple(
        node
        for node in snapshot.nodes
        if node.authority is SourceAuthority.SYFT
        and node.capability is AnalysisCapability.PACKAGE_INVENTORY
    )
    if len(syft_nodes) != 1:
        raise SourceDependencyEvaluationError
    dependencies = tuple(edge for edge in snapshot.dependencies if edge.node_id == osv_node.node_id)
    if len(dependencies) != 1 or dependencies[0].prerequisite_node_id != syft_nodes[0].node_id:
        raise SourceDependencyEvaluationError
    entries = tuple(
        entry
        for entry in snapshot.plan.entries
        if entry.action is SourcePlanAction.RUN
        and entry.capability is AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING
        and entry.analyzer_id == _OSV_ANALYZER_ID
    )
    selected_paths = tuple(sorted({path for entry in entries for path in entry.selected_paths}))
    entry_keys = tuple(
        sorted(f"{entry.capability.value}:{entry.component_id or '-'}" for entry in entries)
    )
    if (
        not entries
        or selected_paths != osv_node.selected_paths
        or entry_keys != osv_node.plan_entry_keys
    ):
        raise SourceDependencyEvaluationError
    return osv_node, syft_nodes[0], selected_paths


def _valid_prerequisite_rows(**values: Any) -> bool:
    parent = values["parent"]
    osv = values["osv_node"]
    syft = values["syft_node"]
    edge = values["dependency"]
    mapping = values["mapping"]
    attempt = values["attempt"]
    job = values["job"]
    tool = values["tool"]
    expected_osv = values["expected_osv"]
    expected_syft = values["expected_syft"]
    snapshot = values["snapshot"]
    selected_paths = values["selected_paths"]
    return bool(
        osv is not None
        and syft is not None
        and edge is not None
        and mapping is not None
        and attempt is not None
        and job is not None
        and tool is not None
        and osv.run_id
        == syft.run_id
        == mapping.run_id
        == attempt.run_id
        == job.run_id
        == parent.run_id
        and edge.run_id == parent.run_id
        and edge.node_id == osv.node_id == expected_osv.node_id
        and edge.prerequisite_node_id == syft.node_id == expected_syft.node_id
        and osv.authority == SourceAuthority.OSV.value
        and osv.capability == AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING.value
        and osv.analyzer_id == _OSV_ANALYZER_ID
        and osv.contract_digest == expected_osv.contract_digest
        and osv.plan_entry_keys_json == list(expected_osv.plan_entry_keys)
        and osv.selected_paths_json == list(selected_paths)
        and osv.scope_digest == expected_osv.scope_digest
        and syft.authority == SourceAuthority.SYFT.value
        and syft.capability == AnalysisCapability.PACKAGE_INVENTORY.value
        and syft.analyzer_id == expected_syft.analyzer_id
        and syft.contract_digest == expected_syft.contract_digest
        and syft.plan_entry_keys_json == list(expected_syft.plan_entry_keys)
        and syft.selected_paths_json == list(expected_syft.selected_paths)
        and syft.scope_digest == expected_syft.scope_digest
        and syft.lifecycle_state == OrchestrationNodeLifecycleState.TERMINAL.value
        and syft.terminal_disposition
        in {
            OrchestrationNodeDisposition.COMPLETE.value,
            OrchestrationNodeDisposition.PARTIAL.value,
        }
        and syft.containment_state == OrchestrationContainmentState.CLEAN.value
        and mapping.node_id == syft.node_id
        and mapping.authority == syft.authority
        and mapping.capability == syft.capability
        and mapping.analyzer_id == syft.analyzer_id
        and mapping.contract_digest == syft.contract_digest
        and mapping.selected_attempt_number == attempt.attempt_number
        and mapping.job_id == attempt.job_id == job.id
        and attempt.node_id == syft.node_id
        and attempt.acceptance_state == "ACCEPTED"
        and attempt.containment_state == OrchestrationContainmentState.CLEAN.value
        and attempt.projection_revalidated is True
        and attempt.native_result_media_type == SAFE_NATIVE_RESULT_MEDIA_TYPE
        and attempt.native_result_schema_version == SAFE_NATIVE_RESULT_SCHEMA_VERSION
        and attempt.native_result_sha256 is not None
        and attempt.native_result_size_bytes is not None
        and attempt.native_result_size_bytes > 0
        and attempt.native_result_storage_path
        == f"sha256/{attempt.native_result_sha256[:2]}/{attempt.native_result_sha256}"
        and attempt.tool_execution_id == tool.id
        and tool.job_id == job.id
        and tool.attempt_number == attempt.attempt_number
        and tool.run_id == parent.run_id
        and tool.adapter_id == SourceAuthority.SYFT.value
        and tool.outcome
        in {
            ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value,
            ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS.value,
            ExecutionOutcome.SUCCEEDED_WITH_WARNINGS.value,
            ExecutionOutcome.PARTIAL_ANALYSIS.value,
        }
        and tool.failure_category is None
        and tool.retryable is None
        and job.adapter_id == SourceAuthority.SYFT.value
        and job.attempt_count == attempt.attempt_number
        and job.status in {JobStatus.SUCCEEDED.value, JobStatus.PARTIAL.value}
        and (
            (
                syft.terminal_disposition == OrchestrationNodeDisposition.COMPLETE.value
                and job.status == JobStatus.SUCCEEDED.value
            )
            or (
                syft.terminal_disposition == OrchestrationNodeDisposition.PARTIAL.value
                and job.status == JobStatus.PARTIAL.value
            )
        )
        and snapshot.run_id == parent.run_id
    )


def _release_is_authorized(parent: SourceOrchestrationRow, now: datetime) -> bool:
    deadline = parent.deadline_at
    if isinstance(deadline, datetime) and deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    return bool(
        parent.lifecycle_state == OrchestrationLifecycleState.ACTIVE.value
        and not parent.cancel_requested
        and isinstance(deadline, datetime)
        and deadline.astimezone(UTC) > now
    )


def _node_matches_evaluation(
    node: SourceOrchestrationNodeRow, evaluation: SourceDependencyEvaluation
) -> bool:
    disposition, reason = _transition_for(evaluation)
    if disposition is None:
        return bool(
            node.lifecycle_state == OrchestrationNodeLifecycleState.READY.value
            and node.terminal_disposition is None
            and node.terminal_reason_code is None
        )
    return bool(
        node.lifecycle_state == OrchestrationNodeLifecycleState.TERMINAL.value
        and node.terminal_disposition == disposition.value
        and node.terminal_reason_code == reason
    )


def _syft_parse_result(native_data: Any) -> SyftParseResult:
    try:
        root = dict(native_data)
        observations = tuple(
            PackageObservation(
                scanner_id=item["scanner_id"],
                scanner_version=item["scanner_version"],
                package_name=item["package_name"],
                package_version=item["package_version"],
                package_type=item["package_type"],
                language=item["language"],
                purl=item["purl"],
                found_by=item["found_by"],
                locations=tuple(item["locations"]),
                projection_id=item["projection_id"],
                snapshot_digest=item["snapshot_digest"],
                binding_digest=item["binding_digest"],
                package_key=item["package_key"],
                package_observation_id=item["package_observation_id"],
            )
            for item in root["observations"]
        )
        result = SyftParseResult(
            scanner_id=root["scanner_id"],
            scanner_version=root["scanner_version"],
            binding_digest=root["binding_digest"],
            projection_id=root["projection_id"],
            snapshot_digest=root["snapshot_digest"],
            syft_schema_version=root["syft_schema_version"],
            requested_cataloger_strategy=tuple(root["requested_cataloger_strategy"]),
            used_catalogers=tuple(root["used_catalogers"]),
            observations=observations,
            package_count=root["package_count"],
            schema_version=root["schema_version"],
        )
        if _load_json(result.canonical_json()) != _load_json(_canonical_json(_thaw(root))):
            raise ValueError
        return result
    except (KeyError, TypeError, ValueError, SourceDependencyEvaluationError):
        raise SourceDependencyEvaluationError from None


def _build_evaluation(
    *,
    run_id: str,
    osv_node_id: str,
    selected_paths: tuple[str, ...],
    scope_digest: str,
    syft_result: SafeSourceNativeResult,
    parsed: SyftParseResult,
    prerequisite_complete: bool,
) -> SourceDependencyEvaluation:
    selected = frozenset(selected_paths)
    classified: list[PackageScopeEvidence] = []
    eligible: list[PackageObservation] = []
    mixed: list[DependencyGapEvidence] = []
    for observation in parsed.observations:
        locations = frozenset(observation.locations)
        if locations.issubset(selected):
            classification = PackageScopeClassification.IN_SCOPE
            eligible.append(observation)
        elif locations.isdisjoint(selected):
            classification = PackageScopeClassification.OUTSIDE_SCOPE
        else:
            classification = PackageScopeClassification.MIXED_SCOPE
            mixed.append(
                DependencyGapEvidence(
                    reason_code="MIXED_SCOPE_PACKAGE_OBSERVATION",
                    package_key=observation.package_key,
                    package_observation_ids=(observation.package_observation_id,),
                    locations=observation.locations,
                )
            )
        classified.append(
            PackageScopeEvidence(
                package_observation_id=observation.package_observation_id,
                package_key=observation.package_key,
                locations=observation.locations,
                classification=classification,
            )
        )
    candidates, gaps = build_osv_query_candidates(tuple(eligible))
    coordinate_gaps = tuple(_coordinate_gap(item) for item in gaps)
    decision = _expected_decision(
        prerequisite_complete=prerequisite_complete,
        observation_count=len(parsed.observations),
        in_scope_count=len(eligible),
        mixed_count=len(mixed),
        candidate_count=len(candidates),
    )
    return SourceDependencyEvaluation(
        run_id=run_id,
        osv_node_id=osv_node_id,
        scope=DependencyScopeEvidence(selected_paths, scope_digest),
        syft_prerequisite=SyftPrerequisiteEvidence(
            node_id=syft_result.node_id,
            job_id=syft_result.job_id,
            selected_attempt_number=syft_result.attempt_number,
            native_result_sha256=syft_result.sha256(),
            prerequisite_complete=prerequisite_complete,
        ),
        observations=tuple(sorted(classified, key=lambda item: item.package_observation_id)),
        mixed_scope_gaps=tuple(
            sorted(mixed, key=lambda item: (item.package_key, item.package_observation_ids))
        ),
        eligible_package_observation_ids=tuple(
            sorted(item.package_observation_id for item in eligible)
        ),
        candidate_ids=tuple(sorted(item.candidate_id for item in candidates)),
        coordinate_gaps=coordinate_gaps,
        decision=decision,
        coverage_limited=bool(mixed or coordinate_gaps or not prerequisite_complete),
    )


def _expected_decision(
    *,
    prerequisite_complete: bool,
    observation_count: int,
    in_scope_count: int,
    mixed_count: int,
    candidate_count: int,
) -> DependencyEvaluationDecision:
    if candidate_count:
        return DependencyEvaluationDecision.OSV_RUN_REQUIRED
    if not prerequisite_complete:
        return DependencyEvaluationDecision.PARTIAL_PREREQUISITE_INCOMPLETE
    if not observation_count:
        return DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES
    if in_scope_count or mixed_count:
        return DependencyEvaluationDecision.PARTIAL_NO_SUPPORTED_COORDINATES
    return DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES_IN_SCOPE


def _transition_for(
    evaluation: SourceDependencyEvaluation,
) -> tuple[OrchestrationNodeDisposition | None, str | None]:
    if evaluation.decision is DependencyEvaluationDecision.OSV_RUN_REQUIRED:
        return None, None
    if evaluation.decision is DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES:
        return OrchestrationNodeDisposition.NOT_APPLICABLE, "NO_PACKAGES_OBSERVED"
    if evaluation.decision is DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES_IN_SCOPE:
        return OrchestrationNodeDisposition.NOT_APPLICABLE, "NO_PACKAGES_IN_ADVISORY_SCOPE"
    if evaluation.mixed_scope_gaps:
        return OrchestrationNodeDisposition.PARTIAL, "MIXED_SCOPE_PACKAGE_OBSERVATION"
    if evaluation.decision is DependencyEvaluationDecision.PARTIAL_PREREQUISITE_INCOMPLETE:
        return OrchestrationNodeDisposition.PARTIAL, "SYFT_PREREQUISITE_PARTIAL"
    return OrchestrationNodeDisposition.PARTIAL, "NO_SUPPORTED_OSV_COORDINATES"


def _coordinate_gap(gap: OsvPackageGap) -> DependencyGapEvidence:
    return DependencyGapEvidence(
        reason_code=gap.reason_code.value,
        package_key=gap.package_key,
        package_observation_ids=gap.package_observation_ids,
        locations=gap.locations,
    )


def _valid_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (AttributeError, TypeError, ValueError):
        return False


def _valid_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _load_json(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > 50 * 1024 * 1024:
        raise SourceDependencyEvaluationError
    value = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_reject_pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )
    if not isinstance(value, dict):
        raise SourceDependencyEvaluationError
    return value


def _require_dict(value: object, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError
    return value


def _parse_observation(value: object) -> PackageScopeEvidence:
    item = _require_dict(
        value, {"classification", "locations", "package_key", "package_observation_id"}
    )
    return PackageScopeEvidence(
        package_observation_id=item["package_observation_id"],
        package_key=item["package_key"],
        locations=tuple(item["locations"]),
        classification=PackageScopeClassification(item["classification"]),
    )


def _parse_gap(value: object) -> DependencyGapEvidence:
    item = _require_dict(
        value, {"locations", "package_key", "package_observation_ids", "reason_code"}
    )
    return DependencyGapEvidence(
        reason_code=item["reason_code"],
        package_key=item["package_key"],
        package_observation_ids=tuple(item["package_observation_ids"]),
        locations=tuple(item["locations"]),
    )


def _thaw(value: Any) -> Any:
    if hasattr(value, "items"):
        return {key: _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value
