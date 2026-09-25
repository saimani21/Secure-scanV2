from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.advisories.osv.models import OsvGapReason
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.evidence import (
    OSV_FINDING_IDENTITY_SCHEMA,
    ComponentKind,
    EvidenceAuthority,
    build_component_ref,
    build_finding_id,
)
from securescan.orchestration.dependency_evaluation import (
    DependencyEvaluationDecision,
    PackageScopeClassification,
    SourceDependencyEvaluation,
    SourceDependencyEvaluationError,
    SourceDependencyEvaluationService,
)
from securescan.orchestration.models import (
    OrchestrationNodeDisposition,
    OrchestrationNodeLifecycleState,
    SourceAuthority,
    SourceOrchestrationIntegrityError,
    frozen_source_v1_authority_roster,
)
from securescan.orchestration.osv_execution import (
    SafeSourceOsvResult,
    SourceOsvAttemptService,
    SourceOsvExecutionError,
    SourceOsvExecutionInput,
    SourceOsvFailureCode,
    SourceOsvJobService,
)
from securescan.orchestration.service import (
    SourceOrchestrationError,
    SourceOrchestrationService,
)
from securescan.persistence.database import (
    SourceOrchestrationDependencyEvaluationRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationScannerJobRow,
)

_OSV_CAPABILITY = "dependency_advisory_matching"
_PRIORITY_BANDS = frozenset(
    {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRANKED"}
)
_PACKAGE_REASONS = frozenset(
    {
        "OUTSIDE_SCOPE",
        "MIXED_SCOPE_PACKAGE_OBSERVATION",
        "SYFT_PREREQUISITE_PARTIAL",
        *(item.value for item in OsvGapReason),
    }
)
_STAGE_REASONS = frozenset(
    {
        "NO_PACKAGES_OBSERVED",
        "NO_PACKAGES_IN_ADVISORY_SCOPE",
        "NO_SUPPORTED_COORDINATES",
        "DEPENDENCY_INCOMPLETE",
        "DEPENDENCY_FAILED",
        "EXECUTION_FAILED",
        "CANCELLED",
    }
)
_OSV_FAILURE_REASONS = frozenset(item.value for item in SourceOsvFailureCode)
_ACCEPTED_PARTIAL_OSV_OUTCOME_REASONS = frozenset(
    {
        "DEPENDENCY_COVERAGE_LIMITED",
        "PACKAGE_GAPS_PRESENT",
    }
)


class DependencyProjectionError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Source dependency projection failed")


@dataclass(frozen=True, slots=True)
class SourceDependencyAdvisorySummary:
    canonical_advisory_id: str
    finding_id: str
    osv_record_ids: tuple[str, ...]
    aliases: tuple[str, ...]
    cve_aliases: tuple[str, ...]
    ghsa_aliases: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    priority_band: str


@dataclass(frozen=True, slots=True)
class SourceDependencySummary:
    component_ref: str
    name: str
    version: str | None
    package_type: str
    purl: str | None
    locations: tuple[Mapping[str, Any], ...]
    vulnerability_evaluation: str
    vulnerability_evaluation_reason: str | None
    known_vulnerability_count: int | None
    advisories: tuple[SourceDependencyAdvisorySummary, ...]
    advisory_aliases: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    priority_bands: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DependencyProjectionMaterial:
    evaluation: SourceDependencyEvaluation | None = None
    evaluation_sha256: str | None = None
    execution_input: SourceOsvExecutionInput | None = None
    accepted_result: SafeSourceOsvResult | None = None
    fallback_evaluation: str | None = None
    public_reason: str | None = None
    report_reason: str | None = None


@dataclass(frozen=True, slots=True)
class _PackageComponent:
    component_ref: str
    package_key: str
    name: str
    version: str | None
    package_type: str
    purl: str | None


@dataclass(frozen=True, slots=True)
class _SyftObservation:
    evidence_id: str
    package_observation_id: str
    package_key: str
    component_ref: str
    locations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ProjectedAdvisory:
    summary: SourceDependencyAdvisorySummary
    native_finding_id: str
    advisory_group_key: str
    package_key: str
    package_observation_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ReportIndex:
    source_run_id: str
    repository_digest: str
    profile_digest: str
    plan_digest: str
    packages: tuple[_PackageComponent, ...]
    observations_by_package: Mapping[str, tuple[_SyftObservation, ...]]
    locations_by_component: Mapping[str, tuple[Mapping[str, Any], ...]]
    advisories_by_package: Mapping[str, tuple[_ProjectedAdvisory, ...]]
    osv_outcome_state: str | None
    osv_outcome_reason: str | None


class SourceDependencyProjectionService:
    """Load verified run-level evidence once and project package semantics."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
    ) -> None:
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise DependencyProjectionError
        self._sessions = session_factory
        self._evaluations = SourceDependencyEvaluationService(
            session_factory, artifact_store
        )
        self._osv_jobs = SourceOsvJobService(
            session_factory, artifact_store, self._evaluations
        )
        self._osv_attempts = SourceOsvAttemptService(
            session_factory, artifact_store, self._osv_jobs
        )
        self._orchestrations = SourceOrchestrationService(
            session_factory,
            artifact_store,
            frozen_source_v1_authority_roster(),
        )

    def project(
        self,
        *,
        run_id: str,
        report: Mapping[str, Any],
        priorities: Mapping[str, str],
    ) -> tuple[SourceDependencySummary, ...]:
        try:
            material = self._load_material(run_id)
            return resolve_dependency_summaries(report, priorities, material)
        except DependencyProjectionError:
            raise
        except (
            OSError,
            SQLAlchemyError,
            SourceDependencyEvaluationError,
            SourceOrchestrationError,
            SourceOrchestrationIntegrityError,
            SourceOsvExecutionError,
            TypeError,
            ValueError,
        ):
            raise DependencyProjectionError from None

    def _load_material(self, run_id: str) -> DependencyProjectionMaterial:
        with self._sessions() as session:
            nodes = tuple(
                session.scalars(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.run_id == run_id)
                    .order_by(SourceOrchestrationNodeRow.node_id)
                )
            )
            evaluations = tuple(
                session.scalars(
                    select(SourceOrchestrationDependencyEvaluationRow).where(
                        SourceOrchestrationDependencyEvaluationRow.run_id == run_id
                    )
                )
            )
            mappings = tuple(
                session.scalars(
                    select(SourceOrchestrationScannerJobRow).where(
                        SourceOrchestrationScannerJobRow.run_id == run_id,
                        SourceOrchestrationScannerJobRow.authority
                        == SourceAuthority.OSV.value,
                    )
                )
            )
        osv_nodes = tuple(
            item
            for item in nodes
            if item.authority == SourceAuthority.OSV.value
            and item.capability == _OSV_CAPABILITY
        )
        if len(osv_nodes) > 1 or len(evaluations) > 1 or len(mappings) > 1:
            raise DependencyProjectionError
        if not osv_nodes:
            if evaluations or mappings:
                raise DependencyProjectionError
            orchestration = self._orchestrations.load(run_id)
            planned = tuple(
                item
                for item in orchestration.snapshot.nodes
                if item.authority is SourceAuthority.OSV
                and item.capability.value == _OSV_CAPABILITY
            )
            roster = tuple(
                item
                for item in orchestration.snapshot.roster.authorities
                if item.authority is SourceAuthority.OSV
                and item.capability.value == _OSV_CAPABILITY
            )
            if planned or len(roster) != 1:
                raise DependencyProjectionError
            return DependencyProjectionMaterial(
                fallback_evaluation="NOT_APPLICABLE"
            )

        node = osv_nodes[0]
        evaluation_row = evaluations[0] if evaluations else None
        mapping = mappings[0] if mappings else None
        if evaluation_row is not None and evaluation_row.osv_node_id != node.node_id:
            raise DependencyProjectionError
        if mapping is not None and mapping.node_id != node.node_id:
            raise DependencyProjectionError

        if evaluation_row is None:
            if mapping is not None:
                raise DependencyProjectionError
            public_reason, report_reason = self._failure_reason(node, nodes)
            return DependencyProjectionMaterial(
                fallback_evaluation="FAILED",
                public_reason=public_reason,
                report_reason=report_reason,
            )

        record = self._evaluations.load(run_id=run_id, osv_node_id=node.node_id)
        evaluation = record.evaluation
        if mapping is None:
            if evaluation.decision is not DependencyEvaluationDecision.OSV_RUN_REQUIRED:
                return DependencyProjectionMaterial(
                    evaluation=evaluation,
                    evaluation_sha256=record.artifact_sha256,
                )
            public_reason, report_reason = self._failure_reason(node, nodes)
            return DependencyProjectionMaterial(
                evaluation=evaluation,
                evaluation_sha256=record.artifact_sha256,
                public_reason=public_reason,
                report_reason=report_reason,
            )

        execution_input = self._osv_jobs.load_input(job_id=mapping.job_id)
        if mapping.selected_attempt_number is None:
            public_reason, report_reason = self._failure_reason(node, nodes)
            return DependencyProjectionMaterial(
                evaluation=evaluation,
                evaluation_sha256=record.artifact_sha256,
                execution_input=execution_input,
                public_reason=public_reason,
                report_reason=report_reason,
            )
        accepted_result = self._osv_attempts.load_accepted_result(
            run_id=run_id, node_id=node.node_id
        )
        return DependencyProjectionMaterial(
            evaluation=evaluation,
            evaluation_sha256=record.artifact_sha256,
            execution_input=execution_input,
            accepted_result=accepted_result,
        )

    @staticmethod
    def _failure_reason(
        node: SourceOrchestrationNodeRow,
        nodes: tuple[SourceOrchestrationNodeRow, ...],
    ) -> tuple[str, str]:
        if node.lifecycle_state != OrchestrationNodeLifecycleState.TERMINAL.value:
            raise DependencyProjectionError
        try:
            disposition = OrchestrationNodeDisposition(node.terminal_disposition)
        except ValueError:
            raise DependencyProjectionError from None
        raw = node.terminal_reason_code
        if not isinstance(raw, str) or not raw:
            raise DependencyProjectionError
        if disposition is OrchestrationNodeDisposition.BLOCKED_BY_DEPENDENCY:
            syft = tuple(
                item
                for item in nodes
                if item.authority == SourceAuthority.SYFT.value
                and item.capability == "package_inventory"
            )
            if len(syft) != 1 or syft[0].terminal_disposition is None:
                raise DependencyProjectionError
            expected = (
                f"SYFT_{syft[0].terminal_reason_code or syft[0].terminal_disposition}"
            )[:128]
            if raw != expected:
                raise DependencyProjectionError
            return "DEPENDENCY_FAILED", raw
        if raw == "DEPENDENCY_EVALUATION_FAILED":
            if disposition is not OrchestrationNodeDisposition.FAILED:
                raise DependencyProjectionError
            return "DEPENDENCY_FAILED", raw
        if raw not in _OSV_FAILURE_REASONS:
            raise DependencyProjectionError
        if disposition not in {
            OrchestrationNodeDisposition.FAILED,
            OrchestrationNodeDisposition.CANCELLED,
        }:
            raise DependencyProjectionError
        return raw, raw


def resolve_dependency_summaries(
    report: Mapping[str, Any],
    priorities: Mapping[str, str],
    material: DependencyProjectionMaterial,
) -> tuple[SourceDependencySummary, ...]:
    try:
        index = _build_report_index(report, priorities)
        _validate_material_shape(material)
        if material.fallback_evaluation is not None:
            _validate_fallback(index, material)
            return tuple(
                _summary(
                    package,
                    locations=index.locations_by_component[package.component_ref],
                    evaluation=material.fallback_evaluation,
                    reason=material.public_reason,
                    advisories=(),
                )
                for package in index.packages
            )
        evaluation = material.evaluation
        if evaluation is None:
            raise DependencyProjectionError
        _validate_evaluation(index, evaluation)
        candidates = _validate_input(index, material)
        accepted = _validate_result(index, material, candidates)
        gaps_by_package = _gaps_by_package(evaluation)
        observations = {
            package_key: tuple(
                item
                for item in evaluation.observations
                if item.package_key == package_key
            )
            for package_key in index.observations_by_package
        }
        summaries = []
        for package in index.packages:
            package_observations = observations[package.package_key]
            classifications = {
                item.classification for item in package_observations
            }
            advisories = tuple(
                item.summary
                for item in index.advisories_by_package.get(package.package_key, ())
            )
            if classifications == {PackageScopeClassification.OUTSIDE_SCOPE}:
                if package.package_key in candidates or advisories:
                    raise DependencyProjectionError
                summaries.append(
                    _summary(
                        package,
                        locations=index.locations_by_component[package.component_ref],
                        evaluation="NOT_APPLICABLE",
                        reason="OUTSIDE_SCOPE",
                        advisories=(),
                    )
                )
                continue

            limitation_codes: set[str] = set()
            heterogeneous = len(classifications) > 1
            if PackageScopeClassification.MIXED_SCOPE in classifications:
                limitation_codes.add("MIXED_SCOPE_PACKAGE_OBSERVATION")
            package_gaps = gaps_by_package.get(package.package_key, ())
            limitation_codes.update(item.reason_code for item in package_gaps)
            if not evaluation.syft_prerequisite.prerequisite_complete:
                limitation_codes.add("SYFT_PREREQUISITE_PARTIAL")
            if not limitation_codes <= _PACKAGE_REASONS:
                raise DependencyProjectionError
            reason = (
                next(iter(limitation_codes))
                if len(limitation_codes) == 1 and not heterogeneous
                else None
            )
            candidate = candidates.get(package.package_key)
            if accepted is None:
                if candidate is not None or _candidate_required(
                    package_observations, package_gaps, evaluation
                ):
                    if material.public_reason is None:
                        raise DependencyProjectionError
                    summaries.append(
                        _summary(
                            package,
                            locations=index.locations_by_component[package.component_ref],
                            evaluation="FAILED",
                            reason=material.public_reason,
                            advisories=(),
                        )
                    )
                else:
                    summaries.append(
                        _summary(
                            package,
                            locations=index.locations_by_component[package.component_ref],
                            evaluation="PARTIAL",
                            reason=reason,
                            advisories=(),
                        )
                    )
                continue
            if candidate is None:
                if advisories:
                    raise DependencyProjectionError
                summaries.append(
                    _summary(
                        package,
                        locations=index.locations_by_component[package.component_ref],
                        evaluation="PARTIAL",
                        reason=reason,
                        advisories=(),
                    )
                )
                continue
            if limitation_codes or heterogeneous:
                summaries.append(
                    _summary(
                        package,
                        locations=index.locations_by_component[package.component_ref],
                        evaluation="PARTIAL",
                        reason=reason,
                        advisories=advisories,
                    )
                )
                continue
            summaries.append(
                _summary(
                    package,
                    locations=index.locations_by_component[package.component_ref],
                    evaluation="COMPLETE",
                    reason=None,
                    advisories=advisories,
                )
            )
        return tuple(sorted(summaries, key=lambda item: item.component_ref))
    except DependencyProjectionError:
        raise
    except (KeyError, TypeError, ValueError):
        raise DependencyProjectionError from None


def _validate_material_shape(material: DependencyProjectionMaterial) -> None:
    if not isinstance(material, DependencyProjectionMaterial):
        raise DependencyProjectionError
    if material.fallback_evaluation is not None:
        if (
            material.fallback_evaluation not in {"FAILED", "NOT_APPLICABLE"}
            or material.evaluation is not None
            or material.evaluation_sha256 is not None
            or material.execution_input is not None
            or material.accepted_result is not None
        ):
            raise DependencyProjectionError
    else:
        if (
            not isinstance(material.evaluation, SourceDependencyEvaluation)
            or not isinstance(material.evaluation_sha256, str)
        ):
            raise DependencyProjectionError
    if material.accepted_result is not None and material.execution_input is None:
        raise DependencyProjectionError
    if material.public_reason is not None and material.public_reason not in (
        _STAGE_REASONS | _OSV_FAILURE_REASONS
    ):
        raise DependencyProjectionError


def _validate_fallback(
    index: _ReportIndex, material: DependencyProjectionMaterial
) -> None:
    if any(index.advisories_by_package.values()):
        raise DependencyProjectionError
    if material.fallback_evaluation == "NOT_APPLICABLE":
        if (
            index.osv_outcome_state is not None
            or material.public_reason is not None
            and material.public_reason not in _STAGE_REASONS
        ):
            raise DependencyProjectionError
        return
    if (
        material.fallback_evaluation != "FAILED"
        or index.osv_outcome_state != "FAILED"
        or index.osv_outcome_reason != material.report_reason
        or material.public_reason is None
    ):
        raise DependencyProjectionError


def _validate_evaluation(
    index: _ReportIndex, evaluation: SourceDependencyEvaluation
) -> None:
    expected = {
        (
            item.package_key,
            item.package_observation_id,
            item.locations,
        )
        for values in index.observations_by_package.values()
        for item in values
    }
    actual = {
        (item.package_key, item.package_observation_id, item.locations)
        for item in evaluation.observations
    }
    if expected != actual:
        raise DependencyProjectionError


def _validate_input(
    index: _ReportIndex,
    material: DependencyProjectionMaterial,
) -> dict[str, Any]:
    evaluation = material.evaluation
    execution_input = material.execution_input
    if evaluation is None:
        raise DependencyProjectionError
    if evaluation.run_id != index.source_run_id:
        raise DependencyProjectionError
    if execution_input is None:
        if material.accepted_result is not None:
            raise DependencyProjectionError
        return {}
    if (
        execution_input.run_id != index.source_run_id
        or execution_input.node_id != evaluation.osv_node_id
        or execution_input.repository_digest != index.repository_digest
        or execution_input.profile_digest != index.profile_digest
        or execution_input.plan_digest != index.plan_digest
        or execution_input.scope_digest != evaluation.scope.scope_digest
        or execution_input.dependency_evaluation_sha256
        != material.evaluation_sha256
        or execution_input.dependency_evaluation_schema_version
        != evaluation.schema_version
        or execution_input.syft_node_id != evaluation.syft_prerequisite.node_id
        or execution_input.syft_job_id != evaluation.syft_prerequisite.job_id
        or execution_input.syft_selected_attempt_number
        != evaluation.syft_prerequisite.selected_attempt_number
        or execution_input.syft_native_result_sha256
        != evaluation.syft_prerequisite.native_result_sha256
        or execution_input.coverage_limited is not evaluation.coverage_limited
        or tuple(item.candidate_id for item in execution_input.candidates)
        != evaluation.candidate_ids
    ):
        raise DependencyProjectionError
    packages = {item.package_key: item for item in index.packages}
    candidates: dict[str, Any] = {}
    for candidate in execution_input.candidates:
        package = packages.get(candidate.package_key)
        observations = index.observations_by_package.get(candidate.package_key, ())
        eligible = tuple(
            sorted(
                item.package_observation_id
                for item in evaluation.observations
                if item.package_key == candidate.package_key
                and item.classification is PackageScopeClassification.IN_SCOPE
            )
        )
        if (
            package is None
            or candidate.package_key in candidates
            or candidate.package_name != package.name
            or candidate.package_version != package.version
            or candidate.package_type != package.package_type
            or candidate.purl != package.purl
            or candidate.package_observation_ids != eligible
            or not eligible
            or not set(eligible)
            <= {item.package_observation_id for item in observations}
        ):
            raise DependencyProjectionError
        candidates[candidate.package_key] = candidate
    return candidates


def _validate_result(
    index: _ReportIndex,
    material: DependencyProjectionMaterial,
    candidates: Mapping[str, Any],
) -> SafeSourceOsvResult | None:
    evaluation = material.evaluation
    execution_input = material.execution_input
    result = material.accepted_result
    if evaluation is None:
        raise DependencyProjectionError
    if result is None:
        if any(index.advisories_by_package.values()):
            raise DependencyProjectionError
        if evaluation.candidate_ids and material.public_reason is None:
            raise DependencyProjectionError
        expected_state = _non_result_outcome_state(evaluation, material.public_reason)
        expected_reason = (
            material.report_reason
            if material.public_reason is not None
            else _non_result_outcome_reason(evaluation)
        )
        if (
            index.osv_outcome_state != expected_state
            or index.osv_outcome_reason != expected_reason
        ):
            raise DependencyProjectionError
        return None
    if execution_input is None or material.public_reason is not None:
        raise DependencyProjectionError
    if (
        result.run_id != execution_input.run_id
        or result.node_id != execution_input.node_id
        or result.job_id != execution_input.job_id
        or result.repository_digest != execution_input.repository_digest
        or result.profile_digest != execution_input.profile_digest
        or result.plan_digest != execution_input.plan_digest
        or result.scope_digest != execution_input.scope_digest
        or result.dependency_evaluation_sha256
        != execution_input.dependency_evaluation_sha256
        or result.syft_native_result_sha256
        != execution_input.syft_native_result_sha256
        or result.candidate_ids
        != tuple(item.candidate_id for item in execution_input.candidates)
        or result.analysis.candidates != execution_input.candidates
        or result.analysis.completed_candidate_ids != result.candidate_ids
        or result.coverage_limited is not execution_input.coverage_limited
        or set(candidates) != {item.package_key for item in result.analysis.candidates}
    ):
        raise DependencyProjectionError
    projected = {
        (
            item.native_finding_id,
            item.advisory_group_key,
            item.package_key,
            item.package_observation_ids,
            item.summary.canonical_advisory_id,
            item.summary.osv_record_ids,
            item.summary.aliases,
            item.summary.cve_aliases,
            item.summary.ghsa_aliases,
            item.summary.fixed_versions,
        )
        for values in index.advisories_by_package.values()
        for item in values
    }
    accepted = {
        (
            item.finding_id,
            item.advisory_group_key,
            item.package_key,
            item.package_observation_ids,
            item.canonical_advisory_id,
            item.osv_record_ids,
            item.aliases,
            item.cve_aliases,
            item.ghsa_aliases,
            item.fixed_versions,
        )
        for item in result.analysis.findings
    }
    if projected != accepted:
        raise DependencyProjectionError
    expected_state = (
        "PARTIAL"
        if result.coverage_limited
        else "COMPLETE_WITH_FINDINGS"
        if result.analysis.findings
        else "COMPLETE"
    )
    expected_reasons = (
        _ACCEPTED_PARTIAL_OSV_OUTCOME_REASONS
        if result.coverage_limited
        else frozenset({None})
    )
    if (
        index.osv_outcome_state != expected_state
        or index.osv_outcome_reason not in expected_reasons
    ):
        raise DependencyProjectionError
    return result


def _non_result_outcome_state(
    evaluation: SourceDependencyEvaluation, failure_reason: str | None
) -> str:
    if failure_reason is not None:
        return "FAILED"
    if evaluation.decision in {
        DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES,
        DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES_IN_SCOPE,
    }:
        return "NOT_APPLICABLE"
    if evaluation.decision in {
        DependencyEvaluationDecision.PARTIAL_NO_SUPPORTED_COORDINATES,
        DependencyEvaluationDecision.PARTIAL_PREREQUISITE_INCOMPLETE,
    }:
        return "PARTIAL"
    raise DependencyProjectionError


def _non_result_outcome_reason(evaluation: SourceDependencyEvaluation) -> str:
    if evaluation.decision is DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES:
        return "NO_PACKAGES_OBSERVED"
    if (
        evaluation.decision
        is DependencyEvaluationDecision.NOT_APPLICABLE_NO_PACKAGES_IN_SCOPE
    ):
        return "NO_PACKAGES_IN_ADVISORY_SCOPE"
    if evaluation.mixed_scope_gaps:
        return "MIXED_SCOPE_PACKAGE_OBSERVATION"
    if (
        evaluation.decision
        is DependencyEvaluationDecision.PARTIAL_PREREQUISITE_INCOMPLETE
    ):
        return "SYFT_PREREQUISITE_PARTIAL"
    if (
        evaluation.decision
        is DependencyEvaluationDecision.PARTIAL_NO_SUPPORTED_COORDINATES
    ):
        return "NO_SUPPORTED_OSV_COORDINATES"
    raise DependencyProjectionError


def _candidate_required(
    observations: tuple[Any, ...],
    gaps: tuple[Any, ...],
    evaluation: SourceDependencyEvaluation,
) -> bool:
    return bool(
        evaluation.decision is DependencyEvaluationDecision.OSV_RUN_REQUIRED
        and not gaps
        and any(
            item.classification is PackageScopeClassification.IN_SCOPE
            for item in observations
        )
    )


def _gaps_by_package(
    evaluation: SourceDependencyEvaluation,
) -> dict[str, tuple[Any, ...]]:
    grouped: dict[str, list[Any]] = {}
    for gap in (*evaluation.mixed_scope_gaps, *evaluation.coordinate_gaps):
        grouped.setdefault(gap.package_key, []).append(gap)
    return {key: tuple(value) for key, value in grouped.items()}


def _summary(
    package: _PackageComponent,
    *,
    locations: tuple[Mapping[str, Any], ...],
    evaluation: str,
    reason: str | None,
    advisories: tuple[SourceDependencyAdvisorySummary, ...],
) -> SourceDependencySummary:
    if (
        evaluation not in {"COMPLETE", "PARTIAL", "FAILED", "NOT_APPLICABLE"}
        or reason is not None
        and reason not in (_PACKAGE_REASONS | _STAGE_REASONS | _OSV_FAILURE_REASONS)
        or evaluation in {"FAILED", "NOT_APPLICABLE"}
        and advisories
    ):
        raise DependencyProjectionError
    advisory_aliases = tuple(
        sorted(
            {
                value
                for advisory in advisories
                for value in (
                    *advisory.aliases,
                    *advisory.cve_aliases,
                    *advisory.ghsa_aliases,
                )
            }
        )
    )
    fixed_versions = tuple(
        sorted(
            {
                value
                for advisory in advisories
                for value in advisory.fixed_versions
            }
        )
    )
    priority_bands = tuple(sorted({item.priority_band for item in advisories}))
    return SourceDependencySummary(
        component_ref=package.component_ref,
        name=package.name,
        version=package.version,
        package_type=package.package_type,
        purl=package.purl,
        locations=locations,
        vulnerability_evaluation=evaluation,
        vulnerability_evaluation_reason=reason,
        known_vulnerability_count=len(advisories) if evaluation == "COMPLETE" else None,
        advisories=advisories,
        advisory_aliases=advisory_aliases,
        fixed_versions=fixed_versions,
        priority_bands=priority_bands,
    )


def _build_report_index(
    report: Mapping[str, Any], priorities: Mapping[str, str]
) -> _ReportIndex:
    root = _mapping(report)
    scope = _mapping_field(root, "scope")
    source_run_id = _string(scope, "source_run_id")
    repository_digest = _string(scope, "repository_digest")
    profile_digest = _string(scope, "profile_digest")
    plan_digest = _string(scope, "plan_digest")
    components = _list(root, "components")
    evidence = _list(root, "evidence")
    findings = _list(root, "findings")
    outcomes = _list(root, "coverage_outcomes")
    packages: dict[str, _PackageComponent] = {}
    for raw in components:
        component = _mapping(raw)
        if component.get("component_kind") != "PACKAGE":
            continue
        component_ref = _string(component, "component_ref")
        package_key = _string(component, "native_component_identity")
        payload = _mapping_field(component, "payload")
        if (
            payload.get("kind") != "PACKAGE_COMPONENT"
            or _string(payload, "package_key") != package_key
            or build_component_ref(ComponentKind.PACKAGE, package_key) != component_ref
            or component_ref in packages
        ):
            raise DependencyProjectionError
        packages[component_ref] = _PackageComponent(
            component_ref=component_ref,
            package_key=package_key,
            name=_string(payload, "package_name"),
            version=_optional_string(payload, "package_version"),
            package_type=_string(payload, "package_type"),
            purl=_optional_string(payload, "purl"),
        )

    evidence_by_id: dict[str, Mapping[str, Any]] = {}
    syft_by_evidence: dict[str, _SyftObservation] = {}
    observations_by_package: dict[str, list[_SyftObservation]] = {}
    locations_by_component: dict[str, set[str]] = {
        component_ref: set() for component_ref in packages
    }
    for raw in evidence:
        item = _mapping(raw)
        evidence_id = _string(item, "evidence_id")
        if evidence_id in evidence_by_id:
            raise DependencyProjectionError
        evidence_by_id[evidence_id] = item
        if item.get("authority") != EvidenceAuthority.SYFT.value:
            continue
        if item.get("evidence_kind") != "SYFT_PACKAGE_OBSERVATION":
            continue
        payload = _mapping_field(item, "payload")
        component_refs = _string_tuple(item, "component_refs")
        if len(component_refs) != 1 or component_refs[0] not in packages:
            raise DependencyProjectionError
        component_ref = component_refs[0]
        package = packages[component_ref]
        package_key = _string(payload, "package_key")
        observation_id = _string(payload, "package_observation_id")
        if (
            payload.get("kind") != "SYFT_PACKAGE_OBSERVATION"
            or package_key != package.package_key
            or item.get("native_identity") != observation_id
            or evidence_id in syft_by_evidence
        ):
            raise DependencyProjectionError
        location_paths = _repository_paths(item)
        observation = _SyftObservation(
            evidence_id,
            observation_id,
            package_key,
            component_ref,
            location_paths,
        )
        syft_by_evidence[evidence_id] = observation
        observations_by_package.setdefault(package_key, []).append(observation)
        locations_by_component[component_ref].update(location_paths)
    if set(observations_by_package) != {
        package.package_key for package in packages.values()
    }:
        raise DependencyProjectionError

    advisories_by_package: dict[str, list[_ProjectedAdvisory]] = {}
    public_ids: set[str] = set()
    relationships: dict[str, set[str]] = {}
    package_by_ref = packages
    for raw in findings:
        finding = _mapping(raw)
        if finding.get("authority") != EvidenceAuthority.OSV.value:
            continue
        if finding.get("category") != "DEPENDENCY_VULNERABILITY":
            raise DependencyProjectionError
        finding_id = _string(finding, "finding_id")
        native_finding_id = _string(finding, "native_finding_identity")
        subject = _mapping_field(finding, "subject")
        component_ref = _string(subject, "component_ref")
        package = package_by_ref.get(component_ref)
        primary_refs = _string_tuple(finding, "primary_evidence_refs")
        supporting_refs = _string_tuple(finding, "supporting_evidence_refs")
        primary = tuple(evidence_by_id.get(value) for value in primary_refs)
        supporting = tuple(syft_by_evidence.get(value) for value in supporting_refs)
        groups = tuple(
            item
            for item in primary
            if item is not None and item.get("evidence_kind") == "OSV_ADVISORY_GROUP"
        )
        if (
            package is None
            or subject.get("kind") != "PACKAGE"
            or finding.get("native_identity_schema") != OSV_FINDING_IDENTITY_SCHEMA
            or build_finding_id(
                EvidenceAuthority.OSV,
                OSV_FINDING_IDENTITY_SCHEMA,
                native_finding_id,
            )
            != finding_id
            or finding_id in public_ids
            or any(item is None for item in primary)
            or any(item is None for item in supporting)
            or not supporting
            or len(groups) != 1
        ):
            raise DependencyProjectionError
        group = groups[0]
        payload = _mapping_field(group, "payload")
        package_observation_ids = _string_tuple(payload, "package_observation_ids")
        supporting_observation_ids = tuple(
            sorted(item.package_observation_id for item in supporting if item is not None)
        )
        if (
            group.get("authority") != EvidenceAuthority.OSV.value
            or _string_tuple(group, "component_refs") != (component_ref,)
            or payload.get("kind") != "OSV_ADVISORY_GROUP"
            or _string(payload, "finding_id") != native_finding_id
            or _string(payload, "advisory_group_key")
            != _string(group, "native_identity")
            or package_observation_ids != supporting_observation_ids
            or any(
                item is None
                or item.component_ref != component_ref
                or item.package_key != package.package_key
                for item in supporting
            )
        ):
            raise DependencyProjectionError
        priority = priorities.get(finding_id)
        if priority not in _PRIORITY_BANDS:
            raise DependencyProjectionError
        osv_record_ids = _string_tuple(payload, "osv_record_ids")
        aliases = _string_tuple(payload, "aliases")
        cve_aliases = _string_tuple(payload, "cve_aliases")
        ghsa_aliases = _string_tuple(payload, "ghsa_aliases")
        fixed_versions = _string_tuple(payload, "fixed_versions")
        identity_values = set(osv_record_ids) | set(aliases)
        seen = relationships.setdefault(package.package_key, set())
        if not identity_values or seen & identity_values:
            raise DependencyProjectionError
        seen.update(identity_values)
        projected = _ProjectedAdvisory(
            summary=SourceDependencyAdvisorySummary(
                canonical_advisory_id=_string(payload, "canonical_advisory_id"),
                finding_id=finding_id,
                osv_record_ids=osv_record_ids,
                aliases=aliases,
                cve_aliases=cve_aliases,
                ghsa_aliases=ghsa_aliases,
                fixed_versions=fixed_versions,
                priority_band=priority,
            ),
            native_finding_id=native_finding_id,
            advisory_group_key=_string(payload, "advisory_group_key"),
            package_key=package.package_key,
            package_observation_ids=package_observation_ids,
        )
        advisories_by_package.setdefault(package.package_key, []).append(projected)
        public_ids.add(finding_id)

    osv_outcomes = tuple(
        _mapping(item)
        for item in outcomes
        if _mapping(item).get("authority") == EvidenceAuthority.OSV.value
    )
    if len(osv_outcomes) > 1:
        raise DependencyProjectionError
    outcome = osv_outcomes[0] if osv_outcomes else None
    return _ReportIndex(
        source_run_id=source_run_id,
        repository_digest=repository_digest,
        profile_digest=profile_digest,
        plan_digest=plan_digest,
        packages=tuple(sorted(packages.values(), key=lambda item: item.component_ref)),
        observations_by_package={
            key: tuple(sorted(value, key=lambda item: item.package_observation_id))
            for key, value in observations_by_package.items()
        },
        locations_by_component={
            key: tuple(
                {"kind": "REPOSITORY_PATH", "path": path}
                for path in sorted(value)
            )
            for key, value in locations_by_component.items()
        },
        advisories_by_package={
            key: tuple(sorted(value, key=lambda item: item.summary.finding_id))
            for key, value in advisories_by_package.items()
        },
        osv_outcome_state=None if outcome is None else _string(outcome, "state"),
        osv_outcome_reason=(
            None if outcome is None else _optional_string(outcome, "reason_code")
        ),
    )


def _repository_paths(item: Mapping[str, Any]) -> tuple[str, ...]:
    paths = []
    for raw in _list(item, "locations"):
        location = _mapping(raw)
        if set(location) != {"kind", "path"} or location.get("kind") != "REPOSITORY_PATH":
            raise DependencyProjectionError
        paths.append(_string(location, "path"))
    if not paths or paths != sorted(set(paths)):
        raise DependencyProjectionError
    return tuple(paths)


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DependencyProjectionError
    return value


def _mapping_field(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    return _mapping(value.get(key))


def _list(value: Mapping[str, Any], key: str) -> list[Any]:
    result = value.get(key)
    if not isinstance(result, list):
        raise DependencyProjectionError
    return result


def _string(value: Mapping[str, Any], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise DependencyProjectionError
    return result


def _optional_string(value: Mapping[str, Any], key: str) -> str | None:
    result = value.get(key)
    if result is not None and (not isinstance(result, str) or not result):
        raise DependencyProjectionError
    return result


def _string_tuple(value: Mapping[str, Any], key: str) -> tuple[str, ...]:
    result = value.get(key)
    if (
        not isinstance(result, list)
        or any(not isinstance(item, str) or not item for item in result)
        or result != sorted(set(result))
    ):
        raise DependencyProjectionError
    return tuple(result)
