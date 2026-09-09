from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from securescan.advisories.osv import (
    OSV_API_VERSION,
    OSV_PROVIDER_ID,
    OsvAdvisoryObservation,
    OsvAdvisoryReference,
    OsvCandidateMatch,
    OsvCvssEvidence,
    OsvCvssScope,
    OsvDependencyAnalysis,
    OsvQueryCandidate,
    build_osv_service_contract,
    group_advisories,
)
from securescan.advisories.osv import (
    canonical_json as osv_canonical_json,
)
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ArtifactKind, ExecutionOutcome, JobFailureCategory, JobStatus
from securescan.persistence.database import (
    AnalysisRunRow,
    JobRow,
    SourceOrchestrationAttemptRow,
    SourceOrchestrationDependencyEvaluationRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationRow,
    SourceOrchestrationScannerJobRow,
    SourceOsvRequestPermitRow,
    ToolExecutionRow,
    utc_now,
)

from .dependency_evaluation import (
    DEPENDENCY_EVALUATION_SCHEMA_VERSION,
    DependencyEvaluationDecision,
    SourceDependencyEvaluation,
    SourceDependencyEvaluationService,
    rebuild_eligible_osv_candidates,
)
from .execution import (
    _valid_durable_clean_receipt,
    source_scanner_job_id,
)
from .execution_models import SafeSourceNativeResult
from .models import (
    OrchestrationContainmentState,
    OrchestrationLifecycleState,
    OrchestrationNodeDisposition,
    OrchestrationNodeLifecycleState,
    SourceAuthority,
)

OSV_EXECUTION_INPUT_SCHEMA_VERSION = "securescan-source-osv-execution-input-s6cb-v1"
OSV_EXECUTION_INPUT_MEDIA_TYPE = "application/vnd.securescan.source-osv-input+json"
OSV_NATIVE_RESULT_SCHEMA_VERSION = "securescan-source-osv-native-result-s6cb-v1"
OSV_NATIVE_RESULT_MEDIA_TYPE = "application/vnd.securescan.source-osv-result+json"
OSV_HELPER_PROTOCOL_VERSION = "securescan-source-osv-helper-s6cb-v1"
OSV_JOB_PAYLOAD_SCHEMA_VERSION = "securescan-source-osv-job-s6cb-v1"
OSV_ADAPTER_VERSION = "s6cb-v1"
OSV_MAX_JOB_ATTEMPTS = 3

_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_JOB_KEY_DOMAIN = b"securescan-source-osv-job-s6cb-v1\0"
_SERVICE_CONTRACT_DIGEST = hashlib.sha256(
    osv_canonical_json(build_osv_service_contract())
).hexdigest()


class SourceOsvExecutionError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Source OSV execution failed")


class SourceOsvExecutionConflictError(SourceOsvExecutionError):
    pass


class OsvRequestOperation(StrEnum):
    QUERY_BATCH = "QUERY_BATCH"
    ADVISORY_GET = "ADVISORY_GET"


class SourceOsvFailureCode(StrEnum):
    NETWORK_FAILURE = "NETWORK_FAILURE"
    CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
    READ_WRITE_TIMEOUT = "READ_WRITE_TIMEOUT"
    HTTP_RATE_LIMIT = "HTTP_RATE_LIMIT"
    HTTP_RETRYABLE_SERVER_ERROR = "HTTP_RETRYABLE_SERVER_ERROR"
    HTTP_PERMANENT_ERROR = "HTTP_PERMANENT_ERROR"
    INVALID_OSV_SCHEMA = "INVALID_OSV_SCHEMA"
    PAGINATION_INTEGRITY_FAILURE = "PAGINATION_INTEGRITY_FAILURE"
    OSV_DATA_CHANGED_DURING_QUERY = "OSV_DATA_CHANGED_DURING_QUERY"
    DEPENDENCY_INPUT_INTEGRITY_FAILURE = "DEPENDENCY_INPUT_INTEGRITY_FAILURE"
    RESULT_CANONICALIZATION_FAILURE = "RESULT_CANONICALIZATION_FAILURE"
    ARTIFACT_PERSISTENCE_FAILURE = "ARTIFACT_PERSISTENCE_FAILURE"
    HELPER_EXECUTION_FAILURE = "HELPER_EXECUTION_FAILURE"
    ATTEMPT_CONTAINMENT_FAILURE = "ATTEMPT_CONTAINMENT_FAILURE"
    CANCELLED = "CANCELLED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"


_RETRYABLE_OSV_FAILURES = frozenset(
    {
        SourceOsvFailureCode.NETWORK_FAILURE,
        SourceOsvFailureCode.CONNECT_TIMEOUT,
        SourceOsvFailureCode.READ_WRITE_TIMEOUT,
        SourceOsvFailureCode.HTTP_RATE_LIMIT,
        SourceOsvFailureCode.HTTP_RETRYABLE_SERVER_ERROR,
        SourceOsvFailureCode.OSV_DATA_CHANGED_DURING_QUERY,
        SourceOsvFailureCode.HELPER_EXECUTION_FAILURE,
    }
)


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _load_json(payload: bytes, *, maximum: int = 100 * 1024 * 1024) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise SourceOsvExecutionError
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (TypeError, ValueError, UnicodeError):
        raise SourceOsvExecutionError from None
    if not isinstance(value, dict) or _canonical_json(value) != payload:
        raise SourceOsvExecutionError
    return value


def _valid_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (TypeError, ValueError):
        return False


def _candidate_data(value: OsvQueryCandidate) -> dict[str, Any]:
    return {
        "candidate_id": value.candidate_id,
        "locations": list(value.locations),
        "package_key": value.package_key,
        "package_name": value.package_name,
        "package_observation_ids": list(value.package_observation_ids),
        "package_type": value.package_type,
        "package_version": value.package_version,
        "projection_id": value.projection_id,
        "purl": value.purl,
        "purl_type": value.purl_type,
        "snapshot_digest": value.snapshot_digest,
        "syft_binding_digest": value.syft_binding_digest,
    }


def _candidate(value: object) -> OsvQueryCandidate:
    if not isinstance(value, dict) or set(value) != {
        "candidate_id",
        "locations",
        "package_key",
        "package_name",
        "package_observation_ids",
        "package_type",
        "package_version",
        "projection_id",
        "purl",
        "purl_type",
        "snapshot_digest",
        "syft_binding_digest",
    }:
        raise SourceOsvExecutionError
    try:
        return OsvQueryCandidate(
            candidate_id=value["candidate_id"],
            package_key=value["package_key"],
            package_name=value["package_name"],
            package_version=value["package_version"],
            package_type=value["package_type"],
            purl=value["purl"],
            purl_type=value["purl_type"],
            package_observation_ids=tuple(value["package_observation_ids"]),
            locations=tuple(value["locations"]),
            projection_id=value["projection_id"],
            snapshot_digest=value["snapshot_digest"],
            syft_binding_digest=value["syft_binding_digest"],
        )
    except (KeyError, TypeError, ValueError):
        raise SourceOsvExecutionError from None


@dataclass(frozen=True, slots=True)
class SourceOsvExecutionInput:
    run_id: str
    node_id: str
    job_id: str
    repository_digest: str
    profile_digest: str
    plan_digest: str
    scope_digest: str
    dependency_evaluation_sha256: str
    dependency_evaluation_size_bytes: int
    dependency_evaluation_schema_version: str
    syft_node_id: str
    syft_job_id: str
    syft_selected_attempt_number: int
    syft_native_result_sha256: str
    candidates: tuple[OsvQueryCandidate, ...]
    coverage_limited: bool
    service_contract_digest: str = _SERVICE_CONTRACT_DIGEST
    schema_version: str = OSV_EXECUTION_INPUT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        candidate_ids = tuple(item.candidate_id for item in self.candidates)
        if (
            self.schema_version != OSV_EXECUTION_INPUT_SCHEMA_VERSION
            or self.service_contract_digest != _SERVICE_CONTRACT_DIGEST
            or not _valid_uuid(self.run_id)
            or not _valid_uuid(self.job_id)
            or not _valid_uuid(self.syft_job_id)
            or any(
                _SHA256.fullmatch(value or "") is None
                for value in (
                    self.node_id,
                    self.repository_digest,
                    self.profile_digest,
                    self.plan_digest,
                    self.scope_digest,
                    self.dependency_evaluation_sha256,
                    self.syft_node_id,
                    self.syft_native_result_sha256,
                )
            )
            or type(self.dependency_evaluation_size_bytes) is not int
            or self.dependency_evaluation_size_bytes < 1
            or self.dependency_evaluation_schema_version
            != DEPENDENCY_EVALUATION_SCHEMA_VERSION
            or type(self.syft_selected_attempt_number) is not int
            or self.syft_selected_attempt_number < 1
            or not self.candidates
            or any(not isinstance(item, OsvQueryCandidate) for item in self.candidates)
            or candidate_ids != tuple(sorted(set(candidate_ids)))
            or type(self.coverage_limited) is not bool
        ):
            raise SourceOsvExecutionError

    def canonical_data(self) -> dict[str, Any]:
        return {
            "candidates": [_candidate_data(item) for item in self.candidates],
            "coverage_limited": self.coverage_limited,
            "dependency_evaluation_schema_version": self.dependency_evaluation_schema_version,
            "dependency_evaluation_sha256": self.dependency_evaluation_sha256,
            "dependency_evaluation_size_bytes": self.dependency_evaluation_size_bytes,
            "job_id": self.job_id,
            "node_id": self.node_id,
            "plan_digest": self.plan_digest,
            "profile_digest": self.profile_digest,
            "repository_digest": self.repository_digest,
            "run_id": self.run_id,
            "schema_version": self.schema_version,
            "scope_digest": self.scope_digest,
            "service_contract_digest": self.service_contract_digest,
            "syft_job_id": self.syft_job_id,
            "syft_native_result_sha256": self.syft_native_result_sha256,
            "syft_node_id": self.syft_node_id,
            "syft_selected_attempt_number": self.syft_selected_attempt_number,
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.canonical_data())

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json()).hexdigest()

    @classmethod
    def from_json(cls, payload: bytes) -> SourceOsvExecutionInput:
        root = _load_json(payload)
        if set(root) != set(cls.__dataclass_fields__):
            raise SourceOsvExecutionError
        try:
            root["candidates"] = tuple(_candidate(item) for item in root["candidates"])
            result = cls(**root)
        except (TypeError, ValueError):
            raise SourceOsvExecutionError from None
        if result.canonical_json() != payload:
            raise SourceOsvExecutionError
        return result


def _cvss_data(value: OsvCvssEvidence) -> dict[str, Any]:
    return {
        "base_score": value.base_score,
        "scope": value.scope.value,
        "source": value.source,
        "type": value.cvss_type,
        "vector": value.vector,
    }


def _advisory_data(value: OsvAdvisoryObservation) -> dict[str, Any]:
    return {
        "aliases": list(value.aliases),
        "api_version": value.api_version,
        "applicable_package_key": value.applicable_package_key,
        "cve_aliases": list(value.cve_aliases),
        "cvss": [_cvss_data(item) for item in value.cvss],
        "fixed_versions": list(value.fixed_versions),
        "ghsa_aliases": list(value.ghsa_aliases),
        "matched_by": value.matched_by,
        "modified": value.modified,
        "osv_record_id": value.osv_record_id,
        "published": value.published,
        "source_service": value.source_service,
        "summary": value.summary,
    }


def _match_data(value: OsvCandidateMatch) -> dict[str, Any]:
    return {
        "advisories": [_advisory_data(item) for item in value.advisories],
        "candidate": _candidate_data(value.candidate),
        "references": [
            {"modified": item.modified, "osv_record_id": item.osv_record_id}
            for item in value.references
        ],
    }


def _advisory(value: object) -> OsvAdvisoryObservation:
    if not isinstance(value, dict):
        raise SourceOsvExecutionError
    try:
        cvss = tuple(
            OsvCvssEvidence(
                cvss_type=item["type"],
                vector=item["vector"],
                source=item["source"],
                base_score=item["base_score"],
                scope=OsvCvssScope(item["scope"]),
            )
            for item in value["cvss"]
        )
        return OsvAdvisoryObservation(
            osv_record_id=value["osv_record_id"],
            modified=value["modified"],
            published=value["published"],
            aliases=tuple(value["aliases"]),
            cve_aliases=tuple(value["cve_aliases"]),
            ghsa_aliases=tuple(value["ghsa_aliases"]),
            summary=value["summary"],
            applicable_package_key=value["applicable_package_key"],
            fixed_versions=tuple(value["fixed_versions"]),
            cvss=cvss,
            source_service=value["source_service"],
            api_version=value["api_version"],
            matched_by=value["matched_by"],
        )
    except (KeyError, TypeError, ValueError):
        raise SourceOsvExecutionError from None


def analysis_document(analysis: OsvDependencyAnalysis) -> dict[str, Any]:
    if not isinstance(analysis, OsvDependencyAnalysis):
        raise SourceOsvExecutionError
    return {
        "canonical": analysis.canonical_data(),
        "candidate_matches": [_match_data(item) for item in analysis.candidate_matches],
    }


def analysis_from_document(value: object) -> OsvDependencyAnalysis:
    if not isinstance(value, dict) or set(value) != {"canonical", "candidate_matches"}:
        raise SourceOsvExecutionError
    try:
        matches = []
        for item in value["candidate_matches"]:
            candidate = _candidate(item["candidate"])
            references = tuple(
                OsvAdvisoryReference(entry["osv_record_id"], entry["modified"])
                for entry in item["references"]
            )
            advisories = tuple(_advisory(entry) for entry in item["advisories"])
            matches.append(OsvCandidateMatch(candidate, references, advisories))
        ordered_matches = tuple(matches)
        candidates = tuple(item.candidate for item in ordered_matches)
        findings = tuple(
            sorted(
                (
                    finding
                    for item in ordered_matches
                    for finding in group_advisories(item.candidate, item.advisories)
                ),
                key=lambda item: item.finding_id,
            )
        )
        candidate_ids = tuple(item.candidate_id for item in candidates)
        analysis = OsvDependencyAnalysis(
            candidates=candidates,
            gaps=(),
            candidate_matches=ordered_matches,
            findings=findings,
            completed_candidate_ids=candidate_ids,
            zero_advisory_candidate_ids=tuple(
                item.candidate.candidate_id for item in ordered_matches if not item.references
            ),
        )
    except (KeyError, TypeError, ValueError):
        raise SourceOsvExecutionError from None
    if analysis.canonical_data() != value["canonical"]:
        raise SourceOsvExecutionError
    return analysis


@dataclass(frozen=True, slots=True)
class SafeSourceOsvResult:
    run_id: str
    node_id: str
    job_id: str
    attempt_number: int
    repository_digest: str
    profile_digest: str
    plan_digest: str
    scope_digest: str
    dependency_evaluation_sha256: str
    syft_native_result_sha256: str
    candidate_ids: tuple[str, ...]
    analysis: OsvDependencyAnalysis = field(repr=False)
    analysis_sha256: str = ""
    coverage_limited: bool = False
    authority: str = OSV_PROVIDER_ID
    api_version: str = OSV_API_VERSION
    analyzer_id: str = "osv-dependency-advisory-v1"
    service_contract_digest: str = _SERVICE_CONTRACT_DIGEST
    schema_version: str = OSV_NATIVE_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        expected_analysis_sha = hashlib.sha256(self.analysis.canonical_json()).hexdigest()
        if not self.analysis_sha256:
            object.__setattr__(self, "analysis_sha256", expected_analysis_sha)
        if (
            self.schema_version != OSV_NATIVE_RESULT_SCHEMA_VERSION
            or self.authority != OSV_PROVIDER_ID
            or self.api_version != OSV_API_VERSION
            or self.analyzer_id != "osv-dependency-advisory-v1"
            or self.service_contract_digest != _SERVICE_CONTRACT_DIGEST
            or not _valid_uuid(self.run_id)
            or not _valid_uuid(self.job_id)
            or type(self.attempt_number) is not int
            or self.attempt_number < 1
            or any(
                _SHA256.fullmatch(item or "") is None
                for item in (
                    self.node_id,
                    self.repository_digest,
                    self.profile_digest,
                    self.plan_digest,
                    self.scope_digest,
                    self.dependency_evaluation_sha256,
                    self.syft_native_result_sha256,
                    self.analysis_sha256,
                )
            )
            or self.analysis_sha256 != expected_analysis_sha
            or self.candidate_ids != tuple(
                item.candidate_id for item in self.analysis.candidates
            )
            or type(self.coverage_limited) is not bool
        ):
            raise SourceOsvExecutionError

    @classmethod
    def from_analysis(
        cls,
        execution_input: SourceOsvExecutionInput,
        *,
        attempt_number: int,
        analysis: OsvDependencyAnalysis,
    ) -> SafeSourceOsvResult:
        return cls(
            run_id=execution_input.run_id,
            node_id=execution_input.node_id,
            job_id=execution_input.job_id,
            attempt_number=attempt_number,
            repository_digest=execution_input.repository_digest,
            profile_digest=execution_input.profile_digest,
            plan_digest=execution_input.plan_digest,
            scope_digest=execution_input.scope_digest,
            dependency_evaluation_sha256=execution_input.dependency_evaluation_sha256,
            syft_native_result_sha256=execution_input.syft_native_result_sha256,
            candidate_ids=tuple(item.candidate_id for item in analysis.candidates),
            analysis=analysis,
            coverage_limited=execution_input.coverage_limited,
        )

    def canonical_data(self) -> dict[str, Any]:
        return {
            "analysis": analysis_document(self.analysis),
            "analysis_sha256": self.analysis_sha256,
            "analyzer_id": self.analyzer_id,
            "api_version": self.api_version,
            "attempt_number": self.attempt_number,
            "authority": self.authority,
            "candidate_ids": list(self.candidate_ids),
            "coverage_limited": self.coverage_limited,
            "dependency_evaluation_sha256": self.dependency_evaluation_sha256,
            "job_id": self.job_id,
            "node_id": self.node_id,
            "plan_digest": self.plan_digest,
            "profile_digest": self.profile_digest,
            "repository_digest": self.repository_digest,
            "run_id": self.run_id,
            "schema_version": self.schema_version,
            "scope_digest": self.scope_digest,
            "service_contract_digest": self.service_contract_digest,
            "syft_native_result_sha256": self.syft_native_result_sha256,
        }

    def canonical_json(self) -> bytes:
        return _canonical_json(self.canonical_data())

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json()).hexdigest()

    @classmethod
    def from_json(cls, payload: bytes) -> SafeSourceOsvResult:
        root = _load_json(payload)
        expected = set(cls.__dataclass_fields__) - {"analysis"}
        if set(root) != expected | {"analysis"}:
            raise SourceOsvExecutionError
        try:
            root["candidate_ids"] = tuple(root["candidate_ids"])
            root["analysis"] = analysis_from_document(root["analysis"])
            result = cls(**root)
        except (TypeError, ValueError):
            raise SourceOsvExecutionError from None
        if result.canonical_json() != payload:
            raise SourceOsvExecutionError
        return result


@dataclass(frozen=True, slots=True)
class SourceOsvJobRecord:
    run_id: str
    node_id: str
    job_id: str
    execution_input_sha256: str
    execution_input_size_bytes: int
    created: bool


@dataclass(frozen=True, slots=True)
class OsvRequestPermit:
    job_id: str
    attempt_number: int
    request_sequence: int
    operation_kind: OsvRequestOperation
    logical_request_digest: str
    transport_attempt_number: int
    authorized_at: datetime


class SourceOsvJobService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        dependency_evaluations: SourceDependencyEvaluationService,
    ) -> None:
        self._sessions = session_factory
        self._artifacts = artifact_store
        self._evaluations = dependency_evaluations

    def create_job(self, *, run_id: str, node_id: str) -> SourceOsvJobRecord:
        evaluation_record = self._evaluations.load(run_id=run_id, osv_node_id=node_id)
        evaluation = evaluation_record.evaluation
        if evaluation.decision is not DependencyEvaluationDecision.OSV_RUN_REQUIRED:
            raise SourceOsvExecutionConflictError
        syft_result = self._load_syft_result(evaluation)
        candidates = rebuild_eligible_osv_candidates(evaluation, syft_result)
        job_id = source_scanner_job_id(node_id)
        execution_input = SourceOsvExecutionInput(
            run_id=run_id,
            node_id=node_id,
            job_id=job_id,
            repository_digest=syft_result.repository_digest,
            profile_digest=syft_result.profile_digest,
            plan_digest=syft_result.plan_digest,
            scope_digest=evaluation.scope.scope_digest,
            dependency_evaluation_sha256=evaluation_record.artifact_sha256,
            dependency_evaluation_size_bytes=evaluation_record.artifact_size_bytes,
            dependency_evaluation_schema_version=evaluation.schema_version,
            syft_node_id=evaluation.syft_prerequisite.node_id,
            syft_job_id=evaluation.syft_prerequisite.job_id,
            syft_selected_attempt_number=evaluation.syft_prerequisite.selected_attempt_number,
            syft_native_result_sha256=evaluation.syft_prerequisite.native_result_sha256,
            candidates=candidates,
            coverage_limited=evaluation.coverage_limited,
        )
        payload = execution_input.canonical_json()
        artifact = self._artifacts.put(
            payload,
            kind=ArtifactKind.SOURCE_OSV_EXECUTION_INPUT,
            media_type=OSV_EXECUTION_INPUT_MEDIA_TYPE,
            sanitized=True,
        )
        if (
            artifact.storage_path != f"sha256/{artifact.sha256[:2]}/{artifact.sha256}"
            or self._artifacts.read_by_sha256(
                artifact.sha256, expected_size_bytes=artifact.size_bytes
            )
            != payload
        ):
            raise SourceOsvExecutionError
        now = _utc(utc_now())
        try:
            with self._sessions.begin() as session:
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == run_id)
                    .with_for_update()
                )
                node = session.scalar(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.node_id == node_id)
                    .with_for_update()
                )
                durable_evaluation = session.get(
                    SourceOrchestrationDependencyEvaluationRow, (run_id, node_id)
                )
                existing = session.scalar(
                    select(SourceOrchestrationScannerJobRow).where(
                        SourceOrchestrationScannerJobRow.node_id == node_id
                    )
                )
                database_now = _database_now(session)
                if existing is not None:
                    if (
                        parent is None
                        or node is None
                        or parent.lifecycle_state
                        != OrchestrationLifecycleState.ACTIVE.value
                        or parent.cancel_requested
                        or database_now >= _utc(parent.deadline_at)
                        or node.lifecycle_state
                        not in {
                            OrchestrationNodeLifecycleState.QUEUED.value,
                            OrchestrationNodeLifecycleState.RUNNING.value,
                            OrchestrationNodeLifecycleState.RETRY_PENDING.value,
                            OrchestrationNodeLifecycleState.RECONCILIATION_REQUIRED.value,
                            OrchestrationNodeLifecycleState.TERMINAL.value,
                        }
                        or not self._matches(
                            existing,
                            execution_input,
                            artifact.sha256,
                            artifact.size_bytes,
                        )
                    ):
                        raise SourceOsvExecutionConflictError
                    return SourceOsvJobRecord(
                        run_id,
                        node_id,
                        existing.job_id,
                        artifact.sha256,
                        artifact.size_bytes,
                        False,
                    )
                if (
                    parent is None
                    or node is None
                    or durable_evaluation is None
                    or parent.lifecycle_state != OrchestrationLifecycleState.ACTIVE.value
                    or parent.cancel_requested
                    or database_now >= _utc(parent.deadline_at)
                    or node.authority != SourceAuthority.OSV.value
                    or node.lifecycle_state != OrchestrationNodeLifecycleState.READY.value
                    or node.scope_digest != execution_input.scope_digest
                    or durable_evaluation.evaluation_artifact_sha256
                    != execution_input.dependency_evaluation_sha256
                    or durable_evaluation.syft_native_result_sha256
                    != execution_input.syft_native_result_sha256
                ):
                    raise SourceOsvExecutionConflictError
                job = JobRow(
                    id=job_id,
                    run_id=run_id,
                    adapter_id=SourceAuthority.OSV.value,
                    status=JobStatus.QUEUED.value,
                    priority=100,
                    attempt_count=0,
                    max_attempts=OSV_MAX_JOB_ATTEMPTS,
                    available_at=now,
                    cancel_requested=False,
                    idempotency_key=_job_key(node_id),
                    payload_json={
                        "input_sha256": artifact.sha256,
                        "input_size_bytes": artifact.size_bytes,
                        "schema_version": OSV_JOB_PAYLOAD_SCHEMA_VERSION,
                    },
                    created_at=now,
                    updated_at=now,
                )
                mapping = SourceOrchestrationScannerJobRow(
                    job_id=job_id,
                    run_id=run_id,
                    node_id=node_id,
                    authority=SourceAuthority.OSV.value,
                    capability=node.capability,
                    analyzer_id=node.analyzer_id,
                    contract_digest=node.contract_digest,
                    input_kind="OSV_DEPENDENCY_INPUT",
                    context_digest=None,
                    context_artifact_sha256=None,
                    context_artifact_size_bytes=None,
                    context_artifact_storage_path=None,
                    projection_id=None,
                    projection_digest=None,
                    dependency_evaluation_sha256=evaluation_record.artifact_sha256,
                    dependency_evaluation_size_bytes=evaluation_record.artifact_size_bytes,
                    dependency_evaluation_schema_version=evaluation.schema_version,
                    syft_native_result_sha256=evaluation.syft_prerequisite.native_result_sha256,
                    osv_scope_digest=evaluation.scope.scope_digest,
                    execution_input_sha256=artifact.sha256,
                    execution_input_size_bytes=artifact.size_bytes,
                    execution_input_schema_version=execution_input.schema_version,
                    selected_attempt_number=None,
                    created_at=now,
                )
                session.add_all((job, mapping))
                node.lifecycle_state = OrchestrationNodeLifecycleState.QUEUED.value
                node.state_version += 1
                session.flush()
                return SourceOsvJobRecord(
                    run_id, node_id, job_id, artifact.sha256, artifact.size_bytes, True
                )
        except SourceOsvExecutionError:
            raise
        except IntegrityError:
            return self._load_existing_after_race(
                execution_input, artifact.sha256, artifact.size_bytes
            )
        except SQLAlchemyError:
            raise SourceOsvExecutionError from None

    def load_input(self, *, job_id: str) -> SourceOsvExecutionInput:
        try:
            with self._sessions() as session:
                mapping = session.get(SourceOrchestrationScannerJobRow, job_id)
                if (
                    mapping is None
                    or mapping.input_kind != "OSV_DEPENDENCY_INPUT"
                    or mapping.execution_input_sha256 is None
                    or mapping.execution_input_size_bytes is None
                ):
                    raise SourceOsvExecutionError
                payload = self._artifacts.read_by_sha256(
                    mapping.execution_input_sha256,
                    expected_size_bytes=mapping.execution_input_size_bytes,
                )
                result = SourceOsvExecutionInput.from_json(payload)
                if not self._matches(
                    mapping,
                    result,
                    mapping.execution_input_sha256,
                    mapping.execution_input_size_bytes,
                ):
                    raise SourceOsvExecutionError
                return result
        except SourceOsvExecutionError:
            raise
        except (OSError, SQLAlchemyError, ValueError):
            raise SourceOsvExecutionError from None

    def _load_existing_after_race(
        self,
        execution_input: SourceOsvExecutionInput,
        sha256: str,
        size_bytes: int,
    ) -> SourceOsvJobRecord:
        try:
            with self._sessions.begin() as session:
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == execution_input.run_id)
                    .with_for_update()
                )
                node = session.scalar(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.node_id == execution_input.node_id)
                    .with_for_update()
                )
                mapping = session.scalar(
                    select(SourceOrchestrationScannerJobRow)
                    .where(
                        SourceOrchestrationScannerJobRow.node_id
                        == execution_input.node_id
                    )
                    .with_for_update()
                )
                now = _database_now(session)
                if (
                    parent is None
                    or node is None
                    or mapping is None
                    or parent.lifecycle_state
                    != OrchestrationLifecycleState.ACTIVE.value
                    or parent.cancel_requested
                    or now >= _utc(parent.deadline_at)
                    or not self._matches(mapping, execution_input, sha256, size_bytes)
                ):
                    raise SourceOsvExecutionConflictError
                return SourceOsvJobRecord(
                    execution_input.run_id,
                    execution_input.node_id,
                    mapping.job_id,
                    sha256,
                    size_bytes,
                    False,
                )
        except SourceOsvExecutionError:
            raise
        except SQLAlchemyError:
            raise SourceOsvExecutionError from None

    def _load_syft_result(self, evaluation: SourceDependencyEvaluation) -> SafeSourceNativeResult:
        try:
            with self._sessions() as session:
                attempt = session.get(
                    SourceOrchestrationAttemptRow,
                    (
                        evaluation.syft_prerequisite.job_id,
                        evaluation.syft_prerequisite.selected_attempt_number,
                    ),
                )
                if (
                    attempt is None
                    or attempt.acceptance_state != "ACCEPTED"
                    or attempt.native_result_sha256
                    != evaluation.syft_prerequisite.native_result_sha256
                    or attempt.native_result_size_bytes is None
                ):
                    raise SourceOsvExecutionError
                payload = self._artifacts.read_by_sha256(
                    attempt.native_result_sha256,
                    expected_size_bytes=attempt.native_result_size_bytes,
                )
                return SafeSourceNativeResult.from_json(payload)
        except SourceOsvExecutionError:
            raise
        except Exception:
            raise SourceOsvExecutionError from None

    @staticmethod
    def _matches(
        mapping: SourceOrchestrationScannerJobRow,
        execution_input: SourceOsvExecutionInput,
        sha256: str,
        size_bytes: int,
    ) -> bool:
        return bool(
            mapping.job_id == execution_input.job_id
            and mapping.run_id == execution_input.run_id
            and mapping.node_id == execution_input.node_id
            and mapping.authority == SourceAuthority.OSV.value
            and mapping.input_kind == "OSV_DEPENDENCY_INPUT"
            and mapping.context_digest is None
            and mapping.projection_id is None
            and mapping.dependency_evaluation_sha256
            == execution_input.dependency_evaluation_sha256
            and mapping.dependency_evaluation_size_bytes
            == execution_input.dependency_evaluation_size_bytes
            and mapping.dependency_evaluation_schema_version
            == execution_input.dependency_evaluation_schema_version
            and mapping.syft_native_result_sha256
            == execution_input.syft_native_result_sha256
            and mapping.osv_scope_digest == execution_input.scope_digest
            and mapping.execution_input_sha256 == sha256 == execution_input.sha256()
            and mapping.execution_input_size_bytes == size_bytes
            and mapping.execution_input_schema_version == execution_input.schema_version
        )


class SourceOsvRequestPermitService:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def authorize(
        self,
        *,
        job_id: str,
        attempt_number: int,
        attempt_token: str,
        helper_identity: str,
        request_sequence: int,
        operation_kind: OsvRequestOperation,
        logical_request_digest: str,
        transport_attempt_number: int,
    ) -> OsvRequestPermit:
        if (
            not _valid_uuid(job_id)
            or not _valid_uuid(attempt_token)
            or type(attempt_number) is not int
            or attempt_number < 1
            or type(request_sequence) is not int
            or request_sequence < 1
            or not isinstance(operation_kind, OsvRequestOperation)
            or _SHA256.fullmatch(logical_request_digest or "") is None
            or _SHA256.fullmatch(helper_identity or "") is None
            or type(transport_attempt_number) is not int
            or transport_attempt_number < 1
        ):
            raise SourceOsvExecutionConflictError
        try:
            with self._sessions.begin() as session:
                unlocked = session.get(SourceOrchestrationScannerJobRow, job_id)
                if unlocked is None:
                    raise SourceOsvExecutionConflictError
                parent = session.scalar(
                    select(SourceOrchestrationRow)
                    .where(SourceOrchestrationRow.run_id == unlocked.run_id)
                    .with_for_update()
                )
                node = session.scalar(
                    select(SourceOrchestrationNodeRow)
                    .where(SourceOrchestrationNodeRow.node_id == unlocked.node_id)
                    .with_for_update()
                )
                mapping = session.scalar(
                    select(SourceOrchestrationScannerJobRow)
                    .where(SourceOrchestrationScannerJobRow.job_id == job_id)
                    .with_for_update()
                )
                job = session.scalar(select(JobRow).where(JobRow.id == job_id).with_for_update())
                attempt = session.scalar(
                    select(SourceOrchestrationAttemptRow)
                    .where(
                        SourceOrchestrationAttemptRow.job_id == job_id,
                        SourceOrchestrationAttemptRow.attempt_number == attempt_number,
                    )
                    .with_for_update()
                )
                previous = session.scalar(
                    select(func.max(SourceOsvRequestPermitRow.request_sequence)).where(
                        SourceOsvRequestPermitRow.job_id == job_id,
                        SourceOsvRequestPermitRow.attempt_number == attempt_number,
                    )
                )
                now = _database_now(session)
                if (
                    parent is None
                    or node is None
                    or mapping is None
                    or job is None
                    or attempt is None
                    or mapping.input_kind != "OSV_DEPENDENCY_INPUT"
                    or parent.lifecycle_state != OrchestrationLifecycleState.ACTIVE.value
                    or parent.cancel_requested
                    or now >= _utc(parent.deadline_at)
                    or node.lifecycle_state != OrchestrationNodeLifecycleState.RUNNING.value
                    or job.status != JobStatus.RUNNING.value
                    or job.cancel_requested
                    or job.lease_token != attempt.lease_token
                    or job.leased_by != attempt.worker_id
                    or job.lease_expires_at is None
                    or now >= _utc(job.lease_expires_at)
                    or attempt.attempt_token != attempt_token
                    or attempt.containment_state != OrchestrationContainmentState.ACTIVE.value
                    or attempt.acceptance_state != "PENDING"
                    or attempt.supervisor_identity != helper_identity
                    or mapping.selected_attempt_number is not None
                    or request_sequence != (previous or 0) + 1
                ):
                    raise SourceOsvExecutionConflictError
                row = SourceOsvRequestPermitRow(
                    job_id=job_id,
                    attempt_number=attempt_number,
                    request_sequence=request_sequence,
                    run_id=mapping.run_id,
                    node_id=mapping.node_id,
                    operation_kind=operation_kind.value,
                    logical_request_digest=logical_request_digest,
                    transport_attempt_number=transport_attempt_number,
                    helper_identity=helper_identity,
                    authorized_at=now,
                )
                session.add(row)
                session.flush()
                return OsvRequestPermit(
                    job_id,
                    attempt_number,
                    request_sequence,
                    operation_kind,
                    logical_request_digest,
                    transport_attempt_number,
                    now,
                )
        except SourceOsvExecutionError:
            raise
        except (IntegrityError, SQLAlchemyError):
            raise SourceOsvExecutionConflictError from None


class SourceOsvAttemptService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        artifact_store: ContentAddressedArtifactStore,
        jobs: SourceOsvJobService,
    ) -> None:
        self._sessions = session_factory
        self._artifacts = artifact_store
        self._jobs = jobs

    def accept_result(
        self,
        result: SafeSourceOsvResult,
        *,
        lease_token: str,
        duration_ms: int,
    ) -> bool:
        if not isinstance(result, SafeSourceOsvResult) or duration_ms < 0:
            raise SourceOsvExecutionConflictError
        execution_input = self._jobs.load_input(job_id=result.job_id)
        if not _result_matches_input(result, execution_input):
            raise SourceOsvExecutionConflictError
        payload = result.canonical_json()
        artifact = self._artifacts.put(
            payload,
            kind=ArtifactKind.SANITIZED_NATIVE_REPORT,
            media_type=OSV_NATIVE_RESULT_MEDIA_TYPE,
            sanitized=True,
        )
        if self._artifacts.read_by_sha256(
            artifact.sha256, expected_size_bytes=artifact.size_bytes
        ) != payload:
            raise SourceOsvExecutionError
        try:
            with self._sessions.begin() as session:
                parent, node, mapping, job, attempt = _locked_attempt_state(
                    session, result.job_id, result.attempt_number
                )
                now = _database_now(session)
                if attempt.acceptance_state == "ACCEPTED":
                    if (
                        attempt.native_result_sha256 != artifact.sha256
                        or mapping.selected_attempt_number != result.attempt_number
                    ):
                        raise SourceOsvExecutionConflictError
                    return False
                if (
                    parent.lifecycle_state != OrchestrationLifecycleState.ACTIVE.value
                    or parent.cancel_requested
                    or now >= _utc(parent.deadline_at)
                    or mapping.input_kind != "OSV_DEPENDENCY_INPUT"
                    or job.status != JobStatus.RUNNING.value
                    or job.cancel_requested
                    or job.lease_token != lease_token
                    or attempt.lease_token != lease_token
                    or job.attempt_count != attempt.attempt_number
                    or attempt.acceptance_state != "PENDING"
                    or mapping.selected_attempt_number is not None
                    or not _valid_durable_clean_receipt(attempt, mapping)
                    or not _mapping_matches_result(mapping, result)
                ):
                    raise SourceOsvExecutionConflictError
                tool = ToolExecutionRow(
                    run_id=mapping.run_id,
                    job_id=job.id,
                    attempt_number=attempt.attempt_number,
                    adapter_id=SourceAuthority.OSV.value,
                    tool_version=OSV_API_VERSION,
                    adapter_version=OSV_ADAPTER_VERSION,
                    outcome=(
                        ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS.value
                        if result.analysis.findings
                        else ExecutionOutcome.SUCCEEDED_NO_OBSERVATIONS.value
                    ),
                    exit_code=0,
                    duration_ms=duration_ms,
                    warning_json=[],
                    error=None,
                    failure_category=None,
                    retryable=None,
                )
                session.add(tool)
                session.flush()
                attempt.tool_execution_id = tool.id
                attempt.native_result_sha256 = artifact.sha256
                attempt.native_result_size_bytes = artifact.size_bytes
                attempt.native_result_media_type = OSV_NATIVE_RESULT_MEDIA_TYPE
                attempt.native_result_schema_version = OSV_NATIVE_RESULT_SCHEMA_VERSION
                attempt.native_result_storage_path = artifact.storage_path
                attempt.projection_revalidated = None
                attempt.dependency_input_revalidated = True
                attempt.acceptance_state = "ACCEPTED"
                attempt.finished_at = now
                attempt.accepted_at = now
                mapping.selected_attempt_number = attempt.attempt_number
                job.status = JobStatus.SUCCEEDED.value
                job.finished_at = now
                job.updated_at = now
                job.leased_by = None
                job.lease_token = None
                job.lease_expires_at = None
                node.lifecycle_state = OrchestrationNodeLifecycleState.TERMINAL.value
                node.terminal_disposition = (
                    OrchestrationNodeDisposition.PARTIAL.value
                    if result.coverage_limited
                    else OrchestrationNodeDisposition.COMPLETE.value
                )
                node.terminal_reason_code = (
                    "DEPENDENCY_COVERAGE_LIMITED" if result.coverage_limited else None
                )
                node.containment_state = OrchestrationContainmentState.CLEAN.value
                node.state_version += 1
                run = session.get(AnalysisRunRow, mapping.run_id)
                if run is None or run.report_json is not None:
                    raise SourceOsvExecutionConflictError
                session.flush()
                return True
        except SourceOsvExecutionError:
            raise
        except (IntegrityError, SQLAlchemyError):
            raise SourceOsvExecutionError from None

    def record_failure(
        self,
        *,
        job_id: str,
        attempt_number: int,
        attempt_token: str,
        lease_token: str,
        failure_code: SourceOsvFailureCode,
        duration_ms: int,
    ) -> None:
        if not isinstance(failure_code, SourceOsvFailureCode) or duration_ms < 0:
            raise SourceOsvExecutionConflictError
        try:
            with self._sessions.begin() as session:
                parent, node, mapping, job, attempt = _locked_attempt_state(
                    session, job_id, attempt_number
                )
                now = _database_now(session)
                if (
                    attempt.attempt_token != attempt_token
                    or attempt.lease_token != lease_token
                    or job.lease_token != lease_token
                    or attempt.acceptance_state != "PENDING"
                    or attempt.tool_execution_id is not None
                    or attempt.containment_state
                    not in {
                        OrchestrationContainmentState.CLEAN.value,
                        OrchestrationContainmentState.RECONCILIATION_REQUIRED.value,
                    }
                ):
                    raise SourceOsvExecutionConflictError
                containment_unknown = (
                    attempt.containment_state
                    == OrchestrationContainmentState.RECONCILIATION_REQUIRED.value
                )
                if containment_unknown:
                    failure_code = SourceOsvFailureCode.ATTEMPT_CONTAINMENT_FAILURE
                retryable = failure_code in _RETRYABLE_OSV_FAILURES and not (
                    parent.cancel_requested or now >= _utc(parent.deadline_at)
                )
                category, outcome = _failure_projection(failure_code)
                tool = ToolExecutionRow(
                    run_id=mapping.run_id,
                    job_id=job.id,
                    attempt_number=attempt.attempt_number,
                    adapter_id=SourceAuthority.OSV.value,
                    tool_version=OSV_API_VERSION,
                    adapter_version=OSV_ADAPTER_VERSION,
                    outcome=outcome.value,
                    exit_code=None,
                    duration_ms=duration_ms,
                    warning_json=[],
                    error=None,
                    failure_category=category.value,
                    retryable=retryable,
                )
                session.add(tool)
                session.flush()
                attempt.tool_execution_id = tool.id
                attempt.acceptance_state = "REJECTED"
                attempt.failure_code = failure_code.value
                attempt.finished_at = now
                job.last_error = failure_code.value
                job.leased_by = None
                job.lease_token = None
                job.lease_expires_at = None
                job.updated_at = now
                if containment_unknown:
                    node.lifecycle_state = (
                        OrchestrationNodeLifecycleState.RECONCILIATION_REQUIRED.value
                    )
                elif retryable and job.attempt_count < job.max_attempts:
                    job.status = JobStatus.RETRY_PENDING.value
                    job.available_at = now + timedelta(seconds=5 if attempt_number == 1 else 30)
                    node.lifecycle_state = OrchestrationNodeLifecycleState.RETRY_PENDING.value
                    node.containment_state = OrchestrationContainmentState.CLEAN.value
                else:
                    job.status = (
                        JobStatus.CANCELLED.value
                        if failure_code is SourceOsvFailureCode.CANCELLED
                        else JobStatus.FAILED.value
                    )
                    job.finished_at = now
                    node.lifecycle_state = OrchestrationNodeLifecycleState.TERMINAL.value
                    node.terminal_disposition = (
                        OrchestrationNodeDisposition.CANCELLED.value
                        if failure_code is SourceOsvFailureCode.CANCELLED
                        else OrchestrationNodeDisposition.FAILED.value
                    )
                    node.terminal_reason_code = failure_code.value
                    node.containment_state = OrchestrationContainmentState.CLEAN.value
                node.state_version += 1
        except SourceOsvExecutionError:
            raise
        except (IntegrityError, SQLAlchemyError):
            raise SourceOsvExecutionError from None

    def load_accepted_result(self, *, run_id: str, node_id: str) -> SafeSourceOsvResult:
        try:
            with self._sessions() as session:
                mapping = session.scalar(
                    select(SourceOrchestrationScannerJobRow).where(
                        SourceOrchestrationScannerJobRow.run_id == run_id,
                        SourceOrchestrationScannerJobRow.node_id == node_id,
                    )
                )
                if mapping is None or mapping.selected_attempt_number is None:
                    raise SourceOsvExecutionError
                attempt = session.get(
                    SourceOrchestrationAttemptRow,
                    (mapping.job_id, mapping.selected_attempt_number),
                )
                if (
                    attempt is None
                    or attempt.acceptance_state != "ACCEPTED"
                    or attempt.native_result_sha256 is None
                    or attempt.native_result_size_bytes is None
                    or attempt.native_result_media_type != OSV_NATIVE_RESULT_MEDIA_TYPE
                    or attempt.native_result_schema_version != OSV_NATIVE_RESULT_SCHEMA_VERSION
                ):
                    raise SourceOsvExecutionError
                payload = self._artifacts.read_by_sha256(
                    attempt.native_result_sha256,
                    expected_size_bytes=attempt.native_result_size_bytes,
                )
                result = SafeSourceOsvResult.from_json(payload)
                if not _mapping_matches_result(mapping, result):
                    raise SourceOsvExecutionError
                return result
        except SourceOsvExecutionError:
            raise
        except (OSError, SQLAlchemyError, ValueError):
            raise SourceOsvExecutionError from None


def _result_matches_input(
    result: SafeSourceOsvResult, execution_input: SourceOsvExecutionInput
) -> bool:
    return bool(
        result.run_id == execution_input.run_id
        and result.node_id == execution_input.node_id
        and result.job_id == execution_input.job_id
        and result.repository_digest == execution_input.repository_digest
        and result.profile_digest == execution_input.profile_digest
        and result.plan_digest == execution_input.plan_digest
        and result.scope_digest == execution_input.scope_digest
        and result.dependency_evaluation_sha256
        == execution_input.dependency_evaluation_sha256
        and result.syft_native_result_sha256 == execution_input.syft_native_result_sha256
        and result.candidate_ids
        == tuple(item.candidate_id for item in execution_input.candidates)
        and result.analysis.candidates == execution_input.candidates
        and result.coverage_limited is execution_input.coverage_limited
    )


def _mapping_matches_result(
    mapping: SourceOrchestrationScannerJobRow, result: SafeSourceOsvResult
) -> bool:
    return bool(
        mapping.input_kind == "OSV_DEPENDENCY_INPUT"
        and mapping.run_id == result.run_id
        and mapping.node_id == result.node_id
        and mapping.job_id == result.job_id
        and mapping.authority == result.authority
        and mapping.analyzer_id == result.analyzer_id
        and mapping.contract_digest == result.service_contract_digest
        and mapping.dependency_evaluation_sha256
        == result.dependency_evaluation_sha256
        and mapping.syft_native_result_sha256 == result.syft_native_result_sha256
        and mapping.osv_scope_digest == result.scope_digest
    )


def _locked_attempt_state(
    session: Session, job_id: str, attempt_number: int
) -> tuple[
    SourceOrchestrationRow,
    SourceOrchestrationNodeRow,
    SourceOrchestrationScannerJobRow,
    JobRow,
    SourceOrchestrationAttemptRow,
]:
    unlocked = session.get(SourceOrchestrationScannerJobRow, job_id)
    if unlocked is None:
        raise SourceOsvExecutionConflictError
    parent = session.scalar(
        select(SourceOrchestrationRow)
        .where(SourceOrchestrationRow.run_id == unlocked.run_id)
        .with_for_update()
    )
    node = session.scalar(
        select(SourceOrchestrationNodeRow)
        .where(SourceOrchestrationNodeRow.node_id == unlocked.node_id)
        .with_for_update()
    )
    mapping = session.scalar(
        select(SourceOrchestrationScannerJobRow)
        .where(SourceOrchestrationScannerJobRow.job_id == job_id)
        .with_for_update()
    )
    job = session.scalar(select(JobRow).where(JobRow.id == job_id).with_for_update())
    attempt = session.scalar(
        select(SourceOrchestrationAttemptRow)
        .where(
            SourceOrchestrationAttemptRow.job_id == job_id,
            SourceOrchestrationAttemptRow.attempt_number == attempt_number,
        )
        .with_for_update()
    )
    if (
        parent is None
        or node is None
        or mapping is None
        or job is None
        or attempt is None
        or len({parent.run_id, node.run_id, mapping.run_id, job.run_id, attempt.run_id}) != 1
    ):
        raise SourceOsvExecutionConflictError
    return parent, node, mapping, job, attempt


def _database_now(session: Session) -> datetime:
    value = session.scalar(select(func.now()))
    if not isinstance(value, datetime):
        raise SourceOsvExecutionError
    return _utc(value)


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise SourceOsvExecutionError
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _job_key(node_id: str) -> str:
    digest = hashlib.sha256()
    digest.update(_JOB_KEY_DOMAIN)
    digest.update(node_id.encode("ascii"))
    return digest.hexdigest()


def _failure_projection(
    code: SourceOsvFailureCode,
) -> tuple[JobFailureCategory, ExecutionOutcome]:
    if code is SourceOsvFailureCode.CANCELLED:
        return JobFailureCategory.CANCELLED, ExecutionOutcome.CANCELLED
    if code is SourceOsvFailureCode.DEADLINE_EXCEEDED:
        return JobFailureCategory.TIMEOUT, ExecutionOutcome.TIMEOUT
    if code in {SourceOsvFailureCode.CONNECT_TIMEOUT, SourceOsvFailureCode.READ_WRITE_TIMEOUT}:
        return JobFailureCategory.TIMEOUT, ExecutionOutcome.TIMEOUT
    if code in _RETRYABLE_OSV_FAILURES:
        return JobFailureCategory.RETRYABLE_INFRASTRUCTURE, ExecutionOutcome.INTERNAL_ERROR
    if code in {
        SourceOsvFailureCode.INVALID_OSV_SCHEMA,
        SourceOsvFailureCode.PAGINATION_INTEGRITY_FAILURE,
    }:
        return JobFailureCategory.NON_RETRYABLE_PARSER, ExecutionOutcome.INVALID_OUTPUT
    return JobFailureCategory.NON_RETRYABLE_POLICY, ExecutionOutcome.SECURITY_POLICY_BLOCKED
