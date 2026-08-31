from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any
from uuid import UUID, uuid5

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ArtifactKind
from securescan.jobs.models import (
    RESERVED_INTERNAL_JOB_PAYLOAD_PREFIX,
    JobRecord,
    JobSubmissionResult,
    ServerOwnedJobSubmissionRequest,
)
from securescan.jobs.submission import JobSubmissionError, JobSubmissionService
from securescan.scanners.semgrep.source_binding import TrustedSemgrepSourceBinding
from securescan.source.enums import AnalysisCapability
from securescan.source.execution_context import (
    SOURCE_EXECUTION_CONTEXT_SCHEMA_VERSION,
    InvalidSourceExecutionContextError,
    SourceExecutionContext,
    SourceExecutionSelectedFile,
)
from securescan.source.models import RepositoryProfile
from securescan.source.planning import (
    SourceAnalysisPlan,
    SourceAnalysisPlanEntry,
    SourcePlanAction,
)

SOURCE_EXECUTION_PAYLOAD_KEY = (
    f"{RESERVED_INTERNAL_JOB_PAYLOAD_PREFIX}source_execution__"
)
_ENVELOPE_FIELDS = frozenset(
    {
        "artifact_kind",
        "artifact_media_type",
        "artifact_sanitized",
        "artifact_sha256",
        "artifact_size_bytes",
        "context_digest",
        "schema_version",
    }
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ARTIFACT_MEDIA_TYPE = "application/json"
_MAX_CONTEXT_ARTIFACT_BYTES = 256 * 1024 * 1024
_SOURCE_RUN_ID_NAMESPACE = UUID("7f736c95-71f8-52a6-921d-32478129cb19")
_SOURCE_JOB_ID_NAMESPACE = UUID("10e4b295-826a-53f2-91fe-6b2a4b619215")


class SourceSemgrepExecutionContextError(RuntimeError):
    """Base class for fixed-message Source Semgrep context failures."""


class InvalidSourceSemgrepExecutionRequestError(
    SourceSemgrepExecutionContextError,
    ValueError,
):
    def __init__(self) -> None:
        RuntimeError.__init__(self, "Source Semgrep execution request is invalid")


class SourceExecutionContextArtifactError(SourceSemgrepExecutionContextError):
    def __init__(self) -> None:
        super().__init__("Source execution context artifact is unavailable or corrupt")


class SourceExecutionContextIdentityError(SourceSemgrepExecutionContextError):
    def __init__(self) -> None:
        super().__init__("Source execution context does not match the durable job")


class SourceExecutionBindingMismatchError(SourceSemgrepExecutionContextError):
    def __init__(self) -> None:
        super().__init__("Source execution context binding does not match trusted configuration")


@dataclass(frozen=True, slots=True)
class SourceExecutionEnvelope:
    artifact_sha256: str
    artifact_size_bytes: int
    context_digest: str
    schema_version: str = SOURCE_EXECUTION_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != SOURCE_EXECUTION_CONTEXT_SCHEMA_VERSION
            or not isinstance(self.artifact_sha256, str)
            or _SHA256_PATTERN.fullmatch(self.artifact_sha256) is None
            or type(self.artifact_size_bytes) is not int
            or not 1 <= self.artifact_size_bytes <= _MAX_CONTEXT_ARTIFACT_BYTES
            or not isinstance(self.context_digest, str)
            or _SHA256_PATTERN.fullmatch(self.context_digest) is None
        ):
            raise InvalidSourceSemgrepExecutionRequestError

    def payload_json(self) -> dict[str, Any]:
        return {
            SOURCE_EXECUTION_PAYLOAD_KEY: {
                "artifact_kind": ArtifactKind.SOURCE_EXECUTION_CONTEXT.value,
                "artifact_media_type": _ARTIFACT_MEDIA_TYPE,
                "artifact_sanitized": False,
                "artifact_sha256": self.artifact_sha256,
                "artifact_size_bytes": self.artifact_size_bytes,
                "context_digest": self.context_digest,
                "schema_version": self.schema_version,
            }
        }

    @classmethod
    def from_payload_json(cls, payload: object) -> SourceExecutionEnvelope:
        try:
            if not isinstance(payload, dict) or set(payload) != {
                SOURCE_EXECUTION_PAYLOAD_KEY
            }:
                raise ValueError
            value = payload[SOURCE_EXECUTION_PAYLOAD_KEY]
            if not isinstance(value, dict) or set(value) != _ENVELOPE_FIELDS:
                raise ValueError
            if (
                value["artifact_kind"]
                != ArtifactKind.SOURCE_EXECUTION_CONTEXT.value
                or value["artifact_media_type"] != _ARTIFACT_MEDIA_TYPE
                or value["artifact_sanitized"] is not False
            ):
                raise ValueError
            return cls(
                artifact_sha256=value["artifact_sha256"],
                artifact_size_bytes=value["artifact_size_bytes"],
                context_digest=value["context_digest"],
                schema_version=value["schema_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidSourceSemgrepExecutionRequestError from exc


def _validated_profile(profile: object) -> RepositoryProfile:
    try:
        if not isinstance(profile, RepositoryProfile):
            raise TypeError
        files = tuple(
            replace(file, entry=replace(file.entry))
            for file in profile.files
        )
        validated = replace(
            profile,
            files=files,
            components=tuple(replace(component) for component in profile.components),
            languages=tuple(replace(language) for language in profile.languages),
            surfaces=tuple(replace(surface) for surface in profile.surfaces),
        )
    except Exception as exc:
        raise InvalidSourceSemgrepExecutionRequestError from exc
    if validated != profile:
        raise InvalidSourceSemgrepExecutionRequestError
    return validated


def _validated_plan(plan: object) -> SourceAnalysisPlan:
    try:
        if not isinstance(plan, SourceAnalysisPlan):
            raise TypeError
        entries = tuple(
            replace(
                entry,
                excluded_paths=tuple(
                    replace(exclusion) for exclusion in entry.excluded_paths
                ),
            )
            for entry in plan.entries
        )
        validated = replace(plan, entries=entries)
    except Exception as exc:
        raise InvalidSourceSemgrepExecutionRequestError from exc
    if validated != plan:
        raise InvalidSourceSemgrepExecutionRequestError
    return validated


def _validated_entry(entry: object) -> SourceAnalysisPlanEntry:
    try:
        if not isinstance(entry, SourceAnalysisPlanEntry):
            raise TypeError
        validated = replace(
            entry,
            excluded_paths=tuple(
                replace(exclusion) for exclusion in entry.excluded_paths
            ),
        )
    except Exception as exc:
        raise InvalidSourceSemgrepExecutionRequestError from exc
    if validated != entry:
        raise InvalidSourceSemgrepExecutionRequestError
    return validated


def build_semgrep_source_execution_context(
    *,
    source_run_id: str,
    job_id: str,
    profile: RepositoryProfile,
    plan: SourceAnalysisPlan,
    entry: SourceAnalysisPlanEntry,
    binding: TrustedSemgrepSourceBinding,
) -> SourceExecutionContext:
    trusted_profile = _validated_profile(profile)
    trusted_plan = _validated_plan(plan)
    trusted_entry = _validated_entry(entry)
    try:
        if not isinstance(binding, TrustedSemgrepSourceBinding):
            raise TypeError
        binding._validate_state()
        profile_digest = trusted_profile.profile_digest()
        plan_digest = trusted_plan.plan_digest()
        if (
            trusted_plan.repository_digest != trusted_profile.repository_digest
            or trusted_plan.profile_digest != profile_digest
            or trusted_entry not in trusted_plan.entries
            or trusted_entry.action is not SourcePlanAction.RUN
            or trusted_entry.capability is not AnalysisCapability.PYTHON_SAST
            or trusted_entry.analyzer_id != binding.source_analyzer_id
            or binding.capability is not AnalysisCapability.PYTHON_SAST
            or not trusted_entry.selected_paths
        ):
            raise ValueError

        files_by_path = {
            file.relative_path: file
            for file in trusted_profile.files
        }
        selected_files: list[SourceExecutionSelectedFile] = []
        for relative_path in trusted_entry.selected_paths:
            file = files_by_path.get(relative_path)
            if file is None or (
                trusted_entry.component_id is not None
                and file.component_id != trusted_entry.component_id
            ):
                raise ValueError
            selected_files.append(
                SourceExecutionSelectedFile(
                    entry=replace(file.entry),
                    component_id=file.component_id,
                )
            )

        return SourceExecutionContext(
            source_run_id=source_run_id,
            job_id=job_id,
            repository_digest=trusted_profile.repository_digest,
            profile_digest=profile_digest,
            plan_digest=plan_digest,
            source_analyzer_id=binding.source_analyzer_id,
            capability=trusted_entry.capability,
            component_id=trusted_entry.component_id,
            selected_files=tuple(selected_files),
            binding_digest=binding.binding_digest(),
            core_adapter_id=binding.core_adapter_id,
        )
    except InvalidSourceSemgrepExecutionRequestError:
        raise
    except Exception as exc:
        raise InvalidSourceSemgrepExecutionRequestError from exc


@dataclass(frozen=True, slots=True)
class SourceSemgrepSubmissionRequest:
    target_id: str
    idempotency_key: str
    profile: RepositoryProfile
    plan: SourceAnalysisPlan
    entry: SourceAnalysisPlanEntry
    binding: TrustedSemgrepSourceBinding
    priority: int = 100
    max_attempts: int = 3


class SourceSemgrepExecutionContextResolver:
    def __init__(
        self,
        artifact_store: ContentAddressedArtifactStore,
        binding: TrustedSemgrepSourceBinding,
    ) -> None:
        if (
            not isinstance(artifact_store, ContentAddressedArtifactStore)
            or not isinstance(binding, TrustedSemgrepSourceBinding)
        ):
            raise InvalidSourceSemgrepExecutionRequestError
        binding._validate_state()
        self._artifact_store = artifact_store
        self._binding = binding

    def resolve(self, job: JobRecord) -> SourceExecutionContext:
        if not isinstance(job, JobRecord):
            raise InvalidSourceSemgrepExecutionRequestError
        envelope = SourceExecutionEnvelope.from_payload_json(job.payload_json)
        try:
            payload = self._artifact_store.read_by_sha256(
                envelope.artifact_sha256,
                expected_size_bytes=envelope.artifact_size_bytes,
            )
        except Exception as exc:
            raise SourceExecutionContextArtifactError from exc
        try:
            context = SourceExecutionContext.from_json(payload)
        except InvalidSourceExecutionContextError as exc:
            raise InvalidSourceExecutionContextError from exc
        if context.context_digest() != envelope.context_digest:
            raise InvalidSourceExecutionContextError
        if (
            context.job_id != job.id
            or context.source_run_id != job.run_id
            or context.core_adapter_id != job.adapter_id
        ):
            raise SourceExecutionContextIdentityError
        try:
            self._binding._validate_state()
            binding_matches = (
                context.binding_digest == self._binding.binding_digest()
                and context.source_analyzer_id == self._binding.source_analyzer_id
                and context.capability is self._binding.capability
                and context.core_adapter_id == self._binding.core_adapter_id
            )
        except Exception as exc:
            raise SourceExecutionBindingMismatchError from exc
        if not binding_matches:
            raise SourceExecutionBindingMismatchError
        return context


class SourceSemgrepSubmissionService:
    def __init__(
        self,
        job_submission_service: JobSubmissionService,
        artifact_store: ContentAddressedArtifactStore,
        *,
        run_id_factory: Callable[[], UUID] | None = None,
        job_id_factory: Callable[[], UUID] | None = None,
    ) -> None:
        if (
            not isinstance(job_submission_service, JobSubmissionService)
            or not isinstance(artifact_store, ContentAddressedArtifactStore)
            or (run_id_factory is not None and not callable(run_id_factory))
            or (job_id_factory is not None and not callable(job_id_factory))
        ):
            raise InvalidSourceSemgrepExecutionRequestError
        self._job_submission_service = job_submission_service
        self._artifact_store = artifact_store
        self._run_id_factory = run_id_factory
        self._job_id_factory = job_id_factory

    @staticmethod
    def _new_id(
        factory: Callable[[], UUID] | None,
        *,
        namespace: UUID,
        idempotency_key: str,
    ) -> str:
        try:
            # UUIDv5 is used only for stable, domain-separated identifiers.
            # Authorization remains the validated context and trusted binding.
            value = (
                uuid5(namespace, idempotency_key)
                if factory is None
                else factory()
            )
            if not isinstance(value, UUID):
                raise TypeError
            return str(value)
        except Exception as exc:
            raise InvalidSourceSemgrepExecutionRequestError from exc

    def submit(
        self,
        request: SourceSemgrepSubmissionRequest,
    ) -> JobSubmissionResult:
        if not isinstance(request, SourceSemgrepSubmissionRequest):
            raise InvalidSourceSemgrepExecutionRequestError
        source_run_id = self._new_id(
            self._run_id_factory,
            namespace=_SOURCE_RUN_ID_NAMESPACE,
            idempotency_key=request.idempotency_key,
        )
        job_id = self._new_id(
            self._job_id_factory,
            namespace=_SOURCE_JOB_ID_NAMESPACE,
            idempotency_key=request.idempotency_key,
        )
        context = build_semgrep_source_execution_context(
            source_run_id=source_run_id,
            job_id=job_id,
            profile=request.profile,
            plan=request.plan,
            entry=request.entry,
            binding=request.binding,
        )
        try:
            artifact = self._artifact_store.put(
                context.canonical_json(),
                kind=ArtifactKind.SOURCE_EXECUTION_CONTEXT,
                media_type=_ARTIFACT_MEDIA_TYPE,
                sanitized=False,
            )
            envelope = SourceExecutionEnvelope(
                artifact_sha256=artifact.sha256,
                artifact_size_bytes=artifact.size_bytes,
                context_digest=context.context_digest(),
            )
            return self._job_submission_service.submit_server_owned(
                ServerOwnedJobSubmissionRequest(
                    run_id=source_run_id,
                    job_id=job_id,
                    target_id=request.target_id,
                    adapter_id=request.binding.core_adapter_id,
                    idempotency_key=request.idempotency_key,
                    payload_json=envelope.payload_json(),
                    expected_target_content_digest=context.repository_digest,
                    priority=request.priority,
                    max_attempts=request.max_attempts,
                )
            )
        except JobSubmissionError:
            raise
        except Exception as exc:
            raise SourceExecutionContextArtifactError from exc
