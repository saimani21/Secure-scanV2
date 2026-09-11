from __future__ import annotations

import json
import secrets
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from securescan.adapters.trusted_registry import TrustedAdapterRegistry
from securescan.advisories.osv import (
    build_osv_source_analyzer_snapshot,
    with_osv_source_support,
)
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import Settings, get_settings
from securescan.execution.docker_sandbox import DockerSandboxExecutor
from securescan.observability.readiness import _bootstrap_database_schema
from securescan.orchestration.models import frozen_source_v1_authority_roster
from securescan.persistence.database import create_session_factory, utc_now
from securescan.product_core import (
    InvalidScanFilterError,
    InvalidScanPaginationError,
    ProductCoreIndexError,
    ProductCoreNotReadyError,
    ProductCoreSubmissionError,
    ScanNotFoundError,
    ScanNotPublishedError,
    SourceFindingSummary,
    SourcePreparedScanRequest,
    SourcePublishedReport,
    SourceScanPage,
    SourceScanQueryError,
    SourceScanQueryPersistenceError,
    SourceScanQueryService,
    SourceScanSubmission,
    SourceScanSubmissionService,
    SourceScanSummary,
)
from securescan.scanners.checkov import (
    CHECKOV_EXECUTABLE_UNAVAILABLE,
    CHECKOV_SOURCE_ANALYZER_ID,
    CheckovExecutableIntegrityError,
    apply_checkov_source_applicability,
    build_checkov_source_analyzer_snapshot,
    create_default_checkov_binding,
    with_checkov_planning_policy,
    with_checkov_source_support,
)
from securescan.scanners.gitleaks import (
    apply_gitleaks_source_applicability,
    build_gitleaks_source_analyzer_snapshot,
    create_default_gitleaks_binding,
    with_gitleaks_planning_policy,
    with_gitleaks_source_support,
)
from securescan.scanners.semgrep import (
    DECLARED_SEMGREP_TOOL_VERSION,
    PRODUCTION_SEMGREP_IMAGE_REFERENCE,
    build_semgrep_source_analyzer_snapshot,
    create_production_semgrep_source_binding,
    create_semgrep_trusted_definition,
    load_baseline_ruleset,
)
from securescan.scanners.syft import (
    apply_syft_source_applicability,
    build_syft_source_analyzer_snapshot,
    create_default_syft_binding,
    with_syft_planning_policy,
    with_syft_source_support,
)
from securescan.source import (
    AnalysisCapability,
    CapabilitySupportRule,
    EnryClient,
    LanguageSupportRule,
    RepositoryProfile,
    SourceAnalysisPlan,
    SourcePlanningPolicy,
    SourceSupportPolicy,
    SourceSupportState,
    TrustedEnryHelper,
    TrustedSourceAnalyzer,
    TrustedSourceAnalyzerRegistry,
    assess_repository_language_support,
    build_repository_inventory,
    build_repository_profile,
    build_source_analysis_plan,
    detect_repository_components,
    enrich_repository_inventory,
    profile_repository_languages,
)
from securescan.workspaces import (
    PreparedRepositoryWorkspace,
    RepositoryWorkspaceError,
    RepositoryWorkspaceManager,
)

_HEX_CHARACTERS = frozenset("0123456789abcdef")
class SourceCliError(RuntimeError):
    def __init__(self, code: str, message: str, exit_code: int) -> None:
        self.code = code
        self.exit_code = exit_code
        super().__init__(message)


class _WorkspaceManager(Protocol):
    def prepare_repository(self, source_directory: Path) -> PreparedRepositoryWorkspace: ...

    def cleanup_workspace(self, workspace: PreparedRepositoryWorkspace) -> None: ...


class _SubmissionService(Protocol):
    def create_lineage(self, *, project_id: str): ...

    def submit_prepared(self, request: SourcePreparedScanRequest) -> SourceScanSubmission: ...


class _QueryService(Protocol):
    def get_scan(self, run_id: str) -> SourceScanSummary: ...

    def list_findings(
        self,
        run_id: str,
        *,
        authority: str | None = None,
        category: str | None = None,
        priority: str | None = None,
        lifecycle_state: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> SourceScanPage[SourceFindingSummary]: ...

    def get_report(self, run_id: str) -> SourcePublishedReport: ...


class _ProfilePlanner(Protocol):
    def build(
        self, workspace: PreparedRepositoryWorkspace
    ) -> tuple[RepositoryProfile, SourceAnalysisPlan]: ...


@dataclass(frozen=True, slots=True)
class SourceCliServices:
    workspace_manager: _WorkspaceManager
    submissions: _SubmissionService
    queries: _QueryService
    profile_planner: _ProfilePlanner
    default_deadline_seconds: int
    clock: Callable[[], datetime] = utc_now
    idempotency_key_factory: Callable[[], str] = lambda: secrets.token_hex(32)


@dataclass(frozen=True, slots=True)
class SourceCliScanResult:
    submission: SourceScanSubmission


class SourceRepositoryProfilePlanner:
    """Compose the frozen Source profile and plan without executing a scanner."""

    def __init__(
        self,
        enry_client_factory: Callable[[], EnryClient],
        registry_factory: Callable[[], TrustedSourceAnalyzerRegistry],
    ) -> None:
        self._enry_client_factory = enry_client_factory
        self._registry_factory = registry_factory
        policy = SourceSupportPolicy(
            language_rules=(
                LanguageSupportRule(
                    "Python",
                    SourceSupportState.SCANNABLE,
                    "PYTHON_SCANNABLE_BY_POLICY",
                ),
            ),
            capability_rules=(
                CapabilitySupportRule(
                    AnalysisCapability.PYTHON_SAST,
                    SourceSupportState.SCANNABLE,
                    "PYTHON_SCANNABLE_BY_POLICY",
                ),
            )
        )
        policy = with_gitleaks_source_support(policy)
        policy = with_syft_source_support(policy)
        policy = with_osv_source_support(policy)
        self._support_policy = with_checkov_source_support(policy)

        planning = with_gitleaks_planning_policy(SourcePlanningPolicy())
        planning = with_syft_planning_policy(planning)
        self._planning_policy = with_checkov_planning_policy(planning)

    def build(
        self, workspace: PreparedRepositoryWorkspace
    ) -> tuple[RepositoryProfile, SourceAnalysisPlan]:
        inventory = build_repository_inventory(workspace)
        languages = profile_repository_languages(
            workspace, inventory, self._enry_client_factory()
        )
        enriched = enrich_repository_inventory(inventory, languages)
        componentized = detect_repository_components(enriched)
        assessment = assess_repository_language_support(
            componentized, self._support_policy
        )
        profile = build_repository_profile(
            componentized, assessment, self._support_policy
        )
        # The frozen Syft overlay owns repository-wide PACKAGE_INVENTORY scope.
        # Generic coverage construction may have emitted component-grouped
        # package surfaces, so remove those provisional surfaces before asking
        # the frozen overlay to establish its authoritative shape.
        profile = replace(
            profile,
            surfaces=tuple(
                surface
                for surface in profile.surfaces
                if surface.capability is not AnalysisCapability.PACKAGE_INVENTORY
            ),
        )
        profile = apply_gitleaks_source_applicability(
            profile, self._support_policy
        )
        profile = apply_syft_source_applicability(profile, self._support_policy)
        profile = apply_checkov_source_applicability(profile, self._support_policy)
        plan = build_source_analysis_plan(
            profile, self._registry_factory(), self._planning_policy
        )
        return profile, plan


def _enry_client(settings: Settings) -> EnryClient:
    if settings.source_enry_helper_sha256 is None:
        raise SourceCliError(
            "SUBMISSION_UNAVAILABLE", "Source scan submission is unavailable", 5
        )
    return EnryClient(
        TrustedEnryHelper(
            helper_path=settings.source_enry_helper_path,
            expected_sha256=settings.source_enry_helper_sha256,
        )
    )


def _analyzer_registry(
    settings: Settings,
    artifacts: ContentAddressedArtifactStore,
    workspaces: RepositoryWorkspaceManager,
) -> TrustedSourceAnalyzerRegistry:
    """Take the existing read-only availability snapshots used by Source planning."""

    docker = DockerSandboxExecutor()
    ruleset = load_baseline_ruleset()
    definition = create_semgrep_trusted_definition(
        image_reference=PRODUCTION_SEMGREP_IMAGE_REFERENCE,
        tool_version=DECLARED_SEMGREP_TOOL_VERSION,
        docker_executor=docker,
        workspace_manager=workspaces,
        ruleset=ruleset,
        artifact_store=artifacts,
        source_resolver=lambda _run_id: workspaces.base_directory,
    )
    semgrep_binding = create_production_semgrep_source_binding(
        definition=definition, ruleset=ruleset
    )
    try:
        checkov = build_checkov_source_analyzer_snapshot(
            create_default_checkov_binding(settings.source_checkov_executable_path)
        )
    except CheckovExecutableIntegrityError:
        checkov = TrustedSourceAnalyzer(
            analyzer_id=CHECKOV_SOURCE_ANALYZER_ID,
            capabilities=(AnalysisCapability.CONFIGURATION_SECURITY,),
            available=False,
            unavailable_reason_code=CHECKOV_EXECUTABLE_UNAVAILABLE,
        )
    analyzers = (
        checkov,
        build_gitleaks_source_analyzer_snapshot(
            create_default_gitleaks_binding(
                settings.source_gitleaks_executable_path
            )
        ),
        build_osv_source_analyzer_snapshot(available=True),
        build_semgrep_source_analyzer_snapshot(
            semgrep_binding,
            TrustedAdapterRegistry((definition,)),
            docker,
        ),
        build_syft_source_analyzer_snapshot(
            create_default_syft_binding(settings.source_syft_executable_path)
        ),
    )
    roster = frozen_source_v1_authority_roster()
    expected = {
        authority.capability: authority.analyzer_id
        for authority in roster.authorities
    }
    if {
        capability: analyzer.analyzer_id
        for analyzer in analyzers
        for capability in analyzer.capabilities
    } != expected:
        raise SourceCliError(
            "SUBMISSION_UNAVAILABLE", "Source scan submission is unavailable", 5
        )
    return TrustedSourceAnalyzerRegistry(
        analyzers=tuple(sorted(analyzers, key=lambda analyzer: analyzer.analyzer_id))
    )


@contextmanager
def create_source_cli_services() -> Iterator[SourceCliServices]:
    """Build the same persistence, artifact, and workspace stack used by the API."""

    settings = get_settings()
    engine, session_factory = create_session_factory(settings)
    try:
        _bootstrap_database_schema(
            engine,
            allow_sqlite_schema_bootstrap=settings.allow_sqlite_schema_bootstrap,
        )
        artifacts = ContentAddressedArtifactStore(settings.artifact_root)
        workspaces = RepositoryWorkspaceManager(settings.source_workspace_root)
        yield SourceCliServices(
            workspace_manager=workspaces,
            submissions=SourceScanSubmissionService(
                session_factory, artifacts, workspaces
            ),
            queries=SourceScanQueryService(session_factory, artifacts),
            profile_planner=SourceRepositoryProfilePlanner(
                lambda: _enry_client(settings),
                lambda: _analyzer_registry(settings, artifacts, workspaces),
            ),
            default_deadline_seconds=settings.source_scan_deadline_seconds,
        )
    finally:
        engine.dispose()


def _canonical_uuid(value: str, *, code: str = "SUBMISSION_CONFLICT") -> str:
    try:
        parsed = str(UUID(value))
    except (AttributeError, TypeError, ValueError):
        raise SourceCliError(code, "A canonical UUID is required", 2) from None
    if parsed != value:
        raise SourceCliError(code, "A canonical UUID is required", 2)
    return parsed


def _idempotency_key(factory: Callable[[], str]) -> str:
    generated = factory()
    if (
        not isinstance(generated, str)
        or len(generated) != 64
        or generated != generated.lower()
        or any(character not in _HEX_CHARACTERS for character in generated)
    ):
        raise SourceCliError(
            "SUBMISSION_CONFLICT", "Idempotency key must be 64 lowercase hex characters", 2
        )
    return generated


def _deadline(clock: Callable[[], datetime], seconds: int) -> datetime:
    if type(seconds) is not int or not 300 <= seconds <= 86_400:
        raise SourceCliError(
            "SUBMISSION_CONFLICT", "Deadline must be between 300 and 86400 seconds", 2
        )
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise SourceCliError(
            "SUBMISSION_UNAVAILABLE", "Source scan submission is unavailable", 5
        )
    return now.astimezone(UTC) + timedelta(seconds=seconds)


def _source_directory(value: Path) -> Path:
    try:
        candidate = value.expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        if candidate.is_symlink():
            raise ValueError
        resolved = candidate.resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError
        return resolved
    except (OSError, RuntimeError, ValueError):
        raise SourceCliError(
            "INVALID_REPOSITORY", "Repository must be an existing local directory", 2
        ) from None


def submit_local_scan(
    services: SourceCliServices,
    *,
    source_path: Path,
    project_id: str,
    lineage_id: str | None,
    deadline_seconds: int | None,
) -> SourceCliScanResult:
    project = _canonical_uuid(project_id)
    lineage = None if lineage_id is None else _canonical_uuid(lineage_id)
    source = _source_directory(source_path)
    key = _idempotency_key(services.idempotency_key_factory)
    deadline = _deadline(
        services.clock,
        services.default_deadline_seconds
        if deadline_seconds is None
        else deadline_seconds,
    )

    workspace: PreparedRepositoryWorkspace | None = None
    submission_started = False
    try:
        workspace = services.workspace_manager.prepare_repository(source)
        profile, plan = services.profile_planner.build(workspace)
        if lineage is None:
            lineage = services.submissions.create_lineage(
                project_id=project
            ).lineage_id
        submission_started = True
        submission = services.submissions.submit_prepared(
            SourcePreparedScanRequest(
                project_id=project,
                lineage_id=lineage,
                workspace=workspace,
                profile=profile,
                plan=plan,
                idempotency_key=key,
                deadline_at=deadline,
            )
        )
        return SourceCliScanResult(submission)
    except SourceCliError:
        raise
    except RepositoryWorkspaceError:
        raise SourceCliError(
            "INVALID_REPOSITORY", "Repository could not be prepared safely", 2
        ) from None
    except (ProductCoreSubmissionError, ProductCoreIndexError):
        raise SourceCliError(
            "SUBMISSION_CONFLICT", "Source scan submission conflicts with durable state", 4
        ) from None
    except SourceScanQueryError as exc:
        raise translate_query_error(exc) from None
    except Exception:
        raise SourceCliError(
            "SUBMISSION_UNAVAILABLE", "Source scan submission is unavailable", 5
        ) from None
    finally:
        # Once submission begins, durable state may reference this workspace even
        # if the final response is interrupted. Only pre-submission failures are
        # safe to clean up here.
        if workspace is not None and not submission_started:
            with suppress(RepositoryWorkspaceError):
                services.workspace_manager.cleanup_workspace(workspace)


def translate_query_error(exc: SourceScanQueryError) -> SourceCliError:
    if isinstance(exc, ScanNotFoundError):
        return SourceCliError("SCAN_NOT_FOUND", "Source scan was not found", 3)
    if isinstance(exc, ScanNotPublishedError):
        return SourceCliError(
            "SCAN_NOT_PUBLISHED", "Source scan report is not published", 3
        )
    if isinstance(exc, ProductCoreNotReadyError):
        return SourceCliError(
            "PRODUCT_CORE_NOT_READY", "Source Product Core data is not ready", 3
        )
    if isinstance(exc, (InvalidScanFilterError, InvalidScanPaginationError)):
        return SourceCliError(exc.code.value, str(exc), 2)
    if isinstance(exc, SourceScanQueryPersistenceError):
        return SourceCliError(
            "QUERY_UNAVAILABLE", "Source scan query is unavailable", 5
        )
    return SourceCliError("QUERY_UNAVAILABLE", "Source scan query is unavailable", 5)


def query_scan(services: SourceCliServices, run_id: str) -> SourceScanSummary:
    try:
        return services.queries.get_scan(_canonical_uuid(run_id, code="SCAN_NOT_FOUND"))
    except SourceCliError:
        raise
    except SourceScanQueryError as exc:
        raise translate_query_error(exc) from None


def query_findings(
    services: SourceCliServices,
    run_id: str,
    *,
    authority: str | None,
    category: str | None,
    priority: str | None,
    lifecycle_state: str | None,
    limit: int,
    offset: int,
) -> SourceScanPage[SourceFindingSummary]:
    try:
        return services.queries.list_findings(
            _canonical_uuid(run_id, code="SCAN_NOT_FOUND"),
            authority=authority,
            category=category,
            priority=priority,
            lifecycle_state=lifecycle_state,
            limit=limit,
            offset=offset,
        )
    except SourceCliError:
        raise
    except SourceScanQueryError as exc:
        raise translate_query_error(exc) from None


def query_report(services: SourceCliServices, run_id: str) -> SourcePublishedReport:
    try:
        return services.queries.get_report(
            _canonical_uuid(run_id, code="SCAN_NOT_FOUND")
        )
    except SourceCliError:
        raise
    except SourceScanQueryError as exc:
        raise translate_query_error(exc) from None


def scan_result_data(result: SourceCliScanResult) -> dict[str, Any]:
    return {
        "lineage_id": result.submission.lineage_id,
        "run_id": result.submission.run_id,
        "submission_status": "SUBMITTED",
        "submission_sequence": result.submission.submission_sequence_number,
    }


def scan_summary_data(summary: SourceScanSummary) -> dict[str, Any]:
    return {
        "coverage_complete": summary.coverage_complete,
        "coverage_counts": dict(summary.coverage_counts),
        "finalized_at": _datetime(summary.finalized_at),
        "finding_count": summary.finding_count,
        "gap_count": summary.gap_count,
        "lineage_id": summary.lineage_id,
        "priority_counts": dict(summary.priority_counts),
        "product_status": summary.product_status.value,
        "published_at": _datetime(summary.published_at),
        "run_id": summary.run_id,
        "submission_sequence": summary.submission_sequence_number,
    }


def finding_page_data(
    page: SourceScanPage[SourceFindingSummary],
) -> dict[str, Any]:
    return {
        "items": [
            {
                "authority": item.authority,
                "category": item.category,
                "finding_id": item.finding_id,
                "lifecycle": item.lifecycle_state,
                "primary_location": _plain(item.primary_location),
                "priority": item.priority_band,
                "severity": item.severity,
                "subject": _plain(item.subject),
            }
            for item in page.items
        ],
        "limit": page.limit,
        "offset": page.offset,
        "total": page.total,
    }


def report_data(report: SourcePublishedReport) -> dict[str, Any]:
    return {"report": _plain(report.report), "run_id": report.run_id}


def canonical_json(value: object, *, pretty: bool = False) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        sort_keys=True,
    )


def _datetime(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat()


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_plain(item) for item in value]
    return value
