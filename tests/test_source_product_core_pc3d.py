from __future__ import annotations

import json
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.cli import main as cli_main
from securescan.cli import source as cli_source
from securescan.cli.source import (
    SourceCliServices,
    SourceRepositoryProfilePlanner,
    submit_local_scan,
)
from securescan.config import Settings
from securescan.orchestration.models import (
    SourceAuthority,
    SourcePlanningSnapshot,
    frozen_source_v1_authority_roster,
)
from securescan.persistence.database import (
    ProjectRow,
    TargetRow,
    create_session_factory,
    initialize_database,
)
from securescan.product_core import (
    InvalidScanFilterError,
    InvalidScanPaginationError,
    ProductCoreNotReadyError,
    ScanNotFoundError,
    ScanNotPublishedError,
    SourceFindingSummary,
    SourceIntakeKind,
    SourcePreparedScanRequest,
    SourceProductStatus,
    SourcePublishedReport,
    SourceScanPage,
    SourceScanQueryPersistenceError,
    SourceScanQueryService,
    SourceScanSubmission,
    SourceScanSubmissionService,
    SourceScanSummary,
)
from securescan.source import (
    AnalysisCapability,
    AnalysisSurface,
    EnryBatchResult,
    EnryClassification,
    EnryFileInput,
    RepositoryProfile,
    SourcePlanAction,
    SourcePlanningPolicy,
    SourceSupportState,
    TrustedEnryHelper,
    TrustedSourceAnalyzer,
    TrustedSourceAnalyzerRegistry,
    build_repository_inventory,
    build_source_analysis_plan,
)
from securescan.workspaces import RepositoryWorkspaceManager

_PROJECT_ID = "11111111-1111-4111-8111-111111111111"
_LINEAGE_ID = "22222222-2222-4222-8222-222222222222"
_RUN_ID = "33333333-3333-4333-8333-333333333333"
_NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)
_KEY = "a" * 64
_RAW_SECRET = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _summary(
    status: SourceProductStatus = SourceProductStatus.QUEUED,
    *,
    coverage_complete: bool | None = None,
) -> SourceScanSummary:
    return SourceScanSummary(
        run_id=_RUN_ID,
        target_id="44444444-4444-4444-8444-444444444444",
        project_id=_PROJECT_ID,
        lineage_id=_LINEAGE_ID,
        submission_sequence_number=1,
        predecessor_run_id=None,
        product_status=status,
        created_at=_NOW,
        published_at=_NOW if status is not SourceProductStatus.QUEUED else None,
        finalized_at=_NOW if status is SourceProductStatus.COMPLETED else None,
        indexed=status is SourceProductStatus.COMPLETED,
        lifecycle_evaluated=status is SourceProductStatus.COMPLETED,
        finding_count=1,
        priority_counts={"HIGH": 1},
        category_counts={"CODE_SECURITY": 1},
        coverage_complete=coverage_complete,
        coverage_counts={"PARTIAL": 1} if coverage_complete is False else {},
        gap_count=1 if coverage_complete is False else None,
    )


def _submission(lineage_id: str = _LINEAGE_ID) -> SourceScanSubmission:
    return SourceScanSubmission(
        run_id=_RUN_ID,
        lineage_id=lineage_id,
        submission_sequence_number=1,
        predecessor_run_id=None,
        predecessor_sequence_number=None,
        intake_kind=SourceIntakeKind.MANAGED_WORKSPACE_V1,
        intake_ref="securescan-workspace-0123456789abcdef",
        created_at=_NOW,
        finalized_at=None,
        created=True,
    )


class _ProfilePlanner:
    def build(self, workspace):
        inventory = build_repository_inventory(workspace)
        paths = tuple(file.relative_path for file in inventory.files)
        profile = RepositoryProfile(
            repository_digest=inventory.repository_digest,
            files=inventory.files,
            surfaces=(
                AnalysisSurface(
                    capability=AnalysisCapability.REPOSITORY_PROFILING,
                    support_state=SourceSupportState.DETECTED,
                    eligible_paths=paths,
                ),
            ),
        )
        return profile, build_source_analysis_plan(
            profile, TrustedSourceAnalyzerRegistry(), SourcePlanningPolicy()
        )


class _NoWorkspace:
    def prepare_repository(self, _source):
        raise AssertionError("read command prepared a workspace")

    def cleanup_workspace(self, _workspace):
        raise AssertionError("read command cleaned a workspace")


class _NoSubmissions:
    def create_lineage(self, *, project_id: str):
        raise AssertionError(f"read command created lineage {project_id}")

    def submit_prepared(self, request):
        raise AssertionError(f"read command submitted {request}")


@dataclass
class _Queries:
    summary: SourceScanSummary = _summary()
    query_error: Exception | None = None
    finding_calls: list[dict[str, Any]] | None = None
    mutation_counter: int = 0
    scan_calls: int = 0

    def get_scan(self, _run_id: str) -> SourceScanSummary:
        self.scan_calls += 1
        if self.query_error is not None:
            raise self.query_error
        return self.summary

    def list_findings(self, _run_id: str, **kwargs: Any):
        if self.query_error is not None:
            raise self.query_error
        if self.finding_calls is not None:
            self.finding_calls.append(kwargs)
        finding = SourceFindingSummary(
            finding_id="f" * 64,
            authority="semgrep-ce",
            category="CODE_SECURITY",
            severity="HIGH",
            priority_band="HIGH",
            priority_reason_codes=("SOURCE_SEVERITY_HIGH",),
            lifecycle_state="NEW",
            first_seen_at=_NOW,
            last_seen_at=_NOW,
            resolved_at=None,
            subject={"kind": "SOURCE_CODE", "rule_id": "safe-rule"},
            primary_location={"kind": "SOURCE_SPAN", "path": "app.py", "start_line": 1},
        )
        return SourceScanPage((finding,), 1, kwargs["limit"], kwargs["offset"])

    def get_report(self, _run_id: str) -> SourcePublishedReport:
        if self.query_error is not None:
            raise self.query_error
        return SourcePublishedReport(
            _RUN_ID,
            {"schema_version": "securescan-unified-evidence-s4-v1", "findings": []},
        )


def _services(queries: _Queries | None = None) -> SourceCliServices:
    return SourceCliServices(
        workspace_manager=_NoWorkspace(),
        submissions=_NoSubmissions(),
        queries=queries or _Queries(),
        profile_planner=_ProfilePlanner(),
        default_deadline_seconds=1_800,
        clock=lambda: _NOW,
        idempotency_key_factory=lambda: _KEY,
    )


def _install_services(monkeypatch: pytest.MonkeyPatch, services: SourceCliServices) -> None:
    @contextmanager
    def factory():
        yield services

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)


def test_cli_app_imports_and_help_exposes_only_pc3d_surface_plus_existing_commands() -> None:
    result = CliRunner().invoke(cli_main.app, ["--help"])

    assert result.exit_code == 0
    for command in ("scan", "status", "findings", "report", "init-db", "run-fake"):
        assert command in result.stdout


def test_console_script_declaration_is_already_correct() -> None:
    pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text("utf-8")
    assert 'securescan = "securescan.cli.main:app"' in pyproject


def test_read_service_composition_does_not_require_enry_or_scanner_availability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'read.db'}",
        artifact_root=tmp_path / "artifacts",
        source_workspace_root=tmp_path / "workspaces",
        source_projection_root=tmp_path / "projections",
        source_enry_helper_sha256=None,
    )

    def reject(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("read composition attempted profiling or scanner discovery")

    monkeypatch.setattr(cli_source, "get_settings", lambda: settings)
    monkeypatch.setattr(cli_source, "_enry_client", reject)
    monkeypatch.setattr(cli_source, "_analyzer_registry", reject)
    with cli_source.create_source_cli_services() as services:
        assert isinstance(services.queries, SourceScanQueryService)


def test_scan_requires_explicit_existing_project_identity() -> None:
    result = CliRunner().invoke(cli_main.app, ["scan", "."])

    assert result.exit_code == 2
    assert "SUBMISSION_CONFLICT" in result.stderr
    assert "--project-id" in result.stderr


@pytest.mark.parametrize("source_kind", ["missing", "file"])
def test_scan_rejects_non_directory_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source_kind: str
) -> None:
    source = tmp_path / source_kind
    if source_kind == "file":
        source.write_text("not a repository", encoding="utf-8")
    _install_services(monkeypatch, _services())

    result = CliRunner().invoke(
        cli_main.app, ["scan", str(source), "--project-id", _PROJECT_ID]
    )

    assert result.exit_code == 2
    assert "INVALID_REPOSITORY" in result.stderr


def test_scan_uses_managed_workspace_and_preserves_it_after_return(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'pc3d.db'}",
        artifact_root=tmp_path / "artifacts",
        source_workspace_root=tmp_path / "workspaces",
        source_projection_root=tmp_path / "projections",
    )
    initialize_database(settings)
    engine, factory = create_session_factory(settings)
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_text("print('safe')\n", encoding="utf-8")
    manager = RepositoryWorkspaceManager(settings.source_workspace_root)
    artifacts = ContentAddressedArtifactStore(settings.artifact_root)
    submissions = SourceScanSubmissionService(factory, artifacts, manager, clock=lambda: _NOW)
    queries = SourceScanQueryService(factory, artifacts)
    with factory.begin() as session:
        session.add(ProjectRow(id=_PROJECT_ID, name="PC3D project", created_at=_NOW))
    services = SourceCliServices(
        manager,
        submissions,
        queries,
        _ProfilePlanner(),
        1_800,
        clock=lambda: _NOW,
        idempotency_key_factory=lambda: _KEY,
    )
    try:
        result = submit_local_scan(
            services,
            source_path=source,
            project_id=_PROJECT_ID,
            lineage_id=None,
            deadline_seconds=None,
        )
        with factory() as session:
            target = session.scalar(select(TargetRow))
        assert target is not None
        assert target.source_path == result.submission.intake_ref
        assert target.source_path.startswith("securescan-workspace-")
        assert str(source.resolve()) not in json.dumps(target.metadata_json)
        managed = settings.source_workspace_root / target.source_path
        assert managed.is_dir()
        assert (managed / "source" / "app.py").is_file()
        assert str(UUID(result.submission.run_id)) == result.submission.run_id
    finally:
        engine.dispose()


def test_profile_planner_uses_frozen_repository_wide_syft_scope_without_scanning(
    tmp_path: Path,
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_text("print('safe')\n", encoding="utf-8")
    (source / "poetry.lock").write_text("example==1.0\n", encoding="utf-8")
    (source / "main.tf").write_text('resource "x" "y" {}\n', encoding="utf-8")
    manager = RepositoryWorkspaceManager((tmp_path / "managed").resolve())
    workspace = manager.prepare_repository(source)

    class Enry:
        configuration = TrustedEnryHelper(
            helper_path=Path("/trusted/enry-helper"), expected_sha256="e" * 64
        )

        def classify(self, files: tuple[EnryFileInput, ...]) -> EnryBatchResult:
            classifications = tuple(
                EnryClassification(
                    relative_path=item.relative_path,
                    language="Python" if item.relative_path == "app.py" else None,
                    candidate_languages=("Python",)
                    if item.relative_path == "app.py"
                    else (),
                    is_binary=False,
                    is_vendor=False,
                    is_generated=False,
                    is_test=False,
                    is_configuration=item.relative_path == "main.tf",
                    is_documentation=False,
                    is_dot_file=False,
                    is_image=False,
                )
                for item in files
            )
            return EnryBatchResult(
                classifications=classifications,
                helper_sha256="e" * 64,
                helper_version="0.2.3",
                enry_version="v2.9.6",
                duration_ms=1,
            )

    roster = frozen_source_v1_authority_roster()
    registry_calls = 0

    def registry() -> TrustedSourceAnalyzerRegistry:
        nonlocal registry_calls
        registry_calls += 1
        return TrustedSourceAnalyzerRegistry(
            analyzers=tuple(
                sorted(
                    (
                        TrustedSourceAnalyzer(
                            authority.analyzer_id,
                            (authority.capability,),
                            True,
                        )
                        for authority in roster.authorities
                    ),
                    key=lambda analyzer: analyzer.analyzer_id,
                )
            )
        )

    profile, plan = SourceRepositoryProfilePlanner(
        lambda: Enry(),  # type: ignore[return-value]
        registry,
    ).build(workspace)
    package_surfaces = tuple(
        surface
        for surface in profile.surfaces
        if surface.capability is AnalysisCapability.PACKAGE_INVENTORY
    )
    assert len(package_surfaces) == 1
    assert package_surfaces[0].component_id is None
    assert package_surfaces[0].eligible_paths == (
        "app.py",
        "main.tf",
        "poetry.lock",
    )
    python_support = next(item for item in profile.languages if item.language == "Python")
    assert python_support.support_state is SourceSupportState.SCANNABLE
    runnable = {
        entry.capability: entry.analyzer_id
        for entry in plan.entries
        if entry.action is SourcePlanAction.RUN
    }
    assert runnable == {
        AnalysisCapability.CONFIGURATION_SECURITY: "checkov-source-v1",
        AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING: "osv-dependency-advisory-v1",
        AnalysisCapability.PACKAGE_INVENTORY: "syft-source-v1",
        AnalysisCapability.PYTHON_SAST: "python-semgrep-v1",
        AnalysisCapability.SECRET_DETECTION: "gitleaks-source-v1",
    }
    assert registry_calls == 1


def test_exact_pinned_requirements_create_production_osv_topology(
    tmp_path: Path,
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "requirements.txt").write_text(
        "PyYAML==5.3.1\nrequests>=2.31\nFlask\n",
        encoding="utf-8",
    )
    manager = RepositoryWorkspaceManager((tmp_path / "managed").resolve())
    workspace = manager.prepare_repository(source)

    class Enry:
        configuration = TrustedEnryHelper(
            helper_path=Path("/trusted/enry-helper"), expected_sha256="e" * 64
        )

        def classify(self, files: tuple[EnryFileInput, ...]) -> EnryBatchResult:
            return EnryBatchResult(
                classifications=tuple(
                    EnryClassification(
                        relative_path=item.relative_path,
                        language=None,
                        candidate_languages=(),
                        is_binary=False,
                        is_vendor=False,
                        is_generated=False,
                        is_test=False,
                        is_configuration=False,
                        is_documentation=False,
                        is_dot_file=False,
                        is_image=False,
                    )
                    for item in files
                ),
                helper_sha256="e" * 64,
                helper_version="0.2.3",
                enry_version="v2.9.6",
                duration_ms=1,
            )

    roster = frozen_source_v1_authority_roster()

    def registry() -> TrustedSourceAnalyzerRegistry:
        return TrustedSourceAnalyzerRegistry(
            analyzers=tuple(
                sorted(
                    (
                        TrustedSourceAnalyzer(
                            authority.analyzer_id,
                            (authority.capability,),
                            True,
                        )
                        for authority in roster.authorities
                    ),
                    key=lambda analyzer: analyzer.analyzer_id,
                )
            )
        )

    try:
        profile, plan = SourceRepositoryProfilePlanner(
            lambda: Enry(),  # type: ignore[return-value]
            registry,
        ).build(workspace)
        snapshot = SourcePlanningSnapshot.create(_RUN_ID, profile, plan, roster)
    finally:
        manager.cleanup_workspace(workspace)

    requirements = next(
        item for item in profile.files if item.relative_path == "requirements.txt"
    )
    assert requirements.role.value == "manifest"
    assert AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING in (
        requirements.eligible_capabilities
    )
    advisory = next(
        entry
        for entry in plan.entries
        if entry.capability is AnalysisCapability.DEPENDENCY_ADVISORY_MATCHING
    )
    assert advisory.action is SourcePlanAction.RUN
    assert advisory.selected_paths == ("requirements.txt",)

    syft = next(item for item in snapshot.nodes if item.authority is SourceAuthority.SYFT)
    osv = next(item for item in snapshot.nodes if item.authority is SourceAuthority.OSV)
    assert syft.selected_paths == ("requirements.txt",)
    assert osv.selected_paths == ("requirements.txt",)
    assert len(snapshot.dependencies) == 1
    assert snapshot.dependencies[0].node_id == osv.node_id
    assert snapshot.dependencies[0].prerequisite_node_id == syft.node_id


def test_pc3d_registry_uses_available_canonical_production_semgrep_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        _env_file=None,
        artifact_root=tmp_path / "artifacts",
        source_workspace_root=tmp_path / "workspaces",
    )
    artifacts = ContentAddressedArtifactStore(settings.artifact_root)
    workspaces = RepositoryWorkspaceManager(settings.source_workspace_root)
    captured: dict[str, str] = {}

    def analyzer(capability: AnalysisCapability, analyzer_id: str):
        return TrustedSourceAnalyzer(analyzer_id, (capability,), True)

    monkeypatch.setattr(cli_source, "DockerSandboxExecutor", lambda: object())
    monkeypatch.setattr(cli_source, "create_default_checkov_binding", lambda _path: object())
    monkeypatch.setattr(cli_source, "create_default_gitleaks_binding", lambda _path: object())
    monkeypatch.setattr(cli_source, "create_default_syft_binding", lambda _path: object())
    monkeypatch.setattr(
        cli_source,
        "build_checkov_source_analyzer_snapshot",
        lambda _binding: analyzer(
            AnalysisCapability.CONFIGURATION_SECURITY, "checkov-source-v1"
        ),
    )
    monkeypatch.setattr(
        cli_source,
        "build_gitleaks_source_analyzer_snapshot",
        lambda _binding: analyzer(
            AnalysisCapability.SECRET_DETECTION, "gitleaks-source-v1"
        ),
    )
    monkeypatch.setattr(
        cli_source,
        "build_syft_source_analyzer_snapshot",
        lambda _binding: analyzer(
            AnalysisCapability.PACKAGE_INVENTORY, "syft-source-v1"
        ),
    )

    def semgrep_snapshot(binding, _registry, _docker):
        captured["image"] = binding.image_reference
        captured["digest"] = binding.binding_digest()
        return analyzer(AnalysisCapability.PYTHON_SAST, "python-semgrep-v1")

    monkeypatch.setattr(
        cli_source,
        "build_semgrep_source_analyzer_snapshot",
        semgrep_snapshot,
    )

    registry = cli_source._analyzer_registry(settings, artifacts, workspaces)
    semgrep = registry.analyzer_for(AnalysisCapability.PYTHON_SAST)

    assert semgrep is not None and semgrep.available
    assert captured == {
        "image": cli_source.PRODUCTION_SEMGREP_IMAGE_REFERENCE,
        "digest": "265fd32e59296d6dc50fd7f8b7558f0e35ead821c4ee689f5ff953bf70393ed2",
    }


def test_scan_command_returns_identity_without_claiming_completion_or_leaking_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject_process(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("PC3D command test attempted scanner/process execution")

    monkeypatch.setattr(subprocess, "Popen", reject_process)
    source = tmp_path / "controlled-private-repository"
    source.mkdir()
    (source / "app.py").write_text("print('safe')\n", encoding="utf-8")
    managed = RepositoryWorkspaceManager((tmp_path / "managed-private-root").resolve())

    class Submissions:
        request: SourcePreparedScanRequest | None = None

        def create_lineage(self, *, project_id: str):
            assert project_id == _PROJECT_ID
            return SimpleNamespace(lineage_id=_LINEAGE_ID)

        def submit_prepared(self, request: SourcePreparedScanRequest):
            self.request = request
            return _submission(request.lineage_id)

    submissions = Submissions()
    services = SourceCliServices(
        managed,
        submissions,
        _Queries(),
        _ProfilePlanner(),
        1_800,
        clock=lambda: _NOW,
        idempotency_key_factory=lambda: _KEY,
    )
    _install_services(monkeypatch, services)

    result = CliRunner().invoke(
        cli_main.app,
        ["scan", str(source), "--project-id", _PROJECT_ID, "--json"],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "lineage_id": _LINEAGE_ID,
        "run_id": _RUN_ID,
        "submission_status": "SUBMITTED",
        "submission_sequence": 1,
    }
    assert submissions.request is not None
    assert submissions.request.idempotency_key == _KEY
    assert submissions.request.deadline_at == _NOW + timedelta(seconds=1_800)
    assert submissions.request.workspace.root_directory.is_dir()
    assert submissions.request.workspace.source_directory != source
    forbidden = (
        str(source.resolve()),
        str(managed.base_directory),
        "scan complete",
        "clean",
        "secure",
        "attempt_token",
        "lease_token",
        "stdout_bytes",
        "stderr_bytes",
    )
    assert all(value not in result.stdout.lower() for value in forbidden)


def test_successful_submission_never_becomes_failure_when_status_read_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    manager = RepositoryWorkspaceManager((tmp_path / "managed").resolve())

    class Submissions:
        calls = 0

        def create_lineage(self, *, project_id: str):
            assert project_id == _PROJECT_ID
            return SimpleNamespace(lineage_id=_LINEAGE_ID)

        def submit_prepared(self, request: SourcePreparedScanRequest):
            self.calls += 1
            assert request.lineage_id == _LINEAGE_ID
            return _submission(request.lineage_id)

    submissions = Submissions()
    queries = _Queries(query_error=SourceScanQueryPersistenceError())
    _install_services(
        monkeypatch,
        SourceCliServices(
            manager,
            submissions,
            queries,
            _ProfilePlanner(),
            1_800,
            clock=lambda: _NOW,
            idempotency_key_factory=lambda: _KEY,
        ),
    )

    result = CliRunner().invoke(
        cli_main.app,
        ["scan", str(source), "--project-id", _PROJECT_ID],
    )

    combined = result.stdout + result.stderr
    assert result.exit_code == 0
    assert _RUN_ID in result.stdout
    assert _LINEAGE_ID in result.stdout
    assert "Sequence: 1" in result.stdout
    assert "Status: SUBMITTED" in result.stdout
    assert submissions.calls == 1
    assert queries.scan_calls == 0
    assert "SUBMISSION_UNAVAILABLE" not in combined
    assert "QUERY_UNAVAILABLE" not in combined
    assert "COMPLETED" not in combined
    assert "clean" not in combined.lower()
    assert "secure" not in combined.lower()


def test_scan_existing_lineage_and_generated_idempotency_are_forwarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_text("pass\n", encoding="utf-8")
    manager = RepositoryWorkspaceManager((tmp_path / "managed").resolve())

    class Submissions:
        def create_lineage(self, *, project_id: str):
            raise AssertionError(f"existing lineage unexpectedly replaced for {project_id}")

        def submit_prepared(self, request: SourcePreparedScanRequest):
            assert request.lineage_id == _LINEAGE_ID
            assert request.idempotency_key == "b" * 64
            return _submission(request.lineage_id)

    _install_services(
        monkeypatch,
        SourceCliServices(
            manager,
            Submissions(),
            _Queries(),
            _ProfilePlanner(),
            1_800,
            clock=lambda: _NOW,
            idempotency_key_factory=lambda: "b" * 64,
        ),
    )
    result = CliRunner().invoke(
        cli_main.app,
        [
            "scan",
            str(source),
            "--project-id",
            _PROJECT_ID,
            "--lineage-id",
            _LINEAGE_ID,
        ],
    )
    assert result.exit_code == 0


@pytest.mark.parametrize("value", ["invalid", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"])
def test_scan_rejects_invalid_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    _install_services(monkeypatch, _services())
    result = CliRunner().invoke(
        cli_main.app,
        ["scan", str(source), "--project-id", _PROJECT_ID, "--lineage-id", value],
    )
    assert result.exit_code == 2
    assert "SUBMISSION_CONFLICT" in result.stderr


@pytest.mark.parametrize(
    "status",
    tuple(SourceProductStatus),
)
def test_status_renders_every_product_state_without_mutation(
    monkeypatch: pytest.MonkeyPatch, status: SourceProductStatus
) -> None:
    queries = _Queries(summary=_summary(status))
    services = _services(queries)
    before = queries.mutation_counter
    _install_services(monkeypatch, services)

    result = CliRunner().invoke(cli_main.app, ["status", _RUN_ID, "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["product_status"] == status.value
    assert queries.mutation_counter == before


def test_completed_status_keeps_partial_coverage_visibly_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_services(
        monkeypatch,
        _services(
            _Queries(
                summary=_summary(
                    SourceProductStatus.COMPLETED, coverage_complete=False
                )
            )
        ),
    )
    result = CliRunner().invoke(cli_main.app, ["status", _RUN_ID])
    assert result.exit_code == 0
    assert "Status: COMPLETED" in result.stdout
    assert "Coverage: INCOMPLETE" in result.stdout
    assert "Gaps: 1" in result.stdout


def test_status_not_found_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_services(monkeypatch, _services(_Queries(query_error=ScanNotFoundError())))
    result = CliRunner().invoke(cli_main.app, ["status", _RUN_ID])
    assert result.exit_code == 3
    assert result.stdout == ""
    assert "SCAN_NOT_FOUND" in result.stderr


def test_findings_delegates_filters_and_pagination_to_pc3b(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    queries = _Queries(finding_calls=calls)
    before = queries.mutation_counter
    _install_services(monkeypatch, _services(queries))
    result = CliRunner().invoke(
        cli_main.app,
        [
            "findings",
            _RUN_ID,
            "--authority",
            "semgrep-ce",
            "--category",
            "CODE_SECURITY",
            "--priority",
            "HIGH",
            "--lifecycle",
            "NEW",
            "--limit",
            "12",
            "--offset",
            "3",
            "--json",
        ],
    )
    assert result.exit_code == 0
    assert calls == [
        {
            "authority": "semgrep-ce",
            "category": "CODE_SECURITY",
            "priority": "HIGH",
            "lifecycle_state": "NEW",
            "limit": 12,
            "offset": 3,
        }
    ]
    assert json.loads(result.stdout)["items"][0]["finding_id"] == "f" * 64
    assert queries.mutation_counter == before


@pytest.mark.parametrize(
    ("error", "code", "exit_code"),
    [
        (InvalidScanFilterError(), "INVALID_FILTER", 2),
        (InvalidScanPaginationError(), "INVALID_PAGINATION", 2),
        (ProductCoreNotReadyError(), "PRODUCT_CORE_NOT_READY", 3),
    ],
)
def test_findings_maps_pc3b_errors_safely(
    monkeypatch: pytest.MonkeyPatch, error: Exception, code: str, exit_code: int
) -> None:
    _install_services(monkeypatch, _services(_Queries(query_error=error)))
    result = CliRunner().invoke(cli_main.app, ["findings", _RUN_ID])
    assert result.exit_code == exit_code
    assert code in result.stderr


def test_report_uses_only_verified_pc3b_result_and_is_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queries = _Queries()
    before = queries.mutation_counter
    _install_services(monkeypatch, _services(queries))
    result = CliRunner().invoke(cli_main.app, ["report", _RUN_ID, "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "report": {
            "findings": [],
            "schema_version": "securescan-unified-evidence-s4-v1",
        },
        "run_id": _RUN_ID,
    }
    assert queries.mutation_counter == before


@pytest.mark.parametrize(
    ("error", "code", "exit_code"),
    [
        (ScanNotPublishedError(), "SCAN_NOT_PUBLISHED", 3),
        (SourceScanQueryPersistenceError(), "QUERY_UNAVAILABLE", 5),
    ],
)
def test_report_fails_safely_for_unpublished_or_integrity_drift(
    monkeypatch: pytest.MonkeyPatch, error: Exception, code: str, exit_code: int
) -> None:
    _install_services(monkeypatch, _services(_Queries(query_error=error)))
    result = CliRunner().invoke(cli_main.app, ["report", _RUN_ID])
    assert result.exit_code == exit_code
    assert code in result.stderr


def test_unexpected_failures_never_disclose_internal_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class HostileQueries(_Queries):
        def get_scan(self, _run_id: str):
            raise RuntimeError(
                f"{_RAW_SECRET} stdout_bytes stderr_bytes attempt_token lease_token "
                "/private/workspace /private/artifacts/native.json"
            )

    _install_services(monkeypatch, _services(HostileQueries()))
    result = CliRunner().invoke(cli_main.app, ["status", _RUN_ID])
    combined = result.stdout + result.stderr
    assert result.exit_code == 5
    assert "QUERY_UNAVAILABLE" in combined
    for forbidden in (
        _RAW_SECRET,
        "stdout_bytes",
        "stderr_bytes",
        "attempt_token",
        "lease_token",
        "/private/workspace",
        "/private/artifacts",
        "native.json",
    ):
        assert forbidden not in combined


def test_settings_freeze_bounded_source_deadline_and_require_enry_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("SECURESCAN_SOURCE_ENRY_HELPER_SHA256", raising=False)
    settings = Settings(_env_file=None, source_enry_helper_path=tmp_path / "enry")
    assert settings.source_scan_deadline_seconds == 1_800
    assert settings.source_enry_helper_path == (tmp_path / "enry").resolve()
    assert settings.source_enry_helper_sha256 is None
    configured = Settings(
        _env_file=None,
        source_enry_helper_path=tmp_path / "enry",
        source_enry_helper_sha256="a" * 64,
    )
    assert configured.source_enry_helper_sha256 == "a" * 64
