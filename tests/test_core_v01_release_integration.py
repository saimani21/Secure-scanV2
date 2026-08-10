from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from release_test_guard import (
    ReleaseTestEnvironment,
    validated_release_test_environment,
)
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from securescan.adapters.trusted_registry import (
    TrustedAdapterRegistry,
    TrustedAdapterResolver,
)
from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.config import get_settings
from securescan.domain.enums import ArtifactKind, JobStatus, RunStatus, TargetType
from securescan.execution import DockerSandboxExecutor
from securescan.jobs import (
    JobCancellationService,
    JobExecutionService,
    JobFailureCommitService,
    JobHeartbeatService,
    JobLeasingService,
    JobRepository,
    JobResultCommitService,
    JobSubmissionRequest,
    JobSubmissionService,
)
from securescan.persistence.database import (
    AnalysisRunRow,
    ProjectRow,
    TargetRow,
    ToolExecutionRow,
    create_session_factory,
)
from securescan.release import CoreV01ReleaseEvaluator
from securescan.runs import RunQueryService
from securescan.scanners.semgrep import (
    create_semgrep_trusted_definition,
    load_baseline_ruleset,
)
from securescan.worker import SingleJobWorkerCycle, WorkerCycleDisposition
from securescan.workspaces import RepositoryWorkspaceManager

pytestmark = [
    pytest.mark.docker,
    pytest.mark.semgrep,
    pytest.mark.postgres,
    pytest.mark.release,
]

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPOSITORY_ROOT / "tests" / "fixtures" / "release_benchmark"
ALEMBIC_INI = REPOSITORY_ROOT / "alembic.ini"
MIGRATIONS = REPOSITORY_ROOT / "migrations"


@dataclass(frozen=True, slots=True)
class _ReleaseDatabase:
    engine: Engine
    sessions: sessionmaker[Session]


def _reset_public_schema(database_url: str) -> None:
    engine = create_engine(database_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


@pytest.fixture(scope="session")
def release_environment() -> ReleaseTestEnvironment:
    return validated_release_test_environment()


@pytest.fixture
def release_database(
    release_environment: ReleaseTestEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_ReleaseDatabase]:
    database_url = release_environment.postgres_url
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(MIGRATIONS))
    monkeypatch.setenv("SECURESCAN_DATABASE_URL", database_url)
    get_settings.cache_clear()
    engine: Engine | None = None
    try:
        _reset_public_schema(database_url)
        command.upgrade(config, "head")
        engine, sessions = create_session_factory(get_settings())
        yield _ReleaseDatabase(engine=engine, sessions=sessions)
    finally:
        if engine is not None:
            engine.dispose()
        _reset_public_schema(database_url)
        get_settings.cache_clear()


def _run_evaluator(
    tmp_path: Path,
    image: str,
    name: str,
):
    return CoreV01ReleaseEvaluator(
        corpus_root=CORPUS,
        semgrep_image=image,
        workspace_base=tmp_path / name,
    ).evaluate()


def _managed_containers() -> tuple[str, ...]:
    result = subprocess.run(  # noqa: S603 - fixed release cleanup inspection
        (
            "docker",
            "ps",
            "-a",
            "-q",
            "--filter",
            "label=securescan.managed=true",
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        shell=False,
        timeout=5,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail("Managed-container cleanup verification failed")
    return tuple(result.stdout.decode("ascii", errors="ignore").split())


def test_core_v01_real_benchmark_meets_curated_acceptance_thresholds(
    tmp_path: Path,
    release_environment: ReleaseTestEnvironment,
) -> None:
    evaluation = _run_evaluator(tmp_path, release_environment.semgrep_image, "acceptance")
    vulnerable = evaluation.vulnerable_case
    clean = evaluation.clean_case

    assert len(vulnerable.expected_findings) == 3
    assert vulnerable.metrics.true_positives == 3
    assert vulnerable.metrics.false_positives == 0
    assert vulnerable.metrics.false_negatives == 0
    assert (vulnerable.metrics.precision, vulnerable.metrics.recall) == (1.0, 1.0)
    assert vulnerable.metrics.f1_score == 1.0
    assert vulnerable.analysis_gap_count == 0
    assert vulnerable.raw_artifact_count == 1
    assert clean.observed_findings == ()
    assert clean.metrics.false_positives == 0
    assert clean.analysis_gap_count == 0
    assert clean.raw_artifact_count == 1
    assert evaluation.acceptance_passed
    assert any(
        "exactly three Python demonstration rules" in item
        for item in evaluation.limitations
    )


def test_core_v01_real_benchmark_is_repeatable(
    tmp_path: Path,
    release_environment: ReleaseTestEnvironment,
) -> None:
    first = _run_evaluator(tmp_path, release_environment.semgrep_image, "first")
    second = _run_evaluator(tmp_path, release_environment.semgrep_image, "second")

    assert first.vulnerable_case.corpus_digest == second.vulnerable_case.corpus_digest
    assert first.clean_case.corpus_digest == second.clean_case.corpus_digest
    assert first.vulnerable_case.observed_findings == second.vulnerable_case.observed_findings
    assert first.clean_case.observed_findings == second.clean_case.observed_findings
    assert first.vulnerable_case.metrics == second.vulnerable_case.metrics
    assert first.clean_case.metrics == second.clean_case.metrics
    assert first.release_evidence_digest == second.release_evidence_digest


def test_core_v01_postgres_worker_vertical_slice_commits_and_retrieves_once(
    tmp_path: Path,
    release_environment: ReleaseTestEnvironment,
    release_database: _ReleaseDatabase,
) -> None:
    source = CORPUS / "vulnerable"
    with release_database.sessions.begin() as session:
        project = ProjectRow(name="Core v0.1 release")
        session.add(project)
        session.flush()
        target = TargetRow(
            project_id=project.id,
            target_type=TargetType.SOURCE_REPOSITORY.value,
            content_digest="0" * 64,
            source_path=str(source),
            metadata_json={},
        )
        session.add(target)
        session.flush()
        target_id = target.id

    submitted = JobSubmissionService(release_database.sessions).submit(
        JobSubmissionRequest(
            target_id=target_id,
            adapter_id="semgrep-ce",
            idempotency_key="e" * 64,
            max_attempts=1,
        )
    )

    def resolve_source(run_id: str) -> Path:
        with release_database.sessions() as session:
            source_path = session.scalar(
                select(TargetRow.source_path)
                .join(AnalysisRunRow, AnalysisRunRow.target_id == TargetRow.id)
                .where(AnalysisRunRow.id == run_id)
            )
        if source_path is None:
            raise RuntimeError("Release source is unavailable")
        return Path(source_path)

    workspace_manager = RepositoryWorkspaceManager(tmp_path / "vertical-workspaces")
    definition = create_semgrep_trusted_definition(
        image_reference=release_environment.semgrep_image,
        tool_version="1.171.0",
        docker_executor=DockerSandboxExecutor(),
        workspace_manager=workspace_manager,
        ruleset=load_baseline_ruleset(),
        artifact_store=ContentAddressedArtifactStore(tmp_path / "artifacts"),
        source_resolver=resolve_source,
    )
    registry = TrustedAdapterRegistry((definition,))
    cancellation = JobCancellationService(release_database.sessions)
    cycle = SingleJobWorkerCycle(
        JobLeasingService(release_database.sessions),
        JobExecutionService(release_database.sessions),
        JobResultCommitService(release_database.sessions),
        JobFailureCommitService(release_database.sessions),
        TrustedAdapterResolver(registry),
        JobRepository(release_database.sessions),
        cancellation,
        JobHeartbeatService(release_database.sessions),
        "release-worker",
        lease_seconds=300,
        heartbeat_interval_seconds=30,
    )

    result = cycle.run_one_job()
    job = JobRepository(release_database.sessions).get_job(submitted.job_id)
    run = RunQueryService(release_database.sessions).get_run(submitted.run_id)
    report = RunQueryService(release_database.sessions).get_report(submitted.run_id)
    with release_database.sessions() as session:
        executions = list(
            session.scalars(
                select(ToolExecutionRow).where(ToolExecutionRow.job_id == submitted.job_id)
            )
        )

    assert result.disposition is WorkerCycleDisposition.SUCCEEDED
    assert job is not None and job.status is JobStatus.SUCCEEDED
    assert run.status is RunStatus.COMPLETED
    assert len(executions) == 1
    observations = report.report_json["observations"]
    assert len(observations) == 3
    assert len({finding["fingerprint"] for finding in observations}) == 3
    artifacts = report.report_json["executions"][0]["artifacts"]
    assert len(artifacts) == 1
    assert artifacts[0]["kind"] == ArtifactKind.SANITIZED_NATIVE_REPORT.value
    public_report = json.dumps(report.report_json, sort_keys=True)
    assert "lease_token" not in public_report
    assert str(source) not in public_report
    assert list(workspace_manager.base_directory.iterdir()) == []


def test_core_v01_release_gate_cleans_all_resources(
    tmp_path: Path,
    release_environment: ReleaseTestEnvironment,
    release_database: _ReleaseDatabase,
) -> None:
    workspace_base = tmp_path / "cleanup-workspaces"
    successful = CoreV01ReleaseEvaluator(
        corpus_root=CORPUS,
        semgrep_image=release_environment.semgrep_image,
        workspace_base=workspace_base,
    ).evaluate()
    broken_corpus = tmp_path / "broken-corpus"
    shutil.copytree(CORPUS, broken_corpus)
    (broken_corpus / "vulnerable" / "eval_case.py").unlink()
    (broken_corpus / "vulnerable" / "eval_case.py").symlink_to("/home/private/repository")

    with pytest.raises(ValueError, match="Benchmark corpus is invalid") as raised:
        CoreV01ReleaseEvaluator(
            corpus_root=broken_corpus,
            semgrep_image=release_environment.semgrep_image,
            workspace_base=workspace_base,
        ).evaluate()

    assert successful.acceptance_passed
    assert "private" not in str(raised.value)
    assert all(
        child.name == "workspaces" and not any(child.iterdir())
        for child in workspace_base.iterdir()
    )
    assert _managed_containers() == ()
    release_database.engine.dispose()
    _reset_public_schema(release_environment.postgres_url)
    verification_engine = create_engine(release_environment.postgres_url)
    try:
        assert inspect(verification_engine).get_table_names() == []
    finally:
        verification_engine.dispose()
