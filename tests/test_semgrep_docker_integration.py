from __future__ import annotations

import hashlib
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from semgrep_test_guard import validated_semgrep_test_image

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import JobStatus
from securescan.execution import DockerSandboxExecutionRequest, DockerSandboxExecutor
from securescan.jobs import JobRecord
from securescan.scanners.semgrep import (
    SEMGREP_ARGUMENTS,
    TrustedSemgrepRuleset,
    create_semgrep_trusted_definition,
    load_source_ruleset,
)
from securescan.workspaces import RepositoryWorkspaceManager

pytestmark = [pytest.mark.docker, pytest.mark.semgrep]

FIXTURES = Path(__file__).parent / "fixtures" / "semgrep" / "repositories"
NOW = datetime(2062, 1, 2, 3, 4, 5, tzinfo=UTC)


@pytest.fixture
def semgrep_image() -> str:
    return validated_semgrep_test_image()


def _job(job_id: str, run_id: str) -> JobRecord:
    return JobRecord(
        id=job_id,
        run_id=run_id,
        adapter_id="semgrep-ce",
        status=JobStatus.RUNNING,
        priority=100,
        attempt_count=1,
        max_attempts=3,
        available_at=NOW,
        leased_by="integration-worker",
        lease_expires_at=NOW + timedelta(seconds=30),
        heartbeat_at=NOW,
        cancel_requested=False,
        idempotency_key=job_id.replace("-", "")[:64].ljust(64, "0"),
        payload_json={},
        last_error=None,
        created_at=NOW,
        updated_at=NOW,
        started_at=NOW,
        finished_at=None,
        lease_token=str(UUID("00000000-0000-4000-8000-000000006203")),
    )


def _composition(
    tmp_path: Path,
    image: str,
    source: Path,
    *,
    job_suffix: int,
    ruleset: TrustedSemgrepRuleset | None = None,
):
    executor = DockerSandboxExecutor()
    manager = RepositoryWorkspaceManager(tmp_path / "workspaces")
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    definition = create_semgrep_trusted_definition(
        image_reference=image,
        tool_version="1.171.0",
        docker_executor=executor,
        workspace_manager=manager,
        ruleset=ruleset or load_source_ruleset(),
        artifact_store=store,
        source_resolver=lambda _run_id: source,
    )
    job_id = str(UUID(f"00000000-0000-4000-8000-{job_suffix:012d}"))
    run_id = str(UUID(f"00000000-0000-4000-8000-{job_suffix + 100:012d}"))
    return definition.factory(), definition, executor, manager, store, _job(job_id, run_id)


def _managed_container_exists(execution_id: str) -> bool:
    completed = subprocess.run(  # noqa: S603 - integration-only fixed Docker state check
        (
            "docker",
            "ps",
            "-a",
            "-q",
            "--filter",
            f"label=securescan.execution={execution_id}",
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        shell=False,
        timeout=5,
        check=False,
    )
    return completed.returncode == 0 and bool(completed.stdout.strip())


def test_semgrep_image_version_and_offline_rules_are_usable(
    tmp_path: Path,
    semgrep_image: str,
) -> None:
    adapter, definition, executor, manager, _, job = _composition(
        tmp_path,
        semgrep_image,
        FIXTURES / "clean-python",
        job_suffix=6201,
    )
    version_source = tmp_path / "version-source"
    version_output = tmp_path / "version-output"
    version_source.mkdir()
    version_output.mkdir(mode=0o777)
    version_output.chmod(0o777)
    version_request = DockerSandboxExecutionRequest(
        definition=definition,
        source_directory=version_source,
        output_directory=version_output,
        arguments=("--version",),
        environment=(("HOME", "/tmp"),),
        execution_id="semgrep-version-check",
    )

    version_result = executor.execute(version_request)
    outcome = adapter.execute(job)

    assert version_result.return_code == 0
    assert b"1." in version_result.stdout
    assert outcome.final_status is JobStatus.SUCCEEDED
    assert definition.policy.network_mode.value == "disabled"
    assert SEMGREP_ARGUMENTS[1:4] == ("--json", "--metrics=off", "--disable-version-check")
    assert list(manager.base_directory.iterdir()) == []
    assert not _managed_container_exists(job.id)


def test_semgrep_adapter_finds_vulnerable_fixture_and_ignores_clean_fixture(
    tmp_path: Path,
    semgrep_image: str,
) -> None:
    vulnerable, _, _, vulnerable_manager, _, vulnerable_job = _composition(
        tmp_path / "vulnerable",
        semgrep_image,
        FIXTURES / "vulnerable-python",
        job_suffix=6202,
    )
    clean, _, _, clean_manager, _, clean_job = _composition(
        tmp_path / "clean",
        semgrep_image,
        FIXTURES / "clean-python",
        job_suffix=6203,
    )

    vulnerable_outcome = vulnerable.execute(vulnerable_job)
    clean_outcome = clean.execute(clean_job)
    findings = vulnerable_outcome.report_json["observations"]

    assert {finding["rule_id"] for finding in findings} == {
        "securescan.python.dangerous-eval",
        "securescan.python.subprocess-shell-true",
        "securescan.python.unsafe-yaml-load",
    }
    assert all(not finding["path"].startswith("/") for finding in findings)
    assert len({finding["fingerprint"] for finding in findings}) == len(findings)
    assert vulnerable_outcome.report_json["executions"][0]["artifacts"]
    assert vulnerable_outcome.report_json["analysis_gaps"] == []
    assert clean_outcome.report_json["observations"] == []
    assert clean_outcome.report_json["analysis_gaps"] == []
    assert list(vulnerable_manager.base_directory.iterdir()) == []
    assert list(clean_manager.base_directory.iterdir()) == []
    assert not _managed_container_exists(vulnerable_job.id)
    assert not _managed_container_exists(clean_job.id)


def test_semgrep_parser_error_produces_partial_result_and_cleanup(
    tmp_path: Path,
    semgrep_image: str,
) -> None:
    diagnostic_rules = b"""\
rules:
  - id: securescan.test.future-rule
    message: This rule requires a future Semgrep version.
    severity: INFO
    languages:
      - python
    min-version: 999.0.0
    pattern: future_call(...)

  - id: securescan.test.sentinel
    message: Test sentinel.
    severity: INFO
    languages:
      - python
    pattern: securescan_test_sentinel(...)
"""
    diagnostic_ruleset = TrustedSemgrepRuleset(
        ruleset_id="securescan-semgrep-diagnostic-test",
        display_name="SecureScan Semgrep diagnostic test",
        version="1",
        content=diagnostic_rules,
        sha256=hashlib.sha256(diagnostic_rules).hexdigest(),
    )
    parser_error_repository = tmp_path / "parser-error-repository"
    parser_error_repository.mkdir()
    fixture = FIXTURES / "parser-error-python" / "broken.txt"
    (parser_error_repository / "broken.py").write_text(
        fixture.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    adapter, _, _, manager, _, job = _composition(
        tmp_path,
        semgrep_image,
        parser_error_repository,
        job_suffix=6204,
        ruleset=diagnostic_ruleset,
    )

    outcome = adapter.execute(job)

    assert outcome.final_status is JobStatus.PARTIAL
    assert outcome.report_json["analysis_gaps"]
    assert outcome.report_json["analysis_gaps"][0]["code"] == "SEMGREP_RULE_ERROR"
    assert list(manager.base_directory.iterdir()) == []
    assert not _managed_container_exists(job.id)
