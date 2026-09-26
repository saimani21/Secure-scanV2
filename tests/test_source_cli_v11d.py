from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from securescan.cli import main as cli_main
from securescan.cli.presentation import terminal_text
from securescan.cli.source import SourceCliScanResult, SourceCliServices
from securescan.product_core import (
    SourceCoverageSummary,
    SourceDependencyAdvisorySummary,
    SourceDependencySummary,
    SourceGapSummary,
    SourceProductStatus,
    SourceProject,
    SourceProjectPage,
    SourceScanListItem,
    SourceScanPage,
    SourceScanStages,
    SourceScanSubmission,
    SourceScanSummary,
    SourceStageProgressState,
    SourceStageSummary,
)
from securescan.product_core.submission import SourceIntakeKind

_PROJECT_ID = "11111111-1111-4111-8111-111111111111"
_LINEAGE_ID = "22222222-2222-4222-8222-222222222222"
_RUN_ID = "33333333-3333-4333-8333-333333333333"
_NOW = datetime(2026, 9, 26, 12, tzinfo=UTC)


def _summary(
    status: SourceProductStatus = SourceProductStatus.COMPLETED,
) -> SourceScanSummary:
    completed = status is SourceProductStatus.COMPLETED
    return SourceScanSummary(
        run_id=_RUN_ID,
        target_id="44444444-4444-4444-8444-444444444444",
        project_id=_PROJECT_ID,
        lineage_id=_LINEAGE_ID,
        submission_sequence_number=2,
        predecessor_run_id=None,
        product_status=status,
        created_at=_NOW,
        published_at=_NOW if completed else None,
        finalized_at=_NOW if completed else None,
        indexed=completed,
        lifecycle_evaluated=completed,
        finding_count=1,
        priority_counts={"CRITICAL": 1},
        category_counts={"SECRET_EXPOSURE": 1},
        coverage_complete=True if completed else None,
        coverage_counts={"COMPLETE_WITH_FINDINGS": 1} if completed else {},
        gap_count=0 if completed else None,
    )


def _scan_item(status: SourceProductStatus = SourceProductStatus.COMPLETED):
    return SourceScanListItem(
        run_id=_RUN_ID,
        target_id="44444444-4444-4444-8444-444444444444",
        project_id=_PROJECT_ID,
        lineage_id=_LINEAGE_ID,
        submission_sequence_number=2,
        predecessor_run_id=None,
        product_status=status,
        created_at=_NOW,
        published_at=_NOW,
        finalized_at=_NOW,
        indexed=True,
        lifecycle_evaluated=True,
    )


def _dependency(evaluation: str, count: int | None):
    advisory = SourceDependencyAdvisorySummary(
        canonical_advisory_id="CVE-2026-1000",
        finding_id="f" * 64,
        osv_record_ids=("GHSA-aaaa-bbbb-cccc",),
        aliases=("CVE-2026-1000", "GHSA-aaaa-bbbb-cccc"),
        cve_aliases=("CVE-2026-1000",),
        ghsa_aliases=("GHSA-aaaa-bbbb-cccc",),
        fixed_versions=("2.0.0",),
        priority_band="HIGH",
    )
    return SourceDependencySummary(
        component_ref="a" * 64,
        name="requests",
        version="2.31.0",
        package_type="python",
        purl="pkg:pypi/requests@2.31.0",
        locations=({"kind": "REPOSITORY_PATH", "path": "requirements.txt"},),
        vulnerability_evaluation=evaluation,
        vulnerability_evaluation_reason=(
            None if evaluation == "COMPLETE" else "DEPENDENCY_INCOMPLETE"
        ),
        known_vulnerability_count=count,
        advisories=(advisory,),
        advisory_aliases=advisory.aliases,
        fixed_versions=advisory.fixed_versions,
        priority_bands=("HIGH",),
    )


@dataclass
class _Projects:
    calls: list[tuple[int, int]] = field(default_factory=list)

    def list_page(self, *, limit: int, offset: int) -> SourceProjectPage:
        self.calls.append((limit, offset))
        item = SourceProject(_PROJECT_ID, "Project\u001b[31m\u202e", _NOW)
        return SourceProjectPage((item,), 9, limit, offset)


@dataclass
class _Queries:
    statuses: list[SourceProductStatus] = field(
        default_factory=lambda: [SourceProductStatus.COMPLETED]
    )
    scan_calls: list[dict[str, Any]] = field(default_factory=list)

    def get_scan(self, _run_id: str) -> SourceScanSummary:
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return _summary(status)

    def list_scans(self, **kwargs: Any):
        self.scan_calls.append(kwargs)
        return SourceScanPage((_scan_item(),), 1, kwargs["limit"], kwargs["offset"])

    def get_stages(self, _run_id: str) -> SourceScanStages:
        return SourceScanStages(
            _RUN_ID,
            SourceProductStatus.COMPLETED,
            _NOW,
            _NOW,
            (
                SourceStageSummary(
                    "semgrep-ce",
                    "python_sast",
                    SourceStageProgressState.COMPLETE,
                    ("COMPLETE_WITH_FINDINGS",),
                    None,
                ),
            ),
        )

    def list_dependencies(self, _run_id: str, *, limit: int, offset: int):
        items = (
            _dependency("COMPLETE", 1),
            _dependency("PARTIAL", None),
            _dependency("FAILED", None),
            _dependency("NOT_APPLICABLE", None),
        )
        return SourceScanPage(items, len(items), limit, offset)

    def get_coverage(self, _run_id: str) -> SourceCoverageSummary:
        return SourceCoverageSummary(
            False,
            {"PARTIAL": 1},
            (
                {
                    "authority": "osv.dev",
                    "capability": "dependency_advisory_matching",
                    "state": "PARTIAL",
                    "framework": None,
                    "component_ref": None,
                },
            ),
        )

    def list_gaps(
        self, _run_id: str, *, authority: str | None, limit: int, offset: int
    ):
        item = SourceGapSummary(
            "b" * 64,
            authority or "osv.dev",
            "DEPENDENCY_INCOMPLETE",
            {"kind": "CAPABILITY", "value": "dependency_advisory_matching"},
            "unsafe\u001b[31m\u202etext",
        )
        return SourceScanPage((item,), 1, limit, offset)


def _submission() -> SourceScanSubmission:
    return SourceScanSubmission(
        run_id=_RUN_ID,
        lineage_id=_LINEAGE_ID,
        submission_sequence_number=2,
        predecessor_run_id=None,
        predecessor_sequence_number=None,
        intake_kind=SourceIntakeKind.MANAGED_WORKSPACE_V1,
        intake_ref="securescan-workspace-0123456789abcdef",
        created_at=_NOW,
        finalized_at=None,
        created=True,
    )


def _services(
    *,
    queries: _Queries | None = None,
    projects: _Projects | None = None,
    monotonic=lambda: 0.0,
    sleep=lambda _seconds: None,
) -> SourceCliServices:
    placeholder = SimpleNamespace()
    return SourceCliServices(
        workspace_manager=placeholder,
        submissions=placeholder,
        queries=queries or _Queries(),
        profile_planner=placeholder,
        default_deadline_seconds=300,
        projects=projects or _Projects(),  # type: ignore[arg-type]
        monotonic=monotonic,
        sleep=sleep,
    )


def _install(monkeypatch: pytest.MonkeyPatch, services: SourceCliServices) -> None:
    @contextmanager
    def factory():
        yield services

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)


def test_project_list_uses_authoritative_page_and_escapes_human_output(monkeypatch) -> None:
    projects = _Projects()
    _install(monkeypatch, _services(projects=projects))

    machine = CliRunner().invoke(
        cli_main.app, ["project", "list", "--limit", "4", "--offset", "3", "--json"]
    )
    human = CliRunner().invoke(
        cli_main.app, ["project", "list", "--limit", "4", "--offset", "3"]
    )

    assert machine.exit_code == 0
    assert json.loads(machine.stdout)["total"] == 9
    assert json.loads(machine.stdout)["offset"] == 3
    assert projects.calls == [(4, 3), (4, 3)]
    assert "\u001b" not in human.stdout
    assert "\\u001b" in human.stdout
    assert "\\u202e" in human.stdout
    assert "Showing 4–4 of 9" in human.stdout


def test_new_query_commands_emit_frozen_json_shapes(monkeypatch) -> None:
    queries = _Queries()
    _install(monkeypatch, _services(queries=queries))
    runner = CliRunner()

    scans = runner.invoke(
        cli_main.app,
        ["scans", "--project-id", _PROJECT_ID, "--limit", "7", "--offset", "2", "--json"],
    )
    global_scans = runner.invoke(cli_main.app, ["scans", "--json"])
    stages = runner.invoke(cli_main.app, ["stages", _RUN_ID, "--json"])
    dependencies = runner.invoke(cli_main.app, ["dependencies", _RUN_ID, "--json"])
    coverage = runner.invoke(cli_main.app, ["coverage", _RUN_ID, "--json"])
    gaps = runner.invoke(cli_main.app, ["gaps", _RUN_ID, "--authority", "osv.dev", "--json"])

    results = (scans, global_scans, stages, dependencies, coverage, gaps)
    assert all(result.exit_code == 0 for result in results)
    assert queries.scan_calls == [
        {"project_id": _PROJECT_ID, "limit": 7, "offset": 2},
        {"project_id": None, "limit": 50, "offset": 0},
    ]
    assert json.loads(scans.stdout)["items"][0]["submission_sequence_number"] == 2
    assert json.loads(global_scans.stdout)["total"] == 1
    assert json.loads(stages.stdout)["stages"][0]["progress_state"] == "COMPLETE"
    assert json.loads(dependencies.stdout)["items"][1]["known_vulnerability_count"] is None
    assert json.loads(coverage.stdout)["complete"] is False
    assert json.loads(gaps.stdout)["items"][0]["code"] == "DEPENDENCY_INCOMPLETE"


def test_dependency_human_output_preserves_unknown_and_not_applicable(monkeypatch) -> None:
    _install(monkeypatch, _services())
    result = CliRunner().invoke(cli_main.app, ["dependencies", _RUN_ID])

    assert result.exit_code == 0
    assert "Known vulnerabilities  1" in result.stdout
    assert result.stdout.count("Known vulnerabilities  Unknown") == 2
    assert "Known vulnerabilities  N/A" in result.stdout
    assert "Observed advisories    1" in result.stdout


def test_gap_human_output_escapes_controls_and_does_not_claim_completeness(monkeypatch) -> None:
    _install(monkeypatch, _services())
    result = CliRunner().invoke(cli_main.app, ["gaps", _RUN_ID])

    assert result.exit_code == 0
    assert "\u001b" not in result.stdout
    assert "\\u001b" in result.stdout
    assert "\\u202e" in result.stdout


@pytest.mark.parametrize(
    "terminal",
    (
        SourceProductStatus.FAILED,
        SourceProductStatus.CANCELLED,
        SourceProductStatus.BLOCKED_BY_PREDECESSOR,
    ),
)
def test_scan_wait_terminal_operational_failures_exit_five(monkeypatch, terminal) -> None:
    queries = _Queries(statuses=[terminal])
    _install(monkeypatch, _services(queries=queries))
    monkeypatch.setattr(
        cli_main,
        "submit_local_scan",
        lambda *_args, **_kwargs: SourceCliScanResult(_submission()),
    )

    result = CliRunner().invoke(
        cli_main.app,
        ["scan", ".", "--project-id", _PROJECT_ID, "--wait", "--json"],
    )

    assert result.exit_code == 5
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == f"SCAN_{terminal.value}"


def test_scan_wait_completes_after_nonterminal_states_and_critical_findings_exit_zero(
    monkeypatch,
) -> None:
    queries = _Queries(
        statuses=[
            SourceProductStatus.QUEUED,
            SourceProductStatus.RUNNING,
            SourceProductStatus.PUBLISHED_PENDING_FINALIZATION,
            SourceProductStatus.COMPLETED,
        ]
    )
    ticks = iter((0.0, 0.1, 0.2, 0.3))
    sleeps: list[float] = []
    _install(
        monkeypatch,
        _services(
            queries=queries,
            monotonic=lambda: next(ticks),
            sleep=sleeps.append,
        ),
    )
    monkeypatch.setattr(
        cli_main,
        "submit_local_scan",
        lambda *_args, **_kwargs: SourceCliScanResult(_submission()),
    )

    result = CliRunner().invoke(
        cli_main.app,
        ["scan", ".", "--project-id", _PROJECT_ID, "--wait", "--json"],
    )

    assert result.exit_code == 0
    assert result.stderr == ""
    assert json.loads(result.stdout)["product_status"] == "COMPLETED"
    assert json.loads(result.stdout)["priority_counts"] == {"CRITICAL": 1}
    assert sleeps == [2.0, 2.0, 2.0]


def test_scan_wait_timeout_does_not_cancel_and_emits_one_error_document(monkeypatch) -> None:
    ticks = iter((0.0, 2.0))
    _install(
        monkeypatch,
        _services(
            queries=_Queries(statuses=[SourceProductStatus.QUEUED]),
            monotonic=lambda: next(ticks),
        ),
    )
    monkeypatch.setattr(
        cli_main,
        "submit_local_scan",
        lambda *_args, **_kwargs: SourceCliScanResult(_submission()),
    )

    result = CliRunner().invoke(
        cli_main.app,
        [
            "scan",
            ".",
            "--project-id",
            _PROJECT_ID,
            "--wait",
            "--wait-timeout-seconds",
            "1",
            "--json",
        ],
    )

    assert result.exit_code == 5
    assert result.stdout == ""
    payload = json.loads(result.stderr)
    assert payload["error"]["code"] == "WAIT_TIMEOUT"
    assert "durable scan was not cancelled" in payload["error"]["message"]


def test_scan_wait_sigint_exits_130_without_cancellation(monkeypatch) -> None:
    def interrupt(_seconds: float) -> None:
        raise KeyboardInterrupt

    _install(
        monkeypatch,
        _services(
            queries=_Queries(statuses=[SourceProductStatus.QUEUED]),
            sleep=interrupt,
        ),
    )
    monkeypatch.setattr(
        cli_main,
        "submit_local_scan",
        lambda *_args, **_kwargs: SourceCliScanResult(_submission()),
    )

    result = CliRunner().invoke(
        cli_main.app,
        ["scan", ".", "--project-id", _PROJECT_ID, "--wait", "--json"],
    )

    assert result.exit_code == 130
    assert json.loads(result.stderr)["error"]["code"] == "WAIT_INTERRUPTED"


def test_terminal_text_escapes_control_bidi_and_bounds_output() -> None:
    rendered = terminal_text("a\x00\x1b\x9f\u202e\u2066" + "z" * 600)

    assert rendered.startswith("a\\u0000\\u001b\\u009f\\u202e\\u2066")
    assert len(rendered) <= 512
    assert rendered.endswith("…")
