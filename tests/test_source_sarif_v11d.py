from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from securescan.cli import main as cli_main
from securescan.cli.output import write_private_atomic
from securescan.cli.sarif import SARIF_PAGE_SIZE, build_sarif_bytes
from securescan.cli.source import SourceCliError, SourceCliServices
from securescan.product_core import (
    SourceFindingSummary,
    SourceProductStatus,
    SourcePublishedReport,
    SourceScanPage,
    SourceScanQueryPersistenceError,
    SourceScanSummary,
)

_RUN_ID = "33333333-3333-4333-8333-333333333333"
_PROJECT_ID = "11111111-1111-4111-8111-111111111111"
_NOW = datetime(2026, 9, 26, 12, tzinfo=UTC)
_SECRET = "github_pat_never_export_this_material"


def _finding(
    identifier: str,
    authority: str,
    category: str,
    priority: str,
    subject: dict[str, Any],
    location: dict[str, Any] | None,
    *,
    severity: str | None = None,
) -> SourceFindingSummary:
    return SourceFindingSummary(
        identifier,
        authority,
        category,
        severity,
        priority,
        ("REASON_B", "REASON_A"),
        "NEW",
        _NOW,
        _NOW,
        None,
        subject,
        location,
    )


def _fixture() -> tuple[tuple[SourceFindingSummary, ...], dict[str, Any]]:
    locations = {
        "semgrep": {
            "kind": "SOURCE_SPAN",
            "path": "src/bad name.py",
            "start_line": 7,
            "end_line": 8,
            "start_column": 4,
            "end_column": 20,
        },
        "gitleaks": {
            "kind": "SOURCE_SPAN",
            "path": "config/example.env",
            "start_line": 2,
            "end_line": 2,
            "start_column": None,
            "end_column": None,
        },
        "checkov": {"kind": "REPOSITORY_PATH", "path": "Dockerfile"},
        "osv": {
            "kind": "REPOSITORY_PATH",
            "path": "requirements test.txt",
        },
    }
    subjects = {
        "semgrep": {"kind": "SOURCE_CODE", "rule_id": "python.eval"},
        "gitleaks": {
            "kind": "SECRET_EXPOSURE",
            "rule_id": "github-pat",
            "detection_kind": "CONTENT",
        },
        "checkov": {
            "kind": "CONFIGURATION_RESOURCE",
            "framework": "dockerfile",
            "resource": "dockerfile.Dockerfile",
        },
        "osv": {"kind": "PACKAGE", "component_ref": "9" * 64},
    }
    summaries = (
        _finding(
            "a" * 64,
            "semgrep-ce",
            "CODE_SECURITY",
            "HIGH",
            subjects["semgrep"],
            locations["semgrep"],
            severity="HIGH",
        ),
        _finding(
            "b" * 64,
            "semgrep-ce",
            "CODE_SECURITY",
            "MEDIUM",
            subjects["semgrep"],
            None,
        ),
        _finding(
            "c" * 64,
            "gitleaks",
            "SECRET_EXPOSURE",
            "CRITICAL",
            subjects["gitleaks"],
            locations["gitleaks"],
        ),
        _finding(
            "d" * 64,
            "checkov",
            "CONFIGURATION_SECURITY",
            "UNRANKED",
            subjects["checkov"],
            locations["checkov"],
            severity="HIGH",
        ),
        _finding(
            "e" * 64,
            "osv.dev",
            "DEPENDENCY_VULNERABILITY",
            "LOW",
            subjects["osv"],
            locations["osv"],
        ),
    )

    def raw(summary: SourceFindingSummary, reference: str) -> dict[str, Any]:
        return {
            "authority": summary.authority,
            "category": summary.category,
            "finding_id": summary.finding_id,
            "locations": (
                [] if summary.primary_location is None else [summary.primary_location]
            ),
            "primary_evidence_refs": [reference],
            "subject": summary.subject,
        }

    report = {
        "components": [
            {
                "component_ref": "9" * 64,
                "payload": {
                    "kind": "PACKAGE_COMPONENT",
                    "package_name": "PyYAML",
                    "package_type": "python",
                    "package_version": "5.3.1",
                    "purl": "pkg:pypi/pyyaml@5.3.1",
                },
            }
        ],
        "evidence": [
            {
                "authority": "semgrep-ce",
                "evidence_id": "1" * 64,
                "evidence_kind": "SEMGREP_RULE_MATCH",
                "payload": {
                    "cwe_ids": ["CWE-78"],
                    "kind": "SEMGREP_RULE_MATCH",
                    "message": "Potential command injection",
                    "rule_id": "python.eval",
                },
            },
            {
                "authority": "semgrep-ce",
                "evidence_id": "2" * 64,
                "evidence_kind": "SEMGREP_RULE_MATCH",
                "payload": {
                    "cwe_ids": [],
                    "kind": "SEMGREP_RULE_MATCH",
                    "message": "Potential dynamic evaluation",
                    "rule_id": "python.eval",
                },
            },
            {
                "authority": "gitleaks",
                "evidence_id": "3" * 64,
                "evidence_kind": "GITLEAKS_SECRET_OBSERVATION",
                "payload": {
                    "detection_kind": "CONTENT",
                    "kind": "GITLEAKS_SECRET_OBSERVATION",
                    "rule_id": "github-pat",
                    "unsafe_test_only": _SECRET,
                },
            },
            {
                "authority": "checkov",
                "evidence_id": "4" * 64,
                "evidence_kind": "CHECKOV_POLICY_OBSERVATION",
                "payload": {
                    "check_id": "CKV_DOCKER_3",
                    "check_name": "Ensure container runs as non-root",
                    "framework": "dockerfile",
                    "kind": "CHECKOV_POLICY_OBSERVATION",
                    "resource": "dockerfile.Dockerfile",
                },
            },
            {
                "authority": "osv.dev",
                "evidence_id": "5" * 64,
                "evidence_kind": "OSV_ADVISORY_GROUP",
                "payload": {
                    "aliases": ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
                    "canonical_advisory_id": "CVE-2020-14343",
                    "fixed_versions": ["5.4"],
                    "kind": "OSV_ADVISORY_GROUP",
                },
            },
        ],
        "findings": [
            raw(summaries[0], "1" * 64),
            raw(summaries[1], "2" * 64),
            raw(summaries[2], "3" * 64),
            raw(summaries[3], "4" * 64),
            raw(summaries[4], "5" * 64),
        ],
        "scope": {"source_run_id": _RUN_ID},
    }
    return summaries, report


@dataclass
class _Queries:
    findings: tuple[SourceFindingSummary, ...]
    report: dict[str, Any]
    status: SourceProductStatus = SourceProductStatus.COMPLETED
    mode: str = "normal"

    def get_scan(self, _run_id: str) -> SourceScanSummary:
        complete = self.status is SourceProductStatus.COMPLETED
        return SourceScanSummary(
            _RUN_ID,
            "4" * 64,
            _PROJECT_ID,
            "22222222-2222-4222-8222-222222222222",
            1,
            None,
            self.status,
            _NOW,
            _NOW if complete else None,
            _NOW if complete else None,
            complete,
            complete,
            len(self.findings),
            {},
            {},
            True if complete else None,
            {},
            0 if complete else None,
        )

    def list_findings(self, _run_id: str, **kwargs: Any):
        if self.mode == "unavailable":
            raise SourceScanQueryPersistenceError
        offset = kwargs["offset"]
        if self.mode == "short":
            return SourceScanPage(self.findings[:1], 2, SARIF_PAGE_SIZE, offset)
        if self.mode == "duplicate":
            return SourceScanPage(
                (self.findings[0], self.findings[0]), 2, SARIF_PAGE_SIZE, offset
            )
        total = len(self.findings)
        if self.mode == "drift" and offset:
            total += 1
        return SourceScanPage(
            self.findings[offset : offset + SARIF_PAGE_SIZE],
            total,
            SARIF_PAGE_SIZE,
            offset,
        )

    def get_report(self, _run_id: str) -> SourcePublishedReport:
        if self.mode == "report-unavailable":
            raise SourceScanQueryPersistenceError
        return SourcePublishedReport(_RUN_ID, self.report)


def _services(queries: _Queries) -> SourceCliServices:
    placeholder = SimpleNamespace()
    return SourceCliServices(
        workspace_manager=placeholder,
        submissions=placeholder,
        queries=queries,
        profile_planner=placeholder,
        default_deadline_seconds=300,
    )


def test_sarif_is_deterministic_authoritative_and_secret_safe() -> None:
    findings, report = _fixture()
    services = _services(_Queries(findings, report))

    first = build_sarif_bytes(services, _RUN_ID)
    second = build_sarif_bytes(services, _RUN_ID)
    document = json.loads(first)
    run = document["runs"][0]

    assert first == second
    assert first.endswith(b"\n") and not first.endswith(b"\n\n")
    assert document["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in document["$schema"]
    assert run["tool"]["driver"]["name"] == "SecureScan"
    assert "version" not in run["tool"]["driver"]
    assert [item["id"] for item in run["tool"]["driver"]["rules"]] == sorted(
        {
            "semgrep-ce:python.eval",
            "gitleaks:github-pat",
            "checkov:CKV_DOCKER_3",
            "osv.dev:CVE-2020-14343",
        }
    )
    assert [item["properties"]["securescanFindingId"] for item in run["results"]] == [
        item.finding_id for item in findings
    ]
    assert [item["level"] for item in run["results"]] == [
        "error",
        "warning",
        "error",
        "none",
        "note",
    ]
    assert sum(item["ruleId"] == "semgrep-ce:python.eval" for item in run["results"]) == 2
    assert "locations" not in run["results"][1]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] == "src/bad%20name.py"
    assert "endColumn" not in run["results"][0]["locations"][0]["physicalLocation"][
        "region"
    ]
    assert run["results"][4]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] == "requirements%20test.txt"
    assert run["results"][3]["message"]["text"] == (
        "Ensure container runs as non-root"
    )
    assert run["results"][2]["message"]["text"] == (
        "Secret detected by Gitleaks rule github-pat."
    )
    rendered = first.decode()
    assert _SECRET not in rendered
    for forbidden in (
        "codeFlows",
        "fixes",
        "snippet",
        "contextRegion",
        "attachments",
        "generatedTimeUtc",
    ):
        assert forbidden not in rendered


def test_zero_findings_is_valid_and_has_no_rules() -> None:
    _findings, report = _fixture()
    report["findings"] = []
    document = json.loads(build_sarif_bytes(_services(_Queries((), report)), _RUN_ID))
    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []


@pytest.mark.parametrize(
    "status",
    (
        SourceProductStatus.QUEUED,
        SourceProductStatus.RUNNING,
        SourceProductStatus.PUBLISHED_PENDING_FINALIZATION,
        SourceProductStatus.FAILED,
        SourceProductStatus.CANCELLED,
        SourceProductStatus.BLOCKED_BY_PREDECESSOR,
    ),
)
def test_noncompleted_scan_fails_before_report(status: SourceProductStatus) -> None:
    findings, report = _fixture()
    with pytest.raises(SourceCliError) as raised:
        build_sarif_bytes(_services(_Queries(findings, report, status)), _RUN_ID)
    assert raised.value.exit_code in {3, 5}


@pytest.mark.parametrize("mode", ("unavailable", "report-unavailable", "short", "duplicate"))
def test_incomplete_or_unavailable_evidence_fails_closed(mode: str) -> None:
    findings, report = _fixture()
    with pytest.raises(SourceCliError):
        build_sarif_bytes(_services(_Queries(findings, report, mode=mode)), _RUN_ID)


def test_total_drift_fails_closed() -> None:
    findings, report = _fixture()
    expanded = tuple(
        replace(findings[0], finding_id=f"{number:064x}") for number in range(201)
    )
    with pytest.raises(SourceCliError):
        build_sarif_bytes(_services(_Queries(expanded, report, mode="drift")), _RUN_ID)


@pytest.mark.parametrize("field", ("authority", "category", "subject", "locations"))
def test_exact_correlation_rejects_report_mismatch(field: str) -> None:
    findings, report = _fixture()
    changed = deepcopy(report)
    finding = changed["findings"][0]
    finding[field] = [] if field == "locations" else "mismatch"
    with pytest.raises(SourceCliError):
        build_sarif_bytes(_services(_Queries(findings, changed)), _RUN_ID)


def test_private_atomic_writer_refuses_unsafe_targets_and_cleans_up(tmp_path: Path) -> None:
    output = tmp_path / "result.sarif"
    write_private_atomic(output, b"first\n", overwrite=False)
    assert output.read_bytes() == b"first\n"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(SourceCliError):
        write_private_atomic(output, b"refused\n", overwrite=False)
    assert output.read_bytes() == b"first\n"
    write_private_atomic(output, b"second\n", overwrite=True)
    assert output.read_bytes() == b"second\n"

    target_link = tmp_path / "target-link"
    target_link.symlink_to(output)
    with pytest.raises(SourceCliError):
        write_private_atomic(target_link, b"unsafe\n", overwrite=True)
    parent_link = tmp_path / "parent-link"
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    parent_link.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(SourceCliError):
        write_private_atomic(parent_link / "out.sarif", b"unsafe\n", overwrite=False)
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(SourceCliError):
        write_private_atomic(directory, b"unsafe\n", overwrite=True)
    assert not tuple(tmp_path.glob(".*.securescan-*.tmp"))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unsupported")
def test_private_atomic_writer_refuses_special_file(tmp_path: Path) -> None:
    fifo = tmp_path / "result.fifo"
    os.mkfifo(fifo)
    with pytest.raises(SourceCliError):
        write_private_atomic(fifo, b"unsafe\n", overwrite=True)


def test_sarif_cli_stdout_is_pure_and_file_failure_creates_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    findings, report = _fixture()
    queries = _Queries(findings, report)

    @contextmanager
    def factory():
        yield _services(queries)

    monkeypatch.setattr(cli_main, "create_source_cli_services", factory)
    stdout = CliRunner().invoke(cli_main.app, ["sarif", _RUN_ID, "--output", "-"])
    assert stdout.exit_code == 0
    assert stdout.stderr == ""
    assert json.loads(stdout.stdout)["version"] == "2.1.0"

    queries.status = SourceProductStatus.FAILED
    destination = tmp_path / "failed.sarif"
    failed = CliRunner().invoke(
        cli_main.app, ["sarif", _RUN_ID, "--output", str(destination)]
    )
    assert failed.exit_code == 5
    assert failed.stdout == ""
    assert json.loads(failed.stderr)["error"]["code"] == "SARIF_SCAN_FAILED"
    assert not destination.exists()
