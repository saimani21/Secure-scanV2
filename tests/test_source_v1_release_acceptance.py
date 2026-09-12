from __future__ import annotations

import importlib.util
import json
import re
from collections import Counter
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts/source_v1_acceptance.py"
_PROJECT_ID = "00000000-0000-4000-8000-000000000101"
_LINEAGE_ID = "00000000-0000-4000-8000-000000000102"
_RUN_IDS = tuple(
    f"00000000-0000-4000-8000-{value:012d}" for value in range(103, 107)
)
_FINDING_ID = "a" * 64


def _load_harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location("source_v1_acceptance", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def harness() -> ModuleType:
    return _load_harness()


def _coverage(*, gitleaks_has_finding: bool) -> list[dict[str, object]]:
    return [
        {
            "authority": "checkov",
            "capability": "configuration_security",
            "component_ref": None,
            "framework": "terraform",
            "selected_scope": [{"kind": "REPOSITORY_PATH", "path": "infra/main.tf"}],
            "state": "COMPLETE_WITH_FINDINGS",
        },
        {
            "authority": "gitleaks",
            "capability": "secret_detection",
            "component_ref": None,
            "framework": None,
            "selected_scope": [
                {"kind": "REPOSITORY_PATH", "path": "config/release-sentinel.txt"}
            ],
            "state": "COMPLETE_WITH_FINDINGS" if gitleaks_has_finding else "COMPLETE",
            "finding_count": 1 if gitleaks_has_finding else 0,
            "gap_count": 0,
        },
        {
            "authority": "osv.dev",
            "capability": "dependency_advisory_matching",
            "component_ref": None,
            "framework": None,
            "selected_scope": [{"kind": "REPOSITORY_PATH", "path": "Pipfile.lock"}],
            "state": "COMPLETE_WITH_FINDINGS",
        },
        {
            "authority": "semgrep-ce",
            "capability": "python_sast",
            "component_ref": None,
            "framework": None,
            "selected_scope": [
                {"kind": "REPOSITORY_PATH", "path": "app/insecure_eval.py"}
            ],
            "state": "COMPLETE_WITH_FINDINGS",
        },
        {
            "authority": "syft",
            "capability": "package_inventory",
            "component_ref": None,
            "framework": None,
            "selected_scope": [{"kind": "REPOSITORY_PATH", "path": "Pipfile.lock"}],
            "state": "COMPLETE",
        },
    ]


def _report(run_id: str, *, gitleaks_has_finding: bool) -> dict[str, object]:
    findings: list[dict[str, object]] = [
        {
            "authority": "semgrep-ce",
            "category": "CODE_SECURITY",
            "finding_id": "b" * 64,
            "locations": [{"path": "app/insecure_eval.py"}],
            "subject": {"rule_id": "securescan.python.dangerous-eval"},
        },
        {
            "authority": "checkov",
            "category": "CONFIGURATION_SECURITY",
            "finding_id": "c" * 64,
            "locations": [{"path": "infra/main.tf"}],
            "primary_evidence_refs": ["f" * 64],
            "subject": {"framework": "terraform"},
        },
        {
            "authority": "osv.dev",
            "category": "DEPENDENCY_VULNERABILITY",
            "finding_id": "d" * 64,
            "locations": [{"path": "Pipfile.lock"}],
            "subject": {"component_ref": "e" * 64},
        },
    ]
    if gitleaks_has_finding:
        findings.append(
            {
                "authority": "gitleaks",
                "category": "SECRET_EXPOSURE",
                "finding_id": _FINDING_ID,
                "locations": [
                    {"path": "config/release-sentinel.txt", "start_line": 3}
                ],
                "subject": {"rule_id": "github-pat"},
            }
        )
    return {
        "components": [
            {
                "component_kind": "PACKAGE",
                "component_ref": "e" * 64,
                "payload": {"purl": "pkg:pypi/pyyaml@5.3.1"},
            }
        ],
        "coverage_outcomes": _coverage(gitleaks_has_finding=gitleaks_has_finding),
        "evidence": [
            {
                "authority": "checkov",
                "evidence_id": "f" * 64,
                "locations": [{"path": "infra/main.tf"}],
                "payload": {"check_id": "CKV_AWS_18"},
            }
        ],
        "findings": findings,
        "gaps": [],
        "scope": {"source_run_id": run_id},
    }


def _write_observations(root: Path) -> None:
    root.mkdir()
    lifecycles = ("NEW", "EXISTING", "RESOLVED", "REOPENED")
    previous_states = (None, "NEW", "EXISTING", "RESOLVED")
    reasons = (
        "FIRST_OBSERVATION",
        "OBSERVED_AGAIN",
        "COMPARABLE_SCOPE_ABSENCE",
        "RETURNED_AFTER_RESOLUTION",
    )
    for sequence, (run_id, lifecycle) in enumerate(
        zip(_RUN_IDS, lifecycles, strict=True), start=1
    ):
        prefix = chr(ord("a") + sequence - 1)
        present = sequence != 3
        report = _report(run_id, gitleaks_has_finding=present)
        coverage_counts = Counter(
            str(item["state"]) for item in report["coverage_outcomes"]  # type: ignore[index]
        )
        documents = {
            "submission": {
                "lineage_id": _LINEAGE_ID,
                "run_id": run_id,
                "submission_sequence": sequence,
                "submission_status": "SUBMITTED",
            },
            "status": {
                "coverage_complete": True,
                "coverage_counts": dict(coverage_counts),
                "finalized_at": "2026-09-11T00:00:00+00:00",
                "finding_count": len(report["findings"]),  # type: ignore[arg-type]
                "gap_count": 0,
                "lineage_id": _LINEAGE_ID,
                "priority_counts": {"HIGH": len(report["findings"])},  # type: ignore[arg-type]
                "product_status": "COMPLETED",
                "published_at": "2026-09-11T00:00:00+00:00",
                "run_id": run_id,
                "submission_sequence": sequence,
            },
            "lifecycle-event": {
                "event_kind": "TRANSITION",
                "finding_id": _FINDING_ID,
                "lineage_id": _LINEAGE_ID,
                "previous_state": previous_states[sequence - 1],
                "project_id": _PROJECT_ID,
                "reason_codes": [reasons[sequence - 1]],
                "resulting_state": lifecycle,
                "run_id": run_id,
                "schema_version": "securescan-source-v1-ra1-lifecycle-event-v1",
                "submission_sequence": sequence,
                "transition_version": sequence,
            },
            "report": {"report": report, "run_id": run_id},
        }
        for kind, document in documents.items():
            (root / f"{prefix}-{kind}.json").write_text(
                json.dumps(document), encoding="utf-8"
            )


def test_fixture_manifest_reuses_exact_frozen_gitleaks_relation(harness: ModuleType) -> None:
    manifest = harness.load_and_verify_manifest()
    contract = manifest["gitleaks_contract"]

    assert harness.MANIFEST_SHA256 == (
        "3006153694f349aa7f263f4a1396a777900950fa50ca9cc567a1c1cd785fa02d"
    )
    assert contract == {
        "benchmark_case_id": "github-pat-positive-01",
        "benchmark_baseline_sha256": (
            "62f9c00f79c659d56490a181de231f0aa3cdca6a418f2ca5a9215f7ed1bbbb34"
        ),
        "benchmark_manifest_sha256": (
            "2946d1b4093f2195612268d6ec7447f38ae4a7266c80f8da52f98d896db04c8e"
        ),
        "benchmark_plan_sha256": (
            "0090cd7d140034f715bc9d060465ea69284f63b3a33ab917479b1264fa542a10"
        ),
        "detection_kind": "CONTENT",
        "expected_line": 3,
        "expected_rule_id": "github-pat",
        "production_config_sha256": (
            "ca699281a4752ca677d7f1c1c22d97d2afca9c169eae28054486d4d95bae7fb4"
        ),
        "target_path": "config/release-sentinel.txt",
    }


def test_materialized_states_are_deterministic_and_change_only_selected_relation(
    tmp_path: Path, harness: ModuleType
) -> None:
    destination = tmp_path / "acceptance"
    harness.prepare_fixtures(destination)
    state_roots = sorted(path for path in destination.iterdir() if path.is_dir())

    assert len(state_roots) == 4
    state_files = [
        {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }
        for root in state_roots
    ]
    assert state_files[0] == state_files[1] == state_files[3]
    assert set(state_files[0]) == set(state_files[2])
    assert all(
        state_files[0][path] == state_files[2][path]
        for path in state_files[0]
        if path != "config/release-sentinel.txt"
    )
    assert state_files[0]["config/release-sentinel.txt"] != state_files[2][
        "config/release-sentinel.txt"
    ]


def test_gitleaks_sentinel_is_frozen_non_live_shape_at_expected_line(
    harness: ModuleType,
) -> None:
    manifest = harness.load_and_verify_manifest()
    source = _ROOT / manifest["states"][0]["gitleaks_fixture_source"]
    lines = source.read_text(encoding="utf-8").splitlines()
    token = lines[2]

    assert lines[1] == "# This value is non-live and must never be used as a credential."
    assert token.startswith("ghp_")
    assert len(token.removeprefix("ghp_")) == 36
    assert token.removeprefix("ghp_").isalnum()


def test_syft_expectation_is_component_evidence_not_finding(harness: ModuleType) -> None:
    expectations = harness.load_and_verify_manifest()["five_authority_expectations"]

    assert expectations["syft"]["evidence_role"] == "package_component"
    assert all(
        value["evidence_role"] == "finding"
        for authority, value in expectations.items()
        if authority != "syft"
    )


def test_summary_proves_four_states_and_emits_only_sanitized_evidence(
    tmp_path: Path, harness: ModuleType
) -> None:
    observations = tmp_path / "observations"
    _write_observations(observations)
    for submission in observations.glob("*-submission.json"):
        submission.unlink()

    summary = harness.build_summary(
        observations, securescan_commit="b" * 40, project_id=_PROJECT_ID
    )
    output = tmp_path / "summary.json"
    harness.write_summary(output, summary)
    raw = output.read_bytes()

    assert [item["selected_lifecycle_state"] for item in summary["runs"]] == [
        "NEW",
        "EXISTING",
        "RESOLVED",
        "REOPENED",
    ]
    assert [item["selected_lifecycle_reason_code"] for item in summary["runs"]] == [
        "FIRST_OBSERVATION",
        "OBSERVED_AGAIN",
        "COMPARABLE_SCOPE_ABSENCE",
        "RETURNED_AFTER_RESOLUTION",
    ]
    assert len({item["selected_finding_id"] for item in summary["runs"]}) == 1
    assert summary["assertions"] == {
        "all_five_authorities_successful_for_all_runs": True,
        "comparable_complete_coverage_for_all_runs": True,
        "c_report_omits_selected_finding": True,
        "c_successful_gitleaks_coverage": True,
        "lifecycle_new_existing_resolved_reopened": True,
        "product_core_index_and_lifecycle_complete_for_all_runs": True,
        "syft_is_component_evidence_not_a_finding": True,
    }
    assert all(value not in raw.lower() for value in (b"ghp_", b"stdout", b"stderr"))


def test_summary_rejects_different_finding_with_same_lifecycle_shape(
    tmp_path: Path, harness: ModuleType
) -> None:
    observations = tmp_path / "observations"
    _write_observations(observations)
    path = observations / "d-lifecycle-event.json"
    lifecycle = json.loads(path.read_text(encoding="utf-8"))
    lifecycle["finding_id"] = "f" * 64
    path.write_text(json.dumps(lifecycle), encoding="utf-8")

    with pytest.raises(harness.AcceptanceError):
        harness.build_summary(
            observations, securescan_commit="b" * 40, project_id=_PROJECT_ID
        )


def test_summary_rejects_noncomparable_coverage_scope(
    tmp_path: Path, harness: ModuleType
) -> None:
    observations = tmp_path / "observations"
    _write_observations(observations)
    wrapper = json.loads((observations / "c-report.json").read_text(encoding="utf-8"))
    wrapper["report"]["coverage_outcomes"][0]["selected_scope"][0]["path"] = "other.tf"
    (observations / "c-report.json").write_text(json.dumps(wrapper), encoding="utf-8")

    with pytest.raises(harness.AcceptanceError):
        harness.build_summary(
            observations, securescan_commit="b" * 40, project_id=_PROJECT_ID
        )


def test_resolved_comes_from_event_while_c_current_report_omits_finding(
    tmp_path: Path, harness: ModuleType
) -> None:
    observations = tmp_path / "observations"
    _write_observations(observations)
    event = json.loads(
        (observations / "c-lifecycle-event.json").read_text(encoding="utf-8")
    )
    report = json.loads((observations / "c-report.json").read_text(encoding="utf-8"))

    assert event["resulting_state"] == "RESOLVED"
    assert event["reason_codes"] == ["COMPARABLE_SCOPE_ABSENCE"]
    assert all(
        finding["finding_id"] != _FINDING_ID for finding in report["report"]["findings"]
    )
    summary = harness.build_summary(
        observations, securescan_commit="b" * 40, project_id=_PROJECT_ID
    )
    assert summary["runs"][2]["selected_lifecycle_state"] == "RESOLVED"


def test_wrong_lifecycle_reason_code_fails_closed(
    tmp_path: Path, harness: ModuleType
) -> None:
    observations = tmp_path / "observations"
    _write_observations(observations)
    path = observations / "c-lifecycle-event.json"
    event = json.loads(path.read_text(encoding="utf-8"))
    event["reason_codes"] = ["OBSERVED_AGAIN"]
    path.write_text(json.dumps(event), encoding="utf-8")

    with pytest.raises(harness.AcceptanceError):
        harness.build_summary(
            observations, securescan_commit="b" * 40, project_id=_PROJECT_ID
        )


def test_durable_lifecycle_events_require_exact_sequences_one_through_four(
    tmp_path: Path, harness: ModuleType
) -> None:
    observations = tmp_path / "observations"
    _write_observations(observations)
    path = observations / "b-lifecycle-event.json"
    event = json.loads(path.read_text(encoding="utf-8"))
    event["submission_sequence"] = 5
    path.write_text(json.dumps(event), encoding="utf-8")

    with pytest.raises(harness.AcceptanceError):
        harness.build_summary(
            observations, securescan_commit="b" * 40, project_id=_PROJECT_ID
        )


def test_c_requires_successful_zero_finding_gitleaks_coverage(
    tmp_path: Path, harness: ModuleType
) -> None:
    observations = tmp_path / "observations"
    _write_observations(observations)
    path = observations / "c-report.json"
    wrapper = json.loads(path.read_text(encoding="utf-8"))
    outcome = next(
        value
        for value in wrapper["report"]["coverage_outcomes"]
        if value["authority"] == "gitleaks"
    )
    outcome["state"] = "PARTIAL"
    outcome["gap_count"] = 1
    path.write_text(json.dumps(wrapper), encoding="utf-8")

    with pytest.raises(harness.AcceptanceError):
        harness.build_summary(
            observations, securescan_commit="b" * 40, project_id=_PROJECT_ID
        )


def test_extra_later_lineage_observations_do_not_enter_selected_summary(
    tmp_path: Path, harness: ModuleType
) -> None:
    observations = tmp_path / "observations"
    _write_observations(observations)
    (observations / "e-lifecycle-event.json").write_text(
        json.dumps({"unselected_later_sequence": 5}), encoding="utf-8"
    )

    summary = harness.build_summary(
        observations, securescan_commit="b" * 40, project_id=_PROJECT_ID
    )

    assert [item["submission_sequence"] for item in summary["runs"]] == [1, 2, 3, 4]
    assert {item["run_id"] for item in summary["runs"]} == set(_RUN_IDS)


def test_summary_is_create_once_and_rejects_sensitive_values(
    tmp_path: Path, harness: ModuleType
) -> None:
    output = tmp_path / "summary.json"
    harness.write_summary(output, {"decision": "PASS"})

    with pytest.raises(harness.AcceptanceError):
        harness.write_summary(output, {"decision": "PASS"})
    with pytest.raises(harness.AcceptanceError):
        harness.write_summary(tmp_path / "unsafe.json", {"stdout": "forbidden"})


def test_harness_has_no_scanner_database_or_network_execution_path() -> None:
    source = _SCRIPT.read_text(encoding="utf-8")

    assert "subprocess" not in source
    assert "sqlalchemy" not in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "create_source_runtime" not in source
    assert "Gitleaks" not in source
    assert '"lifecycle-event"' in source
    assert '"lifecycle")' not in source


def test_runbook_uses_public_cli_and_never_instructs_destructive_data_cleanup() -> None:
    document = (_ROOT / "docs/source-v1-release-acceptance.md").read_text(
        encoding="utf-8"
    )
    shell_blocks = "\n".join(re.findall(r"```bash\n(.*?)```", document, re.DOTALL))

    assert "securescan scan" in shell_blocks
    assert "securescan status" in shell_blocks
    assert "securescan report" in shell_blocks
    assert "scripts/source_v1_acceptance.py summarize" in shell_blocks
    assert "docker compose down -v" not in shell_blocks
    assert "docker volume rm" not in shell_blocks
    assert "test_existing_resolved_reopened_and_existing_history" in shell_blocks
    assert "LAST_RUN_ID" not in shell_blocks
    assert "fresh project and lineage" in document
    assert "require_sequence" in shell_blocks
