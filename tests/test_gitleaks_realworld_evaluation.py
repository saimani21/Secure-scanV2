from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

import securescan.benchmarks.gitleaks_realworld_evaluation as evaluation_module
from securescan.benchmarks.gitleaks_contract import GITLEAKS_BINDING_DIGEST
from securescan.benchmarks.gitleaks_realworld_acquisition import (
    GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256,
)
from securescan.benchmarks.gitleaks_realworld_contract import (
    GITLEAKS_REALWORLD_RESULT_PATH,
)
from securescan.benchmarks.gitleaks_realworld_evaluation import (
    GITLEAKS_F5B3_COMMIT,
    GITLEAKS_F5B3_TAG,
    GITLEAKS_REALWORLD_REPEATABILITY_PATH,
    GITLEAKS_REALWORLD_REPEATABILITY_SHA256,
    GITLEAKS_REALWORLD_RESULT_SHA256,
    GITLEAKS_REALWORLD_RUN2_SHA256,
    GitleaksRealworldEvaluationError,
    GitleaksRealworldLocation,
    GitleaksRealworldRunReport,
    _load_acquired_slots,
    _manifest_matches_slot,
    _parse_completed_execution,
    _prepare_verified_workspaces,
    compare_gitleaks_realworld_runs,
    evaluate_gitleaks_realworld_repository,
    verify_gitleaks_realworld_evidence,
)
from securescan.scanners.gitleaks import (
    GITLEAKS_SCANNER_ID,
    GITLEAKS_VERSION,
    GitleaksDetectionKind,
    GitleaksExecutionStatus,
    GitleaksParseResult,
    NormalizedGitleaksFinding,
)
from securescan.workspaces import PreparedRepositoryWorkspace
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

ROOT = Path(__file__).resolve().parents[1]
_CONTEXT_DIGEST = "c" * 64
_PROJECTION_ID = "securescan-source-projection-" + "1" * 32
_HISTORICAL_F5_TAGS = (
    "source-v0.4F5A-gitleaks-realworld-contract",
    "source-v0.4F5B1-gitleaks-acquisition-policy",
    "source-v0.4F5B2-gitleaks-repository-selection",
    "source-v0.4F5B2R1-gitleaks-repository-selection-correction",
    "source-v0.4F5B2R2-gitleaks-repository-selection-correction",
    "source-v0.4F5B3-gitleaks-realworld-acquisition",
)


def _slot(index: int) -> dict[str, object]:
    return {
        "slot_id": f"RW{index:02d}",
        "repository_id": f"repository-{index}",
        "snapshot_digest": f"{index:x}" * 64,
        "file_count": index,
        "byte_count": index * 10,
    }


def _finding(
    slot: dict[str, object],
    *,
    rule_id: str = "generic-api-key",
    path: str = "src/example.txt",
    kind: GitleaksDetectionKind = GitleaksDetectionKind.CONTENT,
    line: int = 1,
) -> NormalizedGitleaksFinding:
    is_content = kind is GitleaksDetectionKind.CONTENT
    return NormalizedGitleaksFinding(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        rule_id=rule_id,
        file_path=path,
        detection_kind=kind,
        start_line=line if is_content else None,
        end_line=line if is_content else None,
        start_column=1 if is_content else None,
        end_column=8 if is_content else None,
        projection_id=_PROJECTION_ID,
        context_digest=_CONTEXT_DIGEST,
        projection_digest=str(slot["snapshot_digest"]),
    )


def _parse_result(
    slot: dict[str, object],
    findings: tuple[NormalizedGitleaksFinding, ...] = (),
) -> GitleaksParseResult:
    return GitleaksParseResult(
        scanner_id=GITLEAKS_SCANNER_ID,
        scanner_version=GITLEAKS_VERSION,
        binding_digest=GITLEAKS_BINDING_DIGEST,
        projection_id=_PROJECTION_ID,
        context_digest=_CONTEXT_DIGEST,
        projection_digest=str(slot["snapshot_digest"]),
        findings=findings,
        finding_count=len(findings),
    )


def _result(
    index: int,
    findings: tuple[NormalizedGitleaksFinding, ...] | None = None,
):
    slot = _slot(index)
    actual = () if findings is None else findings
    return evaluate_gitleaks_realworld_repository(
        slot,
        _parse_result(slot, actual),
        execution_status=(
            GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
            if not actual
            else GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS
        ),
        return_code=0 if not actual else 1,
    )


def _run(run_number: int, replacement=None) -> GitleaksRealworldRunReport:
    repositories = tuple(
        replacement if index == 1 and replacement is not None else _result(index)
        for index in range(1, 7)
    )
    return GitleaksRealworldRunReport(run_number, repositories)


def _historical_path_exists(tag: str, relative_path: str) -> bool:
    resolved = subprocess.run(  # noqa: S603 - fixed local Git metadata query
        ["git", "rev-parse", f"{tag}^{{commit}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert len(resolved) == 40
    result = subprocess.run(  # noqa: S603 - fixed local Git tree query
        ["git", "cat-file", "-e", f"{tag}:{relative_path}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


@pytest.mark.parametrize("tag", _HISTORICAL_F5_TAGS)
def test_historical_f5_checkpoint_has_no_result_artifact(tag: str) -> None:
    assert not _historical_path_exists(tag, GITLEAKS_REALWORLD_RESULT_PATH)


def test_historical_f5b3_checkpoint_has_no_repeatability_artifact() -> None:
    assert not _historical_path_exists(
        GITLEAKS_F5B3_TAG,
        GITLEAKS_REALWORLD_REPEATABILITY_PATH,
    )


def test_current_f5c_f5d_evidence_is_exact_and_complete() -> None:
    run1, repeatability = verify_gitleaks_realworld_evidence(ROOT.resolve())

    assert run1.run_number == 1
    assert len(run1.repositories) == 6
    assert sum(row.parsed_finding_count for row in run1.repositories) == 138
    assert sum(row.content_finding_count for row in run1.repositories) == 138
    assert sum(row.path_finding_count for row in run1.repositories) == 0
    assert sum(row.unique_structural_finding_count for row in run1.repositories) == 138
    assert sum(row.duplicate_structural_finding_count for row in run1.repositories) == 0
    assert repeatability.run1_sha256 == GITLEAKS_REALWORLD_RESULT_SHA256
    assert hashlib.sha256(repeatability.run2.canonical_json()).hexdigest() == (
        GITLEAKS_REALWORLD_RUN2_SHA256
    )
    assert len(repeatability.repositories) == 6
    assert all(
        row.missing_from_run2 == 0
        and row.new_in_run2 == 0
        and row.canonical_set_equal
        for row in (*repeatability.repositories, repeatability.aggregate)
    )


@pytest.mark.parametrize(
    ("relative_path", "expected_sha256"),
    (
        (GITLEAKS_REALWORLD_RESULT_PATH, GITLEAKS_REALWORLD_RESULT_SHA256),
        (
            GITLEAKS_REALWORLD_REPEATABILITY_PATH,
            GITLEAKS_REALWORLD_REPEATABILITY_SHA256,
        ),
    ),
)
def test_current_evidence_is_regular_canonical_digest_bound_and_confidential(
    relative_path: str,
    expected_sha256: str,
) -> None:
    path = ROOT / relative_path
    metadata = path.lstat()
    payload = path.read_bytes()
    document = json.loads(payload)

    assert path.is_file()
    assert not path.is_symlink()
    assert os.path.isfile(path)
    assert metadata.st_size == len(payload)
    assert hashlib.sha256(payload).hexdigest() == expected_sha256
    assert payload == json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode() + b"\n"
    assert all(
        forbidden not in payload
        for forbidden in (
            b'"Secret"',
            b'"Match"',
            b'"Fingerprint"',
            b"credential_hash",
            b"raw_secret_content",
            b"scanner_output",
            b"stdout_bytes",
            b"stderr_bytes",
            b"/tmp/",
            str(ROOT).encode(),
        )
    )


@pytest.mark.parametrize("invalid", ("missing", "modified", "symlink"))
def test_current_evidence_verifier_rejects_invalid_entries(
    tmp_path: Path,
    invalid: str,
) -> None:
    root = (tmp_path / "repository").resolve()
    for relative in (
        GITLEAKS_REALWORLD_RESULT_PATH,
        GITLEAKS_REALWORLD_REPEATABILITY_PATH,
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    result = root / GITLEAKS_REALWORLD_RESULT_PATH
    if invalid == "missing":
        result.unlink()
    elif invalid == "modified":
        result.write_bytes(result.read_bytes() + b"modified\n")
    else:
        target = tmp_path / "result-target"
        shutil.copy2(result, target)
        result.unlink()
        result.symlink_to(target)

    with pytest.raises(GitleaksRealworldEvaluationError):
        verify_gitleaks_realworld_evidence(root)


def _workspace(tmp_path: Path) -> PreparedRepositoryWorkspace:
    entry = RepositoryManifestEntry(
        relative_path="file.txt",
        size_bytes=7,
        sha256=hashlib.sha256(b"content").hexdigest(),
    )
    entries = (entry,)
    digest = repository_content_digest(entries)
    manifest = RepositoryManifest(
        entries=entries,
        file_count=1,
        total_bytes=7,
        content_digest=digest,
    )
    root = (tmp_path / ("securescan-workspace-" + "a" * 32)).resolve()
    return PreparedRepositoryWorkspace(
        workspace_id=root.name,
        root_directory=root,
        source_directory=root / "source",
        output_directory=root / "output",
        manifest=manifest,
    )


def test_f5b3_and_acquired_manifest_provenance_are_exact() -> None:
    assert GITLEAKS_F5B3_COMMIT == "618ce6c393208528842c200df3927cf8df81de22"
    assert GITLEAKS_F5B3_TAG == "source-v0.4F5B3-gitleaks-realworld-acquisition"
    assert GITLEAKS_REALWORLD_ACQUIRED_MANIFEST_SHA256 == (
        "3a7f55e43210427974985c4e4009a1027fc4db12f3d94e119b490df8f0fc3b52"
    )


def test_acquired_manifest_is_verified_before_execution() -> None:
    slots = _load_acquired_slots(ROOT)
    assert tuple(slot["slot_id"] for slot in slots) == tuple(
        f"RW{index:02d}" for index in range(1, 7)
    )
    assert len({slot["snapshot_digest"] for slot in slots}) == 6


def test_parser_failure_is_converted_to_fixed_evaluation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_parser(_result: object, _projection: object) -> None:
        raise ValueError("hostile parser detail")

    monkeypatch.setattr(
        evaluation_module,
        "parse_gitleaks_execution_result",
        fail_parser,
    )
    with pytest.raises(
        GitleaksRealworldEvaluationError,
        match="^Gitleaks real-world evaluation failed$",
    ):
        _parse_completed_execution(object(), object())  # type: ignore[arg-type]


def test_return_code_zero_is_completed_without_findings() -> None:
    result = _result(1)
    assert result.execution_status is GitleaksExecutionStatus.COMPLETED_NO_FINDINGS
    assert result.return_code == 0
    assert result.parsed_finding_count == 0


def test_return_code_one_records_sanitized_content_and_path_findings() -> None:
    slot = _slot(1)
    findings = (
        _finding(slot),
        _finding(
            slot,
            rule_id="pkcs12-file",
            path="testdata/client.p12",
            kind=GitleaksDetectionKind.PATH,
        ),
    )
    result = evaluate_gitleaks_realworld_repository(
        slot,
        _parse_result(slot, findings),
        execution_status=GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
        return_code=1,
    )
    assert result.parsed_finding_count == 2
    assert result.content_finding_count == 1
    assert result.path_finding_count == 1
    assert result.observed_rule_ids == ("generic-api-key", "pkcs12-file")


@pytest.mark.parametrize(
    ("start_line", "end_line", "start_column", "end_column"),
    (
        (235, 236, 46, 19),
        (37, 38, 41, 26),
        (10, 10, 5, 9),
    ),
)
def test_realworld_location_accepts_parser_valid_coordinates(
    start_line: int,
    end_line: int,
    start_column: int,
    end_column: int,
) -> None:
    location = GitleaksRealworldLocation(
        start_line=start_line,
        end_line=end_line,
        start_column=start_column,
        end_column=end_column,
    )

    assert location.canonical_data() == {
        "end_column": end_column,
        "end_line": end_line,
        "start_column": start_column,
        "start_line": start_line,
    }


@pytest.mark.parametrize(
    ("start_line", "end_line", "start_column", "end_column"),
    (
        (10, 10, 9, 5),
        (11, 10, 5, 9),
        (10, 10, 0, 9),
        (10, 10, 5, -1),
    ),
)
def test_realworld_location_rejects_parser_invalid_coordinates(
    start_line: int,
    end_line: int,
    start_column: int,
    end_column: int,
) -> None:
    with pytest.raises(GitleaksRealworldEvaluationError):
        GitleaksRealworldLocation(
            start_line=start_line,
            end_line=end_line,
            start_column=start_column,
            end_column=end_column,
        )


@pytest.mark.parametrize(
    ("status", "return_code"),
    (
        (GitleaksExecutionStatus.FAILED, 2),
        (GitleaksExecutionStatus.TIMED_OUT, -1),
        (GitleaksExecutionStatus.CANCELLED, -15),
        (GitleaksExecutionStatus.OUTPUT_LIMIT_EXCEEDED, -1),
    ),
)
def test_incomplete_execution_can_never_become_clean(status, return_code: int) -> None:
    slot = _slot(1)
    with pytest.raises(GitleaksRealworldEvaluationError):
        evaluate_gitleaks_realworld_repository(
            slot,
            _parse_result(slot),
            execution_status=status,
            return_code=return_code,
        )


def test_status_return_code_contradiction_fails_closed() -> None:
    slot = _slot(1)
    with pytest.raises(GitleaksRealworldEvaluationError):
        evaluate_gitleaks_realworld_repository(
            slot,
            _parse_result(slot),
            execution_status=GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
            return_code=1,
        )


def test_snapshot_digest_mismatch_is_rejected() -> None:
    slot = _slot(1)
    mismatched = dict(slot, snapshot_digest="f" * 64)
    with pytest.raises(GitleaksRealworldEvaluationError):
        evaluate_gitleaks_realworld_repository(
            mismatched,
            _parse_result(slot),
            execution_status=GitleaksExecutionStatus.COMPLETED_NO_FINDINGS,
            return_code=0,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (("snapshot_digest", "2" * 64), ("file_count", 2), ("byte_count", 8)),
)
def test_verified_workspace_identity_mismatch_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    workspace = _workspace(tmp_path)
    slot = {
        "snapshot_digest": workspace.manifest.content_digest,
        "file_count": workspace.manifest.file_count,
        "byte_count": workspace.manifest.total_bytes,
    }
    slot[field] = value
    assert not _manifest_matches_slot(workspace, slot)


def test_missing_retained_snapshot_is_rejected(tmp_path: Path) -> None:
    retained = tmp_path / "retained"
    retained.mkdir()
    with pytest.raises(GitleaksRealworldEvaluationError):
        _prepare_verified_workspaces(
            ROOT,
            retained.resolve(),
            tuple(_slot(index) for index in range(1, 7)),
        )


def test_duplicate_structural_ids_remain_duplicate_observations() -> None:
    slot = _slot(1)
    finding = _finding(slot)
    result = evaluate_gitleaks_realworld_repository(
        slot,
        _parse_result(slot, (finding, finding)),
        execution_status=GitleaksExecutionStatus.COMPLETED_WITH_FINDINGS,
        return_code=1,
    )
    assert result.parsed_finding_count == 2
    assert result.unique_structural_finding_count == 1
    assert result.duplicate_structural_finding_count == 1
    assert len(result.observations) == 2


def test_all_six_repositories_are_required_for_complete_run() -> None:
    with pytest.raises(GitleaksRealworldEvaluationError):
        GitleaksRealworldRunReport(1, tuple(_result(index) for index in range(1, 6)))


def test_equal_runs_are_repeatable_per_repository_and_in_aggregate() -> None:
    comparison = compare_gitleaks_realworld_runs(_run(1), _run(2))
    assert all(row.canonical_set_equal for row in comparison.repositories)
    assert all(row.missing_from_run2 == 0 for row in comparison.repositories)
    assert all(row.new_in_run2 == 0 for row in comparison.repositories)
    assert comparison.aggregate.canonical_set_equal


def test_repeatability_report_rejects_inconsistent_aggregate() -> None:
    comparison = compare_gitleaks_realworld_runs(_run(1), _run(2))
    with pytest.raises(GitleaksRealworldEvaluationError):
        replace(
            comparison,
            aggregate=replace(comparison.aggregate, missing_from_run2=1),
        )


def test_missing_and_new_findings_are_detected() -> None:
    slot = _slot(1)
    first = _result(1, (_finding(slot, rule_id="github-pat"),))
    second = _result(1, (_finding(slot, rule_id="slack-bot-token"),))
    comparison = compare_gitleaks_realworld_runs(_run(1, first), _run(2, second))
    row = comparison.repositories[0]
    assert row.missing_from_run2 == 1
    assert row.new_in_run2 == 1
    assert not row.canonical_set_equal
    assert not comparison.aggregate.canonical_set_equal


def test_comparison_is_order_independent_and_ignores_runtime_identity() -> None:
    slot = _slot(1)
    first_findings = (
        _finding(slot, rule_id="github-pat", line=2),
        _finding(slot, rule_id="generic-api-key", line=1),
    )
    second_findings = tuple(reversed(first_findings))
    first = _result(1, first_findings)
    second = _result(1, second_findings)
    comparison = compare_gitleaks_realworld_runs(_run(1, first), _run(2, second))
    assert comparison.repositories[0].canonical_set_equal
    payload = comparison.canonical_json()
    assert b"projection_id" not in payload
    assert b"context_digest" not in payload
    assert b"duration" not in payload
    assert b"process" not in payload


def test_canonical_reports_are_stable_and_publish_no_accuracy_metrics() -> None:
    run = _run(1)
    assert run.canonical_json() == replace(run).canonical_json()
    payload = run.canonical_json()
    document = json.loads(payload)
    assert document["purpose"] == (
        "OPERATIONAL_GENERALIZATION_WITHOUT_COMPLETE_GROUND_TRUTH"
    )
    for forbidden in (b'"TP"', b'"TN"', b'"FP"', b'"FN"', b"precision", b"recall", b'"F1"'):
        assert forbidden not in payload


def test_canonical_artifacts_are_confidentiality_safe() -> None:
    run1 = _run(1)
    repeatability = compare_gitleaks_realworld_runs(run1, _run(2))
    for payload in (run1.canonical_json(), repeatability.canonical_json()):
        for forbidden in (
            b'"Secret"',
            b'"Match"',
            b'"Fingerprint"',
            b"credential_hash",
            b"raw_secret_content",
            b"scanner_output",
            b"stdout_bytes",
            b"stderr_bytes",
            b"/tmp/",
        ):
            assert forbidden not in payload


def test_production_bridge_is_the_only_scanner_execution_surface() -> None:
    source = (
        ROOT / "src/securescan/benchmarks/gitleaks_realworld_evaluation.py"
    ).read_text()
    assert "GitleaksSourceExecutionBridge" in source
    assert "parse_gitleaks_execution_result" in source
    assert "build_gitleaks_finding_identities" in source
    for forbidden in (
        'subprocess.run(["gitleaks"',
        "Popen(",
        "git clone",
        "git checkout",
        "requests.get(",
        "urlopen(",
    ):
        assert forbidden not in source
