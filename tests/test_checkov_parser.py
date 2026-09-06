from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from securescan.scanners.checkov import (
    CheckovFailureCode,
    CheckovFrameworkState,
    CheckovParserError,
    expected_checkov_frameworks,
    parse_checkov_json,
)
from securescan.scanners.checkov import parser as checkov_parser

ROOT = Path("/tmp/securescan-source-projection-" + "5" * 32 + "/source")
PROJECTION_ID = "securescan-source-projection-" + "5" * 32
DIGEST = "a" * 64
BINDING = "b" * 64
PATHS = frozenset({"fail.tf", "pass.tf", "suppressed.tf", "malformed.tf", "other.tf"})


def _record(
    result: str,
    *,
    check_id: str = "CKV_AWS_18",
    path: str = "/fail.tf",
    resource: str = "aws_s3_bucket.controlled",
    lines: list[int] | None = None,
    severity: str | None = None,
) -> dict[str, object]:
    check_result: dict[str, object] = {
        "result": result,
        "evaluations": {"RAW_SECRET": "must-not-persist"},
    }
    if result == "SKIPPED":
        check_result["suppress_comment"] = "controlled reason"
    return {
        "check_id": check_id,
        "check_name": "Controlled check",
        "resource": resource,
        "file_path": path,
        "file_line_range": [1, 3] if lines is None else lines,
        "check_result": check_result,
        "severity": severity,
        "code_block": [[1, "RAW_SECRET"]],
        "evaluations": {"RAW_SECRET": "must-not-persist"},
        "connected_node": {"RAW_SECRET": "must-not-persist"},
    }


def _document() -> dict[str, object]:
    return {
        "check_type": "terraform",
        "results": {
            "failed_checks": [_record("FAILED")],
            "passed_checks": [_record("PASSED", path="/pass.tf")],
            "skipped_checks": [_record("SKIPPED", path="/suppressed.tf")],
            "parsing_errors": [str(ROOT / "malformed.tf")],
        },
        "summary": {
            "passed": 1,
            "failed": 1,
            "skipped": 1,
            "parsing_errors": 1,
            "resource_count": 3,
            "checkov_version": "3.3.16",
        },
        "url": "Add an API key to see more details",
    }


def _parse(document: object | None = None):
    return parse_checkov_json(
        json.dumps(_document() if document is None else document).encode(),
        projection_root=ROOT,
        authorized_paths=PATHS,
        projection_id=PROJECTION_ID,
        snapshot_digest=DIGEST,
        binding_digest=BINDING,
    )


def test_normalizes_failed_suppressed_passed_and_parse_gap_evidence() -> None:
    result = _parse()
    assert len(result.findings) == 1
    assert len(result.suppressions) == 1
    assert len(result.passed_observations) == 1
    assert len(result.gaps) == 1
    assert result.suppressions[0].reason == "controlled reason"
    assert result.gaps[0].normalized_path == "malformed.tf"
    assert result.framework_outcomes[0].state is CheckovFrameworkState.INCOMPLETE_PARSE_GAP
    assert all(
        item.state is CheckovFrameworkState.NOT_APPLICABLE for item in result.framework_outcomes[1:]
    )
    canonical = result.canonical_json()
    assert b"RAW_SECRET" not in canonical
    assert str(ROOT).encode() not in canonical
    assert b"code_block" not in canonical
    assert b"evaluations" not in canonical
    assert b"connected_node" not in canonical


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b"not-json",
        b'{"check_type":"terraform","check_type":"kubernetes"}',
        b'{"value":NaN}',
        b"[]",
    ],
)
def test_invalid_json_and_root_shapes_fail_closed(payload: bytes) -> None:
    with pytest.raises(CheckovParserError):
        parse_checkov_json(
            payload,
            projection_root=ROOT,
            authorized_paths=PATHS,
            projection_id=PROJECTION_ID,
            snapshot_digest=DIGEST,
            binding_digest=BINDING,
        )


def test_unsupported_framework_fails_explicitly() -> None:
    document = _document()
    document["check_type"] = "secrets"
    with pytest.raises(CheckovParserError) as error:
        _parse(document)
    assert error.value.code is CheckovFailureCode.UNSUPPORTED_FRAMEWORK


@pytest.mark.parametrize("path", ["/../escape", "/etc/passwd", "C:/host", "/missing.tf"])
def test_unsafe_or_unauthorized_paths_fail_closed(path: str) -> None:
    document = _document()
    document["results"]["failed_checks"][0]["file_path"] = path  # type: ignore[index]
    with pytest.raises(CheckovParserError) as error:
        _parse(document)
    assert error.value.code is CheckovFailureCode.PATH_INVALID


@pytest.mark.parametrize("lines", [[3, 2], [-1, 2], [1], [1, "2"]])
def test_invalid_line_ranges_fail_closed(lines: list[object]) -> None:
    document = _document()
    document["results"]["failed_checks"][0]["file_line_range"] = lines  # type: ignore[index]
    with pytest.raises(CheckovParserError):
        _parse(document)


def test_upstream_zero_start_line_becomes_missing_optional_location() -> None:
    document = _document()
    document["results"]["failed_checks"][0]["file_line_range"] = [0, 1]  # type: ignore[index]
    finding = _parse(document).findings[0]
    assert finding.line_start is None
    assert finding.line_end is None


def test_missing_optional_line_and_severity_are_not_invented() -> None:
    document = _document()
    record = document["results"]["failed_checks"][0]  # type: ignore[index]
    record["file_line_range"] = None
    record["severity"] = None
    finding = _parse(document).findings[0]
    assert finding.line_start is None
    assert finding.line_end is None
    assert finding.severity is None


def test_legitimate_offline_severity_is_preserved() -> None:
    document = _document()
    document["results"]["failed_checks"][0]["severity"] = "HIGH"  # type: ignore[index]
    assert _parse(document).findings[0].severity == "HIGH"


def test_summary_contradiction_never_becomes_clean() -> None:
    document = _document()
    document["summary"]["failed"] = 0  # type: ignore[index]
    with pytest.raises(CheckovParserError) as error:
        _parse(document)
    assert error.value.code is CheckovFailureCode.RESULT_INCONSISTENT


def test_parse_gap_never_becomes_clean_framework_completion() -> None:
    result = _parse()
    outcome = result.framework_outcomes[0]
    assert outcome.parsing_gap_count == 1
    assert outcome.state is CheckovFrameworkState.INCOMPLETE_PARSE_GAP


def test_completed_zero_finding_report_is_distinct_from_failure_or_gap() -> None:
    document = _document()
    document["results"]["failed_checks"] = []  # type: ignore[index]
    document["results"]["skipped_checks"] = []  # type: ignore[index]
    document["results"]["parsing_errors"] = []  # type: ignore[index]
    document["summary"].update(  # type: ignore[union-attr]
        failed=0,
        skipped=0,
        parsing_errors=0,
    )
    result = _parse(document)
    assert result.findings == ()
    assert result.suppressions == ()
    assert result.gaps == ()
    assert result.framework_outcomes[0].state is CheckovFrameworkState.COMPLETED


def test_suppression_is_neither_active_finding_nor_pass() -> None:
    result = _parse()
    assert result.suppressions[0].normalized_path == "suppressed.tf"
    assert all(item.normalized_path != "suppressed.tf" for item in result.findings)
    assert all(item.normalized_path != "suppressed.tf" for item in result.passed_observations)


def test_line_shift_does_not_change_finding_identity() -> None:
    first = _parse().findings[0]
    document = _document()
    document["results"]["failed_checks"][0]["file_line_range"] = [20, 30]  # type: ignore[index]
    second = _parse(document).findings[0]
    assert first.finding_id == second.finding_id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("check_id", "CKV2_AWS_6"),
        ("resource", "aws_s3_bucket.other"),
        ("file_path", "/other.tf"),
    ],
)
def test_check_resource_or_file_change_changes_identity(field: str, value: str) -> None:
    first = _parse().findings[0]
    document = _document()
    document["results"]["failed_checks"][0][field] = value  # type: ignore[index]
    second = _parse(document).findings[0]
    assert first.finding_id != second.finding_id


def test_input_order_does_not_change_normalized_finding_order() -> None:
    document = _document()
    second = _record("FAILED", check_id="CKV2_AWS_6", resource="aws_s3_bucket.other")
    document["results"]["failed_checks"].append(second)  # type: ignore[index]
    document["summary"]["failed"] = 2  # type: ignore[index]
    first_result = _parse(document)
    reversed_document = deepcopy(document)
    reversed_document["results"]["failed_checks"].reverse()  # type: ignore[index]
    assert first_result.canonical_json() == _parse(reversed_document).canonical_json()


def test_duplicate_logical_observation_fails_closed() -> None:
    document = _document()
    document["results"]["failed_checks"].append(  # type: ignore[index]
        deepcopy(document["results"]["failed_checks"][0])  # type: ignore[index]
    )
    document["summary"]["failed"] = 2  # type: ignore[index]
    with pytest.raises(CheckovParserError) as error:
        _parse(document)
    assert error.value.code is CheckovFailureCode.RESULT_INCONSISTENT


def test_document_and_record_limits_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checkov_parser, "_MAX_DOCUMENT_BYTES", 1)
    with pytest.raises(CheckovParserError):
        _parse()
    monkeypatch.setattr(checkov_parser, "_MAX_DOCUMENT_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(checkov_parser, "_MAX_RECORDS", 1)
    with pytest.raises(CheckovParserError):
        _parse()


def _summary_only() -> bytes:
    return json.dumps(
        {
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "parsing_errors": 0,
            "resource_count": 0,
            "checkov_version": "3.3.16",
        }
    ).encode()


@pytest.mark.parametrize(
    "paths",
    [
        frozenset({"main.tf"}),
        frozenset({"infra/main.tf.json"}),
        frozenset({"Dockerfile"}),
        frozenset({"containers/Dockerfile.production"}),
        frozenset({".github/workflows/build.yml"}),
    ],
)
def test_expected_framework_missing_from_summary_only_output_fails_closed(
    paths: frozenset[str],
) -> None:
    with pytest.raises(CheckovParserError) as error:
        parse_checkov_json(
            _summary_only(),
            projection_root=ROOT,
            authorized_paths=paths,
            projection_id=PROJECTION_ID,
            snapshot_digest=DIGEST,
            binding_digest=BINDING,
        )
    assert error.value.code is CheckovFailureCode.RESULT_INCONSISTENT


def test_mixed_projection_requires_every_deterministically_expected_framework() -> None:
    paths = PATHS | {"Dockerfile"}
    with pytest.raises(CheckovParserError) as error:
        parse_checkov_json(
            json.dumps(_document()).encode(),
            projection_root=ROOT,
            authorized_paths=paths,
            projection_id=PROJECTION_ID,
            snapshot_digest=DIGEST,
            binding_digest=BINDING,
        )
    assert error.value.code is CheckovFailureCode.RESULT_INCONSISTENT


def test_generic_yaml_and_json_zero_summary_is_true_non_applicable() -> None:
    paths = frozenset({"settings.yaml", "data.json"})
    result = parse_checkov_json(
        _summary_only(),
        projection_root=ROOT,
        authorized_paths=paths,
        projection_id=PROJECTION_ID,
        snapshot_digest=DIGEST,
        binding_digest=BINDING,
    )
    assert expected_checkov_frameworks(paths) == frozenset()
    assert all(
        outcome.state is CheckovFrameworkState.NOT_APPLICABLE
        for outcome in result.framework_outcomes
    )


def test_generic_zero_summary_requires_integer_counts() -> None:
    document = json.loads(_summary_only())
    document["failed"] = False
    with pytest.raises(CheckovParserError) as error:
        parse_checkov_json(
            json.dumps(document).encode(),
            projection_root=ROOT,
            authorized_paths=frozenset({"settings.yaml"}),
            projection_id=PROJECTION_ID,
            snapshot_digest=DIGEST,
            binding_digest=BINDING,
        )
    assert error.value.code is CheckovFailureCode.RESULT_INCONSISTENT
