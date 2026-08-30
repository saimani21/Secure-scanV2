from __future__ import annotations

import json
from pathlib import Path

import pytest

from securescan.domain.enums import RunStatus
from securescan.scanners.semgrep import SemgrepOutputMalformedError, parse_semgrep_output
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)

FIXTURES = Path(__file__).parent / "fixtures" / "semgrep" / "output"


def _manifest(*paths: str) -> RepositoryManifest:
    entries = tuple(
        RepositoryManifestEntry(relative_path=path, size_bytes=1, sha256="0" * 64)
        for path in sorted(paths)
    )
    return RepositoryManifest(
        entries=entries,
        file_count=len(entries),
        total_bytes=len(entries),
        content_digest=repository_content_digest(entries),
    )


def _parse(
    raw: bytes,
    manifest: RepositoryManifest | None = None,
    *,
    maximum_findings: int = 100_000,
):
    return parse_semgrep_output(
        raw,
        manifest or _manifest("app.py", "worker.py", "broken.py"),
        scanner_id="semgrep-ce",
        scanner_version="1.171.0",
        maximum_findings=maximum_findings,
    )


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_parser_normalizes_valid_findings_and_severity() -> None:
    document = json.loads(_fixture("valid-findings.json"))
    for index, severity in enumerate(("WARNING", "INFO", "EXPERIMENTAL"), start=1):
        finding = json.loads(json.dumps(document["results"][0]))
        finding["check_id"] = f"securescan.python.severity-{severity.lower()}"
        finding["start"]["line"] += index
        finding["end"]["line"] += index
        finding["extra"]["severity"] = severity
        document["results"].append(finding)
    parsed = _parse(json.dumps(document).encode())
    finding = parsed.findings[0]

    assert parsed.accepted_result_count == 4
    assert finding.path == "app.py"
    assert finding.native_severity == "high"
    assert finding.message == "Semgrep security rule matched"
    assert finding.cwe_ids == ["CWE-95"]
    assert finding.properties["start_column"] == 5
    assert "metavars" not in finding.properties
    assert "ignored" not in finding.properties["metadata"]
    assert [item.native_severity for item in parsed.findings] == [
        "high",
        "medium",
        "low",
        "informational",
    ]


def test_parser_maps_only_paths_present_in_repository_manifest() -> None:
    invalid_paths = (
        "/workspace/source/not-in-manifest.py",
        "/home/private/repository/app.py",
        "../app.py",
        "/workspace/output/result.json",
        "C:\\private\\app.py",
    )

    for invalid_path in invalid_paths:
        document = json.loads(_fixture("valid-findings.json"))
        document["results"][0]["path"] = invalid_path
        parsed = _parse(json.dumps(document).encode())
        assert parsed.findings == ()
        assert parsed.rejected_result_count == 1
        assert parsed.analysis_gaps[0].code == "SEMGREP_FINDING_REJECTED"


def test_parser_rejects_malformed_top_level_documents() -> None:
    documents = (
        b"\xff",
        b"{broken",
        b"[]",
        b'{"results": {}, "errors": []}',
        b'{"results": [], "errors": {}}',
    )

    for document in documents:
        with pytest.raises(SemgrepOutputMalformedError):
            _parse(document)


@pytest.mark.parametrize(
    "document",
    (
        b'{"results": [], "results": [], "errors": []}',
        b'{"results": [{"extra": {"severity": "ERROR", "severity": "INFO"}}], '
        b'"errors": []}',
    ),
)
def test_parser_rejects_duplicate_json_object_keys(document: bytes) -> None:
    with pytest.raises(SemgrepOutputMalformedError):
        _parse(document)


@pytest.mark.parametrize("constant", (b"NaN", b"Infinity", b"-Infinity"))
def test_parser_rejects_non_finite_json_numbers(constant: bytes) -> None:
    document = b'{"results": [], "errors": [], "unknown": ' + constant + b"}"

    with pytest.raises(SemgrepOutputMalformedError):
        _parse(document)


def test_parser_rejects_or_gaps_malformed_individual_results() -> None:
    parsed = _parse(_fixture("malformed-result-items.json"))

    assert parsed.raw_result_count == 2
    assert parsed.accepted_result_count == 0
    assert parsed.rejected_result_count == 2
    assert len(parsed.analysis_gaps) == 2


def test_parser_converts_scanner_errors_to_analysis_gaps() -> None:
    document = json.loads(_fixture("findings-with-errors.json"))
    document["errors"].extend(
        [
            {"type": "Invalid target"},
            {"type": "Language unsupported"},
            {"type": "Timeout"},
            {"type": "Rule configuration"},
            {"type": "Internal error"},
            {"unexpected": "shape"},
        ]
    )
    parsed = _parse(json.dumps(document).encode())

    assert parsed.semgrep_error_count == 7
    assert {gap.code for gap in parsed.analysis_gaps} == {
        "SEMGREP_PARSE_ERROR",
        "SEMGREP_INVALID_TARGET",
        "SEMGREP_UNSUPPORTED_LANGUAGE",
        "SEMGREP_TIMEOUT",
        "SEMGREP_RULE_ERROR",
        "SEMGREP_INTERNAL_ERROR",
        "SEMGREP_UNKNOWN_DIAGNOSTIC",
    }
    assert "private scanner diagnostic" not in parsed.analysis_gaps[0].message


def test_parser_never_reports_clean_when_errors_are_present() -> None:
    parsed = _parse(b'{"results": [], "errors": [{"type": "unknown"}]}')

    status = RunStatus.PARTIAL if parsed.analysis_gaps else RunStatus.COMPLETED
    assert parsed.findings == ()
    assert status is RunStatus.PARTIAL


def test_parser_deduplicates_and_sorts_findings_deterministically() -> None:
    duplicate_document = json.loads(_fixture("duplicates.json"))
    second = json.loads(_fixture("valid-findings.json"))["results"][0]
    duplicate_document["results"].append(second)
    reversed_document = {
        "results": list(reversed(duplicate_document["results"])),
        "errors": [],
    }

    first = _parse(json.dumps(duplicate_document).encode())
    second_parse = _parse(json.dumps(reversed_document).encode())

    assert first.duplicate_result_count == 1
    assert [item.fingerprint for item in first.findings] == [
        item.fingerprint for item in second_parse.findings
    ]
    assert [item.path for item in first.findings] == ["app.py", "worker.py"]


def test_parser_computes_stable_securescan_fingerprints() -> None:
    original = json.loads(_fixture("valid-findings.json"))
    changed_scanner_fingerprint = json.loads(_fixture("valid-findings.json"))
    changed_scanner_fingerprint["results"][0]["extra"]["fingerprint"] = "different"

    first = _parse(json.dumps(original).encode(), _manifest("app.py"))
    second = _parse(
        json.dumps(changed_scanner_fingerprint).encode(),
        _manifest("app.py"),
    )
    different_rule = json.loads(_fixture("valid-findings.json"))
    different_rule["results"][0]["check_id"] = "securescan.python.other"
    third = _parse(json.dumps(different_rule).encode(), _manifest("app.py"))

    assert first.findings[0].fingerprint == second.findings[0].fingerprint
    assert first.findings[0].fingerprint != third.findings[0].fingerprint


def test_parser_ignores_untrusted_finding_messages() -> None:
    document = json.loads(_fixture("valid-findings.json"))
    document["results"][0]["extra"].pop("message")

    parsed = _parse(json.dumps(document).encode())

    assert parsed.accepted_result_count == 1
    assert parsed.findings[0].message == "Semgrep security rule matched"


def test_parser_bounds_safe_cwe_metadata_and_diagnostics() -> None:
    document = json.loads(_fixture("valid-findings.json"))
    document["results"][0]["extra"]["message"] = "untrusted scanner message"
    bounded_metadata_finding = json.loads(_fixture("valid-findings.json"))["results"][0]
    bounded_metadata_finding["check_id"] = "securescan.python.bounded-metadata"
    bounded_metadata_finding["start"]["line"] = 20
    bounded_metadata_finding["end"]["line"] = 20
    bounded_metadata_finding["extra"]["metadata"]["cwe"] = [
        f"CWE-{index}" for index in reversed(range(1, 101))
    ] + ["not-a-cwe", "CWE-0", "CWE-1\u0007"]
    bounded_metadata_finding["extra"]["metadata"]["technology"] = [
        f"technology-{index:03d}" for index in reversed(range(100))
    ]
    bounded_metadata_finding["extra"]["metadata"]["references"] = [
        "safe-reference",
        "unsafe-control\u0007",
        "x" * 1_025,
    ]
    document["results"].append(bounded_metadata_finding)
    document["errors"] = [{"type": "unknown"} for _ in range(105)]

    parsed = _parse(json.dumps(document).encode())

    assert parsed.rejected_result_count == 0
    metadata = parsed.findings[1].properties["metadata"]
    assert set(metadata) == {"cwe"}
    assert len(metadata["cwe"]) == 64
    assert metadata["cwe"] == sorted(metadata["cwe"])
    assert len(parsed.analysis_gaps) == 101
    assert parsed.analysis_gaps[-1].code == "SEMGREP_DIAGNOSTIC_LIMIT"


def test_parser_finding_limit_truncation_produces_analysis_gap() -> None:
    document = json.loads(_fixture("valid-findings.json"))
    second = json.loads(_fixture("valid-findings.json"))["results"][0]
    second["check_id"] = "securescan.python.second"
    second["start"]["line"] = 30
    second["end"]["line"] = 30
    document["results"].append(second)

    parsed = _parse(json.dumps(document).encode(), maximum_findings=1)

    assert len(parsed.findings) == 1
    assert parsed.rejected_result_count == 1
    assert parsed.analysis_gaps[0].code == "SEMGREP_FINDING_LIMIT"


def test_parser_public_errors_hide_json_paths_source_and_credentials() -> None:
    hostile = (
        "postgresql://user:password@host/database token=secret-value "
        "/home/private/repository /var/run/docker.sock source-code-secret"
    )
    malformed = json.dumps({"results": "invalid", "errors": [], "hostile": hostile}).encode()

    with pytest.raises(SemgrepOutputMalformedError) as raised:
        _parse(malformed)
    assert str(raised.value) == "Semgrep result output is malformed"
    assert all(secret not in str(raised.value) for secret in hostile.split())

    diagnostic = json.dumps(
        {"results": [], "errors": [{"type": "unknown", "message": hostile}]}
    ).encode()
    parsed = _parse(diagnostic)
    serialized_gaps = " ".join(gap.message for gap in parsed.analysis_gaps)
    assert all(secret not in serialized_gaps for secret in hostile.split())
