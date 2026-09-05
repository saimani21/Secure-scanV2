from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from test_gitleaks_source_execution import (
    RAW_SECRET,
    _environment,
    _Executor,
    _Handle,
    _process_result,
)

import securescan.scanners.gitleaks.parser as parser_module
from securescan.scanners.gitleaks import (
    GITLEAKS_PARSER_SCHEMA_VERSION,
    GITLEAKS_V04B_BASELINE_COMMIT,
    GITLEAKS_V8301_PATH_ONLY_RULE_IDS,
    GitleaksDetectionKind,
    GitleaksExecutionStatus,
    GitleaksParserError,
    GitleaksParserFailureCode,
    parse_gitleaks_execution_result,
)
from securescan.workspaces.models import (
    RepositoryManifest,
    repository_content_digest,
)


def _finding(**changes):
    finding = {
        "RuleID": "github-pat",
        "Description": "Identified a GitHub Personal Access Token",
        "StartLine": 1,
        "EndLine": 1,
        "StartColumn": 1,
        "EndColumn": 5,
        "Match": f"token={RAW_SECRET.decode('ascii')}",
        "Secret": "REDACTED",
        "File": "app.py",
        "SymlinkFile": "",
        "Commit": "",
        "Entropy": 4.5,
        "Author": "",
        "Email": "",
        "Date": "",
        "Message": "",
        "Tags": ["github", "key"],
        "Fingerprint": "app.py:github-pat:1",
    }
    finding.update(changes)
    return finding


def _path_finding(file_path: str = "bundle.p12", **changes):
    finding = _finding(
        RuleID="pkcs12-file",
        File=file_path,
        StartLine=0,
        EndLine=0,
        StartColumn=0,
        EndColumn=0,
        Match=f"file detected: {file_path}",
        Fingerprint=f"{file_path}:pkcs12-file:0",
    )
    finding.update(changes)
    return finding


def _envelope(environment, stdout: bytes, *, return_code: int):
    envelope = environment.bridge(
        _Executor(
            _process_result(
                return_code=return_code,
                stdout=stdout,
                stderr=RAW_SECRET,
            )
        )
    ).start(environment.job).poll()
    assert envelope is not None
    return envelope


def _json_envelope(environment, findings, *, return_code: int = 1):
    return _envelope(
        environment,
        json.dumps(
            findings,
            ensure_ascii=False,
            allow_nan=True,
            separators=(",", ":"),
        ).encode("utf-8"),
        return_code=return_code,
    )


def _parse(tmp_path: Path, findings, *, return_code: int = 1):
    environment = _environment(tmp_path)
    envelope = _json_envelope(environment, findings, return_code=return_code)
    return (
        parse_gitleaks_execution_result(envelope, environment.projection),
        environment,
        envelope,
    )


def _path_case(
    tmp_path: Path,
    *,
    projected_file: str = "bundle.p12",
    finding_changes: dict | None = None,
    return_code: int = 1,
):
    environment = _environment(tmp_path)
    finding = _path_finding(projected_file)
    finding.update(finding_changes or {})
    envelope = _json_envelope(
        environment,
        [finding],
        return_code=return_code,
    )

    source_directory = environment.projection.source_directory
    source_mode = source_directory.stat().st_mode & 0o777
    target_parent = (source_directory / projected_file).parent
    target_parent_mode = target_parent.stat().st_mode & 0o777
    source_directory.chmod(0o700)
    target_parent.chmod(0o700)
    (source_directory / "app.py").rename(source_directory / projected_file)
    target_parent.chmod(target_parent_mode)
    source_directory.chmod(source_mode)

    entries = tuple(
        sorted(
            (
                replace(entry, relative_path=projected_file)
                if entry.relative_path == "app.py"
                else entry
                for entry in environment.projection.manifest.entries
            ),
            key=lambda entry: entry.relative_path,
        )
    )
    digest = repository_content_digest(entries)
    manifest = RepositoryManifest(
        entries=entries,
        file_count=len(entries),
        total_bytes=sum(entry.size_bytes for entry in entries),
        content_digest=digest,
    )
    projection = replace(
        environment.projection,
        manifest=manifest,
        projection_digest=digest,
    )
    return environment, projection, replace(envelope, projection_digest=digest)


def _assert_failure(
    tmp_path: Path,
    findings,
    expected: GitleaksParserFailureCode,
    *,
    return_code: int = 1,
) -> None:
    environment = _environment(tmp_path)
    envelope = _json_envelope(environment, findings, return_code=return_code)
    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, environment.projection)
    assert raised.value.code is expected
    assert RAW_SECRET.decode("ascii") not in str(raised.value)
    assert RAW_SECRET.decode("ascii") not in repr(raised.value)


def test_exit_zero_with_exact_empty_array_is_accepted(tmp_path: Path) -> None:
    result, _environment_value, _envelope_value = _parse(
        tmp_path,
        [],
        return_code=0,
    )

    assert result.schema_version == GITLEAKS_PARSER_SCHEMA_VERSION
    assert result.findings == ()
    assert result.finding_count == 0


def test_exit_one_with_valid_redacted_finding_is_accepted(tmp_path: Path) -> None:
    result, environment, envelope = _parse(tmp_path, [_finding()])

    assert result.scanner_id == "gitleaks"
    assert result.scanner_version == "8.30.1"
    assert result.binding_digest == envelope.binding_digest
    assert result.projection_id == environment.projection.projection_id
    assert result.finding_count == 1
    assert result.findings[0].rule_id == "github-pat"
    assert result.findings[0].file_path == "app.py"
    assert result.findings[0].detection_kind is GitleaksDetectionKind.CONTENT
    assert result.findings[0].start_line == 1
    assert result.findings[0].end_line == 1
    assert result.findings[0].start_column == 1
    assert result.findings[0].end_column == 5


def test_frozen_v8301_path_only_rule_set_is_complete() -> None:
    assert frozenset({"pkcs12-file"}) == GITLEAKS_V8301_PATH_ONLY_RULE_IDS


@pytest.mark.parametrize("file_path", ("bundle.p12", "nested/client.PFX"))
def test_manifest_authorized_pkcs12_paths_with_exact_zero_shape_are_accepted(
    tmp_path: Path,
    file_path: str,
) -> None:
    _environment_value, projection, envelope = _path_case(
        tmp_path,
        projected_file=file_path,
    )

    result = parse_gitleaks_execution_result(envelope, projection)

    finding = result.findings[0]
    assert finding.rule_id == "pkcs12-file"
    assert finding.file_path == file_path
    assert finding.detection_kind is GitleaksDetectionKind.PATH
    assert (
        finding.start_line,
        finding.end_line,
        finding.start_column,
        finding.end_column,
    ) == (None, None, None, None)


def test_path_detection_canonical_json_is_deterministic_and_null_located(
    tmp_path: Path,
) -> None:
    _environment_value, projection, envelope = _path_case(tmp_path)

    first = parse_gitleaks_execution_result(envelope, projection)
    second = parse_gitleaks_execution_result(envelope, projection)
    normalized = json.loads(first.canonical_json())["findings"][0]

    assert first == second
    assert first.canonical_json() == second.canonical_json()
    assert normalized["detection_kind"] == "PATH"
    assert normalized["start_line"] is None
    assert normalized["end_line"] is None
    assert normalized["start_column"] is None
    assert normalized["end_column"] is None


@pytest.mark.parametrize("rule_id", ("github-pat", "unknown-rule"))
def test_non_path_rules_with_zero_locations_are_rejected(
    tmp_path: Path,
    rule_id: str,
) -> None:
    _assert_failure(
        tmp_path,
        [_path_finding("app.py", RuleID=rule_id)],
        GitleaksParserFailureCode.LOCATION_INVALID,
    )


@pytest.mark.parametrize(
    "changes",
    (
        {"StartLine": 0, "EndLine": 0, "StartColumn": 0, "EndColumn": 1},
        {"StartLine": 0, "EndLine": 1, "StartColumn": 0, "EndColumn": 0},
        {"StartLine": 1, "EndLine": 1, "StartColumn": 1, "EndColumn": 1},
        {"StartLine": -1},
        {"StartLine": True},
        {"EndLine": False},
        {"StartColumn": -1},
    ),
)
def test_pkcs12_path_rule_rejects_non_exact_zero_location_shapes(
    tmp_path: Path,
    changes: dict,
) -> None:
    _environment_value, projection, envelope = _path_case(
        tmp_path,
        finding_changes=changes,
    )

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, projection)

    assert raised.value.code is GitleaksParserFailureCode.LOCATION_INVALID


@pytest.mark.parametrize("missing", ("EndLine", "StartColumn", "EndColumn"))
def test_pkcs12_path_rule_requires_all_four_zero_location_fields(
    tmp_path: Path,
    missing: str,
) -> None:
    _environment_value, projection, envelope = _path_case(tmp_path)
    document = json.loads(envelope.stdout_bytes)
    del document[0][missing]
    envelope = replace(
        envelope,
        stdout_bytes=json.dumps(document, separators=(",", ":")).encode(),
    )

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, projection)

    assert raised.value.code is GitleaksParserFailureCode.LOCATION_INVALID


def test_pkcs12_rule_rejects_a_nonmatching_manifest_path(tmp_path: Path) -> None:
    _assert_failure(
        tmp_path,
        [_path_finding("app.py")],
        GitleaksParserFailureCode.LOCATION_INVALID,
    )


@pytest.mark.parametrize("file_path", ("missing.p12", "../outside.p12"))
def test_pkcs12_rule_rejects_missing_or_escaping_paths(
    tmp_path: Path,
    file_path: str,
) -> None:
    _environment_value, projection, envelope = _path_case(
        tmp_path,
        finding_changes={"File": file_path},
    )

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, projection)

    assert raised.value.code is GitleaksParserFailureCode.PATH_INVALID


def test_pkcs12_rule_rejects_absolute_path_outside_projection(
    tmp_path: Path,
) -> None:
    _environment_value, projection, envelope = _path_case(
        tmp_path,
        finding_changes={"File": "/tmp/outside.p12"},
    )

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, projection)

    assert raised.value.code is GitleaksParserFailureCode.PATH_INVALID


def test_pkcs12_rule_rechecks_projected_file_content(tmp_path: Path) -> None:
    _environment_value, projection, envelope = _path_case(tmp_path)
    projected_file = projection.source_directory / "bundle.p12"
    projected_file.chmod(0o600)
    projected_file.write_bytes(b"mutated path finding content\n")

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, projection)

    assert raised.value.code is GitleaksParserFailureCode.PROJECTION_MISMATCH


def test_pkcs12_finding_under_exit_zero_is_contradictory(tmp_path: Path) -> None:
    _environment_value, projection, envelope = _path_case(
        tmp_path,
        return_code=0,
    )

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, projection)

    assert raised.value.code is GitleaksParserFailureCode.OUTPUT_CONTRADICTORY


def test_pkcs12_finding_still_requires_exact_secret_redaction(
    tmp_path: Path,
) -> None:
    _environment_value, projection, envelope = _path_case(
        tmp_path,
        finding_changes={"Secret": RAW_SECRET.decode("ascii")},
    )

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, projection)

    assert raised.value.code is GitleaksParserFailureCode.SECRET_NOT_REDACTED


@pytest.mark.parametrize("field", ("Link", "Fragment"))
def test_unreachable_dir_mode_finding_fields_remain_rejected(
    tmp_path: Path,
    field: str,
) -> None:
    _assert_failure(
        tmp_path,
        [_finding(**{field: "scanner-controlled"})],
        GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA,
    )


def test_exit_one_with_multiple_valid_findings_is_accepted(tmp_path: Path) -> None:
    result, _environment_value, _envelope_value = _parse(
        tmp_path,
        [_finding(), _finding(RuleID="generic-api-key")],
    )

    assert result.finding_count == 2
    assert tuple(finding.rule_id for finding in result.findings) == (
        "github-pat",
        "generic-api-key",
    )


def test_exit_one_with_empty_array_is_rejected(tmp_path: Path) -> None:
    _assert_failure(
        tmp_path,
        [],
        GitleaksParserFailureCode.OUTPUT_CONTRADICTORY,
    )


def test_exit_zero_with_findings_is_rejected(tmp_path: Path) -> None:
    _assert_failure(
        tmp_path,
        [_finding()],
        GitleaksParserFailureCode.OUTPUT_CONTRADICTORY,
        return_code=0,
    )


@pytest.mark.parametrize(
    ("payload", "expected"),
    (
        (b"{not-json", GitleaksParserFailureCode.OUTPUT_INVALID_JSON),
        (b"\xff", GitleaksParserFailureCode.OUTPUT_INVALID_UTF8),
        (b'{"root":"object"}', GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA),
        (b'"scalar"', GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA),
        (b"7", GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA),
        (b"null", GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA),
        (b"[7]", GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA),
        (b"[null]", GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA),
    ),
)
def test_malformed_utf8_and_non_finding_roots_fail_closed(
    tmp_path: Path,
    payload: bytes,
    expected: GitleaksParserFailureCode,
) -> None:
    environment = _environment(tmp_path)
    envelope = _envelope(environment, payload, return_code=1)

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, environment.projection)

    assert raised.value.code is expected


def test_duplicate_json_object_key_is_rejected(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    payload = (
        b'[{"RuleID":"github-pat","RuleID":"other",'
        b'"File":"app.py","StartLine":1}]'
    )
    envelope = _envelope(environment, payload, return_code=1)

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, environment.projection)

    assert raised.value.code is GitleaksParserFailureCode.OUTPUT_INVALID_JSON


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_non_finite_json_constants_are_rejected(
    tmp_path: Path,
    constant: str,
) -> None:
    environment = _environment(tmp_path)
    payload = json.dumps([_finding()]).replace("4.5", constant).encode("utf-8")
    envelope = _envelope(environment, payload, return_code=1)

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, environment.projection)

    assert raised.value.code is GitleaksParserFailureCode.OUTPUT_INVALID_JSON


def test_excessive_json_nesting_is_rejected(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    payload = ("[" * 34 + "]" * 34).encode("ascii")
    envelope = _envelope(environment, payload, return_code=1)

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, environment.projection)

    assert raised.value.code is GitleaksParserFailureCode.OUTPUT_INVALID_JSON


@pytest.mark.parametrize("missing", ("RuleID", "File", "StartLine"))
def test_required_fields_are_enforced(tmp_path: Path, missing: str) -> None:
    finding = _finding()
    del finding[missing]
    _assert_failure(
        tmp_path,
        [finding],
        GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA,
    )


def test_unknown_finding_field_is_rejected(tmp_path: Path) -> None:
    _assert_failure(
        tmp_path,
        [_finding(UnknownField="value")],
        GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA,
    )


@pytest.mark.parametrize(
    "secret",
    (RAW_SECRET.decode("ascii"), "redacted", "***", "", None, 7),
)
def test_secret_must_be_exact_observed_redaction(
    tmp_path: Path,
    secret: object,
) -> None:
    _assert_failure(
        tmp_path,
        [_finding(Secret=secret)],
        GitleaksParserFailureCode.SECRET_NOT_REDACTED,
    )


def test_secret_and_match_are_never_normalized_or_represented(tmp_path: Path) -> None:
    result, _environment_value, _envelope_value = _parse(tmp_path, [_finding()])
    serialized = repr(result) + str(result)

    assert RAW_SECRET.decode("ascii") not in serialized
    assert "REDACTED" not in serialized
    assert not hasattr(result.findings[0], "secret")
    assert not hasattr(result.findings[0], "match")
    assert not hasattr(result.findings[0], "description")
    assert not hasattr(result.findings[0], "tags")
    assert not hasattr(result.findings[0], "entropy")
    assert not hasattr(result.findings[0], "fingerprint")
    assert not hasattr(result.findings[0], "commit")
    assert not hasattr(result.findings[0], "author")
    assert not hasattr(result.findings[0], "email")
    assert not hasattr(result.findings[0], "message")


def test_match_is_type_checked_but_its_value_is_not_propagated(tmp_path: Path) -> None:
    _assert_failure(
        tmp_path,
        [_finding(Match=7)],
        GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA,
    )


def test_multiline_tabbed_gitleaks_match_is_validated_and_discarded(
    tmp_path: Path,
) -> None:
    match = "synthetic-prefix\r\n\tsynthetic-suffix"

    result, _environment_value, _envelope_value = _parse(
        tmp_path,
        [_finding(Match=match)],
    )

    assert result.finding_count == 1
    assert not hasattr(result.findings[0], "match")
    assert match not in repr(result)
    assert match.encode() not in result.canonical_json()


@pytest.mark.parametrize("control", ("\x00", "\x08", "\x0b", "\x0c", "\x7f"))
def test_non_layout_match_controls_remain_rejected(
    tmp_path: Path,
    control: str,
) -> None:
    _assert_failure(
        tmp_path,
        [_finding(Match=f"synthetic-prefix{control}synthetic-suffix")],
        GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA,
    )


@pytest.mark.parametrize(
    "file_path",
    (
        "/outside/app.py",
        "../app.py",
        "nested/../app.py",
        "app.py\x00suffix",
        "https://example.invalid/app.py",
        "file:///tmp/app.py",
        "missing.py",
        "nested\\settings.txt",
        "./app.py",
        "nested//settings.txt",
    ),
)
def test_untrusted_or_noncanonical_paths_are_rejected(
    tmp_path: Path,
    file_path: str,
) -> None:
    _assert_failure(
        tmp_path,
        [_finding(File=file_path)],
        GitleaksParserFailureCode.PATH_INVALID,
    )


def test_absolute_path_inside_trusted_projection_is_canonicalized(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    absolute = str(environment.projection.source_directory / "app.py")
    envelope = _json_envelope(environment, [_finding(File=absolute)])

    result = parse_gitleaks_execution_result(envelope, environment.projection)

    assert result.findings[0].file_path == "app.py"
    assert str(tmp_path) not in repr(result)


def test_selected_nested_projection_file_is_accepted(tmp_path: Path) -> None:
    finding = _finding(File="nested/settings.txt")
    del finding["StartColumn"]
    del finding["EndColumn"]
    result, _environment_value, _envelope_value = _parse(
        tmp_path,
        [finding],
    )

    assert result.findings[0].file_path == "nested/settings.txt"


@pytest.mark.parametrize("value", (True, False, 0, -1, 2_147_483_648, "1", None))
def test_invalid_start_lines_are_rejected(tmp_path: Path, value: object) -> None:
    _assert_failure(
        tmp_path,
        [_finding(StartLine=value)],
        GitleaksParserFailureCode.LOCATION_INVALID,
    )


def test_reversed_line_range_is_rejected(tmp_path: Path) -> None:
    _assert_failure(
        tmp_path,
        [_finding(StartLine=2, EndLine=1)],
        GitleaksParserFailureCode.LOCATION_INVALID,
    )


@pytest.mark.parametrize(
    ("start_line", "end_line", "start_column", "end_column"),
    (
        (235, 236, 46, 19),
        (37, 38, 41, 26),
    ),
)
def test_exact_gitleaks_multiline_locations_are_accepted_and_normalized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    start_line: int,
    end_line: int,
    start_column: int,
    end_column: int,
) -> None:
    app_content = (b"x" * 80 + b"\n") * 240
    monkeypatch.setattr(
        parser_module,
        "_read_verified_file",
        lambda _entry, _projection: app_content,
    )
    result, _environment_value, _envelope_value = _parse(
        tmp_path,
        [
            _finding(
                StartLine=start_line,
                EndLine=end_line,
                StartColumn=start_column,
                EndColumn=end_column,
                Match="synthetic-prefix\n\tsynthetic-suffix",
            )
        ],
    )

    finding = result.findings[0]
    assert (
        finding.start_line,
        finding.end_line,
        finding.start_column,
        finding.end_column,
    ) == (start_line, end_line, start_column, end_column)
    assert not hasattr(finding, "match")
    assert not hasattr(finding, "secret")
    assert b"synthetic-prefix" not in result.canonical_json()
    assert b"REDACTED" not in result.canonical_json()


def test_same_line_forward_columns_are_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_content = (b"x" * 20 + b"\n") * 10
    monkeypatch.setattr(
        parser_module,
        "_read_verified_file",
        lambda _entry, _projection: app_content,
    )
    result, _environment_value, _envelope_value = _parse(
        tmp_path,
        [
            _finding(
                StartLine=10,
                EndLine=10,
                StartColumn=5,
                EndColumn=9,
            )
        ],
    )

    assert result.findings[0].start_column == 5
    assert result.findings[0].end_column == 9


def test_same_line_reversed_columns_are_rejected(tmp_path: Path) -> None:
    _assert_failure(
        tmp_path,
        [
            _finding(
                StartLine=1,
                EndLine=1,
                StartColumn=9,
                EndColumn=5,
            )
        ],
        GitleaksParserFailureCode.LOCATION_INVALID,
    )


@pytest.mark.parametrize(
    "changes",
    (
        {"StartColumn": True, "EndColumn": 5},
        {"StartColumn": 1, "EndColumn": False},
        {"StartColumn": 0, "EndColumn": 5},
        {"StartColumn": -1, "EndColumn": 5},
        {"StartColumn": 1, "EndColumn": -1},
        {"StartColumn": 5, "EndColumn": 4},
        {"StartColumn": 999, "EndColumn": 999},
        {"StartColumn": 1},
        {"EndColumn": 5},
    ),
)
def test_invalid_columns_are_rejected(tmp_path: Path, changes: dict) -> None:
    finding = _finding()
    if set(changes) == {"StartColumn"}:
        del finding["EndColumn"]
    elif set(changes) == {"EndColumn"}:
        del finding["StartColumn"]
    finding.update(changes)
    _assert_failure(
        tmp_path,
        [finding],
        GitleaksParserFailureCode.LOCATION_INVALID,
    )


def test_line_beyond_verified_file_content_is_rejected(tmp_path: Path) -> None:
    _assert_failure(
        tmp_path,
        [_finding(StartLine=2, EndLine=2)],
        GitleaksParserFailureCode.LOCATION_INVALID,
    )


@pytest.mark.parametrize(
    "tags",
    (
        "github",
        [7],
        [""],
        ["unsafe\ncontrol"],
        ["x" * 257],
        ["tag"] * 65,
        None,
    ),
)
def test_malformed_tags_are_rejected(tmp_path: Path, tags: object) -> None:
    _assert_failure(
        tmp_path,
        [_finding(Tags=tags)],
        GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA,
    )


def test_empty_tags_are_valid_but_not_propagated(tmp_path: Path) -> None:
    result, _environment_value, _envelope_value = _parse(
        tmp_path,
        [_finding(Tags=[])],
    )

    assert result.finding_count == 1
    assert not hasattr(result.findings[0], "tags")


@pytest.mark.parametrize(
    "changes",
    (
        {"RuleID": "x" * 257},
        {"RuleID": "unsafe rule"},
        {"Description": "x" * 4097},
        {"Match": "x" * (64 * 1024 + 1)},
        {"Fingerprint": "x" * (64 * 1024 + 1)},
        {"Description": "unsafe\x00description"},
    ),
)
def test_oversized_or_unsafe_scanner_strings_are_rejected(
    tmp_path: Path,
    changes: dict,
) -> None:
    _assert_failure(
        tmp_path,
        [_finding(**changes)],
        GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA,
    )


@pytest.mark.parametrize("entropy", (True, False, -0.1, "4.5", None))
def test_invalid_entropy_metadata_is_rejected(
    tmp_path: Path,
    entropy: object,
) -> None:
    _assert_failure(
        tmp_path,
        [_finding(Entropy=entropy)],
        GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA,
    )


def test_duplicate_findings_are_preserved_without_deduplication(
    tmp_path: Path,
) -> None:
    finding = _finding()
    result, _environment_value, _envelope_value = _parse(
        tmp_path,
        [finding, finding],
    )

    assert result.finding_count == 2
    assert result.findings[0] == result.findings[1]


def test_parser_result_contains_no_raw_streams(tmp_path: Path) -> None:
    result, _environment_value, _envelope_value = _parse(tmp_path, [_finding()])
    canonical = result.canonical_json()

    assert not hasattr(result, "stdout")
    assert not hasattr(result, "stderr")
    assert not hasattr(result, "stdout_bytes")
    assert not hasattr(result, "stderr_bytes")
    assert RAW_SECRET not in canonical
    assert b"REDACTED" not in canonical
    assert json.loads(canonical)["finding_count"] == 1


@pytest.mark.parametrize(
    "result",
    (
        _process_result(return_code=2, stdout=RAW_SECRET, stderr=RAW_SECRET),
        _process_result(
            return_code=-15,
            stdout=RAW_SECRET,
            stderr=RAW_SECRET,
            timed_out=True,
            termination_requested=True,
        ),
        _process_result(
            return_code=-15,
            stdout=RAW_SECRET,
            stderr=RAW_SECRET,
            output_limit_exceeded=True,
            termination_requested=True,
        ),
        _process_result(
            return_code=-9,
            stdout=RAW_SECRET,
            stderr=RAW_SECRET,
            termination_requested=True,
            force_killed=True,
        ),
    ),
)
def test_incomplete_execution_results_cannot_be_parsed(
    tmp_path: Path,
    result,
) -> None:
    environment = _environment(tmp_path)
    envelope = environment.bridge(_Executor(result)).start(environment.job).poll()
    assert envelope is not None

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, environment.projection)

    assert raised.value.code is GitleaksParserFailureCode.EXECUTION_INCOMPLETE
    assert RAW_SECRET.decode("ascii") not in str(raised.value)


def test_cancelled_execution_result_cannot_be_parsed(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    process = _Handle(None)
    handle = environment.bridge(_Executor(scan_handle=process)).start(environment.job)
    handle.terminate()
    envelope = handle.poll()
    assert envelope is not None
    assert envelope.execution_status is GitleaksExecutionStatus.CANCELLED

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, environment.projection)

    assert raised.value.code is GitleaksParserFailureCode.EXECUTION_INCOMPLETE


def test_parser_errors_never_include_stdout_stderr_or_paths(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    envelope = _envelope(
        environment,
        b"[malformed-" + RAW_SECRET,
        return_code=1,
    )

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, environment.projection)

    error = f"{raised.value!r}\n{raised.value}"
    assert RAW_SECRET.decode("ascii") not in error
    assert str(tmp_path) not in error


def test_parser_rejects_projection_identity_mismatch(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    envelope = _json_envelope(environment, [_finding()])
    mismatched = replace(environment.projection, context_digest="c" * 64)

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, mismatched)

    assert raised.value.code is GitleaksParserFailureCode.PROJECTION_MISMATCH


def test_parser_rechecks_projected_file_content(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    envelope = _json_envelope(environment, [_finding()])
    projected_file = environment.projection.source_directory / "app.py"
    projected_file.chmod(0o600)
    projected_file.write_bytes(b"mutated\n")

    with pytest.raises(GitleaksParserError) as raised:
        parse_gitleaks_execution_result(envelope, environment.projection)

    assert raised.value.code is GitleaksParserFailureCode.PROJECTION_MISMATCH


def test_parser_is_deterministic_and_preserves_scanner_order(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    envelope = _json_envelope(
        environment,
        [_finding(RuleID="first-rule"), _finding(RuleID="second-rule")],
    )

    first = parse_gitleaks_execution_result(envelope, environment.projection)
    second = parse_gitleaks_execution_result(envelope, environment.projection)

    assert first == second
    assert tuple(finding.rule_id for finding in first.findings) == (
        "first-rule",
        "second-rule",
    )


def test_optional_gitleaks_fields_may_be_absent(tmp_path: Path) -> None:
    result, _environment_value, _envelope_value = _parse(
        tmp_path,
        [{"RuleID": "github-pat", "File": "app.py", "StartLine": 1}],
    )

    finding = result.findings[0]
    assert finding.end_line == 1
    assert finding.start_column is None
    assert finding.end_column is None


@pytest.mark.parametrize(
    "field",
    (
        "Description",
        "Match",
        "Author",
        "Commit",
        "Date",
        "Email",
        "Fingerprint",
        "Message",
        "SymlinkFile",
        "Tags",
        "Entropy",
    ),
)
def test_present_optional_fields_require_their_exact_type(
    tmp_path: Path,
    field: str,
) -> None:
    _assert_failure(
        tmp_path,
        [_finding(**{field: None})],
        GitleaksParserFailureCode.OUTPUT_INVALID_SCHEMA,
    )


def test_v04b_baseline_and_frozen_evidence_are_unchanged() -> None:
    root = Path(__file__).resolve().parents[1]
    tag_commit = subprocess.run(  # noqa: S603 - fixed local Git metadata query
        ["git", "rev-parse", "source-v0.4B-gitleaks-source-execution^{commit}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ancestry = subprocess.run(  # noqa: S603 - fixed local Git metadata query
        ["git", "merge-base", "--is-ancestor", tag_commit, "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    frozen_paths = (
        "benchmarks/gitleaks/gitleaks-binding-v1.json",
        "src/securescan/scanners/gitleaks/binding.py",
        "src/securescan/scanners/gitleaks/config",
        "src/securescan/scanners/gitleaks/source_execution.py",
        "src/securescan/scanners/semgrep/source_lifecycle.py",
        "tests/test_gitleaks_source_execution.py",
        "benchmarks/python_sast",
        "docs/python-sast-maturity-v1.md",
    )
    unchanged = subprocess.run(  # noqa: S603 - fixed local Git metadata query
        ["git", "diff", "--quiet", tag_commit, "--", *frozen_paths],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert tag_commit == GITLEAKS_V04B_BASELINE_COMMIT
    assert ancestry.returncode == 0
    assert unchanged.returncode == 0
