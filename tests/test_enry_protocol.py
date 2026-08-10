from __future__ import annotations

import base64
import json
from dataclasses import FrozenInstanceError

import pytest

from securescan.source.enry_protocol import (
    ENRY_HELPER_VERSION,
    ENRY_LIBRARY_VERSION,
    ENRY_MAX_CONTENT_BYTES,
    ENRY_SCHEMA_VERSION,
    EnryClassification,
    EnryFileInput,
    EnryHelperRejectedRequestError,
    EnryProtocolError,
    InvalidEnryFileInputError,
    decode_enry_responses,
    encode_enry_requests,
)

_CORRELATIONS = (("file-00000000", "src/app.py"),)


def _response(**overrides: object) -> dict[str, object]:
    response: dict[str, object] = {
        "candidate_languages": ["Python"],
        "enry_version": ENRY_LIBRARY_VERSION,
        "helper_version": ENRY_HELPER_VERSION,
        "is_binary": False,
        "is_configuration": False,
        "is_documentation": False,
        "is_dot_file": False,
        "is_generated": False,
        "is_image": False,
        "is_test": False,
        "is_vendor": False,
        "language": "Python",
        "ok": True,
        "relative_path": "src/app.py",
        "request_id": "file-00000000",
        "schema_version": ENRY_SCHEMA_VERSION,
    }
    response.update(overrides)
    return response


def _output(**overrides: object) -> bytes:
    return (
        json.dumps(
            _response(**overrides),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _decode(output: bytes) -> tuple[EnryClassification, ...]:
    return decode_enry_responses(
        output,
        expected_correlations=_CORRELATIONS,
        expected_helper_version=ENRY_HELPER_VERSION,
        expected_enry_version=ENRY_LIBRARY_VERSION,
    )


def test_request_encoding_is_deterministic_canonical_and_correlated() -> None:
    files = (
        EnryFileInput("README.md", b"# Demo\n"),
        EnryFileInput("src/app.py", b"print('secret-value')\n"),
    )

    first_payload, first_correlations = encode_enry_requests(
        files,
        maximum_files=2,
        maximum_payload_bytes=4096,
    )
    second_payload, second_correlations = encode_enry_requests(
        files,
        maximum_files=2,
        maximum_payload_bytes=4096,
    )

    assert first_payload == second_payload
    assert first_correlations == second_correlations == (
        ("file-00000000", "README.md"),
        ("file-00000001", "src/app.py"),
    )
    lines = first_payload.splitlines()
    assert json.loads(lines[0]) == {
        "content_base64": base64.b64encode(b"# Demo\n").decode("ascii"),
        "relative_path": "README.md",
        "request_id": "file-00000000",
        "schema_version": ENRY_SCHEMA_VERSION,
    }
    assert first_payload.endswith(b"\n")
    assert not first_payload.endswith(b"\n\n")
    assert b"secret-value" not in first_payload


@pytest.mark.parametrize(
    "files",
    [
        (
            EnryFileInput("z.py", b""),
            EnryFileInput("a.py", b""),
        ),
        (
            EnryFileInput("a.py", b"first"),
            EnryFileInput("a.py", b"second"),
        ),
    ],
)
def test_request_encoding_rejects_unsorted_and_duplicate_paths(
    files: tuple[EnryFileInput, ...],
) -> None:
    with pytest.raises(EnryProtocolError):
        encode_enry_requests(
            files,
            maximum_files=10,
            maximum_payload_bytes=4096,
        )


def test_request_encoding_enforces_file_and_payload_limits() -> None:
    files = (EnryFileInput("src/app.py", b"content"),)
    oversized_batch = (
        EnryFileInput("src/app.py", b"content"),
        EnryFileInput("src/other.py", b"content"),
    )

    with pytest.raises(EnryProtocolError):
        encode_enry_requests(
            files,
            maximum_files=0,
            maximum_payload_bytes=4096,
        )
    with pytest.raises(EnryProtocolError):
        encode_enry_requests(
            oversized_batch,
            maximum_files=1,
            maximum_payload_bytes=4096,
        )
    with pytest.raises(EnryProtocolError):
        encode_enry_requests(
            files,
            maximum_files=1,
            maximum_payload_bytes=1,
        )


@pytest.mark.parametrize(
    "relative_path",
    [
        "/absolute.py",
        "../escape.py",
        "src/../escape.py",
        "src\\app.py",
        "src//app.py",
        "src/\x00app.py",
        "src/control\u0085name.py",
        "src/\ud800.py",
        f"{'a' * 4094}.py",
    ],
)
def test_file_input_rejects_noncanonical_paths(relative_path: str) -> None:
    with pytest.raises(InvalidEnryFileInputError):
        EnryFileInput(relative_path, b"")


def test_file_input_rejects_mutable_and_oversized_content() -> None:
    with pytest.raises(InvalidEnryFileInputError):
        EnryFileInput("src/app.py", bytearray(b"mutable"))  # type: ignore[arg-type]
    with pytest.raises(InvalidEnryFileInputError):
        EnryFileInput("src/app.py", b"x" * (ENRY_MAX_CONTENT_BYTES + 1))

    valid = EnryFileInput("src/app.py", b"")
    with pytest.raises(FrozenInstanceError):
        valid.content = b"changed"  # type: ignore[misc]


def test_successful_response_parsing_is_immutable() -> None:
    classification = _decode(_output())[0]

    assert classification == EnryClassification(
        relative_path="src/app.py",
        language="Python",
        candidate_languages=("Python",),
        is_binary=False,
        is_vendor=False,
        is_generated=False,
        is_test=False,
        is_configuration=False,
        is_documentation=False,
        is_dot_file=False,
        is_image=False,
    )
    with pytest.raises(FrozenInstanceError):
        classification.language = "Go"  # type: ignore[misc]


def test_empty_language_normalizes_to_none() -> None:
    classification = _decode(_output(language="", candidate_languages=[]))[0]

    assert classification.language is None
    assert classification.candidate_languages == ()


def test_binary_response_requires_no_language_or_candidates() -> None:
    classification = _decode(
        _output(language="", candidate_languages=[], is_binary=True)
    )[0]

    assert classification.is_binary is True
    assert classification.language is None
    assert classification.candidate_languages == ()

    with pytest.raises(EnryProtocolError):
        _decode(_output(is_binary=True))


def test_duplicate_json_key_is_rejected() -> None:
    output = _output().replace(
        b'"ok":true',
        b'"ok":true,"ok":true',
    )

    with pytest.raises(EnryProtocolError):
        _decode(output)


def test_unknown_and_missing_fields_are_rejected() -> None:
    unknown = _response(unexpected=True)
    missing = _response()
    del missing["language"]

    for response in (unknown, missing):
        output = json.dumps(response, separators=(",", ":")).encode("ascii") + b"\n"
        with pytest.raises(EnryProtocolError):
            _decode(output)


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
def test_nonstandard_json_constants_are_rejected(constant: bytes) -> None:
    output = _output().replace(b'"language":"Python"', b'"language":' + constant)

    with pytest.raises(EnryProtocolError):
        _decode(output)


def test_non_utf8_output_is_rejected() -> None:
    with pytest.raises(EnryProtocolError):
        _decode(b"\xff\n")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "9.9.9"),
        ("helper_version", "9.9.9"),
        ("enry_version", "v9.9.9"),
    ],
)
def test_version_mismatches_are_rejected(field: str, value: str) -> None:
    with pytest.raises(EnryProtocolError):
        _decode(_output(**{field: value}))


def test_response_count_and_blank_lines_are_rejected() -> None:
    for output in (b"", _output() + _output(), _output() + b"\n"):
        with pytest.raises(EnryProtocolError):
            _decode(output)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", "file-99999999"),
        ("relative_path", "src/other.py"),
    ],
)
def test_response_correlation_mismatches_are_rejected(
    field: str,
    value: str,
) -> None:
    with pytest.raises(EnryProtocolError):
        _decode(_output(**{field: value}))


@pytest.mark.parametrize(
    "candidates",
    [
        ["Python", "Go"],
        ["Python", "Python"],
        ["Python", ""],
        ["Py\u0085thon"],
    ],
)
def test_noncanonical_candidates_are_rejected(candidates: list[str]) -> None:
    with pytest.raises(EnryProtocolError):
        _decode(_output(candidate_languages=candidates))


def test_primary_language_must_occur_in_candidates() -> None:
    with pytest.raises(EnryProtocolError):
        _decode(_output(candidate_languages=["Go"]))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ok", 1),
        ("is_binary", 0),
        ("candidate_languages", "Python"),
    ],
)
def test_response_requires_exact_json_types(field: str, value: object) -> None:
    with pytest.raises(EnryProtocolError):
        _decode(_output(**{field: value}))


def test_helper_rejection_is_explicit_and_sanitized() -> None:
    output = _output(
        ok=False,
        error_code="INVALID_CONTENT",
        language="",
        candidate_languages=[],
    )

    with pytest.raises(EnryHelperRejectedRequestError) as raised:
        _decode(output)

    assert str(raised.value) == "Enry helper rejected a request"
    assert "INVALID_CONTENT" not in str(raised.value)


def test_helper_rejection_still_requires_valid_classification_fields() -> None:
    output = _output(
        ok=False,
        error_code="INVALID_CONTENT",
        language="Python",
        candidate_languages=["Python", "Python"],
    )

    with pytest.raises(EnryProtocolError) as raised:
        _decode(output)

    assert not isinstance(raised.value, EnryHelperRejectedRequestError)


def test_sensitive_protocol_data_never_appears_in_errors() -> None:
    sensitive = "sensitive-content-value"
    output = _output(relative_path=sensitive)

    with pytest.raises(EnryProtocolError) as raised:
        _decode(output)

    assert sensitive not in str(raised.value)
    assert str(raised.value) == "Enry protocol data is invalid"
