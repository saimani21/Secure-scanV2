from __future__ import annotations

import base64
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import NoReturn

ENRY_SCHEMA_VERSION = "1.0.0"
ENRY_HELPER_VERSION = "0.2.3"
ENRY_LIBRARY_VERSION = "v2.9.6"
ENRY_MAX_CONTENT_BYTES = 1024 * 1024

_MAX_RELATIVE_PATH_BYTES = 4096
_ERROR_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z", re.ASCII)
_COMMON_RESPONSE_FIELDS = frozenset(
    {
        "candidate_languages",
        "enry_version",
        "helper_version",
        "is_binary",
        "is_configuration",
        "is_documentation",
        "is_dot_file",
        "is_generated",
        "is_image",
        "is_test",
        "is_vendor",
        "language",
        "ok",
        "relative_path",
        "request_id",
        "schema_version",
    }
)
_ALL_RESPONSE_FIELDS = _COMMON_RESPONSE_FIELDS | {"error_code"}
_FLAG_FIELDS = (
    "is_binary",
    "is_vendor",
    "is_generated",
    "is_test",
    "is_configuration",
    "is_documentation",
    "is_dot_file",
    "is_image",
)


def _is_control_character(character: str) -> bool:
    return unicodedata.category(character) == "Cc"


class EnryProtocolError(RuntimeError):
    """Raised when Enry protocol data violates the trusted schema."""

    def __init__(self) -> None:
        super().__init__("Enry protocol data is invalid")


class InvalidEnryFileInputError(EnryProtocolError, ValueError):
    """Raised when a file cannot be represented by the Enry protocol."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Enry file input is invalid")


class EnryHelperRejectedRequestError(EnryProtocolError):
    """Raised when the trusted helper explicitly rejects a request."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "Enry helper rejected a request")


class _InvalidJSONError(ValueError):
    pass


def _valid_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    if any(_is_control_character(character) for character in value):
        return False
    try:
        path_bytes = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(path_bytes) > _MAX_RELATIVE_PATH_BYTES:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(component not in {"", ".", ".."} for component in path.parts)
    )


def _valid_clean_string(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if any(_is_control_character(character) for character in value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class EnryFileInput:
    relative_path: str
    content: bytes

    def __post_init__(self) -> None:
        if (
            not _valid_relative_path(self.relative_path)
            or not isinstance(self.content, bytes)
            or len(self.content) > ENRY_MAX_CONTENT_BYTES
        ):
            raise InvalidEnryFileInputError


@dataclass(frozen=True, slots=True)
class EnryClassification:
    relative_path: str
    language: str | None
    candidate_languages: tuple[str, ...]
    is_binary: bool
    is_vendor: bool
    is_generated: bool
    is_test: bool
    is_configuration: bool
    is_documentation: bool
    is_dot_file: bool
    is_image: bool

    def __post_init__(self) -> None:
        flags = (
            self.is_binary,
            self.is_vendor,
            self.is_generated,
            self.is_test,
            self.is_configuration,
            self.is_documentation,
            self.is_dot_file,
            self.is_image,
        )
        if (
            not _valid_relative_path(self.relative_path)
            or not isinstance(self.candidate_languages, tuple)
            or any(not _valid_clean_string(item) for item in self.candidate_languages)
            or self.candidate_languages != tuple(sorted(self.candidate_languages))
            or len(set(self.candidate_languages)) != len(self.candidate_languages)
            or (
                self.language is not None
                and (
                    not _valid_clean_string(self.language)
                    or self.language not in self.candidate_languages
                )
            )
            or any(type(flag) is not bool for flag in flags)
            or (
                self.is_binary
                and (self.language is not None or bool(self.candidate_languages))
            )
        ):
            raise EnryProtocolError


def _validate_request_collection(
    files: tuple[EnryFileInput, ...],
    *,
    allow_empty: bool,
    maximum_files: int,
    maximum_payload_bytes: int,
) -> None:
    if (
        not isinstance(files, tuple)
        or (not allow_empty and not files)
        or any(not isinstance(file, EnryFileInput) for file in files)
        or type(maximum_files) is not int
        or maximum_files < 1
        or type(maximum_payload_bytes) is not int
        or maximum_payload_bytes < 1
    ):
        raise EnryProtocolError

    paths = tuple(file.relative_path for file in files)
    if paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
        raise EnryProtocolError


def _encode_request_line(file: EnryFileInput, index: int) -> bytes:
    return json.dumps(
        {
            "content_base64": base64.b64encode(file.content).decode("ascii"),
            "relative_path": file.relative_path,
            "request_id": f"file-{index:08d}",
            "schema_version": ENRY_SCHEMA_VERSION,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def encode_enry_requests(
    files: tuple[EnryFileInput, ...],
    *,
    maximum_files: int,
    maximum_payload_bytes: int,
) -> tuple[bytes, tuple[tuple[str, str], ...]]:
    _validate_request_collection(
        files,
        allow_empty=False,
        maximum_files=maximum_files,
        maximum_payload_bytes=maximum_payload_bytes,
    )
    if len(files) > maximum_files:
        raise EnryProtocolError

    lines: list[bytes] = []
    correlations: list[tuple[str, str]] = []
    payload_size = 0
    for index, file in enumerate(files):
        request_id = f"file-{index:08d}"
        encoded = _encode_request_line(file, index)
        payload_size += len(encoded) + 1
        if payload_size > maximum_payload_bytes:
            raise EnryProtocolError
        lines.append(encoded)
        correlations.append((request_id, file.relative_path))

    return b"\n".join(lines) + b"\n", tuple(correlations)


def partition_enry_requests(
    files: tuple[EnryFileInput, ...],
    *,
    maximum_files: int,
    maximum_payload_bytes: int,
) -> tuple[tuple[EnryFileInput, ...], ...]:
    _validate_request_collection(
        files,
        allow_empty=True,
        maximum_files=maximum_files,
        maximum_payload_bytes=maximum_payload_bytes,
    )
    if not files:
        return ()

    batches: list[tuple[EnryFileInput, ...]] = []
    current: list[EnryFileInput] = []
    current_payload_bytes = 0

    for file in files:
        encoded_line = _encode_request_line(file, len(current))
        encoded_size = len(encoded_line) + 1
        if current and (
            len(current) >= maximum_files
            or current_payload_bytes + encoded_size > maximum_payload_bytes
        ):
            batches.append(tuple(current))
            current = []
            current_payload_bytes = 0
            encoded_line = _encode_request_line(file, 0)
            encoded_size = len(encoded_line) + 1

        if encoded_size > maximum_payload_bytes:
            raise EnryProtocolError
        current.append(file)
        current_payload_bytes += encoded_size

    if current:
        batches.append(tuple(current))
    return tuple(batches)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidJSONError
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    raise _InvalidJSONError


def _decode_object(line: str) -> dict[str, object]:
    try:
        value = json.loads(
            line,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, _InvalidJSONError, TypeError, ValueError):
        raise EnryProtocolError from None
    if not isinstance(value, dict):
        raise EnryProtocolError
    return value


def _valid_correlations(value: object) -> bool:
    if not isinstance(value, tuple) or not value:
        return False
    request_ids: list[str] = []
    paths: list[str] = []
    for item in value:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not _valid_clean_string(item[0])
            or not _valid_relative_path(item[1])
        ):
            return False
        request_ids.append(item[0])
        paths.append(item[1])
    return len(set(request_ids)) == len(request_ids) and len(set(paths)) == len(paths)


def _decode_classification(
    response: dict[str, object],
    *,
    expected_request_id: str,
    expected_relative_path: str,
    expected_helper_version: str,
    expected_enry_version: str,
) -> EnryClassification:
    fields = frozenset(response)
    if not fields >= _COMMON_RESPONSE_FIELDS or fields - _ALL_RESPONSE_FIELDS:
        raise EnryProtocolError
    if (
        response["schema_version"] != ENRY_SCHEMA_VERSION
        or response["helper_version"] != expected_helper_version
        or response["enry_version"] != expected_enry_version
        or response["request_id"] != expected_request_id
        or response["relative_path"] != expected_relative_path
        or type(response["ok"]) is not bool
        or any(type(response[field]) is not bool for field in _FLAG_FIELDS)
    ):
        raise EnryProtocolError

    raw_language = response["language"]
    if not isinstance(raw_language, str):
        raise EnryProtocolError
    language = raw_language or None
    if language is not None and not _valid_clean_string(language):
        raise EnryProtocolError

    raw_candidates = response["candidate_languages"]
    if not isinstance(raw_candidates, list) or any(
        not _valid_clean_string(candidate) for candidate in raw_candidates
    ):
        raise EnryProtocolError
    candidates = tuple(raw_candidates)

    classification = EnryClassification(
        relative_path=expected_relative_path,
        language=language,
        candidate_languages=candidates,
        is_binary=response["is_binary"],
        is_vendor=response["is_vendor"],
        is_generated=response["is_generated"],
        is_test=response["is_test"],
        is_configuration=response["is_configuration"],
        is_documentation=response["is_documentation"],
        is_dot_file=response["is_dot_file"],
        is_image=response["is_image"],
    )
    if response["ok"] is False:
        error_code = response.get("error_code")
        if (
            not isinstance(error_code, str)
            or _ERROR_CODE_PATTERN.fullmatch(error_code) is None
        ):
            raise EnryProtocolError
        raise EnryHelperRejectedRequestError
    if "error_code" in response and response["error_code"] != "":
        raise EnryProtocolError

    return classification


def decode_enry_responses(
    output: bytes,
    *,
    expected_correlations: tuple[tuple[str, str], ...],
    expected_helper_version: str,
    expected_enry_version: str,
) -> tuple[EnryClassification, ...]:
    if (
        not isinstance(output, bytes)
        or not output
        or not _valid_correlations(expected_correlations)
        or not _valid_clean_string(expected_helper_version)
        or not _valid_clean_string(expected_enry_version)
    ):
        raise EnryProtocolError
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EnryProtocolError from None

    lines = text.splitlines()
    if (
        not lines
        or any(not line for line in lines)
        or len(lines) != len(expected_correlations)
    ):
        raise EnryProtocolError

    classifications: list[EnryClassification] = []
    for line, (request_id, relative_path) in zip(
        lines,
        expected_correlations,
        strict=True,
    ):
        response = _decode_object(line)
        classifications.append(
            _decode_classification(
                response,
                expected_request_id=request_id,
                expected_relative_path=relative_path,
                expected_helper_version=expected_helper_version,
                expected_enry_version=expected_enry_version,
            )
        )
    return tuple(classifications)
