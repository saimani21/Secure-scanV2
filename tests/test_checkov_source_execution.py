from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from securescan.execution import CancellableProcessResult
from securescan.scanners.checkov import (
    CheckovExecutionResultEnvelope,
    CheckovExecutionStatus,
    CheckovFailureCode,
    CheckovParserError,
    TrustedCheckovBinding,
    parse_checkov_execution_result,
)
from securescan.source.projection import PreparedSourceProjection
from securescan.workspaces.models import (
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)


def _write(path: Path, content: bytes, mode: int) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    return hashlib.sha256(content).hexdigest()


def _binding(tmp_path: Path) -> TrustedCheckovBinding:
    executable = tmp_path / "checkov"
    config = tmp_path / "securescan-checkov-v1.yaml"
    return TrustedCheckovBinding(
        executable,
        _write(executable, b"checkov", 0o700),
        config,
        _write(config, b"framework: [terraform]\n", 0o600),
    )


def _projection(tmp_path: Path) -> PreparedSourceProjection:
    projection_id = "securescan-source-projection-" + "4" * 32
    root = tmp_path / projection_id
    entry = RepositoryManifestEntry("main.tf", 1, hashlib.sha256(b"x").hexdigest())
    entries = (entry,)
    digest = repository_content_digest(entries)
    return PreparedSourceProjection(
        projection_id=projection_id,
        root_directory=root,
        source_directory=root / "source",
        manifest=RepositoryManifest(entries, 1, 1, digest),
        context_digest="c" * 64,
        projection_digest=digest,
    )


def _result(
    *,
    return_code: int = 0,
    timed_out: bool = False,
    output_limit_exceeded: bool = False,
    termination_requested: bool = False,
    force_killed: bool = False,
) -> CancellableProcessResult:
    return CancellableProcessResult(
        return_code,
        b"sensitive raw stdout",
        b"sensitive raw stderr",
        3,
        timed_out,
        output_limit_exceeded,
        termination_requested,
        force_killed,
    )


@pytest.mark.parametrize(
    ("result", "cancelled", "status", "failure"),
    [
        (_result(), False, CheckovExecutionStatus.COMPLETED, None),
        (
            _result(return_code=2),
            False,
            CheckovExecutionStatus.FAILED,
            CheckovFailureCode.PROCESS_FAILURE,
        ),
        (
            _result(return_code=-15, timed_out=True, termination_requested=True),
            False,
            CheckovExecutionStatus.TIMED_OUT,
            CheckovFailureCode.TIMEOUT,
        ),
        (
            _result(return_code=-15, output_limit_exceeded=True, termination_requested=True),
            False,
            CheckovExecutionStatus.OUTPUT_LIMIT_EXCEEDED,
            CheckovFailureCode.OUTPUT_LIMIT,
        ),
        (
            _result(return_code=-15, termination_requested=True),
            True,
            CheckovExecutionStatus.CANCELLED,
            CheckovFailureCode.CANCELLED,
        ),
    ],
)
def test_lifecycle_is_fail_closed_and_raw_streams_are_repr_safe(
    tmp_path: Path,
    result: CancellableProcessResult,
    cancelled: bool,
    status: CheckovExecutionStatus,
    failure: CheckovFailureCode | None,
) -> None:
    envelope = CheckovExecutionResultEnvelope.from_process_result(
        result,
        binding=_binding(tmp_path),
        projection=_projection(tmp_path),
        cancellation_requested=cancelled,
    )
    assert envelope.execution_status is status
    assert envelope.failure_code is failure
    assert envelope.stdout_bytes == b"sensitive raw stdout"
    assert envelope.stderr_bytes == b"sensitive raw stderr"
    assert "sensitive" not in repr(envelope)
    assert "sensitive" not in str(envelope)


def test_process_failure_cannot_be_parsed_as_clean(tmp_path: Path) -> None:
    envelope = CheckovExecutionResultEnvelope.from_process_result(
        _result(return_code=2),
        binding=_binding(tmp_path),
        projection=_projection(tmp_path),
        cancellation_requested=False,
    )
    with pytest.raises(CheckovParserError) as error:
        parse_checkov_execution_result(
            envelope,
            projection_root=tmp_path,
            authorized_paths=frozenset({"main.tf"}),
        )
    assert error.value.code is CheckovFailureCode.PROCESS_FAILURE
