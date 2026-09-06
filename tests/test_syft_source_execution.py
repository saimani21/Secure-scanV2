from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from securescan.execution import CancellableProcessResult
from securescan.scanners.syft import (
    SyftExecutionResultEnvelope,
    SyftExecutionStatus,
    SyftFailureCode,
    SyftParserError,
    TrustedSyftBinding,
    parse_syft_execution_result,
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


def _binding(tmp_path: Path) -> TrustedSyftBinding:
    executable = tmp_path / "syft"
    config = tmp_path / "securescan-syft-v1.yaml"
    return TrustedSyftBinding(
        executable_path=executable,
        executable_sha256=_write(executable, b"binary", 0o700),
        config_path=config,
        config_sha256=_write(config, b"config", 0o600),
    )


def _projection(tmp_path: Path) -> PreparedSourceProjection:
    projection_id = "securescan-source-projection-" + "2" * 32
    root = tmp_path / projection_id
    entry = RepositoryManifestEntry("a.txt", 1, hashlib.sha256(b"a").hexdigest())
    entries = (entry,)
    manifest = RepositoryManifest(entries, 1, 1, repository_content_digest(entries))
    return PreparedSourceProjection(
        projection_id=projection_id,
        root_directory=root,
        source_directory=root / "source",
        manifest=manifest,
        context_digest="c" * 64,
        projection_digest=manifest.content_digest,
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
        return_code=return_code,
        stdout=b"sensitive raw stdout",
        stderr=b"sensitive raw stderr",
        duration_ms=3,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        termination_requested=termination_requested,
        force_killed=force_killed,
    )


@pytest.mark.parametrize(
    ("result", "cancelled", "status", "failure"),
    [
        (_result(), False, SyftExecutionStatus.COMPLETED, None),
        (
            _result(return_code=2),
            False,
            SyftExecutionStatus.FAILED,
            SyftFailureCode.INVALID_EXIT_CODE,
        ),
        (
            _result(return_code=-15, timed_out=True, termination_requested=True),
            False,
            SyftExecutionStatus.TIMED_OUT,
            SyftFailureCode.TIMEOUT,
        ),
        (
            _result(return_code=-15, output_limit_exceeded=True, termination_requested=True),
            False,
            SyftExecutionStatus.OUTPUT_LIMIT_EXCEEDED,
            SyftFailureCode.OUTPUT_LIMIT,
        ),
        (
            _result(return_code=-15, termination_requested=True),
            True,
            SyftExecutionStatus.CANCELLED,
            SyftFailureCode.CANCELLED,
        ),
        (
            _result(return_code=-9, termination_requested=True, force_killed=True),
            False,
            SyftExecutionStatus.FAILED,
            SyftFailureCode.EXECUTION_FAILED,
        ),
    ],
)
def test_process_lifecycle_is_fail_closed(
    tmp_path: Path,
    result: CancellableProcessResult,
    cancelled: bool,
    status: SyftExecutionStatus,
    failure: SyftFailureCode | None,
) -> None:
    envelope = SyftExecutionResultEnvelope.from_process_result(
        result,
        binding=_binding(tmp_path),
        projection=_projection(tmp_path),
        cancellation_requested=cancelled,
    )
    assert envelope.execution_status is status
    assert envelope.failure_code is failure
    assert envelope.stdout_bytes == b"sensitive raw stdout"
    assert envelope.stderr_bytes == b"sensitive raw stderr"
    assert b"sensitive" not in repr(envelope).encode()


def test_failure_cannot_be_parsed_as_empty_inventory(tmp_path: Path) -> None:
    envelope = SyftExecutionResultEnvelope.from_process_result(
        _result(return_code=2),
        binding=_binding(tmp_path),
        projection=_projection(tmp_path),
        cancellation_requested=False,
    )
    with pytest.raises(SyftParserError):
        parse_syft_execution_result(envelope, _projection(tmp_path))
