from __future__ import annotations

from pathlib import Path

import pytest

from securescan.artifacts.store import ContentAddressedArtifactStore
from securescan.domain.enums import ArtifactKind, ExecutionOutcome


def test_content_addressed_store_is_deterministic(tmp_path: Path):
    store = ContentAddressedArtifactStore(tmp_path)
    first = store.put(b"same", kind=ArtifactKind.STDOUT, media_type="text/plain", sanitized=True)
    second = store.put(b"same", kind=ArtifactKind.STDOUT, media_type="text/plain", sanitized=True)
    assert first.sha256 == second.sha256
    assert first.storage_path == second.storage_path
    assert store.read(first) == b"same"


def test_artifact_tampering_is_detected(tmp_path: Path):
    store = ContentAddressedArtifactStore(tmp_path)
    record = store.put(
        b"original",
        kind=ArtifactKind.STDOUT,
        media_type="text/plain",
        sanitized=True,
    )
    (tmp_path / record.storage_path).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="digest mismatch"):
        store.read(record)


def test_test_secret_is_redacted_before_persistence(service, adapter, target):
    report = service.run(adapter, target, mode="secret")
    assert report.executions[0].outcome is ExecutionOutcome.SUCCEEDED_WITH_OBSERVATIONS
    execution = report.executions[0]
    assert execution.artifacts
    for artifact in execution.artifacts:
        data = service.artifact_store.read(artifact)
        assert b"abc123_SUPER_SECRET" not in data
        assert b"stderrSecret999" not in data
    assert "abc123_SUPER_SECRET" not in report.model_dump_json()
    assert "stderrSecret999" not in report.model_dump_json()
