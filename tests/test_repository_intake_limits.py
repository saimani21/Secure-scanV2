from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from securescan.workspaces.models import (
    PreparedRepositoryWorkspace,
    RepositoryIntakeLimits,
    RepositoryManifest,
    RepositoryManifestEntry,
    repository_content_digest,
)


def test_repository_intake_limits_are_immutable_and_secure() -> None:
    limits = RepositoryIntakeLimits()

    assert limits.max_file_count == 50_000
    assert limits.max_single_file_bytes == 33_554_432
    assert limits.max_total_bytes == 1_073_741_824
    assert limits.max_directory_depth == 64
    assert limits.max_relative_path_bytes == 4_096
    with pytest.raises(FrozenInstanceError):
        limits.max_file_count = 1  # type: ignore[misc]


def test_repository_intake_limits_reject_invalid_values() -> None:
    invalid_values = (
        {"max_file_count": 0},
        {"max_file_count": True},
        {"max_single_file_bytes": 1023},
        {"max_single_file_bytes": 256 * 1024 * 1024 + 1},
        {"max_total_bytes": 1024, "max_single_file_bytes": 2048},
        {"max_total_bytes": 16 * 1024**3 + 1},
        {"max_directory_depth": 0},
        {"max_directory_depth": 257},
        {"max_relative_path_bytes": 63},
        {"max_relative_path_bytes": 16_385},
    )

    for changes in invalid_values:
        with pytest.raises(ValueError, match="Repository intake limits are invalid"):
            RepositoryIntakeLimits(**changes)


def test_manifest_models_are_immutable_and_validate_consistency(tmp_path: Path) -> None:
    entry = RepositoryManifestEntry(
        relative_path="src/example.py",
        size_bytes=3,
        sha256="a" * 64,
    )
    entries = (entry,)
    manifest = RepositoryManifest(
        entries=entries,
        file_count=1,
        total_bytes=3,
        content_digest=repository_content_digest(entries),
    )
    workspace = PreparedRepositoryWorkspace(
        workspace_id="securescan-workspace-" + "b" * 16,
        root_directory=tmp_path / ("securescan-workspace-" + "b" * 16),
        source_directory=tmp_path / ("securescan-workspace-" + "b" * 16) / "source",
        output_directory=tmp_path / ("securescan-workspace-" + "b" * 16) / "output",
        manifest=manifest,
    )

    assert manifest.canonical_data()["entries"][0]["relative_path"] == "src/example.py"
    assert str(tmp_path) not in str(manifest.canonical_data())
    with pytest.raises(FrozenInstanceError):
        entry.size_bytes = 4  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        workspace.workspace_id = "changed"  # type: ignore[misc]
    for invalid_path in ("/absolute", "../escape", "a/../b", "bad\0name"):
        with pytest.raises(ValueError, match="Repository manifest entry is invalid"):
            RepositoryManifestEntry(invalid_path, 0, "a" * 64)
    with pytest.raises(ValueError, match="Repository manifest is invalid"):
        RepositoryManifest(entries, 2, 3, repository_content_digest(entries))
