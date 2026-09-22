from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from securescan.cli.main import app
from securescan.config import Settings
from securescan.runtime_storage import (
    RuntimeStorageInitializationError,
    initialize_source_runtime_storage,
)
from securescan.source_runtime import SourceRuntimeError, create_source_runtime

_ROOT_MARKER = ".securescan-source-projection-root"
_ROOT_MARKER_CONTENT = b"securescan_source_projection_root_version=1\n"


def _settings(tmp_path: Path) -> Settings:
    root = tmp_path / "deployment"
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'runtime.db'}",
        deploy_data_root=root,
        runtime_uid=os.geteuid() if hasattr(os, "geteuid") else 1000,
        runtime_gid=os.getegid() if hasattr(os, "getegid") else 1000,
        artifact_root=root / "artifacts",
        source_workspace_root=root / "source-workspaces",
        source_projection_root=root / "source-projections",
        source_runtime_receipt_root=root / "source-runtime-receipts",
    )


def test_absent_runtime_roots_initialize_consistently_and_privately(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)

    initialized = initialize_source_runtime_storage(settings)

    assert initialized.deployment_root == settings.deploy_data_root
    for root in (
        initialized.deployment_root,
        initialized.artifact_root,
        initialized.workspace_root,
        initialized.projection_root,
        initialized.receipt_root,
    ):
        assert root is not None and root.is_dir() and not root.is_symlink()
        if os.name == "posix":
            assert stat.S_IMODE(root.stat(follow_symlinks=False).st_mode) == 0o700
    assert (initialized.projection_root / _ROOT_MARKER).read_bytes() == (_ROOT_MARKER_CONTENT)


def test_valid_initialized_roots_reopen_idempotently(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    first = initialize_source_runtime_storage(settings)
    identities = {
        path: (path.stat().st_dev, path.stat().st_ino)
        for path in (
            first.artifact_root,
            first.workspace_root,
            first.projection_root,
            first.receipt_root,
        )
    }

    second = initialize_source_runtime_storage(settings)

    assert second == first
    assert identities == {path: (path.stat().st_dev, path.stat().st_ino) for path in identities}


def test_explicit_initialization_marks_only_empty_private_projection_root(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o700)
    settings.source_projection_root.mkdir(mode=0o700)

    initialize_source_runtime_storage(settings)

    assert (settings.source_projection_root / _ROOT_MARKER).read_bytes() == (_ROOT_MARKER_CONTENT)


def test_unmarked_populated_projection_root_fails_closed_without_changes(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o700)
    settings.source_projection_root.mkdir(mode=0o700)
    unrelated = settings.source_projection_root / "unrelated"
    unrelated.write_bytes(b"preserve")

    with pytest.raises(RuntimeStorageInitializationError) as raised:
        initialize_source_runtime_storage(settings)

    assert raised.value.code == "PROJECTION_ROOT_OWNERSHIP_INVALID"
    assert unrelated.read_bytes() == b"preserve"
    assert not (settings.source_projection_root / _ROOT_MARKER).exists()


@pytest.mark.parametrize(
    "marker_content",
    (b"not-a-descriptor\n", b"securescan_source_projection_root_version=2\n"),
)
def test_malformed_or_contradictory_projection_descriptor_fails_closed(
    tmp_path: Path,
    marker_content: bytes,
) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o700)
    settings.source_projection_root.mkdir(mode=0o700)
    marker = settings.source_projection_root / _ROOT_MARKER
    marker.write_bytes(marker_content)
    marker.chmod(0o400)

    with pytest.raises(RuntimeStorageInitializationError) as raised:
        initialize_source_runtime_storage(settings)

    assert raised.value.code == "PROJECTION_ROOT_OWNERSHIP_INVALID"
    assert marker.read_bytes() == marker_content


def test_symlinked_runtime_path_fails_closed_without_touching_target(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    settings.artifact_root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeStorageInitializationError) as raised:
        initialize_source_runtime_storage(settings)

    assert raised.value.code == "RUNTIME_STORAGE_PATH_UNSAFE"
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions are required")
def test_wrong_runtime_root_permissions_are_actionable_and_not_repaired(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o755)
    settings.deploy_data_root.chmod(0o755)

    with pytest.raises(RuntimeStorageInitializationError) as raised:
        initialize_source_runtime_storage(settings)

    assert raised.value.code == "RUNTIME_STORAGE_OWNERSHIP_INVALID"
    assert raised.value.phase == "deployment_storage"
    assert stat.S_IMODE(settings.deploy_data_root.stat().st_mode) == 0o755


def test_mismatched_deployment_topology_refuses_before_creating_directories(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path).model_copy(
        update={"artifact_root": tmp_path / "different" / "artifacts"}
    )

    with pytest.raises(RuntimeStorageInitializationError) as raised:
        initialize_source_runtime_storage(settings)

    assert raised.value.code == "RUNTIME_STORAGE_CONFIGURATION_MISMATCH"
    assert not settings.deploy_data_root.exists()
    assert not settings.artifact_root.exists()


def test_initialization_does_not_alter_unrelated_sibling(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    sentinel = unrelated / "sentinel"
    sentinel.write_bytes(b"unchanged")
    before = unrelated.stat()

    initialize_source_runtime_storage(settings)

    after = unrelated.stat()
    assert sentinel.read_bytes() == b"unchanged"
    assert (after.st_dev, after.st_ino, after.st_mode) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    )


def test_cli_init_is_supported_and_machine_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr("securescan.cli.main.get_settings", lambda: settings)

    result = CliRunner().invoke(app, ["init", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "initialized"
    assert payload["deployment_root"] == str(settings.deploy_data_root)


def test_worker_reports_safe_actionable_projection_initialization_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail():
        raise SourceRuntimeError(
            "PROJECTION_ROOT_OWNERSHIP_INVALID",
            "Projection root ownership is invalid",
            phase="projection_storage",
            remediation="Run 'securescan init' with the worker configuration",
        )

    monkeypatch.setattr("securescan.cli.main.create_source_runtime", fail)

    result = CliRunner().invoke(app, ["worker", "--once"])

    assert result.exit_code == 5
    assert "Error [PROJECTION_ROOT_OWNERSHIP_INVALID]" in result.stderr
    assert "Phase: projection_storage" in result.stderr
    assert "Run 'securescan init'" in result.stderr
    assert "Traceback" not in result.stderr


def test_production_runtime_translates_uninitialized_projection_root(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path).model_copy(update={"deploy_data_root": None})
    settings.source_projection_root.mkdir(mode=0o700, parents=True)

    with pytest.raises(SourceRuntimeError) as raised, create_source_runtime(settings):
        pytest.fail("runtime opened an unmarked existing projection root")

    assert raised.value.code == "PROJECTION_ROOT_OWNERSHIP_INVALID"
    assert raised.value.phase == "projection_storage"
    assert "securescan init" in raised.value.remediation


def test_production_runtime_reports_database_connection_failure_actionably(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    initialize_source_runtime_storage(settings)

    class UnreachableEngine:
        def connect(self):
            raise OSError("test-only connection failure")

        def dispose(self) -> None:
            return

    monkeypatch.setattr(
        "securescan.source_runtime.create_session_factory",
        lambda _settings: (UnreachableEngine(), object()),
    )

    with pytest.raises(SourceRuntimeError) as raised, create_source_runtime(settings):
        pytest.fail("runtime opened an unreachable database")

    assert raised.value.code == "DATABASE_UNAVAILABLE"
    assert raised.value.phase == "database_connection"
    assert "test-only connection failure" not in str(raised.value)


def test_worker_initialization_error_preserves_machine_readable_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail():
        raise SourceRuntimeError(
            "ARTIFACT_ROOT_UNAVAILABLE",
            "Artifact root is unavailable",
            phase="artifact_storage",
            remediation="Run 'securescan init' with the worker configuration",
        )

    monkeypatch.setattr("securescan.cli.main.create_source_runtime", fail)

    result = CliRunner().invoke(app, ["worker", "--once", "--json"])

    assert result.exit_code == 5
    payload = json.loads(result.stderr)
    assert payload["error"]["code"] == "ARTIFACT_ROOT_UNAVAILABLE"
    assert payload["error"]["phase"] == "artifact_storage"
