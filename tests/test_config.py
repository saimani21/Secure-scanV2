from pathlib import Path

from securescan.config import Settings
from securescan.source import SourceProjectionManager
from securescan.workspaces import RepositoryWorkspaceManager

_MUTABLE_DATA_ENVIRONMENT = (
    "SECURESCAN_DATABASE_URL",
    "SECURESCAN_ARTIFACT_ROOT",
    "SECURESCAN_SOURCE_PROJECTION_ROOT",
    "SECURESCAN_SOURCE_WORKSPACE_ROOT",
    "SECURESCAN_SOURCE_RUNTIME_RECEIPT_ROOT",
)


def _clear_mutable_data_environment(monkeypatch) -> None:
    for name in _MUTABLE_DATA_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)


def _assert_default_locations(settings: Settings, expected_root: Path) -> None:
    assert settings.database_url == (
        f"sqlite:///{(expected_root / 'securescan.db').as_posix()}"
    )
    assert settings.artifact_root == expected_root / "artifacts"
    assert settings.source_projection_root == expected_root / "source-projections"
    assert settings.source_workspace_root == expected_root / "source-workspaces"
    assert settings.source_runtime_receipt_root == (
        expected_root / "source-runtime-receipts"
    )
    assert all(
        path.is_absolute()
        for path in (
            settings.artifact_root,
            settings.source_projection_root,
            settings.source_workspace_root,
            settings.source_runtime_receipt_root,
        )
    )


def test_default_mutable_data_locations_are_user_scoped_and_cwd_independent(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    first_cwd = tmp_path / "first"
    second_cwd = tmp_path / "second"
    first_cwd.mkdir()
    second_cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    _clear_mutable_data_environment(monkeypatch)

    monkeypatch.chdir(first_cwd)
    first = Settings(_env_file=None)
    monkeypatch.chdir(second_cwd)
    second = Settings(_env_file=None)

    expected_root = (home / ".local" / "share" / "securescan").resolve()
    _assert_default_locations(first, expected_root)
    _assert_default_locations(second, expected_root)
    assert first.database_url == second.database_url
    assert first.artifact_root == second.artifact_root

    manager = SourceProjectionManager.initialize_base_directory(
        first.source_projection_root
    )
    workspace_manager = RepositoryWorkspaceManager(first.source_workspace_root)
    assert manager.base_directory == first.source_projection_root
    assert workspace_manager.base_directory == first.source_workspace_root


def test_absolute_xdg_data_home_is_authoritative(
    tmp_path: Path, monkeypatch
) -> None:
    xdg_data_home = tmp_path / "xdg-data"
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_data_home))
    _clear_mutable_data_environment(monkeypatch)

    settings = Settings(_env_file=None)

    _assert_default_locations(settings, (xdg_data_home / "securescan").resolve())


def test_relative_xdg_data_home_cannot_create_cwd_relative_defaults(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    working_directory = tmp_path / "repository"
    working_directory.mkdir()
    monkeypatch.chdir(working_directory)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", "relative-data")
    _clear_mutable_data_environment(monkeypatch)

    settings = Settings(_env_file=None)

    expected_root = (home / ".local" / "share" / "securescan").resolve()
    _assert_default_locations(settings, expected_root)
    assert working_directory not in settings.artifact_root.parents


def test_explicit_mutable_data_path_overrides_remain_authoritative(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    working_directory = tmp_path / "repository"
    working_directory.mkdir()
    monkeypatch.chdir(working_directory)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SECURESCAN_ARTIFACT_ROOT", "runtime/artifacts")
    monkeypatch.setenv("SECURESCAN_SOURCE_PROJECTION_ROOT", "~/projections")
    monkeypatch.setenv("SECURESCAN_SOURCE_WORKSPACE_ROOT", "runtime/workspaces")
    monkeypatch.setenv(
        "SECURESCAN_SOURCE_RUNTIME_RECEIPT_ROOT", "runtime/receipts"
    )

    settings = Settings(_env_file=None)

    assert settings.artifact_root == (working_directory / "runtime/artifacts").resolve()
    assert settings.source_projection_root == (home / "projections").resolve()
    assert settings.source_workspace_root == (
        working_directory / "runtime/workspaces"
    ).resolve()
    assert settings.source_runtime_receipt_root == (
        working_directory / "runtime/receipts"
    ).resolve()
    assert all(
        path.is_absolute()
        for path in (
            settings.artifact_root,
            settings.source_projection_root,
            settings.source_workspace_root,
            settings.source_runtime_receipt_root,
        )
    )
