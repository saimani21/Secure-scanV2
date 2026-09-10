from pathlib import Path

from securescan.config import Settings
from securescan.source import SourceProjectionManager
from securescan.workspaces import RepositoryWorkspaceManager


def test_default_settings_initialize_absolute_owned_projection_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SECURESCAN_SOURCE_PROJECTION_ROOT", raising=False)
    monkeypatch.delenv("SECURESCAN_SOURCE_WORKSPACE_ROOT", raising=False)

    settings = Settings(_env_file=None)
    manager = SourceProjectionManager(settings.source_projection_root)
    workspace_manager = RepositoryWorkspaceManager(settings.source_workspace_root)

    assert settings.source_projection_root == (
        tmp_path / "data" / "source-projections"
    )
    assert settings.source_projection_root.is_absolute()
    assert manager.base_directory == settings.source_projection_root
    assert settings.source_workspace_root == tmp_path / "data" / "source-workspaces"
    assert settings.source_workspace_root.is_absolute()
    assert workspace_manager.base_directory == settings.source_workspace_root
