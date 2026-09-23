import json
import os
import stat
from pathlib import Path

import pytest

from securescan.config import Settings, get_operator_settings
from securescan.operator.profile import (
    OperatorProfileError,
    parse_operator_env_file,
    write_operator_profile,
)


def test_profile_is_private_and_supplies_fresh_shell_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "config" / "operator.json"
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))
    monkeypatch.delenv("SECURESCAN_API_PORT", raising=False)
    write_operator_profile({"api_port": 18000, "postgres_password": "not-printed"})

    settings = Settings(_env_file=None)

    assert settings.api_port == 18000
    assert stat.S_IMODE(profile.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(profile.stat().st_mode) == 0o600


def test_environment_has_priority_over_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "operator.json"
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))
    write_operator_profile({"api_port": 18000})
    monkeypatch.setenv("SECURESCAN_API_PORT", "19000")

    assert Settings(_env_file=None).api_port == 19000


def test_operator_settings_ignore_unrelated_cwd_dotenv_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "config" / "operator.json"
    first = tmp_path / "project-a"
    second = tmp_path / "project-b"
    first.mkdir()
    second.mkdir()
    (first / ".env").write_text(
        "SECURESCAN_API_PORT=19001\n"
        "SECURESCAN_OPERATOR_COMPOSE_PROJECT=malicious-a\n",
        encoding="utf-8",
    )
    (second / ".env").write_text(
        "SECURESCAN_API_PORT=19002\n"
        "SECURESCAN_OPERATOR_COMPOSE_PROJECT=malicious-b\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))
    monkeypatch.delenv("SECURESCAN_API_PORT", raising=False)
    monkeypatch.delenv("SECURESCAN_OPERATOR_COMPOSE_PROJECT", raising=False)
    write_operator_profile(
        {"api_port": 18002, "operator_compose_project": "deployment-a"}
    )

    monkeypatch.chdir(first)
    get_operator_settings.cache_clear()
    first_settings = get_operator_settings()
    monkeypatch.chdir(second)
    get_operator_settings.cache_clear()
    second_settings = get_operator_settings()

    assert first_settings.api_port == second_settings.api_port == 18002
    assert (
        first_settings.operator_compose_project
        == second_settings.operator_compose_project
        == "deployment-a"
    )
    get_operator_settings.cache_clear()


def test_legacy_settings_retain_cwd_dotenv_compatibility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "legacy"
    project.mkdir()
    (project / ".env").write_text("SECURESCAN_API_PORT=19001\n", encoding="utf-8")
    monkeypatch.chdir(project)
    monkeypatch.delenv("SECURESCAN_API_PORT", raising=False)
    monkeypatch.setenv(
        "SECURESCAN_OPERATOR_PROFILE", str(tmp_path / "missing-operator.json")
    )

    assert Settings().api_port == 19001


def test_operator_environment_still_overrides_profile_from_any_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "config" / "operator.json"
    cwd = tmp_path / "project"
    cwd.mkdir()
    (cwd / ".env").write_text("SECURESCAN_API_PORT=19001\n", encoding="utf-8")
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))
    write_operator_profile({"api_port": 18002})
    monkeypatch.setenv("SECURESCAN_API_PORT", "18003")
    monkeypatch.chdir(cwd)
    get_operator_settings.cache_clear()

    assert get_operator_settings().api_port == 18003
    get_operator_settings.cache_clear()


def test_unsafe_profile_permissions_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "config" / "operator.json"
    profile.parent.mkdir(mode=0o700)
    profile.write_text('{"profile_version":1,"settings":{}}', encoding="utf-8")
    profile.chmod(0o644)
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))

    with pytest.raises(OperatorProfileError):
        Settings(_env_file=None)


def test_symlinked_profile_and_parent_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir(mode=0o700)
    real_profile = real_directory / "operator.json"
    write_target = tmp_path / "profile-link.json"
    real_profile.write_text('{"profile_version":1,"settings":{}}', encoding="utf-8")
    real_profile.chmod(0o600)
    write_target.symlink_to(real_profile)
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(write_target))
    with pytest.raises(OperatorProfileError, match="permissions are unsafe"):
        Settings(_env_file=None)

    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_directory, target_is_directory=True)
    monkeypatch.setenv(
        "SECURESCAN_OPERATOR_PROFILE", str(linked_parent / "new-operator.json")
    )
    with pytest.raises(OperatorProfileError, match="directory permissions are unsafe"):
        write_operator_profile({"api_port": 18002})
    assert not (real_directory / "new-operator.json").exists()


def test_wrong_owner_simulation_fails_before_profile_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "config" / "operator.json"
    profile.parent.mkdir(mode=0o700)
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))
    actual_uid = os.geteuid()
    monkeypatch.setattr(
        "securescan.operator.profile.os.geteuid", lambda: actual_uid + 1
    )

    with pytest.raises(OperatorProfileError, match="directory permissions are unsafe"):
        write_operator_profile({"api_port": 18002})
    assert not profile.exists()


def test_controlled_env_parser_never_accepts_shell_export(tmp_path: Path) -> None:
    source = tmp_path / "operator.env"
    source.write_text("export SECURESCAN_API_PORT=18000\n", encoding="utf-8")

    with pytest.raises(OperatorProfileError, match="KEY=VALUE"):
        parse_operator_env_file(source)


def test_controlled_env_parser_rejects_duplicate_settings(tmp_path: Path) -> None:
    source = tmp_path / "operator.env"
    source.write_text(
        "SECURESCAN_API_PORT=18000\nSECURESCAN_API_PORT=18001\n",
        encoding="utf-8",
    )

    with pytest.raises(OperatorProfileError, match="duplicates"):
        parse_operator_env_file(source)


def test_profile_json_is_deterministic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = tmp_path / "config" / "operator.json"
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))
    write_operator_profile({"postgres_password": "secret", "api_port": 18000})

    assert json.loads(profile.read_text()) == {
        "profile_version": 1,
        "settings": {"api_port": 18000, "postgres_password": "secret"},
    }
    assert "secret" not in str(profile)
    assert os.path.isabs(profile)


def test_profile_update_uses_atomic_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "config" / "operator.json"
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))
    write_operator_profile({"api_port": 18001})
    original_inode = profile.stat().st_ino

    write_operator_profile({"api_port": 18002})

    assert profile.stat().st_ino != original_inode
    assert json.loads(profile.read_text())["settings"]["api_port"] == 18002
    assert list(profile.parent.glob(".operator-*.tmp")) == []
