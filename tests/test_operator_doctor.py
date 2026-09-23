import os
from pathlib import Path

import pytest

from securescan.config import Settings
from securescan.operator.doctor import Doctor
from securescan.operator.models import CheckState


def _settings(tmp_path: Path) -> Settings:
    deploy = tmp_path / "deploy"
    return Settings(
        _env_file=None,
        database_url="postgresql+psycopg://user:password@127.0.0.1:55432/db",
        deploy_data_root=deploy,
        artifact_root=deploy / "artifacts",
        source_workspace_root=deploy / "source-workspaces",
        source_projection_root=deploy / "source-projections",
        source_runtime_receipt_root=deploy / "source-runtime-receipts",
        hmac_key="0123456789abcdef",
        postgres_db="db",
        postgres_user="user",
        postgres_password="password",
        runtime_uid=os.geteuid(),
        runtime_gid=os.getegid(),
    )


def _by_name(report, name: str):
    return next(check for check in report.checks if check.name == name)


def test_doctor_distinguishes_missing_cli_from_daemon_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr("securescan.operator.doctor.shutil.which", lambda *_a, **_k: None)

    missing = Doctor(settings).run()

    assert _by_name(missing, "Docker CLI").status is CheckState.FAIL
    assert "not installed" in _by_name(missing, "Docker CLI").detail
    assert "without Docker CLI" in _by_name(missing, "Docker daemon").detail

    class Compose:
        def __init__(self, _settings):
            pass

        def verify(self):
            return None

        def services(self):
            return {}

    monkeypatch.setattr("securescan.operator.doctor.shutil.which", lambda *_a, **_k: "/docker")
    monkeypatch.setattr("securescan.operator.doctor.ComposeClient", Compose)

    def command(_self, argv, _timeout=15):
        if argv[-1] == "info":
            raise RuntimeError

    monkeypatch.setattr(Doctor, "_command", command)
    unavailable = Doctor(settings).run()

    assert _by_name(unavailable, "Docker CLI").status is CheckState.PASS
    assert _by_name(unavailable, "Docker daemon").status is CheckState.FAIL
    assert _by_name(unavailable, "Docker Compose").status is CheckState.PASS
