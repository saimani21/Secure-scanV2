import os
import subprocess
from pathlib import Path

import pytest

from securescan.config import Settings
from securescan.operator.compose import ComposeClient


def test_compose_lifecycle_is_scoped_to_configured_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compose_file = tmp_path / "compose.yaml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    settings = Settings(
        _env_file=None,
        operator_compose_file=compose_file,
        operator_compose_project="securescan-isolated-v11",
        postgres_password="password",
    )
    calls: list[tuple[str, ...]] = []

    def run(argv, **_kwargs):
        calls.append(tuple(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("securescan.operator.compose.subprocess.run", run)

    ComposeClient(settings).down()

    assert calls == [
        (
            "docker",
            "compose",
            "--project-name",
            "securescan-isolated-v11",
            "--file",
            str(compose_file),
            "down",
            "--remove-orphans",
        )
    ]
    assert "-v" not in calls[0]
    assert "securescan-core-step1" not in calls[0]


def test_compose_environment_is_controlled_and_never_passes_unrelated_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    compose_file = tmp_path / "compose.yaml"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-cross-boundary")
    settings = Settings(
        _env_file=None,
        operator_compose_file=compose_file,
        postgres_password="password",
    )
    client = ComposeClient(settings)

    assert "UNRELATED_SECRET" not in client.environment
    assert client.environment["SECURESCAN_POSTGRES_PASSWORD"] == "password"
    assert client.base[0:2] == ("docker", "compose")
    assert os.path.isabs(client.base[-1])
