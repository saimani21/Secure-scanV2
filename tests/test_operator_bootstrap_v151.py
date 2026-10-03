from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

import securescan.cli.main as cli_main
import securescan.operator.inspection as inspection
from securescan.config import Settings, get_operator_settings
from securescan.operator.inspection import operator_configuration_data
from securescan.operator.models import OperatorError
from securescan.operator.prerequisites import verify_enry
from securescan.operator.profile import OperatorProfileError, read_operator_profile
from securescan.operator.toolchain import TRUSTED_ENRY_HELPER_SHA256

_PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _settings(tmp_path: Path, helper: Path, sha256: str | None) -> Settings:
    deploy = tmp_path / "deploy"
    return Settings(
        _env_file=None,
        database_url="postgresql+psycopg://operator:private@127.0.0.1:55451/db",
        deploy_data_root=deploy,
        artifact_root=deploy / "artifacts",
        source_workspace_root=deploy / "workspaces",
        source_projection_root=deploy / "projections",
        source_runtime_receipt_root=deploy / "receipts",
        source_enry_helper_path=helper,
        source_enry_helper_sha256=sha256,
        hmac_key="private-hmac-value",
        postgres_db="db",
        postgres_user="operator",
        postgres_password="private",
        postgres_port=55451,
        api_port=18151,
        runtime_uid=os.geteuid(),
        runtime_gid=os.getegid(),
    )


def _helper(tmp_path: Path, *, mode: int = 0o700) -> tuple[Path, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "trusted helper"
    content = b"#!/bin/sh\nexit 0\n"
    path.write_bytes(content)
    path.chmod(mode)
    return path, hashlib.sha256(content).hexdigest()


def test_fresh_configure_persists_release_enry_identity_and_needs_no_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "configuration with spaces" / "v15-final.profile"
    source = tmp_path / "input" / "operator.env"
    source.parent.mkdir()
    source.write_text(
        "SECURESCAN_API_PORT=18151\n"
        "SECURESCAN_SOURCE_ENRY_HELPER_PATH=../tools/enry helper\n"
        "SECURESCAN_POSTGRES_PASSWORD=do-not-print\n"
        "SECURESCAN_HMAC_KEY=also-do-not-print\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))
    monkeypatch.delenv("SECURESCAN_SOURCE_ENRY_HELPER_SHA256", raising=False)

    result = CliRunner().invoke(
        cli_main.app,
        ["system", "configure", "--from-env-file", str(source)],
    )

    assert result.exit_code == 0
    assert "SecureScan application JSON" in result.stdout
    assert "do not source" in result.stdout
    assert "do-not-print" not in result.output
    assert "also-do-not-print" not in result.output
    payload = json.loads(profile.read_text(encoding="utf-8"))
    assert payload["profile_version"] == 1
    assert payload["settings"]["source_enry_helper_sha256"] == TRUSTED_ENRY_HELPER_SHA256
    assert payload["settings"]["source_enry_helper_path"] == str(
        (source.parent / "../tools/enry helper").resolve()
    )

    source.unlink()
    get_operator_settings.cache_clear()
    assert get_operator_settings().api_port == 18151
    assert get_operator_settings().source_enry_helper_sha256 == TRUSTED_ENRY_HELPER_SHA256
    get_operator_settings.cache_clear()


def test_configure_preserves_explicit_independent_enry_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "config" / "operator.json"
    source = tmp_path / "operator.env"
    source.write_text(
        f"SECURESCAN_SOURCE_ENRY_HELPER_SHA256={'a' * 64}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))

    result = CliRunner().invoke(
        cli_main.app,
        ["system", "configure", "--from-env-file", str(source)],
    )

    assert result.exit_code == 0
    assert read_operator_profile()["source_enry_helper_sha256"] == "a" * 64


def test_configure_respects_process_environment_identity_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "config" / "operator.json"
    source = tmp_path / "operator.env"
    source.write_text("SECURESCAN_API_PORT=18151\n", encoding="utf-8")
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))
    monkeypatch.setenv("SECURESCAN_SOURCE_ENRY_HELPER_SHA256", "b" * 64)

    result = CliRunner().invoke(
        cli_main.app,
        ["system", "configure", "--from-env-file", str(source)],
    )

    assert result.exit_code == 0
    assert read_operator_profile()["source_enry_helper_sha256"] == "b" * 64


def test_configure_never_executes_hostile_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "executed"
    source = tmp_path / "operator.env"
    source.write_text(
        f"SECURESCAN_HMAC_KEY=$(touch {marker})\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(tmp_path / "config" / "operator.json"))

    result = CliRunner().invoke(
        cli_main.app,
        ["system", "configure", "--from-env-file", str(source)],
    )

    assert result.exit_code == 0
    assert not marker.exists()
    assert str(marker) not in result.output


@pytest.mark.parametrize(
    ("sha256", "expected_code", "expected_message"),
    [
        (None, "SCANNER_CONFIGURATION_INVALID", "SHA-256 is not configured"),
        ("0" * 64, "SCANNER_IDENTITY_MISMATCH", "does not match"),
    ],
)
def test_enry_diagnostics_distinguish_missing_and_mismatched_identity(
    tmp_path: Path,
    sha256: str | None,
    expected_code: str,
    expected_message: str,
) -> None:
    helper, _actual = _helper(tmp_path)

    with pytest.raises(OperatorError) as raised:
        verify_enry(_settings(tmp_path, helper, sha256))

    assert raised.value.code == expected_code
    assert expected_message in str(raised.value)
    assert "0" * 64 not in str(raised.value)


def test_enry_diagnostics_distinguish_missing_unreadable_and_untrusted_paths(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing helper"
    with pytest.raises(OperatorError) as missing_error:
        verify_enry(_settings(tmp_path, missing, "a" * 64))
    assert missing_error.value.code == "SCANNER_PREREQUISITE_MISSING"
    assert str(missing) in str(missing_error.value)

    unreadable, digest = _helper(tmp_path / "unreadable", mode=0o100)
    with pytest.raises(OperatorError) as unreadable_error:
        verify_enry(_settings(tmp_path / "unreadable", unreadable, digest))
    assert unreadable_error.value.code == "SCANNER_PREREQUISITE_UNREADABLE"

    untrusted, digest = _helper(tmp_path / "untrusted", mode=0o722)
    with pytest.raises(OperatorError) as untrusted_error:
        verify_enry(_settings(tmp_path / "untrusted", untrusted, digest))
    assert untrusted_error.value.code == "SCANNER_PREREQUISITE_UNTRUSTED"
    assert "permissions are untrusted" in str(untrusted_error.value)


def test_enry_valid_identity_passes_without_executing_helper(tmp_path: Path) -> None:
    helper, digest = _helper(tmp_path)

    verify_enry(_settings(tmp_path, helper, digest))


def test_config_inventory_is_read_only_and_omits_all_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, digest = _helper(tmp_path)
    settings = _settings(tmp_path, helper, digest)
    for name in (
        "verify_enry",
        "verify_gitleaks",
        "verify_syft",
        "verify_checkov",
        "verify_semgrep_image",
    ):
        monkeypatch.setattr(inspection, name, lambda _settings: None)

    data = operator_configuration_data(settings)
    rendered = json.dumps(data, sort_keys=True)

    assert data["deployment"]["api_port"] == 18151
    assert data["scanners"]["enry"]["trusted_identity_state"] == "VALID"
    assert data["scanners"]["enry"]["path_state"] == "EXECUTABLE"
    for forbidden in (
        "private-hmac-value",
        "postgresql+psycopg",
        "operator:private",
        '"postgres_password"',
        '"hmac_key"',
    ):
        assert forbidden not in rendered


def test_system_config_text_and_json_never_print_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = {
        "deployment": {
            "api_port": 18151,
            "compose_file": "/release/compose.yaml",
            "compose_project": "securescan-v151",
            "image_tag": "securescan-v151",
            "postgres_port": 55451,
        },
        "operator_profile": {
            "exists": True,
            "format": "securescan-json-v1",
            "load": "automatic",
            "path": "/config/operator.profile",
        },
        "scanners": {
            "enry": {
                "path": "/tools/enry helper",
                "path_state": "EXECUTABLE",
                "trusted_identity_state": "VALID",
            },
            "semgrep": {
                "image": "semgrep/example@sha256:abc",
                "trusted_identity_state": "VALID",
            },
        },
        "storage": {
            "artifact_root": "/data/artifacts",
            "deployment_root": "/data",
            "projection_root": "/data/projections",
            "receipt_root": "/data/receipts",
            "workspace_root": "/data/workspaces",
        },
    }
    monkeypatch.setattr(cli_main, "get_operator_settings", lambda: object())
    monkeypatch.setattr(cli_main, "operator_configuration_data", lambda _settings: data)

    text = CliRunner().invoke(cli_main.app, ["system", "config"])
    machine = CliRunner().invoke(cli_main.app, ["system", "config", "--json"])

    assert text.exit_code == machine.exit_code == 0
    assert "do not source" in text.stdout
    assert json.loads(machine.stdout) == data
    combined = text.output + machine.output
    assert "password" not in combined.lower()
    assert "hmac" not in combined.lower()


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        '{"profile_version":2,"settings":{}}',
        '{"profile_version":1,"settings":[]}',
    ],
)
def test_malformed_or_unsupported_profile_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: str
) -> None:
    directory = tmp_path / "config"
    directory.mkdir(mode=0o700)
    profile = directory / "operator.profile"
    profile.write_text(payload, encoding="utf-8")
    profile.chmod(0o600)
    monkeypatch.setenv("SECURESCAN_OPERATOR_PROFILE", str(profile))

    with pytest.raises(OperatorProfileError):
        Settings(_env_file=None)


def test_missing_profile_remains_safe_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "SECURESCAN_OPERATOR_PROFILE", str(tmp_path / "missing" / "operator.profile")
    )

    assert Settings(_env_file=None).api_port == 8000


def test_operator_image_builder_contains_declared_package_data() -> None:
    dockerfile = (_PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    for required_copy in (
        "COPY alembic.ini compose.yaml ./",
        "COPY migrations ./migrations",
        "COPY docs ./docs",
        "COPY examples ./examples",
    ):
        assert required_copy in dockerfile
    assert dockerfile.index("COPY examples ./examples") < dockerfile.index(
        "RUN python -m venv /opt/securescan"
    )
