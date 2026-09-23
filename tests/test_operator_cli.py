import json

import pytest
from typer.testing import CliRunner

import securescan.cli.main as cli_main
from securescan.operator.models import (
    CheckState,
    ComponentState,
    DoctorCheck,
    DoctorReport,
    SystemState,
    SystemStatus,
)

_STATUS = SystemStatus(
    SystemState.READY,
    ComponentState.READY,
    ComponentState.READY,
    ComponentState.READY,
    ComponentState.RUNNING,
    "http://127.0.0.1:18000",
)


class FakeManager:
    ui_url = "http://127.0.0.1:18000"

    def up(self) -> SystemStatus:
        return _STATUS

    def down(self) -> SystemStatus:
        return SystemStatus(
            SystemState.STOPPED,
            ComponentState.STOPPED,
            ComponentState.STOPPED,
            ComponentState.UNKNOWN,
            ComponentState.STOPPED,
            self.ui_url,
        )

    def status(self) -> SystemStatus:
        return _STATUS


@pytest.mark.parametrize(
    "arguments",
    (["system", "up"], ["system", "down"], ["system", "status"]),
)
def test_system_commands_parse(arguments: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_operator_manager", FakeManager)

    result = CliRunner().invoke(cli_main.app, arguments)

    assert result.exit_code == 0
    assert "SecureScan Source v1.1" in result.stdout


def test_system_status_json_is_deterministic_and_contains_no_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_main, "_operator_manager", FakeManager)

    first = CliRunner().invoke(cli_main.app, ["system", "status", "--json"])
    second = CliRunner().invoke(cli_main.app, ["system", "status", "--json"])

    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["system_status"] == "READY"
    assert "password" not in first.stdout.lower()
    assert "hmac" not in first.stdout.lower()


def test_doctor_json_and_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    report = DoctorReport((DoctorCheck("Docker", CheckState.PASS, "ready"),))
    monkeypatch.setattr(
        cli_main, "Doctor", lambda _settings: type("D", (), {"run": lambda _self: report})()
    )
    monkeypatch.setattr(cli_main, "get_operator_settings", lambda: object())

    result = CliRunner().invoke(cli_main.app, ["doctor", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["result"] == "READY"


def test_operator_manager_uses_dotenv_free_operator_loader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = object()
    observed: list[object] = []
    monkeypatch.setattr(cli_main, "get_operator_settings", lambda: settings)
    monkeypatch.setattr(
        cli_main,
        "OperatorManager",
        lambda value: observed.append(value) or FakeManager(),
    )

    manager = cli_main._operator_manager()

    assert isinstance(manager, FakeManager)
    assert observed == [settings]


def test_open_prints_url_when_browser_launch_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "_operator_manager", FakeManager)
    monkeypatch.setattr(cli_main.webbrowser, "open", lambda *_args, **_kwargs: False)

    result = CliRunner().invoke(cli_main.app, ["open"])

    assert result.exit_code == 5
    assert "http://127.0.0.1:18000/" in result.output
    assert "open the URL above manually" in result.output


def test_existing_scan_status_namespace_remains_distinct() -> None:
    result = CliRunner().invoke(cli_main.app, ["status", "not-a-run-id"])

    assert result.exit_code != 0
    assert "SecureScan Source v1.1" not in result.output


def test_operator_failure_never_echoes_configured_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securescan.operator.models import OperatorError

    class FailedManager(FakeManager):
        def up(self):
            raise OperatorError("CONFIGURATION_INVALID", "Database configuration is invalid")

    monkeypatch.setattr(cli_main, "_operator_manager", FailedManager)

    result = CliRunner().invoke(cli_main.app, ["system", "up", "--json"])

    assert result.exit_code == 5
    assert json.loads(result.stderr)["error"]["code"] == "CONFIGURATION_INVALID"
    assert "password" not in result.output.lower()
