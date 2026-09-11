from __future__ import annotations

import json
import signal
import threading
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import securescan.cli.main as cli_main
from securescan.cli.main import app
from securescan.config import Settings
from securescan.source_runtime import (
    SourceRuntimeCycleSummary,
    SourceRuntimeError,
    SourceRuntimeLoop,
)


def _summary() -> SourceRuntimeCycleSummary:
    return SourceRuntimeCycleSummary(*(0 for _ in range(18)))


class _Runtime:
    def __init__(
        self,
        outcomes: list[SourceRuntimeCycleSummary | Exception],
        *,
        stop_event: threading.Event | None = None,
        stop_after_call: int = 1,
    ) -> None:
        self.outcomes = outcomes
        self.stop_event = stop_event
        self.stop_after_call = stop_after_call
        self.calls = 0

    def run_once(self) -> SourceRuntimeCycleSummary:
        outcome = self.outcomes[self.calls]
        self.calls += 1
        if self.stop_event is not None and self.calls == self.stop_after_call:
            self.stop_event.set()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _canonical(summary: SourceRuntimeCycleSummary) -> str:
    return json.dumps(summary.canonical_data(), separators=(",", ":"), sort_keys=True)


def test_continuous_loop_repeats_bounded_cycles_and_emits_each_summary() -> None:
    stop_event = threading.Event()
    runtime = _Runtime([_summary(), _summary(), _summary()])
    emitted: list[SourceRuntimeCycleSummary] = []
    waits: list[float] = []

    def on_cycle(summary: SourceRuntimeCycleSummary) -> None:
        emitted.append(summary)
        if len(emitted) == 3:
            stop_event.set()

    def wait(timeout: float) -> bool:
        waits.append(timeout)
        return False

    completed = SourceRuntimeLoop(
        runtime,
        stop_event,
        poll_seconds=1.25,
        on_cycle=on_cycle,
        waiter=wait,
    ).run()

    assert completed == runtime.calls == 3
    assert emitted == [_summary(), _summary(), _summary()]
    assert waits == [1.25, 1.25]


def test_stop_requested_before_loop_executes_no_cycle_or_wait() -> None:
    stop_event = threading.Event()
    stop_event.set()
    runtime = _Runtime([_summary()])

    def forbidden_cycle(_summary: SourceRuntimeCycleSummary) -> None:
        raise AssertionError("stopped loop attempted output or wait")

    def forbidden_wait(_timeout: float) -> bool:
        raise AssertionError("stopped loop attempted output or wait")

    completed = SourceRuntimeLoop(
        runtime,
        stop_event,
        poll_seconds=1,
        on_cycle=forbidden_cycle,
        waiter=forbidden_wait,
    ).run()

    assert completed == 0
    assert runtime.calls == 0


def test_stop_requested_during_cycle_finishes_cycle_without_starting_next() -> None:
    stop_event = threading.Event()
    runtime = _Runtime([_summary(), _summary()], stop_event=stop_event)
    emitted: list[SourceRuntimeCycleSummary] = []

    completed = SourceRuntimeLoop(
        runtime,
        stop_event,
        poll_seconds=1,
        on_cycle=emitted.append,
        waiter=lambda _timeout: False,
    ).run()

    assert completed == runtime.calls == 1
    assert emitted == [_summary()]


def test_poll_wait_can_be_interrupted_by_stop_event() -> None:
    stop_event = threading.Event()
    runtime = _Runtime([_summary(), _summary()])
    waits: list[float] = []

    def interrupt_wait(timeout: float) -> bool:
        waits.append(timeout)
        stop_event.set()
        return stop_event.wait(timeout)

    completed = SourceRuntimeLoop(
        runtime,
        stop_event,
        poll_seconds=2.5,
        on_cycle=lambda _summary: None,
        waiter=interrupt_wait,
    ).run()

    assert completed == runtime.calls == 1
    assert waits == [2.5]


def test_cli_worker_once_bypasses_continuous_loop_and_poll_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime([_summary()])

    @contextmanager
    def runtime_context():
        yield SimpleNamespace(runtime=runtime)

    def forbidden_loop(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("--once constructed the continuous runtime loop")

    monkeypatch.setattr(cli_main, "create_source_runtime", runtime_context)
    monkeypatch.setattr(cli_main, "SourceRuntimeLoop", forbidden_loop)

    result = CliRunner().invoke(app, ["worker", "--once"])

    assert result.exit_code == 0
    assert runtime.calls == 1
    assert result.stdout == _canonical(_summary()) + "\n"


@pytest.mark.parametrize("requested_signal", [signal.SIGINT, signal.SIGTERM])
def test_cli_signal_requests_stop_finishes_cycle_and_restores_handlers(
    monkeypatch: pytest.MonkeyPatch,
    requested_signal: signal.Signals,
) -> None:
    previous_handler = object()
    current = {
        managed_signal: previous_handler
        for managed_signal in (signal.SIGINT, signal.SIGTERM)
    }

    def get_handler(managed_signal: signal.Signals) -> object:
        return current[managed_signal]

    def set_handler(managed_signal: signal.Signals, handler: object) -> None:
        current[managed_signal] = handler

    class SignalRuntime:
        calls = 0

        def run_once(self) -> SourceRuntimeCycleSummary:
            self.calls += 1
            handler = current[requested_signal]
            assert callable(handler)
            handler(requested_signal, None)
            return _summary()

    runtime = SignalRuntime()

    @contextmanager
    def runtime_context(_settings: Settings):
        yield SimpleNamespace(runtime=runtime)

    monkeypatch.setattr(signal, "getsignal", get_handler)
    monkeypatch.setattr(signal, "signal", set_handler)
    monkeypatch.setattr(cli_main, "create_source_runtime", runtime_context)
    monkeypatch.setattr(cli_main, "get_settings", lambda: Settings(_env_file=None))

    result = CliRunner().invoke(app, ["worker"])

    assert result.exit_code == 0
    assert runtime.calls == 1
    assert result.stdout == _canonical(_summary()) + "\n"
    assert set(current.values()) == {previous_handler}


def test_continuous_cycle_failure_summary_is_visible_and_loop_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_secret = "RAW_RUNTIME_SECRET"
    failed = replace(
        _summary(), assembly_failed_count=1, finalization_failed_count=1
    )
    runtime = _Runtime([failed, _summary()], stop_after_call=2)

    @contextmanager
    def runtime_context(_settings: Settings):
        yield SimpleNamespace(runtime=runtime, sensitive=raw_secret)

    @contextmanager
    def signal_context(stop_event: threading.Event):
        runtime.stop_event = stop_event
        yield

    real_loop = SourceRuntimeLoop

    def loop_without_delay(*args: object, **kwargs: object) -> SourceRuntimeLoop:
        return real_loop(*args, **kwargs, waiter=lambda _timeout: False)

    monkeypatch.setattr(cli_main, "create_source_runtime", runtime_context)
    monkeypatch.setattr(cli_main, "shutdown_signal_handlers", signal_context)
    monkeypatch.setattr(cli_main, "SourceRuntimeLoop", loop_without_delay)
    monkeypatch.setattr(cli_main, "get_settings", lambda: Settings(_env_file=None))

    result = CliRunner().invoke(app, ["worker"])

    assert result.exit_code == 0
    assert runtime.calls == 2
    assert result.stderr == _canonical(failed) + "\n"
    assert result.stdout == _canonical(_summary()) + "\n"
    assert raw_secret not in result.output
    assert "stdout" not in result.output
    assert "stderr" not in result.output
    assert "token" not in result.output


def test_continuous_runtime_failure_is_sanitized_and_nonzero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _Runtime([SourceRuntimeError()])

    @contextmanager
    def runtime_context(_settings: Settings):
        yield SimpleNamespace(runtime=runtime)

    monkeypatch.setattr(cli_main, "create_source_runtime", runtime_context)
    monkeypatch.setattr(cli_main, "get_settings", lambda: Settings(_env_file=None))

    result = CliRunner().invoke(app, ["worker"])

    assert result.exit_code == 5
    assert result.stdout == ""
    assert result.stderr == (
        "Error [RUNTIME_UNAVAILABLE]: Source runtime cycle is unavailable\n"
    )
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("poll_seconds", [0.09, 60.01])
def test_poll_setting_rejects_values_outside_bounded_contract(
    poll_seconds: float,
) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, source_worker_poll_seconds=poll_seconds)


def test_poll_setting_defaults_to_one_second(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SECURESCAN_SOURCE_WORKER_POLL_SECONDS", raising=False)

    assert Settings(_env_file=None).source_worker_poll_seconds == 1.0


def test_poll_setting_environment_override_is_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECURESCAN_SOURCE_WORKER_POLL_SECONDS", "2.75")

    settings = Settings(_env_file=None)

    assert settings.source_worker_poll_seconds == 2.75
