from __future__ import annotations

import signal
import threading

import pytest

from securescan.runtime import RuntimeSignalError, shutdown_signal_handlers


def _mock_signal_state(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[signal.Signals, object], list[tuple[signal.Signals, object]]]:
    initial = object()
    current = {
        managed_signal: initial
        for managed_signal in (signal.SIGINT, signal.SIGTERM)
        if hasattr(signal, managed_signal.name)
    }
    registrations: list[tuple[signal.Signals, object]] = []

    def getsignal(managed_signal: signal.Signals) -> object:
        return current[managed_signal]

    def install(managed_signal: signal.Signals, handler: object) -> None:
        registrations.append((managed_signal, handler))
        current[managed_signal] = handler

    monkeypatch.setattr(signal, "getsignal", getsignal)
    monkeypatch.setattr(signal, "signal", install)
    return current, registrations


def test_shutdown_signal_handler_sets_event_without_exiting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stop_event = threading.Event()
    _, registrations = _mock_signal_state(monkeypatch)

    with shutdown_signal_handlers(stop_event):
        installed = [handler for _, handler in registrations]
        assert installed
        for handler in installed:
            assert callable(handler)
            handler(signal.SIGINT, None)
            handler(signal.SIGINT, None)

    assert stop_event.is_set()


def test_shutdown_signal_handlers_restore_previous_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current, _ = _mock_signal_state(monkeypatch)
    previous = dict(current)

    with shutdown_signal_handlers(threading.Event()):
        assert current != previous
    assert current == previous

    with (
        pytest.raises(RuntimeError, match="supervised failure"),
        shutdown_signal_handlers(threading.Event()),
    ):
        raise RuntimeError("supervised failure")
    assert current == previous


def test_shutdown_signal_installation_requires_main_thread() -> None:
    errors: list[Exception] = []

    def install_from_thread() -> None:
        try:
            with shutdown_signal_handlers(threading.Event()):
                pass
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=install_from_thread)
    thread.start()
    thread.join(timeout=2)

    assert not thread.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeSignalError)
