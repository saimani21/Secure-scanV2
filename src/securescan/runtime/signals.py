from __future__ import annotations

import signal
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from types import FrameType


class RuntimeSignalError(RuntimeError):
    """Raised when shutdown signal handlers cannot be managed safely."""


@contextmanager
def shutdown_signal_handlers(
    stop_event: threading.Event,
) -> Iterator[None]:
    if not isinstance(stop_event, threading.Event):
        raise RuntimeSignalError("A valid shutdown event is required")
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeSignalError("Shutdown signal handlers must be installed from the main thread")

    managed_signals = [signal.SIGINT]
    if hasattr(signal, "SIGTERM"):
        managed_signals.append(signal.SIGTERM)
    previous_handlers: dict[signal.Signals, signal.Handlers] = {}

    def request_shutdown(
        _signal_number: int,
        _frame: FrameType | None,
    ) -> None:
        stop_event.set()

    try:
        for managed_signal in managed_signals:
            previous_handlers[managed_signal] = signal.getsignal(managed_signal)
            signal.signal(managed_signal, request_shutdown)
    except Exception as exc:
        for managed_signal, previous_handler in previous_handlers.items():
            with suppress(Exception):
                signal.signal(managed_signal, previous_handler)
        raise RuntimeSignalError("Shutdown signal handlers could not be installed") from exc

    try:
        yield
    finally:
        restoration_error: Exception | None = None
        for managed_signal, previous_handler in previous_handlers.items():
            try:
                signal.signal(managed_signal, previous_handler)
            except Exception as exc:
                restoration_error = restoration_error or exc
        if restoration_error is not None:
            raise RuntimeSignalError(
                "Shutdown signal handlers could not be restored"
            ) from restoration_error
