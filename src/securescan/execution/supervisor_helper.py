from __future__ import annotations

import base64
import ctypes
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from securescan.orchestration.execution_models import (
    AttemptContainmentOutcome,
    SourceAttemptCleanupReceipt,
)

from .supervisor import SUPERVISOR_PROTOCOL_VERSION, supervisor_identity

_PR_SET_CHILD_SUBREAPER = 36
_PR_SET_PDEATHSIG = 1
_TERM_GRACE_SECONDS = 0.5
_KILL_GRACE_SECONDS = 1.5


def _process_stat(pid: int) -> tuple[int, int, int]:
    payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = payload[payload.rfind(")") + 2 :].split()
    return int(fields[1]), int(fields[2]), int(fields[19])


def _set_subreaper() -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl failed")


def _set_parent_death_signal() -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            os._exit(126)


def _members(scanner_pgid: int, supervisor_pid: int) -> set[int]:
    members: set[int] = set()
    proc = Path("/proc")
    if not proc.is_dir():
        return {-1}
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            ppid, pgid, _ = _process_stat(int(entry.name))
        except (OSError, ValueError):
            continue
        if pgid == scanner_pgid or ppid == supervisor_pid:
            members.add(int(entry.name))
    return members


def _reap() -> None:
    while True:
        try:
            child, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if child == 0:
            return


def _terminate_tree(
    process: subprocess.Popen[bytes],
    scanner_pgid: int,
    supervisor_pid: int,
    *,
    immediate: bool,
) -> tuple[bool, bool]:
    force_killed = immediate
    if not immediate:
        with suppress(ProcessLookupError):
            os.killpg(scanner_pgid, signal.SIGTERM)
        deadline = time.monotonic() + _TERM_GRACE_SECONDS
        while time.monotonic() < deadline:
            process.poll()
            _reap()
            if not _members(scanner_pgid, supervisor_pid):
                return True, force_killed
            time.sleep(0.01)
    force_killed = True
    with suppress(ProcessLookupError):
        os.killpg(scanner_pgid, signal.SIGKILL)
    deadline = time.monotonic() + _KILL_GRACE_SECONDS
    while time.monotonic() < deadline:
        process.poll()
        _reap()
        if not _members(scanner_pgid, supervisor_pid):
            return True, force_killed
        time.sleep(0.01)
    _reap()
    return not _members(scanner_pgid, supervisor_pid), force_killed


def _read_request(fd: int) -> dict[str, Any]:
    payload = bytearray()
    while len(payload) <= 24 * 1024 * 1024:
        chunk = os.read(fd, 64 * 1024)
        if not chunk:
            break
        payload.extend(chunk)
    value = json.loads(bytes(payload).decode("utf-8"))
    if not isinstance(value, dict) or value.get("protocol_version") != SUPERVISOR_PROTOCOL_VERSION:
        raise ValueError
    return value


def _write_event(fd: int, value: dict[str, Any]) -> None:
    payload = (
        json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        + b"\n"
    )
    view = memoryview(payload)
    while view:
        count = os.write(fd, view)
        view = view[count:]


def _write_receipt(directory: Path, receipt: SourceAttemptCleanupReceipt) -> None:
    name = f"{receipt.job_id}-{receipt.attempt_number}-{receipt.attempt_token}.json"
    destination = directory / name
    fd, temporary = tempfile.mkstemp(prefix=".receipt-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        payload = receipt.canonical_json()
        os.write(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, destination)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(temporary):
            os.unlink(temporary)


def _run(
    request: dict[str, Any],
    liveness_fd: int,
    control_fd: int,
    event_fd: int,
    receipt_dir: Path,
) -> int:
    _set_subreaper()
    supervisor_pid = os.getpid()
    _, _, supervisor_start = _process_stat(supervisor_pid)
    stdin_value = request["stdin"]
    stdin_data = None if stdin_value is None else base64.b64decode(stdin_value, validate=True)
    with tempfile.TemporaryFile(mode="w+b") as stdin_file:
        if stdin_data is not None:
            stdin_file.write(stdin_data)
            stdin_file.seek(0)
        process = subprocess.Popen(  # noqa: S603 - trusted worker already froze argv
            tuple(request["argv"]),
            cwd=request["cwd"],
            env=request["environment"],
            stdin=subprocess.DEVNULL if stdin_data is None else stdin_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            bufsize=0,
            start_new_session=True,
            preexec_fn=_set_parent_death_signal,
        )
    scanner_pid = process.pid
    scanner_pgid = os.getpgid(scanner_pid)
    _, _, scanner_start = _process_stat(scanner_pid)
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd = None if pidfd_open is None else pidfd_open(scanner_pid)
    identity = supervisor_identity(supervisor_pid, supervisor_start)
    _write_event(
        event_fd,
        {
            "scanner_pgid": scanner_pgid,
            "scanner_pid": scanner_pid,
            "scanner_start_ticks": scanner_start,
            "supervisor_identity": identity,
            "supervisor_pid": supervisor_pid,
            "supervisor_start_ticks": supervisor_start,
            "type": "handshake",
        },
    )
    assert process.stdout is not None and process.stderr is not None
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(liveness_fd, selectors.EVENT_READ, "liveness")
    selector.register(control_fd, selectors.EVENT_READ, "control")
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    if pidfd is not None:
        selector.register(pidfd, selectors.EVENT_READ, "pidfd")
    stdout = bytearray()
    stderr = bytearray()
    started = time.monotonic()
    timed_out = False
    output_limit = False
    termination_requested = False
    force_killed = False
    requested_immediate = False
    process_exited = False
    while True:
        if time.monotonic() - started >= request["timeout_seconds"]:
            timed_out = True
            termination_requested = True
        for key, _ in selector.select(0.02):
            kind = key.data
            if kind in {"liveness", "control"}:
                data = os.read(key.fd, 16)
                if kind == "liveness" and not data:
                    termination_requested = True
                elif kind == "control" and data:
                    termination_requested = True
                    requested_immediate = b"K" in data
                elif kind == "control" and not data:
                    termination_requested = True
            elif kind == "pidfd":
                process_exited = True
                selector.unregister(key.fd)
            else:
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = stdout if kind == "stdout" else stderr
                limit = request[f"{kind}_limit_bytes"]
                remaining = limit - len(target)
                target.extend(chunk[: max(0, remaining)])
                if len(chunk) > remaining:
                    output_limit = True
                    termination_requested = True
        if process.poll() is not None:
            process_exited = True
        streams_open = any(key.data in {"stdout", "stderr"} for key in selector.get_map().values())
        if termination_requested or (process_exited and not streams_open):
            break
    if process_exited:
        process.wait()
    empty, cleanup_force = _terminate_tree(
        process,
        scanner_pgid,
        supervisor_pid,
        immediate=requested_immediate,
    )
    force_killed = force_killed or cleanup_force
    try:
        return_code = process.wait(timeout=0.1)
    except (ChildProcessError, subprocess.TimeoutExpired):
        if process.returncode is not None:
            return_code = process.returncode
        else:
            return_code = -signal.SIGKILL
            empty = False
    _reap()
    duration_ms = max(0, int((time.monotonic() - started) * 1000))
    outcome = (
        AttemptContainmentOutcome.CLEAN
        if empty
        else AttemptContainmentOutcome.RECONCILIATION_REQUIRED
    )
    receipt = SourceAttemptCleanupReceipt(
        job_id=request["job_id"],
        attempt_number=request["attempt_number"],
        attempt_token=request["attempt_token"],
        supervisor_identity=identity,
        supervisor_pid=supervisor_pid,
        supervisor_start_ticks=supervisor_start,
        scanner_pid=scanner_pid,
        scanner_pgid=scanner_pgid,
        scanner_start_ticks=scanner_start,
        cleanup_outcome=outcome,
        process_tree_empty=empty,
    )
    _write_receipt(receipt_dir, receipt)
    _write_event(
        event_fd,
        {
            "duration_ms": duration_ms,
            "force_killed": force_killed,
            "output_limit_exceeded": output_limit,
            "receipt": base64.b64encode(receipt.canonical_json()).decode("ascii"),
            "return_code": return_code,
            "stderr": base64.b64encode(bytes(stderr)).decode("ascii"),
            "stdout": base64.b64encode(bytes(stdout)).decode("ascii"),
            "termination_requested": termination_requested,
            "timed_out": timed_out,
            "type": "result",
        },
    )
    if pidfd is not None:
        os.close(pidfd)
    return 0 if empty else 70


def main() -> int:
    if len(sys.argv) != 6:
        return 64
    request_fd, liveness_fd, control_fd, event_fd = map(int, sys.argv[1:5])
    receipt_dir = Path(sys.argv[5])
    try:
        metadata = receipt_dir.stat()
        if (
            receipt_dir.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            return 65
        request = _read_request(request_fd)
        return _run(request, liveness_fd, control_fd, event_fd, receipt_dir)
    except BaseException:
        return 70
    finally:
        for descriptor in (request_fd, liveness_fd, control_fd, event_fd):
            with suppress(OSError):
                os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
