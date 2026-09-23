from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from securescan.config import Settings
from securescan.operator.compose import compose_environment
from securescan.operator.models import ComponentState, OperatorError

_PROC_CMDLINE_LIMIT_BYTES = 64 * 1024
_PROC_ENVIRONMENT_LIMIT_BYTES = 1024 * 1024
_DEPLOYMENT_MARKER_NAME = b"SECURESCAN_OPERATOR_DEPLOYMENT_ID"


class _ProcessIdentityInspectionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class WorkerIdentity:
    pid: int
    start_ticks: str
    executable: str
    command_sha256: str
    deployment_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.pid) is not int
            or self.pid <= 1
            or not isinstance(self.start_ticks, str)
            or not self.start_ticks.isdigit()
            or not isinstance(self.executable, str)
            or not Path(self.executable).is_absolute()
            or re.fullmatch(r"[0-9a-f]{64}", self.command_sha256) is None
            or re.fullmatch(r"[0-9a-f]{64}", self.deployment_sha256) is None
        ):
            raise ValueError("Worker identity is invalid")

    def canonical_data(self) -> dict[str, object]:
        return {
            "command_sha256": self.command_sha256,
            "deployment_sha256": self.deployment_sha256,
            "executable": self.executable,
            "pid": self.pid,
            "start_ticks": self.start_ticks,
            "version": 1,
        }


def _command_digest(command: bytes) -> str:
    return hashlib.sha256(b"securescan-managed-worker-v1\0" + command).hexdigest()


def _deployment_digest(settings: Settings) -> str:
    value = f"{settings.operator_compose_project}\0{settings.deploy_data_root}".encode()
    return hashlib.sha256(b"securescan-operator-deployment-v1\0" + value).hexdigest()


def _read_bounded_proc_file(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
        raise ValueError("Process metadata exceeds its inspection bound")
    finally:
        os.close(descriptor)


def _deployment_marker(environment: bytes) -> str:
    if not environment or not environment.endswith(b"\0"):
        raise ValueError("Process environment is malformed")
    marker: bytes | None = None
    for entry in environment[:-1].split(b"\0"):
        if not entry or b"=" not in entry:
            raise ValueError("Process environment is malformed")
        name, value = entry.split(b"=", 1)
        if name == _DEPLOYMENT_MARKER_NAME:
            if marker is not None:
                raise ValueError("Process deployment marker is duplicated")
            marker = value
    if marker is None or re.fullmatch(rb"[0-9a-f]{64}", marker) is None:
        raise ValueError("Process deployment marker is invalid")
    return marker.decode("ascii")


def _proc_identity(pid: int) -> WorkerIdentity | None:
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        closing = stat_text.rfind(")")
        stat_fields = stat_text[closing + 2 :].split()
        if stat_fields[0] == "Z":
            return None
        start_ticks = stat_fields[19]
        command = _read_bounded_proc_file(
            Path(f"/proc/{pid}/cmdline"), _PROC_CMDLINE_LIMIT_BYTES
        )
        environment = _read_bounded_proc_file(
            Path(f"/proc/{pid}/environ"), _PROC_ENVIRONMENT_LIMIT_BYTES
        )
        deployment_sha256 = _deployment_marker(environment)
        executable = str(Path(f"/proc/{pid}/exe").resolve(strict=True))
    except FileNotFoundError:
        return None
    except (OSError, IndexError, RuntimeError, ValueError) as exc:
        raise _ProcessIdentityInspectionError from exc
    return WorkerIdentity(pid, start_ticks, executable, _command_digest(command), deployment_sha256)


class WorkerProcessManager:
    def __init__(self, settings: Settings) -> None:
        if settings.deploy_data_root is None:
            raise OperatorError("CONFIGURATION_MISSING", "Deployment root is not configured")
        self.settings = settings
        self.root = settings.deploy_data_root / "operator"
        self.identity_path = self.root / "worker.identity.json"
        self.log_path = self.root / "worker.log"
        self.lock_path = self.root / "operator.lock"
        self.deployment_sha256 = _deployment_digest(settings)

    def prepare(self) -> None:
        try:
            self.root.mkdir(mode=0o700, parents=False, exist_ok=True)
            metadata = self.root.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != os.geteuid()
            ):
                raise OperatorError(
                    "OPERATOR_STATE_UNSAFE",
                    "Operator state directory must be private and owned by this user",
                )
        except OperatorError:
            raise
        except OSError as exc:
            raise OperatorError(
                "OPERATOR_STATE_UNAVAILABLE", "Operator state is unavailable"
            ) from exc

    @contextmanager
    def lifecycle_lock(self) -> Iterator[None]:
        self.prepare()
        descriptor = os.open(
            self.lock_path,
            os.O_CREAT
            | os.O_RDWR
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise OperatorError(
                    "OPERATOR_STATE_UNSAFE", "Operator lifecycle lock is unsafe"
                )
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read_stored(self) -> WorkerIdentity | None:
        if not os.path.lexists(self.identity_path):
            return None
        try:
            metadata = self.identity_path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ValueError
            flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.identity_path, flags)
            opened = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(descriptor)
                raise ValueError
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if data.pop("version") != 1:
                raise ValueError
            identity = WorkerIdentity(**data)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            raise OperatorError(
                "STALE_WORKER_STATE", "Managed worker identity is invalid"
            ) from None
        return identity

    def _write_stored(self, identity: WorkerIdentity) -> None:
        descriptor, name = tempfile.mkstemp(prefix=".worker-", dir=self.root)
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(identity.canonical_data(), handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.identity_path)
            os.chmod(self.identity_path, 0o600)
        finally:
            if temporary.exists():
                temporary.unlink()

    def inspect(self) -> ComponentState:
        try:
            stored = self._read_stored()
        except OperatorError:
            return ComponentState.STALE
        if stored is None:
            return ComponentState.STOPPED
        try:
            live = _proc_identity(stored.pid)
        except _ProcessIdentityInspectionError:
            return ComponentState.STALE
        if live is None:
            return ComponentState.STOPPED
        return ComponentState.RUNNING if live == stored else ComponentState.STALE

    def start(self) -> None:
        state = self.inspect()
        if state is ComponentState.RUNNING:
            return
        if state is ComponentState.STALE:
            raise OperatorError(
                "STALE_WORKER_STATE", "Managed worker state does not match the live process"
            )
        self.identity_path.unlink(missing_ok=True)
        argv = (sys.executable, "-m", "securescan.cli.main", "worker", "--json")
        environment = compose_environment(self.settings)
        environment["SECURESCAN_OPERATOR_DEPLOYMENT_ID"] = self.deployment_sha256
        for name in (
            "SOURCE_ENRY_HELPER_PATH",
            "SOURCE_ENRY_HELPER_SHA256",
            "SOURCE_GITLEAKS_EXECUTABLE_PATH",
            "SOURCE_SYFT_EXECUTABLE_PATH",
            "SOURCE_CHECKOV_EXECUTABLE_PATH",
            "SOURCE_SCAN_DEADLINE_SECONDS",
            "SOURCE_WORKER_POLL_SECONDS",
            "ALLOW_SQLITE_SCHEMA_BOOTSTRAP",
        ):
            field = name.lower()
            value = getattr(self.settings, field)
            if value is not None:
                environment[f"SECURESCAN_{name}"] = str(value)
        process: subprocess.Popen[bytes] | None = None
        try:
            descriptor = os.open(self.log_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "ab", closefd=True) as log:
                process = subprocess.Popen(
                    argv,
                    cwd=self.settings.operator_compose_file.parent,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=log,
                    close_fds=True,
                    start_new_session=True,
                )
            time.sleep(1.0)
            if process.poll() is not None:
                raise OperatorError("WORKER_START_FAILED", "Managed worker exited during startup")
            try:
                identity = _proc_identity(process.pid)
            except _ProcessIdentityInspectionError:
                identity = None
            if identity is None:
                process.terminate()
                raise OperatorError(
                    "WORKER_START_FAILED", "Managed worker identity could not be verified"
                )
            expected_command = b"\0".join(item.encode() for item in argv) + b"\0"
            if (
                identity.command_sha256 != _command_digest(expected_command)
                or identity.executable != str(Path(sys.executable).resolve())
                or identity.deployment_sha256 != self.deployment_sha256
            ):
                process.terminate()
                raise OperatorError(
                    "WORKER_START_FAILED", "Managed worker identity could not be verified"
                )
            self._write_stored(identity)
        except OperatorError:
            raise
        except OSError as exc:
            if process is not None and process.poll() is None:
                process.terminate()
            raise OperatorError(
                "WORKER_START_FAILED", "Managed worker could not be started"
            ) from exc

    def stop(self) -> None:
        stored = self._read_stored()
        if stored is None:
            return
        try:
            live = _proc_identity(stored.pid)
        except _ProcessIdentityInspectionError:
            raise OperatorError(
                "STALE_WORKER_STATE", "Managed worker identity could not be verified"
            ) from None
        if live is None:
            self.identity_path.unlink(missing_ok=True)
            return
        if live != stored:
            raise OperatorError(
                "STALE_WORKER_STATE", "Refusing to signal a process with mismatched identity"
            )
        os.kill(stored.pid, signal.SIGTERM)
        deadline = time.monotonic() + self.settings.operator_shutdown_timeout_seconds
        while time.monotonic() < deadline:
            try:
                live = _proc_identity(stored.pid)
            except _ProcessIdentityInspectionError:
                raise OperatorError(
                    "STALE_WORKER_STATE", "Managed worker identity could not be verified"
                ) from None
            if live is None:
                self.identity_path.unlink(missing_ok=True)
                return
            time.sleep(0.1)
        try:
            live = _proc_identity(stored.pid)
        except _ProcessIdentityInspectionError:
            raise OperatorError(
                "STALE_WORKER_STATE", "Managed worker identity could not be verified"
            ) from None
        if live != stored:
            raise OperatorError(
                "STALE_WORKER_STATE", "Refusing forced stop after worker identity changed"
            )
        os.kill(stored.pid, signal.SIGKILL)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                live = _proc_identity(stored.pid)
            except _ProcessIdentityInspectionError:
                raise OperatorError(
                    "STALE_WORKER_STATE", "Managed worker identity could not be verified"
                ) from None
            if live is None:
                self.identity_path.unlink(missing_ok=True)
                return
            time.sleep(0.1)
        raise OperatorError("WORKER_STOP_FAILED", "Managed worker did not stop")
