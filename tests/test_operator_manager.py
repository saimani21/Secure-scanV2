from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from securescan.config import Settings
from securescan.operator.compose import ComposeService
from securescan.operator.manager import ApiReadiness, OperatorManager
from securescan.operator.models import ComponentState, OperatorError, SystemState
from securescan.operator.process import (
    WorkerIdentity,
    WorkerProcessManager,
    _deployment_marker,
    _proc_identity,
    _read_bounded_proc_file,
)


def _settings(tmp_path: Path, **updates: object) -> Settings:
    deploy = tmp_path / "deploy"
    values: dict[str, object] = {
        "database_url": "postgresql+psycopg://user:password@127.0.0.1:55432/db",
        "deploy_data_root": deploy,
        "artifact_root": deploy / "artifacts",
        "source_workspace_root": deploy / "source-workspaces",
        "source_projection_root": deploy / "source-projections",
        "source_runtime_receipt_root": deploy / "source-runtime-receipts",
        "hmac_key": "0123456789abcdef",
        "postgres_db": "db",
        "postgres_user": "user",
        "postgres_password": "password",
        "runtime_uid": os.geteuid(),
        "runtime_gid": os.getegid(),
        "operator_startup_timeout_seconds": 5,
        "operator_shutdown_timeout_seconds": 1,
    }
    values.update(updates)
    return Settings(_env_file=None, **values)


class FakeCompose:
    def __init__(self, *, migration_fails: bool = False) -> None:
        self.state: dict[str, ComposeService] = {}
        self.migration_fails = migration_fails
        self.build_count = 0
        self.migration_count = 0
        self.down_count = 0
        self.stopped: list[str] = []

    def verify(self) -> None:
        return None

    def services(self) -> dict[str, ComposeService]:
        return dict(self.state)

    def build(self) -> None:
        self.build_count += 1

    def up_postgres(self) -> None:
        self.state["postgres"] = ComposeService("postgres", "running", "healthy")

    def migrate(self) -> None:
        self.migration_count += 1
        if self.migration_fails:
            raise OperatorError("COMPOSE_FAILED", "migration failed")

    def up_api(self) -> None:
        self.state["api"] = ComposeService("api", "running", "healthy")

    def stop(self, *services: str) -> None:
        for service in services:
            self.stopped.append(service)
            self.state.pop(service, None)

    def down(self) -> None:
        self.down_count += 1
        self.state.clear()


class FakeWorker:
    def __init__(self) -> None:
        self.state = ComponentState.STOPPED
        self.start_count = 0
        self.stop_count = 0
        self.active_locks = 0
        self.maximum_locks = 0

    @contextmanager
    def lifecycle_lock(self):
        self.active_locks += 1
        self.maximum_locks = max(self.maximum_locks, self.active_locks)
        try:
            yield
        finally:
            self.active_locks -= 1

    def inspect(self) -> ComponentState:
        return self.state

    def start(self) -> None:
        self.start_count += 1
        self.state = ComponentState.RUNNING

    def stop(self) -> None:
        self.stop_count += 1
        self.state = ComponentState.STOPPED


def _ready(_settings: Settings, _timeout: float) -> ApiReadiness:
    return ApiReadiness(True, True, True)


def test_up_and_down_are_idempotent_and_manage_exactly_one_worker(tmp_path: Path) -> None:
    compose = FakeCompose()
    worker = FakeWorker()
    manager = OperatorManager(
        _settings(tmp_path),
        compose=compose,
        worker=worker,
        api_probe=_ready,
        host_scanner_check=lambda _settings: None,
        semgrep_check=lambda _settings: None,
    )

    assert manager.up().system_status is SystemState.READY
    assert manager.up().system_status is SystemState.READY
    assert worker.start_count == 1

    assert manager.down().system_status is SystemState.STOPPED
    assert manager.down().system_status is SystemState.STOPPED
    assert compose.down_count == 2


def test_migration_failure_rolls_back_only_new_database(tmp_path: Path) -> None:
    compose = FakeCompose(migration_fails=True)
    manager = OperatorManager(
        _settings(tmp_path),
        compose=compose,
        worker=FakeWorker(),
        api_probe=_ready,
        host_scanner_check=lambda _settings: None,
        semgrep_check=lambda _settings: None,
    )

    with pytest.raises(OperatorError, match="migration failed"):
        manager.up()

    assert compose.stopped == ["postgres"]


def test_up_fails_before_services_when_scanner_prerequisite_is_missing(
    tmp_path: Path,
) -> None:
    compose = FakeCompose()
    worker = FakeWorker()

    def fail(_settings: Settings) -> None:
        raise OperatorError(
            "SCANNER_PREREQUISITE_FAILED", "Gitleaks trusted runtime verification failed"
        )

    manager = OperatorManager(
        _settings(tmp_path),
        compose=compose,
        worker=worker,
        api_probe=_ready,
        host_scanner_check=fail,
        semgrep_check=lambda _settings: None,
    )

    with pytest.raises(OperatorError, match="Gitleaks trusted runtime"):
        manager.up()

    assert compose.build_count == 0
    assert compose.state == {}
    assert worker.start_count == 0


def test_preexisting_database_is_not_rolled_back_on_migration_failure(tmp_path: Path) -> None:
    compose = FakeCompose(migration_fails=True)
    compose.state["postgres"] = ComposeService("postgres", "running", "healthy")
    manager = OperatorManager(
        _settings(tmp_path),
        compose=compose,
        worker=FakeWorker(),
        api_probe=_ready,
        host_scanner_check=lambda _settings: None,
        semgrep_check=lambda _settings: None,
    )

    with pytest.raises(OperatorError):
        manager.up()

    assert compose.stopped == []


def test_api_readiness_timeout_never_reports_ready(tmp_path: Path) -> None:
    compose = FakeCompose()
    worker = FakeWorker()
    ticks = iter(range(100))
    manager = OperatorManager(
        _settings(tmp_path),
        compose=compose,
        worker=worker,
        api_probe=lambda _settings, _timeout: ApiReadiness(True, False, False),
        sleeper=lambda _seconds: None,
        clock=lambda: float(next(ticks)),
        host_scanner_check=lambda _settings: None,
        semgrep_check=lambda _settings: None,
    )

    with pytest.raises(OperatorError, match="health/ready"):
        manager.up()
    assert worker.start_count == 0
    assert compose.stopped == ["api", "postgres"]


def test_partial_status_is_degraded(tmp_path: Path) -> None:
    compose = FakeCompose()
    compose.state = {
        "postgres": ComposeService("postgres", "running", "healthy"),
        "api": ComposeService("api", "running", "unhealthy"),
    }
    manager = OperatorManager(
        _settings(tmp_path),
        compose=compose,
        worker=FakeWorker(),
        api_probe=lambda _settings, _timeout: ApiReadiness(True, False, False),
        host_scanner_check=lambda _settings: None,
        semgrep_check=lambda _settings: None,
    )

    status = manager.status()

    assert status.system_status is SystemState.DEGRADED
    assert status.database is ComponentState.READY
    assert status.api is ComponentState.UNREADY
    assert status.worker is ComponentState.STOPPED


def test_stale_identity_never_kills_unrelated_process(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o700)
    manager = WorkerProcessManager(settings)
    manager.prepare()
    environment = {
        **os.environ,
        "SECURESCAN_OPERATOR_DEPLOYMENT_ID": manager.deployment_sha256,
    }
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], env=environment
    )
    try:
        identity = _proc_identity(process.pid)
        assert identity is not None
        forged = identity.__class__(
            identity.pid,
            identity.start_ticks,
            identity.executable,
            "0" * 64,
            identity.deployment_sha256,
        )
        manager._write_stored(forged)

        with pytest.raises(OperatorError, match="Refusing to signal"):
            manager.stop()
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_worker_immediate_failure_is_actionable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o700)
    manager = WorkerProcessManager(settings)
    manager.prepare()

    class ExitedProcess:
        pid = 12345

        def poll(self) -> int:
            return 2

    monkeypatch.setattr(
        "securescan.operator.process.subprocess.Popen", lambda *_a, **_k: ExitedProcess()
    )
    monkeypatch.setattr("securescan.operator.process.time.sleep", lambda _seconds: None)

    with pytest.raises(OperatorError, match="exited during startup"):
        manager.start()


def test_forced_shutdown_reverifies_identity_before_sigkill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o700)
    manager = WorkerProcessManager(settings)
    manager.prepare()
    identity = WorkerIdentity(12345, "10", "/python", "a" * 64, manager.deployment_sha256)
    changed = WorkerIdentity(12345, "11", "/python", "a" * 64, manager.deployment_sha256)
    manager._write_stored(identity)
    identities = iter((identity, changed))
    signals: list[signal.Signals] = []
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(
        "securescan.operator.process._proc_identity", lambda *_args: next(identities)
    )
    monkeypatch.setattr(
        "securescan.operator.process.os.kill", lambda _pid, sent: signals.append(sent)
    )
    monkeypatch.setattr("securescan.operator.process.time.monotonic", lambda: next(ticks))

    with pytest.raises(OperatorError, match="identity changed"):
        manager.stop()

    assert signals == [signal.SIGTERM]


def test_verified_worker_receives_graceful_sigterm(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o700)
    manager = WorkerProcessManager(settings)
    manager.prepare()
    code = "import signal,time; signal.signal(signal.SIGTERM, lambda *_: exit(0)); time.sleep(60)"
    environment = {
        **os.environ,
        "SECURESCAN_OPERATOR_DEPLOYMENT_ID": manager.deployment_sha256,
    }
    process = subprocess.Popen([sys.executable, "-c", code], env=environment)
    try:
        time.sleep(0.1)
        identity = _proc_identity(process.pid)
        assert identity is not None
        manager._write_stored(identity)
        manager.stop()
        process.wait(timeout=5)
        assert process.returncode == 0
        assert not manager.identity_path.exists()
    finally:
        if process.poll() is None:
            process.kill()


def test_live_deployment_marker_parsing_is_exact_and_fail_closed() -> None:
    expected = "a" * 64
    assert (
        _deployment_marker(
            b"PATH=/usr/bin\0SECURESCAN_OPERATOR_DEPLOYMENT_ID="
            + expected.encode()
            + b"\0"
        )
        == expected
    )
    for malformed in (
        b"PATH=/usr/bin\0",
        b"SECURESCAN_OPERATOR_DEPLOYMENT_ID=bad\0",
        b"SECURESCAN_OPERATOR_DEPLOYMENT_ID=" + expected.encode(),
        b"BROKEN\0SECURESCAN_OPERATOR_DEPLOYMENT_ID=" + expected.encode() + b"\0",
        (
            b"SECURESCAN_OPERATOR_DEPLOYMENT_ID="
            + expected.encode()
            + b"\0SECURESCAN_OPERATOR_DEPLOYMENT_ID="
            + expected.encode()
            + b"\0"
        ),
    ):
        with pytest.raises(ValueError):
            _deployment_marker(malformed)


def test_live_process_missing_deployment_marker_is_stale_and_not_signaled(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o700)
    manager = WorkerProcessManager(settings)
    manager.prepare()
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        manager._write_stored(
            WorkerIdentity(
                pid=process.pid,
                start_ticks="1",
                executable=str(Path(sys.executable).resolve()),
                command_sha256="a" * 64,
                deployment_sha256=manager.deployment_sha256,
            )
        )

        assert manager.inspect() is ComponentState.STALE
        with pytest.raises(OperatorError, match="could not be verified"):
            manager.stop()
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_process_metadata_read_is_bounded(tmp_path: Path) -> None:
    metadata = tmp_path / "metadata"
    metadata.write_bytes(b"x" * 9)

    with pytest.raises(ValueError, match="exceeds"):
        _read_bounded_proc_file(metadata, 8)


def test_cross_deployment_worker_identity_never_signals_other_worker(
    tmp_path: Path,
) -> None:
    fake_root = tmp_path / "fake-module"
    package = fake_root / "securescan" / "cli"
    package.mkdir(parents=True)
    (fake_root / "securescan" / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "main.py").write_text(
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, lambda *_: exit(0))\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    settings_a = _settings(
        tmp_path / "a", operator_compose_project="deployment-a"
    )
    settings_b = _settings(
        tmp_path / "b", operator_compose_project="deployment-b"
    )
    settings_a.deploy_data_root.mkdir(mode=0o700, parents=True)
    settings_b.deploy_data_root.mkdir(mode=0o700, parents=True)
    manager_a = WorkerProcessManager(settings_a)
    manager_b = WorkerProcessManager(settings_b)
    manager_a.prepare()
    manager_b.prepare()
    argv = (sys.executable, "-m", "securescan.cli.main", "worker", "--json")

    def spawn(marker: str) -> subprocess.Popen[bytes]:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(fake_root),
            "SECURESCAN_OPERATOR_DEPLOYMENT_ID": marker,
        }
        return subprocess.Popen(
            argv,
            cwd=tmp_path,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    worker_a = spawn(manager_a.deployment_sha256)
    worker_b = spawn(manager_b.deployment_sha256)
    try:
        time.sleep(0.1)
        identity_a = _proc_identity(worker_a.pid)
        identity_b = _proc_identity(worker_b.pid)
        assert identity_a is not None and identity_b is not None
        assert identity_a.command_sha256 == identity_b.command_sha256
        assert identity_a.executable == identity_b.executable
        assert identity_a.deployment_sha256 != identity_b.deployment_sha256
        forged_a = WorkerIdentity(
            pid=identity_b.pid,
            start_ticks=identity_b.start_ticks,
            executable=identity_b.executable,
            command_sha256=identity_b.command_sha256,
            deployment_sha256=identity_a.deployment_sha256,
        )
        manager_a._write_stored(forged_a)

        with pytest.raises(OperatorError, match="Refusing to signal"):
            manager_a.stop()

        assert worker_a.poll() is None
        assert worker_b.poll() is None
    finally:
        for worker in (worker_a, worker_b):
            if worker.poll() is None:
                worker.terminate()
        for worker in (worker_a, worker_b):
            worker.wait(timeout=5)


def test_lifecycle_lock_serializes_concurrent_callers(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.deploy_data_root.mkdir(mode=0o700)
    first = WorkerProcessManager(settings)
    second = WorkerProcessManager(settings)
    active = 0
    maximum = 0
    guard = threading.Lock()

    def enter(manager: WorkerProcessManager) -> None:
        nonlocal active, maximum
        with manager.lifecycle_lock():
            with guard:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.1)
            with guard:
                active -= 1

    threads = [threading.Thread(target=enter, args=(item,)) for item in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert maximum == 1
    assert all(not thread.is_alive() for thread in threads)
    assert stat_mode(first.root) == 0o700
    assert stat_mode(first.lock_path) == 0o600


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
