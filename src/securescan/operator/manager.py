from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass

from sqlalchemy.engine import make_url

from securescan.config import Settings
from securescan.operator.compose import ComposeClient, ComposeService
from securescan.operator.models import ComponentState, OperatorError, SystemState, SystemStatus
from securescan.operator.prerequisites import verify_host_scanners, verify_semgrep_image
from securescan.operator.process import WorkerProcessManager
from securescan.runtime_storage import (
    RuntimeStorageInitializationError,
    initialize_source_runtime_storage,
)


@dataclass(frozen=True, slots=True)
class ApiReadiness:
    reachable: bool
    ready: bool
    schema_at_head: bool


def validate_operator_settings(settings: Settings) -> None:
    if settings.deploy_data_root is None:
        raise OperatorError("CONFIGURATION_MISSING", "SECURESCAN_DEPLOY_DATA_ROOT is required")
    if not settings.postgres_db or not settings.postgres_user or not settings.postgres_password:
        raise OperatorError("CONFIGURATION_MISSING", "PostgreSQL configuration is incomplete")
    if settings.hmac_key == "development-only-key":
        raise OperatorError("CONFIGURATION_MISSING", "A non-default HMAC key is required")
    if not settings.operator_compose_file.is_file():
        raise OperatorError("CONFIGURATION_INVALID", "Compose configuration is unavailable")
    try:
        url = make_url(settings.database_url)
    except Exception:
        raise OperatorError("CONFIGURATION_INVALID", "Database configuration is invalid") from None
    if not url.drivername.startswith("postgresql"):
        raise OperatorError("CONFIGURATION_INVALID", "Host worker database must use PostgreSQL")
    if (
        url.username != settings.postgres_user
        or url.password != settings.postgres_password
        or url.database != settings.postgres_db
        or (url.port or 5432) != settings.postgres_port
        or url.host not in {"127.0.0.1", "localhost"}
    ):
        raise OperatorError(
            "CONFIGURATION_INVALID",
            "Host worker database configuration does not match the Compose deployment",
        )
    if re.fullmatch(r"[A-Za-z0-9._~-]+", settings.postgres_password) is None:
        raise OperatorError(
            "CONFIGURATION_INVALID",
            "PostgreSQL password must use URL-unreserved characters",
        )


def probe_api(settings: Settings, timeout: float = 2.0) -> ApiReadiness:
    request = urllib.request.Request(
        f"http://127.0.0.1:{settings.api_port}/health/ready",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(64 * 1024))
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read(64 * 1024))
        except (ValueError, OSError):
            return ApiReadiness(True, False, False)
    except (OSError, ValueError):
        return ApiReadiness(False, False, False)
    if not isinstance(payload, dict):
        return ApiReadiness(True, False, False)
    return ApiReadiness(
        True,
        payload.get("status") == "ready" and payload.get("schema_at_head") is True,
        payload.get("schema_at_head") is True,
    )


class OperatorManager:
    def __init__(
        self,
        settings: Settings,
        *,
        compose: ComposeClient | None = None,
        worker: WorkerProcessManager | None = None,
        api_probe: Callable[[Settings, float], ApiReadiness] = probe_api,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        host_scanner_check: Callable[[Settings], None] = verify_host_scanners,
        semgrep_check: Callable[[Settings], None] = verify_semgrep_image,
    ) -> None:
        self.settings = settings
        self.compose = compose or ComposeClient(settings)
        self.worker = worker or WorkerProcessManager(settings)
        self.api_probe = api_probe
        self.sleeper = sleeper
        self.clock = clock
        self.host_scanner_check = host_scanner_check
        self.semgrep_check = semgrep_check

    @property
    def ui_url(self) -> str:
        return f"http://127.0.0.1:{self.settings.api_port}"

    @staticmethod
    def _running(service: ComposeService | None) -> bool:
        return service is not None and service.state == "running"

    def _wait_database(self) -> None:
        deadline = self.clock() + self.settings.operator_startup_timeout_seconds
        while self.clock() < deadline:
            service = self.compose.services().get("postgres")
            if self._running(service) and service is not None and service.health == "healthy":
                return
            if service is not None and service.state in {"exited", "dead"}:
                break
            self.sleeper(0.5)
        raise OperatorError("POSTGRES_HEALTH_TIMEOUT", "PostgreSQL did not become healthy")

    def _wait_api(self) -> None:
        deadline = self.clock() + self.settings.operator_startup_timeout_seconds
        while self.clock() < deadline:
            readiness = self.api_probe(self.settings, 2.0)
            if readiness.ready and readiness.schema_at_head:
                return
            service = self.compose.services().get("api")
            if service is not None and service.state in {"exited", "dead"}:
                break
            self.sleeper(0.5)
        raise OperatorError("API_READINESS_TIMEOUT", "API did not satisfy /health/ready")

    def up(self) -> SystemStatus:
        validate_operator_settings(self.settings)
        self.host_scanner_check(self.settings)
        try:
            initialize_source_runtime_storage(self.settings)
        except RuntimeStorageInitializationError as exc:
            raise OperatorError(exc.code, str(exc)) from None
        with self.worker.lifecycle_lock():
            self.compose.verify()
            self.semgrep_check(self.settings)
            before = self.compose.services()
            database_was_running = self._running(before.get("postgres"))
            api_was_running = self._running(before.get("api"))
            worker_was_running = self.worker.inspect() is ComponentState.RUNNING
            started_database = False
            started_api = False
            started_worker = False
            try:
                if not database_was_running or not api_was_running:
                    self.compose.build()
                if not database_was_running:
                    self.compose.up_postgres()
                    started_database = True
                self._wait_database()
                self.compose.migrate()
                if not api_was_running:
                    self.compose.up_api()
                    started_api = True
                self._wait_api()
                if not worker_was_running:
                    self.worker.start()
                    started_worker = True
                status = self.status()
                if status.system_status is not SystemState.READY:
                    raise OperatorError("SYSTEM_NOT_READY", "SecureScan did not reach READY")
                return status
            except Exception:
                # Roll back only resources this invocation started; persistent
                # volumes and all pre-existing services remain untouched.
                if started_worker:
                    with suppress(OperatorError):
                        self.worker.stop()
                if started_api:
                    with suppress(OperatorError):
                        self.compose.stop("api")
                if started_database:
                    with suppress(OperatorError):
                        self.compose.stop("postgres")
                raise

    def down(self) -> SystemStatus:
        validate_operator_settings(self.settings)
        with self.worker.lifecycle_lock():
            self.worker.stop()
            self.compose.down()
        return self.status()

    def status(self) -> SystemStatus:
        worker = self.worker.inspect()
        try:
            services = self.compose.services()
            postgres = services.get("postgres")
            if self._running(postgres):
                database = (
                    ComponentState.READY
                    if postgres is not None and postgres.health == "healthy"
                    else ComponentState.STARTING
                )
            else:
                database = ComponentState.STOPPED
            api_service = services.get("api")
            if self._running(api_service):
                readiness = self.api_probe(self.settings, 2.0)
                api = ComponentState.READY if readiness.ready else ComponentState.UNREADY
                schema = (
                    ComponentState.READY if readiness.schema_at_head else ComponentState.UNREADY
                )
            else:
                api = ComponentState.STOPPED
                schema = ComponentState.UNKNOWN
        except OperatorError:
            database = ComponentState.ERROR
            api = ComponentState.ERROR
            schema = ComponentState.UNKNOWN
        if (
            database is ComponentState.READY
            and api is ComponentState.READY
            and schema is ComponentState.READY
            and worker is ComponentState.RUNNING
        ):
            overall = SystemState.READY
        elif (
            database is ComponentState.STOPPED
            and api is ComponentState.STOPPED
            and worker is ComponentState.STOPPED
        ):
            overall = SystemState.STOPPED
        elif ComponentState.ERROR in {database, api} or worker is ComponentState.STALE:
            overall = SystemState.ERROR
        else:
            overall = SystemState.DEGRADED
        return SystemStatus(overall, database, api, schema, worker, self.ui_url)
