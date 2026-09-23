from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class SystemState(StrEnum):
    READY = "READY"
    DEGRADED = "DEGRADED"
    STOPPED = "STOPPED"
    ERROR = "ERROR"


class ComponentState(StrEnum):
    READY = "READY"
    RUNNING = "RUNNING"
    STARTING = "STARTING"
    UNREADY = "UNREADY"
    STOPPED = "STOPPED"
    STALE = "STALE_WORKER_STATE"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class SystemStatus:
    system_status: SystemState
    database: ComponentState
    api: ComponentState
    schema: ComponentState
    worker: ComponentState
    ui_url: str

    def canonical_data(self) -> dict[str, Any]:
        return {
            "api": {
                "schema_at_head": self.schema is ComponentState.READY,
                "status": self.api.value,
            },
            "database": {"status": self.database.value},
            "system_status": self.system_status.value,
            "ui_url": self.ui_url,
            "worker": {"status": self.worker.value},
        }


class CheckState(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    status: CheckState
    detail: str

    def canonical_data(self) -> dict[str, str]:
        return {"detail": self.detail, "name": self.name, "status": self.status.value}


@dataclass(frozen=True, slots=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]

    @property
    def ready(self) -> bool:
        return all(check.status is not CheckState.FAIL for check in self.checks)

    def canonical_data(self) -> dict[str, Any]:
        return {
            "checks": [check.canonical_data() for check in self.checks],
            "result": "READY" if self.ready else "BLOCKED",
        }


class OperatorError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
