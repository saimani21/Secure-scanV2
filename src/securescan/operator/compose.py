from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass

from securescan.config import Settings
from securescan.operator.models import OperatorError


@dataclass(frozen=True, slots=True)
class ComposeService:
    name: str
    state: str
    health: str


def compose_environment(settings: Settings) -> dict[str, str]:
    allowed_host = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "XDG_RUNTIME_DIR")
    environment = {key: os.environ[key] for key in allowed_host if key in os.environ}
    values: dict[str, object] = {
        "SECURESCAN_DATABASE_URL": settings.database_url,
        "SECURESCAN_DEPLOY_DATA_ROOT": settings.deploy_data_root or "",
        "SECURESCAN_RUNTIME_UID": settings.runtime_uid,
        "SECURESCAN_RUNTIME_GID": settings.runtime_gid,
        "SECURESCAN_ARTIFACT_ROOT": settings.artifact_root,
        "SECURESCAN_SOURCE_WORKSPACE_ROOT": settings.source_workspace_root,
        "SECURESCAN_SOURCE_PROJECTION_ROOT": settings.source_projection_root,
        "SECURESCAN_SOURCE_RUNTIME_RECEIPT_ROOT": settings.source_runtime_receipt_root,
        "SECURESCAN_HMAC_KEY": settings.hmac_key,
        "SECURESCAN_MAX_OUTPUT_BYTES": settings.max_output_bytes,
        "SECURESCAN_DEFAULT_TIMEOUT_SECONDS": settings.default_timeout_seconds,
        "SECURESCAN_POSTGRES_DB": settings.postgres_db,
        "SECURESCAN_POSTGRES_USER": settings.postgres_user,
        "SECURESCAN_POSTGRES_PASSWORD": settings.postgres_password,
        "SECURESCAN_POSTGRES_PORT": settings.postgres_port,
        "SECURESCAN_API_PORT": settings.api_port,
        "SECURESCAN_IMAGE_TAG": settings.operator_compose_project,
    }
    environment.update({key: str(value) for key, value in values.items()})
    return environment


class ComposeClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.environment = compose_environment(settings)
        self.base = (
            "docker",
            "compose",
            "--project-name",
            settings.operator_compose_project,
            "--file",
            str(settings.operator_compose_file),
        )

    def _run(
        self, *arguments: str, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                (*self.base, *arguments),
                cwd=self.settings.operator_compose_file.parent,
                env=self.environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout or self.settings.operator_startup_timeout_seconds,
                check=False,
            )
        except FileNotFoundError:
            raise OperatorError("DOCKER_CLI_MISSING", "Docker CLI is not installed") from None
        except subprocess.TimeoutExpired:
            raise OperatorError("COMPOSE_TIMEOUT", "Docker Compose operation timed out") from None
        if result.returncode != 0:
            raise OperatorError(
                "COMPOSE_FAILED",
                "Docker Compose operation failed; run 'securescan doctor' for details",
            )
        return result

    def verify(self) -> None:
        if shutil.which("docker", path=self.environment.get("PATH")) is None:
            raise OperatorError("DOCKER_CLI_MISSING", "Docker CLI is not installed")
        self._run("version", timeout=10)
        self._run("config", "--quiet", timeout=15)

    def build(self) -> None:
        self._run("build", "migrate", "api")

    def up_postgres(self) -> None:
        self._run("up", "--detach", "postgres")

    def migrate(self) -> None:
        self._run("run", "--rm", "migrate")

    def up_api(self) -> None:
        self._run("up", "--detach", "--no-deps", "api")

    def stop(self, *services: str) -> None:
        if services:
            self._run("stop", *services)

    def down(self) -> None:
        self._run("down", "--remove-orphans")

    def services(self) -> dict[str, ComposeService]:
        result = self._run("ps", "--all", "--format", "json", timeout=15)
        text = result.stdout.strip()
        if not text:
            return {}
        try:
            payload = json.loads(text)
            rows = payload if isinstance(payload, list) else [payload]
        except json.JSONDecodeError:
            try:
                rows = [json.loads(line) for line in text.splitlines()]
            except json.JSONDecodeError as exc:
                raise OperatorError(
                    "COMPOSE_STATUS_INVALID", "Docker Compose status is invalid"
                ) from exc
        services: dict[str, ComposeService] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("Service", ""))
            if name:
                services[name] = ComposeService(
                    name=name,
                    state=str(row.get("State", "")).lower(),
                    health=str(row.get("Health", "")).lower(),
                )
        return services
