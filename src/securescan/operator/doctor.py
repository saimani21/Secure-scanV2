from __future__ import annotations

import os
import shutil
import socket
import stat
import subprocess
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from securescan.config import Settings
from securescan.operator.compose import ComposeClient, compose_environment
from securescan.operator.manager import validate_operator_settings
from securescan.operator.models import CheckState, DoctorCheck, DoctorReport, OperatorError
from securescan.operator.prerequisites import (
    verify_checkov,
    verify_enry,
    verify_gitleaks,
    verify_semgrep_image,
    verify_syft,
)


def _check(name: str, action: Callable[[], None], detail: str) -> DoctorCheck:
    try:
        action()
    except Exception:
        return DoctorCheck(name, CheckState.FAIL, f"{detail}; review the configured prerequisite")
    return DoctorCheck(name, CheckState.PASS, detail)


def _private_directory(path: Path) -> None:
    if not path.exists():
        return
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        raise ValueError


def _port_available(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", port))


def _migration_configuration(compose_file: Path) -> None:
    config_path = compose_file.parent / "alembic.ini"
    config = Config(str(config_path))
    script_location = config.get_main_option("script_location")
    if not script_location:
        raise ValueError
    location = Path(script_location)
    if not location.is_absolute():
        config.set_main_option("script_location", str((config_path.parent / location).resolve()))
    if not ScriptDirectory.from_config(config).get_heads():
        raise ValueError


class Doctor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.environment = compose_environment(settings)

    def _command(self, argv: tuple[str, ...], timeout: float = 15) -> None:
        result = subprocess.run(
            argv,
            cwd=self.settings.operator_compose_file.parent,
            env=self.environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError

    def run(self) -> DoctorReport:
        checks: list[DoctorCheck] = []
        checks.append(
            _check(
                "SecureScan configuration",
                lambda: validate_operator_settings(self.settings),
                "valid",
            )
        )
        checks.append(
            _check(
                "Runtime identity",
                lambda: (
                    None
                    if self.settings.runtime_uid == os.geteuid()
                    and self.settings.runtime_gid == os.getegid()
                    else (_ for _ in ()).throw(ValueError())
                ),
                "matches current user",
            )
        )
        roots = (
            ("Deployment root", self.settings.deploy_data_root),
            ("Artifact root", self.settings.artifact_root),
            ("Workspace root", self.settings.source_workspace_root),
            ("Projection root", self.settings.source_projection_root),
            ("Receipt root", self.settings.source_runtime_receipt_root),
        )
        for name, root in roots:
            if root is None:
                checks.append(DoctorCheck(name, CheckState.FAIL, "not configured"))
            elif root.exists():
                checks.append(
                    _check(name, lambda path=root: _private_directory(path), "private directory")
                )
            else:
                checks.append(DoctorCheck(name, CheckState.WARN, "will be created by system up"))

        docker = shutil.which("docker", path=self.environment.get("PATH"))
        if docker is None:
            checks.extend(
                (
                    DoctorCheck("Docker CLI", CheckState.FAIL, "not installed"),
                    DoctorCheck(
                        "Docker daemon", CheckState.FAIL, "cannot be checked without Docker CLI"
                    ),
                    DoctorCheck(
                        "Docker Compose", CheckState.FAIL, "cannot be checked without Docker CLI"
                    ),
                    DoctorCheck(
                        "Compose configuration",
                        CheckState.FAIL,
                        "cannot be checked without Docker CLI",
                    ),
                )
            )
        else:
            checks.append(DoctorCheck("Docker CLI", CheckState.PASS, "installed"))
            checks.append(
                _check("Docker daemon", lambda: self._command((docker, "info")), "reachable")
            )
            checks.append(
                _check(
                    "Docker Compose",
                    lambda: self._command((docker, "compose", "version")),
                    "available",
                )
            )
            checks.append(
                _check(
                    "Compose configuration",
                    lambda: ComposeClient(self.settings).verify(),
                    "valid",
                )
            )

        services = {}
        with suppress(OperatorError):
            services = ComposeClient(self.settings).services()
        for name, port, service_name in (
            ("PostgreSQL port", self.settings.postgres_port, "postgres"),
            ("API port", self.settings.api_port, "api"),
        ):
            service = services.get(service_name)
            if service is not None and service.state == "running":
                checks.append(DoctorCheck(name, CheckState.PASS, "used by configured deployment"))
            else:
                checks.append(_check(name, lambda value=port: _port_available(value), "available"))

        checks.append(
            _check(
                "Migration compatibility",
                lambda: _migration_configuration(self.settings.operator_compose_file),
                "migration graph is loadable",
            )
        )

        checks.append(
            _check(
                "Enry helper",
                lambda: verify_enry(self.settings),
                "trusted identity verified",
            )
        )
        checks.append(
            _check(
                "Gitleaks",
                lambda: verify_gitleaks(self.settings),
                "trusted runtime verified",
            )
        )
        checks.append(
            _check(
                "Syft",
                lambda: verify_syft(self.settings),
                "trusted runtime verified",
            )
        )
        checks.append(
            _check(
                "Checkov",
                lambda: verify_checkov(self.settings),
                "trusted runtime verified",
            )
        )
        if docker is None:
            checks.append(DoctorCheck("Semgrep", CheckState.FAIL, "Docker CLI is unavailable"))
        else:
            checks.append(
                _check(
                    "Semgrep",
                    lambda: verify_semgrep_image(self.settings),
                    "trusted pinned image available",
                )
            )
        return DoctorReport(tuple(checks))
