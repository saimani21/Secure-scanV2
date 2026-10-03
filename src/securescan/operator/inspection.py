from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from securescan.config import Settings
from securescan.operator.models import OperatorError
from securescan.operator.prerequisites import (
    verify_checkov,
    verify_enry,
    verify_gitleaks,
    verify_semgrep_image,
    verify_syft,
)
from securescan.operator.profile import operator_profile_path
from securescan.scanners.semgrep import PRODUCTION_SEMGREP_IMAGE_REFERENCE


def _path_state(path: Path) -> str:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return "MISSING"
    except PermissionError:
        return "UNREADABLE"
    except OSError:
        return "UNTRUSTED"
    if not stat.S_ISREG(metadata.st_mode):
        return "UNTRUSTED"
    if not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        return "NOT_EXECUTABLE"
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return "UNTRUSTED"
    return "EXECUTABLE"


def _identity_state(action: Callable[[], None]) -> str:
    try:
        action()
    except OperatorError as exc:
        if exc.code in {"SCANNER_CONFIGURATION_INVALID", "SCANNER_PREREQUISITE_MISSING"}:
            return "MISSING"
        if exc.code == "SCANNER_IDENTITY_MISMATCH":
            return "MISMATCH"
        if exc.code == "SCANNER_PREREQUISITE_UNREADABLE":
            return "UNREADABLE"
        return "UNTRUSTED"
    except Exception:
        return "UNTRUSTED"
    return "VALID"


def operator_configuration_data(settings: Settings) -> dict[str, Any]:
    profile = operator_profile_path()
    scanner_paths = (
        ("enry", settings.source_enry_helper_path, verify_enry),
        ("gitleaks", settings.source_gitleaks_executable_path, verify_gitleaks),
        ("syft", settings.source_syft_executable_path, verify_syft),
        ("checkov", settings.source_checkov_executable_path, verify_checkov),
    )
    scanners: dict[str, dict[str, Any]] = {}
    for name, path, verifier in scanner_paths:
        scanners[name] = {
            "path": str(path),
            "path_state": _path_state(path),
            "trusted_identity_state": _identity_state(lambda check=verifier: check(settings)),
        }
    scanners["semgrep"] = {
        "image": PRODUCTION_SEMGREP_IMAGE_REFERENCE,
        "trusted_identity_state": _identity_state(lambda: verify_semgrep_image(settings)),
    }
    return {
        "deployment": {
            "api_port": settings.api_port,
            "compose_file": str(settings.operator_compose_file),
            "compose_project": settings.operator_compose_project,
            "image_tag": settings.operator_compose_project,
            "postgres_port": settings.postgres_port,
        },
        "operator_profile": {
            "exists": os.path.lexists(profile),
            "format": "securescan-json-v1",
            "load": "automatic",
            "path": str(profile),
        },
        "scanners": scanners,
        "storage": {
            "artifact_root": str(settings.artifact_root),
            "deployment_root": (
                None if settings.deploy_data_root is None else str(settings.deploy_data_root)
            ),
            "projection_root": str(settings.source_projection_root),
            "receipt_root": str(settings.source_runtime_receipt_root),
            "workspace_root": str(settings.source_workspace_root),
        },
    }
