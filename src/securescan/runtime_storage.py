from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from securescan.config import Settings
from securescan.source.projection import (
    SourceProjectionError,
    SourceProjectionManager,
    SourceProjectionOwnershipError,
)

_PROTECTED_EXACT_ROOTS = (Path("/"), Path("/tmp"), Path("/var/tmp"))
_PROTECTED_ROOT_TREES = (
    Path("/dev"),
    Path("/etc"),
    Path("/proc"),
    Path("/root"),
    Path("/run"),
    Path("/sys"),
    Path("/var/run"),
)
_ROOT_NAMES = {
    "artifact": "artifacts",
    "workspace": "source-workspaces",
    "projection": "source-projections",
    "receipt": "source-runtime-receipts",
}


class RuntimeStorageInitializationError(RuntimeError):
    """A safe, actionable runtime-storage bootstrap failure."""

    def __init__(self, code: str, phase: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.phase = phase


@dataclass(frozen=True, slots=True)
class RuntimeStorageInitialization:
    deployment_root: Path | None
    artifact_root: Path
    workspace_root: Path
    projection_root: Path
    receipt_root: Path

    def canonical_data(self) -> dict[str, str | None]:
        return {
            "artifact_root": str(self.artifact_root),
            "deployment_root": (
                None if self.deployment_root is None else str(self.deployment_root)
            ),
            "projection_root": str(self.projection_root),
            "receipt_root": str(self.receipt_root),
            "status": "initialized",
            "workspace_root": str(self.workspace_root),
        }


def _failure(code: str, phase: str, message: str) -> RuntimeStorageInitializationError:
    return RuntimeStorageInitializationError(code, phase, message)


def _is_protected(path: Path) -> bool:
    return path in _PROTECTED_EXACT_ROOTS or any(
        path == protected or path.is_relative_to(protected) for protected in _PROTECTED_ROOT_TREES
    )


def _validate_no_symlink_ancestors(path: Path, *, phase: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise _failure(
                "RUNTIME_STORAGE_UNAVAILABLE",
                phase,
                "Runtime storage path metadata is unavailable",
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise _failure(
                "RUNTIME_STORAGE_PATH_UNSAFE",
                phase,
                "Runtime storage paths must not contain symbolic links",
            )


def _validate_path(path: Path, *, phase: str) -> None:
    if not path.is_absolute() or ".git" in path.parts or _is_protected(path):
        raise _failure(
            "RUNTIME_STORAGE_PATH_UNSAFE",
            phase,
            "Runtime storage path is not an allowed private location",
        )
    _validate_no_symlink_ancestors(path, phase=phase)


def _prepare_private_directory(
    path: Path,
    *,
    phase: str,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> Path:
    _validate_path(path, phase=phase)
    existed = os.path.lexists(path)
    try:
        if not existed:
            path.mkdir(mode=0o700, parents=True, exist_ok=False)
        metadata = path.stat(follow_symlinks=False)
    except (OSError, RuntimeError) as exc:
        raise _failure(
            "RUNTIME_STORAGE_UNAVAILABLE",
            phase,
            "Runtime storage directory could not be created or opened",
        ) from exc
    owner_uid = os.geteuid() if hasattr(os, "geteuid") else None
    owner_gid = os.getegid() if hasattr(os, "getegid") else None
    if expected_uid is not None:
        owner_uid = expected_uid
    if expected_gid is not None:
        owner_gid = expected_gid
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700)
        or (owner_uid is not None and metadata.st_uid != owner_uid)
        or (owner_gid is not None and metadata.st_gid != owner_gid)
    ):
        raise _failure(
            "RUNTIME_STORAGE_OWNERSHIP_INVALID",
            phase,
            "Runtime storage must be a private directory owned by the configured runtime identity",
        )
    return path


def _configured_roots(settings: Settings) -> dict[str, Path]:
    return {
        "artifact": settings.artifact_root,
        "workspace": settings.source_workspace_root,
        "projection": settings.source_projection_root,
        "receipt": settings.source_runtime_receipt_root,
    }


def _validate_deployment_topology(settings: Settings, root: Path) -> None:
    expected = {kind: root / name for kind, name in _ROOT_NAMES.items()}
    if _configured_roots(settings) != expected:
        raise _failure(
            "RUNTIME_STORAGE_CONFIGURATION_MISMATCH",
            "configuration",
            "Configured host runtime roots must be the standard children of the deployment root",
        )


def initialize_source_runtime_storage(
    settings: Settings,
    *,
    allow_empty_projection: bool = True,
) -> RuntimeStorageInitialization:
    """Create or validate all Source runtime roots through one trusted boundary."""

    if not isinstance(settings, Settings):
        raise _failure(
            "RUNTIME_STORAGE_CONFIGURATION_INVALID",
            "configuration",
            "Runtime storage configuration is invalid",
        )
    deployment_root = settings.deploy_data_root
    if deployment_root is not None:
        if hasattr(os, "geteuid") and (
            settings.runtime_uid != os.geteuid() or settings.runtime_gid != os.getegid()
        ):
            raise _failure(
                "RUNTIME_IDENTITY_MISMATCH",
                "deployment_storage",
                "Configured container UID and GID must match the user running initialization",
            )
        _validate_deployment_topology(settings, deployment_root)
        _prepare_private_directory(
            deployment_root,
            phase="deployment_storage",
            expected_uid=settings.runtime_uid,
            expected_gid=settings.runtime_gid,
        )

    _prepare_private_directory(settings.artifact_root, phase="artifact_storage")
    _prepare_private_directory(settings.source_workspace_root, phase="workspace_storage")
    _prepare_private_directory(
        settings.source_runtime_receipt_root,
        phase="runtime_receipt_storage",
    )
    try:
        if allow_empty_projection:
            projections = SourceProjectionManager.initialize_base_directory(
                settings.source_projection_root
            )
        else:
            projections = SourceProjectionManager(settings.source_projection_root)
    except SourceProjectionOwnershipError as exc:
        raise _failure(
            "PROJECTION_ROOT_OWNERSHIP_INVALID",
            "projection_storage",
            "Projection root ownership is invalid; run 'securescan init' and "
            "resolve any reported conflict",
        ) from exc
    except SourceProjectionError as exc:
        raise _failure(
            "PROJECTION_ROOT_UNAVAILABLE",
            "projection_storage",
            "Projection root could not be initialized safely",
        ) from exc

    return RuntimeStorageInitialization(
        deployment_root=deployment_root,
        artifact_root=settings.artifact_root,
        workspace_root=settings.source_workspace_root,
        projection_root=projections.base_directory,
        receipt_root=settings.source_runtime_receipt_root,
    )
