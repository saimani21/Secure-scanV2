from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROFILE_VERSION = 1


class OperatorProfileError(RuntimeError):
    """Raised when the persistent operator profile is unsafe or invalid."""


def operator_profile_path() -> Path:
    override = os.environ.get("SECURESCAN_OPERATOR_PROFILE")
    if override:
        return Path(os.path.abspath(Path(override).expanduser()))
    configured = Path(os.environ.get("XDG_CONFIG_HOME", "")).expanduser()
    root = configured if configured.is_absolute() else Path.home() / ".config"
    return root / "securescan" / "operator.json"


def _private_regular_file(path: Path) -> bool:
    metadata = os.lstat(path)
    return (
        stat.S_ISREG(metadata.st_mode)
        and not metadata.st_mode & 0o077
        and metadata.st_uid == os.geteuid()
    )


def _private_directory(path: Path) -> bool:
    metadata = os.lstat(path)
    return (
        stat.S_ISDIR(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and metadata.st_uid == os.geteuid()
    )


def read_operator_profile() -> dict[str, Any]:
    path = operator_profile_path()
    if not os.path.lexists(path):
        return {}
    try:
        if not _private_directory(path.parent) or not _private_regular_file(path):
            raise OperatorProfileError("Operator profile permissions are unsafe")
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            current.st_dev,
            current.st_ino,
        ):
            os.close(descriptor)
            raise OperatorProfileError("Operator profile permissions are unsafe")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except OperatorProfileError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise OperatorProfileError("Operator profile is unreadable") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("profile_version") != PROFILE_VERSION
        or not isinstance(payload.get("settings"), dict)
    ):
        raise OperatorProfileError("Operator profile format is invalid")
    settings = payload["settings"]
    if any(not isinstance(key, str) for key in settings):
        raise OperatorProfileError("Operator profile format is invalid")
    return dict(settings)


def write_operator_profile(settings: Mapping[str, object]) -> Path:
    path = operator_profile_path()
    try:
        if os.path.lexists(path.parent):
            if not _private_directory(path.parent):
                raise OperatorProfileError(
                    "Operator profile directory permissions are unsafe"
                )
        else:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
        if not _private_directory(path.parent):
            raise OperatorProfileError("Operator profile directory permissions are unsafe")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".operator-", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            payload = {"profile_version": PROFILE_VERSION, "settings": dict(settings)}
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        finally:
            if temporary.exists():
                temporary.unlink()
    except OperatorProfileError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise OperatorProfileError("Operator profile could not be written") from exc
    return path


def parse_operator_env_file(path: Path) -> dict[str, str]:
    """Parse a deliberately small KEY=VALUE format; never execute shell syntax."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise OperatorProfileError("Configuration file is unreadable") from exc
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line or line.startswith("export "):
            raise OperatorProfileError(f"Configuration line {line_number} must use KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key.startswith("SECURESCAN_") or not key.replace("_", "").isalnum():
            raise OperatorProfileError(f"Configuration line {line_number} has an unsupported key")
        if value[:1] in {'"', "'"}:
            if len(value) < 2 or value[-1] != value[0]:
                raise OperatorProfileError(f"Configuration line {line_number} has invalid quoting")
            value = value[1:-1]
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise OperatorProfileError(
                f"Configuration line {line_number} contains control characters"
            )
        field = key.removeprefix("SECURESCAN_").lower()
        if field in values:
            raise OperatorProfileError(
                f"Configuration line {line_number} duplicates a setting"
            )
        values[field] = value
    return values
