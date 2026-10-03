from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path

from securescan.config import Settings
from securescan.operator.compose import compose_environment
from securescan.operator.models import OperatorError
from securescan.scanners.checkov import create_default_checkov_binding
from securescan.scanners.gitleaks import create_default_gitleaks_binding
from securescan.scanners.semgrep import PRODUCTION_SEMGREP_IMAGE_REFERENCE
from securescan.scanners.syft import create_default_syft_binding
from securescan.source import EnryClient, EnryHelperIntegrityError, TrustedEnryHelper


def _safe_path(path: Path) -> str:
    rendered = str(path)
    if any(ord(character) < 32 or ord(character) == 127 for character in rendered):
        return "<configured path>"
    return rendered


def _verify_enry_file_before_runtime(path: Path, expected_sha256: str) -> None:
    """Classify stable operator errors without weakening the runtime verifier."""

    safe_path = _safe_path(path)
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        raise OperatorError(
            "SCANNER_PREREQUISITE_MISSING",
            f"Enry helper executable not found at {safe_path}",
        ) from None
    except PermissionError:
        raise OperatorError(
            "SCANNER_PREREQUISITE_UNREADABLE",
            f"Enry helper executable is unreadable at {safe_path}",
        ) from None
    except OSError:
        raise OperatorError(
            "SCANNER_PREREQUISITE_UNTRUSTED",
            "Enry helper path could not be trusted",
        ) from None

    executable_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    if not stat.S_ISREG(before.st_mode) or not before.st_mode & executable_bits:
        raise OperatorError(
            "SCANNER_PREREQUISITE_UNTRUSTED",
            "Enry helper is not a trusted regular executable",
        )
    if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise OperatorError(
            "SCANNER_PREREQUISITE_UNTRUSTED",
            "Enry helper permissions are untrusted",
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size) != (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
            ):
                raise OperatorError(
                    "SCANNER_PREREQUISITE_UNTRUSTED",
                    "Enry helper changed during trusted identity inspection",
                )
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 64 * 1024):
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise OperatorError(
                    "SCANNER_PREREQUISITE_UNTRUSTED",
                    "Enry helper changed during trusted identity inspection",
                )
        finally:
            os.close(descriptor)
    except OperatorError:
        raise
    except FileNotFoundError:
        raise OperatorError(
            "SCANNER_PREREQUISITE_MISSING",
            f"Enry helper executable not found at {safe_path}",
        ) from None
    except PermissionError:
        raise OperatorError(
            "SCANNER_PREREQUISITE_UNREADABLE",
            f"Enry helper executable is unreadable at {safe_path}",
        ) from None
    except OSError:
        raise OperatorError(
            "SCANNER_PREREQUISITE_UNTRUSTED",
            "Enry helper path could not be trusted",
        ) from None

    if digest.hexdigest() != expected_sha256:
        raise OperatorError(
            "SCANNER_IDENTITY_MISMATCH",
            "Configured Enry helper digest does not match the trusted release identity",
        )


def verify_enry(settings: Settings) -> None:
    if settings.source_enry_helper_sha256 is None:
        raise OperatorError(
            "SCANNER_CONFIGURATION_INVALID", "Enry trusted SHA-256 is not configured"
        )
    _verify_enry_file_before_runtime(
        settings.source_enry_helper_path,
        settings.source_enry_helper_sha256,
    )
    try:
        EnryClient(
            TrustedEnryHelper(
                helper_path=settings.source_enry_helper_path,
                expected_sha256=settings.source_enry_helper_sha256,
            )
        ).verify_runtime()
    except EnryHelperIntegrityError:
        raise OperatorError(
            "SCANNER_PREREQUISITE_UNTRUSTED",
            "Enry helper changed or became untrusted during runtime verification",
        ) from None
    except Exception:
        raise OperatorError(
            "SCANNER_PREREQUISITE_FAILED", "Enry trusted runtime verification failed"
        ) from None


def verify_gitleaks(settings: Settings) -> None:
    try:
        create_default_gitleaks_binding(settings.source_gitleaks_executable_path).verify_runtime()
    except Exception:
        raise OperatorError(
            "SCANNER_PREREQUISITE_FAILED", "Gitleaks trusted runtime verification failed"
        ) from None


def verify_syft(settings: Settings) -> None:
    try:
        create_default_syft_binding(settings.source_syft_executable_path).verify_runtime()
    except Exception:
        raise OperatorError(
            "SCANNER_PREREQUISITE_FAILED", "Syft trusted runtime verification failed"
        ) from None


def verify_checkov(settings: Settings) -> None:
    try:
        create_default_checkov_binding(settings.source_checkov_executable_path).verify_runtime()
    except Exception:
        raise OperatorError(
            "SCANNER_PREREQUISITE_FAILED", "Checkov trusted runtime verification failed"
        ) from None


def verify_host_scanners(settings: Settings) -> None:
    verify_enry(settings)
    verify_gitleaks(settings)
    verify_syft(settings)
    verify_checkov(settings)


def verify_semgrep_image(settings: Settings) -> None:
    try:
        result = subprocess.run(
            ("docker", "image", "inspect", PRODUCTION_SEMGREP_IMAGE_REFERENCE),
            cwd=settings.operator_compose_file.parent,
            env=compose_environment(settings),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        result = None
    if result is None or result.returncode != 0:
        raise OperatorError(
            "SCANNER_PREREQUISITE_FAILED", "Semgrep trusted pinned image is unavailable"
        )
