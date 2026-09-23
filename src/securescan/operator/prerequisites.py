from __future__ import annotations

import subprocess

from securescan.config import Settings
from securescan.operator.compose import compose_environment
from securescan.operator.models import OperatorError
from securescan.scanners.checkov import create_default_checkov_binding
from securescan.scanners.gitleaks import create_default_gitleaks_binding
from securescan.scanners.semgrep import PRODUCTION_SEMGREP_IMAGE_REFERENCE
from securescan.scanners.syft import create_default_syft_binding
from securescan.source import EnryClient, TrustedEnryHelper


def verify_enry(settings: Settings) -> None:
    if settings.source_enry_helper_sha256 is None:
        raise OperatorError(
            "SCANNER_CONFIGURATION_INVALID", "Enry trusted SHA-256 is not configured"
        )
    try:
        EnryClient(
            TrustedEnryHelper(
                helper_path=settings.source_enry_helper_path,
                expected_sha256=settings.source_enry_helper_sha256,
            )
        ).verify_runtime()
    except OperatorError:
        raise
    except Exception:
        raise OperatorError(
            "SCANNER_PREREQUISITE_FAILED", "Enry trusted runtime verification failed"
        ) from None


def verify_gitleaks(settings: Settings) -> None:
    try:
        create_default_gitleaks_binding(
            settings.source_gitleaks_executable_path
        ).verify_runtime()
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
        create_default_checkov_binding(
            settings.source_checkov_executable_path
        ).verify_runtime()
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
