#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from securescan.execution import CancellableProcessExecutor, CancellableProcessResult
from securescan.scanners.gitleaks import create_default_gitleaks_binding

PASS_STATUS = "PINNED_BINARY_FUNCTIONALITY_SENTINEL_PASS"
_SENTINEL_PREFIX = "ghp_"
_SENTINEL_SUFFIX = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
_TEMPORARY_ROOT = Path("/tmp")


class GitleaksFunctionalitySentinelError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Pinned Gitleaks functionality sentinel failed")


def _wait_for_result(
    executor: CancellableProcessExecutor,
    request_root: Path,
    executable_path: Path,
) -> CancellableProcessResult:
    binding = create_default_gitleaks_binding(executable_path)
    request = binding.build_current_snapshot_request(request_root)
    result: CancellableProcessResult | None = None
    try:
        with executor.start(request) as handle:
            result = handle.wait(request.timeout_seconds + 2)
    except Exception:
        raise GitleaksFunctionalitySentinelError from None
    if result is None:
        raise GitleaksFunctionalitySentinelError
    return result


def _json_findings(result: CancellableProcessResult) -> list[object]:
    try:
        document = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GitleaksFunctionalitySentinelError from None
    if not isinstance(document, list):
        raise GitleaksFunctionalitySentinelError
    return document


def verify_pinned_binary_functionality(executable_path: Path) -> str:
    binding = create_default_gitleaks_binding(executable_path)
    executor = CancellableProcessExecutor()
    try:
        binding.verify_runtime(executor)
    except Exception:
        raise GitleaksFunctionalitySentinelError from None

    token = _SENTINEL_PREFIX + _SENTINEL_SUFFIX
    if len(_SENTINEL_SUFFIX) != 36 or len(token) != 40:
        raise GitleaksFunctionalitySentinelError

    try:
        with (
            tempfile.TemporaryDirectory(
                prefix="securescan-gitleaks-positive-",
                dir=_TEMPORARY_ROOT,
            ) as positive_name,
            tempfile.TemporaryDirectory(
                prefix="securescan-gitleaks-empty-",
                dir=_TEMPORARY_ROOT,
            ) as empty_name,
        ):
            positive_root = Path(positive_name)
            empty_root = Path(empty_name)
            (positive_root / "sentinel.txt").write_text(
                f'synthetic_github_pat = "{token}"\n',
                encoding="utf-8",
            )
            positive = _wait_for_result(executor, positive_root, executable_path)
            empty = _wait_for_result(executor, empty_root, executable_path)
    except GitleaksFunctionalitySentinelError:
        raise
    except (OSError, UnicodeError):
        raise GitleaksFunctionalitySentinelError from None

    token_bytes = token.encode("ascii")
    if (
        positive.return_code != 1
        or positive.timed_out
        or positive.output_limit_exceeded
        or token_bytes in positive.stdout
        or token_bytes in positive.stderr
        or empty.return_code != 0
        or empty.stderr
        or empty.timed_out
        or empty.output_limit_exceeded
    ):
        raise GitleaksFunctionalitySentinelError

    positive_findings = _json_findings(positive)
    empty_findings = _json_findings(empty)
    github_findings = [
        finding
        for finding in positive_findings
        if isinstance(finding, dict) and finding.get("RuleID") == "github-pat"
    ]
    if (
        not github_findings
        or any(finding.get("Secret") != "REDACTED" for finding in github_findings)
        or empty_findings
    ):
        raise GitleaksFunctionalitySentinelError
    return PASS_STATUS


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the pinned Linux x64 Gitleaks functionality sentinel.",
    )
    parser.add_argument(
        "--gitleaks",
        required=True,
        type=Path,
        help="Absolute path to the pre-provisioned trusted Gitleaks executable.",
    )
    arguments = parser.parse_args()
    try:
        status = verify_pinned_binary_functionality(arguments.gitleaks)
    except GitleaksFunctionalitySentinelError as exc:
        parser.exit(1, f"{exc}\n")
    print(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
