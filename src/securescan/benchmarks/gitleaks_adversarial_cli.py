from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from securescan.benchmarks.gitleaks_adversarial import (
    GITLEAKS_ADVERSARIAL_RESULT_PATH,
)
from securescan.benchmarks.gitleaks_adversarial_benchmark import (
    GitleaksAdversarialBenchmarkError,
    check_controlled_gitleaks_adversarial,
    record_gitleaks_adversarial_report,
    run_controlled_gitleaks_adversarial,
)


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "pyproject.toml").is_file():
        raise GitleaksAdversarialBenchmarkError
    return root


def _canonical_json(value: dict[str, object]) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        raise GitleaksAdversarialBenchmarkError from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("mode", choices=("check", "report", "record"))
    parser.add_argument("--gitleaks", required=True, type=Path)
    arguments = parser.parse_args(argv)
    executable_path = arguments.gitleaks
    if not executable_path.is_absolute():
        parser.error("--gitleaks must be an absolute path")

    root = repository_root()
    try:
        if arguments.mode == "check":
            os.write(
                1,
                _canonical_json(
                    check_controlled_gitleaks_adversarial(
                        root,
                        executable_path,
                    )
                ),
            )
            return 0
        report = run_controlled_gitleaks_adversarial(
            root,
            executable_path,
        )
        if arguments.mode == "report":
            os.write(1, report.canonical_json())
            return 0
        record_gitleaks_adversarial_report(root, report)
        print(f"recorded {GITLEAKS_ADVERSARIAL_RESULT_PATH}")
        return 0
    except GitleaksAdversarialBenchmarkError as exc:
        print(str(exc), file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
