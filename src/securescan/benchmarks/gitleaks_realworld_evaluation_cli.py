from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

from securescan.benchmarks.gitleaks_realworld_contract import (
    GITLEAKS_REALWORLD_RESULT_PATH,
)
from securescan.benchmarks.gitleaks_realworld_evaluation import (
    GITLEAKS_REALWORLD_REPEATABILITY_PATH,
    GitleaksRealworldEvaluationError,
    run_and_record_gitleaks_realworld,
)


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "pyproject.toml").is_file():
        raise GitleaksRealworldEvaluationError
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("mode", choices=("record",))
    parser.add_argument("--gitleaks", required=True, type=Path)
    parser.add_argument("--retained-workspaces", required=True, type=Path)
    arguments = parser.parse_args(argv)
    if not arguments.gitleaks.is_absolute() or not arguments.retained_workspaces.is_absolute():
        parser.error("trusted paths must be absolute")
    root = repository_root()
    try:
        run1, repeatability = run_and_record_gitleaks_realworld(
            root,
            arguments.gitleaks,
            arguments.retained_workspaces,
        )
        run1_digest = hashlib.sha256(run1.canonical_json()).hexdigest()
        repeatability_digest = hashlib.sha256(
            repeatability.canonical_json()
        ).hexdigest()
        os.write(
            1,
            (
                f"recorded {GITLEAKS_REALWORLD_RESULT_PATH} {run1_digest}\n"
                f"recorded {GITLEAKS_REALWORLD_REPEATABILITY_PATH} "
                f"{repeatability_digest}\n"
            ).encode("ascii"),
        )
        return 0
    except GitleaksRealworldEvaluationError as exc:
        print(str(exc), file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
