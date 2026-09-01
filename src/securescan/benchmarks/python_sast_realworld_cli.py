from __future__ import annotations

import argparse
import json
from pathlib import Path

from securescan.benchmarks.python_sast_realworld import acquire, verify


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "pyproject.toml").is_file():
        raise RuntimeError("SecureScan repository root is invalid")
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("acquire", "verify", "summary"))
    arguments = parser.parse_args(argv)
    root = repository_root()
    benchmark_root = root / "benchmarks/python_sast_realworld"
    cache_root = root / ".cache/securescan-realworld-python"
    if arguments.mode == "acquire":
        summary = acquire(benchmark_root, cache_root)
    else:
        summary = verify(benchmark_root, cache_root)
    if arguments.mode == "summary":
        print(json.dumps(summary, allow_nan=False, separators=(",", ":"), sort_keys=True))
    else:
        print(f"accepted_case_set_digest={summary['accepted_case_set_digest']}")
        print(f"reviewed_candidate_count={summary['reviewed_candidate_count']}")
        print(f"accepted_case_count={summary['accepted_case_count']}")
        print(f"deferred_candidate_count={summary['deferred_candidate_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
