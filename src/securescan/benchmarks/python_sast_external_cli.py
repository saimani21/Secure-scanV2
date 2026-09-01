from __future__ import annotations

import argparse
from pathlib import Path

from securescan.benchmarks.python_sast_external import (
    acquire_external_sources,
    build_candidate_evidence,
    candidate_inventory_digest,
    load_source_lock,
    source_lock_digest,
    write_candidate_evidence,
)

_BENCHMARK_RELATIVE_ROOT = Path("benchmarks/python_sast_external")
_CACHE_RELATIVE_ROOT = Path(".cache/securescan-benchmarks")


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "pyproject.toml").is_file():
        raise RuntimeError("SecureScan repository root is invalid")
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("acquire", "verify"))
    arguments = parser.parse_args(argv)
    root = repository_root()
    benchmark_root = root / _BENCHMARK_RELATIVE_ROOT
    cache_root = root / _CACHE_RELATIVE_ROOT
    source_lock = load_source_lock(benchmark_root / "sources.lock.json")
    if arguments.mode == "acquire":
        acquire_external_sources(cache_root, source_lock)
    inventory, summary = build_candidate_evidence(cache_root, source_lock)
    write_candidate_evidence(
        benchmark_root / "candidates.json",
        benchmark_root / "candidate-summary.json",
        inventory,
        summary,
    )
    print(f"source_lock_digest={source_lock_digest(source_lock)}")
    print(f"candidate_inventory_digest={candidate_inventory_digest(inventory)}")
    print(f"full_candidate_count={summary['full_candidate_count']}")
    print(f"review_sample_count={summary['review_sample_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
