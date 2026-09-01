from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from securescan.benchmarks.python_sast import (
    EXPECTED_SCANNER_VERSION,
    FROZEN_CORPUS_DIGEST,
    FROZEN_RULESET_DIGEST,
    FROZEN_RULESET_ID,
    FROZEN_RULESET_VERSION,
    SCANNER_ID,
    canonical_benchmark_report,
    load_benchmark_manifest,
    run_frozen_semgrep_benchmark,
)

_MANIFEST_RELATIVE_PATH = Path("benchmarks/python_sast/manifest.json")
_CONTROLLED_REPORT_RELATIVE_PATH = Path(
    "benchmarks/python_sast/initial-v0.3e-baseline.json"
)


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "pyproject.toml").is_file():
        raise RuntimeError("SecureScan repository root is invalid")
    return root


def benchmark_report(root: Path) -> bytes:
    manifest = load_benchmark_manifest(root / _MANIFEST_RELATIVE_PATH)
    evaluation = run_frozen_semgrep_benchmark(root, manifest)
    if (
        evaluation.scanner_id != SCANNER_ID
        or evaluation.scanner_version != EXPECTED_SCANNER_VERSION
        or manifest.ruleset_id != FROZEN_RULESET_ID
        or manifest.ruleset_version != FROZEN_RULESET_VERSION
        or manifest.ruleset_digest != FROZEN_RULESET_DIGEST
        or manifest.corpus_digest != FROZEN_CORPUS_DIGEST
    ):
        raise RuntimeError("Controlled Python SAST benchmark identity is invalid")
    return canonical_benchmark_report(evaluation)


def record_report(path: Path, payload: bytes) -> bool:
    if not isinstance(path, Path) or not isinstance(payload, bytes) or not payload:
        raise ValueError("Controlled Python SAST benchmark report is invalid")
    if path.exists():
        if path.is_file() and not path.is_symlink() and path.read_bytes() == payload:
            return False
        raise FileExistsError("Controlled Python SAST benchmark report already exists")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".python-sast-baseline-",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary_path, 0o644)
        os.link(temporary_path, path, follow_symlinks=False)
    finally:
        temporary_path.unlink(missing_ok=True)
    return True


def _check_lines(root: Path) -> tuple[str, ...]:
    manifest = load_benchmark_manifest(root / _MANIFEST_RELATIVE_PATH)
    return (
        f"expected_scanner={SCANNER_ID} version={EXPECTED_SCANNER_VERSION}",
        f"ruleset={manifest.ruleset_id} version={manifest.ruleset_version} "
        f"digest={manifest.ruleset_digest}",
        f"corpus_digest={manifest.corpus_digest}",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("mode", choices=("check", "report", "record"))
    arguments = parser.parse_args(argv)
    root = repository_root()
    if arguments.mode == "check":
        print("\n".join(_check_lines(root)))
        return 0
    payload = benchmark_report(root)
    if arguments.mode == "report":
        os.write(1, payload)
        return 0
    path = root / _CONTROLLED_REPORT_RELATIVE_PATH
    created = record_report(path, payload)
    state = "recorded" if created else "already-recorded"
    print(f"{state} {_CONTROLLED_REPORT_RELATIVE_PATH.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
