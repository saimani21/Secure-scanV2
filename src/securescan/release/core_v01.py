from __future__ import annotations

import argparse
import os
import tempfile
from contextlib import suppress
from pathlib import Path

from securescan.release.benchmark import CoreV01ReleaseEvaluator
from securescan.release.report import canonical_release_json, render_release_markdown

_JSON_REPORT = "securescan-core-v0.1-benchmark.json"
_MARKDOWN_REPORT = "securescan-core-v0.1-benchmark.md"
_PROTECTED_OUTPUTS = {
    Path("/"),
    Path("/dev"),
    Path("/etc"),
    Path("/proc"),
    Path("/root"),
    Path("/run"),
    Path("/sys"),
    Path("/var/run"),
}


def _absolute_safe_directory(path: str, field_name: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise ValueError(f"{field_name} must be an absolute safe directory")
    resolved = candidate.resolve(strict=False)
    if any(
        resolved == protected
        or (protected != Path("/") and resolved.is_relative_to(protected))
        for protected in _PROTECTED_OUTPUTS
    ):
        raise ValueError(f"{field_name} must be an absolute safe directory")
    return resolved


def _atomic_write(path: Path, data: bytes, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError("Release report already exists")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".release-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists() and not overwrite:
            raise FileExistsError("Release report already exists")
        os.replace(temporary_name, path)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary_name)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate SecureScan Core v0.1")
    parser.add_argument("--corpus-root", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--semgrep-image", required=True)
    parser.add_argument("--workspace-base", required=True)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def run_cli(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        corpus_root = _absolute_safe_directory(options.corpus_root, "corpus root")
        output_directory = _absolute_safe_directory(
            options.output_directory,
            "output directory",
        )
        workspace_base = _absolute_safe_directory(options.workspace_base, "workspace base")
        if not corpus_root.is_dir():
            raise ValueError("Benchmark corpus is invalid")
        output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        workspace_base.mkdir(mode=0o700, parents=True, exist_ok=True)
        evaluation = CoreV01ReleaseEvaluator(
            corpus_root=corpus_root,
            semgrep_image=options.semgrep_image,
            workspace_base=workspace_base,
        ).evaluate()
        _atomic_write(
            output_directory / _JSON_REPORT,
            canonical_release_json(evaluation),
            overwrite=options.overwrite,
        )
        _atomic_write(
            output_directory / _MARKDOWN_REPORT,
            render_release_markdown(evaluation).encode("utf-8"),
            overwrite=options.overwrite,
        )
    except Exception:
        print("SecureScan release benchmark failed")
        return 2
    print("SecureScan release benchmark completed")
    return 0 if evaluation.acceptance_passed else 1


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
