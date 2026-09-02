from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from securescan.benchmarks.python_sast_maturity import (
    BASELINE_COMMIT,
    BASELINE_TAG,
    build_maturity_decision,
    canonical_document,
    render_markdown,
    write_artifacts,
)

_JSON_RELATIVE_PATH = Path("benchmarks/python_sast/python-sast-maturity-decision-v1.json")
_MARKDOWN_RELATIVE_PATH = Path("docs/python-sast-maturity-v1.md")


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "pyproject.toml").is_file():
        raise RuntimeError("SecureScan repository root is invalid")
    return root


def payloads(root: Path) -> tuple[bytes, bytes]:
    decision = build_maturity_decision(root)
    return canonical_document(decision), render_markdown(decision)


def _check(root: Path, json_payload: bytes, markdown_payload: bytes) -> None:
    paths = (
        (root / _JSON_RELATIVE_PATH, json_payload),
        (root / _MARKDOWN_RELATIVE_PATH, markdown_payload),
    )
    for path, expected in paths:
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise RuntimeError(f"F2F artifact differs: {path.name}")
    print(f"baseline={BASELINE_TAG} commit={BASELINE_COMMIT}")
    for path, expected in paths:
        print(f"{path.name}={hashlib.sha256(expected).hexdigest()}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("mode", choices=("check", "generate", "summary"))
    arguments = parser.parse_args(argv)
    root = repository_root()
    json_payload, markdown_payload = payloads(root)
    if arguments.mode == "check":
        _check(root, json_payload, markdown_payload)
        return 0
    if arguments.mode == "summary":
        import json

        decision = json.loads(json_payload)
        print(f"maturity={decision['maturity']}")
        print(
            "evidence_strength_distribution="
            f"{decision['evidence_strength_distribution']}"
        )
        return 0
    created = write_artifacts(
        root / _JSON_RELATIVE_PATH,
        root / _MARKDOWN_RELATIVE_PATH,
        json_payload,
        markdown_payload,
    )
    print("recorded" if created else "already-recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
